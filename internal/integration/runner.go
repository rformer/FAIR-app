package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/egress"
)

// F-011 T-17 (F-011-AC-08; design §3.3): the connector runner. The integrate
// service's leader claims due connector integrations (integration.claim_due:
// FOR UPDATE SKIP LOCKED, a lease that returns the integration if the
// replica dies), opens their credentials, fetches the source through the
// guard, and submits the complete batch through the gateway as the
// integration's service account (its own token, client_credentials), so the
// risk service's checks, limits, RLS and audit apply as to any push. The
// outcome is recorded on the integration: a success schedules the next run;
// a failure is a failed run, retried at the schedule with exponential
// back-off, and the third consecutive failure notifies the integration's
// managers (integration.run_failed, F-009). The runner never writes risk
// data.

// LeaseSeconds is how long a claimed integration stays claimed.
const LeaseSeconds = 15 * 60

// Submission is one batch to submit as the integration's service account.
type Submission struct {
	IntegrationID    string
	ServiceAccountID string
	ClientSecret     string
	Trigger          string // schedule or manual
	Key              string // Idempotency-Key: the claim
	Body             []byte // fair.integration.v1
}

// Submitter submits a batch and answers the platform's status and body.
type Submitter interface {
	Submit(ctx context.Context, s Submission) (status int, body []byte, err error)
}

// GatewaySubmitter submits through the gateway: a 10-minute token from
// /api/v1/oauth/token (client_credentials, the service account's id and
// secret by basic authentication), then the batch to
// /api/v1/imports/{integration}/batches?trigger=.
type GatewaySubmitter struct {
	URL    *url.URL     // FAIR_INTEGRATE_GATEWAY_URL
	Client *http.Client // TLS 1.2+, the gateway's CA (FAIR_INTEGRATE_GATEWAY_CA_FILE)
}

func (g GatewaySubmitter) Submit(ctx context.Context, s Submission) (int, []byte, error) {
	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.URL.JoinPath("/api/v1/oauth/token").String(), strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(s.ServiceAccountID), url.QueryEscape(s.ClientSecret))
	resp, err := g.Client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("integration: the gateway's token endpoint: %w", err)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		return 0, nil, fmt.Errorf("integration: the service account's token was refused (%d %s)", resp.StatusCode, e.Error)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil || tok.AccessToken == "" {
		return 0, nil, errors.New("integration: the gateway answered no token")
	}
	u := g.URL.JoinPath("/api/v1/imports", s.IntegrationID, "batches")
	u.RawQuery = url.Values{"trigger": {s.Trigger}}.Encode()
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(s.Body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Idempotency-Key", s.Key)
	resp, err = g.Client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("integration: submitting the batch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

// Runner runs due connectors.
type Runner struct {
	DB     *pgxpool.Pool // app_integrate
	Keys   *Keyring
	Fetch  Fetcher
	Submit Submitter
	Batch  int // integrations claimed a step (default 4)
}

// Claim is a claimed connector integration.
type Claim struct {
	ID               string
	BUID             string
	Kind             string
	Mapping          json.RawMessage
	Connector        Connector
	ServiceAccountID string
	Trigger          string
	Token            string
}

// Outcome is what one connector run came to.
type Outcome struct {
	IntegrationID string
	Succeeded     bool
	Run           string // the run (succeeded or failed)
	Failure       string
	Refused       string // the refused host, if the guard refused one
	Failures      int    // consecutive failures after this run
}

// Step claims due integrations and runs each; it answers their outcomes.
func (r Runner) Step(ctx context.Context) ([]Outcome, error) {
	n := r.Batch
	if n <= 0 {
		n = 4
	}
	rows, err := r.DB.Query(ctx, `SELECT id::text, bu_id::text, kind, mapping, connector, service_account_id::text, trigger, token::text
		FROM integration.claim_due($1, $2)`, LeaseSeconds, n)
	if err != nil {
		return nil, err
	}
	var claims []Claim
	for rows.Next() {
		var c Claim
		var conn []byte
		if err := rows.Scan(&c.ID, &c.BUID, &c.Kind, &c.Mapping, &conn, &c.ServiceAccountID, &c.Trigger, &c.Token); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal(conn, &c.Connector); err != nil {
			rows.Close()
			return nil, err
		}
		claims = append(claims, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []Outcome
	var errs []error
	for _, c := range claims {
		o, err := r.RunOne(ctx, c)
		if err != nil {
			errs = append(errs, fmt.Errorf("integration %s: %w", c.ID, err))
			continue
		}
		out = append(out, o)
	}
	return out, errors.Join(errs...)
}

// Run steps every interval until ctx ends.
func (r Runner) Run(ctx context.Context, every time.Duration, onErr func(error)) error {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, err := r.Step(ctx); err != nil && ctx.Err() == nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// RunOne runs one claimed integration and records its outcome; an error is
// one the outcome could not be recorded for (the lease returns it).
func (r Runner) RunOne(ctx context.Context, c Claim) (Outcome, error) {
	o := Outcome{IntegrationID: c.ID}
	fail := func(err error) (Outcome, error) {
		o.Failure = clip(err.Error(), 500)
		if errors.Is(err, egress.ErrRefused) {
			o.Refused = c.Connector.Host()
		}
		return r.failed(ctx, c, o)
	}
	source, err := r.credential(ctx, c.ID, PurposeSource)
	if err != nil && !errors.Is(err, errNoCredential) {
		return fail(err)
	}
	client, err := r.credential(ctx, c.ID, PurposeClient)
	if errors.Is(err, errNoCredential) {
		return fail(errors.New("integration: no client credential: set the service account's client secret"))
	}
	if err != nil {
		return fail(err)
	}
	got, err := r.Fetch.Fetch(ctx, TestRequest{IntegrationID: c.ID, BUID: c.BUID, Kind: c.Kind, Mapping: c.Mapping, Connector: c.Connector, Source: source})
	if err != nil {
		return fail(err)
	}
	status, body, err := r.Submit.Submit(ctx, Submission{IntegrationID: c.ID, ServiceAccountID: c.ServiceAccountID, ClientSecret: client.ClientSecret,
		Trigger: c.Trigger, Key: "connector-" + c.Token, Body: got.Body})
	if err != nil {
		return fail(err)
	}
	if status != http.StatusCreated {
		var e struct {
			Error  string `json:"error"`
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(body, &e)
		return fail(fmt.Errorf("integration: the platform refused the batch (%d %s: %s)", status, e.Error, e.Detail))
	}
	var res struct {
		Run struct {
			ID string `json:"id"`
		} `json:"run"`
	}
	if err := json.Unmarshal(body, &res); err != nil || res.Run.ID == "" {
		return fail(errors.New("integration: the platform's answer names no run"))
	}
	if _, err := r.DB.Exec(ctx, "SELECT integration.connector_succeeded($1, $2, $3)", c.ID, c.Token, res.Run.ID); err != nil {
		return o, err
	}
	o.Succeeded, o.Run = true, res.Run.ID
	return o, nil
}

func (r Runner) failed(ctx context.Context, c Claim, o Outcome) (Outcome, error) {
	var refused any
	if o.Refused != "" {
		refused = o.Refused
	}
	var raw []byte
	if err := r.DB.QueryRow(ctx, "SELECT integration.connector_failed($1, $2, $3, $4)", c.ID, c.Token, o.Failure, refused).Scan(&raw); err != nil {
		return o, err
	}
	var res struct {
		Run      string `json:"run"`
		Failures int    `json:"failures"`
	}
	_ = json.Unmarshal(raw, &res)
	o.Run, o.Failures = res.Run, res.Failures
	return o, nil
}

var errNoCredential = errors.New("integration: no such credential")

func (r Runner) credential(ctx context.Context, id, purpose string) (*Credential, error) {
	var s Sealed
	err := r.DB.QueryRow(ctx, "SELECT key_id, nonce, ciphertext FROM integration.secret_for_run($1, $2)", id, purpose).Scan(&s.KeyID, &s.Nonce, &s.Ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNoCredential
	}
	if err != nil {
		return nil, err
	}
	if r.Keys == nil {
		return nil, errors.New("integration: credentials need the connector-credentials keys (FAIR_INTEGRATE_SECRETS_DIR)")
	}
	c, err := r.Keys.Open(id, purpose, s)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
