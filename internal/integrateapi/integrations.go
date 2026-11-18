package integrateapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/egress"
	"github.com/rformer/fair-app/internal/integration"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-011 T-16 (F-011-AC-01 to AC-05, AC-08; design §3.1, §6.1).

var deliveries = []string{"push", "file", "connector"}

// integrationBody is a create or change. Kind, BU and delivery are fixed
// once created (a change that names them must name them unchanged).
type integrationBody struct {
	BUID             string          `json:"bu_id"`
	Name             string          `json:"name"`
	Kind             string          `json:"kind"`
	Delivery         string          `json:"delivery"`
	Mapping          json.RawMessage `json:"mapping"`
	Connector        json.RawMessage `json:"connector"`
	ServiceAccountID *string         `json:"service_account_id"`
	AutoAccept       bool            `json:"auto_accept"`
	ExpectedVersion  int             `json:"expected_version"`
}

// current is what the API reads of an integration to check a change.
type current struct {
	ID       string          `json:"id"`
	BUID     string          `json:"bu_id"`
	Kind     string          `json:"kind"`
	Delivery string          `json:"delivery"`
	Mapping  json.RawMessage `json:"mapping"`
	State    string          `json:"state"`
}

// checkMapping refuses a mapping that is not the declarative form
// (integration.Mapping) or names fields the kind does not have.
func checkMapping(kind string, raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "{}", nil
	}
	var m integration.Mapping
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return "", errors.New("integration: the mapping is an object of columns, values, defaults and separator")
	}
	if len(m.Columns) > 0 || len(m.Values) > 0 || len(m.Defaults) > 0 || m.Separator != "" {
		if err := integration.CheckMapping(kind, m); err != nil {
			return "", err
		}
	}
	if len(raw) > 65536 {
		return "", errors.New("integration: the mapping is at most 64 KiB")
	}
	return string(raw), nil
}

// connector parses the body's connector (nil without one).
func connector(raw json.RawMessage) (*integration.Connector, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	c, err := integration.ParseConnector(raw)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// checkDestination runs the guard over the source host. A refused host is
// recorded (integration.destination_refused, in its own transaction: the
// save is refused) by a caller who may manage the integration, and answered
// 422; a recording refused by the database answers that refusal instead.
func (a *API) checkDestination(w http.ResponseWriter, r *http.Request, p authz.Principal, bu, integrationID, host, during string) bool {
	_, err := a.Guard.Resolve(r.Context(), host)
	if err == nil {
		return true
	}
	if !errors.Is(err, egress.ErrRefused) {
		problem(w, http.StatusUnprocessableEntity, "destination_unresolved", err.Error())
		return false
	}
	if rerr := a.recordRefusal(r.Context(), p, bu, integrationID, host, err.Error(), during); rerr != nil {
		fail(w, rerr)
		return false
	}
	problem(w, http.StatusUnprocessableEntity, "destination_refused", err.Error())
	return false
}

func (a *API) recordRefusal(ctx context.Context, p authz.Principal, bu, integrationID, host, detail, during string) error {
	var b, i any
	if bu != "" {
		b = bu
	}
	if integrationID != "" {
		i = integrationID
	}
	return authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT integration.destination_refused($1::uuid, $2::uuid, $3, $4, $5)", b, i, host, detail, during)
		return err
	})
}

func (a *API) listIntegrations(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	deleted := false
	switch v := r.URL.Query().Get("deleted"); v {
	case "", "false":
	case "true":
		deleted = true
	default:
		problem(w, http.StatusBadRequest, "invalid_value", "deleted is true or false")
		return
	}
	raw, err := a.one(r, p, "SELECT coalesce(jsonb_agg(x), '[]') FROM integration.list($1) x", deleted)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"integrations": raw})
}

func (a *API) getIntegration(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	iid, ok := id(w, r, "id")
	if !ok {
		return
	}
	raw, err := a.one(r, p, "SELECT integration.get($1)", iid)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, raw)
}

func (a *API) createIntegration(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var b integrationBody
	if !decode(w, r, &b) {
		return
	}
	switch {
	case !uuidRE.MatchString(b.BUID):
		problem(w, http.StatusBadRequest, "invalid_request", "bu_id is a business unit id")
		return
	case !slices.Contains(integration.InputKinds, b.Kind):
		problem(w, http.StatusUnprocessableEntity, "invalid_integration", "kind is assets, loss_events, risks or control_status")
		return
	case !slices.Contains(deliveries, b.Delivery):
		problem(w, http.StatusUnprocessableEntity, "invalid_integration", "delivery is push, file or connector")
		return
	case b.ServiceAccountID != nil && !uuidRE.MatchString(*b.ServiceAccountID):
		problem(w, http.StatusBadRequest, "invalid_request", "service_account_id is a service account's id")
		return
	case utf8.RuneCountInString(b.Name) > 100:
		problem(w, http.StatusUnprocessableEntity, "invalid_integration", "the name is 1 to 100 characters")
		return
	}
	mapping, err := checkMapping(b.Kind, b.Mapping)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_mapping", err.Error())
		return
	}
	c, err := connector(b.Connector)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_connector", err.Error())
		return
	}
	var conn any
	if c != nil {
		if b.Delivery != "connector" {
			problem(w, http.StatusUnprocessableEntity, "invalid_integration", "only a connector integration has connector settings")
			return
		}
		if !a.checkDestination(w, r, p, b.BUID, "", c.Host(), "save") {
			return
		}
		cj, _ := json.Marshal(c)
		conn = string(cj)
	}
	var raw json.RawMessage
	err = a.tx(r, p, func(tx pgx.Tx) error {
		var nid string
		if err := tx.QueryRow(r.Context(), "SELECT integration.add($1::uuid, $2, $3, $4, $5::jsonb, $6::jsonb, $7::uuid, $8)::text",
			b.BUID, b.Name, b.Kind, b.Delivery, mapping, conn, b.ServiceAccountID, b.AutoAccept).Scan(&nid); err != nil {
			return err
		}
		return tx.QueryRow(r.Context(), "SELECT integration.get($1)", nid).Scan(&raw)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, raw)
}

func (a *API) updateIntegration(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	iid, ok := id(w, r, "id")
	if !ok {
		return
	}
	var b integrationBody
	if !decode(w, r, &b) {
		return
	}
	if b.ServiceAccountID != nil && !uuidRE.MatchString(*b.ServiceAccountID) {
		problem(w, http.StatusBadRequest, "invalid_request", "service_account_id is a service account's id")
		return
	}
	var cur current
	raw, err := a.one(r, p, "SELECT integration.get($1)", iid)
	if err == nil {
		err = json.Unmarshal(raw, &cur)
	}
	if err != nil {
		fail(w, err)
		return
	}
	if (b.BUID != "" && b.BUID != cur.BUID) || (b.Kind != "" && b.Kind != cur.Kind) || (b.Delivery != "" && b.Delivery != cur.Delivery) {
		problem(w, http.StatusUnprocessableEntity, "integration_fixed", "an integration keeps its business unit, kind and delivery")
		return
	}
	if utf8.RuneCountInString(b.Name) > 100 {
		problem(w, http.StatusUnprocessableEntity, "invalid_integration", "the name is 1 to 100 characters")
		return
	}
	mapping, err := checkMapping(cur.Kind, b.Mapping)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_mapping", err.Error())
		return
	}
	c, err := connector(b.Connector)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_connector", err.Error())
		return
	}
	var conn any
	if c != nil {
		if cur.Delivery != "connector" {
			problem(w, http.StatusUnprocessableEntity, "invalid_integration", "only a connector integration has connector settings")
			return
		}
		if !a.checkDestination(w, r, p, cur.BUID, iid, c.Host(), "save") {
			return
		}
		cj, _ := json.Marshal(c)
		conn = string(cj)
	}
	err = a.tx(r, p, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), "SELECT integration.change($1, $2, $3, $4::jsonb, $5::jsonb, $6::uuid, $7)",
			iid, b.ExpectedVersion, b.Name, mapping, conn, b.ServiceAccountID, b.AutoAccept); err != nil {
			return err
		}
		return tx.QueryRow(r.Context(), "SELECT integration.get($1)", iid).Scan(&raw)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, raw)
}

type reasonBody struct {
	Reason string `json:"reason"`
}

// state runs one of the state functions (pause, resume, remove) and
// answers the integration as it now is.
func (a *API) state(w http.ResponseWriter, r *http.Request, p authz.Principal, sql string, args ...any) {
	iid, ok := id(w, r, "id")
	if !ok {
		return
	}
	var raw json.RawMessage
	err := a.tx(r, p, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), sql, append([]any{iid}, args...)...); err != nil {
			return err
		}
		return tx.QueryRow(r.Context(), "SELECT integration.get($1)", iid).Scan(&raw)
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, raw)
}

// optionalBody decodes a body that may be absent.
func optionalBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.ContentLength == 0 {
		return true
	}
	return decode(w, r, v)
}

func (a *API) pauseIntegration(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var b struct{}
	if optionalBody(w, r, &b) {
		a.state(w, r, p, "SELECT integration.pause($1)")
	}
}

func (a *API) resumeIntegration(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var b struct{}
	if optionalBody(w, r, &b) {
		a.state(w, r, p, "SELECT integration.resume($1)")
	}
}

// deleteIntegration deletes with a reason; its runs, links and the
// provenance of what it brought in stay (AC-05), its credentials go.
func (a *API) deleteIntegration(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var b reasonBody
	if !decode(w, r, &b) {
		return
	}
	a.state(w, r, p, "SELECT integration.remove($1, $2)", b.Reason)
}

// runIntegration queues a connector run now; the runner (T-17) sends it as
// a manual run, as the integration's service account.
func (a *API) runIntegration(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	iid, ok := id(w, r, "id")
	if !ok {
		return
	}
	var b struct{}
	if !optionalBody(w, r, &b) {
		return
	}
	raw, err := a.one(r, p, "SELECT integration.run_now($1)", iid)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, raw)
}

// testIntegration fetches the connector's first page through the guard and
// answers its count and first mapping problems; nothing is submitted.
func (a *API) testIntegration(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	iid, ok := id(w, r, "id")
	if !ok {
		return
	}
	var b struct{}
	if !optionalBody(w, r, &b) {
		return
	}
	var cur struct {
		current
		Connector integration.Connector `json:"connector"`
	}
	raw, err := a.one(r, p, "SELECT integration.for_test($1)", iid)
	if err == nil {
		err = json.Unmarshal(raw, &cur)
	}
	if err != nil {
		fail(w, err)
		return
	}
	if !a.checkDestination(w, r, p, cur.BUID, iid, cur.Connector.Host(), "test") {
		return
	}
	if a.Tester == nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "the connectors are not available")
		return
	}
	req := integration.TestRequest{IntegrationID: iid, BUID: cur.BUID, Kind: cur.Kind, Mapping: cur.Mapping, Connector: cur.Connector}
	if cred, err := a.source(r.Context(), iid); err != nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", err.Error())
		return
	} else {
		req.Source = cred
	}
	res, err := a.Tester.Test(r.Context(), req)
	if errors.Is(err, egress.ErrRefused) {
		if rerr := a.recordRefusal(r.Context(), p, cur.BUID, iid, cur.Connector.Host(), err.Error(), "test"); rerr != nil {
			fail(w, rerr)
			return
		}
		problem(w, http.StatusUnprocessableEntity, "destination_refused", err.Error())
		return
	}
	if err != nil {
		msg := err.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
		problem(w, http.StatusUnprocessableEntity, "source_failed", msg)
		return
	}
	if len(res.Problems) > integration.MaxTestProblems {
		res.Problems = res.Problems[:integration.MaxTestProblems]
	}
	if res.Problems == nil {
		res.Problems = []integration.Refusal{}
	}
	writeJSON(w, http.StatusOK, res)
}

// source opens the integration's source credential (nil when none is set).
// The caller's right to manage the integration was checked first.
func (a *API) source(ctx context.Context, iid string) (*integration.Credential, error) {
	var s integration.Sealed
	err := a.DB.QueryRow(ctx, "SELECT key_id, nonce, ciphertext FROM integration.secret_for_run($1, 'source')", iid).Scan(&s.KeyID, &s.Nonce, &s.Ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("the credential could not be read")
	}
	if a.Keys == nil {
		return nil, errors.New("credentials need the connector-credentials keys (FAIR_INTEGRATE_SECRETS_DIR)")
	}
	c, err := a.Keys.Open(iid, integration.PurposeSource, s)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func purpose(w http.ResponseWriter, r *http.Request) (string, bool) {
	v := r.PathValue("purpose")
	if v != integration.PurposeSource && v != integration.PurposeClient {
		problem(w, http.StatusNotFound, "not_found", "")
		return "", false
	}
	return v, true
}

// putCredential seals and stores a credential (AC-03); the answer says only
// that it is set.
func (a *API) putCredential(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	iid, ok := id(w, r, "id")
	if !ok {
		return
	}
	pur, ok := purpose(w, r)
	if !ok {
		return
	}
	var c integration.Credential
	if !decode(w, r, &c) {
		return
	}
	if err := c.Check(pur); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_credential", err.Error())
		return
	}
	if a.Keys == nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "credentials need the connector-credentials keys (FAIR_INTEGRATE_SECRETS_DIR)")
		return
	}
	s, err := a.Keys.Seal(iid, pur, c)
	if err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_credential", err.Error())
		return
	}
	a.state(w, r, p, "SELECT integration.set_secret($1, $2, $3, $4, $5)", pur, s.KeyID, s.Nonce, s.Ciphertext)
}

func (a *API) deleteCredential(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	pur, ok := purpose(w, r)
	if !ok {
		return
	}
	var b struct{}
	if optionalBody(w, r, &b) {
		a.state(w, r, p, "SELECT integration.remove_secret($1, $2)", pur)
	}
}

// listRuns answers ?before=<run id> (older than), ?limit= 1 to 200 (50);
// more says whether older ones remain (AC-08).
func (a *API) listRuns(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	iid, ok := id(w, r, "id")
	if !ok {
		return
	}
	q := r.URL.Query()
	var before any
	if v := q.Get("before"); v != "" {
		if !uuidRE.MatchString(v) {
			problem(w, http.StatusBadRequest, "invalid_value", "before is a run id")
			return
		}
		before = v
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			problem(w, http.StatusBadRequest, "invalid_value", "limit is 1 to 200")
			return
		}
		limit = n
	}
	raw, err := a.one(r, p, "SELECT integration.runs($1, $2::uuid, $3)", iid, before, limit+1)
	if err != nil {
		fail(w, err)
		return
	}
	var runs []json.RawMessage
	if err := json.Unmarshal(raw, &runs); err != nil {
		fail(w, err)
		return
	}
	more := len(runs) > limit
	if more {
		runs = runs[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs, "more": more})
}

func (a *API) getRun(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	iid, ok := id(w, r, "id")
	if !ok {
		return
	}
	run, ok := id(w, r, "run")
	if !ok {
		return
	}
	raw, err := a.one(r, p, "SELECT integration.run_get($1)", run)
	if err != nil {
		fail(w, err)
		return
	}
	var of struct {
		IntegrationID string `json:"integration_id"`
	}
	if json.Unmarshal(raw, &of) != nil || of.IntegrationID != iid {
		problem(w, http.StatusNotFound, "not_found", "")
		return
	}
	writeJSON(w, http.StatusOK, raw)
}
