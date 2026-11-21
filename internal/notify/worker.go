package notify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rformer/fair-app/pkg/telemetry"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// F-009 T-10 (F-009-AC-13 to AC-16, AC-19; design §3.5, §3.8, §3.9): the
// delivery workers. Every replica claims due deliveries (notify.claim),
// sends each by its channel and settles it (notify.settle); the leader
// returns uncertain claims (notify.reclaim), sends digests and keeps the
// retention (notify.purge).

// Mailer sends one email (SMTPSender does).
type Mailer interface {
	Send(ctx context.Context, cfg SMTPConfig, to string, msg Message, id string) (Sent, error)
}

// Poster posts one webhook delivery (WebhookSender does).
type Poster interface {
	Send(ctx context.Context, target, secret, previous, id string, body []byte) (Sent, error)
}

// Worker delivers.
type Worker struct {
	DB         *pgxpool.Pool // app_notify
	Composer   func() Composer
	Mail       Mailer
	Post       Poster
	Keys       *Keyring
	RetryHours func() int // notification.retry_hours
	Batch      int        // deliveries per claim; default 50
}

type claimed struct {
	ID       string          `json:"id"`
	Kind     string          `json:"channel_kind"`
	Config   json.RawMessage `json:"config"`
	Secret   *string         `json:"secret"`
	Previous *string         `json:"previous"`
	Email    *string         `json:"email"`
	Envelope Envelope        `json:"envelope"`
	Label    string          `json:"label"`
	Security bool            `json:"security"`
	Attempts int             `json:"attempts"`
}

// WebhookConfig is a webhook's configuration (notify.channel config).
type WebhookConfig struct {
	URL string `json:"url"`
}

// Step claims up to Batch due deliveries, sends and settles each; it says
// how many it settled.
func (w Worker) Step(ctx context.Context) (int, error) {
	batch := w.Batch
	if batch <= 0 {
		batch = 50
	}
	token := uuid.NewString()
	rows, err := w.DB.Query(ctx, "SELECT x FROM notify.claim($1, $2) x", batch, token)
	if err != nil {
		return 0, fmt.Errorf("notify: claiming: %w", err)
	}
	var work []claimed
	for rows.Next() {
		var raw []byte
		var c claimed
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return 0, err
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			rows.Close()
			return 0, err
		}
		work = append(work, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, c := range work {
		sent, err := w.send(ctx, c)
		if err := w.settle(ctx, c.Kind, c.ID, token, sent, err); err != nil {
			return 0, err
		}
	}
	return len(work), nil
}

func (w Worker) composer() Composer {
	if w.Composer == nil {
		return Composer{}
	}
	return w.Composer()
}

func (w Worker) send(ctx context.Context, c claimed) (Sent, error) {
	switch c.Kind {
	case "smtp":
		var cfg SMTPConfig
		if err := json.Unmarshal(c.Config, &cfg); err != nil {
			return Sent{}, Permanent{err}
		}
		if c.Email == nil {
			return Sent{}, Permanent{errors.New("notify: the recipient has no address")}
		}
		msg, err := w.composer().Email(c.Envelope, c.Label)
		if err != nil {
			return Sent{}, Permanent{err}
		}
		return w.Mail.Send(ctx, cfg, *c.Email, msg, c.ID)
	case "webhook":
		var cfg WebhookConfig
		if err := json.Unmarshal(c.Config, &cfg); err != nil {
			return Sent{}, Permanent{err}
		}
		secret, err := w.open(c.Secret)
		if err != nil || secret == "" {
			return Sent{}, Permanent{fmt.Errorf("notify: the webhook's secret: %w", err)}
		}
		previous, _ := w.open(c.Previous)
		body, err := w.composer().WebhookBody(c.Envelope, c.ID)
		if err != nil {
			return Sent{}, Permanent{err}
		}
		return w.Post.Send(ctx, cfg.URL, secret, previous, c.ID, body)
	}
	return Sent{}, Permanent{fmt.Errorf("notify: unknown channel kind %q", c.Kind)}
}

func (w Worker) open(b64 *string) (string, error) {
	if b64 == nil || w.Keys == nil {
		return "", nil
	}
	ct, err := base64.StdEncoding.DecodeString(*b64)
	if err != nil {
		return "", err
	}
	return w.Keys.Open(ct)
}

func (w Worker) retryHours() int {
	if w.RetryHours == nil {
		return 24
	}
	if h := w.RetryHours(); h >= 1 && h <= 72 {
		return h
	}
	return 24
}

// settle records a send's outcome (the error decides: none, refused,
// permanent, or retry).
func (w Worker) settle(ctx context.Context, channel, id, token string, sent Sent, err error) error {
	outcome, detail := "sent", sent.TLSVersion
	if sent.Status != 0 {
		detail = fmt.Sprintf("%d %s", sent.Status, sent.TLSVersion)
	}
	switch {
	case err == nil:
	case errors.Is(err, ErrRefused):
		outcome, detail = "refused", err.Error()
	case IsPermanent(err):
		outcome, detail = "permanent", err.Error()
	default:
		outcome, detail = "retry", err.Error()
	}
	var final string
	if err := w.DB.QueryRow(ctx, "SELECT notify.settle($1, $2, $3, $4, $5)", id, token, outcome, detail, w.retryHours()).Scan(&final); err != nil {
		return fmt.Errorf("notify: settling %s: %w", id, err)
	}
	switch channel { // F-012 T-09: only fixed names reach telemetry
	case "smtp", "email":
		channel = "email"
	case "webhook":
	default:
		channel = "other"
	}
	telemetry.Delivery(ctx, channel, outcome)
	return nil
}

// Reclaim returns uncertain claims to pending (the leader, design §3.5).
func (w Worker) Reclaim(ctx context.Context) (int, error) {
	var n int
	err := w.DB.QueryRow(ctx, "SELECT notify.reclaim()").Scan(&n)
	return n, err
}

// Digest sends one due digest, if any; it says whether it sent one.
func (w Worker) Digest(ctx context.Context) (bool, error) {
	token := uuid.NewString()
	var raw []byte
	if err := w.DB.QueryRow(ctx, "SELECT notify.claim_digest($1)", token).Scan(&raw); err != nil {
		return false, fmt.Errorf("notify: claiming a digest: %w", err)
	}
	if raw == nil {
		return false, nil
	}
	var d struct {
		Email  string          `json:"email"`
		Config json.RawMessage `json:"config"`
		Items  []struct {
			ID       string   `json:"id"`
			Envelope Envelope `json:"envelope"`
			Label    string   `json:"label"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return false, err
	}
	items := make([]DigestItem, 0, len(d.Items))
	for _, it := range d.Items {
		items = append(items, DigestItem{Envelope: it.Envelope, Label: it.Label})
	}
	var sent Sent
	var cfg SMTPConfig
	err := json.Unmarshal(d.Config, &cfg)
	if err == nil {
		var msg Message
		if msg, err = w.composer().Digest(items); err == nil {
			sent, err = w.Mail.Send(ctx, cfg, d.Email, msg, "digest-"+token)
		}
	}
	for _, it := range d.Items {
		if serr := w.settle(ctx, "email", it.ID, token, sent, err); serr != nil {
			return true, serr
		}
	}
	return true, nil
}

// Purge applies the retention (daily, design §3.9).
func (w Worker) Purge(ctx context.Context, logDays int) (deliveries, notices int, err error) {
	err = w.DB.QueryRow(ctx, "SELECT (r->>'deliveries')::int, (r->>'notices')::int FROM notify.purge($1) r", logDays).Scan(&deliveries, &notices)
	return deliveries, notices, err
}

// Banner reads the system-use banner's first sentence (for emails).
func Banner(ctx context.Context, db *pgxpool.Pool) (string, error) {
	var s *string
	if err := db.QueryRow(ctx, "SELECT notify.banner()").Scan(&s); err != nil || s == nil {
		return "", err
	}
	return *s, nil
}

// RunDelivery steps until ctx ends, pausing when nothing was due.
func (w Worker) RunDelivery(ctx context.Context, every time.Duration, onErr func(error)) {
	for ctx.Err() == nil {
		n, err := w.Step(ctx)
		if err != nil && ctx.Err() == nil && onErr != nil {
			onErr(err)
		}
		if n > 0 && err == nil {
			continue
		}
		select {
		case <-ctx.Done():
		case <-time.After(every):
		}
	}
}
