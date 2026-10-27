package posture

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/config"
)

// SecOps notification (F-015 T-15, AC-23). In SaaS mode posture.apply_change
// enqueues a notification for every weakening change in the change's own
// transaction (migration 0019); this file delivers the queue to the vendor's
// SecOps webhook.
//
// Each delivery is an HTTPS POST of the event JSON with:
//
//	X-FAIR-Delivery:  the notification id (receivers de-duplicate on it)
//	X-FAIR-Timestamp: Unix seconds
//	X-FAIR-Signature: sha256=<hex HMAC-SHA-256 of "<timestamp>.<body>">
//
// Any 2xx response acknowledges it; anything else is retried with backoff.

// CheckDeploymentMode compares the configured mode with the one the
// installer recorded (posture.deployment_mode; nil when unset). Production
// requires a recorded mode, and the two must always agree.
func CheckDeploymentMode(env, configured string, recorded *string) error {
	switch {
	case recorded == nil && env == "production":
		return errors.New("posture: the installer has not recorded the deployment mode (SELECT posture.set_deployment_mode(...) as fair_owner)")
	case recorded != nil && *recorded != configured:
		return fmt.Errorf("posture: FAIR_DEPLOYMENT_MODE=%s, but this install is %s", configured, *recorded)
	}
	return nil
}

// SecOpsSender delivers one notification.
type SecOpsSender interface {
	Send(ctx context.Context, id int64, event []byte) error
}

// SecOpsWebhook is the signed-webhook SecOpsSender.
type SecOpsWebhook struct {
	URL    string
	Secret []byte
	Client *http.Client
	Now    func() time.Time
}

// NewSecOpsWebhook builds the webhook sender. The signing secret is read
// from a file (at least 32 bytes); production requires an https:// URL, and
// TLS 1.2 is the floor.
func NewSecOpsWebhook(env, url, secretFile string) (*SecOpsWebhook, error) {
	if url == "" {
		return nil, errors.New("posture: FAIR_SECOPS_WEBHOOK_URL is required in SaaS mode")
	}
	if env == "production" && !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("posture: the SecOps webhook must be https:// in production, got %q", url)
	}
	secret, err := config.ReadSecretFile(secretFile)
	if err != nil {
		return nil, fmt.Errorf("posture: SecOps signing secret (FAIR_SECOPS_SECRET_FILE): %w", err)
	}
	if len(secret) < 32 {
		return nil, errors.New("posture: the SecOps signing secret must be at least 32 bytes")
	}
	return &SecOpsWebhook{
		URL:    url,
		Secret: []byte(secret),
		Client: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: http.ProxyFromEnvironment}},
		Now: time.Now,
	}, nil
}

// SignSecOps returns the X-FAIR-Signature value for a delivery.
func SignSecOps(secret []byte, timestamp string, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(timestamp + "."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// VerifySecOps checks a delivery's signature (for receivers and tests).
func VerifySecOps(secret []byte, timestamp string, body []byte, signature string) bool {
	return hmac.Equal([]byte(SignSecOps(secret, timestamp, body)), []byte(signature))
}

// Send implements SecOpsSender.
func (w *SecOpsWebhook) Send(ctx context.Context, id int64, event []byte) error {
	ts := strconv.FormatInt(w.Now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(event))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-FAIR-Delivery", strconv.FormatInt(id, 10))
	req.Header.Set("X-FAIR-Timestamp", ts)
	req.Header.Set("X-FAIR-Signature", SignSecOps(w.Secret, ts, event))
	resp, err := w.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("SecOps webhook answered %s", resp.Status)
	}
	return nil
}

// DeliverSecOps sends up to maxRows due notifications and records each outcome.
func DeliverSecOps(ctx context.Context, db *pgxpool.Pool, s SecOpsSender, maxRows int) (delivered, failed int, err error) {
	rows, err := db.Query(ctx, "SELECT id, event::text FROM posture.secops_claim($1)", maxRows)
	if err != nil {
		return 0, 0, err
	}
	type due struct {
		id    int64
		event string
	}
	var batch []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.event); err != nil {
			rows.Close()
			return 0, 0, err
		}
		batch = append(batch, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	for _, d := range batch {
		if sendErr := s.Send(ctx, d.id, []byte(d.event)); sendErr != nil {
			failed++
			if _, err := db.Exec(ctx, "SELECT posture.secops_failed($1, $2)", d.id, sendErr.Error()); err != nil {
				return delivered, failed, err
			}
			continue
		}
		delivered++
		if _, err := db.Exec(ctx, "SELECT posture.secops_delivered($1)", d.id); err != nil {
			return delivered, failed, err // re-sent after the lease: receivers de-duplicate on X-FAIR-Delivery
		}
	}
	return delivered, failed, nil
}

// RunSecOps delivers the queue every interval until ctx ends.
func RunSecOps(ctx context.Context, db *pgxpool.Pool, s SecOpsSender, every time.Duration, onError func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, failed, err := DeliverSecOps(ctx, db, s, 50); err != nil && ctx.Err() == nil {
			onError(err)
		} else if failed > 0 {
			onError(fmt.Errorf("%d SecOps notifications failed; retrying with backoff", failed))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
