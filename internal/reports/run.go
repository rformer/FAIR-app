package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/rformer/fair-app/internal/keys"
	"github.com/rformer/fair-app/internal/reason"
	"github.com/rformer/fair-app/internal/reports/doc"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-010 T-09 (design §3.3, §3.6): report runs. A request inserts the run
// and its River job in the requester's transaction (report.request); the
// worker reads under the requester's delegated read-only context, builds the
// document with the kind's reader, renders each requested format, stores the
// files in the report store with their SHA-256 digests and completes the run
// (report.complete_run), or fails it (report.fail_run).

// River for reports: risk_river (the analysis schema), queue report.
const (
	RiverSchema = "risk_river"
	Queue       = "report"
	Attempts    = 3
	// MaxRisks bounds a report's scope (OQ11): open risks the requester sees.
	MaxRisks = 10_000
	// MaxRunning: a requester's runs queued or running at once (OQ11).
	MaxRunning = 3
	// MaxFile bounds every file (OQ11; report.file's bound).
	MaxFile = 100 << 20
)

// Formats in their fixed order, with their files (design §3.5: names never
// from data) and media types.
var Formats = []string{"pdf", "csv", "json"}

// FileName is a format's file name.
func FileName(format string) string {
	return map[string]string{"pdf": "report.pdf", "csv": "report-csv.zip", "json": "report.json"}[format]
}

// MediaType is a format's media type.
func MediaType(format string) string {
	return map[string]string{"pdf": "application/pdf", "csv": "application/zip", "json": "application/json"}[format]
}

// GenerateArgs is the job generating run RunID.
type GenerateArgs struct {
	RunID string `json:"run_id"`
}

// Kind implements river.JobArgs.
func (GenerateArgs) Kind() string { return "report.generate" }

// InsertOpts implements river.JobArgsWithInsertOpts.
func (GenerateArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: Queue, MaxAttempts: Attempts}
}

// Run is a run as a reader sees it.
type Run struct {
	ID            string
	RequestedBy   string
	RequesterName string
	BU            doc.Ref
	Kind          string
	Params        json.RawMessage
	Formats       []string
	Reason        string
	ScheduleID    string
}

// Built is a reader's document and the number of risks it covers.
type Built struct {
	Doc   doc.Document
	Risks int
}

// Kind is a report kind (design §3.4): its parameters and its reader.
type Kind struct {
	Name  string
	Title string
	// Params checks a request's parameters and returns them canonical; nil
	// accepts only none ({}).
	Params func(json.RawMessage) (json.RawMessage, error)
	// Read builds the document in tx: the requester's delegated read-only
	// context, one REPEATABLE READ snapshot.
	Read func(ctx context.Context, tx pgx.Tx, r Run) (Built, error)
}

// Request is what a requester asks for (design §6).
type Request struct {
	Kind    string
	BU      string
	Params  json.RawMessage
	Formats []string
	Reason  string
}

// ErrParams is a request's parameters refused by its kind.
var ErrParams = errors.New("reports: parameters")

// CheckFormats returns formats in their fixed order, or an error.
func CheckFormats(formats []string) ([]string, error) {
	var out []string
	for _, f := range Formats {
		if slices.Contains(formats, f) {
			out = append(out, f)
		}
	}
	for _, f := range formats {
		if !slices.Contains(Formats, f) {
			return nil, fmt.Errorf("reports: format %q is not one of pdf, csv, json", f)
		}
	}
	if len(out) == 0 || len(out) != len(formats) {
		return nil, errors.New("reports: formats name pdf, csv or json, each once")
	}
	return out, nil
}

// CheckParams checks a request's parameters with its kind.
func (k Kind) CheckParams(raw json.RawMessage) (json.RawMessage, error) {
	if len(strings.TrimSpace(string(raw))) == 0 || string(raw) == "null" {
		raw = json.RawMessage(`{}`)
	}
	if k.Params == nil {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil || len(m) > 0 {
			return nil, fmt.Errorf("%w: %s takes no parameters", ErrParams, k.Name)
		}
		return json.RawMessage(`{}`), nil
	}
	out, err := k.Params(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParams, err)
	}
	return out, nil
}

// RequestRun queues a run in tx (the requester's DB context): the database
// counts the scope, checks report.export and the running limit, and records
// report.requested; the job is queued in the same transaction. The caller
// has checked the kind, its parameters, the formats and the reason rule.
// Refusals are the database's (PF029 limit_exceeded, too_many_running;
// 42501; P0002).
func RequestRun(ctx context.Context, tx pgx.Tx, enqueue func(context.Context, pgx.Tx, GenerateArgs) error, req Request) (string, error) {
	var reason any
	if s := strings.TrimSpace(req.Reason); s != "" {
		reason = s
	}
	var id string
	if err := tx.QueryRow(ctx, "SELECT report.request($1, $2, $3, $4, $5)::text", req.Kind, req.BU, []byte(req.Params), req.Formats, reason).Scan(&id); err != nil {
		return "", err
	}
	if err := enqueue(ctx, tx, GenerateArgs{RunID: id}); err != nil {
		return "", fmt.Errorf("reports: queue the run: %w", err)
	}
	return id, nil
}

// Enqueuer queues a report job in the request's transaction.
func Enqueuer(c *river.Client[pgx.Tx]) func(context.Context, pgx.Tx, GenerateArgs) error {
	return func(ctx context.Context, tx pgx.Tx, args GenerateArgs) error {
		_, err := c.InsertTx(ctx, tx, args, nil)
		return err
	}
}

// ReasonSettings reads export.reason_required (settings.Client).
type ReasonSettings = reason.Settings

// ReasonRequired is the reason rule for a report of bu's subtree (design
// §3.6, OQ7; reason.InSubtree). It fails closed.
func ReasonRequired(ctx context.Context, q reason.RowQuerier, s ReasonSettings, bu string) (bool, error) {
	return reason.InSubtree(ctx, q, s, bu)
}

// LoadContextKey reads the report context key (risk/secrets/
// report-context.{key,id}; FAIR_REPORT_CONTEXT_KEY_FILE and _ID_FILE).
func LoadContextKey(getenv func(string) string) (authz.ContextKey, error) {
	kf, idf := getenv("FAIR_REPORT_CONTEXT_KEY_FILE"), getenv("FAIR_REPORT_CONTEXT_KEY_ID_FILE")
	if kf == "" || idf == "" {
		return authz.ContextKey{}, errors.New("reports: FAIR_REPORT_CONTEXT_KEY_FILE and FAIR_REPORT_CONTEXT_KEY_ID_FILE are required")
	}
	id, err := keys.ReadID(idf)
	if err != nil {
		return authz.ContextKey{}, fmt.Errorf("FAIR_REPORT_CONTEXT_KEY_ID_FILE: %w", err)
	}
	sec, err := keys.ReadSecret(kf, keys.SecretLen)
	if err != nil {
		return authz.ContextKey{}, fmt.Errorf("FAIR_REPORT_CONTEXT_KEY_FILE: %w", err)
	}
	return authz.ContextKey{ID: id, Secret: sec}, nil
}
