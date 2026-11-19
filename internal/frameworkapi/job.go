package frameworkapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	oscaltypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-2-3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/rformer/fair-app/internal/framework"
)

// F-013 T-05 (F-013-AC-01 to AC-03, AC-05; design §1, §3.1, §3.2): imports
// are River jobs (queue framework of risk_river). The job reads the
// upload once (framework.claim_import), parses it outside any transaction,
// and records the outcome in one (framework.finish_import): a version or
// baseline applied with its events, a dry run's summary, or the problems
// that refused it. An uploaded profile selects from the catalog version
// its request names; every import of the profile resolves to it (nested
// profiles are resolved for shipped content only).

// River schema and queue of framework imports.
const (
	RiverSchema = "risk_river"
	Queue       = "framework"
	Attempts    = 3
	JobTimeout  = 5 * time.Minute
)

// ImportArgs is one import's job.
type ImportArgs struct {
	ImportID string `json:"import_id"`
}

// Kind implements river.JobArgs.
func (ImportArgs) Kind() string { return "framework.import" }

// InsertOpts implements river.JobArgsWithInsertOpts.
func (ImportArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: Queue, MaxAttempts: Attempts}
}

// Meta is an import's request: who the framework is (catalogs and CSV
// simple files), which catalog version and key a profile has.
type Meta struct {
	Format    string            `json:"format,omitempty"` // json or csv
	Family    *framework.Family `json:"family,omitempty"`
	Label     string            `json:"label,omitempty"`
	Title     string            `json:"title,omitempty"`
	Published string            `json:"published,omitempty"`
	Catalog   *framework.Ref    `json:"catalog,omitempty"` // a profile's catalog version
	Key       string            `json:"key,omitempty"`     // a profile's baseline key
}

// Worker works import jobs.
type Worker struct {
	river.WorkerDefaults[ImportArgs]
	DB     *pgxpool.Pool // app_rw
	Logger *slog.Logger
}

// Timeout implements river.Worker.
func (w *Worker) Timeout(*river.Job[ImportArgs]) time.Duration { return JobTimeout }

// Work implements river.Worker.
func (w *Worker) Work(ctx context.Context, job *river.Job[ImportArgs]) error {
	err := w.Run(ctx, job.Args.ImportID)
	if err != nil && job.Attempt >= job.MaxAttempts {
		// The last attempt: record the failure, so the import is final.
		if _, ferr := w.DB.Exec(ctx, "SELECT framework.finish_import($1, 'failed', $2::jsonb, NULL)", job.Args.ImportID,
			fmt.Sprintf(`[{"pointer": "", "message": %q}]`, "the import could not be completed; try again")); ferr != nil && w.Logger != nil {
			w.Logger.Error("framework import", "import", job.Args.ImportID, "error", ferr.Error())
		}
		return river.JobCancel(err)
	}
	return err
}

// Result is what a parsed import records: a version (with its diff) or a
// baseline, and a summary.
type Result struct {
	Version  *framework.Version `json:"version,omitempty"`
	Diff     *Diff              `json:"diff,omitempty"`
	Baseline *Baseline          `json:"baseline,omitempty"`
	Summary  map[string]any     `json:"summary"`
}

// Diff is framework.Diff with the version it is against.
type Diff struct {
	framework.Diff
	Since string `json:"since"`
}

// Baseline is a parsed baseline with its version.
type Baseline struct {
	framework.Baseline
	Version framework.Ref `json:"version"`
}

// Run works one import.
func (w *Worker) Run(ctx context.Context, id string) error {
	var kind, sha string
	var dry bool
	var file []byte
	var metaRaw []byte
	err := w.DB.QueryRow(ctx, "SELECT kind, dry_run, file, meta, sha256 FROM framework.claim_import($1)", id).Scan(&kind, &dry, &file, &metaRaw, &sha)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // finished already (a retry after the outcome was recorded)
	}
	if err != nil {
		return err
	}
	var meta Meta
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		return w.refuse(ctx, id, framework.Problems{{Pointer: "", Message: "the import's request is not readable"}})
	}
	res, err := w.parse(ctx, kind, file, meta)
	var probs framework.Problems
	if errors.As(err, &probs) {
		return w.refuse(ctx, id, probs)
	}
	if err != nil {
		return err
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return err
	}
	_, err = w.DB.Exec(ctx, "SELECT framework.finish_import($1, 'succeeded', NULL, $2::jsonb)", id, string(raw))
	return err
}

func (w *Worker) refuse(ctx context.Context, id string, p framework.Problems) error {
	raw, _ := json.Marshal(p)
	_, err := w.DB.Exec(ctx, "SELECT framework.finish_import($1, 'refused', $2::jsonb, NULL)", id, string(raw))
	return err
}

// version reads a stored version's requirements (nil when there is none).
func (w *Worker) version(ctx context.Context, family, label string) (*framework.Version, error) {
	var raw []byte
	if err := w.DB.QueryRow(ctx, "SELECT framework.version_payload($1, $2)", family, label).Scan(&raw); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	var v framework.Version
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (w *Worker) parse(ctx context.Context, kind string, file []byte, meta Meta) (*Result, error) {
	switch kind {
	case "catalog", "simple":
		var v *framework.Version
		var err error
		switch {
		case kind == "catalog":
			if meta.Family == nil {
				return nil, framework.Problems{{Pointer: "/family", Message: "a catalog import names its framework family"}}
			}
			v, err = framework.ParseCatalog(file, *meta.Family)
		case meta.Format == "csv":
			if meta.Family == nil {
				return nil, framework.Problems{{Pointer: "/family", Message: "a CSV import names its framework family and version"}}
			}
			v, err = framework.ParseSimpleCSV(file, framework.Meta{Family: *meta.Family, Label: meta.Label, Title: meta.Title, Published: meta.Published})
		default:
			v, err = framework.ParseSimple(file)
		}
		if err != nil {
			return nil, err
		}
		res := &Result{Version: v, Summary: map[string]any{"family": v.Family.Key, "version": v.Label, "requirements": len(v.Requirements)}}
		withdrawn := 0
		for _, r := range v.Requirements {
			if r.Withdrawn {
				withdrawn++
			}
		}
		res.Summary["withdrawn"] = withdrawn
		var since string
		if err := w.DB.QueryRow(ctx, "SELECT coalesce(framework.latest_version($1), '')", v.Family.Key).Scan(&since); err != nil {
			return nil, err
		}
		if since != "" {
			prev, err := w.version(ctx, v.Family.Key, since)
			if err != nil {
				return nil, err
			}
			if prev != nil {
				d := framework.Compare(prev, v)
				res.Diff = &Diff{Diff: d, Since: since}
				res.Summary["since"], res.Summary["added"], res.Summary["changed"], res.Summary["removed"] = since, len(d.Added), len(d.Changed), len(d.Withdrawn)
			}
		}
		return res, nil
	case "profile":
		if meta.Catalog == nil || meta.Key == "" {
			return nil, framework.Problems{{Pointer: "/catalog", Message: "a profile import names the catalog version it selects from and the baseline's key"}}
		}
		cat, err := w.version(ctx, meta.Catalog.Family, meta.Catalog.Version)
		if err != nil {
			return nil, err
		}
		if cat == nil {
			return nil, framework.Problems{{Pointer: "/catalog", Message: fmt.Sprintf("%s %s is not imported; import the catalog first", meta.Catalog.Family, meta.Catalog.Version)}}
		}
		lookup := func(string, *oscaltypes.Resource) (*framework.Import, error) {
			return &framework.Import{Catalog: cat}, nil
		}
		b, _, err := framework.ParseProfile(file, meta.Key, lookup)
		if err != nil {
			return nil, err
		}
		return &Result{Baseline: &Baseline{Baseline: *b, Version: *meta.Catalog},
			Summary: map[string]any{"baseline": b.Key, "family": meta.Catalog.Family, "version": meta.Catalog.Version, "requirements": len(b.Selected), "notes": b.Notes}}, nil
	}
	return nil, framework.Problems{{Pointer: "", Message: "unknown import kind " + kind}}
}

// NewClient is the risk service's River client for framework imports.
func NewClient(pool *pgxpool.Pool, w *Worker, logger *slog.Logger) (*river.Client[pgx.Tx], error) {
	ws := river.NewWorkers()
	river.AddWorker(ws, w)
	return river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues:  map[string]river.QueueConfig{Queue: {MaxWorkers: 1}},
		Workers: ws,
		Schema:  RiverSchema,
		Logger:  logger,
	})
}

// Enqueuer queues an import's job in the request's transaction.
func Enqueuer(c *river.Client[pgx.Tx]) func(context.Context, pgx.Tx, ImportArgs) error {
	return func(ctx context.Context, tx pgx.Tx, args ImportArgs) error {
		_, err := c.InsertTx(ctx, tx, args, nil)
		return err
	}
}
