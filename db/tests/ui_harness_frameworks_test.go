package tests

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/frameworkapi"
	"github.com/rformer/fair-app/internal/reason"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-013 T-10: frameworks in the UI harness. The framework API is mounted
// beside the risk service's other APIs as cmd/risk does, with its import
// worker; the shipped frameworks come with the migration.

// mountHarnessFrameworks mounts the framework API on mux and starts its
// import worker; the returned function stops it.
func mountHarnessFrameworks(t *testing.T, mux *http.ServeMux, rp *pgxpool.Pool, keys *authz.LocalKeys, rule reason.Settings) func() {
	t.Helper()
	w := &frameworkapi.Worker{DB: rp}
	c, err := frameworkapi.NewClient(rp, w, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	api := &frameworkapi.API{DB: rp, Enqueue: frameworkapi.Enqueuer(c), Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: rp}), Reasons: rule}
	h := api.Handler(keys, nil)
	for _, prefix := range frameworkapi.Prefixes {
		mux.Handle(prefix, h)
		mux.Handle(prefix+"/", h)
	}
	for _, pattern := range frameworkapi.Patterns {
		mux.Handle(pattern, h)
	}
	return func() { _ = c.Stop(context.Background()) }
}

// seedFrameworks (F-013 T-10): "riskanalyst" (Risk Analyst at the root)
// keeps a control "Account management reviews" at the root, in place and
// mapped in full to NIST SP 800-53 5.2.0 AC-2, used by no scenario (so the
// seeded scenarios could use it), and citing "NIST SP 800-53r5" "AC-02(01)"
// as a plain reference (a suggested mapping in its editor).
func seedFrameworks(t *testing.T, e *env, keys *authz.LocalKeys, url string) {
	t.Helper()
	root := e.adminQuery("SELECT id FROM iam.bu WHERE code = 'ENTERPRISE'")
	ea := &riskAPIEnv{riskEnv: riskEnv{e, map[string]string{"ENTERPRISE": root}}, url: url, keys: keys, n: 700000}
	d := modeltest.Control()
	d["name"] = "Account management reviews"
	d["references"] = []any{map[string]any{"framework": "NIST SP 800-53r5", "identifier": "AC-02(01)"}}
	d["mappings"] = []any{map[string]any{"framework": "nist-800-53", "version": "5.2.0", "requirement": "ac-2", "strength": "full",
		"rationale": "Quarterly reviews of every account's access."}}
	d["implementation"] = map[string]any{"status": "in_place", "assessed_on": time.Now().UTC().Format(time.DateOnly)}
	if got := ea.call(t, "POST", "riskanalyst", "/api/v1/controls", map[string]any{"bu_id": root, "document": d, "change_note": "Mapped to AC-2"}); got.code != 201 {
		t.Fatalf("seed a mapped control: %d %s", got.code, got.raw)
	}
	t.Log("frameworks seeded")
}
