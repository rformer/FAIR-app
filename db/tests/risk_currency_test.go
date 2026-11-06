package tests

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	risksvc "github.com/rformer/fair-app/internal/risk"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
	"github.com/rformer/fair-app/pkg/audit"
)

// F-003 T-04 (F-003-AC-07; design §3.4): the installation currency is set at
// install, audited, and fixed once amounts are stored in it.
func TestRiskCurrency(t *testing.T) {
	r := riskFixture(t)
	ctx := context.Background()
	conn, err := pgx.ConnectConfig(ctx, migratorConfig(t, r.env))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	c, err := audit.DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	emit := audit.WithTrail(audit.Validating{Next: audit.NewMemory(), Catalog: c}, audit.Trail{DB: conn, Role: "fair_owner"})
	set := func(code string) (string, error) { return risksvc.SetCurrency(ctx, conn, emit, code, "installer") }
	events := func() string {
		return r.adminQuery(`SELECT coalesce(string_agg((body -> 'attributes' ->> 'previous') || '>' || (body -> 'attributes' ->> 'currency'), ',' ORDER BY id), '')
			FROM audit.intake WHERE body ->> 'type' = 'risk.currency_set'`)
	}

	if got, err := risksvc.Currency(ctx, r.appPool()); err != nil || got != "" {
		t.Fatalf("before install: %q %v", got, err)
	}
	for _, bad := range []string{"us", "USDX", "12A", ""} {
		if _, err := set(bad); err == nil {
			t.Errorf("currency %q accepted", bad)
		}
	}
	if _, err := risksvc.SetCurrency(ctx, conn, emit, "USD", " "); err == nil {
		t.Error("no operator accepted")
	}
	if prev, err := set("usd"); err != nil || prev != "" {
		t.Fatalf("first set: %q %v", prev, err)
	}
	if prev, err := set("USD"); err != nil || prev != "USD" {
		t.Fatalf("same again: %q %v", prev, err)
	}
	// Before any amount is stored it may change; amounts given as a basis
	// in words are not amounts.
	asset := modeltest.Asset()
	delete(asset, "value")
	asset["value_basis"] = "Replacement cost."
	r.create(t, "analyst", "asset", r.bu["A"], asset)
	if prev, err := set("EUR"); err != nil || prev != "USD" {
		t.Fatalf("change before amounts: %q %v", prev, err)
	}
	if got := events(); got != ">USD,USD>EUR" {
		t.Fatalf("events: %q", got)
	}
	if got, err := risksvc.Currency(ctx, r.appPool()); err != nil || got != "EUR" {
		t.Fatalf("read by app_rw: %q %v", got, err)
	}
	// Once an amount is stored, in any BU, the currency is fixed (PF019),
	// even where the installer's own context sees nothing.
	r.create(t, "mallory", "loss_profile", r.bu["B"], modeltest.LossProfile())
	if _, err := set("GBP"); !strings.Contains(pgCode(err), "PF019") {
		t.Fatalf("change after amounts: %s", pgCode(err))
	}
	if prev, err := set("EUR"); err != nil || prev != "EUR" {
		t.Fatalf("the same code after amounts: %q %v", prev, err)
	}
	if got := events(); got != ">USD,USD>EUR" {
		t.Fatalf("events after: %q", got)
	}
	// Only the installer sets it.
	for _, role := range []string{"app_rw", "app_posture", "app_audit"} {
		r.mustFail(role, "SELECT risk.set_currency('JPY', 'x')", "permission denied")
		r.mustFail(role, "SELECT risk.has_magnitudes()", "permission denied")
	}
}
