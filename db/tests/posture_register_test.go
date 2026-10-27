package tests

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-12 (AC-01): startup registration.

func f001Client(e *env, extra ...settings.Def) *settings.Client {
	e.t.Helper()
	c := settings.NewClient(settings.ClientOptions{Source: settings.DBSource{DB: e.appPool()}, Service: "iam"})
	if err := c.Register(append(settings.F001Defs(), extra...)...); err != nil {
		e.t.Fatal(err)
	}
	return c
}

func defWith(key string, edit func(d *settings.Def)) settings.Def {
	for _, d := range settings.F001Defs() {
		if d.Key == key {
			edit(&d)
			return d
		}
	}
	panic(key)
}

// Verification for T-12: a service refuses to start with a key the active
// profile does not bind; with every key bound it starts, and its
// definitions are recorded.
func TestPostureStartupRegistration(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	reg := settings.DBRegistrar{DB: e.appPool()}

	if err := f001Client(e).Start(ctx, reg, "F-001", "1"); !errors.Is(err, settings.ErrStartup) || !strings.Contains(err.Error(), "not seeded") {
		t.Fatalf("start before the seed: %v", err)
	}
	addMACKey(e, "k1")
	if _, err := posture.Seed(ctx, e.posturePool(), audit.NewMemory(), "system:installer", posture.DefaultProfile, ""); err != nil {
		t.Fatal(err)
	}

	unbound := settings.Def{Key: "auth.passkeys_required", Kind: settings.KindBool, Direction: settings.TrueIsStricter}
	err := f001Client(e, unbound).Start(ctx, reg, "F-001", "1")
	if !errors.Is(err, settings.ErrStartup) || !strings.Contains(err.Error(), "auth.passkeys_required") || !strings.Contains(err.Error(), "not bound by the active profile") {
		t.Fatalf("start with an unbound key: %v", err)
	}
	if n := e.adminQuery("SELECT count(*) FROM posture.setting_def"); n != "0" {
		t.Fatalf("a refused start left %s definitions", n)
	}

	c := f001Client(e)
	if err := c.Start(ctx, reg, "F-001", "1"); err != nil {
		t.Fatalf("start: %v", err)
	}
	if d, err := c.Duration(settings.KeySessionIdleTimeout, ""); err != nil || d.Minutes() != 15 {
		t.Fatalf("after start: %v %v", d, err)
	}
	got := e.adminQuery(`SELECT count(*) || ':' ||
		(SELECT hard_floor::text || ':' || hard_floor_families::text FROM posture.setting_def WHERE key = 'fips.enabled') || ':' ||
		(SELECT hard_floor::text FROM posture.setting_def WHERE key = 'tls.min_version') || ':' ||
		(SELECT array_to_string(params, ',') FROM posture.setting_def WHERE key = 'session.idle_timeout')
		FROM posture.setting_def WHERE owner_feature = 'F-001'`)
	if got != `20:true:{fedramp,cmmc}:"1.2":ac-11_odp.02` {
		t.Fatalf("registered definitions: %s", got)
	}
	// Restarting (another replica, or the same service later) is idempotent.
	if err := f001Client(e).Start(ctx, reg, "F-001", "2"); err != nil {
		t.Fatalf("restart: %v", err)
	}
	// A registered change can now go through the write path.
	postureAdmins(e)
	e.wantStateAs("app_posture", "admin", "PERFORM "+request(settings.KeyAuthLockoutThreshold, "NULL", "2", "NULL"), "ok")
}

// Registration is open to every service, so it can never weaken anything.
func TestPostureRegistrationCannotWeaken(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	reg := settings.DBRegistrar{DB: e.appPool()}
	addMACKey(e, "k1")
	if _, err := posture.Seed(ctx, e.posturePool(), audit.NewMemory(), "system:installer", posture.DefaultProfile, ""); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(ctx, "F-001", "1", settings.F001Defs()); err != nil {
		t.Fatal(err)
	}
	refused := map[string]struct {
		owner string
		def   settings.Def
		want  string
	}{
		"direction flipped": {"F-001", defWith(settings.KeySessionIdleTimeout, func(d *settings.Def) { d.Direction = settings.HigherIsStricter }), "PF004"},
		"made BU-scopable":  {"F-001", defWith(settings.KeySessionIdleTimeout, func(d *settings.Def) { d.BUScopable = true }), "PF004"},
		"enum order changed": {"F-001", defWith(settings.KeyTLSMinVersion, func(d *settings.Def) {
			d.Order = []string{"1.0", "1.1", "1.3", "1.2"}
		}), "PF004"},
		"another feature": {"F-002", defWith(settings.KeySessionIdleTimeout, func(*settings.Def) {}), "PF004"},
		"floor lowered":   {"F-001", defWith(settings.KeyTLSMinVersion, func(d *settings.Def) { d.Floor = "1.1" }), "PF001"},
		"floor removed":   {"F-001", defWith(settings.KeyAuditEnabled, func(d *settings.Def) { d.Floor = nil }), "PF001"},
		"floor narrowed": {"F-001", defWith(settings.KeyFIPSEnabled, func(d *settings.Def) {
			d.FloorFamilies = []settings.Family{settings.FamilyFedRAMP}
		}), "PF001"},
		"all-family floor narrowed": {"F-001", defWith(settings.KeyAuditEnabled, func(d *settings.Def) {
			d.FloorFamilies = []settings.Family{settings.FamilyFedRAMP}
		}), "PF001"},
		// Tightening is allowed only if the active profile still complies.
		"floor above the active bound": {"F-001", defWith(settings.KeyTLSMinVersion, func(d *settings.Def) { d.Floor = "1.3" }), "PF001"},
	}
	for name, c := range refused {
		err := reg.Register(ctx, c.owner, "2", []settings.Def{c.def})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %s", name, err, c.want)
		}
	}
	if got := e.adminQuery(`SELECT hard_floor::text FROM posture.setting_def WHERE key = 'tls.min_version'`); got != `"1.2"` {
		t.Fatalf("tls floor is now %s", got)
	}

	// Tightening that the active profile meets is accepted: FIPS floor for every family.
	if err := reg.Register(ctx, "F-001", "2", []settings.Def{defWith(settings.KeyFIPSEnabled, func(d *settings.Def) { d.FloorFamilies = nil })}); err != nil {
		t.Fatalf("widening the FIPS floor: %v", err)
	}

	// A value in force that the definition rejects blocks registration.
	e.admin(e.db, `UPDATE posture.setting_value SET value = '"three"' WHERE key = 'auth.lockout_threshold'`)
	if err := reg.Register(ctx, "F-001", "2", settings.F001Defs()); err == nil || !strings.Contains(err.Error(), "PF004") {
		t.Fatalf("registration over an invalid value in force: %v", err)
	}

	e.wantState("app_engine", "PERFORM posture.register_settings('F-001', '1', '[]')", "42501")
}
