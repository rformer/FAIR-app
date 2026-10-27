package tests

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/approvals"
	"github.com/rformer/fair-app/internal/oscal"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-20 (AC-14, AC-15): custom profile versions, diffs, base updates,
// and export/import.

// approvedCustom creates ACME FedRAMP version 1 from fedramp-moderate 1.1.0:
// idle timeout tightened to 10m, lockout loosened to 5 (bound 6) with a
// justification; submitted and approved by the second admin.
func approvedCustom(t *testing.T, e *env, pr posture.Profiles) {
	t.Helper()
	ctx := context.Background()
	admin := e.principal("admin")
	if _, err := pr.Create(ctx, admin, settings.ProfileFedRAMPModerate, "1.1.0", "acme", "ACME FedRAMP"); err != nil {
		t.Fatal(err)
	}
	if _, err := pr.Edit(ctx, admin, "acme", "1", settings.KeySessionIdleTimeout, j(`"10m0s"`), j(`"10m0s"`), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := pr.Edit(ctx, admin, "acme", "1", settings.KeyAuthLockoutThreshold, j(`5`), j(`6`), "shared kiosks"); err != nil {
		t.Fatal(err)
	}
	approve(t, e, pr, "acme", "1")
}

func approve(t *testing.T, e *env, pr posture.Profiles, id, version string) {
	t.Helper()
	ctx := context.Background()
	req, err := pr.Submit(ctx, e.principal("admin"), id, version)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (approvals.Service{DB: e.appPool()}).Decide(ctx, e.principal("admin2"), req, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := pr.Approve(ctx, id, version); err != nil {
		t.Fatal(err)
	}
}

// loadBase loads fedramp-moderate 1.2.0 through the release path: idle
// timeout relaxed to 20m (weaker than ACME's 10m), lockout tightened to 4
// and token lifetime tightened to 30 days (stricter than ACME).
func loadBase(t *testing.T, e *env) {
	t.Helper()
	files, _ := releaseFiles(t)
	b := variant(t, files, settings.ProfileFedRAMPModerate, "1.2.0", func(s map[string]profilepkg.Setting) {
		set := func(key string, def, bound any) {
			x := s[key]
			x.Default, x.Bound = def, bound
			s[key] = x
		}
		set(settings.KeySessionIdleTimeout, "20m0s", "20m0s")
		set(settings.KeyAuthLockoutThreshold, 4, 4)
		set(settings.KeyTokenMaxLifetime, "720h0m0s", "720h0m0s")
	})
	e.mustOwner("SELECT posture.sync_packages(ARRAY[" + byteaLiteral(b) + "])")
}

func value(e *env, id, version, key string) string {
	return e.adminQuery("SELECT default_value::text || '/' || bound::text || ':' || loosened || ':' || coalesce(justification, '-') FROM posture.profile_value WHERE profile_id = '" +
		id + "' AND version = '" + version + "' AND key = '" + key + "'")
}

// Verification for T-20 (upgrade simulation): a weaker base is pinned, a
// stricter one proposed; nothing in the custom profile silently weakens.
func TestBaseUpdatePinsAndProposes(t *testing.T) {
	e, _, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	mem := audit.NewMemory()
	pr := posture.Profiles{DB: e.appPool(), Audit: mem}
	admin := e.principal("admin")
	approvedCustom(t, e, pr)
	loadBase(t, e)

	// AC-15: the effect on each derived profile, before anything changes.
	effects, err := pr.BaseUpdateEffects(ctx, admin, settings.ProfileFedRAMPModerate, "1.2.0")
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]string{}
	for _, f := range effects {
		if f.ProfileID != "acme" || f.Version != "1" {
			t.Fatalf("effect on %s %s", f.ProfileID, f.Version)
		}
		actions[f.Key] = f.Action
	}
	if actions[settings.KeySessionIdleTimeout] != "pinned" || actions[settings.KeyAuthLockoutThreshold] != "proposed" ||
		actions[settings.KeyTokenMaxLifetime] != "proposed" || actions[settings.KeyAuditEnabled] != "unchanged" || len(actions) != 20 {
		t.Fatalf("effects %v", actions)
	}

	v2, err := pr.Rebase(ctx, admin, "acme", "1", "1.2.0")
	if err != nil || v2 != "2" {
		t.Fatalf("rebase: %q %v", v2, err)
	}
	// Pinned: ACME keeps 10m although the base relaxed to 20m.
	if got := value(e, "acme", "2", settings.KeySessionIdleTimeout); got != `"10m0s"/"10m0s":false:-` {
		t.Fatalf("idle %s", got)
	}
	// Proposed: ACME keeps its values; still loosened against the new base, justification kept.
	if got := value(e, "acme", "2", settings.KeyAuthLockoutThreshold); got != `5/6:true:shared kiosks` {
		t.Fatalf("lockout %s", got)
	}
	// Proposed and now looser than the base with no justification: submission is blocked.
	if got := value(e, "acme", "2", settings.KeyTokenMaxLifetime); got != `"2160h0m0s"/"2160h0m0s":true:-` {
		t.Fatalf("token %s", got)
	}
	if _, err := pr.Submit(ctx, admin, "acme", "2"); !errors.Is(err, posture.ErrInvalidValue) || !strings.Contains(err.Error(), "token.max_lifetime: the base update proposes") {
		t.Fatalf("submit with an unresolved proposal: %v", err)
	}
	// The admin adopts the proposal.
	if loose, err := pr.Edit(ctx, admin, "acme", "2", settings.KeyTokenMaxLifetime, j(`"720h0m0s"`), j(`"720h0m0s"`), ""); err != nil || loose {
		t.Fatalf("adopt the proposal: %v %v", loose, err)
	}
	approve(t, e, pr, "acme", "2")

	// AC-14: versions diff key by key.
	diff, err := pr.Diff(ctx, admin, "acme", "1", "acme", "2")
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string]string{}
	for _, r := range diff {
		changes[r.Key] = r.Change
	}
	if changes[settings.KeySessionIdleTimeout] != "unchanged" || changes[settings.KeyTokenMaxLifetime] != "tighten" ||
		changes[settings.KeyAuthLockoutThreshold] != "unchanged" {
		t.Fatalf("diff %v", changes)
	}
	// Nothing in version 2 is weaker than in version 1.
	for k, c := range changes {
		if c == "loosen" || c == "mixed" {
			t.Errorf("%s silently weakened (%s)", k, c)
		}
	}
	if got := e.adminQuery("SELECT base_version || ':' || status FROM posture.profile WHERE id = 'acme' AND version = '2'"); got != "1.2.0:approved" {
		t.Fatalf("version 2 %s", got)
	}
	// A rebased version no longer shows up in the effects of that base version.
	if effects, _ := pr.BaseUpdateEffects(ctx, admin, settings.ProfileFedRAMPModerate, "1.2.0"); len(effects) != 20 {
		t.Fatalf("%d effects; only version 1 still derives from 1.1.0", len(effects))
	}
	if ev := mem.OfType("profile.rebased"); len(ev) != 1 {
		t.Fatalf("rebase audit %+v", ev)
	}
}

func TestCustomProfileVersions(t *testing.T) {
	e, _, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	pr := posture.Profiles{DB: e.appPool(), Audit: audit.NewMemory()}
	admin := e.principal("admin")
	approvedCustom(t, e, pr)
	v, err := pr.NewVersion(ctx, admin, "acme", "1")
	if err != nil || v != "2" {
		t.Fatalf("new version: %q %v", v, err)
	}
	if got := value(e, "acme", "2", settings.KeyAuthLockoutThreshold); got != `5/6:true:shared kiosks` {
		t.Fatalf("copied value %s", got)
	}
	if _, err := pr.NewVersion(ctx, admin, "acme", "1"); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("second draft: %v", err)
	}
	// Version 1 is immutable.
	if _, err := pr.Edit(ctx, admin, "acme", "1", settings.KeySessionIdleTimeout, j(`"5m0s"`), j(`"5m0s"`), ""); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("edit of an approved version: %v", err)
	}
	if _, err := pr.Diff(ctx, e.principal("auditor"), "acme", "1", "acme", "2"); !errors.Is(err, posture.ErrNotPermitted) {
		t.Fatalf("auditor diff: %v", err)
	}
}

func TestCustomProfileExportImport(t *testing.T) {
	e, _, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	mem := audit.NewMemory()
	pr := posture.Profiles{DB: e.appPool(), Audit: mem}
	admin := e.principal("admin")
	approvedCustom(t, e, pr)
	same := func(id string) {
		t.Helper()
		for _, k := range []string{settings.KeySessionIdleTimeout, settings.KeyAuthLockoutThreshold, settings.KeyTokenMaxLifetime} {
			if a, b := value(e, "acme", "1", k), value(e, id, "1", k); a != b {
				t.Errorf("%s %s: %s, original %s", id, k, b, a)
			}
		}
		if got := e.adminQuery("SELECT status || ':' || label_deviates FROM posture.profile WHERE id = '" + id + "'"); got != "draft:true" {
			t.Errorf("%s imported as %s", id, got)
		}
	}

	// JSON round trip.
	js, err := pr.ExportJSON(ctx, admin, "acme", "1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pr.ImportJSON(ctx, admin, "acme-json", js); err != nil {
		t.Fatal(err)
	}
	same("acme-json")

	// OSCAL: a valid profile with set-parameters; our own export round-trips through back-matter.
	ox, err := pr.ExportOSCAL(ctx, admin, "acme", "1")
	if err != nil {
		t.Fatal(err)
	}
	if kind, err := oscal.Validate(ox); err != nil || kind != oscal.Profile {
		t.Fatalf("OSCAL export: %v %v", kind, err)
	}
	if !strings.Contains(string(ox), `"param-id": "ac-11_odp.02"`) || !strings.Contains(string(ox), `"10m0s"`) ||
		!strings.Contains(string(ox), "Deviates from FedRAMP Moderate") {
		t.Fatal("OSCAL export lacks the set-parameters or the deviation label")
	}
	if _, err := pr.ImportOSCAL(ctx, admin, "acme-oscal", ox); err != nil {
		t.Fatal(err)
	}
	same("acme-oscal")

	// Without the embedded native JSON, set-parameters map to the settings that implement them.
	var doc map[string]any
	_ = json.Unmarshal(ox, &doc)
	delete(doc["profile"].(map[string]any), "back-matter")
	bare, _ := json.Marshal(doc)
	if _, err := pr.ImportOSCAL(ctx, admin, "acme-params", bare); err != nil {
		t.Fatal(err)
	}
	if got := value(e, "acme-params", "1", settings.KeySessionIdleTimeout); got != `"10m0s"/"10m0s":false:-` {
		t.Fatalf("idle from set-parameters: %s", got)
	}
	if got := value(e, "acme-params", "1", settings.KeyAuthLockoutThreshold); got != `5/6:true:shared kiosks` {
		t.Fatalf("lockout from set-parameters: %s", got)
	}
	if len(mem.OfType("profile.imported")) != 3 {
		t.Fatalf("import audit %+v", mem.OfType("profile.imported"))
	}

	// Refused imports create nothing.
	bad := map[string]func() error{
		"not a document": func() error { _, err := pr.ImportJSON(ctx, admin, "x1", []byte(`{"format":"v0"}`)); return err },
		"below the floor": func() error {
			b := strings.Replace(string(js), `"bound": "1.2"`, `"bound": "1.1"`, 1)
			_, err := pr.ImportJSON(ctx, admin, "x2", []byte(b))
			return err
		},
		"loosened without justification": func() error {
			b := strings.Replace(string(js), `"justification": "shared kiosks"`, `"justification": ""`, 1)
			_, err := pr.ImportJSON(ctx, admin, "x3", []byte(b))
			return err
		},
		"unknown setting": func() error {
			b := strings.Replace(string(js), `"settings": {`, `"settings": {"no.such_setting": {"default": 1, "bound": 1},`, 1)
			_, err := pr.ImportJSON(ctx, admin, "x4", []byte(b))
			return err
		},
		"unmapped parameter": func() error {
			b := strings.Replace(string(bare), `"ac-11_odp.02"`, `"zz-99_odp.01"`, 1)
			_, err := pr.ImportOSCAL(ctx, admin, "x5", []byte(b))
			return err
		},
		"no permission": func() error { _, err := pr.ImportJSON(ctx, e.principal("auditor"), "x6", js); return err },
	}
	for name, f := range bad {
		if err := f(); !errors.Is(err, posture.ErrImport) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := e.adminQuery("SELECT count(*) FROM posture.profile WHERE id LIKE 'x%'"); n != "0" {
		t.Fatalf("refused imports left %s profiles", n)
	}
	if _, err := pr.ExportJSON(ctx, admin, settings.ProfileFedRAMPModerate, "1.1.0"); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("export of a built-in profile: %v", err)
	}
}
