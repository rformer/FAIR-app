package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io/fs"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/dbconn"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/profiles"
)

// F-015 T-10 (AC-05, AC-09, AC-10): package loading, offline import, seed.

// posturePool connects as app_posture, as the posture service does.
func (e *env) posturePool() *pgxpool.Pool {
	e.t.Helper()
	cc, err := dbconn.Config("development", "app_posture", e.secrets["app_posture"], "fair-test")
	if err != nil {
		e.t.Fatal(err)
	}
	cc.Database = e.db
	pc, err := pgxpool.ParseConfig("")
	if err != nil {
		e.t.Fatal(err)
	}
	pc.ConnConfig = cc
	pool, err := pgxpool.NewWithConfig(context.Background(), pc)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(pool.Close)
	return pool
}

// releaseFiles returns the embedded release: manifest.json and packages.
func releaseFiles(t *testing.T) (map[string][]byte, *profilepkg.Manifest) {
	t.Helper()
	dir, err := fs.Sub(profiles.Packages, "packages")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	entries, err := fs.ReadDir(dir, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		b, err := fs.ReadFile(dir, en.Name())
		if err != nil {
			t.Fatal(err)
		}
		files[en.Name()] = b
	}
	m, err := profilepkg.DecodeManifest(files["manifest.json"])
	if err != nil {
		t.Fatal(err)
	}
	return files, m
}

// variant returns a copy of an embedded package as a new version, with edit
// applied to its settings.
func variant(t *testing.T, files map[string][]byte, id, version string, edit func(s map[string]profilepkg.Setting)) []byte {
	t.Helper()
	p, err := profilepkg.Decode(files[profilepkg.FileName(id, "1.0.0")])
	if err != nil {
		t.Fatal(err)
	}
	p.Profile.Version = version
	if edit != nil {
		edit(p.Settings)
	}
	b, err := profilepkg.Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func byteaLiteral(b []byte) string {
	return "convert_to('" + strings.ReplaceAll(string(b), "'", "''") + "', 'UTF8')"
}

// The release's packages are loaded by iam migrate, insert-only and pinned
// by the digest the database computes itself.
func TestPosturePackagesLoadedAtMigrate(t *testing.T) {
	e := setup(t)
	files, m := releaseFiles(t)
	var want []string
	for _, p := range m.Packages {
		want = append(want, p.ID+"@"+p.Version)
	}
	got := slices.Sorted(slices.Values(e.install.Packages.Imported))
	if !slices.Equal(got, want) {
		t.Fatalf("first migrate imported %v, want %v", got, want)
	}
	for _, p := range m.Packages {
		row := e.adminQuery("SELECT kind || ':' || status || ':' || package_digest || ':' || (SELECT count(*) FROM posture.profile_value v WHERE v.profile_id = p.id AND v.version = p.version) FROM posture.profile p WHERE id = '" + p.ID + "' AND version = '" + p.Version + "'")
		if row != "builtin:approved:"+p.SHA256+":19" {
			t.Errorf("%s: %s", p.ID, row)
		}
	}
	if got := e.adminQuery(`SELECT default_value::text || ' ' || bound::text FROM posture.profile_value WHERE profile_id = 'enterprise-baseline' AND key = 'session.idle_timeout'`); got != `"15m0s" "30m0s"` {
		t.Errorf("enterprise idle timeout loaded as %s", got)
	}

	res, err := e.migrate("")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages.Imported) != 0 || len(res.Packages.Unchanged) != 3 {
		t.Fatalf("second migrate: %+v", res.Packages)
	}

	// Immutable: the same id and version with other bytes is refused.
	fed := profilepkg.FileName("fedramp-moderate", "1.0.0")
	changed := []byte(strings.Replace(string(files[fed]), `"title": "FedRAMP Moderate"`, `"title": "FedRAMP Moderate (edited)"`, 1))
	e.ownerFails("SELECT posture.sync_packages(ARRAY["+byteaLiteral(changed)+"])", "packages are immutable")

	// A registered setting's floor is re-checked on load.
	e.admin(e.db, `INSERT INTO posture.setting_def (key, type, direction, enum_order, hard_floor, owner_feature, registered_version)
		VALUES ('tls.min_version', 'enum', 'ordered', ARRAY['1.0','1.1','1.2','1.3'], '"1.2"', 'F-001', '1')`)
	weak := variant(t, files, "fedramp-moderate", "9.9.9", func(s map[string]profilepkg.Setting) {
		x := s["tls.min_version"]
		x.Bound, x.Default = "1.1", "1.1"
		s["tls.min_version"] = x
	})
	e.ownerFails("SELECT posture.sync_packages(ARRAY["+byteaLiteral(weak)+"])", "hard floor")
	e.ownerFails("SELECT posture.sync_packages(ARRAY["+byteaLiteral([]byte(`{"format": "v0"}`))+"])", "not a fair-profile-package/v1")

	// Only the release path (fair_owner) may call it.
	e.wantState("app_posture", "PERFORM posture.sync_packages('{}')", "42501")
	e.wantState("app_rw", "PERFORM posture.import_package('\\x00')", "42501")
}

type failingEmitter struct{}

func (failingEmitter) Emit(context.Context, audit.Event) error { return errors.New("audit sink down") }

// Verification for T-10: the seed is audited, and fails closed with the audit.
func TestPostureSeed(t *testing.T) {
	e := setup(t)
	pool := e.posturePool()
	ctx := context.Background()
	empty := func() {
		t.Helper()
		if got := e.adminQuery("SELECT (SELECT count(*) FROM posture.active_profile) + (SELECT count(*) FROM posture.setting_value)"); got != "0" {
			t.Fatalf("a failed seed left %s rows", got)
		}
	}

	if _, err := posture.Seed(ctx, pool, audit.NewMemory(), "system:installer", posture.DefaultProfile, ""); err == nil || !strings.Contains(err.Error(), "MAC key") {
		t.Fatalf("seed without a MAC key: %v", err)
	}
	empty()
	addMACKey(e, "k1")
	if _, err := posture.Seed(ctx, pool, failingEmitter{}, "system:installer", posture.DefaultProfile, ""); err == nil || !strings.Contains(err.Error(), "audit sink down") {
		t.Fatalf("seed with a failing audit sink: %v", err)
	}
	empty()
	if _, err := posture.Seed(ctx, pool, audit.NewMemory(), "system:installer", "no-such-profile", ""); err == nil {
		t.Fatal("seeded from an unknown profile")
	}
	empty()

	mem := audit.NewMemory()
	s, err := posture.Seed(ctx, pool, mem, "system:installer", posture.DefaultProfile, "")
	if err != nil {
		t.Fatal(err)
	}
	_, m := releaseFiles(t)
	var digest string
	for _, p := range m.Packages {
		if p.ID == posture.DefaultProfile {
			digest = p.SHA256
		}
	}
	if s.Version != "1.0.0" || s.Settings != 19 || s.Digest != digest {
		t.Fatalf("seeded %+v", s)
	}
	ev := mem.OfType("posture.seeded")
	if len(ev) != 1 || ev[0].Severity != audit.SeverityHigh || ev[0].Actor != "system:installer" ||
		ev[0].Attributes["package_digest"] != digest || ev[0].Attributes["settings"] != "19" {
		t.Fatalf("audit events %+v", mem.Events())
	}
	if got := e.adminQuery(`SELECT profile_id || '@' || version FROM posture.active_profile`); got != "fedramp-moderate@1.0.0" {
		t.Fatalf("active profile %s", got)
	}
	if got := e.adminQuery(`SELECT count(*) FROM posture.setting_value s JOIN posture.profile_value v
		ON v.profile_id = 'fedramp-moderate' AND v.key = s.key AND v.default_value = s.value
		WHERE s.bu_id IS NULL AND s.source = 'profile'`); got != "19" {
		t.Fatalf("%s of 19 settings seeded with the profile default", got)
	}
	if got := e.adminQuery("SELECT status FROM posture.profile WHERE id = 'fedramp-moderate'"); got != "active" {
		t.Fatalf("seeded profile status %s", got)
	}
	if got := mustAs(e, "app_posture", "SELECT count(*) FROM posture.mac_mismatches()"); got != "0" {
		t.Fatalf("%s MAC mismatches after seeding", got)
	}
	if _, err := posture.Seed(ctx, pool, audit.NewMemory(), "system:installer", "cmmc-l2-r2", ""); err == nil || !strings.Contains(err.Error(), "already seeded") {
		t.Fatalf("second seed: %v", err)
	}
}

// Verification for T-10: a signed release imports offline; unsigned or
// tampered packages are refused and load nothing.
func TestPostureImportSigned(t *testing.T) {
	e := setup(t)
	pool := e.posturePool()
	ctx := context.Background()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	files, m := releaseFiles(t)

	// A later release adds fedramp-moderate 1.1.0 alongside the shipped packages.
	newer := variant(t, files, "fedramp-moderate", "1.1.0", nil)
	newFile := profilepkg.FileName("fedramp-moderate", "1.1.0")
	files[newFile] = newer
	m.Packages = append(m.Packages, profilepkg.ManifestEntry{File: newFile, ID: "fedramp-moderate", Version: "1.1.0", SHA256: profilepkg.Digest(newer)})
	if files["manifest.json"], err = profilepkg.Encode(m); err != nil {
		t.Fatal(err)
	}
	sigs, err := profilepkg.SignRelease(key, "manifest.json", files)
	if err != nil {
		t.Fatal(err)
	}
	signed := maps.Clone(files)
	maps.Copy(signed, sigs)

	count := func() string { return e.adminQuery("SELECT count(*) FROM posture.profile") }
	refused := map[string]map[string][]byte{}
	tampered := maps.Clone(signed)
	tampered[newFile] = []byte(strings.Replace(string(newer), `"bound": "15m0s"`, `"bound": "1h0m0s"`, 1))
	refused["tampered package"] = tampered
	unsigned := maps.Clone(signed)
	delete(unsigned, newFile+".sig")
	refused["unsigned package"] = unsigned
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherSigs, _ := profilepkg.SignRelease(other, "manifest.json", files)
	forged := maps.Clone(files)
	maps.Copy(forged, otherSigs)
	refused["signed by another key"] = forged
	for name, f := range refused {
		mem := audit.NewMemory()
		if _, err := posture.Import(ctx, pool, mem, &key.PublicKey, "system:installer", f); err == nil {
			t.Errorf("%s: imported", name)
		}
		if c := count(); c != "3" || len(mem.Events()) != 0 {
			t.Errorf("%s: %s profiles, %d audit events after a refused import", name, c, len(mem.Events()))
		}
	}

	mem := audit.NewMemory()
	res, err := posture.Import(ctx, pool, mem, &key.PublicKey, "system:installer", signed)
	if err != nil {
		t.Fatal(err)
	}
	var outcomes []string
	for _, r := range res {
		outcomes = append(outcomes, r.Profile+"@"+r.Version+":"+r.Outcome)
	}
	slices.Sort(outcomes)
	if want := []string{"cmmc-l2-r2@1.0.0:unchanged", "enterprise-baseline@1.0.0:unchanged", "fedramp-moderate@1.0.0:unchanged", "fedramp-moderate@1.1.0:imported"}; !slices.Equal(outcomes, want) {
		t.Fatalf("outcomes %v", outcomes)
	}
	if ev := mem.OfType("posture.package_imported"); len(ev) != 1 || ev[0].Attributes["version"] != "1.1.0" {
		t.Fatalf("audit events %+v", mem.Events())
	}
	if got := e.adminQuery("SELECT status || ':' || package_digest FROM posture.profile WHERE id = 'fedramp-moderate' AND version = '1.1.0'"); got != "approved:"+profilepkg.Digest(newer) {
		t.Fatalf("imported profile %s", got)
	}

	// The import path trusts the posture service for the signature, but the
	// database still enforces registered floors.
	e.admin(e.db, `INSERT INTO posture.setting_def (key, type, direction, enum_order, hard_floor, owner_feature, registered_version)
		VALUES ('tls.min_version', 'enum', 'ordered', ARRAY['1.0','1.1','1.2','1.3'], '"1.2"', 'F-001', '1')`)
	weak := variant(t, files, "fedramp-moderate", "6.6.6", func(s map[string]profilepkg.Setting) {
		x := s["tls.min_version"]
		x.Bound, x.Default = "1.0", "1.0"
		s["tls.min_version"] = x
	})
	e.wantState("app_posture", "PERFORM posture.import_package("+byteaLiteral(weak)+")", "PF001")
}
