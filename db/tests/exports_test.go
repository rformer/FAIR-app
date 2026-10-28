package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/oscal"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-35 (AC-47; design §6.9 integrity): exports are signed and
// timestamped, recorded with their digest and audited, reproducible from
// the record, and refused once the record no longer reproduces them.
func TestExportsSignedRecordedReproducible(t *testing.T) {
	ae := apiFixture(t, settings.ProfileEnterpriseBaseline)
	e := ae.e
	str := func(r apiResp, k string) string { s, _ := r.body[k].(string); return s }

	// Permissions: posture.view to see the API, posture.export to export.
	if r := ae.call(t, "nobody", "POST", "/exports", "auto", map[string]any{"kind": "assessment_results"}); r.code != 404 {
		t.Fatalf("without posture.view: %d %s", r.code, r.raw)
	}
	if r := ae.call(t, "auditor", "POST", "/exports", "auto", map[string]any{"kind": "assessment_results"}); r.code != 403 {
		t.Fatalf("without posture.export: %d %s", r.code, r.raw)
	}
	if r := ae.call(t, "admin", "POST", "/exports", "auto", map[string]any{"kind": "report"}); r.code != 400 {
		t.Fatalf("unknown kind: %d", r.code)
	}
	// Nothing open: no POA&M.
	if r := ae.call(t, "admin", "POST", "/exports", "auto", map[string]any{"kind": "poam"}); r.code != 409 || str(r, "error") != "nothing_open" {
		t.Fatalf("POA&M with nothing open: %d %s", r.code, r.raw)
	}

	// Export: signed, timestamped, valid OSCAL, recorded and audited.
	created := ae.call(t, "admin", "POST", "/exports", "auto", map[string]any{"kind": "assessment_results"})
	if created.code != 201 {
		t.Fatalf("export: %d %s", created.code, created.raw)
	}
	id := str(created, "export_id")
	if loc := created.hdr.Get("Location"); !strings.HasSuffix(loc, "/exports/"+id) {
		t.Errorf("Location %q", loc)
	}
	doc, stmt, sig := []byte(str(created, "document")), []byte(str(created, "statement")), str(created, "signature")
	if kind, err := oscal.Validate(doc); err != nil || kind != oscal.AssessmentResults {
		t.Fatalf("document: %v %v", kind, err)
	}
	if err := posture.VerifyExport(&ae.exportKey.PublicKey, doc, stmt, sig); err != nil {
		t.Fatalf("signature: %v", err)
	}
	for _, field := range []string{`"created_at"`, `"as_of"`, `"document_sha256":"` + str(created, "document_sha256") + `"`} {
		if !strings.Contains(string(stmt), field) {
			t.Errorf("the signed statement lacks %s: %s", field, stmt)
		}
	}
	ev := ae.mem.OfType(posture.EventExported)
	if len(ev) != 1 || ev[0].Severity != audit.SeverityHigh || ev[0].Attributes["document_sha256"] != str(created, "document_sha256") ||
		ev[0].Attributes["export_id"] != id {
		t.Fatalf("audit: %+v", ev)
	}
	if got := e.adminQuery("SELECT document_digest FROM posture.export_record WHERE id = '" + id + "'"); got != str(created, "document_sha256") {
		t.Fatalf("recorded digest %q", got)
	}
	// A verifier refuses another key, another document and another statement.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := posture.VerifyExport(&other.PublicKey, doc, stmt, sig); !errors.Is(err, posture.ErrExportSignature) {
		t.Errorf("another key: %v", err)
	}
	if err := posture.VerifyExport(&ae.exportKey.PublicKey, append(doc, ' '), stmt, sig); !errors.Is(err, posture.ErrExportSignature) {
		t.Errorf("another document: %v", err)
	}
	if err := posture.VerifyExport(&ae.exportKey.PublicKey, doc, []byte(strings.Replace(string(stmt), "assessment_results", "poam", 1)), sig); !errors.Is(err, posture.ErrExportSignature) {
		t.Errorf("another statement: %v", err)
	}

	// Re-generation gives the identical digest: fetched, and reproduced by as_of.
	got := ae.call(t, "admin", "GET", "/exports/"+id, "", nil)
	rep := ae.call(t, "admin", "POST", "/exports", "auto", map[string]any{"kind": "assessment_results", "as_of": str(created, "as_of")})
	for name, r := range map[string]apiResp{"fetched": got, "reproduced": rep} {
		if r.code != 200 || str(r, "document") != string(doc) || str(r, "statement") != string(stmt) || str(r, "signature") != sig ||
			str(r, "document_sha256") != str(created, "document_sha256") {
			t.Errorf("%s export differs: %d %.200s", name, r.code, r.raw)
		}
	}
	if len(ae.mem.OfType(posture.EventExportFetched)) != 2 {
		t.Errorf("fetches audited: %d", len(ae.mem.OfType(posture.EventExportFetched)))
	}
	if r := ae.call(t, "admin", "POST", "/exports", "auto", map[string]any{"kind": "poam", "as_of": str(created, "as_of")}); r.code != 404 {
		t.Errorf("reproducing an export never made: %d", r.code)
	}
	for _, c := range []struct {
		user, path string
		code       int
	}{{"auditor", "/exports/" + id, 403}, {"nobody", "/exports/" + id, 404}, {"admin", "/exports/not-a-uuid", 404},
		{"admin", "/exports/00000000-0000-4000-8000-000000000000", 404}} {
		if r := ae.call(t, c.user, "GET", c.path, "", nil); r.code != c.code {
			t.Errorf("%s GET %s: %d, want %d", c.user, c.path, r.code, c.code)
		}
	}

	// A POA&M once something is open; the history lists both, without documents.
	e.admin(e.db, `UPDATE posture.setting_value SET value = '"1.0"' WHERE key = 'tls.min_version' AND bu_id IS NULL`)
	if r := ae.call(t, "admin", "POST", "/exports", "auto", map[string]any{"kind": "poam"}); r.code != 201 {
		t.Fatalf("POA&M: %d %s", r.code, r.raw)
	}
	hist := ae.call(t, "auditor", "GET", "/exports", "", nil)
	list, _ := hist.body["exports"].([]any)
	if hist.code != 200 || len(list) != 2 || strings.Contains(hist.raw, `"document"`) {
		t.Fatalf("history: %d %s", hist.code, hist.raw)
	}

	// Records are append-only.
	if got := e.adminQuery(`SELECT has_table_privilege('posture_definer', 'posture.export_record', 'UPDATE')
		OR has_table_privilege('posture_definer', 'posture.export_record', 'DELETE')
		OR has_table_privilege('app_posture', 'posture.export_record', 'SELECT')`); got != "f" {
		t.Fatalf("export_record is writable: %s", got)
	}

	// Tampering with a record is caught when it is served, and reported.
	e.admin(e.db, `UPDATE posture.export_record SET snapshot = t.s, snapshot_digest = encode(sha256(t.s), 'hex')
		FROM (SELECT id, convert_to(replace(convert_from(snapshot, 'UTF8'), '"self-hosted"', '"saas"'), 'UTF8') s
		      FROM posture.export_record WHERE id = '`+id+`') t WHERE posture.export_record.id = t.id`)
	if r := ae.call(t, "admin", "GET", "/exports/"+id, "", nil); r.code != 500 || str(r, "error") != "export_not_reproducible" ||
		strings.Contains(r.raw, "assessment-results") {
		t.Fatalf("tampered snapshot served: %d %.200s", r.code, r.raw)
	}
	e.admin(e.db, `UPDATE posture.export_record SET snapshot_digest = repeat('0', 64) WHERE id = '`+id+`'`)
	if r := ae.call(t, "admin", "POST", "/exports", "auto", map[string]any{"kind": "assessment_results", "as_of": str(created, "as_of")}); r.code != 500 {
		t.Fatalf("tampered digest reproduced: %d", r.code)
	}
	if m := ae.mem.OfType(posture.EventExportMismatched); len(m) != 2 || m[0].Severity != audit.SeverityCritical ||
		!strings.Contains(m[0].Reason, "rebuilt document differs") || !strings.Contains(m[1].Reason, "snapshot does not match") {
		t.Fatalf("mismatch events: %+v", m)
	}
}

// The database accepts only records consistent with their signed statement
// and snapshot, created now, by a holder of posture.export.
func TestExportRecordChecks(t *testing.T) {
	ae := apiFixture(t, settings.ProfileEnterpriseBaseline)
	e := ae.e
	ctx := context.Background()
	x := posture.Exports{DB: e.posturePool(), Audit: audit.NewMemory(), Key: ae.exportKey}
	good, err := x.Create(ctx, e.principal("admin"), posture.KindAssessmentResults)
	if err != nil {
		t.Fatal(err)
	}
	snap := e.adminQuery("SELECT encode(snapshot, 'hex') FROM posture.export_record WHERE id = '" + good.ID + "'")

	record := func(user string, mutate func(args []any)) error {
		args := []any{"6f1e2d3c-0000-4000-8000-000000000001", good.Kind, good.AsOf, good.CreatedAt, mustHex(t, snap), good.SnapshotDigest,
			good.DocumentDigest, []byte(strings.Replace(string(good.Statement), good.ID, "6f1e2d3c-0000-4000-8000-000000000001", 1)),
			good.Signature, good.KeyID}
		mutate(args)
		return authz.WithDBContext(ctx, e.posturePool(), e.principal(user).DBToken, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "SELECT posture.record_export($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)", args...)
			return err
		})
	}
	for name, c := range map[string]struct {
		user   string
		mutate func([]any)
		want   error
	}{
		"auditor":                {"auditor", func([]any) {}, posture.ErrNotPermitted},
		"snapshot digest":        {"admin", func(a []any) { a[5] = strings.Repeat("0", 64) }, posture.ErrInvalidValue},
		"statement kind":         {"admin", func(a []any) { a[1] = posture.KindPOAM }, posture.ErrInvalidValue},
		"statement digest":       {"admin", func(a []any) { a[6] = strings.Repeat("1", 64) }, posture.ErrInvalidValue},
		"created an hour ago":    {"admin", func(a []any) { a[3] = good.CreatedAt.Add(-3600e9) }, posture.ErrInvalidValue},
		"same kind and as_of":    {"admin", func([]any) {}, nil},
		"statement not JSON":     {"admin", func(a []any) { a[7] = []byte("x") }, posture.ErrInvalidValue},
		"created_by not the ctx": {"admin2", func([]any) {}, posture.ErrInvalidValue},
	} {
		err := posture.MapError(record(c.user, c.mutate))
		if name == "same kind and as_of" {
			if err == nil || !strings.Contains(err.Error(), "export_record_kind_as_of_key") {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}

	// Audit fails closed: nothing is recorded.
	x.Audit = failingEmitter{}
	if _, err := x.Create(ctx, e.principal("admin"), posture.KindAssessmentResults); err == nil {
		t.Fatal("export recorded with the audit sink down")
	}
	if n := e.adminQuery("SELECT count(*) FROM posture.export_record"); n != "1" {
		t.Fatalf("%s records", n)
	}
	// No signing key: not configured.
	x.Audit, x.Key = audit.NewMemory(), nil
	if _, err := x.Create(ctx, e.principal("admin"), posture.KindAssessmentResults); !errors.Is(err, posture.ErrConfiguration) {
		t.Fatalf("without a key: %v", err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte
		for _, c := range s[2*i : 2*i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			case c >= 'a' && c <= 'f':
				v |= byte(c-'a') + 10
			default:
				t.Fatalf("not hex: %q", s)
			}
		}
		b[i] = v
	}
	return b
}
