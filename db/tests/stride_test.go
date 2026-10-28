package tests

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	posturev1 "github.com/rformer/fair-app/internal/api/posturev1"
	"github.com/rformer/fair-app/internal/approvals"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-36: the STRIDE suite (design §8). Every threat in the §8 table
// is covered by named tests: those below, written as attacks, and earlier
// tests that already attack the same mitigation. TestSTRIDECatalog keeps
// the table and the suite in step. `make test-stride` runs the suite.

// strideSuite maps each §8 row ("Threat | Example") to its tests, as
// "<package dir>:<test name>".
var strideSuite = map[string][]string{
	"Spoofing | Forged profile package": {
		"db/tests:TestPostureImportSigned", "internal/profilepkg:TestVerifyRelease", "internal/profilegen:TestPackagesSignedReleaseTamper",
	},
	"Tampering | DBA or attacker edits `setting_value` directly": {
		"db/tests:TestPostureNoDirectWrites", "db/tests:TestPostureDirectEditDetected", "db/tests:TestDriftDetectsDirectDBEdit",
	},
	"Tampering | Exception expiry extended by editing the DB": {
		"db/tests:TestPostureNoDirectWrites", "db/tests:TestSTRIDEExceptionExtension",
	},
	`Repudiation | "I didn't approve that loosening"`: {
		"db/tests:TestApprovalLifecycle", "db/tests:TestSTRIDERepudiationAndCollusion",
	},
	"Information disclosure | Scanner reads Secrets": {
		"internal/scanner:TestScannerRBACIsReadOnlyAndMatchesAccess", "internal/scanner:TestPermissionManifest",
	},
	"Information disclosure | Posture page reveals restricted-BU overrides": {
		"db/tests:TestPostureAPIRestrictedBUHidden",
	},
	"Denial of service | Revert job starved or blocked": {
		"db/tests:TestRevertFaultInjection", "db/tests:TestDriftExceptionsAndMissedRevert", "db/tests:TestSTRIDERevertStarvation",
	},
	"Elevation of privilege | Collusion between two admins to loosen": {
		"db/tests:TestSecOpsSaaSNotifiesWeakening", "db/tests:TestExceptionDuration", "db/tests:TestRevertOnExpiry",
		"db/tests:TestSTRIDERepudiationAndCollusion",
	},
	"Elevation of privilege | Scanner ServiceAccount compromised": {
		"internal/scanner:TestScannerRBACIsReadOnlyAndMatchesAccess", "internal/scanner:TestScannerPodHardenedAndEgressRestricted",
		"db/tests:TestScannerChannelAuthentication", "db/tests:TestSTRIDECompromisedScanner",
	},
}

// The §8 table and the suite agree: every row has tests, every test exists,
// and no mapping names a row the design no longer has. Runs without a
// database.
func TestSTRIDECatalog(t *testing.T) {
	root := filepath.Join("..", "..")
	f, err := os.Open(filepath.Join(root, "specs", "features", "F-015-security-posture-profiles", "design.md")) // #nosec G304 -- the repository's own file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var rows []string
	in := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "## 8."):
			in = true
		case in && strings.HasPrefix(line, "## "):
			in = false
		case in && strings.HasPrefix(line, "| ") && !strings.HasPrefix(line, "| Threat") && !strings.HasPrefix(line, "|---"):
			cells := strings.Split(strings.Trim(line, "| "), " | ")
			rows = append(rows, cells[0]+" | "+cells[1])
		}
	}
	if len(rows) < 9 {
		t.Fatalf("found %d §8 rows: %q", len(rows), rows)
	}
	for _, r := range rows {
		if len(strideSuite[r]) == 0 {
			t.Errorf("§8 threat %q has no tests in the STRIDE suite", r)
		}
	}
	// make test-stride runs the TestSTRIDE* tests and those its lists name.
	mk, err := os.ReadFile(filepath.Join(root, "Makefile")) // #nosec G304 -- the repository's own file
	if err != nil {
		t.Fatal(err)
	}
	run := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^STRIDE_(?:DB|UNIT)_TESTS = (.*)$`).FindAllSubmatch(mk, -1) {
		for _, n := range strings.Split(strings.TrimSpace(string(m[1])), "|") {
			run[n] = true
		}
	}
	for r, tests := range strideSuite {
		for _, ref := range tests {
			if _, name, _ := strings.Cut(ref, ":"); !run[name] && !strings.HasPrefix(name, "TestSTRIDE") {
				t.Errorf("%q: %s is not run by make test-stride", r, name)
			}
		}
		if !slices.Contains(rows, r) {
			t.Errorf("the suite maps %q, which is not a §8 row", r)
		}
		for _, ref := range tests {
			dir, name, _ := strings.Cut(ref, ":")
			files, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(dir), "*_test.go"))
			re := regexp.MustCompile(`(?m)^func ` + name + `\(t \*testing\.T\)`)
			found := false
			for _, file := range files {
				b, err := os.ReadFile(file) // #nosec G304 -- the repository's own test files
				if err == nil && re.Match(b) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%q: test %s not found", r, ref)
			}
		}
	}
}

// Tampering: an exception's expiry (or approver) edited in the database is
// detected by its row MAC as a critical finding; posture's own updates keep
// the MAC valid.
func TestSTRIDEExceptionExtension(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	mem := audit.NewMemory()
	d := posture.Drift{DB: e.posturePool(), Audit: mem}
	x := approvedException(t, e, ev, 30*24*time.Hour)
	subject := "exception:" + x.ID
	scan := func() posture.ScanResult {
		t.Helper()
		res, err := d.Scan(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := scan(); len(res.Opened) != 0 {
		t.Fatalf("findings for an untouched exception: %v", ids(res.Opened))
	}

	// The attack: a superuser extends the expiry by ten years.
	e.admin(e.db, "UPDATE posture.exception SET expires_at = expires_at + interval '10 years' WHERE id = '"+x.ID+"'")
	res := scan()
	i := slices.IndexFunc(res.Opened, func(f posture.Finding) bool {
		return f.CheckID == posture.CheckRowMAC && f.Subject == subject
	})
	if i < 0 {
		t.Fatalf("the extended exception was not detected: %v", ids(res.Opened))
	}
	if f := res.Opened[i]; f.Severity != "critical" || !slices.Contains(f.Controls, "CM-5") || !strings.Contains(f.Remediation, "exception record") {
		t.Fatalf("finding %+v", f)
	}
	if ev := mem.OfType(posture.EventDriftDetected); len(ev) == 0 || ev[len(ev)-1].Severity != audit.SeverityCritical {
		t.Fatalf("not audited as critical: %+v", mem.Events())
	}

	// Rewriting the approver (to disown the approval) is detected the same way.
	other := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'auditor@example.test'")
	y := approvedException(t, e, ev, 0)
	e.admin(e.db, "UPDATE posture.exception SET approved_by = '"+other+"' WHERE id = '"+y.ID+"'")
	if !slices.Contains(ids(scan().Opened), posture.CheckRowMAC+" exception:"+y.ID) {
		t.Fatal("a rewritten approver was not detected")
	}

	// No laundering: posture's later updates (y superseded x; z supersedes
	// y and is then reverted) never re-sign a tampered row, while an
	// untouched exception stays valid through them.
	z := approvedException(t, e, ev, 0)
	expire(e, z.ID)
	if out, err := posture.RevertDue(ctx, e.posturePool(), audit.NewMemory(), nil); err != nil || len(out) != 1 || out[0].Err != nil {
		t.Fatalf("revert: %+v %v", out, err)
	}
	res = scan()
	if len(res.Opened)+len(res.Resolved) != 0 {
		t.Fatalf("after posture's own updates: opened %v, resolved %v", ids(res.Opened), ids(res.Resolved))
	}
	got := e.adminQuery("SELECT string_agg(key, ',' ORDER BY key) FROM posture.mac_mismatches() WHERE key LIKE 'exception:%'")
	want := []string{subject, "exception:" + y.ID}
	slices.Sort(want)
	if got != strings.Join(want, ",") {
		t.Fatalf("exception MAC mismatches %q, want %q", got, want)
	}
}

// Denial of service: a revert blocked by a row lock gives up within the lock
// timeout, is recorded as revert_failed and retried, and does not hold up
// the other reverts in the batch.
func TestSTRIDERevertStarvation(t *testing.T) {
	e, ev, _, _ := evaluatorFixture(t)
	ctx := context.Background()
	pool := e.posturePool()
	blocked := approvedException(t, e, ev, 0)
	expire(e, blocked.ID)
	// A second due exception on another setting.
	admin := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'admin@example.test'")
	free := e.adminQuery(`SET ROLE posture_definer; INSERT INTO posture.exception (key, value, bound_at_creation, justification, owner_id,
		approved_by, created_at, expires_at, state) VALUES ('session.idle_timeout', '"30m0s"', '"15m0s"', 'pilot', '` + admin + `', '` + admin + `',
		now() - interval '30 days', now() - interval '1 second', 'active') RETURNING id`)
	e.admin(e.db, `SET ROLE posture_definer; SELECT posture.write_value('session.idle_timeout', NULL, '"30m0s"', 'exception', NULL, '`+free+`')`)

	// Another session holds the blocked setting's row.
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	holder := exec.CommandContext(lctx, "psql", "--no-psqlrc", "-X", "-q", "-d", e.db, "-c",
		"BEGIN; SELECT 1 FROM posture.setting_value WHERE key = '"+settings.KeyAuthInactiveDisable+"' AND bu_id IS NULL FOR UPDATE; SELECT pg_sleep(60); COMMIT;")
	holder.Env = e.adminEnv
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	pid := ""
	for deadline := time.Now().Add(10 * time.Second); pid == "" && time.Now().Before(deadline); {
		pid = e.adminQuery("SELECT coalesce(min(pid)::text, '') FROM pg_stat_activity WHERE datname = current_database() AND query LIKE '%pg_sleep(60)%' AND pid <> pg_backend_pid()")
		if pid == "" {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if pid == "" {
		t.Fatal("the lock holder did not start")
	}
	release := func() {
		e.adminQuery("SELECT pg_terminate_backend(" + pid + ")")
		_ = holder.Wait()
	}
	defer cancel()

	start := time.Now()
	out, err := posture.RevertDue(ctx, pool, audit.NewMemory(), nil)
	took := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if took > posture.RevertLockTimeout+5*time.Second {
		t.Fatalf("the revert pass took %v with a row locked", took)
	}
	result := map[string]error{}
	for _, o := range out {
		result[o.ExceptionID] = o.Err
	}
	if len(out) != 2 || result[blocked.ID] == nil || result[free] != nil {
		t.Fatalf("outcomes %+v", out)
	}
	if got := exceptionState(e, blocked.ID); got != "revert_failed:1" {
		t.Fatalf("blocked exception %s", got)
	}
	if got := exceptionState(e, free); !strings.HasPrefix(got, "reverted:") {
		t.Fatalf("the other revert was held up: %s", got)
	}
	if got := e.adminQuery("SELECT severity || ':' || status FROM posture.drift_finding WHERE check_id = 'revert_failed'"); got != "critical:open" {
		t.Fatalf("revert_failed finding %q", got)
	}

	// Once the lock is gone, the retry reverts it.
	release()
	e.timeTravel("UPDATE posture.exception SET revert_next_at = now() WHERE id = '" + blocked.ID + "'")
	if out, err := posture.RevertDue(ctx, pool, audit.NewMemory(), nil); err != nil || len(out) != 1 || out[0].Err != nil {
		t.Fatalf("retry: %+v %v", out, err)
	}
}

// Repudiation and collusion: a loosening needs two people, both recorded
// on the request, the exception and the audit events, and nobody approves
// their own request. What two colluding admins obtain is bounded (it
// expires) and visible (POA&M evidence naming both).
func TestSTRIDERepudiationAndCollusion(t *testing.T) {
	e, ev, mem, _ := evaluatorFixture(t)
	ctx := context.Background()
	admin, admin2 := e.principal("admin"), e.principal("admin2")

	// Nobody approves their own loosening.
	res, err := ev.Change(ctx, admin, posture.ChangeRequest{Key: settings.KeyAuthInactiveDisable,
		Value: json.RawMessage(`"8760h0m0s"`), Explanation: "contractors"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (approvals.Service{DB: e.appPool()}).Decide(ctx, admin, res.ApprovalID, true, ""); err == nil {
		t.Fatal("a requester approved their own loosening")
	}
	if _, err := (approvals.Service{DB: e.appPool()}).Decide(ctx, admin2, res.ApprovalID, true, ""); err != nil {
		t.Fatal(err)
	}
	x, err := ev.ApplyApproved(ctx, res.ChangeID)
	if err != nil {
		t.Fatal(err)
	}

	// Both identities, on the request and on the exception.
	got := e.adminQuery("SELECT requested_by || '|' || decided_by || '|' || status FROM iam.approval_request WHERE id = '" + res.ApprovalID + "'")
	if got != admin.UserID+"|"+admin2.UserID+"|approved" || x.OwnerID != admin.UserID || x.ApprovedBy != admin2.UserID {
		t.Fatalf("request %s, exception owner %s approver %s", got, x.OwnerID, x.ApprovedBy)
	}
	// And in the audit trail: the approval decision and the exception.
	outbox := e.adminQuery(`SELECT payload->'attributes'->>'requested_by' || '|' || (payload->'attributes'->>'decided_by') FROM iam.event_outbox
		WHERE topic = 'audit' AND payload->>'type' = 'approval.approved' AND payload->>'target' = 'approval:` + res.ApprovalID + `'`)
	if outbox != admin.UserID+"|"+admin2.UserID {
		t.Fatalf("approval audit %q", outbox)
	}
	created := mem.OfType("setting.exception_created")
	if len(created) != 1 || created[0].Attributes["owner"] != admin.UserID || created[0].Attributes["approved_by"] != admin2.UserID {
		t.Fatalf("exception audit %+v", created)
	}

	// Collusion is bounded: the exception expires within exception.max_duration.
	var maxDur string
	if err := e.posturePool().QueryRow(ctx, "SELECT value #>> '{}' FROM posture.registry_view() WHERE key = 'exception.max_duration'").Scan(&maxDur); err != nil {
		t.Fatal(err)
	}
	limit, err := time.ParseDuration(maxDur)
	if err != nil || time.Until(x.ExpiresAt) > limit {
		t.Fatalf("expires in %v, max %s (%v)", time.Until(x.ExpiresAt), maxDur, err)
	}
	// And visible: the POA&M lists it with both people.
	s, err := posture.LoadExportSnapshot(ctx, e.posturePool())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := posture.ExportPOAM(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{x.ID, `"value": "` + admin.UserID + `"`, `"value": "` + admin2.UserID + `"`} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("POA&M lacks %q", want)
		}
	}
}

// Elevation of privilege: a compromised scanner identity can report only
// deployment findings. It cannot report, or resolve, application checks,
// and its reports never touch application findings.
func TestSTRIDECompromisedScanner(t *testing.T) {
	ctx := context.Background()
	se := scannerFixture(t)
	e := se.e
	e.admin(e.db, `UPDATE posture.setting_value SET value = '"1h0m0s"' WHERE key = 'session.idle_timeout' AND bu_id IS NULL`)
	se.scan(t)
	app := func() string {
		return e.adminQuery("SELECT string_agg(check_id || ':' || status, ',' ORDER BY check_id) FROM posture.drift_finding WHERE kind = 'app'")
	}
	before := app()
	if !strings.Contains(before, posture.CheckRowMAC+":open") {
		t.Fatalf("app findings %q", before)
	}
	now := time.Now().UnixMilli()
	report := func(checks []string, findings ...*posturev1.DeploymentFinding) error {
		return se.report(ctx, &posturev1.ScanReport{ScannerInstance: "posture-scanner-0", StartedUnixMs: now - 1000, FinishedUnixMs: now,
			ChecksRun: checks, Findings: findings})
	}

	// Claim to have run application checks with nothing found (to resolve
	// them), or report application findings: refused.
	for name, err := range map[string]error{
		"resolve row_mac_mismatch":     report([]string{posture.CheckRowMAC}),
		"resolve unapproved_deviation": report([]string{posture.CheckDeviation}),
		"resolve revert_failed":        report([]string{"revert_failed"}),
		"report hard_floor_violation": report([]string{posture.CheckHardFloor}, &posturev1.DeploymentFinding{CheckId: posture.CheckHardFloor,
			Severity: "low", Controls: []string{"CM-6"}, Subject: "setting:tls.min_version", DetailJson: `{}`, Remediation: "none"}),
	} {
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A valid report (every deployment check, nothing found) leaves the
	// application findings alone.
	if err := report([]string{"image_digests", "network_policy", "pod_hardening", "pod_security_admission", "platform_rbac",
		"plaintext_secrets", "signature_admission", "storage_encryption", "tls_endpoints"}); err != nil {
		t.Fatal(err)
	}
	if after := app(); after != before {
		t.Fatalf("a scanner report changed application findings: %q -> %q", before, after)
	}
	// Its findings are deployment findings, whatever they claim to be about.
	if err := report([]string{"pod_hardening"}, &posturev1.DeploymentFinding{CheckId: "pod_hardening", Severity: "low",
		Controls: []string{"CM-7"}, Subject: "setting:tls.min_version", DetailJson: `{}`, Remediation: "x"}); err != nil {
		t.Fatal(err)
	}
	if got := e.adminQuery("SELECT kind FROM posture.drift_finding WHERE check_id = 'pod_hardening' AND status = 'open'"); got != "deployment" {
		t.Fatalf("scanner finding kind %q", got)
	}
}
