package tests

// F-012 T-08 (F-012-AC-13, AC-21; design §3.4.1): upgrades from earlier
// releases, with representative data, and the expand–contract rule.
//
// For each earlier release (the newest patch of each of the two newest
// minor releases before this one; until the first release exists, the
// baseline commit in db/upgrade/baseline, D-OQ3; FAIR_UPGRADE_FROM overrides
// with refs, comma-separated):
//  1. a git worktree of that release runs its own UI harness
//     (TestPostureUIHarness), which seeds every feature through that
//     release's services (with FAIR_UI_ENGINE_SOCKET, the analyses, register,
//     acceptances and reports too);
//  2. the seeded database is copied (CREATE DATABASE … TEMPLATE) and the
//     harness stopped;
//  3. this release bootstraps and migrates the copy (iam migrate's runner),
//     which must apply exactly the migrations the old release lacks;
//  4. this release's checks pass on it: rows kept, every BU-owned table
//     registered with RLS, the audit trail verifies in full;
//  5. both releases' services (iam, gateway, risk, posture, audit, built from
//     their trees) start on the upgraded schema and answer authenticated
//     requests through their own gateway, the old ones included (AC-21: an
//     operator can roll back to the previous images without data loss).
//
// It builds and runs two releases, so it is opt-in (FAIR_TEST_UPGRADE=1; the
// release pipeline's upgrade job and the DB suite in CI set it).

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	auditsvc "github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/audit/integrity"
	"github.com/rformer/fair-app/internal/gateway"
	"github.com/rformer/fair-app/pkg/audit"
)

// upgradeTables are counted before and after the upgrade: nothing may be
// lost.
var upgradeTables = []string{
	"iam.app_user", "iam.bu", "iam.role_assignment", "posture.setting_change",
	"risk.scenario", "risk.scenario_version", "risk.library_entry", "risk.control",
	"estimate.request", "analysis.run", "register.risk", "register.treatment",
	"acceptance.acceptance", "notify.notice", "report.run",
	"integration.integration", "integration.loss_event", "audit.intake", "audit.record",
}

func TestUpgradeFromPreviousReleases(t *testing.T) {
	if os.Getenv("FAIR_TEST_UPGRADE") != "1" {
		t.Skip("set FAIR_TEST_UPGRADE=1 to build and upgrade from earlier releases (F-012 T-08)")
	}
	if os.Getenv("FAIR_TEST_PG") != "1" {
		t.Skip("set FAIR_TEST_PG=1 and libpq admin variables to run database tests")
	}
	root := repoRoot(t)
	bases := previousReleases(t, root)
	if len(bases) == 0 {
		t.Fatal("no earlier release and no db/upgrade/baseline")
	}
	for _, base := range bases {
		t.Run(base, func(t *testing.T) { upgradeFrom(t, root, base) })
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", append([]string{"-c", "safe.directory=*"}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

var releaseTag = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

// previousReleases are the refs to upgrade from (D-OQ3).
func previousReleases(t *testing.T, root string) []string {
	t.Helper()
	if v := os.Getenv("FAIR_UPGRADE_FROM"); v != "" {
		return strings.Split(v, ",")
	}
	head := gitIn(t, root, "rev-parse", "HEAD")
	var bases []string
	seen := map[string]bool{}
	for _, tag := range strings.Fields(gitIn(t, root, "tag", "--list", "v*", "--sort=-v:refname")) {
		m := releaseTag.FindStringSubmatch(tag)
		if m == nil || gitIn(t, root, "rev-list", "-n", "1", tag) == head {
			continue
		}
		minor := m[1] + "." + m[2]
		if seen[minor] {
			continue // only the newest patch of each minor release
		}
		seen[minor] = true
		bases = append(bases, tag)
		if len(bases) == 2 {
			return bases
		}
	}
	if len(bases) > 0 {
		return bases
	}
	b, err := os.ReadFile(filepath.Join(root, "db", "upgrade", "baseline")) // #nosec G304 -- the repository's own file
	if err != nil {
		return nil
	}
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			return []string{l}
		}
	}
	return nil
}

func upgradeFrom(t *testing.T, root, base string) {
	ctx := context.Background()
	old := filepath.Join(t.TempDir(), "release")
	gitIn(t, root, "worktree", "add", "--detach", old, base)
	t.Cleanup(func() {
		cmd := exec.CommandContext(context.Background(), "git", "-c", "safe.directory=*", "worktree", "remove", "--force", old)
		cmd.Dir = root
		_ = cmd.Run()
	})

	// 1. The old release seeds its data through its own services.
	seeded := seedOldRelease(t, root, old)

	// 2. A copy of it to upgrade.
	e := &env{t: t, root: root, db: "fairup_" + randHex(6), secrets: map[string]string{}, adminEnv: os.Environ()}
	e.admin("postgres", fmt.Sprintf("CREATE DATABASE %s TEMPLATE %s", e.db, seeded))
	t.Cleanup(func() {
		_ = e.psqlAs(nil, "postgres", fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", e.db))
	})
	before := countRows(t, e)
	oldTrail, oldMax := trailDigest(t, e, 0)
	if before["risk.scenario"] == 0 || before["audit.record"]+before["audit.intake"] == 0 {
		t.Fatalf("the old release seeded too little to test an upgrade: %v", before)
	}

	// 3. This release's bootstrap and migrations on it.
	dir := t.TempDir()
	for _, r := range []string{"app_migrator", "app_rw", "app_engine", "app_posture", "app_gateway", "app_audit", "app_notify", "app_integrate"} {
		p := filepath.Join(dir, r)
		if err := os.WriteFile(p, []byte(randHex(24)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		e.secrets[r] = p
	}
	e.script("db-bootstrap.sh", map[string]string{
		"PGDATABASE":                   e.db,
		"FAIR_MIGRATOR_PASSWORD_FILE":  e.secrets["app_migrator"],
		"FAIR_RW_PASSWORD_FILE":        e.secrets["app_rw"],
		"FAIR_ENGINE_PASSWORD_FILE":    e.secrets["app_engine"],
		"FAIR_POSTURE_PASSWORD_FILE":   e.secrets["app_posture"],
		"FAIR_GATEWAY_PASSWORD_FILE":   e.secrets["app_gateway"],
		"FAIR_AUDIT_PASSWORD_FILE":     e.secrets["app_audit"],
		"FAIR_NOTIFY_PASSWORD_FILE":    e.secrets["app_notify"],
		"FAIR_INTEGRATE_PASSWORD_FILE": e.secrets["app_integrate"],
	})
	res, err := e.migrate("")
	if err != nil {
		t.Fatalf("upgrade from %s: %v", base, err)
	}
	want := newMigrations(t, root, old)
	if !slices.Equal(res.Applied, want) {
		t.Fatalf("the upgrade applied %v, want the migrations %s lacks: %v", res.Applied, base, want)
	}
	t.Logf("upgraded from %s: %d migrations (%s to %s)", base, len(want), first(want), last(want))

	// 4. This release's checks on the upgraded data.
	after := countRows(t, e)
	for _, tb := range upgradeTables {
		if after[tb] < before[tb] {
			t.Errorf("%s: %d rows before the upgrade, %d after", tb, before[tb], after[tb])
		}
	}
	if u := e.unregisteredBUTables(); u != "" {
		t.Errorf("after the upgrade, BU-owned tables without RLS registration: %s", u)
	}
	pool := e.auditPool()
	drainTrail(t, auditsvc.Sequencer{DB: pool})
	if _, err := checkpointer(t, pool, newCheckpointKey(t)).Close(ctx); err != nil {
		t.Fatal(err)
	}
	// The trail: the old records unchanged by the upgrade, byte for byte, and
	// every record's leaf and chain hash right. The old harness overwrites
	// one record's body on purpose (event ui-2), so the Posture page shows an
	// integrity finding; that leaf, and only it, may fail.
	if d, _ := trailDigest(t, e, oldMax); d != oldTrail {
		t.Fatal("the upgrade changed records of the audit trail")
	}
	tampered := e.adminQuery("SELECT coalesce(max(seq)::text, '') FROM audit.record WHERE event_id = 'ui-2'")
	checkTrail(t, e, tampered)
	v := auditsvc.Verifier{DB: pool, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool})}
	r, err := v.Full(ctx)
	switch {
	case err != nil:
		t.Fatalf("verify the trail: %v", err)
	case tampered == "" && !r.OK:
		t.Fatalf("the audit trail does not verify after the upgrade: %+v", r)
	case tampered != "" && (r.OK || fmt.Sprint(r.FailedSeq) != tampered):
		t.Fatalf("the full verification should fail at the harness's tampered record %s only: %+v", tampered, r)
	}

	// 5. Both releases' services on the upgraded schema (expand–contract).
	for _, rel := range []struct{ name, dir string }{{"this release", root}, {base, old}} {
		t.Run(strings.ReplaceAll(rel.name, " ", "_"), func(t *testing.T) { smokeRelease(t, e, rel.dir) })
	}
}

func first(l []string) string {
	if len(l) == 0 {
		return "none"
	}
	return l[0]
}

func last(l []string) string {
	if len(l) == 0 {
		return "none"
	}
	return l[len(l)-1]
}

// newMigrations are this release's migration files the old tree lacks.
func newMigrations(t *testing.T, root, old string) []string {
	t.Helper()
	list := func(d string) []string {
		ents, err := os.ReadDir(filepath.Join(d, "db", "migrations"))
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".sql") {
				out = append(out, e.Name())
			}
		}
		slices.Sort(out)
		return out
	}
	have := list(old)
	var out []string
	for _, m := range list(root) {
		if !slices.Contains(have, m) {
			out = append(out, strings.TrimSuffix(m, ".sql"))
		}
	}
	return out
}

func countRows(t *testing.T, e *env) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, tb := range upgradeTables {
		var n int
		q := fmt.Sprintf("SELECT CASE WHEN to_regclass('%s') IS NULL THEN 0 ELSE (xpath('/row/n/text()', query_to_xml('SELECT count(*) AS n FROM %s', false, true, '')))[1]::text::int END", tb, tb)
		if _, err := fmt.Sscan(e.adminQuery(q), &n); err != nil {
			t.Fatalf("%s: %v", tb, err)
		}
		out[tb] = n
	}
	return out
}

// seedOldRelease runs the old release's UI harness until it is ready, copies
// nothing itself but returns the name of the harness's database, closed to
// new connections, with the harness stopped once the caller has copied it.
func seedOldRelease(t *testing.T, root, old string) string {
	t.Helper()
	// The harness wants the built UI; any index.html serves.
	if err := os.MkdirAll(filepath.Join(old, "web", "dist"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "web", "dist", "index.html"), []byte("<!doctype html><title>FAIR</title>"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, root: root, db: "postgres", adminEnv: os.Environ()}
	existing := e.adminQuery("SELECT coalesce(string_agg(datname, ','), '') FROM pg_database WHERE datname LIKE 'fairtest_%'")

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-timeout", "45m", "-run", "^TestPostureUIHarness$", "-v", "./db/tests/")
	cmd.Dir = old
	cmd.Env = append(os.Environ(), "FAIR_UI_HARNESS=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var tail []string
	ready := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		sent := false
		for sc.Scan() {
			l := sc.Text()
			tail = append(tail, l)
			if len(tail) > 60 {
				tail = tail[1:]
			}
			if !sent && strings.Contains(l, "HARNESS READY") {
				ready <- true
				sent = true
			}
		}
		if !sent {
			ready <- false
		}
	}()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		_ = os.WriteFile(filepath.Join(old, "web", ".harness-stop"), nil, 0o600)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Minute):
			cancel()
			<-done
		}
		cancel()
	}
	t.Cleanup(stop)
	if !<-ready {
		stop()
		t.Fatalf("the old release's harness did not become ready:\n%s", strings.Join(tail, "\n"))
	}
	var db string
	for _, d := range strings.Split(e.adminQuery("SELECT coalesce(string_agg(datname, ','), '') FROM pg_database WHERE datname LIKE 'fairtest_%'"), ",") {
		if d != "" && !slices.Contains(strings.Split(existing, ","), d) {
			if db != "" {
				t.Fatalf("more than one new test database (%s, %s); run the upgrade test alone", db, d)
			}
			db = d
		}
	}
	if db == "" {
		t.Fatal("the harness's database was not found")
	}
	// Closed to new connections and emptied, so it can be a template; the
	// caller copies it before the harness is stopped (which drops it).
	e.admin("postgres", fmt.Sprintf("ALTER DATABASE %s ALLOW_CONNECTIONS false", db))
	e.admin("postgres", fmt.Sprintf("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '%s' AND pid <> pg_backend_pid()", db))
	t.Cleanup(func() {
		_ = e.psqlAs(nil, "postgres", fmt.Sprintf("ALTER DATABASE %s ALLOW_CONNECTIONS true", db))
	})
	for range 50 {
		if e.adminQuery(fmt.Sprintf("SELECT count(*) FROM pg_stat_activity WHERE datname = '%s'", db)) == "0" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return db
}

// smokeRelease builds a release's services from dir, starts them on the
// upgraded database in development mode with keys from that release's
// `iam keys init`, and sends authenticated requests through its gateway.
func smokeRelease(t *testing.T, e *env, dir string) {
	t.Helper()
	ctx := context.Background()
	bin := t.TempDir()
	for _, c := range []string{"iam", "gateway", "risk", "posture", "audit"} {
		cmd := exec.CommandContext(ctx, "go", "build", "-o", filepath.Join(bin, c), "./cmd/"+c)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", c, err, out)
		}
	}
	keys := filepath.Join(t.TempDir(), "keys")
	base := append(slices.Clone(e.adminEnv), "PGDATABASE="+e.db, "FAIR_ENV=development", "FAIR_ALLOW_PLAINTEXT=true", "FAIR_DEPLOYMENT_MODE=self-hosted")
	run := func(env []string, name string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, filepath.Join(bin, name), args...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
		}
	}
	run(base, "iam", "keys", "init", "-dir", keys)
	run(append(slices.Clone(base), "FAIR_MIGRATOR_PASSWORD_FILE="+e.secrets["app_migrator"]), "iam", "keys", "register", "-dir", keys)

	port := func() string {
		l, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		return l.Addr().String()
	}
	type svc struct {
		name, addr string
		env        []string
	}
	k := func(p string) string { return filepath.Join(keys, filepath.FromSlash(p)) }
	services := []svc{
		{"risk", port(), []string{"FAIR_DB_PASSWORD_FILE=" + e.secrets["app_rw"], "FAIR_JWT_KEYS_DIR=" + k("risk/jwt"),
			"FAIR_REPORT_CONTEXT_KEY_FILE=" + k("risk/secrets/report-context.key"), "FAIR_REPORT_CONTEXT_KEY_ID_FILE=" + k("risk/secrets/report-context.id")}},
		{"posture", port(), []string{"FAIR_DB_PASSWORD_FILE=" + e.secrets["app_posture"], "FAIR_JWT_KEYS_DIR=" + k("posture/jwt")}},
		{"audit", port(), []string{"FAIR_DB_PASSWORD_FILE=" + e.secrets["app_audit"], "FAIR_JWT_KEYS_DIR=" + k("audit/jwt"),
			"FAIR_AUDIT_CHECKPOINT_KEYS_DIR=" + k("audit/checkpoint")}},
		{"iam", port(), []string{"FAIR_DB_PASSWORD_FILE=" + e.secrets["app_rw"], "FAIR_JWT_KEYS_DIR=" + k("iam/jwt"),
			"FAIR_LOGIN_TICKET_KEYS_DIR=" + k("iam/login-ticket"), "FAIR_TOKEN_PEPPER_FILE=" + k("iam/secrets/token-pepper"), "FAIR_PUBLIC_ORIGIN=http://localhost"}},
	}
	var ups []string
	for _, s := range services {
		ups = append(ups, s.name+"=http://"+s.addr)
	}
	gw := svc{"gateway", port(), []string{"FAIR_DB_PASSWORD_FILE=" + e.secrets["app_gateway"], "FAIR_JWT_KEYS_DIR=" + k("gateway/jwt"),
		"FAIR_LOGIN_TICKET_KEYS_DIR=" + k("gateway/login-ticket"), "FAIR_SESSION_PEPPER_FILE=" + k("gateway/secrets/session-pepper"),
		"FAIR_TOKEN_PEPPER_FILE=" + k("gateway/secrets/token-pepper"), "FAIR_DB_CONTEXT_KEY_FILE=" + k("gateway/secrets/db-context.key"),
		"FAIR_DB_CONTEXT_KEY_ID_FILE=" + k("gateway/secrets/db-context.id"), "FAIR_PUBLIC_ORIGIN=http://localhost",
		"FAIR_UPSTREAMS=" + strings.Join(ups, ",")}}
	logs := map[string]*logBuf{}
	for _, s := range append(services, gw) {
		cctx, cancel := context.WithCancel(ctx)
		cmd := exec.CommandContext(cctx, filepath.Join(bin, s.name))
		if s.name == "iam" {
			cmd = exec.CommandContext(cctx, filepath.Join(bin, s.name), "serve")
		}
		cmd.Env = append(append(slices.Clone(base), "FAIR_LISTEN_ADDR="+s.addr), s.env...)
		buf := &logBuf{}
		logs[s.name] = buf
		cmd.Stdout, cmd.Stderr = buf, buf
		if err := cmd.Start(); err != nil {
			cancel()
			t.Fatalf("start %s: %v", s.name, err)
		}
		t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	}
	dump := func() string {
		var b strings.Builder
		for n, l := range logs {
			fmt.Fprintf(&b, "--- %s\n%s\n", n, tailLines(l.String(), 15))
		}
		return b.String()
	}
	client := &http.Client{Timeout: 10 * time.Second}
	for _, s := range append(services, gw) {
		deadline := time.Now().Add(90 * time.Second)
		for {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+s.addr+"/readyz", nil)
			resp, err := client.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s is not ready on the upgraded schema:\n%s", s.name, dump())
			}
			time.Sleep(time.Second)
		}
	}

	// Sessions for seeded users (the banner acknowledged), and requests that
	// read each service's data through the gateway.
	pepper, err := os.ReadFile(k("gateway/secrets/session-pepper")) // #nosec G304 -- the test's own key file
	if err != nil {
		t.Fatal(err)
	}
	sess := gateway.Sessions{DB: e.gatewayPool(), Pepper: []byte(strings.TrimSpace(string(pepper))),
		Timeouts: func() (time.Duration, time.Duration, error) { return 30 * time.Minute, 12 * time.Hour, nil }}
	tokens := map[string]string{}
	for _, u := range []string{"riskanalyst", "auditor", "riskowner"} {
		id := e.adminQuery("SELECT coalesce(max(id::text), '') FROM iam.app_user WHERE email = '" + u + "@example.test'")
		if id == "" {
			if u == "riskowner" {
				continue // seeded only with the engine (FAIR_UI_ENGINE_SOCKET)
			}
			t.Fatalf("the seeded user %s is missing", u)
		}
		_, tok, err := sess.Create(ctx, gateway.Login{UserID: id, AuthMethod: "oidc",
			MFA: map[string]any{"amr": []string{"mfa"}, "satisfied": true}, UserAgent: "upgrade-test"})
		if err != nil {
			t.Fatalf("session for %s: %v", u, err)
		}
		tokens[u] = tok
	}
	e.admin(e.db, "UPDATE iam.session SET banner_ack_at = now(), banner_version = coalesce((SELECT max(version) FROM iam.banner), 0)")
	for _, c := range []struct{ user, path, want string }{
		{"riskanalyst", "/api/v1/me", `"auth_method"`},
		{"riskanalyst", "/api/v1/scenarios", `"id"`},
		{"riskanalyst", "/api/v1/library", `"id"`},
		{"auditor", "/api/v1/posture/settings", `"key"`},
		{"auditor", "/api/v1/audit/records", `"seq"`},
		{"riskowner", "/api/v1/register/risks", `"id"`},
	} {
		if tokens[c.user] == "" {
			t.Logf("GET %s skipped: %s was not seeded (no engine)", c.path, c.user)
			continue
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+gw.addr+c.path, nil)
		req.AddCookie(&http.Cookie{Name: "__Host-sid", Value: tokens[c.user], Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", c.path, err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
		switch {
		case resp.StatusCode != http.StatusOK:
			t.Errorf("GET %s as %s: %d %s", c.path, c.user, resp.StatusCode, body)
		case !strings.Contains(string(body), c.want):
			t.Errorf("GET %s as %s returned none of the seeded data: %.300s", c.path, c.user, body)
		}
	}
	if t.Failed() {
		t.Log(dump())
	}
}


// logBuf is a service's output, written by the process and read by the test.
type logBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func tailLines(s string, n int) string {
	l := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

// trailDigest is a digest of the audit records up to seq upTo (0: all) and
// the highest seq.
func trailDigest(t *testing.T, e *env, upTo int64) (string, int64) {
	t.Helper()
	cond := ""
	if upTo > 0 {
		cond = fmt.Sprintf("WHERE seq <= %d", upTo)
	}
	out := e.adminQuery(fmt.Sprintf(`SELECT coalesce(md5(string_agg(seq || ':' || encode(body, 'hex') || ':' || encode(leaf_hash, 'hex') || ':' ||
		encode(chain_hash, 'hex') || ':' || segment, ',' ORDER BY seq)), '') || ' ' || coalesce(max(seq), 0) FROM audit.record %s`, cond))
	var d string
	var n int64
	if _, err := fmt.Sscan(out, &d, &n); err != nil && out != " 0" {
		t.Fatalf("trail digest %q: %v", out, err)
	}
	return d, n
}

// checkTrail recomputes every record's leaf and chain hash
// (internal/audit/integrity); only the record allowed may have a wrong leaf.
func checkTrail(t *testing.T, e *env, allowed string) {
	t.Helper()
	rows := e.adminQuery(`SELECT string_agg(seq || ' ' || encode(body, 'hex') || ' ' || encode(leaf_hash, 'hex') || ' ' || encode(chain_hash, 'hex'), E'\n' ORDER BY seq) FROM audit.record`)
	var prev integrity.Hash
	n := 0
	for _, l := range strings.Split(rows, "\n") {
		f := strings.Fields(l)
		if len(f) != 4 {
			continue
		}
		body, err1 := hex.DecodeString(f[1])
		leaf, err2 := hex.DecodeString(f[2])
		chain, err3 := hex.DecodeString(f[3])
		var seq uint64
		_, err4 := fmt.Sscan(f[0], &seq)
		if err := errors.Join(err1, err2, err3, err4); err != nil {
			t.Fatal(err)
		}
		if integrity.Leaf(body) != integrity.Hash(leaf) && f[0] != allowed {
			t.Errorf("audit record %d: the body does not match its leaf hash", seq)
		}
		if n > 0 && integrity.Chain(prev, seq, integrity.Hash(leaf)) != integrity.Hash(chain) {
			t.Errorf("audit record %d: the chain hash does not follow from record %d", seq, seq-1)
		}
		prev = integrity.Hash(chain)
		n++
	}
	if n == 0 {
		t.Fatal("no audit records")
	}
	t.Logf("audit trail: %d records, leaves and chain checked", n)
}
