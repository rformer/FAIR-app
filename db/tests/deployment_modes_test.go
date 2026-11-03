package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/config"
	"github.com/rformer/fair-app/internal/keys"
	"github.com/rformer/fair-app/internal/migrate"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-37: the deployment-mode matrix (design §11, requirements
// "Deployment modes"). Each subtest installs one mode and checks every row
// of the table; CI runs the modes as a matrix (job deployment-modes).
func TestDeploymentModeMatrix(t *testing.T) {
	for _, mode := range []string{config.ModeSaaS, config.ModeSelfHosted, config.ModeAirGapped} {
		t.Run(mode, func(t *testing.T) { deploymentMode(t, mode) })
	}
}

func deploymentMode(t *testing.T, mode string) {
	ctx := context.Background()
	rg := registryFixture(t, settings.ProfileEnterpriseBaseline, mode)
	e := rg.e
	saas := mode == config.ModeSaaS
	if got := e.adminQuery("SELECT posture.deployment_mode()"); got != mode {
		t.Fatalf("recorded mode %q", got)
	}

	// Keys and integrations: what the posture service checks at startup.
	var macKey *string
	if err := e.posturePool().QueryRow(ctx, "SELECT posture.mac_key_active()").Scan(&macKey); err != nil || macKey == nil {
		t.Fatalf("active MAC key: %v %v", macKey, err)
	}
	vars := map[string]string{"FAIR_EXPORT_SIGNING_KEY_FILE": "/secrets/export.key", "FAIR_JWT_KEYS_DIR": "/secrets/jwt"}
	if saas {
		maps.Copy(vars, map[string]string{"FAIR_SECOPS_WEBHOOK_URL": "https://secops.vendor.example/intake",
			"FAIR_SECOPS_SECRET_FILE": "/secrets/secops", "FAIR_SCANNER_GRPC_ADDR": ":9443"})
	}
	check := func(v map[string]string) error {
		return posture.CheckInstall(posture.InstallCheck{Env: "production", Mode: mode, Getenv: func(k string) string { return v[k] }, ActiveMACKey: macKey})
	}
	if err := check(vars); err != nil {
		t.Fatalf("a complete %s install refused: %v", mode, err)
	}
	withWebhook := maps.Clone(vars)
	withWebhook["FAIR_SECOPS_WEBHOOK_URL"], withWebhook["FAIR_SECOPS_SECRET_FILE"] = "https://secops.vendor.example/intake", "/secrets/secops"
	if err := check(withWebhook); (err != nil) != (mode == config.ModeAirGapped) {
		t.Errorf("a SecOps webhook in %s mode: %v", mode, err)
	}

	// Profile packages: the release's packages load at migrate in every
	// mode; later ones import offline, verified with the bundled key.
	if got := e.adminQuery("SELECT count(*) FROM posture.profile WHERE kind = 'builtin'"); got != "3" {
		t.Fatalf("%s built-in profiles", got)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	files, _ := releaseFiles(t)
	sigs, err := profilepkg.SignRelease(key, "manifest.json", files)
	if err != nil {
		t.Fatal(err)
	}
	signed := maps.Clone(files)
	maps.Copy(signed, sigs)
	if _, err := posture.Import(ctx, e.posturePool(), audit.NewMemory(), &key.PublicKey, "system:installer", signed); err != nil {
		t.Errorf("offline import of a signed release: %v", err)
	}
	if _, err := posture.Import(ctx, e.posturePool(), audit.NewMemory(), &key.PublicKey, "system:installer", files); err == nil {
		t.Error("an unsigned release imported")
	}

	// Deployment drift: always on in SaaS; opt-in with a warning otherwise.
	k := posture.K8sAccess{DB: e.posturePool(), Audit: audit.NewMemory()}
	st, err := k.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if saas != (st.State == posture.AccessGranted && st.Warning == "") || !saas && st.State != posture.AccessUndecided {
		t.Errorf("undecided Kubernetes access in %s mode: %q %q", mode, st.State, st.Warning)
	}
	_, err = k.Decide(ctx, posture.AccessDeclined, "customer declined", "")
	if saas != errors.Is(err, posture.ErrNotApplicable) || !saas && err != nil {
		t.Errorf("declining access in %s mode: %v", mode, err)
	}

	// Weakening notifications: vendor SecOps only in SaaS.
	r, err := rg.set.Set(ctx, e.principal("admin"), settings.Request{Key: settings.KeySessionIdleTimeout, Value: 25 * time.Minute,
		Explanation: "call centre shifts"})
	if err != nil || r.Outcome != settings.Applied {
		t.Fatalf("in-bounds loosening: %+v %v", r, err)
	}
	want := "0"
	if saas {
		want = "1"
	}
	if got := e.adminQuery("SELECT count(*) FROM posture.secops_outbox"); got != want {
		t.Errorf("SecOps notifications in %s mode: %s, want %s", mode, got, want)
	}

	// OSCAL export: the same in every mode, signed with the installation's
	// key and naming the mode.
	exportKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	x, err := (posture.Exports{DB: e.posturePool(), Audit: audit.NewMemory(), Key: exportKey}).Create(ctx, e.principal("admin"), posture.KindAssessmentResults)
	if err != nil {
		t.Fatal(err)
	}
	if err := posture.VerifyExport(&exportKey.PublicKey, x.Document, x.Statement, x.Signature); err != nil {
		t.Errorf("export signature: %v", err)
	}
	if !strings.Contains(string(x.Document), `"value": "`+mode+`"`) {
		t.Errorf("the export does not name the %s mode", mode)
	}

	// The mode is one of the three.
	if out, err := e.owner("SELECT posture.set_deployment_mode('offline')"); err == nil || !strings.Contains(out, "saas, self-hosted or air-gapped") {
		t.Errorf("an unknown mode: %v %s", err, out)
	}
	deploymentModeF001(t, mode, e)
}

// deploymentModeF001 checks F-001's rows of the matrix (design §10; T-41).
func deploymentModeF001(t *testing.T, mode string, e *env) {
	ctx := context.Background()
	saas := mode == config.ModeSaaS

	// Signing keys: files in every mode, from the mode's store (the store
	// itself: scripts/openbao-e2e.sh, deploy/k8s/keys). iam keys init
	// creates them; the DB-context key is registered by the installer and
	// then verifies the gateway's contexts.
	dir := t.TempDir()
	set, err := keys.Init(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Check(dir); err != nil {
		t.Fatal(err)
	}
	cc, err := migrate.ConnConfig("development", e.secrets["app_migrator"])
	if err != nil {
		t.Fatal(err)
	}
	cc.Database = e.db
	mem := audit.NewMemory()
	catalog, err := audit.DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	emit := audit.Validating{Next: mem, Catalog: catalog}
	withConn := func(f func(*pgx.Conn) error) error {
		conn, err := pgx.ConnectConfig(ctx, cc)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close(ctx) }()
		return f(conn)
	}
	register := func() (bool, error) {
		var added bool
		err := withConn(func(c *pgx.Conn) error {
			var err error
			_, added, err = keys.RegisterDBContext(ctx, c, emit, dir)
			return err
		})
		return added, err
	}
	if added, err := register(); err != nil || !added {
		t.Fatalf("registering the DB-context key: %v %v", added, err)
	}
	if added, err := register(); err != nil || added {
		t.Fatalf("registering it again: %v %v", added, err)
	}
	sec, _ := keys.ReadSecret(filepath.Join(dir, keys.Gateway, keys.SecretsDir, keys.DBContextKey), keys.SecretLen)
	first := authz.ContextKey{ID: set.DBContext, Secret: sec}
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('erin@example.test', 'Erin')")
	e.mustOwner(grant("admin", "user:erin", "Executive Viewer", "ENTERPRISE"))
	e.drain()
	e.mustOwner("SELECT authz.retire_ctx_key('k1', now())") // the fixture's key: ours is the only one
	scoped := func(k authz.ContextKey) string {
		out, _ := e.asCtx(e.mint("erin", k), "SELECT cardinality(authz.visible_bus('register')) > 0")
		return out
	}
	if got := scoped(first); got != "t" {
		t.Fatalf("a context signed with the registered key: %q", got)
	}
	// Rotation: register the successor, then retire the old key; contexts
	// it signed still verify for the retirement window.
	if err := withConn(func(c *pgx.Conn) error { return keys.RetireDBContext(ctx, c, emit, set.DBContext) }); err == nil {
		t.Fatal("retired the only DB-context key")
	}
	next, err := keys.Rotate(dir, keys.KindDBContext, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if added, err := register(); err != nil || !added {
		t.Fatalf("registering the successor: %v %v", added, err)
	}
	if err := withConn(func(c *pgx.Conn) error { return keys.RetireDBContext(ctx, c, emit, set.DBContext) }); err != nil {
		t.Fatal(err)
	}
	sec2, _ := keys.ReadSecret(filepath.Join(dir, keys.Gateway, keys.SecretsDir, keys.DBContextKey), keys.SecretLen)
	if scoped(authz.ContextKey{ID: next, Secret: sec2}) != "t" || scoped(first) != "t" {
		t.Error("the successor, or the retired key within its window, does not verify")
	}
	// A key directory from another installation does not overwrite this one's.
	_ = os.WriteFile(filepath.Join(dir, keys.Gateway, keys.SecretsDir, keys.DBContextKey), []byte(strings.Repeat("z", 43)), 0o600)
	if _, err := register(); !errors.Is(err, keys.ErrKeyMismatch) {
		t.Fatalf("a different secret under a registered id: %v", err)
	}
	if n := len(mem.Events()); n != 3 {
		t.Errorf("%d install-log events, want 3 (two registrations, one retirement)", n)
	}

	// Break-glass alerts: the vendor's SecOps only in SaaS; the internal
	// relay (iam.notice_outbox, F-009) in every mode.
	before := e.adminQuery("SELECT count(*) FROM posture.secops_outbox")
	e.mustOwner(`SELECT posture.breakglass_secops('{"type": "breakglass.login"}')`)
	want, _ := strconv.Atoi(before)
	if saas {
		want++
	}
	if got := e.adminQuery("SELECT count(*) FROM posture.secops_outbox"); got != strconv.Itoa(want) {
		t.Errorf("break-glass SecOps alerts in %s mode: %s, want %d", mode, got, want)
	}

	// IdP metadata: URL fetches everywhere but air-gapped, which takes
	// files only. (Last: a new fixture resets the shared roles' passwords.)
	ie := idpFixture(t)
	ie.api.DeploymentMode = mode
	oid := ie.create(t, "oidc", "Partner", "partner.example")
	r := ie.do(t, "POST", "/api/v1/idps/"+oid+"/metadata/fetch", ie.admin, map[string]any{"url": "https://idp.partner.example", "reason": "x"}, ie.hdr())
	if (r.body["error"] == "air_gapped") != (mode == config.ModeAirGapped) {
		t.Errorf("a metadata URL fetch in %s mode: %d %s", mode, r.code, r.raw)
	}
}
