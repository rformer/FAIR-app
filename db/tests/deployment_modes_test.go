package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/config"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/pkg/audit"
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
}
