package tests

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	posturev1 "github.com/rformer/fair-app/internal/api/posturev1"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/audit"
)

// Verification for F-015 T-30 (AC-39, AC-40): declined path -> no scanner
// reports accepted, a persistent banner, every deployment check Not
// assessed; a later grant needs an admin's acknowledgement.
func TestK8sAccessConsent(t *testing.T) {
	ctx := context.Background()
	se := scannerFixture(t) // granted at install (self-hosted)
	e := se.e
	mem := audit.NewMemory()
	k := posture.K8sAccess{DB: e.posturePool(), Audit: mem}
	report := func() error {
		return se.report(ctx, &posturev1.ScanReport{ScannerInstance: "s-0", StartedUnixMs: time.Now().UnixMilli(),
			FinishedUnixMs: time.Now().UnixMilli(), ChecksRun: []string{"pod_security_admission", "node_fips"},
			CheckErrors: []*posturev1.CheckError{{CheckId: "tls_endpoints", Error: "dial timeout"}}})
	}
	assessed := func() map[string]string {
		t.Helper()
		as, err := k.Assessment(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(as) != 10 {
			t.Fatalf("%d checks assessed", len(as))
		}
		out := map[string]string{}
		for _, a := range as {
			if len(a.Controls) == 0 {
				t.Errorf("%s has no controls", a.CheckID)
			}
			out[a.CheckID] = a.Reason
			if a.Assessed {
				out[a.CheckID] = "assessed"
			}
		}
		return out
	}
	st, err := k.Status(ctx)
	if err != nil || st.State != posture.AccessGranted || st.Warning != "" || st.Digest != st.CurrentDigest {
		t.Fatalf("granted at install: %+v %v", st, err)
	}

	// Granted: reports are accepted; checks that ran are assessed, the
	// failed one and those that did not run are Not assessed.
	if err := report(); err != nil {
		t.Fatal(err)
	}
	a := assessed()
	if a["pod_security_admission"] != "assessed" || !strings.Contains(a["tls_endpoints"], "dial timeout") || a["image_digests"] != "the check did not run" {
		t.Fatalf("granted assessment %v", a)
	}
	// A silent scanner: Not assessed.
	e.admin(e.db, "UPDATE posture.scanner_report SET received_at = now() - interval '1 hour'")
	if a := assessed(); !strings.Contains(a["pod_security_admission"], "has not reported since") {
		t.Fatalf("stale assessment %v", a)
	}

	// Revoke: a reason is required; then disabled with a banner.
	if _, err := k.Decide(ctx, posture.AccessRevoked, " ", ""); !errors.Is(err, posture.ErrExplanationRequired) {
		t.Fatalf("revoke without reason: %v", err)
	}
	if _, err := k.Decide(ctx, posture.AccessRevoked, "security review pending", ""); err != nil {
		t.Fatal(err)
	}
	if ev := mem.OfType("posture.k8s_access_revoked"); len(ev) != 1 || ev[0].Severity != audit.SeverityHigh || ev[0].Actor != posture.InstallerActor {
		t.Fatalf("revoke audit %+v", ev)
	}
	st, _ = k.Status(ctx)
	if st.State != posture.AccessRevoked || !strings.Contains(st.Warning, "revoked") || !strings.Contains(st.Warning, "Not assessed") {
		t.Fatalf("revoked status %+v", st)
	}
	if err := report(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("report while revoked: %v", err)
	}
	for id, r := range assessed() {
		if r != "Kubernetes access revoked" {
			t.Errorf("%s: %s", id, r)
		}
	}

	// A later grant: requested by the installer, acknowledged by an admin.
	if _, err := k.Decide(ctx, posture.AccessGranted, "", ""); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("installer granting directly after a revoke: %v", err)
	}
	if _, err := k.Decide(ctx, posture.AccessRequested, "", ""); err != nil {
		t.Fatal(err)
	}
	st, _ = k.Status(ctx)
	if !strings.Contains(st.Warning, "acknowledgement") {
		t.Fatalf("requested banner %q", st.Warning)
	}
	if err := report(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("report while requested: %v", err)
	}
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('viewer@example.test', 'Viewer')")
	e.mustOwner(grant("admin", "user:viewer", "Executive Viewer", "ENTERPRISE"))
	e.drain()
	if err := k.Acknowledge(ctx, e.principal("viewer"), st.Digest); !errors.Is(err, posture.ErrNotPermitted) {
		t.Fatalf("acknowledge without settings.change: %v", err)
	}
	if err := k.Acknowledge(ctx, e.principal("admin"), strings.Repeat("0", 64)); !errors.Is(err, posture.ErrInvalidValue) {
		t.Fatalf("acknowledge other permissions: %v", err)
	}
	if err := k.Acknowledge(ctx, e.principal("admin"), st.Digest); err != nil {
		t.Fatal(err)
	}
	if st, _ = k.Status(ctx); st.State != posture.AccessGranted || st.Warning != "" {
		t.Fatalf("after acknowledgement %+v", st)
	}
	if ev := mem.OfType("posture.k8s_access_granted"); len(ev) != 1 || ev[0].Actor != e.principal("admin").UserID {
		t.Fatalf("acknowledgement audit %+v", ev)
	}
	if err := report(); err != nil {
		t.Fatalf("report after acknowledgement: %v", err)
	}

	// A release with changed permissions asks for re-consent.
	e.admin(e.db, "UPDATE posture.k8s_access SET permissions_digest = repeat('a', 64)")
	if st, _ = k.Status(ctx); !strings.Contains(st.Warning, "changes the scanner") {
		t.Fatalf("changed permissions banner %q", st.Warning)
	}
	if _, err := k.Decide(ctx, posture.AccessGranted, "", ""); err != nil {
		t.Fatalf("re-consent: %v", err)
	}
	if st, _ = k.Status(ctx); st.Warning != "" {
		t.Fatalf("after re-consent %q", st.Warning)
	}
}

// Declined at install: nothing assessed and a banner; SaaS cannot decline
// (AC-38) and counts as granted when undecided.
func TestK8sAccessDeclinedAndSaaS(t *testing.T) {
	ctx := context.Background()
	de := driftFixture(t) // self-hosted, undecided
	e := de.e
	k := posture.K8sAccess{DB: e.posturePool(), Audit: audit.NewMemory()}
	st, err := k.Status(ctx)
	if err != nil || st.State != posture.AccessUndecided || !strings.Contains(st.Warning, "not been decided") {
		t.Fatalf("undecided %+v %v", st, err)
	}
	if _, err := k.Decide(ctx, posture.AccessRequested, "", ""); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("request before any decision: %v", err)
	}
	if _, err := k.Decide(ctx, posture.AccessDeclined, "", ""); !errors.Is(err, posture.ErrExplanationRequired) {
		t.Fatalf("decline without reason: %v", err)
	}
	if _, err := k.Decide(ctx, posture.AccessDeclined, "no cluster-wide reads in this environment", ""); err != nil {
		t.Fatal(err)
	}
	st, _ = k.Status(ctx)
	if st.State != posture.AccessDeclined || !strings.Contains(st.Warning, "declined") || !strings.Contains(st.Warning, "grant it later") {
		t.Fatalf("declined %+v", st)
	}
	as, _ := k.Assessment(ctx, 0)
	for _, a := range as {
		if a.Assessed || a.Reason != "Kubernetes access declined" {
			t.Errorf("%+v", a)
		}
	}

	// SaaS: always on.
	e.mustOwner("SELECT posture.set_deployment_mode('saas')")
	e.admin(e.db, "DELETE FROM posture.k8s_access")
	if st, _ = k.Status(ctx); st.State != posture.AccessGranted || st.Warning != "" {
		t.Fatalf("SaaS undecided %+v", st)
	}
	if _, err := k.Decide(ctx, posture.AccessDeclined, "please", ""); !errors.Is(err, posture.ErrNotApplicable) {
		t.Fatalf("SaaS decline: %v", err)
	}
}
