package tests

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	posturev1 "github.com/rformer/fair-app/internal/api/posturev1"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/internal/scanner/kube"
	"github.com/rformer/fair-app/pkg/audit"
)

// F-015 T-27 (AC-38, AC-39; design §6.8): posture-scanner reports scans to
// the posture service over mTLS gRPC; posture accepts only the scanner's
// certificate identity and records deployment findings with the drift
// finding lifecycle.

// fakeReader serves empty lists, refusing the resources in forbidden.
type fakeReader struct{ forbidden map[string]bool }

func (f fakeReader) List(_ context.Context, r kube.Resource, _ string) ([]kube.Object, string, error) {
	if f.forbidden[r.Plural] {
		return nil, "", kube.ErrForbidden
	}
	return nil, "1", nil
}

func (f fakeReader) Watch(ctx context.Context, _ kube.Resource, _, _ string, _ func(kube.Event) error) error {
	<-ctx.Done()
	return nil
}

type staticCheck struct {
	id           string
	findings     []scanner.Finding
	observations []scanner.Observation
	err          error
}

func (c *staticCheck) ID() string { return c.id }
func (c *staticCheck) Run(context.Context, scanner.Reader, scanner.Scope) (scanner.Result, error) {
	return scanner.Result{Findings: c.findings, Observations: c.observations}, c.err
}

type scannerEnv struct {
	driftEnv
	addr    string
	ca      testCA
	lines   *bytes.Buffer
	sink    *audit.Memory
	report  func(context.Context, *posturev1.ScanReport) error
	clientT func(t *testing.T, cn string, uris ...string) *tls.Config
}

func scannerFixture(t *testing.T) scannerEnv {
	t.Helper()
	de := driftFixture(t)
	// Reports are accepted only with Kubernetes access granted (T-30).
	if _, err := (posture.K8sAccess{DB: de.e.posturePool(), Audit: audit.NewMemory()}).Decide(context.Background(), posture.AccessGranted, "", ""); err != nil {
		t.Fatal(err)
	}
	ca := newTestCA(t, "platform")
	srvCert, srvKey := ca.issue(t, "posture", false, []string{"posture.fair-platform"})
	conf, err := posture.ScannerTLS(srvCert, srvKey, ca.pemFile)
	if err != nil {
		t.Fatal(err)
	}
	var lines bytes.Buffer
	sink := audit.NewMemory()
	g := posture.NewScannerServer(&posture.ScannerService{DB: de.e.posturePool(), Audit: audit.Multi{audit.NewJSONLines(&lines), sink}}, conf)
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = g.Serve(lis) }()
	t.Cleanup(g.Stop)
	clientT := func(t *testing.T, cn string, uris ...string) *tls.Config {
		t.Helper()
		c, k := ca.issue(t, cn, true, nil, uris...)
		conf, err := scanner.ClientTLS(c, k, ca.pemFile, "posture.fair-platform")
		if err != nil {
			t.Fatal(err)
		}
		return conf
	}
	conn, report, err := scanner.Dial(lis.Addr().String(), clientT(t, "posture-scanner", posture.DefaultScannerIdentity))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return scannerEnv{driftEnv: de, addr: lis.Addr().String(), ca: ca, lines: &lines, sink: sink, report: report, clientT: clientT}
}

func TestScannerReportsOverMTLS(t *testing.T) {
	ctx := context.Background()
	se := scannerFixture(t)
	e := se.e
	pss := &staticCheck{id: "pod_security_admission", findings: []scanner.Finding{
		{Severity: "high", Controls: []string{"CM-6", "CM-7"}, Subject: "namespace/fair-platform", DetailJSON: `{"enforce":"baseline"}`, Remediation: "Label the namespace restricted."},
		{Severity: "high", Controls: []string{"CM-6", "CM-7"}, Subject: "namespace/fair-data", DetailJSON: `{"enforce":""}`, Remediation: "Label the namespace restricted."},
	}}
	np := &staticCheck{id: "network_policy_default_deny"}
	sc := &scanner.Scanner{Reader: fakeReader{forbidden: map[string]bool{"nodes": true}}, Checks: []scanner.Check{pss, np},
		Scope: scanner.Scope{Namespaces: []string{"fair-platform", "fair-data"}}, Instance: "posture-scanner-0", Report: se.report}

	r, err := sc.ScanOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.ChecksRun, []string{"pod_security_admission", "network_policy_default_deny"}) || len(r.CheckErrors) != 1 ||
		r.CheckErrors[0].CheckId != scanner.AccessCheckID {
		t.Fatalf("report %v / %v", r.ChecksRun, r.CheckErrors)
	}
	wantIDs(t, "deployment findings", se.open(t),
		"pod_security_admission deployment:namespace/fair-data", "pod_security_admission deployment:namespace/fair-platform")
	if got := e.adminQuery("SELECT string_agg(DISTINCT kind, ',') FROM posture.drift_finding"); got != "deployment" {
		t.Fatalf("kinds %s", got)
	}
	if got := e.adminQuery("SELECT instance || ':' || cardinality(checks_run) || ':' || jsonb_array_length(check_errors) || ':' || findings FROM posture.scanner_report"); got != "posture-scanner-0:2:1:2" {
		t.Fatalf("scanner report %s", got)
	}

	// Fixed in one namespace: resolved. A check that fails keeps its findings.
	pss.findings = pss.findings[1:]
	if _, err := sc.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	wantIDs(t, "after fix", se.open(t), "pod_security_admission deployment:namespace/fair-data")
	pss.err = errors.New("apiserver timeout")
	if _, err := sc.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	wantIDs(t, "check failed: findings kept", se.open(t), "pod_security_admission deployment:namespace/fair-data")

	// Events follow the drift event schema (kind deployment, deployment: targets).
	sc2 := bufio.NewScanner(se.lines)
	n := 0
	for sc2.Scan() {
		n++
		if err := posture.ValidateDriftEvent(sc2.Bytes()); err != nil {
			t.Errorf("event does not match the schema: %v\n%s", err, sc2.Text())
		}
	}
	if n != 3 || se.sink.OfType(posture.EventDriftDetected)[0].Attributes["kind"] != "deployment" {
		t.Fatalf("%d events", n)
	}
}

func TestScannerChannelAuthentication(t *testing.T) {
	ctx := context.Background()
	se := scannerFixture(t)
	report := func(conf *tls.Config) error {
		conn, rep, err := scanner.Dial(se.addr, conf)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		return rep(ctx, &posturev1.ScanReport{ScannerInstance: "x", StartedUnixMs: time.Now().UnixMilli(), FinishedUnixMs: time.Now().UnixMilli()})
	}
	if err := report(se.clientT(t, "posture-scanner", posture.DefaultScannerIdentity)); err != nil {
		t.Fatalf("scanner identity: %v", err)
	}
	if err := report(se.clientT(t, "iam", "spiffe://fair-platform/iam")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("another platform identity: %v", err)
	}
	if err := report(se.clientT(t, "no-uri")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("no identity: %v", err)
	}
	foreign := newTestCA(t, "foreign")
	c, k := foreign.issue(t, "posture-scanner", true, nil, posture.DefaultScannerIdentity)
	conf, err := scanner.ClientTLS(c, k, se.ca.pemFile, "posture.fair-platform")
	if err != nil {
		t.Fatal(err)
	}
	if err := report(conf); status.Code(err) != codes.Unavailable {
		t.Fatalf("certificate from another CA: %v", err)
	}
	// No client certificate at all, and TLS below 1.2, are refused.
	noCert := se.clientT(t, "posture-scanner", posture.DefaultScannerIdentity)
	noCert.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }
	if err := report(noCert); status.Code(err) != codes.Unavailable {
		t.Fatalf("no client certificate: %v", err)
	}
	old := se.clientT(t, "posture-scanner", posture.DefaultScannerIdentity)
	old.MinVersion, old.MaxVersion, old.CipherSuites = tls.VersionTLS10, tls.VersionTLS11, nil
	if err := report(old); status.Code(err) != codes.Unavailable {
		t.Fatalf("TLS 1.1: %v", err)
	}
	if got := se.e.adminQuery("SELECT count(*) FROM posture.scanner_report"); got != "1" {
		t.Fatalf("%s reports recorded", got)
	}
}

// Reports are untrusted input: anything malformed is refused whole.
func TestScannerReportValidation(t *testing.T) {
	ctx := context.Background()
	se := scannerFixture(t)
	conn, err := grpc.NewClient(se.addr, grpc.WithTransportCredentials(credentials.NewTLS(se.clientT(t, "posture-scanner", posture.DefaultScannerIdentity))))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	client := posturev1.NewScannerReportsClient(conn)
	now := time.Now().UnixMilli()
	good := func() *posturev1.ScanReport {
		return &posturev1.ScanReport{ScannerInstance: "posture-scanner-0", StartedUnixMs: now - 1000, FinishedUnixMs: now,
			ChecksRun: []string{"pod_security_admission"},
			Findings: []*posturev1.DeploymentFinding{{CheckId: "pod_security_admission", Severity: "high", Controls: []string{"CM-6"},
				Subject: "namespace/x", DetailJson: `{"a":1}`, Remediation: "Fix it."}}}
	}
	if _, err := client.Report(ctx, good()); err != nil {
		t.Fatalf("good report: %v", err)
	}
	for name, mutate := range map[string]func(*posturev1.ScanReport){
		"finding for a check not run": func(r *posturev1.ScanReport) { r.Findings[0].CheckId = "image_digests" },
		"application check id": func(r *posturev1.ScanReport) {
			r.ChecksRun[0], r.Findings[0].CheckId = "row_mac_mismatch", "row_mac_mismatch"
		},
		"bad severity":         func(r *posturev1.ScanReport) { r.Findings[0].Severity = "urgent" },
		"bad control":          func(r *posturev1.ScanReport) { r.Findings[0].Controls = []string{"cm6"} },
		"no controls":          func(r *posturev1.ScanReport) { r.Findings[0].Controls = nil },
		"detail not an object": func(r *posturev1.ScanReport) { r.Findings[0].DetailJson = `[1]` },
		"control character":    func(r *posturev1.ScanReport) { r.Findings[0].Subject = "ns/\x1b[31mx" },
		"duplicate finding":    func(r *posturev1.ScanReport) { r.Findings = append(r.Findings, r.Findings[0]) },
		"bad instance":         func(r *posturev1.ScanReport) { r.ScannerInstance = "a b" },
		"from the future":      func(r *posturev1.ScanReport) { r.FinishedUnixMs = now + int64(time.Hour/time.Millisecond) },
		"duplicate check":      func(r *posturev1.ScanReport) { r.ChecksRun = append(r.ChecksRun, r.ChecksRun[0]) },
	} {
		r := good()
		mutate(r)
		if _, err := client.Report(ctx, r); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	wantIDs(t, "only the good report recorded", se.open(t), "pod_security_admission deployment:namespace/x")
}

// T-29: observations record how passing subjects were assessed; each scan
// replaces those of the checks it ran, and they are validated like findings.
func TestScannerObservations(t *testing.T) {
	ctx := context.Background()
	se := scannerFixture(t)
	fips := &staticCheck{id: posture.CheckNodeFIPS, observations: []scanner.Observation{
		{Subject: "node/a", Method: "verified", DetailJSON: `{"probe_pod":"fips-probe-x"}`},
		{Subject: "node/b", Method: "attested", DetailJSON: `{"label":"fair-platform.io/fips=attested"}`}}}
	sc := &scanner.Scanner{Reader: fakeReader{}, Checks: []scanner.Check{fips}, Instance: "s-0", Report: se.report}
	got := func() string {
		t.Helper()
		os, err := posture.Observations(ctx, se.e.posturePool())
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, o := range os {
			out = append(out, o.CheckID+" "+o.Subject+" "+o.Method)
		}
		return strings.Join(out, ", ")
	}
	if _, err := sc.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if g := got(); g != "node_fips deployment:node/a verified, node_fips deployment:node/b attested" {
		t.Fatalf("observations %s", g)
	}
	fips.observations = fips.observations[1:] // node a left the cluster
	if _, err := sc.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if g := got(); g != "node_fips deployment:node/b attested" {
		t.Fatalf("after the second scan: %s", g)
	}
	fips.err = errors.New("apiserver timeout") // a failed check keeps its last observations
	if _, err := sc.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if g := got(); g != "node_fips deployment:node/b attested" {
		t.Fatalf("after a failed check: %s", g)
	}
	for name, o := range map[string]*posturev1.Observation{
		"unknown method":       {CheckId: posture.CheckNodeFIPS, Subject: "node/c", Method: "assumed"},
		"check not run":        {CheckId: "pod_hardening", Subject: "node/c", Method: "verified"},
		"detail not an object": {CheckId: posture.CheckNodeFIPS, Subject: "node/c", Method: "verified", DetailJson: "[]"},
	} {
		r := &posturev1.ScanReport{ScannerInstance: "s-0", StartedUnixMs: time.Now().UnixMilli(), FinishedUnixMs: time.Now().UnixMilli(),
			ChecksRun: []string{posture.CheckNodeFIPS}, Observations: []*posturev1.Observation{o}}
		if err := se.report(ctx, r); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// AC-41: node FIPS findings count only where the active profile requires
// FIPS mode (fips.enabled).
func TestScannerNodeFIPSFollowsProfile(t *testing.T) {
	ctx := context.Background()
	se := scannerFixture(t) // FedRAMP Moderate: FIPS required
	fips := &staticCheck{id: posture.CheckNodeFIPS, findings: []scanner.Finding{
		{Severity: "high", Controls: []string{"SC-13"}, Subject: "node/worker-0", DetailJSON: `{"fips":""}`, Remediation: "Enable FIPS mode."}}}
	sc := &scanner.Scanner{Reader: fakeReader{}, Checks: []scanner.Check{fips}, Instance: "s-0", Report: se.report}
	if _, err := sc.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	wantIDs(t, "FIPS required", se.open(t), "node_fips deployment:node/worker-0")

	// Under a profile that does not require FIPS the same scan passes.
	se.e.admin(se.e.db, `UPDATE posture.setting_value SET value = 'false' WHERE key = 'fips.enabled' AND bu_id IS NULL`)
	if _, err := sc.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	wantIDs(t, "FIPS not required", se.open(t))
}
