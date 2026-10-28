package posture

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	posturev1 "github.com/rformer/fair-app/internal/api/posturev1"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// Deployment scan reports (F-015 T-27; AC-38, AC-39; design §6.8; migration
// 0030). posture-scanner reports each complete scan over mTLS gRPC;
// the service accepts only the scanner's certificate identity, validates
// the report (it is untrusted input), and records its findings, kind
// "deployment", with the drift finding lifecycle and events (T-26).

// DefaultScannerIdentity is the URI SAN the scanner's client certificate
// carries.
const DefaultScannerIdentity = "spiffe://fair-platform/posture-scanner"

// Limits on a report.
const (
	maxChecks      = 100
	maxFindings    = 10_000
	maxDetailBytes = 16 << 10
	maxSubject     = 512
	maxRemediation = 2000
	maxCheckError  = 1000
	maxClockSkew   = 5 * time.Minute
)

var (
	checkIDRE  = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	controlRE  = regexp.MustCompile(`^[A-Z]{2}-[0-9]+(\([0-9]+\))?$`)
	instanceRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	severities = []string{"low", "medium", "high", "critical"}
)

// ScannerService implements posturev1.ScannerReportsServer.
type ScannerService struct {
	posturev1.UnimplementedScannerReportsServer
	DB       *pgxpool.Pool // app_posture
	Audit    audit.Emitter
	Identity string // required client certificate URI SAN; DefaultScannerIdentity when empty
	Now      func() time.Time
	Logger   *slog.Logger // optional; errors are never returned to the client in detail
}

// Report records one scan.
func (s *ScannerService) Report(ctx context.Context, r *posturev1.ScanReport) (*posturev1.ReportAck, error) {
	if err := s.Authorize(ctx); err != nil {
		return nil, err
	}
	// Declined (or not yet granted) Kubernetes access disables deployment
	// drift detection (AC-40): a scanner deployed anyway records nothing.
	if err := (K8sAccess{DB: s.DB}).requireGranted(ctx); err != nil {
		if errors.Is(err, ErrAccessNotGranted) {
			return nil, status.Error(codes.FailedPrecondition, notGrantedMessage(err))
		}
		return nil, status.Error(codes.Unavailable, "posture is unavailable")
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	findings, err := validateReport(r, now())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	observations, err := validateObservations(r)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// Node FIPS mode matters only where the active profile requires it
	// (AC-41): otherwise the check counts as passed, resolving its findings.
	if slices.Contains(r.GetChecksRun(), CheckNodeFIPS) && !s.fipsRequired(ctx) {
		findings = slices.DeleteFunc(findings, func(f Finding) bool { return f.CheckID == CheckNodeFIPS })
	}
	payload, err := json.Marshal(findings)
	if err != nil {
		return nil, status.Error(codes.Internal, "encode findings")
	}
	errs, _ := json.Marshal(checkErrors(r.GetCheckErrors()))
	checks := r.GetChecksRun()
	if checks == nil {
		checks = []string{} // NOT NULL in posture.scanner_report
	}
	var opened, resolved []Finding
	err = pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if len(checks) > 0 {
			if opened, resolved, err = recordFindings(ctx, tx, s.Audit, "deployment", checks, payload); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "SELECT posture.record_deployment_observations($1, $2)", checks, observations); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, "SELECT posture.record_scanner_report($1, $2, $3, $4, $5, $6)", r.GetScannerInstance(),
			time.UnixMilli(r.GetStartedUnixMs()), time.UnixMilli(r.GetFinishedUnixMs()), checks, errs, len(findings))
		return err
	})
	if err != nil {
		if s.Logger != nil {
			s.Logger.Error("recording a deployment scan", "instance", r.GetScannerInstance(), "error", err.Error())
		}
		return nil, status.Error(codes.Unavailable, "recording the scan failed") // details stay in the service log
	}
	return &posturev1.ReportAck{Opened: int32(len(opened)), Resolved: int32(len(resolved))}, nil // #nosec G115 -- bounded by maxFindings
}

// CheckNodeFIPS is the deployment check whose findings depend on the profile.
const CheckNodeFIPS = "node_fips"

// fipsRequired reports whether fips.enabled is in force; if it cannot be
// read, FIPS counts as required (fail safe).
func (s *ScannerService) fipsRequired(ctx context.Context) bool {
	snap, err := settings.DBSource{DB: s.DB}.Snapshot(ctx)
	if err != nil {
		return true
	}
	var on bool
	if err := json.Unmarshal(snap.Instance["fips.enabled"], &on); err != nil {
		return true
	}
	return on
}

// Authorize requires a verified client certificate carrying the scanner
// identity (the TLS layer has already verified it against the scanner CA).
func (s *ScannerService) Authorize(ctx context.Context) error {
	want := s.Identity
	if want == "" {
		want = DefaultScannerIdentity
	}
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no peer")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.VerifiedChains) == 0 || len(ti.State.PeerCertificates) == 0 {
		return status.Error(codes.Unauthenticated, "a verified client certificate is required")
	}
	for _, u := range ti.State.PeerCertificates[0].URIs {
		if u.String() == want {
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "client certificate is not the posture scanner's")
}

func validateReport(r *posturev1.ScanReport, now time.Time) ([]Finding, error) {
	if !instanceRE.MatchString(r.GetScannerInstance()) {
		return nil, errors.New("invalid scanner_instance")
	}
	start, end := time.UnixMilli(r.GetStartedUnixMs()), time.UnixMilli(r.GetFinishedUnixMs())
	if r.GetStartedUnixMs() <= 0 || end.Before(start) || end.After(now.Add(maxClockSkew)) {
		return nil, errors.New("invalid scan times")
	}
	checks := r.GetChecksRun()
	if len(checks) > maxChecks {
		return nil, fmt.Errorf("more than %d checks", maxChecks)
	}
	seen := map[string]bool{}
	for _, c := range checks {
		if !checkIDRE.MatchString(c) || seen[c] || slices.Contains(driftChecks, c) || c == "revert_failed" {
			return nil, fmt.Errorf("invalid or duplicate check %q", c)
		}
		seen[c] = true
	}
	if len(r.GetFindings()) > maxFindings {
		return nil, fmt.Errorf("more than %d findings", maxFindings)
	}
	if len(r.GetCheckErrors()) > maxChecks {
		return nil, fmt.Errorf("more than %d check errors", maxChecks)
	}
	for _, ce := range r.GetCheckErrors() {
		if !checkIDRE.MatchString(ce.GetCheckId()) {
			return nil, fmt.Errorf("invalid check error id %q", ce.GetCheckId())
		}
	}
	out := make([]Finding, 0, len(r.GetFindings()))
	keys := map[string]bool{}
	for i, f := range r.GetFindings() {
		bad := func(what string) error { return fmt.Errorf("finding %d: %s", i, what) }
		switch {
		case !seen[f.GetCheckId()]:
			return nil, bad("check_id is not one of checks_run")
		case !slices.Contains(severities, f.GetSeverity()):
			return nil, bad("invalid severity")
		case len(f.GetControls()) == 0:
			return nil, bad("no controls")
		case f.GetSubject() == "" || len(f.GetSubject()) > maxSubject || strings.IndexFunc(f.GetSubject(), unicode.IsControl) >= 0:
			return nil, bad("invalid subject")
		case f.GetRemediation() == "" || len(f.GetRemediation()) > maxRemediation:
			return nil, bad("invalid remediation")
		case len(f.GetDetailJson()) > maxDetailBytes:
			return nil, bad("detail too large")
		}
		for _, c := range f.GetControls() {
			if !controlRE.MatchString(c) {
				return nil, bad("invalid control " + c)
			}
		}
		detail := json.RawMessage(f.GetDetailJson())
		if len(detail) == 0 {
			detail = json.RawMessage("{}")
		}
		var obj map[string]any
		if err := json.Unmarshal(detail, &obj); err != nil || obj == nil {
			return nil, bad("detail_json is not a JSON object")
		}
		subject := "deployment:" + f.GetSubject()
		k := f.GetCheckId() + " " + subject
		if keys[k] {
			return nil, bad("duplicate check and subject")
		}
		keys[k] = true
		out = append(out, Finding{CheckID: f.GetCheckId(), Severity: f.GetSeverity(), Controls: f.GetControls(),
			Subject: subject, Detail: detail, Remediation: f.GetRemediation()})
	}
	return out, nil
}

// observation is a validated observation, as posture stores it.
type observation struct {
	CheckID string          `json:"check_id"`
	Subject string          `json:"subject"`
	Method  string          `json:"method"`
	Detail  json.RawMessage `json:"detail"`
}

// validateObservations checks a report's observations (untrusted input,
// like its findings) and returns them as JSON for the database.
func validateObservations(r *posturev1.ScanReport) ([]byte, error) {
	if len(r.GetObservations()) > maxFindings {
		return nil, fmt.Errorf("more than %d observations", maxFindings)
	}
	out := make([]observation, 0, len(r.GetObservations()))
	seen := map[string]bool{}
	for i, o := range r.GetObservations() {
		bad := func(what string) error { return fmt.Errorf("observation %d: %s", i, what) }
		switch {
		case !slices.Contains(r.GetChecksRun(), o.GetCheckId()):
			return nil, bad("check_id is not one of checks_run")
		case o.GetMethod() != "verified" && o.GetMethod() != "attested":
			return nil, bad("method must be verified or attested")
		case o.GetSubject() == "" || len(o.GetSubject()) > maxSubject || strings.IndexFunc(o.GetSubject(), unicode.IsControl) >= 0:
			return nil, bad("invalid subject")
		case len(o.GetDetailJson()) > maxDetailBytes:
			return nil, bad("detail too large")
		}
		detail := json.RawMessage(o.GetDetailJson())
		if len(detail) == 0 {
			detail = json.RawMessage("{}")
		}
		var obj map[string]any
		if err := json.Unmarshal(detail, &obj); err != nil || obj == nil {
			return nil, bad("detail_json is not a JSON object")
		}
		subject := "deployment:" + o.GetSubject()
		if k := o.GetCheckId() + " " + subject; seen[k] {
			return nil, bad("duplicate check and subject")
		}
		seen[o.GetCheckId()+" "+subject] = true
		out = append(out, observation{CheckID: o.GetCheckId(), Subject: subject, Method: o.GetMethod(), Detail: detail})
	}
	return json.Marshal(out)
}

// Observation is how a passing deployment subject was assessed.
type Observation struct {
	CheckID, Subject, Method string
	Detail                   json.RawMessage
	ObservedAt               time.Time
}

// Observations returns the latest deployment observations, e.g. which
// nodes' FIPS mode is verified and which only attested.
func Observations(ctx context.Context, db Reader) ([]Observation, error) {
	rows, err := db.Query(ctx, "SELECT check_id, subject, method, detail, observed_at FROM posture.deployment_observations()")
	if err != nil {
		return nil, mapErr(err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Observation, error) {
		var o Observation
		err := r.Scan(&o.CheckID, &o.Subject, &o.Method, &o.Detail, &o.ObservedAt)
		return o, err
	})
}

func checkErrors(in []*posturev1.CheckError) []map[string]string {
	out := []map[string]string{}
	for _, ce := range in {
		msg := ce.GetError()
		if len(msg) > maxCheckError {
			msg = msg[:maxCheckError]
		}
		out = append(out, map[string]string{"check_id": ce.GetCheckId(), "error": msg})
	}
	return out
}

// ScannerTLS is the server side of the scanner channel: TLS 1.2 or later
// with the platform's settings, and a client certificate signed by the
// scanner CA required.
func ScannerTLS(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("scanner channel certificate: %w", err)
	}
	ca, err := os.ReadFile(clientCAFile) // #nosec G304 -- operator-configured mount path
	if err != nil {
		return nil, fmt.Errorf("scanner client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("scanner client CA: no certificates in %s", clientCAFile)
	}
	c := server.TLSConfig()
	c.Certificates = []tls.Certificate{cert}
	c.ClientAuth = tls.RequireAndVerifyClientCert
	c.ClientCAs = pool
	return c, nil
}

// NewScannerServer returns a gRPC server for svc over tlsConf.
func NewScannerServer(svc *ScannerService, tlsConf *tls.Config) *grpc.Server {
	g := NewScannerGRPC(tlsConf)
	posturev1.RegisterScannerReportsServer(g, svc)
	return g
}

// NewScannerGRPC returns the scanner channel's gRPC server, with nothing
// registered (the e2e sink registers its own).
func NewScannerGRPC(tlsConf *tls.Config) *grpc.Server {
	return grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConf)),
		grpc.MaxRecvMsgSize(16<<20),
		grpc.ConnectionTimeout(10*time.Second),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 30 * time.Second}),
	)
}
