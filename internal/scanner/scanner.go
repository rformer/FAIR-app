// Package scanner is posture-scanner (F-015 T-27, design §6.8): it reads
// the cluster through a read-only client, runs the deployment checks (the
// catalog is T-28), and reports each complete scan to the posture service
// over mTLS gRPC. It runs every 15 minutes and soon after watched resources
// change.
package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	posturev1 "github.com/rformer/fair-app/internal/api/posturev1"
	"github.com/rformer/fair-app/internal/scanner/kube"
	"github.com/rformer/fair-app/internal/server"
)

// Finding is one deployment finding. Subject names the object, for example
// "namespace/fair-platform"; posture prefixes it with "deployment:".
type Finding struct {
	CheckID     string
	Severity    string // low, medium, high, critical
	Controls    []string
	Subject     string
	DetailJSON  string // a JSON object
	Remediation string
}

// Scope is what the scanner looks at.
type Scope struct {
	Namespaces []string // the platform namespaces
}

// Check is one deployment check (T-28 adds the catalog).
type Check interface {
	ID() string
	Run(ctx context.Context, k Reader, s Scope) ([]Finding, error)
}

// Reader is the read-only API the scanner needs (kube.Client).
type Reader interface {
	List(ctx context.Context, r kube.Resource, namespace string) ([]kube.Object, string, error)
	Watch(ctx context.Context, r kube.Resource, namespace, resourceVersion string, fn func(kube.Event) error) error
}

// Access lists what the scanner reads (design §6.8 permissions table): the
// access probe tries each once per scan and reports reads RBAC refuses.
var Access = struct {
	Namespaced, Cluster []kube.Resource
}{
	Namespaced: []kube.Resource{kube.Pods, kube.Deployments, kube.StatefulSets, kube.DaemonSets, kube.Services,
		kube.NetworkPolicies, kube.ServiceAccounts, kube.Roles, kube.RoleBindings, kube.ExternalSecrets},
	Cluster: []kube.Resource{kube.Namespaces, kube.Nodes, kube.StorageClasses, kube.ClusterRoles, kube.ClusterRoleBindings,
		kube.ValidatingAdmissionPolicies, kube.ValidatingWebhookConfigurations},
}

// AccessCheckID names the access probe in check errors.
const AccessCheckID = "scanner_access"

// Scanner runs scans.
type Scanner struct {
	Kube     *kube.Client
	Reader   Reader // defaults to Kube
	Checks   []Check
	Scope    Scope
	Instance string
	Report   func(ctx context.Context, r *posturev1.ScanReport) error
	Interval time.Duration // default 15 minutes
	Debounce time.Duration // after a watch event; default 10 s
	Logger   *slog.Logger
}

func (s *Scanner) reader() Reader {
	if s.Reader != nil {
		return s.Reader
	}
	return s.Kube
}

// ScanOnce runs the access probe and every check, then reports the scan. A
// check that fails is reported as a check error, not as passed: its
// existing findings stay open.
func (s *Scanner) ScanOnce(ctx context.Context) (*posturev1.ScanReport, error) {
	r := &posturev1.ScanReport{ScannerInstance: s.Instance, StartedUnixMs: time.Now().UnixMilli()}
	r.CheckErrors = append(r.CheckErrors, s.probe(ctx)...)
	for _, c := range s.Checks {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		fs, err := c.Run(cctx, s.reader(), s.Scope)
		cancel()
		if err != nil {
			r.CheckErrors = append(r.CheckErrors, &posturev1.CheckError{CheckId: c.ID(), Error: err.Error()})
			continue
		}
		r.ChecksRun = append(r.ChecksRun, c.ID())
		for _, f := range fs {
			r.Findings = append(r.Findings, &posturev1.DeploymentFinding{CheckId: c.ID(), Severity: f.Severity, Controls: f.Controls,
				Subject: f.Subject, DetailJson: f.DetailJSON, Remediation: f.Remediation})
		}
	}
	r.FinishedUnixMs = time.Now().UnixMilli()
	if err := s.Report(ctx, r); err != nil {
		return r, fmt.Errorf("report: %w", err)
	}
	return r, nil
}

// probe reads every resource the scanner is meant to read once. A refused
// read is reported (the RBAC differs from the manifest); a resource type the
// cluster does not serve (for example an absent CRD) is not.
func (s *Scanner) probe(ctx context.Context) []*posturev1.CheckError {
	var out []*posturev1.CheckError
	try := func(r kube.Resource, ns string) {
		_, _, err := s.reader().List(ctx, r, ns)
		if err != nil && !errors.Is(err, kube.ErrNotFound) {
			out = append(out, &posturev1.CheckError{CheckId: AccessCheckID, Error: err.Error()})
		}
	}
	for _, r := range Access.Cluster {
		try(r, "")
	}
	for _, ns := range s.Scope.Namespaces {
		for _, r := range Access.Namespaced {
			try(r, ns)
		}
	}
	return out
}

// Run scans at start, every Interval, and Debounce after any watched change
// (namespaces, and pods, deployments and network policies in the platform
// namespaces), until ctx ends.
func (s *Scanner) Run(ctx context.Context) {
	interval, debounce := s.Interval, s.Debounce
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	if debounce <= 0 {
		debounce = 10 * time.Second
	}
	changed := make(chan struct{}, 1)
	var wg sync.WaitGroup
	watch := func(r kube.Resource, ns string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.watchLoop(ctx, r, ns, changed)
		}()
	}
	watch(kube.Namespaces, "")
	for _, ns := range s.Scope.Namespaces {
		for _, r := range []kube.Resource{kube.Pods, kube.Deployments, kube.NetworkPolicies} {
			watch(r, ns)
		}
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	scan := func() {
		if _, err := s.ScanOnce(ctx); err != nil && ctx.Err() == nil {
			s.Logger.Error("scan", "error", err.Error())
		}
	}
	scan()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-tick.C:
			scan()
		case <-changed:
			select { // let a burst of changes settle
			case <-ctx.Done():
			case <-time.After(debounce):
			}
			select {
			case <-changed:
			default:
			}
			scan()
		}
	}
}

// watchLoop lists and watches r, signalling changed for every event after
// the initial list, and starts over with backoff when the watch ends.
func (s *Scanner) watchLoop(ctx context.Context, r kube.Resource, ns string, changed chan<- struct{}) {
	backoff := time.Second
	for ctx.Err() == nil {
		_, rv, err := s.reader().List(ctx, r, ns)
		if err == nil {
			backoff = time.Second
			err = s.reader().Watch(ctx, r, ns, rv, func(e kube.Event) error {
				if e.Type != "BOOKMARK" {
					select {
					case changed <- struct{}{}:
					default:
					}
				}
				return nil
			})
		}
		if err != nil && ctx.Err() == nil {
			s.Logger.Warn("watch", "resource", r.String(), "namespace", ns, "error", err.Error())
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 5*time.Minute)
		}
	}
}

// ClientTLS is the scanner's side of the channel: TLS 1.2 or later with the
// platform settings, the posture CA, and the client certificate, re-read on
// every handshake so rotated certificates are picked up.
func ClientTLS(certFile, keyFile, caFile, serverName string) (*tls.Config, error) {
	ca, err := os.ReadFile(caFile) // #nosec G304 -- operator-configured mount path
	if err != nil {
		return nil, fmt.Errorf("posture CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("posture CA: no certificates in %s", caFile)
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return nil, fmt.Errorf("scanner certificate: %w", err)
	}
	c := server.TLSConfig()
	c.RootCAs = pool
	c.ServerName = serverName
	c.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}
	return c, nil
}

// Dial returns a reporter for the posture service at addr.
func Dial(addr string, tlsConf *tls.Config) (*grpc.ClientConn, func(ctx context.Context, r *posturev1.ScanReport) error, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
	if err != nil {
		return nil, nil, err
	}
	client := posturev1.NewScannerReportsClient(conn)
	return conn, func(ctx context.Context, r *posturev1.ScanReport) error {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := client.Report(ctx, r)
		return err
	}, nil
}
