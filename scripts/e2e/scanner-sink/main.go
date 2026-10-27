// Command scanner-sink is a test stand-in for the posture service's scanner
// channel, used by scripts/k8s-e2e-scanner.sh (F-015 T-27). It serves the
// real mTLS configuration (posture.ScannerTLS) and identity check, and
// logs each report as one JSON line instead of recording it.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"os"

	"google.golang.org/grpc/peer"

	posturev1 "github.com/rformer/fair-app/internal/api/posturev1"
	"github.com/rformer/fair-app/internal/posture"
)

type sink struct {
	posturev1.UnimplementedScannerReportsServer
	auth *posture.ScannerService // for its identity check only
}

func (s *sink) Report(ctx context.Context, r *posturev1.ScanReport) (*posturev1.ReportAck, error) {
	if err := s.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	from := ""
	if p, ok := peer.FromContext(ctx); ok {
		from = p.Addr.String()
	}
	b, _ := json.Marshal(map[string]any{"report": map[string]any{"instance": r.GetScannerInstance(), "checks_run": r.GetChecksRun(),
		"check_errors": r.GetCheckErrors(), "findings": len(r.GetFindings()), "from": from}})
	_, _ = os.Stdout.Write(append(b, '\n'))
	return &posturev1.ReportAck{}, nil
}

func main() {
	conf, err := posture.ScannerTLS("/tls/tls.crt", "/tls/tls.key", "/tls/ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", ":9443") // #nosec G102 -- a pod; NetworkPolicy limits who connects
	if err != nil {
		log.Fatal(err)
	}
	s := &sink{auth: &posture.ScannerService{}}
	g := posture.NewScannerGRPC(conf)
	posturev1.RegisterScannerReportsServer(g, s)
	log.Print("scanner-sink listening on :9443")
	log.Fatal(g.Serve(lis))
}
