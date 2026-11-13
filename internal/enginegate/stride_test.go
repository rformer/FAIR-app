package enginegate

import (
	"context"
	"crypto/tls"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/rformer/fair-app/internal/api/enginev1"
	"github.com/rformer/fair-app/internal/keys"
)

// F-005 T-16 (design §8): the engine channel's and the engine's isolation
// threats, attacked at the gate and in the deployment (the database rows are
// in db/tests/stride_f005_test.go).

// S: a client poses as the risk service, or calls the engine directly.
// The gate accepts only TLS with a pinned client certificate: plaintext
// gRPC, a certificate from another installation, and a client with no
// certificate are refused before anything reaches the engine; the engine
// has no network listener (TestEngineManifest).
func TestSTRIDEF005EngineChannel(t *testing.T) {
	c := start(t, time.Now)
	other := t.TempDir()
	if _, err := keys.Init(other, time.Now()); err != nil {
		t.Fatal(err)
	}
	call := func(opt grpc.DialOption) error {
		conn, err := grpc.NewClient("passthrough:///"+c.addr, opt)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err = enginev1.NewEngineClient(conn).Info(ctx, &enginev1.InfoRequest{})
		return err
	}
	if err := call(grpc.WithTransportCredentials(insecure.NewCredentials())); err == nil {
		t.Error("plaintext gRPC reached the engine")
	}
	impostor := clientConf(t, filepath.Join(other, keys.Risk, keys.EngineClientDir))
	impostor.VerifyPeerCertificate = clientConf(t, c.clientDir()).VerifyPeerCertificate // it trusts this gate
	if err := call(grpc.WithTransportCredentials(credentials.NewTLS(impostor))); err == nil {
		t.Error("another installation's client reached the engine")
	}
	anonymous := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12} // #nosec G402 -- the attacker's client
	if err := call(grpc.WithTransportCredentials(credentials.NewTLS(anonymous))); err == nil {
		t.Error("a client without a certificate reached the engine")
	}
	if err := call(grpc.WithTransportCredentials(credentials.NewTLS(clientConf(t, c.clientDir())))); err != nil {
		t.Errorf("the pinned client: %v", err)
	}
}

// I: the engine sees or keeps more than it needs. A simulation carries the
// bundle and the run's parameters only, an aggregate the members' series;
// the engine's container has no keys, no credentials, no service-account
// token and no egress (deploy/k8s/engine.yaml).
func TestSTRIDEF005EngineIsolation(t *testing.T) {
	fields := func(m protoreflect.ProtoMessage) []string {
		var out []string
		fs := m.ProtoReflect().Descriptor().Fields()
		for i := range fs.Len() {
			out = append(out, string(fs.Get(i).Name()))
		}
		slices.Sort(out)
		return out
	}
	for _, c := range []struct {
		msg  protoreflect.ProtoMessage
		want []string
	}{
		{&enginev1.SimulateRequest{}, []string{"bundle", "control_sets", "convergence_threshold_bp", "iterations", "run_id", "seed"}},
		{&enginev1.AggregateHeader{}, []string{"aggregate_id", "iterations", "members", "seed"}},
		{&enginev1.Member{}, []string{"control_set", "position", "run_id", "scenario_name"}},
		{&enginev1.MemberChunk{}, []string{"offset", "position", "values"}},
	} {
		if got := fields(c.msg); !slices.Equal(got, c.want) {
			t.Errorf("%T carries %v; the engine needs only %v", c.msg, got, c.want)
		}
	}

	ds := manifest(t, "engine.yaml")
	var spec any
	for _, d := range kinds(ds, "Deployment") {
		if get(d, "metadata", "name") == "engine" {
			spec = get(d, "spec", "template", "spec")
		}
	}
	if get(spec, "automountServiceAccountToken") != false {
		t.Error("the engine pod mounts a service-account token")
	}
	for _, v := range get(spec, "volumes").([]any) {
		if get(v, "secret") != nil || get(v, "projected") != nil {
			t.Errorf("the engine pod mounts secrets: %v", v)
		}
	}
	engine := byName(get(spec, "containers"), "engine")
	if engine["env"] != nil || engine["envFrom"] != nil || engine["ports"] != nil {
		t.Errorf("the engine container has environment or ports: %v", engine)
	}
	noEgress := false
	for _, np := range kinds(ds, "NetworkPolicy") {
		if get(np, "metadata", "name") == "engine-no-egress" {
			l, _ := get(np, "spec", "egress").([]any)
			noEgress = len(l) == 0
		}
	}
	if !noEgress {
		t.Error("the engine pod has egress")
	}
}
