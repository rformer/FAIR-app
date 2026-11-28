package checks

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"

	"github.com/rformer/fair-app/internal/profilepkg"
	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/internal/scanner/kube"
)

// Verification for F-015 T-28: every check has passing and failing fixtures
// for kind/k3d, OpenShift and RKE2. A fixture is a cluster written as the
// API objects that distribution produces (testdata/<distribution>/pass.yaml
// and fail.yaml), on top of the platform RBAC of deploy/k8s; a fixture
// object annotated fixture/delete removes the object of that kind and name.
// Service addresses dial local test servers (fixture/tls annotation on the
// Service: good, expiring, expired, plaintext, tls10, weak).

// fixtureReader serves a fixture's objects.
type fixtureReader struct {
	objs   map[string][]kube.Object // resource plural -> objects
	served map[string]bool          // resource plurals the "cluster" serves
}

func (f *fixtureReader) List(_ context.Context, r kube.Resource, ns string) ([]kube.Object, string, error) {
	if !f.served[r.Plural] {
		return nil, "", kube.ErrNotFound
	}
	var out []kube.Object
	for _, o := range f.objs[r.Plural] {
		if !r.Namespaced || ns == "" || o.Metadata.Namespace == ns {
			out = append(out, o)
		}
	}
	return out, "1", nil
}

func (f *fixtureReader) Watch(ctx context.Context, _ kube.Resource, _, _ string, _ func(kube.Event) error) error {
	<-ctx.Done()
	return nil
}

var plurals = map[string]string{
	"Namespace": "namespaces", "Node": "nodes", "Pod": "pods", "Service": "services", "ServiceAccount": "serviceaccounts",
	"Deployment": "deployments", "NetworkPolicy": "networkpolicies", "Role": "roles", "RoleBinding": "rolebindings",
	"ClusterRole": "clusterroles", "ClusterRoleBinding": "clusterrolebindings", "StorageClass": "storageclasses",
	"PersistentVolumeClaim": "persistentvolumeclaims", "ValidatingAdmissionPolicy": "validatingadmissionpolicies",
	"ValidatingWebhookConfiguration": "validatingwebhookconfigurations", "ExternalSecret": "externalsecrets",
}

func yamlDocs(t *testing.T, file string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(file) // #nosec G304 -- test fixtures
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var out []map[string]any
	for {
		var d map[string]any
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			return out
		} else if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if d != nil {
			out = append(out, d)
		}
	}
}

func loadFixture(t *testing.T, distro, variant string) *fixtureReader {
	t.Helper()
	type key struct{ kind, ns, name string }
	docs := map[key]map[string]any{}
	var order []key
	add := func(d map[string]any) {
		md, _ := d["metadata"].(map[string]any)
		k := key{fmt.Sprint(d["kind"]), fmt.Sprint(md["namespace"]), fmt.Sprint(md["name"])}
		if ann, _ := md["annotations"].(map[string]any); ann["fixture/delete"] == "true" {
			delete(docs, k)
			return
		}
		if _, ok := docs[k]; !ok {
			order = append(order, k)
		}
		docs[k] = d
	}
	for _, d := range yamlDocs(t, "../../../deploy/k8s/posture-scanner.yaml") {
		if slices.Contains(releasemanifest.RBACKinds, fmt.Sprint(d["kind"])) {
			add(d)
		}
	}
	for _, d := range yamlDocs(t, filepath.Join("testdata", distro, variant+".yaml")) {
		add(d)
	}
	// F-014 T-04: a compliant cluster runs the reference gateway and posture
	// as deploy/k8s describes them; they must pass every check.
	if variant == "pass" {
		for _, d := range referenceWorkloads(t) {
			add(d)
		}
	}
	f := &fixtureReader{objs: map[string][]kube.Object{}, served: map[string]bool{}}
	for _, p := range plurals {
		f.served[p] = true
	}
	for _, k := range order {
		d, ok := docs[k]
		if !ok {
			continue
		}
		if k.kind == "FixtureCluster" { // what the "cluster" does not serve
			for _, p := range strings.Fields(fmt.Sprint(d["notServed"])) {
				f.served[p] = false
			}
			continue
		}
		p, ok := plurals[k.kind]
		if !ok {
			t.Fatalf("fixture kind %s", k.kind)
		}
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		var o kube.Object
		if err := json.Unmarshal(raw, &o); err != nil {
			t.Fatal(err)
		}
		o.Raw = raw
		f.objs[p] = append(f.objs[p], o)
	}
	return f
}

// referenceDigests are the fixtures' release digests of the reference
// workloads' images.
var referenceDigests = map[string]string{
	"gateway": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
	"posture": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
}

// referenceWorkloads are deploy/k8s/gateway.yaml's and posture.yaml's
// objects as a cluster serves them: each Deployment as a running pod of its
// template (images by the release's digests), its Services answering with
// good TLS, its NetworkPolicies.
func referenceWorkloads(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, c := range slices.Sorted(maps.Keys(referenceDigests)) {
		for _, d := range yamlDocs(t, "../../../deploy/k8s/"+c+".yaml") {
			md, _ := d["metadata"].(map[string]any)
			switch d["kind"] {
			case "NetworkPolicy":
				out = append(out, d)
			case "Service":
				md["annotations"] = map[string]any{"fixture/tls": "good"}
				out = append(out, d)
			case "Deployment":
				name := fmt.Sprint(md["name"])
				tmpl, _ := d["spec"].(map[string]any)["template"].(map[string]any)
				tmd, _ := tmpl["metadata"].(map[string]any)
				labels, _ := tmd["labels"].(map[string]any)
				labels["pod-template-hash"] = "5f6d7c8b9"
				spec, _ := tmpl["spec"].(map[string]any)
				var statuses []any
				for _, x := range spec["containers"].([]any) {
					ctr := x.(map[string]any)
					img := strings.Replace(fmt.Sprint(ctr["image"]), ":REPLACE_WITH_DIGEST", "@"+referenceDigests[c], 1)
					if img == ctr["image"] {
						t.Fatalf("%s: container %v is not the release's image placeholder", c, ctr["name"])
					}
					ctr["image"] = img
					statuses = append(statuses, map[string]any{"name": ctr["name"], "image": img, "imageID": img})
				}
				out = append(out, map[string]any{
					"apiVersion": "v1", "kind": "Pod",
					"metadata": map[string]any{
						"name": name + "-5f6d7c8b9-ref00", "namespace": md["namespace"], "labels": labels,
						"ownerReferences": []any{map[string]any{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": name + "-5f6d7c8b9", "uid": "ref-" + name}},
					},
					"spec":   spec,
					"status": map[string]any{"containerStatuses": statuses},
				})
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("no reference workloads")
	}
	return out
}

// --- test TLS endpoints -----------------------------------------------------

func selfSigned(t *testing.T, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "endpoint"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter, DNSNames: []string{"endpoint"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serve starts a test endpoint with the given behaviour and returns its
// address.
func serve(t *testing.T, behaviour string) string {
	t.Helper()
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	var cert tls.Certificate
	switch behaviour {
	case "good":
		cert = selfSigned(t, time.Now().Add(365*24*time.Hour))
	case "expiring":
		cert = selfSigned(t, time.Now().Add(10*24*time.Hour))
	case "expired":
		cert = selfSigned(t, time.Now().Add(-time.Hour))
	}
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				switch behaviour {
				case "plaintext":
					_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
				case "tls10", "weak":
					rawServer(c, behaviour)
				default:
					s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
					_ = s.HandshakeContext(context.Background())
				}
			}(c)
		}
	}()
	return lis.Addr().String()
}

// rawServer answers a ClientHello with a ServerHello for the offered
// version and first suite: "tls10" accepts TLS 1.0 hellos, "weak" accepts
// TLS 1.2 hellos whatever suites they offer. Anything else gets an alert.
func rawServer(c net.Conn, behaviour string) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:5]))
	if _, err := io.ReadFull(c, body); err != nil || body[0] != 1 {
		return
	}
	h := body[4:]
	version := binary.BigEndian.Uint16(h[0:2])
	sid := int(h[34])
	suite := binary.BigEndian.Uint16(h[35+sid+2 : 35+sid+4])
	accept := (behaviour == "tls10" && version == tls.VersionTLS10) || (behaviour == "weak" && version == tls.VersionTLS12)
	if !accept {
		_, _ = c.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46}) // protocol_version alert
		return
	}
	sh := binary.BigEndian.AppendUint16(nil, version)
	sh = append(sh, make([]byte, 32)...)
	sh = append(sh, 0)
	sh = binary.BigEndian.AppendUint16(sh, suite)
	sh = append(sh, 0, 0, 0)
	hs := append([]byte{2, 0, 0, byte(len(sh))}, sh...)                                             // #nosec G115 -- a 40-byte ServerHello
	rec := append([]byte{0x16, 0x03, 0x03}, binary.BigEndian.AppendUint16(nil, uint16(len(hs)))...) // #nosec G115 -- small
	_, _ = c.Write(append(rec, hs...))
}

// --- the fixtures -------------------------------------------------------------

type distribution struct {
	name       string
	psaDefault string
	failWant   map[string][]string // check id -> subjects of the expected findings
	passObs    []string            // "check subject method" observations of the pass fixture
}

var distributions = []distribution{
	{name: "kind", passObs: []string{"node_fips node/fair-control-plane attested"}, failWant: map[string][]string{
		"pod_security_admission": {"namespace/fair-platform"},
		"network_policy":         {"namespace/fair-platform", "workload/fair-platform/Deployment/iam"},
		"tls_endpoints":          {"endpoint/iam.fair-platform.svc:443", "endpoint/posture.fair-platform.svc:9443"},
		"node_fips":              {"node/fair-control-plane"},
		"image_digests":          {"workload/fair-platform/Deployment/iam"},
		"signature_admission":    {"cluster/admission"},
		"pod_hardening":          {"workload/fair-platform/Deployment/iam"},
		"storage_encryption":     {"storageclass/standard"},
		"plaintext_secrets":      {"workload/fair-platform/Deployment/iam"},
		"platform_rbac":          {"rbac/ClusterRoleBinding/fair-posture-scanner", "rbac/Role/fair-platform/posture-scanner"},
	}},
	{name: "openshift", passObs: []string{"node_fips node/worker-0 attested"}, failWant: map[string][]string{
		"pod_security_admission": {"namespace/fair-platform"},
		"network_policy":         {"workload/fair-platform/Deployment/iam"},
		"tls_endpoints":          {"endpoint/iam.fair-platform.svc:443"},
		"node_fips":              {"node/worker-0"},
		"image_digests":          {"workload/fair-platform/Deployment/iam"},
		"signature_admission":    {"cluster/admission"},
		"pod_hardening":          {"workload/fair-platform/Deployment/iam"},
		"storage_encryption":     {"storageclass/gp2-csi"},
		"plaintext_secrets":      {"workload/fair-platform/Deployment/iam", "workload/fair-platform/Deployment/iam/secret-sources"},
		"platform_rbac":          {"rbac/ClusterRoleBinding/fair-platform-debug"},
	}},
	{name: "rke2", psaDefault: "restricted", passObs: []string{"node_fips node/rke2-agent-1 attested", "node_fips node/rke2-server-0 verified"},
		failWant: map[string][]string{
			"pod_security_admission": {"namespace/fair-platform"},
			"network_policy":         {"namespace/fair-platform"},
			"tls_endpoints":          {"endpoint/iam.fair-platform.svc:443", "endpoint/posture.fair-platform.svc:9443"},
			"node_fips":              {"node/rke2-agent-1"},
			"image_digests":          {"workload/fair-platform/Deployment/iam", "workload/fair-platform/Deployment/posture-scanner"},
			"signature_admission":    {"cluster/admission"},
			"pod_hardening":          {"workload/fair-platform/Deployment/posture-scanner"},
			"storage_encryption":     {"storageclass/local-path"},
			"plaintext_secrets":      {"workload/fair-platform/Deployment/posture-scanner"},
			"platform_rbac":          {"rbac/RoleBinding/fair-platform/debug", "rbac/Role/fair-platform/posture-scanner"},
		}},
}

const (
	iamDigest     = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	scannerDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// releaseFor signs a release manifest for the fixtures: the two platform
// images by digest and the RBAC of deploy/k8s.
func releaseFor(t *testing.T) (string, *ecdsa.PublicKey) {
	t.Helper()
	rbac, err := releasemanifest.RBACFromDir("../../../deploy/k8s")
	if err != nil {
		t.Fatal(err)
	}
	m := &releasemanifest.Manifest{Format: releasemanifest.Format, Release: "1.0.0", RBAC: rbac, Images: map[string]string{
		"iam": "ghcr.io/rformer/fair-iam@" + iamDigest, "posture-scanner": "ghcr.io/rformer/fair-posture-scanner@" + scannerDigest}}
	for c, d := range referenceDigests {
		m.Images[c] = "ghcr.io/rformer/fair-" + c + "@" + d
	}
	b, err := releasemanifest.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sig, err := profilepkg.Sign(key, b)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "release-manifest.json")
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file+".sig", sig, 0o600); err != nil {
		t.Fatal(err)
	}
	return file, &key.PublicKey
}

func run(t *testing.T, d distribution, variant string) (map[string][]scanner.Finding, []string) {
	t.Helper()
	f := loadFixture(t, d.name, variant)
	// Each Service address goes to a test endpoint behaving as annotated.
	routes := map[string]string{}
	for _, o := range f.objs["services"] {
		var sv struct {
			Spec struct {
				Ports []struct{ Port int } `json:"ports"`
			} `json:"spec"`
		}
		_ = json.Unmarshal(o.Raw, &sv)
		for _, p := range sv.Spec.Ports {
			routes[fmt.Sprintf("%s.%s.svc:%d", o.Metadata.Name, o.Metadata.Namespace, p.Port)] = serve(t, o.Metadata.Annotations["fixture/tls"])
		}
	}
	manifest, pub := releaseFor(t)
	cfg := Config{PSADefault: d.psaDefault, ReleaseManifest: manifest, ReleaseKey: pub,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			to, ok := routes[addr]
			if !ok {
				return nil, fmt.Errorf("no route to %s", addr)
			}
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", to)
		}}
	out := map[string][]scanner.Finding{}
	obs := []string{}
	scope := scanner.Scope{Namespaces: []string{"fair-platform"}, ProbeNamespace: "fair-fips-probe"}
	for _, c := range Catalog(cfg) {
		res, err := c.Run(context.Background(), f, scope)
		if err != nil {
			t.Fatalf("%s %s: %s: %v", d.name, variant, c.ID(), err)
		}
		fs := res.Findings
		for _, o := range res.Observations {
			if !json.Valid([]byte(o.DetailJSON)) || (o.Method != "verified" && o.Method != "attested") {
				t.Errorf("%s: bad observation %+v", c.ID(), o)
			}
			obs = append(obs, c.ID()+" "+o.Subject+" "+o.Method)
		}
		for _, fd := range fs {
			if fd.CheckID != c.ID() || fd.Severity == "" || len(fd.Controls) == 0 || fd.Remediation == "" || !json.Valid([]byte(fd.DetailJSON)) {
				t.Errorf("%s: finding without severity, controls, remediation or detail: %+v", c.ID(), fd) // AC-42
			}
		}
		out[c.ID()] = fs
	}
	sort.Strings(obs)
	return out, obs
}

func subjects(fs []scanner.Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.Subject)
	}
	sort.Strings(out)
	return out
}

func TestCatalogFixtures(t *testing.T) {
	if n := len(Metas()); n != 10 {
		t.Fatalf("%d checks, want the 10 of design §6.8", n)
	}
	for _, d := range distributions {
		t.Run(d.name, func(t *testing.T) {
			pass, obs := run(t, d, "pass")
			for id, fs := range pass {
				if len(fs) != 0 {
					t.Errorf("pass fixture: %s found %v", id, fs)
				}
			}
			if !slices.Equal(obs, d.passObs) {
				t.Errorf("pass fixture observations %v, want %v", obs, d.passObs)
			}
			got, _ := run(t, d, "fail")
			for _, m := range Metas() {
				want := slices.Sorted(slices.Values(d.failWant[m.ID]))
				if len(want) == 0 {
					t.Errorf("fail fixture has no expectation for %s", m.ID)
				}
				if g := subjects(got[m.ID]); !slices.Equal(g, want) {
					t.Errorf("fail fixture: %s found %v, want %v", m.ID, g, want)
					for _, f := range got[m.ID] {
						t.Logf("  %s %s %s", f.Severity, f.Subject, f.DetailJSON)
					}
				}
			}
		})
	}
}

// A missing, unsigned or tampered release manifest makes the image and RBAC
// checks fail as errors: never "passed".
func TestReleaseManifestRequired(t *testing.T) {
	f := loadFixture(t, "kind", "pass")
	manifest, pub := releaseFor(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tampered := filepath.Join(t.TempDir(), "m.json")
	b, _ := os.ReadFile(manifest)                                                            // #nosec G304 -- test temp file
	sig, _ := os.ReadFile(manifest + ".sig")                                                 // #nosec G304 -- test temp file
	_ = os.WriteFile(tampered, bytes.Replace(b, []byte("1.0.0"), []byte("1.0.1"), 1), 0o600) // #nosec G703 -- test temp file
	_ = os.WriteFile(tampered+".sig", sig, 0o600)                                            // #nosec G703 -- test temp file
	for name, cfg := range map[string]Config{
		"none":      {},
		"wrong key": {ReleaseManifest: manifest, ReleaseKey: &other.PublicKey},
		"tampered":  {ReleaseManifest: tampered, ReleaseKey: pub},
	} {
		for _, c := range Catalog(cfg) {
			if c.ID() != "image_digests" && c.ID() != "platform_rbac" {
				continue
			}
			if _, err := c.Run(context.Background(), f, scanner.Scope{Namespaces: []string{"fair-platform"}}); !errors.Is(err, errNoManifest) {
				t.Errorf("%s: %s: %v", name, c.ID(), err)
			}
		}
	}
}

// F-014 T-09: a verified manifest can be passed directly (Config.Manifest),
// and an optional RBAC entry (a hook's, an option's) is never reported
// missing, while a required one is; a present optional object that differs
// is still reported.
func TestOptionalRBAC(t *testing.T) {
	f := loadFixture(t, "kind", "pass")
	rbac, err := releasemanifest.RBACFromDir("../../../deploy/k8s")
	if err != nil {
		t.Fatal(err)
	}
	extra := releasemanifest.RBACEntry{Kind: "ClusterRole", Name: "fair-preflight", SHA256: strings.Repeat("a", 64)}
	run := func(entries []releasemanifest.RBACEntry) []string {
		m := &releasemanifest.Manifest{Format: releasemanifest.Format, Release: "1.0.0", RBAC: entries,
			Images: map[string]string{"iam": "ghcr.io/rformer/fair-iam@" + iamDigest}}
		for _, c := range Catalog(Config{Manifest: m}) {
			if c.ID() != "platform_rbac" {
				continue
			}
			res, err := c.Run(context.Background(), f, scanner.Scope{Namespaces: []string{"fair-platform"}, ProbeNamespace: "fair-fips-probe"})
			if err != nil {
				t.Fatal(err)
			}
			return subjects(res.Findings)
		}
		t.Fatal("no platform_rbac check")
		return nil
	}
	if got := run(rbac); len(got) != 0 {
		t.Errorf("deploy/k8s's RBAC: %v", got)
	}
	opt := extra
	opt.Optional = releasemanifest.OptionalHook
	if got := run(append(slices.Clone(rbac), opt)); len(got) != 0 {
		t.Errorf("an absent hook's RBAC was reported: %v", got)
	}
	if got := run(append(slices.Clone(rbac), extra)); !slices.Equal(got, []string{"rbac/ClusterRole/fair-preflight"}) {
		t.Errorf("an absent required entry: %v", got)
	}
	changed := slices.Clone(rbac)
	for i := range changed {
		changed[i].Optional = "scanner.enabled"
		if changed[i].Key() == "Role/fair-platform/posture-scanner" {
			changed[i].SHA256 = strings.Repeat("b", 64)
		}
	}
	if got := run(changed); !slices.Equal(got, []string{"rbac/Role/fair-platform/posture-scanner"}) {
		t.Errorf("a changed optional object: %v", got)
	}
}

// F-014 T-10 (design §3.17): a mirrored third-party copy the signed
// manifest lists in its mirrors is the release's image; one it does not
// list, or by another digest, is reported.
func TestMirroredImages(t *testing.T) {
	f := loadFixture(t, "kind", "pass")
	rbac, err := releasemanifest.RBACFromDir("../../../deploy/k8s")
	if err != nil {
		t.Fatal(err)
	}
	run := func(mirrorDigest string) []string {
		m := &releasemanifest.Manifest{Format: releasemanifest.Format, Release: "1.0.0", RBAC: rbac, Images: map[string]string{
			"posture-scanner": "ghcr.io/rformer/fair-posture-scanner@" + scannerDigest}}
		for c, d := range referenceDigests {
			m.Images[c] = "ghcr.io/rformer/fair-" + c + "@" + d
		}
		if mirrorDigest != "" {
			// The fixture's iam image, as if it were a mirrored copy.
			m.Mirrors = []releasemanifest.Mirror{{Component: "copy", Image: "ghcr.io/rformer/fair-iam@" + mirrorDigest,
				Source: "publisher.invalid/iam:1@" + mirrorDigest, Identity: "https://github.com/p/iam/.github/workflows/r.yml@refs/tags/v1",
				Issuer: "https://token.actions.githubusercontent.com"}}
		}
		for _, c := range Catalog(Config{Manifest: m}) {
			if c.ID() != "image_digests" {
				continue
			}
			res, err := c.Run(context.Background(), f, scanner.Scope{Namespaces: []string{"fair-platform"}, ProbeNamespace: "fair-fips-probe"})
			if err != nil {
				t.Fatal(err)
			}
			return subjects(res.Findings)
		}
		t.Fatal("no image_digests check")
		return nil
	}
	if got := run(iamDigest); len(got) != 0 {
		t.Errorf("listed mirror: %v", got)
	}
	for name, d := range map[string]string{"not listed": "", "other digest": scannerDigest} {
		if got := run(d); !slices.Contains(got, "workload/fair-platform/Deployment/iam") {
			t.Errorf("%s: %v", name, got)
		}
	}
}
