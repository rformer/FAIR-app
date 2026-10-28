package releasemanifest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/profilepkg"
)

// The hash ignores order, field order and defaulted subject apiGroups, so
// the YAML reference manifest and the API server's object agree; any change
// to what is granted or to whom changes it.
func TestHashNormalizes(t *testing.T) {
	role := `{"metadata":{"name":"r","resourceVersion":"7"},"rules":[
		{"apiGroups":["apps"],"resources":["deployments","daemonsets"],"verbs":["watch","get","list"]},
		{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]}]}`
	same := `{"rules":[{"verbs":["get","list"],"resources":["pods"],"apiGroups":[""]},
		{"resources":["daemonsets","deployments"],"apiGroups":["apps"],"verbs":["get","list","watch"]}],"metadata":{"name":"r"}}`
	h1, err := Hash("Role", []byte(role))
	if err != nil {
		t.Fatal(err)
	}
	if h2, _ := Hash("Role", []byte(same)); h1 != h2 {
		t.Fatal("reordered role hashes differently")
	}
	for name, changed := range map[string]string{
		"added verb":     strings.Replace(role, `"get","list"]}]`, `"get","list","create"]}]`, 1),
		"added resource": strings.Replace(role, `["pods"]`, `["pods","secrets"]`, 1),
		"resource names": strings.Replace(role, `"verbs":["get","list"]}`, `"verbs":["get","list"],"resourceNames":["x"]}`, 1),
		"wildcard group": strings.Replace(role, `"apiGroups":[""]`, `"apiGroups":["*"]`, 1),
		"rule removed":   `{"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]}]}`,
	} {
		if h, _ := Hash("Role", []byte(changed)); h == h1 {
			t.Errorf("%s: same hash", name)
		}
	}

	b1 := `{"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"r"},
		"subjects":[{"kind":"ServiceAccount","name":"a","namespace":"n"},{"kind":"User","name":"u","apiGroup":"rbac.authorization.k8s.io"}]}`
	b2 := `{"subjects":[{"kind":"User","name":"u"},{"kind":"ServiceAccount","name":"a","namespace":"n","apiGroup":""}],
		"roleRef":{"kind":"Role","name":"r"}}`
	h3, _ := Hash("RoleBinding", []byte(b1))
	if h4, _ := Hash("RoleBinding", []byte(b2)); h3 != h4 {
		t.Fatal("equivalent bindings hash differently")
	}
	for name, changed := range map[string]string{
		"added subject": strings.Replace(b1, `"subjects":[`, `"subjects":[{"kind":"Group","name":"system:authenticated"},`, 1),
		"other role":    strings.Replace(b1, `"name":"r"`, `"name":"cluster-admin"`, 1),
	} {
		if h, _ := Hash("RoleBinding", []byte(changed)); h == h3 {
			t.Errorf("%s: same hash", name)
		}
	}
}

func TestRBACFromDeploy(t *testing.T) {
	es, err := RBACFromDir("../../deploy/k8s")
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, e := range es {
		keys = append(keys, e.Key())
	}
	want := "ClusterRole//fair-posture-scanner ClusterRoleBinding//fair-posture-scanner Role/fair-fips-probe/posture-scanner " +
		"Role/fair-platform/posture-scanner RoleBinding/fair-fips-probe/posture-scanner RoleBinding/fair-platform/posture-scanner"
	if strings.Join(keys, " ") != want {
		t.Fatalf("RBAC entries %v", keys)
	}
	// An OpenShift release adds its directory: the fips-probe SCC's Role and binding.
	os, err := RBACFromDir("../../deploy/k8s", "../../deploy/k8s/openshift")
	if err != nil {
		t.Fatal(err)
	}
	if len(os) != len(es)+2 || !strings.Contains(fmt.Sprint(os), "fair-fips-probe-scc") {
		t.Fatalf("OpenShift RBAC entries %v", os)
	}
}

func TestSignVerify(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	m := &Manifest{Format: Format, Release: "1.0.0",
		Images: map[string]string{"iam": "ghcr.io/rformer/fair-iam@sha256:" + strings.Repeat("a", 64)},
		RBAC:   []RBACEntry{{Kind: "ClusterRole", Name: "fair-posture-scanner", SHA256: strings.Repeat("b", 64)}}}
	b, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := profilepkg.Sign(key, b)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Verify(&key.PublicKey, b, sig); err != nil || got.Release != "1.0.0" {
		t.Fatalf("verify: %+v %v", got, err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := Verify(&other.PublicKey, b, sig); !errors.Is(err, profilepkg.ErrSignature) {
		t.Fatalf("other key: %v", err)
	}
	tampered := []byte(strings.Replace(string(b), "aaaa", "aaab", 1))
	if _, err := Verify(&key.PublicKey, tampered, sig); !errors.Is(err, profilepkg.ErrSignature) {
		t.Fatalf("tampered: %v", err)
	}
	for name, bad := range map[string]*Manifest{
		"tag, not digest": {Format: Format, Release: "1", Images: map[string]string{"iam": "ghcr.io/x/iam:1.0"}},
		"wrong format":    {Format: "v0", Release: "1", Images: m.Images},
		"namespaced role without namespace": {Format: Format, Release: "1", Images: m.Images,
			RBAC: []RBACEntry{{Kind: "Role", Name: "r", SHA256: strings.Repeat("c", 64)}}},
	} {
		if _, err := Encode(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestImageReferenceHelpers(t *testing.T) {
	d := "sha256:" + strings.Repeat("e", 64)
	for in, want := range map[string]string{
		"ghcr.io/rformer/fair-iam@" + d: "ghcr.io/rformer/fair-iam",
		"ghcr.io/rformer/fair-iam:1.2":  "ghcr.io/rformer/fair-iam",
		"localhost:5000/fair-iam:dev":   "localhost:5000/fair-iam",
		"busybox":                       "busybox",
	} {
		if got := Repository(in); got != want {
			t.Errorf("Repository(%s) = %s", in, got)
		}
	}
	if Digest("ghcr.io/x@"+d) != d || Digest("docker.io/library/busybox@"+d) != d || Digest(d) != d || Digest("busybox:1.36") != "" {
		t.Error("Digest")
	}
}
