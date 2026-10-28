package scanner

import (
	"bytes"
	"errors"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	"github.com/rformer/fair-app/internal/scanner/kube"
)

// Verification for F-015 T-27 (static RBAC audit): the scanner's RBAC in
// deploy/k8s/posture-scanner.yaml is read-only, never grants Secrets, grants
// exactly what scanner.Access reads, binds only the scanner's
// ServiceAccount; the pod is hardened and its egress is restricted. The kind
// test (scripts/k8s-e2e-scanner.sh) checks the same against a live cluster.

const manifest = "../../deploy/k8s/posture-scanner.yaml"

type doc map[string]any

func loadManifest(t *testing.T) []doc {
	t.Helper()
	b, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var docs []doc
	for {
		// A plain map: yaml.v3 decodes nested mappings into the target's
		// own type, which the accessors below do not expect.
		var d map[string]any
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			return docs
		} else if err != nil {
			t.Fatal(err)
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
}

func (d doc) kind() string { s, _ := d["kind"].(string); return s }
func (d doc) name() string { return str(d.m("metadata")["name"]) }
func (d doc) m(k string) doc {
	v, _ := d[k].(map[string]any)
	return v
}
func str(v any) string { s, _ := v.(string); return s }
func strs(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, x := range l {
		out = append(out, str(x))
	}
	return out
}
func list(v any) []doc {
	var out []doc
	l, _ := v.([]any)
	for _, x := range l {
		m, _ := x.(map[string]any)
		out = append(out, m)
	}
	return out
}

func TestScannerRBACIsReadOnlyAndMatchesAccess(t *testing.T) {
	docs := loadManifest(t)
	granted := map[string][]string{} // kind -> "group/resource"
	for _, d := range docs {
		if d.kind() != "Role" && d.kind() != "ClusterRole" {
			continue
		}
		for _, r := range list(d["rules"]) {
			if len(strs(r["nonResourceURLs"])) > 0 {
				t.Errorf("%s %s: nonResourceURLs granted", d.kind(), d.name())
			}
			for _, v := range strs(r["verbs"]) {
				if !slices.Contains([]string{"get", "list", "watch"}, v) {
					t.Errorf("%s %s: verb %q (only get, list, watch)", d.kind(), d.name(), v)
				}
			}
			for _, g := range strs(r["apiGroups"]) {
				for _, res := range strs(r["resources"]) {
					if g == "*" || res == "*" || strings.Contains(res, "/") {
						t.Errorf("%s %s: wildcard or subresource %q/%q", d.kind(), d.name(), g, res)
					}
					if res == "secrets" {
						t.Errorf("%s %s: Secrets granted", d.kind(), d.name())
					}
					granted[d.kind()] = append(granted[d.kind()], g+"/"+res)
				}
			}
			if len(strs(r["resourceNames"])) > 0 {
				t.Errorf("%s %s: resourceNames are not used", d.kind(), d.name())
			}
		}
	}
	want := func(rs []kube.Resource) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.Group+"/"+r.Plural)
		}
		sort.Strings(out)
		return out
	}
	for kind, rs := range map[string][]kube.Resource{"Role": Access.Namespaced, "ClusterRole": Access.Cluster} {
		got := granted[kind]
		sort.Strings(got)
		if !slices.Equal(got, want(rs)) {
			t.Errorf("%s grants\n %v\nscanner.Access reads\n %v", kind, got, want(rs))
		}
	}

	for _, d := range docs {
		if d.kind() != "RoleBinding" && d.kind() != "ClusterRoleBinding" {
			continue
		}
		subj := list(d["subjects"])
		if len(subj) != 1 || str(subj[0]["kind"]) != "ServiceAccount" || str(subj[0]["name"]) != "posture-scanner" ||
			str(subj[0]["namespace"]) != "fair-platform" {
			t.Errorf("%s %s binds %v", d.kind(), d.name(), d["subjects"])
		}
		if ref := d.m("roleRef"); !strings.HasSuffix(str(ref["name"]), "posture-scanner") {
			t.Errorf("%s %s binds role %v", d.kind(), d.name(), ref)
		}
	}
}

func TestScannerPodHardenedAndEgressRestricted(t *testing.T) {
	var dep, np doc
	for _, d := range loadManifest(t) {
		switch {
		case d.kind() == "Deployment":
			dep = d
		case d.kind() == "NetworkPolicy" && d.name() == "posture-scanner":
			np = d
		case d.kind() == "ServiceAccount" && d["automountServiceAccountToken"] != false:
			t.Error("the ServiceAccount must not automount its token")
		}
	}
	pod := dep.m("spec").m("template").m("spec")
	if str(pod["serviceAccountName"]) != "posture-scanner" || pod["automountServiceAccountToken"] != false || pod["hostNetwork"] == true {
		t.Errorf("pod identity: %v", pod)
	}
	psc := pod.m("securityContext")
	// fsGroup with 0440 Secrets: readable by the non-root user, by no one else
	// (found by the kind test: 0400 Secrets are owned by root).
	if psc["runAsNonRoot"] != true || str(psc.m("seccompProfile")["type"]) != "RuntimeDefault" || psc["fsGroup"] != 65532 {
		t.Errorf("pod securityContext %v", psc)
	}
	for _, c := range list(pod["containers"]) {
		sc := c.m("securityContext")
		if sc["allowPrivilegeEscalation"] != false || sc["readOnlyRootFilesystem"] != true || !slices.Equal(strs(sc.m("capabilities")["drop"]), []string{"ALL"}) {
			t.Errorf("container securityContext %v", sc)
		}
		if !strings.Contains(str(c["image"]), "fair-posture-scanner") {
			t.Errorf("image %v", c["image"])
		}
	}
	for _, v := range list(pod["volumes"]) {
		if v["hostPath"] != nil {
			t.Error("hostPath volume")
		}
		if sec := v.m("secret"); sec != nil && sec["defaultMode"] != 0o440 {
			t.Errorf("secret volume %s mode %v, want 0440 with fsGroup", str(v["name"]), sec["defaultMode"])
		}
		if p := v.m("projected"); p != nil {
			for _, s := range list(p["sources"]) {
				if tok := s.m("serviceAccountToken"); tok != nil && tok["expirationSeconds"] != 3600 {
					t.Errorf("projected token lifetime %v", tok["expirationSeconds"])
				}
			}
		}
	}

	spec := np.m("spec")
	if !slices.Equal(strs(spec["policyTypes"]), []string{"Ingress", "Egress"}) || spec["ingress"] != nil {
		t.Errorf("scanner must deny all ingress: %v", spec)
	}
	var rules []string
	for _, e := range list(spec["egress"]) {
		var to []string
		for _, p := range list(e["to"]) {
			switch {
			case p.m("ipBlock") != nil:
				to = append(to, "ip:"+str(p.m("ipBlock")["cidr"]))
			case p.m("podSelector") != nil && str(p.m("podSelector").m("matchLabels")["app.kubernetes.io/part-of"]) == "fair-platform":
				to = append(to, "platform-pods")
			case p.m("podSelector") != nil:
				to = append(to, "pod:"+str(p.m("podSelector").m("matchLabels")["app.kubernetes.io/name"]))
			default:
				to = append(to, "other")
			}
		}
		if len(to) == 0 {
			to = []string{"any"}
		}
		var ports []string
		for _, p := range list(e["ports"]) {
			ports = append(ports, str(p["protocol"])+"/"+strings.TrimSpace(strings.Trim(yamlScalar(p["port"]), `"`)))
		}
		rules = append(rules, strings.Join(to, "+")+" "+strings.Join(ports, ","))
	}
	want := []string{"ip:REPLACE_WITH_APISERVER_CIDR TCP/443,TCP/6443", "pod:posture TCP/9443",
		"platform-pods TCP/8443,TCP/9443,TCP/4222", "ip:REPLACE_WITH_INGRESS_CIDR TCP/443", "any UDP/53,TCP/53"}
	if !slices.Equal(rules, want) {
		t.Errorf("egress\n got %v\nwant %v", rules, want)
	}
}

func yamlScalar(v any) string {
	b, _ := yaml.Marshal(v)
	return strings.TrimSpace(string(b))
}
