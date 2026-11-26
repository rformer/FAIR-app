package accessctl

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type rbacRule struct {
	APIGroups []string `yaml:"apiGroups"`
	Resources []string `yaml:"resources"`
	Verbs     []string `yaml:"verbs"`
}

type rbacDoc struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Rules    []rbacRule                    `yaml:"rules"`
	RoleRef  struct{ Kind, Name string }   `yaml:"roleRef"`
	Subjects []struct{ Kind, Name string } `yaml:"subjects"`
}

// F-012 T-18 (F-012-AC-27; design §3.9, §6 "E: operators hold standing
// access"): the operator role's Kubernetes rights beyond the view policy
// reach no data: no Secrets, no way into a pod (exec, attach, port-forward,
// proxy), no tokens, no new or changed workloads, no RBAC or impersonation.
func TestOperatorRBACReachesNoData(t *testing.T) {
	dir := filepath.Join(repoRoot, "deploy", "fleet", "addons-config")
	b, err := os.ReadFile(filepath.Join(dir, "operator-access.yaml")) // #nosec G304 -- test files
	if err != nil {
		t.Fatal(err)
	}
	k, err := os.ReadFile(filepath.Join(dir, "kustomization.yaml")) // #nosec G304 -- test files
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(k, []byte("- operator-access.yaml")) {
		t.Error("addons-config does not apply operator-access.yaml")
	}
	var docs []rbacDoc
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var d rbacDoc
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		docs = append(docs, d)
	}
	if len(docs) != 2 || docs[0].Kind != "ClusterRole" || docs[1].Kind != "ClusterRoleBinding" {
		t.Fatalf("want one ClusterRole and its binding, got %+v", docs)
	}
	bind := docs[1]
	if bind.RoleRef.Kind != "ClusterRole" || bind.RoleRef.Name != docs[0].Metadata.Name || len(bind.Subjects) != 1 ||
		bind.Subjects[0].Kind != "Group" || bind.Subjects[0].Name != OperatorGroup {
		t.Errorf("the binding gives %s to %+v; want the group %s only", bind.RoleRef.Name, bind.Subjects, OperatorGroup)
	}
	forbidden := []string{"secrets", "pods/exec", "pods/attach", "pods/portforward", "pods/proxy", "services/proxy", "nodes/proxy",
		"serviceaccounts", "serviceaccounts/token", "pods/ephemeralcontainers", "configmaps", "persistentvolumeclaims",
		"roles", "rolebindings", "clusterroles", "clusterrolebindings", "certificatesigningrequests", "tokenreviews"}
	writes := []string{"create", "update", "patch", "delete", "deletecollection", "escalate", "bind", "impersonate", "*"}
	allowedWrites := map[string][]string{
		"pods":               []string{"delete"},
		"pods/eviction":      []string{"create"},
		"deployments/scale":  []string{"patch", "update"},
		"statefulsets/scale": []string{"patch", "update"},
		"nodes":              []string{"patch"},
	}
	for _, r := range docs[0].Rules {
		for _, g := range r.APIGroups {
			if g == "*" {
				t.Errorf("rule %+v: every API group", r)
			}
		}
		for _, res := range r.Resources {
			if res == "*" || strings.HasSuffix(res, "/*") || slices.Contains(forbidden, res) {
				t.Errorf("rule %+v reaches %s", r, res)
			}
			for _, v := range r.Verbs {
				if slices.Contains(writes, v) && !slices.Contains(allowedWrites[res], v) {
					t.Errorf("rule %+v: %s on %s", r, v, res)
				}
			}
		}
		for _, v := range r.Verbs {
			if v == "*" || v == "escalate" || v == "bind" || v == "impersonate" {
				t.Errorf("rule %+v: verb %s", r, v)
			}
		}
	}
}
