package enginegate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

func manifest(t *testing.T, name string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "k8s", name)) // #nosec G304 -- the repository's own manifests
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
			t.Fatal(err)
		}
		out = append(out, d)
	}
}

func get(v any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, _ := v.(map[string]any)
			v = m[k]
		case int:
			l, _ := v.([]any)
			if k >= len(l) {
				return nil
			}
			v = l[k]
		}
	}
	return v
}

func byName(list any, name string) map[string]any {
	l, _ := list.([]any)
	for _, x := range l {
		if m, _ := x.(map[string]any); m["name"] == name {
			return m
		}
	}
	return nil
}

func kinds(ds []map[string]any, kind string) []map[string]any {
	var out []map[string]any
	for _, d := range ds {
		if d["kind"] == kind {
			out = append(out, d)
		}
	}
	return out
}

// TestEngineManifest ties deploy/k8s/engine.yaml to design §11: the engine
// container listens on no TCP port and holds no keys; the gate is the only
// listener; the socket is in memory; only the risk service may connect;
// there is no egress.
func TestEngineManifest(t *testing.T) {
	ds := manifest(t, "engine.yaml")
	var dep map[string]any
	for _, d := range kinds(ds, "Deployment") {
		if get(d, "metadata", "name") == "engine" {
			dep = d
		}
	}
	if dep == nil {
		t.Fatal("no engine Deployment")
	}
	spec := get(dep, "spec", "template", "spec")
	if get(spec, "automountServiceAccountToken") != false || get(spec, "securityContext", "runAsNonRoot") != true {
		t.Error("the pod mounts a service-account token or may run as root")
	}
	var names []string
	for _, c := range get(spec, "containers").([]any) {
		m := c.(map[string]any)
		names = append(names, m["name"].(string))
		sc := m["securityContext"]
		if get(sc, "readOnlyRootFilesystem") != true || get(sc, "allowPrivilegeEscalation") != false || fmt.Sprint(get(sc, "capabilities", "drop")) != "[ALL]" {
			t.Errorf("%s: not hardened: %v", m["name"], sc)
		}
	}
	if !slices.Equal(names, []string{"engine", "engine-gate"}) {
		t.Fatalf("containers %v", names)
	}
	engine := byName(get(spec, "containers"), "engine")
	if engine["ports"] != nil {
		t.Errorf("the engine container declares ports: %v", engine["ports"])
	}
	if engine["env"] != nil {
		t.Errorf("the engine container has environment (keys?): %v", engine["env"])
	}
	if mounts := get(engine, "volumeMounts"); len(mounts.([]any)) != 1 || get(mounts, 0, "name") != "socket" {
		t.Errorf("the engine mounts more than its socket: %v", mounts)
	}
	if args := fmt.Sprint(engine["args"]); args != "[serve --socket /run/engine/engine.sock --workers 4]" {
		t.Errorf("engine args %s", args)
	}
	gate := byName(get(spec, "containers"), "engine-gate")
	var ports []int
	for _, p := range get(gate, "ports").([]any) {
		ports = append(ports, get(p, "containerPort").(int))
	}
	if !slices.Equal(ports, []int{8444, 8081}) {
		t.Errorf("gate ports %v", ports)
	}
	if get(byName(get(gate, "env"), "FAIR_ENGINE_SOCKET"), "value") != SocketPath {
		t.Error("the gate forwards elsewhere than the engine's socket")
	}
	if get(byName(get(spec, "volumes"), "socket"), "emptyDir", "medium") != "Memory" {
		t.Error("the socket is not in an in-memory volume")
	}

	svc := kinds(ds, "Service")
	if len(svc) != 1 || len(get(svc[0], "spec", "ports").([]any)) != 1 || get(svc[0], "spec", "ports", 0, "port") != 8444 {
		t.Errorf("the Service exposes more than the gate: %v", svc)
	}

	var ingress, egress int
	for _, np := range kinds(ds, "NetworkPolicy") {
		if get(np, "spec", "podSelector", "matchLabels", "app.kubernetes.io/name") != "engine" {
			continue
		}
		types := fmt.Sprint(get(np, "spec", "policyTypes"))
		switch types {
		case "[Ingress]":
			ingress++
			rules := get(np, "spec", "ingress").([]any)
			if len(rules) != 1 || len(get(rules[0], "from").([]any)) != 1 ||
				get(rules[0], "from", 0, "podSelector", "matchLabels", "app.kubernetes.io/name") != "risk" ||
				get(rules[0], "from", 0, "namespaceSelector") != nil ||
				len(get(rules[0], "ports").([]any)) != 1 || get(rules[0], "ports", 0, "port") != 8444 {
				t.Errorf("ingress admits more than the risk service on the gate: %v", rules)
			}
		case "[Egress]":
			egress++
			if l, _ := get(np, "spec", "egress").([]any); len(l) != 0 {
				t.Errorf("the engine has egress: %v", l)
			}
		default:
			t.Errorf("unexpected policy types %s", types)
		}
	}
	if ingress != 1 || egress != 1 {
		t.Errorf("want one ingress and one no-egress policy, got %d and %d", ingress, egress)
	}

	// The risk service may reach the gate.
	found := false
	for _, np := range kinds(manifest(t, "risk.yaml"), "NetworkPolicy") {
		for _, r := range func() []any { l, _ := get(np, "spec", "egress").([]any); return l }() {
			if get(r, "to", 0, "podSelector", "matchLabels", "app.kubernetes.io/name") == "engine" && get(r, "ports", 0, "port") == 8444 {
				found = true
			}
		}
	}
	if !found {
		t.Error("the risk service's egress does not admit the engine's gate")
	}
}
