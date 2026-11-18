package integration

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// F-011 T-15 (design §11): what the integrate service checks at startup.
func TestCheckInstall(t *testing.T) {
	full := map[string]string{"FAIR_JWT_KEYS_DIR": "/keys/jwt", "FAIR_INTEGRATE_SECRETS_DIR": "/keys/secrets",
		"FAIR_INTEGRATE_GATEWAY_URL": "https://gateway.fair-platform.svc", "FAIR_INTEGRATE_CLUSTER_CIDRS": "10.96.0.0/12, 10.244.0.0/16"}
	env := func(drop string, set map[string]string) func(string) string {
		return func(k string) string {
			if k == drop {
				return ""
			}
			if v, ok := set[k]; ok {
				return v
			}
			return full[k]
		}
	}
	for _, mode := range []string{"saas", "self-hosted", "air-gapped"} {
		if err := CheckInstall(InstallCheck{Env: "production", Mode: mode, Getenv: env("", nil)}); err != nil {
			t.Errorf("%s: a complete install refused: %v", mode, err)
		}
		for k := range full {
			if err := CheckInstall(InstallCheck{Env: "production", Mode: mode, Getenv: env(k, nil)}); err == nil || !strings.Contains(err.Error(), k) {
				t.Errorf("%s without %s: %v", mode, k, err)
			}
		}
	}
	// Outside production nothing is required, but what is set is checked.
	if err := CheckInstall(InstallCheck{Env: "development", Getenv: func(string) string { return "" }}); err != nil {
		t.Errorf("development: %v", err)
	}
	for _, bad := range []string{"http://gateway", "https://gateway/api", "https://u:p@gateway", "https://gateway?x=1", "gateway:8443"} {
		if err := CheckInstall(InstallCheck{Env: "development", Getenv: env("", map[string]string{"FAIR_INTEGRATE_GATEWAY_URL": bad})}); err == nil {
			t.Errorf("gateway URL %q accepted", bad)
		}
	}
	if err := CheckInstall(InstallCheck{Env: "development", Getenv: env("", map[string]string{"FAIR_INTEGRATE_CLUSTER_CIDRS": "10.0.0.0/33"})}); err == nil {
		t.Error("a bad cluster range accepted")
	}
}

// The reference manifest (deploy/k8s/integrate.yaml) keeps the hardening:
// non-root, read-only, no capabilities, no service-account token, the
// install's environment, ingress from the gateway only, and egress to the
// database, DNS, the gateway and HTTPS outside the cluster only.
func TestManifest(t *testing.T) {
	b, err := os.ReadFile("../../deploy/k8s/integrate.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	docs := map[string]map[string]any{}
	for {
		var d map[string]any
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		md, _ := d["metadata"].(map[string]any)
		docs[fmt.Sprint(d["kind"], "/", md["name"])] = d
	}
	get := func(v any, path ...any) any {
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
	dep := docs["Deployment/integrate"]
	if dep == nil {
		t.Fatal("no Deployment integrate")
	}
	spec := get(dep, "spec", "template", "spec")
	if get(spec, "automountServiceAccountToken") != false || get(spec, "securityContext", "runAsNonRoot") != true {
		t.Error("the pod mounts a token or may run as root")
	}
	c := get(spec, "containers", 0)
	sc := get(c, "securityContext")
	if get(sc, "readOnlyRootFilesystem") != true || get(sc, "allowPrivilegeEscalation") != false || fmt.Sprint(get(sc, "capabilities", "drop")) != "[ALL]" {
		t.Errorf("container security context: %v", sc)
	}
	var env []string
	for _, e := range get(c, "env").([]any) {
		env = append(env, fmt.Sprint(get(e, "name")))
	}
	for _, k := range []string{"FAIR_ENV", "FAIR_DEPLOYMENT_MODE", "FAIR_INTEGRATE_GATEWAY_URL", "FAIR_INTEGRATE_CLUSTER_CIDRS", "FAIR_DB_PASSWORD_FILE"} {
		if !slices.Contains(env, k) {
			t.Errorf("the container lacks %s", k)
		}
	}
	in := docs["NetworkPolicy/integrate-ingress-from-gateway"]
	if fmt.Sprint(get(in, "spec", "ingress", 0, "from", 0, "podSelector", "matchLabels", "app.kubernetes.io/name")) != "gateway" || len(get(in, "spec", "ingress").([]any)) != 1 {
		t.Error("ingress is not from the gateway alone")
	}
	out := docs["NetworkPolicy/integrate-egress"]
	var ports []string
	for _, rule := range get(out, "spec", "egress").([]any) {
		for _, p := range get(rule, "ports").([]any) {
			ports = append(ports, fmt.Sprint(get(p, "port")))
		}
		if cidr := get(rule, "to", 0, "ipBlock", "cidr"); cidr != nil {
			except := fmt.Sprint(get(rule, "to", 0, "ipBlock", "except"))
			for _, x := range []string{"169.254.0.0/16", "127.0.0.0/8"} {
				if !strings.Contains(except, x) {
					t.Errorf("egress to %v does not except %s", cidr, x)
				}
			}
		}
	}
	slices.Sort(ports)
	if fmt.Sprint(slices.Compact(ports)) != "[443 53 5432 8443]" {
		t.Errorf("egress ports: %v", ports)
	}
}
