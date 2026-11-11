package keys

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

var deployDir = filepath.Join("..", "..", "deploy", "k8s", "keys")

func docs(t *testing.T, file string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(deployDir, file)) // #nosec G304 -- the repository's own manifests
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
		out = append(out, d)
	}
}

// at walks a decoded document: string keys and int indexes.
func at(v any, path ...any) any {
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

func named(list any, name string) map[string]any {
	l, _ := list.([]any)
	for _, x := range l {
		if m, _ := x.(map[string]any); m["name"] == name {
			return m
		}
	}
	return nil
}

func serviceEnv(svc string) map[string]string {
	env := map[string]string{}
	for _, m := range Mounts {
		if m.Service == svc {
			maps.Copy(env, m.Env)
		}
	}
	return env
}

func serviceDirs(svc string) []string {
	var dirs []string
	for _, m := range Mounts {
		if m.Service == svc {
			dirs = append(dirs, m.Dir)
		}
	}
	return dirs
}

// deploymentOf names the Deployment holding a service's container: the
// gate runs in the engine's pod (F-005 T-10).
func deploymentOf(svc string) string {
	if svc == EngineGate {
		return "engine"
	}
	return svc
}

func deployment(t *testing.T, ds []map[string]any, svc string) map[string]any {
	t.Helper()
	for _, d := range ds {
		if d["kind"] == "Deployment" && at(d, "metadata", "name") == deploymentOf(svc) {
			return d
		}
	}
	t.Fatalf("no Deployment %s", svc)
	return nil
}

// checkEnv: the service's container has exactly the key environment of
// Mounts, and every path under MountRoot.
func checkEnv(t *testing.T, file string, d map[string]any, svc string) {
	t.Helper()
	c := named(at(d, "spec", "template", "spec", "containers"), svc)
	got := map[string]string{}
	for _, e := range at(c, "env").([]any) {
		m := e.(map[string]any)
		got[m["name"].(string)] = fmt.Sprint(m["value"])
	}
	if !maps.Equal(got, serviceEnv(svc)) {
		t.Errorf("%s %s: env %v, want %v", file, svc, got, serviceEnv(svc))
	}
	if at(d, "spec", "template", "spec", "securityContext", "fsGroup") != 65532 {
		t.Errorf("%s %s: fsGroup is not the services' group", file, svc)
	}
}

// TestDeployManifests ties deploy/k8s/keys to the layout (F-001 T-41):
// every mode delivers the same directories at the same paths.
func TestDeployManifests(t *testing.T) {
	services := []string{Gateway, IAM, Posture, Audit, Risk, EngineGate}

	t.Run("secret-mounts", func(t *testing.T) {
		ds := docs(t, "secret-mounts.yaml")
		for _, svc := range services {
			d := deployment(t, ds, svc)
			checkEnv(t, "secret-mounts", d, svc)
			c := named(at(d, "spec", "template", "spec", "containers"), svc)
			for _, dir := range serviceDirs(svc) {
				vol := named(at(d, "spec", "template", "spec", "volumes"), "keys-"+dir)
				mode, _ := at(vol, "secret", "defaultMode").(int)
				if at(vol, "secret", "secretName") != "fair-"+svc+"-"+dir || mode == 0 || mode&0o007 != 0 || mode&0o222 != 0 {
					t.Errorf("%s %s: volume %v", svc, dir, vol)
				}
				vm := named(at(c, "volumeMounts"), "keys-"+dir)
				if at(vm, "mountPath") != MountRoot+"/"+dir || at(vm, "readOnly") != true {
					t.Errorf("%s %s: mount %v", svc, dir, vm)
				}
			}
		}
	})

	t.Run("saas", func(t *testing.T) {
		ds := docs(t, filepath.Join("saas", "external-secrets.yaml"))
		want := map[string]bool{}
		for _, m := range Mounts {
			want["fair-"+m.Service+"-"+m.Dir] = true
		}
		for _, d := range ds {
			switch d["kind"] {
			case "SecretStore":
				// Workload identity only: no static cloud credentials.
				b, _ := yaml.Marshal(d)
				if strings.Contains(string(b), "secretRef") || strings.Contains(string(b), "SecretRef") {
					t.Errorf("the SecretStore uses static credentials: %s", b)
				}
				if p, _ := at(d, "spec", "provider").(map[string]any); len(p) != 1 || !slices.ContainsFunc([]string{"aws", "gcpsm", "azurekv"}, func(k string) bool { return p[k] != nil }) {
					t.Errorf("the SecretStore is not a KMS-backed cloud secret manager: %v", p)
				}
			case "ExternalSecret":
				name := at(d, "metadata", "name").(string)
				if !want[name] {
					t.Errorf("unexpected ExternalSecret %s", name)
					continue
				}
				delete(want, name)
				key, _ := at(d, "spec", "dataFrom", 0, "extract", "key").(string)
				var svc, dir string
				for _, m := range Mounts {
					if "fair-"+m.Service+"-"+m.Dir == name {
						svc, dir = m.Service, m.Dir
					}
				}
				if !strings.HasSuffix(key, "/"+svc+"/"+dir) || at(d, "spec", "target", "name") != name || at(d, "spec", "data") != nil ||
					at(d, "spec", "target", "template", "data") != nil {
					t.Errorf("ExternalSecret %s: %v", name, d["spec"])
				}
			default:
				t.Errorf("unexpected %v", d["kind"])
			}
		}
		if len(want) > 0 {
			t.Errorf("no ExternalSecret for %v", slices.Sorted(maps.Keys(want)))
		}
	})

	t.Run("openbao", func(t *testing.T) {
		ds := docs(t, filepath.Join("openbao", "sidecars.yaml"))
		kust, _ := os.ReadFile(filepath.Join(deployDir, "openbao", "kustomization.yaml")) // #nosec G304 -- the repository's own file
		for _, svc := range services {
			d := deployment(t, ds, svc)
			checkEnv(t, "sidecars", d, svc)
			spec := at(d, "spec", "template", "spec")
			agent := named(at(spec, "initContainers"), "openbao-agent")
			img, _ := at(agent, "image").(string)
			sc := at(agent, "securityContext")
			if at(agent, "restartPolicy") != "Always" || !strings.Contains(img, "@sha256:") || at(sc, "runAsNonRoot") != true ||
				at(sc, "readOnlyRootFilesystem") != true || at(sc, "allowPrivilegeEscalation") != false || at(sc, "runAsUser") != 65532 ||
				fmt.Sprint(at(sc, "capabilities", "drop")) != "[ALL]" || at(agent, "startupProbe") == nil {
				t.Errorf("%s: agent sidecar %v", svc, agent)
			}
			if c := fmt.Sprint(at(agent, "command")); !strings.Contains(c, "/etc/openbao/"+svc+".hcl") {
				t.Errorf("%s: agent command %s", svc, c)
			}
			if at(named(at(spec, "volumes"), "keys"), "emptyDir", "medium") != "Memory" {
				t.Errorf("%s: keys are not in memory", svc)
			}
			if at(named(at(named(at(spec, "containers"), svc), "volumeMounts"), "keys"), "readOnly") != true {
				t.Errorf("%s: the service can write its keys", svc)
			}
			if at(named(at(spec, "volumes"), "openbao-token"), "projected", "sources", 0, "serviceAccountToken", "audience") != "openbao" {
				t.Errorf("%s: the agent's token is not for OpenBao's audience", svc)
			}

			hcl := read(t, "openbao", svc+".hcl")
			for _, want := range []string{`method "kubernetes"`, `role       = "fair-` + svc + `"`, `source      = "/etc/openbao/` + svc + `.ctmpl"`,
				`perms       = "0640"`, `address = "https://`} {
				if !strings.Contains(hcl, want) {
					t.Errorf("%s.hcl lacks %s", svc, want)
				}
			}
			// The template reads exactly the service's entries and writes
			// each only into its own directory, guarded, private.
			tmpl := read(t, "openbao", svc+".ctmpl")
			reads := regexp.MustCompile(`secret "secret/data/fair/([a-z-]+)/([a-z-]+)"`).FindAllStringSubmatch(tmpl, -1)
			writes := regexp.MustCompile(`printf "/keys/([a-z-]+)/%s"`).FindAllStringSubmatch(tmpl, -1)
			var got []string
			for i, r := range reads {
				if r[1] != svc || i >= len(writes) || writes[i][1] != r[2] {
					t.Errorf("%s.ctmpl: entry %v written to %v", svc, r, writes)
				}
				got = append(got, r[2])
			}
			if !slices.Equal(got, serviceDirs(svc)) || strings.Count(tmpl, "regexMatch") != len(got) || strings.Count(tmpl, `"0640"`) != len(got) {
				t.Errorf("%s.ctmpl: reads %v, want %v, each guarded and 0640", svc, got, serviceDirs(svc))
			}
			// The policy grants read on exactly those entries.
			pol := read(t, "openbao", "policy-"+svc+".hcl")
			paths := regexp.MustCompile(`path "secret/data/fair/([a-z-]+)/([a-z-]+)"`).FindAllStringSubmatch(pol, -1)
			var pd []string
			for _, p := range paths {
				if p[1] != svc {
					t.Errorf("policy-%s grants %s", svc, p[0])
				}
				pd = append(pd, p[2])
			}
			if !slices.Equal(pd, serviceDirs(svc)) || strings.Count(pol, `capabilities = ["read"]`) != len(pd) {
				t.Errorf("policy-%s: %v, want read on %v", svc, pd, serviceDirs(svc))
			}
			for _, f := range []string{svc + ".hcl", svc + ".ctmpl"} {
				if !strings.Contains(string(kust), f) {
					t.Errorf("kustomization.yaml does not ship %s", f)
				}
			}
		}
	})
}

func read(t *testing.T, p ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{deployDir}, p...)...)) // #nosec G304 -- the repository's own files
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
