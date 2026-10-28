package scanner

import (
	"bytes"
	"errors"
	"io"
	"os"
	"slices"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

// Verification for F-015 T-29 (static): fips-probe mounts exactly one host
// file, read-only, and holds nothing else of value; its namespace contains
// only the probe; the OpenShift SCC grants nothing beyond restricted-v2
// except hostPath, and only to the probe's ServiceAccount.

func loadDocs(t *testing.T, file string) []doc {
	t.Helper()
	b, err := os.ReadFile(file) // #nosec G304 -- repository manifests
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var docs []doc
	for {
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

func TestFIPSProbeManifest(t *testing.T) {
	var kinds []string
	var ds, ns, np doc
	for _, d := range loadDocs(t, "../../deploy/k8s/fips-probe.yaml") {
		kinds = append(kinds, d.kind())
		switch d.kind() {
		case "DaemonSet":
			ds = d
		case "Namespace":
			ns = d
		case "NetworkPolicy":
			np = d
		case "ServiceAccount":
			if d["automountServiceAccountToken"] != false {
				t.Error("ServiceAccount automounts its token")
			}
		}
		if d.kind() != "Namespace" && str(d.m("metadata")["namespace"]) != "fair-fips-probe" {
			t.Errorf("%s %s outside fair-fips-probe", d.kind(), d.name())
		}
	}
	// Nothing else lives in the privileged namespace; no RBAC for the probe.
	if !slices.Equal(kinds, []string{"Namespace", "ServiceAccount", "DaemonSet", "NetworkPolicy"}) {
		t.Errorf("fips-probe.yaml holds %v", kinds)
	}
	if str(ns.m("metadata").m("labels")["pod-security.kubernetes.io/enforce"]) != "privileged" {
		t.Error("the probe namespace must enforce privileged (hostPath) and hold nothing else")
	}
	if sp := np.m("spec"); !slices.Equal(strs(sp["policyTypes"]), []string{"Ingress", "Egress"}) || sp["ingress"] != nil || sp["egress"] != nil {
		t.Errorf("probe namespace must deny all traffic: %v", sp)
	}

	pod := ds.m("spec").m("template").m("spec")
	if pod["automountServiceAccountToken"] != false || pod["hostNetwork"] == true || pod["hostPID"] == true || pod["hostIPC"] == true {
		t.Errorf("pod identity/host access: %v", pod)
	}
	if psc := pod.m("securityContext"); psc["runAsNonRoot"] != true || str(psc.m("seccompProfile")["type"]) != "RuntimeDefault" {
		t.Errorf("pod securityContext %v", psc)
	}
	if tol := list(pod["tolerations"]); len(tol) != 1 || str(tol[0]["operator"]) != "Exists" {
		t.Errorf("the probe must run on every node: %v", pod["tolerations"])
	}
	vols := list(pod["volumes"])
	if len(vols) != 1 {
		t.Fatalf("%d volumes, want exactly the FIPS flag", len(vols))
	}
	hp := vols[0].m("hostPath")
	if str(hp["path"]) != "/proc/sys/crypto/fips_enabled" || str(hp["type"]) != "File" {
		t.Errorf("hostPath %v: exactly the FIPS flag file, type File", hp)
	}
	ctrs := list(pod["containers"])
	if len(ctrs) != 1 || len(list(pod["initContainers"])) != 0 {
		t.Fatalf("containers %v", pod["containers"])
	}
	c := ctrs[0]
	sc := c.m("securityContext")
	if sc["allowPrivilegeEscalation"] != false || sc["readOnlyRootFilesystem"] != true || !slices.Equal(strs(sc.m("capabilities")["drop"]), []string{"ALL"}) || sc["privileged"] == true {
		t.Errorf("container securityContext %v", sc)
	}
	mounts := list(c["volumeMounts"])
	if len(mounts) != 1 || mounts[0]["readOnly"] != true || str(mounts[0]["mountPath"]) != "/host/fips_enabled" {
		t.Errorf("mounts %v", mounts)
	}
	if cmd := strs(c.m("readinessProbe").m("exec")["command"]); !slices.Equal(cmd, []string{"/fips-probe", "check"}) {
		t.Errorf("readiness must run the check: %v", cmd)
	}
	if c["ports"] != nil {
		t.Error("the probe must not listen")
	}
}

func TestFIPSProbeOpenShiftSCC(t *testing.T) {
	var scc, role, binding doc
	for _, d := range loadDocs(t, "../../deploy/k8s/openshift/fips-probe-scc.yaml") {
		switch d.kind() {
		case "SecurityContextConstraints":
			scc = d
		case "Role":
			role = d
		case "RoleBinding":
			binding = d
		default:
			t.Errorf("unexpected %s", d.kind())
		}
	}
	for k, want := range map[string]any{
		"allowHostDirVolumePlugin": true, "allowHostIPC": false, "allowHostNetwork": false, "allowHostPID": false,
		"allowHostPorts": false, "allowPrivilegeEscalation": false, "allowPrivilegedContainer": false, "readOnlyRootFilesystem": true,
		"allowedCapabilities": nil, "defaultAddCapabilities": nil,
	} {
		if scc[k] != want {
			t.Errorf("SCC %s = %v, want %v", k, scc[k], want)
		}
	}
	if !slices.Equal(strs(scc["volumes"]), []string{"hostPath"}) || !slices.Equal(strs(scc["requiredDropCapabilities"]), []string{"ALL"}) {
		t.Errorf("SCC volumes %v, drop %v", scc["volumes"], scc["requiredDropCapabilities"])
	}
	if str(scc.m("runAsUser")["type"]) != "MustRunAsNonRoot" || len(strs(scc["users"])) != 0 || len(strs(scc["groups"])) != 0 {
		t.Errorf("SCC runAsUser %v users %v groups %v", scc["runAsUser"], scc["users"], scc["groups"])
	}
	rules := list(role["rules"])
	if len(rules) != 1 || !slices.Equal(strs(rules[0]["verbs"]), []string{"use"}) ||
		!slices.Equal(strs(rules[0]["resourceNames"]), []string{"fair-fips-probe"}) || str(role.m("metadata")["namespace"]) != "fair-fips-probe" {
		t.Errorf("SCC role %v", rules)
	}
	subj := list(binding["subjects"])
	if len(subj) != 1 || str(subj[0]["name"]) != "fips-probe" || str(subj[0]["namespace"]) != "fair-fips-probe" {
		t.Errorf("SCC binding subjects %v", subj)
	}
}
