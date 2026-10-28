package checks

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/internal/scanner/kube"
)

// 1. Pod security admission = restricted on every platform namespace.
func podSecurityAdmission(cfg Config) check {
	c := check{Meta: Meta{ID: "pod_security_admission", Title: "Pod security admission enforces restricted on platform namespaces",
		Controls:    []string{"CM-6", "CM-7"},
		Remediation: "Label the namespace pod-security.kubernetes.io/enforce=restricted (or attest a restricted cluster default at install)."}}
	c.run = func(ctx context.Context, r scanner.Reader, s scanner.Scope) ([]scanner.Finding, error) {
		objs, _, err := r.List(ctx, kube.Namespaces, "")
		if err != nil {
			return nil, err
		}
		levels := map[string]string{}
		found := map[string]bool{}
		for _, o := range objs {
			levels[o.Metadata.Name] = o.Metadata.Labels["pod-security.kubernetes.io/enforce"]
			found[o.Metadata.Name] = true
		}
		var out []scanner.Finding
		for _, ns := range s.Namespaces {
			level := levels[ns]
			switch {
			case !found[ns]:
				out = append(out, c.finding("high", "namespace/"+ns, map[string]any{"namespace": ns, "error": "namespace not found"},
					"The platform namespace is missing; reinstall or correct the scanner's namespace list."))
			case level == "restricted", level == "" && cfg.PSADefault == "restricted":
				continue
			default:
				d := map[string]any{"namespace": ns, "enforce": level, "attested_default": cfg.PSADefault}
				out = append(out, c.finding("high", "namespace/"+ns, d, ""))
			}
		}
		return out, nil
	}
	return c
}

type networkPolicy struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		PodSelector labelSelector `json:"podSelector"`
		PolicyTypes []string      `json:"policyTypes"`
		Ingress     []any         `json:"ingress"`
		Egress      []any         `json:"egress"`
	} `json:"spec"`
}

func (n networkPolicy) defaultDeny() bool {
	return n.Spec.PodSelector.empty() && slices.Contains(n.Spec.PolicyTypes, "Ingress") &&
		slices.Contains(n.Spec.PolicyTypes, "Egress") && len(n.Spec.Ingress) == 0 && len(n.Spec.Egress) == 0
}

// 2. NetworkPolicy default deny in each platform namespace, and an explicit
// policy for every platform workload.
func networkPolicies() check {
	c := check{Meta: Meta{ID: "network_policy", Title: "NetworkPolicy default deny and per-workload allow rules",
		Controls:    []string{"SC-7", "AC-4"},
		Remediation: "Apply the platform's default-deny NetworkPolicy and its per-service policies from the release bundle."}}
	c.run = func(ctx context.Context, r scanner.Reader, s scanner.Scope) ([]scanner.Finding, error) {
		ps, err := pods(ctx, r, s)
		if err != nil {
			return nil, err
		}
		objs, err := listAll(ctx, r, kube.NetworkPolicies, s)
		if err != nil {
			return nil, err
		}
		nps, err := decode[networkPolicy](objs)
		if err != nil {
			return nil, err
		}
		var out []scanner.Finding
		for _, ns := range s.Namespaces {
			if !slices.ContainsFunc(nps, func(n networkPolicy) bool { return n.Metadata.Namespace == ns && n.defaultDeny() }) {
				out = append(out, c.finding("high", "namespace/"+ns, map[string]any{"namespace": ns, "default_deny": false},
					"Apply a default-deny NetworkPolicy (empty podSelector, Ingress and Egress, no rules) to the namespace."))
			}
		}
		byWorkload, keys := workloadPods(ps)
		for _, w := range keys {
			p := byWorkload[w]
			selected := slices.ContainsFunc(nps, func(n networkPolicy) bool {
				return n.Metadata.Namespace == p.Metadata.Namespace && !n.defaultDeny() && n.Spec.PodSelector.matches(p.Metadata.Labels)
			})
			if !selected {
				out = append(out, c.finding("medium", "workload/"+w, map[string]any{"workload": w, "explicit_policy": false},
					"Add the workload's NetworkPolicy from the release bundle; under default deny it has no permitted traffic, outside it all traffic."))
			}
		}
		return out, nil
	}
	return c
}

// 4. Node FIPS mode: each node attested or verified (fips-probe, T-29).
// Posture keeps these findings only where the active profile requires
// FIPS (fips.enabled).
func nodeFIPS() check {
	c := check{Meta: Meta{ID: "node_fips", Title: "Nodes run in FIPS mode",
		Controls:    []string{"SC-13"},
		Remediation: "Run the node in FIPS mode and deploy fips-probe, or attest FIPS mode at install, so the node is labelled fair-platform.io/fips."}}
	c.run = func(ctx context.Context, r scanner.Reader, _ scanner.Scope) ([]scanner.Finding, error) {
		objs, _, err := r.List(ctx, kube.Nodes, "")
		if err != nil {
			return nil, err
		}
		var out []scanner.Finding
		for _, o := range objs {
			switch v := o.Metadata.Labels[LabelFIPS]; v {
			case "verified", "attested":
			default:
				out = append(out, c.finding("high", "node/"+o.Metadata.Name, map[string]any{"node": o.Metadata.Name, "fips": v}, ""))
			}
		}
		return out, nil
	}
	return c
}

func isTrue(b *bool) bool  { return b != nil && *b }
func isFalse(b *bool) bool { return b != nil && !*b }

// 7. Non-root, read-only root filesystem, no privilege escalation, all
// capabilities dropped, no host namespaces or hostPath volumes, on every
// platform workload.
func podHardening() check {
	c := check{Meta: Meta{ID: "pod_hardening", Title: "Platform pods run non-root with a read-only root filesystem",
		Controls:    []string{"CM-6", "CM-7"},
		Remediation: "Restore the workload's security context from the release bundle (runAsNonRoot, readOnlyRootFilesystem, allowPrivilegeEscalation: false, drop ALL)."}}
	c.run = func(ctx context.Context, r scanner.Reader, s scanner.Scope) ([]scanner.Finding, error) {
		ps, err := pods(ctx, r, s)
		if err != nil {
			return nil, err
		}
		byWorkload, keys := workloadPods(ps)
		var out []scanner.Finding
		for _, w := range keys {
			p := byWorkload[w]
			var problems []string
			if p.Spec.HostNetwork || p.Spec.HostPID || p.Spec.HostIPC {
				problems = append(problems, "host namespaces")
			}
			for _, v := range p.Spec.Volumes {
				if v.HostPath != nil {
					problems = append(problems, "hostPath volume "+v.Name)
				}
			}
			psc := p.Spec.SecurityContext
			if psc == nil {
				psc = &securityContext{}
			}
			for _, ctr := range p.containers() {
				sc := ctr.SecurityContext
				if sc == nil {
					sc = &securityContext{}
				}
				nonRoot := isTrue(sc.RunAsNonRoot) || (sc.RunAsNonRoot == nil && isTrue(psc.RunAsNonRoot))
				uid := sc.RunAsUser
				if uid == nil {
					uid = psc.RunAsUser
				}
				if uid != nil {
					nonRoot = (nonRoot || *uid > 0) && *uid != 0 // an explicit UID 0 is root whatever runAsNonRoot says
				}
				if !nonRoot {
					problems = append(problems, ctr.Name+": may run as root")
				}
				if !isTrue(sc.ReadOnlyRootFilesystem) {
					problems = append(problems, ctr.Name+": writable root filesystem")
				}
				if !isFalse(sc.AllowPrivilegeEscalation) {
					problems = append(problems, ctr.Name+": privilege escalation allowed")
				}
				if isTrue(sc.Privileged) {
					problems = append(problems, ctr.Name+": privileged")
				}
				if sc.Capabilities == nil || !slices.Contains(sc.Capabilities.Drop, "ALL") {
					problems = append(problems, ctr.Name+": capabilities not dropped")
				} else if extra := slices.DeleteFunc(slices.Clone(sc.Capabilities.Add), func(c string) bool { return c == "NET_BIND_SERVICE" }); len(extra) > 0 {
					problems = append(problems, ctr.Name+": adds capabilities "+strings.Join(extra, ","))
				}
			}
			if len(problems) > 0 {
				out = append(out, c.finding("high", "workload/"+w, map[string]any{"workload": w, "problems": problems}, ""))
			}
		}
		return out, nil
	}
	return c
}

var (
	secretName  = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|dsn|conn(ection)?[_-]?str)`)
	secretArg   = regexp.MustCompile(`(?i)^--?(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key)(=.+)$`)
	urlUserinfo = regexp.MustCompile(`://[^/@\s:]+:[^/@\s]+@`)
)

// plaintext reports why an env var or argument looks like an inline
// secret, or "".
func plaintextEnv(e envVar) string {
	if e.ValueFrom != nil || e.Value == "" {
		return ""
	}
	if urlUserinfo.MatchString(e.Value) {
		return "credentials in a URL in " + e.Name
	}
	up := strings.ToUpper(e.Name)
	if strings.HasSuffix(up, "_FILE") || strings.HasSuffix(up, "_PATH") || strings.HasPrefix(e.Value, "/") {
		return "" // a reference to a mounted file, the platform's convention
	}
	if secretName.MatchString(e.Name) {
		return "literal value in " + e.Name
	}
	return ""
}

// 9. Secrets referenced from a secrets store, never set as plaintext values
// in env or arguments.
func plaintextSecrets() check {
	c := check{Meta: Meta{ID: "plaintext_secrets", Title: "Secrets come from a secrets store, never plaintext values",
		Controls:    []string{"IA-5", "SC-28"},
		Remediation: "Move the value into the secrets store (ExternalSecret or a Kubernetes Secret) and reference it as a mounted file; rotate the exposed secret."}}
	c.run = func(ctx context.Context, r scanner.Reader, s scanner.Scope) ([]scanner.Finding, error) {
		ps, err := pods(ctx, r, s)
		if err != nil {
			return nil, err
		}
		// Secrets an ExternalSecret produces, when the operator is installed.
		managed := map[string]bool{}
		esoInstalled := true
		objs, err := listAll(ctx, r, kube.ExternalSecrets, s)
		switch {
		case errors.Is(err, kube.ErrNotFound):
			esoInstalled = false
		case err != nil:
			return nil, err
		}
		type externalSecret struct {
			Metadata meta `json:"metadata"`
			Spec     struct {
				Target struct {
					Name string `json:"name"`
				} `json:"target"`
			} `json:"spec"`
		}
		ess, err := decode[externalSecret](objs)
		if err != nil {
			return nil, err
		}
		for _, e := range ess {
			name := e.Spec.Target.Name
			if name == "" {
				name = e.Metadata.Name
			}
			managed[e.Metadata.Namespace+"/"+name] = true
		}

		byWorkload, keys := workloadPods(ps)
		var out []scanner.Finding
		for _, w := range keys {
			p := byWorkload[w]
			var plain []string
			refs := map[string]bool{}
			for _, ctr := range p.containers() {
				for _, e := range ctr.Env {
					if why := plaintextEnv(e); why != "" {
						plain = append(plain, ctr.Name+": "+why)
					}
					if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
						refs[e.ValueFrom.SecretKeyRef.Name] = true
					}
				}
				for _, ef := range ctr.EnvFrom {
					if ef.SecretRef != nil {
						refs[ef.SecretRef.Name] = true
					}
				}
				for _, a := range append(slices.Clone(ctr.Command), ctr.Args...) {
					if secretArg.MatchString(a) || urlUserinfo.MatchString(a) {
						plain = append(plain, ctr.Name+": secret in a command-line argument")
					}
				}
			}
			for _, v := range p.Spec.Volumes {
				if v.Secret != nil {
					refs[v.Secret.SecretName] = true
				}
			}
			if len(plain) > 0 {
				// The values themselves are never put in the finding.
				out = append(out, c.finding("high", "workload/"+w, map[string]any{"workload": w, "plaintext": plain}, ""))
			}
			if esoInstalled {
				var unmanaged []string
				for name := range refs {
					if !managed[p.Metadata.Namespace+"/"+name] {
						unmanaged = append(unmanaged, name)
					}
				}
				if len(unmanaged) > 0 {
					sort.Strings(unmanaged)
					out = append(out, c.finding("low", "workload/"+w+"/secret-sources", map[string]any{"workload": w, "not_from_secrets_store": unmanaged},
						"Create these Secrets from the secrets store with ExternalSecrets rather than by hand."))
				}
			}
		}
		return out, nil
	}
	return c
}

type storageClass struct {
	Metadata    meta              `json:"metadata"`
	Provisioner string            `json:"provisioner"`
	Parameters  map[string]string `json:"parameters"`
}

// encrypted reports whether a class's volumes are encrypted at rest, and how
// that is known.
func (sc storageClass) encrypted() (bool, string) {
	if sc.Metadata.Annotations[AnnotationEncrypted] == "true" {
		return true, "attested at install"
	}
	p := sc.Parameters
	switch sc.Provisioner {
	case "ebs.csi.aws.com", "kubernetes.io/aws-ebs":
		return p["encrypted"] == "true", "parameters.encrypted"
	case "pd.csi.storage.gke.io", "kubernetes.io/gce-pd", "disk.csi.azure.com", "kubernetes.io/azure-disk", "file.csi.azure.com":
		return true, "provider-managed encryption at rest"
	case "rbd.csi.ceph.com", "driver.longhorn.io":
		return p["encrypted"] == "true", "parameters.encrypted"
	case "pxd.portworx.com", "kubernetes.io/portworx-volume":
		return p["secure"] == "true", "parameters.secure"
	}
	return false, "provisioner " + sc.Provisioner + " gives no encryption setting"
}

// 8. The storage classes of platform volumes encrypt at rest.
func storageEncryption() check {
	c := check{Meta: Meta{ID: "storage_encryption", Title: "Platform volumes use encrypted storage classes",
		Controls:    []string{"SC-28"},
		Remediation: "Move the platform's volumes to an encrypted storage class, or attest encryption at rest for this class at install."}}
	c.run = func(ctx context.Context, r scanner.Reader, s scanner.Scope) ([]scanner.Finding, error) {
		objs, _, err := r.List(ctx, kube.StorageClasses, "")
		if err != nil {
			return nil, err
		}
		classes, err := decode[storageClass](objs)
		if err != nil {
			return nil, err
		}
		byName := map[string]storageClass{}
		def := ""
		for _, sc := range classes {
			byName[sc.Metadata.Name] = sc
			if sc.Metadata.Annotations["storageclass.kubernetes.io/is-default-class"] == "true" {
				def = sc.Metadata.Name
			}
		}
		pvcObjs, err := listAll(ctx, r, kube.PersistentVolumeClaims, s)
		if err != nil {
			return nil, err
		}
		type pvc struct {
			Metadata meta `json:"metadata"`
			Spec     struct {
				StorageClassName *string `json:"storageClassName"`
			} `json:"spec"`
		}
		pvcs, err := decode[pvc](pvcObjs)
		if err != nil {
			return nil, err
		}
		used := map[string][]string{}
		for _, v := range pvcs {
			class := def
			if v.Spec.StorageClassName != nil {
				class = *v.Spec.StorageClassName
			}
			used[class] = append(used[class], v.Metadata.Namespace+"/"+v.Metadata.Name)
		}
		var out []scanner.Finding
		for _, name := range sortedKeys(used) {
			sc, ok := byName[name]
			if !ok {
				out = append(out, c.finding("medium", "storageclass/"+name, map[string]any{"storage_class": name, "claims": used[name], "error": "class not found"},
					"The claims name a storage class that does not exist; bind them to an encrypted class."))
				continue
			}
			if enc, how := sc.encrypted(); !enc {
				out = append(out, c.finding("high", "storageclass/"+name,
					map[string]any{"storage_class": name, "provisioner": sc.Provisioner, "claims": used[name], "reason": how}, ""))
			}
		}
		return out, nil
	}
	return c
}

var errNoManifest = errors.New("release manifest unavailable")

func wrapManifest(err error) error { return fmt.Errorf("%w: %w", errNoManifest, err) }
