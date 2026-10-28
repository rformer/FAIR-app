package checks

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"

	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/internal/scanner/kube"
)

// 5. Every platform container runs an image of the signed release manifest,
// referenced by digest, and the digest actually running is that one.
func imageDigests(cfg Config) check {
	c := check{Meta: Meta{ID: "image_digests", Title: "Running images match the signed release manifest",
		Controls:    []string{"CM-14", "SI-7", "SR-4"},
		Remediation: "Redeploy the workload from the release bundle, which references every image by its signed digest."}}
	c.run = func(ctx context.Context, r scanner.Reader, s scanner.Scope) ([]scanner.Finding, error) {
		m, err := cfg.release()
		if err != nil {
			return nil, wrapManifest(err)
		}
		want := map[string]string{} // repository -> digest
		for _, img := range m.Images {
			want[releasemanifest.Repository(img)] = releasemanifest.Digest(img)
		}
		ps, err := pods(ctx, r, s)
		if err != nil {
			return nil, err
		}
		type issue struct{ sev, text string }
		problems := map[string][]issue{}
		for _, p := range ps {
			running := map[string]string{}
			for _, st := range append(slices.Clone(p.Status.InitContainerStatuses), p.Status.ContainerStatuses...) {
				running[st.Name] = releasemanifest.Digest(st.ImageID)
			}
			w := p.workload()
			for _, ctr := range p.containers() {
				repo := releasemanifest.Repository(ctr.Image)
				exp, known := want[repo]
				switch {
				case !known:
					problems[w] = append(problems[w], issue{"high", ctr.Name + ": image " + repo + " is not in release " + m.Release})
				case releasemanifest.Digest(ctr.Image) == "":
					problems[w] = append(problems[w], issue{"medium", ctr.Name + ": image referenced by tag, not digest"})
				case releasemanifest.Digest(ctr.Image) != exp:
					problems[w] = append(problems[w], issue{"critical", ctr.Name + ": digest differs from release " + m.Release})
				}
				if known && running[ctr.Name] != "" && running[ctr.Name] != exp {
					problems[w] = append(problems[w], issue{"critical", ctr.Name + ": running digest " + running[ctr.Name] + " differs from release " + m.Release})
				}
			}
		}
		var out []scanner.Finding
		for _, w := range sortedKeys(problems) {
			sev, texts := "low", []string{}
			rank := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
			for _, i := range problems[w] {
				if !slices.Contains(texts, i.text) {
					texts = append(texts, i.text)
				}
				if rank[i.sev] > rank[sev] {
					sev = i.sev
				}
			}
			sort.Strings(texts)
			out = append(out, c.finding(sev, "workload/"+w, map[string]any{"workload": w, "release": m.Release, "problems": texts}, ""))
		}
		return out, nil
	}
	return c
}

// knownVerifiers are admission configurations of image signature verifiers
// (by name), used when no object carries AnnotationVerifiesSignatures.
var knownVerifiers = []string{"policy.sigstore.dev", "sigstore", "connaisseur", "ratify"}

// 6. An admission policy verifies image signatures, and fails closed.
func signatureAdmission() check {
	c := check{Meta: Meta{ID: "signature_admission", Title: "Admission verifies image signatures",
		Controls:    []string{"CM-14", "SI-7"},
		Remediation: "Install an image signature verification admission controller (for example the Sigstore policy-controller) enforcing the release signing identity, with failurePolicy Fail, and annotate it fair-platform.io/verifies-image-signatures=true."}}
	c.run = func(ctx context.Context, r scanner.Reader, _ scanner.Scope) ([]scanner.Finding, error) {
		type admission struct {
			Metadata meta `json:"metadata"`
			Spec     struct {
				FailurePolicy *string `json:"failurePolicy"`
			} `json:"spec"`
			Webhooks []struct {
				Name          string  `json:"name"`
				FailurePolicy *string `json:"failurePolicy"`
			} `json:"webhooks"`
		}
		var found []string
		var failOpen []string
		for _, res := range []kube.Resource{kube.ValidatingAdmissionPolicies, kube.ValidatingWebhookConfigurations} {
			objs, _, err := r.List(ctx, res, "")
			if errors.Is(err, kube.ErrNotFound) {
				continue // e.g. no ValidatingAdmissionPolicy API on this cluster
			}
			if err != nil {
				return nil, err
			}
			as, err := decode[admission](objs)
			if err != nil {
				return nil, err
			}
			for _, a := range as {
				names := []string{a.Metadata.Name}
				for _, w := range a.Webhooks {
					names = append(names, w.Name)
				}
				verifier := a.Metadata.Annotations[AnnotationVerifiesSignatures] == "true"
				for _, n := range names {
					for _, k := range knownVerifiers {
						verifier = verifier || strings.Contains(n, k)
					}
				}
				if !verifier {
					continue
				}
				found = append(found, res.Plural+"/"+a.Metadata.Name)
				for _, w := range a.Webhooks {
					if w.FailurePolicy != nil && *w.FailurePolicy == "Ignore" {
						failOpen = append(failOpen, a.Metadata.Name+"/"+w.Name)
					}
				}
			}
		}
		switch {
		case len(found) == 0:
			return []scanner.Finding{c.finding("high", "cluster/admission", map[string]any{"verifier": false}, "")}, nil
		case len(failOpen) > 0:
			return []scanner.Finding{c.finding("medium", "cluster/admission", map[string]any{"verifiers": found, "fail_open": failOpen},
				"Set failurePolicy: Fail on the signature-verification webhook, so an unavailable verifier blocks unverified images.")}, nil
		}
		return nil, nil
	}
	return c
}

// 10. The platform's own RBAC matches the signed release manifest: nothing
// changed, missing or added (Roles and bindings in the platform namespaces,
// platform-labelled cluster roles, and cluster bindings granting anything
// to a platform ServiceAccount).
func platformRBAC(cfg Config) check {
	c := check{Meta: Meta{ID: "platform_rbac", Title: "Platform RBAC unchanged from the release",
		Controls:    []string{"AC-6", "CM-5"},
		Remediation: "Restore the platform RBAC from the release bundle and investigate who changed it (Kubernetes audit log)."}}
	c.run = func(ctx context.Context, r scanner.Reader, s scanner.Scope) ([]scanner.Finding, error) {
		m, err := cfg.release()
		if err != nil {
			return nil, wrapManifest(err)
		}
		expected := map[string]string{}
		for _, e := range m.RBAC {
			expected[e.Key()] = e.SHA256
		}
		live := map[string]string{}
		hash := func(kind string, o kube.Object) error {
			h, err := releasemanifest.Hash(kind, o.Raw)
			if err != nil {
				return err
			}
			live[releasemanifest.RBACEntry{Kind: kind, Namespace: o.Metadata.Namespace, Name: o.Metadata.Name}.Key()] = h
			return nil
		}
		// The platform namespaces and fips-probe's (T-29).
		rbacScope := s
		if s.ProbeNamespace != "" {
			rbacScope.Namespaces = append(slices.Clone(s.Namespaces), s.ProbeNamespace)
		}
		for kind, res := range map[string]kube.Resource{"Role": kube.Roles, "RoleBinding": kube.RoleBindings} {
			objs, err := listAll(ctx, r, res, rbacScope)
			if err != nil {
				return nil, err
			}
			for _, o := range objs {
				if err := hash(kind, o); err != nil {
					return nil, err
				}
			}
		}
		platformSA := func(raw json.RawMessage) bool {
			var b struct {
				Subjects []struct{ Kind, Namespace string } `json:"subjects"`
			}
			_ = json.Unmarshal(raw, &b)
			return slices.ContainsFunc(b.Subjects, func(sub struct{ Kind, Namespace string }) bool {
				return sub.Kind == "ServiceAccount" && slices.Contains(rbacScope.Namespaces, sub.Namespace)
			})
		}
		for kind, res := range map[string]kube.Resource{"ClusterRole": kube.ClusterRoles, "ClusterRoleBinding": kube.ClusterRoleBindings} {
			objs, _, err := r.List(ctx, res, "")
			if err != nil {
				return nil, err
			}
			for _, o := range objs {
				key := releasemanifest.RBACEntry{Kind: kind, Name: o.Metadata.Name}.Key()
				_, inManifest := expected[key]
				platform := o.Metadata.Labels["app.kubernetes.io/part-of"] == "fair-platform"
				if inManifest || platform || (kind == "ClusterRoleBinding" && platformSA(o.Raw)) {
					if err := hash(kind, o); err != nil {
						return nil, err
					}
				}
			}
		}
		var out []scanner.Finding
		subject := func(key string) string { return "rbac/" + strings.TrimSuffix(strings.Replace(key, "//", "/", 1), "/") }
		for _, key := range sortedKeys(expected) {
			switch got, ok := live[key]; {
			case !ok:
				out = append(out, c.finding("medium", subject(key), map[string]any{"object": key, "state": "missing", "release": m.Release},
					"Restore the missing RBAC object from the release bundle; the component it serves may be failing."))
			case got != expected[key]:
				out = append(out, c.finding("high", subject(key), map[string]any{"object": key, "state": "changed", "release": m.Release}, ""))
			}
		}
		for _, key := range sortedKeys(live) {
			if _, ok := expected[key]; !ok {
				out = append(out, c.finding("high", subject(key), map[string]any{"object": key, "state": "unexpected", "release": m.Release},
					"Remove the RBAC object, which is not part of the release, and investigate who added it (Kubernetes audit log)."))
			}
		}
		return out, nil
	}
	return c
}
