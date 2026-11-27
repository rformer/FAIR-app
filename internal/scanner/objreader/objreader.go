// Package objreader is a read-only object source for the deployment checks
// (F-014 T-09; design §2, §3.7): a scanner.Reader over a set of objects,
// serving them the way internal/scanner/kube serves a live cluster (List by
// resource and namespace, kube.ErrNotFound for what is not served, Secrets
// refused), so the same checks.Catalog runs over a chart render, a test
// fixture or, through Overlay, a live cluster with the release's objects as
// if applied (the preflight, T-13).
//
// Applied turns rendered objects into what a cluster serves once they are
// applied: each workload also as a running pod of its template (its
// containers' statuses naming the template's images), the claims of its
// volume claim templates, and Helm hooks gone (they run before the release
// and are deleted, or complete, by then).
package objreader

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/internal/scanner/kube"
)

// Resources maps each kind the deployment checks read (scanner.Access) and
// the workload kinds to its API resource. Objects of other kinds are not
// served (the checks never read them).
var Resources = map[string]kube.Resource{
	"Namespace":                      kube.Namespaces,
	"Node":                           kube.Nodes,
	"Pod":                            kube.Pods,
	"Service":                        kube.Services,
	"PersistentVolumeClaim":          kube.PersistentVolumeClaims,
	"ServiceAccount":                 kube.ServiceAccounts,
	"Deployment":                     kube.Deployments,
	"StatefulSet":                    kube.StatefulSets,
	"DaemonSet":                      kube.DaemonSets,
	"NetworkPolicy":                  kube.NetworkPolicies,
	"Role":                           kube.Roles,
	"RoleBinding":                    kube.RoleBindings,
	"ClusterRole":                    kube.ClusterRoles,
	"ClusterRoleBinding":             kube.ClusterRoleBindings,
	"StorageClass":                   kube.StorageClasses,
	"ValidatingAdmissionPolicy":      kube.ValidatingAdmissionPolicies,
	"ValidatingWebhookConfiguration": kube.ValidatingWebhookConfigurations,
	"ExternalSecret":                 kube.ExternalSecrets,
}

// HookAnnotation marks a Helm hook.
const HookAnnotation = "helm.sh/hook"

// Set is a set of objects served as a cluster serves them. The zero value
// is not usable; use New.
type Set struct {
	objs      map[string][]kube.Object // resource -> objects, in insertion order
	notServed map[string]bool          // resources answered with kube.ErrNotFound
}

// New returns an empty set that serves every resource of Resources.
func New() *Set {
	return &Set{objs: map[string][]kube.Object{}, notServed: map[string]bool{}}
}

// NotServed makes List answer kube.ErrNotFound for these resources, as a
// cluster without the API (an External Secrets operator, the
// ValidatingAdmissionPolicy API) does.
func (s *Set) NotServed(rs ...kube.Resource) {
	for _, r := range rs {
		s.notServed[r.String()] = true
	}
}

// Add adds an object (decoded JSON or YAML); an object of the same kind,
// namespace and name is replaced. It reports whether the set serves the
// object's kind: objects of other kinds are ignored.
func (s *Set) Add(doc map[string]any) (bool, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return false, err
	}
	return s.AddJSON(raw)
}

// AddJSON adds an object given as JSON (see Add).
func (s *Set) AddJSON(raw []byte) (bool, error) {
	var head struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return false, fmt.Errorf("objreader: %w", err)
	}
	res, ok := Resources[head.Kind]
	if !ok {
		return false, nil
	}
	var o kube.Object
	if err := json.Unmarshal(raw, &o); err != nil {
		return false, fmt.Errorf("objreader: %s: %w", head.Kind, err)
	}
	if o.Metadata.Name == "" {
		return false, fmt.Errorf("objreader: a %s without a name", head.Kind)
	}
	if res.Namespaced != (o.Metadata.Namespace != "") {
		return false, fmt.Errorf("objreader: %s %s: namespace %q for a resource that is namespaced=%v", head.Kind, o.Metadata.Name, o.Metadata.Namespace, res.Namespaced)
	}
	o.Raw = append(json.RawMessage(nil), raw...)
	key := res.String()
	for i, x := range s.objs[key] {
		if x.Metadata.Namespace == o.Metadata.Namespace && x.Metadata.Name == o.Metadata.Name {
			s.objs[key][i] = o
			return true, nil
		}
	}
	s.objs[key] = append(s.objs[key], o)
	return true, nil
}

// AddYAML adds every object of a multi-document YAML stream.
func (s *Set) AddYAML(r io.Reader) error {
	docs, err := DecodeYAML(r)
	if err != nil {
		return err
	}
	for _, d := range docs {
		if _, err := s.Add(d); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes the object of that kind, namespace and name, if any.
func (s *Set) Delete(kind, namespace, name string) {
	res, ok := Resources[kind]
	if !ok {
		return
	}
	key := res.String()
	l := s.objs[key]
	for i, x := range l {
		if x.Metadata.Namespace == namespace && x.Metadata.Name == name {
			s.objs[key] = append(l[:i:i], l[i+1:]...)
			return
		}
	}
}

// Objects returns the set's objects of a resource in every namespace.
func (s *Set) Objects(r kube.Resource) []kube.Object {
	return append([]kube.Object(nil), s.objs[r.String()]...)
}

// List implements scanner.Reader: the objects of r in namespace ns (every
// namespace when ns is "" or r is cluster-scoped).
func (s *Set) List(_ context.Context, r kube.Resource, ns string) ([]kube.Object, string, error) {
	if r.Plural == "secrets" && r.Group == "" {
		return nil, "", kube.ErrSecretsRefused
	}
	if s.notServed[r.String()] {
		return nil, "", kube.ErrNotFound
	}
	out := []kube.Object{}
	for _, o := range s.objs[r.String()] {
		if !r.Namespaced || ns == "" || o.Metadata.Namespace == ns {
			out = append(out, o)
		}
	}
	return out, "1", nil
}

// Watch implements scanner.Reader: a set does not change, so Watch blocks
// until ctx ends.
func (s *Set) Watch(ctx context.Context, _ kube.Resource, _, _ string, _ func(kube.Event) error) error {
	<-ctx.Done()
	return nil
}

// Namespaces returns the names of the set's namespaces, sorted.
func (s *Set) Namespaces() []string {
	var out []string
	for _, o := range s.objs[kube.Namespaces.String()] {
		out = append(out, o.Metadata.Name)
	}
	sort.Strings(out)
	return out
}

// overlay serves top's objects over base's.
type overlay struct {
	base scanner.Reader
	top  *Set
}

// Overlay returns a reader serving base's objects with top's applied over
// them: an object of top replaces base's of the same resource, namespace
// and name, and top's others are added. A resource base does not serve
// (kube.ErrNotFound) is served from top alone when top holds objects of it.
// Any other error of base is returned as it is. Watch is base's: top does
// not change.
func Overlay(base scanner.Reader, top *Set) scanner.Reader {
	return &overlay{base: base, top: top}
}

func (o *overlay) List(ctx context.Context, r kube.Resource, ns string) ([]kube.Object, string, error) {
	mine, _, terr := o.top.List(ctx, r, ns)
	if errors.Is(terr, kube.ErrSecretsRefused) {
		return nil, "", terr
	}
	objs, rv, err := o.base.List(ctx, r, ns)
	switch {
	case errors.Is(err, kube.ErrNotFound) && terr == nil && len(mine) > 0:
		return mine, "1", nil
	case err != nil:
		return nil, "", err
	}
	if terr != nil {
		return objs, rv, nil
	}
	type key struct{ ns, name string }
	replaced := map[key]bool{}
	for _, m := range mine {
		replaced[key{m.Metadata.Namespace, m.Metadata.Name}] = true
	}
	out := make([]kube.Object, 0, len(objs)+len(mine))
	for _, x := range objs {
		if !replaced[key{x.Metadata.Namespace, x.Metadata.Name}] {
			out = append(out, x)
		}
	}
	return append(out, mine...), rv, nil
}

func (o *overlay) Watch(ctx context.Context, r kube.Resource, ns, rv string, fn func(kube.Event) error) error {
	return o.base.Watch(ctx, r, ns, rv, fn)
}

// DecodeYAML decodes a multi-document YAML stream into objects, normalized
// through JSON (numbers as float64, as from the API server's JSON); empty
// documents are skipped.
func DecodeYAML(r io.Reader) ([]map[string]any, error) {
	dec := yaml.NewDecoder(r)
	var out []map[string]any
	for {
		var d map[string]any
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			return out, nil
		} else if err != nil {
			return nil, fmt.Errorf("objreader: %w", err)
		}
		if d == nil {
			continue
		}
		n, err := normalize(d)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
}

// DecodeYAMLString is DecodeYAML over a string.
func DecodeYAMLString(text string) ([]map[string]any, error) {
	return DecodeYAML(strings.NewReader(text))
}

func normalize(d map[string]any) (map[string]any, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("objreader: %w", err)
	}
	var n map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&n); err != nil {
		return nil, fmt.Errorf("objreader: %w", err)
	}
	return n, nil
}

// Key names an object: "<kind>/<namespace>/<name>".
func Key(o map[string]any) string {
	return fmt.Sprintf("%v/%s/%s", o["kind"], str(o, "metadata", "namespace"), str(o, "metadata", "name"))
}

// IsHook reports whether an object is a Helm hook.
func IsHook(o map[string]any) bool {
	_, ok := dig(o, "metadata", "annotations", HookAnnotation).(string)
	return ok
}

// templateHash is the pod-template-hash the applied pods of a Deployment
// carry (any stable value: the checks group a Deployment's pods by it).
const templateHash = "5f6d7c8b9"

// Applied returns what a cluster serves once objs are applied: every object
// but Helm hooks, and for each workload a running pod of its template
// (a Deployment's through its ReplicaSet, a StatefulSet's ordinal 0, a
// DaemonSet's one pod), with container statuses naming the template's
// images, plus the PersistentVolumeClaims of a StatefulSet's volume claim
// templates and of a CloudNativePG Cluster's first instance. The input is
// not changed.
func Applied(objs []map[string]any) ([]map[string]any, error) {
	var out []map[string]any
	for _, src := range objs {
		if IsHook(src) {
			continue
		}
		o, err := deepCopy(src)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
		ns, name := str(o, "metadata", "namespace"), str(o, "metadata", "name")
		switch o["kind"] {
		case "Deployment", "StatefulSet", "DaemonSet":
			p, err := podOf(o)
			if err != nil {
				return nil, err
			}
			out = append(out, p)
			if o["kind"] != "StatefulSet" {
				continue
			}
			vcts, _ := dig(o, "spec", "volumeClaimTemplates").([]any)
			for _, v := range vcts {
				out = append(out, map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaim",
					"metadata": map[string]any{"name": fmt.Sprintf("%s-%s-0", str(v, "metadata", "name"), name), "namespace": ns},
					"spec":     dig(v, "spec")})
			}
		case "Cluster":
			if api, _ := o["apiVersion"].(string); strings.HasPrefix(api, "postgresql.cnpg.io/") {
				out = append(out, map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaim",
					"metadata": map[string]any{"name": name + "-1", "namespace": ns},
					"spec":     map[string]any{"accessModes": []any{"ReadWriteOnce"}}})
			}
		}
	}
	return out, nil
}

// podOf is a running pod of a workload's template.
func podOf(o map[string]any) (map[string]any, error) {
	ns, name := str(o, "metadata", "namespace"), str(o, "metadata", "name")
	tmpl, _ := dig(o, "spec", "template").(map[string]any)
	if tmpl == nil {
		return nil, fmt.Errorf("objreader: %s has no pod template", Key(o))
	}
	labels := map[string]any{}
	if l, ok := dig(tmpl, "metadata", "labels").(map[string]any); ok {
		for k, v := range l {
			labels[k] = v
		}
	}
	md := map[string]any{"namespace": ns, "labels": labels}
	if a, ok := dig(tmpl, "metadata", "annotations").(map[string]any); ok {
		md["annotations"] = a
	}
	switch o["kind"] {
	case "Deployment":
		labels["pod-template-hash"] = templateHash
		md["name"] = name + "-" + templateHash + "-ref00"
		md["ownerReferences"] = []any{map[string]any{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": name + "-" + templateHash}}
	case "StatefulSet":
		md["name"] = name + "-0"
		md["ownerReferences"] = []any{map[string]any{"apiVersion": "apps/v1", "kind": "StatefulSet", "name": name}}
	default:
		md["name"] = name + "-ref00"
		md["ownerReferences"] = []any{map[string]any{"apiVersion": "apps/v1", "kind": "DaemonSet", "name": name}}
	}
	spec, _ := tmpl["spec"].(map[string]any)
	status := map[string]any{}
	for list, st := range map[string]string{"containers": "containerStatuses", "initContainers": "initContainerStatuses"} {
		cs, _ := spec[list].([]any)
		var sts []any
		for _, c := range cs {
			img := str(c, "image")
			sts = append(sts, map[string]any{"name": str(c, "name"), "image": img, "imageID": img, "ready": true})
		}
		if sts != nil {
			status[st] = sts
		}
	}
	status["phase"] = "Running"
	return map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": md, "spec": spec, "status": status}, nil
}

func deepCopy(o map[string]any) (map[string]any, error) {
	return normalize(o)
}

func dig(v any, path ...string) any {
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}

func str(v any, path ...string) string {
	s, _ := dig(v, path...).(string)
	return s
}
