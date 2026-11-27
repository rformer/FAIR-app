package objreader

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/internal/scanner/kube"
)

var _ scanner.Reader = (*Set)(nil)

const objs = `
apiVersion: v1
kind: Namespace
metadata: {name: fair-platform}
---
apiVersion: v1
kind: Service
metadata: {name: iam, namespace: fair-platform}
spec: {ports: [{port: 443}]}
---
apiVersion: v1
kind: Service
metadata: {name: other, namespace: elsewhere}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: ignored, namespace: fair-platform}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: iam, namespace: fair-platform}
spec:
  template:
    metadata: {labels: {app.kubernetes.io/name: iam}}
    spec:
      initContainers: [{name: init, image: "r/fair-iam@sha256:1"}]
      containers: [{name: iam, image: "r/fair-iam@sha256:1"}]
---
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: nats, namespace: fair-platform}
spec:
  template:
    metadata: {labels: {app: nats}}
    spec: {containers: [{name: nats, image: "r/fair-nats@sha256:2"}]}
  volumeClaimTemplates: [{metadata: {name: data}, spec: {accessModes: [ReadWriteOnce]}}]
---
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: fips-probe, namespace: fair-fips-probe}
spec:
  template:
    metadata: {labels: {app.kubernetes.io/name: fips-probe}}
    spec: {containers: [{name: probe, image: "r/fair-fips-probe@sha256:3"}]}
---
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata: {name: fair-db, namespace: fair-data}
---
apiVersion: batch/v1
kind: Job
metadata:
  name: fair-preflight
  namespace: fair-platform
  annotations: {helm.sh/hook: pre-install}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: fair-preflight
  annotations: {helm.sh/hook: pre-install}
`

func names(t *testing.T, r scanner.Reader, res kube.Resource, ns string) []string {
	t.Helper()
	l, _, err := r.List(context.Background(), res, ns)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, o := range l {
		out = append(out, strings.TrimPrefix(o.Metadata.Namespace+"/"+o.Metadata.Name, "/"))
	}
	slices.Sort(out)
	return out
}

// A set serves its objects as the kube client serves a cluster's: by
// resource and namespace, kinds the checks do not read left out, Secrets
// refused, unserved APIs not found.
func TestSet(t *testing.T) {
	s := New()
	if err := s.AddYAML(strings.NewReader(objs)); err != nil {
		t.Fatal(err)
	}
	if got := names(t, s, kube.Services, "fair-platform"); !slices.Equal(got, []string{"fair-platform/iam"}) {
		t.Errorf("services in fair-platform: %v", got)
	}
	if got := names(t, s, kube.Services, ""); len(got) != 2 {
		t.Errorf("services everywhere: %v", got)
	}
	if got := names(t, s, kube.ClusterRoles, "fair-platform"); !slices.Equal(got, []string{"fair-preflight"}) {
		t.Errorf("cluster roles: %v", got)
	}
	if ok, err := s.Add(map[string]any{"kind": "ConfigMap", "metadata": map[string]any{"name": "x", "namespace": "y"}}); ok || err != nil {
		t.Errorf("a ConfigMap was served: %v %v", ok, err)
	}
	if _, err := s.Add(map[string]any{"kind": "Service", "metadata": map[string]any{"name": "x"}}); err == nil {
		t.Error("a Service without a namespace was accepted")
	}
	// Same kind, namespace and name replaces.
	if _, err := s.Add(map[string]any{"kind": "Service", "metadata": map[string]any{"name": "iam", "namespace": "fair-platform", "labels": map[string]any{"v": "2"}}}); err != nil {
		t.Fatal(err)
	}
	if l := s.Objects(kube.Services); len(l) != 2 || l[0].Metadata.Labels["v"] != "2" {
		t.Errorf("replace: %+v", l)
	}
	s.Delete("Service", "elsewhere", "other")
	if got := names(t, s, kube.Services, ""); !slices.Equal(got, []string{"fair-platform/iam"}) {
		t.Errorf("after delete: %v", got)
	}
	if _, _, err := s.List(context.Background(), kube.Resource{Version: "v1", Plural: "secrets", Namespaced: true}, ""); !errors.Is(err, kube.ErrSecretsRefused) {
		t.Errorf("secrets: %v", err)
	}
	s.NotServed(kube.ExternalSecrets)
	if _, _, err := s.List(context.Background(), kube.ExternalSecrets, ""); !errors.Is(err, kube.ErrNotFound) {
		t.Errorf("not served: %v", err)
	}
	if l, _, err := s.List(context.Background(), kube.StorageClasses, ""); err != nil || len(l) != 0 {
		t.Errorf("an empty resource: %v %v", l, err)
	}
	if got := s.Namespaces(); !slices.Equal(got, []string{"fair-platform"}) {
		t.Errorf("namespaces %v", got)
	}
}

// Applied: hooks gone; each workload also a running pod of its template;
// claims of volume claim templates and of a CloudNativePG Cluster.
func TestApplied(t *testing.T) {
	docs, err := DecodeYAMLString(objs)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := Applied(docs)
	if err != nil {
		t.Fatal(err)
	}
	s := New()
	for _, d := range applied {
		if IsHook(d) {
			t.Errorf("hook %s applied", Key(d))
		}
		if _, err := s.Add(d); err != nil {
			t.Fatal(err)
		}
	}
	if got := names(t, s, kube.Pods, ""); !slices.Equal(got, []string{"fair-fips-probe/fips-probe-ref00", "fair-platform/iam-5f6d7c8b9-ref00", "fair-platform/nats-0"}) {
		t.Errorf("pods %v", got)
	}
	if got := names(t, s, kube.PersistentVolumeClaims, ""); !slices.Equal(got, []string{"fair-data/fair-db-1", "fair-platform/data-nats-0"}) {
		t.Errorf("claims %v", got)
	}
	if got := names(t, s, kube.ClusterRoles, ""); len(got) != 0 {
		t.Errorf("the hook's ClusterRole: %v", got)
	}
	if got := names(t, s, kube.Deployments, ""); !slices.Equal(got, []string{"fair-platform/iam"}) {
		t.Errorf("deployments %v", got)
	}
	l, _, _ := s.List(context.Background(), kube.Pods, "fair-platform")
	for _, p := range l {
		if p.Metadata.Name != "iam-5f6d7c8b9-ref00" {
			continue
		}
		raw := string(p.Raw)
		for _, want := range []string{`"pod-template-hash":"5f6d7c8b9"`, `"kind":"ReplicaSet"`, `"initContainerStatuses"`, `"imageID":"r/fair-iam@sha256:1"`} {
			if !strings.Contains(raw, want) {
				t.Errorf("iam pod lacks %s: %s", want, raw)
			}
		}
	}
	if _, err := Applied([]map[string]any{{"kind": "Deployment", "metadata": map[string]any{"name": "x", "namespace": "y"}}}); err == nil {
		t.Error("a Deployment without a template was applied")
	}
}

// Overlay: the top set replaces and adds to the base's objects; an API the
// base does not serve comes from the top; Secrets stay refused.
func TestOverlay(t *testing.T) {
	base := New()
	base.NotServed(kube.ValidatingAdmissionPolicies)
	_, _ = base.Add(map[string]any{"kind": "Namespace", "metadata": map[string]any{"name": "kube-system"}})
	_, _ = base.Add(map[string]any{"kind": "Namespace", "metadata": map[string]any{"name": "fair-platform", "labels": map[string]any{"old": "1"}}})
	top := New()
	_, _ = top.Add(map[string]any{"kind": "Namespace", "metadata": map[string]any{"name": "fair-platform", "labels": map[string]any{"new": "1"}}})
	_, _ = top.Add(map[string]any{"kind": "Namespace", "metadata": map[string]any{"name": "fair-data"}})
	_, _ = top.Add(map[string]any{"kind": "ValidatingAdmissionPolicy", "metadata": map[string]any{"name": "p"}})
	o := Overlay(base, top)
	if got := names(t, o, kube.Namespaces, ""); !slices.Equal(got, []string{"fair-data", "fair-platform", "kube-system"}) {
		t.Errorf("namespaces %v", got)
	}
	l, _, _ := o.List(context.Background(), kube.Namespaces, "")
	for _, n := range l {
		if n.Metadata.Name == "fair-platform" && (n.Metadata.Labels["new"] != "1" || n.Metadata.Labels["old"] != "") {
			t.Errorf("fair-platform not replaced: %+v", n.Metadata)
		}
	}
	if got := names(t, o, kube.ValidatingAdmissionPolicies, ""); !slices.Equal(got, []string{"p"}) {
		t.Errorf("policies %v", got)
	}
	if _, _, err := o.List(context.Background(), kube.ExternalSecrets, ""); err != nil {
		t.Errorf("both serve external secrets (none): %v", err)
	}
	base.NotServed(kube.ExternalSecrets)
	if _, _, err := o.List(context.Background(), kube.ExternalSecrets, ""); !errors.Is(err, kube.ErrNotFound) {
		t.Errorf("neither has external secrets: %v", err)
	}
	if _, _, err := o.List(context.Background(), kube.Resource{Version: "v1", Plural: "secrets", Namespaced: true}, ""); !errors.Is(err, kube.ErrSecretsRefused) {
		t.Errorf("secrets: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := o.Watch(ctx, kube.Pods, "", "", nil); err != nil {
		t.Errorf("watch: %v", err)
	}
}
