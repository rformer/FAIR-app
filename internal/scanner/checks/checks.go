// Package checks is the deployment check catalog (F-015 T-28; AC-41,
// AC-42; design §6.8). Each check reads the cluster through the scanner's
// read-only Reader and returns findings with a severity, the affected
// 800-53r5 controls and remediation guidance. A check that cannot read what
// it needs returns an error, which the scanner reports as such (never as
// "passed").
package checks

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/rformer/fair-app/internal/releasemanifest"
	"github.com/rformer/fair-app/internal/scanner"
	"github.com/rformer/fair-app/internal/scanner/kube"
)

// Labels and annotations the installer (F-014) or fips-probe (T-29) set to
// attest what the API cannot show.
const (
	// LabelFIPS on a node: "attested" when the installer or customer
	// declares FIPS mode (exports say "attested, not verified"). Only a Ready
	// fips-probe pod on the node verifies it (T-29).
	LabelFIPS = "fair-platform.io/fips"
	// AnnotationEncrypted on a StorageClass: "true" when the installer
	// attests encryption at rest the parameters do not show (e.g. LUKS).
	AnnotationEncrypted = "fair-platform.io/encrypted-at-rest"
	// AnnotationVerifiesSignatures on a ValidatingAdmissionPolicy or
	// ValidatingWebhookConfiguration: "true" when it verifies image
	// signatures.
	AnnotationVerifiesSignatures = "fair-platform.io/verifies-image-signatures"
)

// Config is what the checks need besides the cluster.
type Config struct {
	// PSADefault is the cluster-wide pod security admission level the
	// installer attests (RKE2 and others configure it in the API server's
	// admission configuration, which the scanner cannot read). "" = none.
	PSADefault string
	// IngressEndpoints are host:port addresses of the platform's ingress
	// (installer value), probed with the internal Services.
	IngressEndpoints []string
	// ReleaseManifest and ReleaseKey locate the signed release manifest
	// (releasemanifest.Load); the image and RBAC checks fail without it.
	ReleaseManifest string
	ReleaseKey      *ecdsa.PublicKey
	Dial            func(ctx context.Context, addr string) (net.Conn, error) // default: TCP, 5 s timeout
	Now             func() time.Time
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c Config) dial(ctx context.Context, addr string) (net.Conn, error) {
	if c.Dial != nil {
		return c.Dial(ctx, addr)
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}

func (c Config) release() (*releasemanifest.Manifest, error) {
	if c.ReleaseManifest == "" || c.ReleaseKey == nil {
		return nil, fmt.Errorf("no release manifest configured")
	}
	return releasemanifest.Load(c.ReleaseKey, c.ReleaseManifest)
}

// Meta describes a check for the catalog (and the OSCAL export, T-33).
type Meta struct {
	ID          string
	Title       string
	Controls    []string
	Remediation string
}

// check is a catalog entry: run returns findings; a check that also records
// how passing subjects were assessed sets result instead.
type check struct {
	Meta
	run    func(ctx context.Context, r scanner.Reader, s scanner.Scope) ([]scanner.Finding, error)
	result func(ctx context.Context, r scanner.Reader, s scanner.Scope) (scanner.Result, error)
}

func (c check) ID() string { return c.Meta.ID }
func (c check) Run(ctx context.Context, r scanner.Reader, s scanner.Scope) (scanner.Result, error) {
	if c.result != nil {
		return c.result(ctx, r, s)
	}
	fs, err := c.run(ctx, r, s)
	return scanner.Result{Findings: fs}, err
}

// observation builds an observation of this check.
func (c check) observation(subject, method string, detail map[string]any) scanner.Observation {
	b, _ := json.Marshal(detail)
	return scanner.Observation{CheckID: c.Meta.ID, Subject: subject, Method: method, DetailJSON: string(b)}
}

// finding builds a finding of this check.
func (c check) finding(severity, subject string, detail map[string]any, remediation string) scanner.Finding {
	if remediation == "" {
		remediation = c.Remediation
	}
	b, _ := json.Marshal(detail)
	return scanner.Finding{CheckID: c.Meta.ID, Severity: severity, Controls: c.Controls, Subject: subject,
		DetailJSON: string(b), Remediation: remediation}
}

// Catalog returns the ten checks of design §6.8.
func Catalog(cfg Config) []scanner.Check {
	var out []scanner.Check
	for _, c := range catalog(cfg) {
		out = append(out, c)
	}
	return out
}

// Metas lists the catalog's metadata.
func Metas() []Meta {
	var out []Meta
	for _, c := range catalog(Config{}) {
		out = append(out, c.Meta)
	}
	return out
}

func catalog(cfg Config) []check {
	return []check{
		podSecurityAdmission(cfg), networkPolicies(), tlsEndpoints(cfg), nodeFIPS(), imageDigests(cfg),
		signatureAdmission(), podHardening(), storageEncryption(), plaintextSecrets(), platformRBAC(cfg),
	}
}

// --- object decoding ---------------------------------------------------

func decode[T any](objs []kube.Object) ([]T, error) {
	out := make([]T, 0, len(objs))
	for _, o := range objs {
		var t T
		if err := json.Unmarshal(o.Raw, &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// listAll lists r in every platform namespace.
func listAll(ctx context.Context, r scanner.Reader, res kube.Resource, s scanner.Scope) ([]kube.Object, error) {
	var out []kube.Object
	for _, ns := range s.Namespaces {
		objs, _, err := r.List(ctx, res, ns)
		if err != nil {
			return nil, err
		}
		out = append(out, objs...)
	}
	return out, nil
}

type meta struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	Labels          map[string]string `json:"labels"`
	Annotations     map[string]string `json:"annotations"`
	OwnerReferences []struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"ownerReferences"`
}

type securityContext struct {
	RunAsNonRoot             *bool  `json:"runAsNonRoot"`
	RunAsUser                *int64 `json:"runAsUser"`
	ReadOnlyRootFilesystem   *bool  `json:"readOnlyRootFilesystem"`
	AllowPrivilegeEscalation *bool  `json:"allowPrivilegeEscalation"`
	Privileged               *bool  `json:"privileged"`
	Capabilities             *struct {
		Add  []string `json:"add"`
		Drop []string `json:"drop"`
	} `json:"capabilities"`
}

type envVar struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	ValueFrom *struct {
		SecretKeyRef *struct {
			Name string `json:"name"`
		} `json:"secretKeyRef"`
	} `json:"valueFrom"`
}

type container struct {
	Name            string           `json:"name"`
	Image           string           `json:"image"`
	Command         []string         `json:"command"`
	Args            []string         `json:"args"`
	Env             []envVar         `json:"env"`
	SecurityContext *securityContext `json:"securityContext"`
	EnvFrom         []struct {
		SecretRef *struct {
			Name string `json:"name"`
		} `json:"secretRef"`
	} `json:"envFrom"`
}

type pod struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		HostNetwork     bool             `json:"hostNetwork"`
		HostPID         bool             `json:"hostPID"`
		HostIPC         bool             `json:"hostIPC"`
		SecurityContext *securityContext `json:"securityContext"`
		Containers      []container      `json:"containers"`
		InitContainers  []container      `json:"initContainers"`
		Volumes         []struct {
			Name     string `json:"name"`
			HostPath *struct {
				Path string `json:"path"`
			} `json:"hostPath"`
			Secret *struct {
				SecretName string `json:"secretName"`
			} `json:"secret"`
			PersistentVolumeClaim *struct {
				ClaimName string `json:"claimName"`
			} `json:"persistentVolumeClaim"`
		} `json:"volumes"`
	} `json:"spec"`
	Status struct {
		ContainerStatuses     []containerStatus `json:"containerStatuses"`
		InitContainerStatuses []containerStatus `json:"initContainerStatuses"`
	} `json:"status"`
}

type containerStatus struct {
	Name    string `json:"name"`
	Image   string `json:"image"`
	ImageID string `json:"imageID"`
}

func (p pod) containers() []container {
	return append(append([]container(nil), p.Spec.InitContainers...), p.Spec.Containers...)
}

// workload names the controller a pod belongs to, so findings stay stable
// across pod restarts: "<namespace>/<kind>/<name>" (a ReplicaSet's
// Deployment by its pod-template-hash; a bare pod by its own name).
func (p pod) workload() string {
	ns := p.Metadata.Namespace
	for _, o := range p.Metadata.OwnerReferences {
		switch o.Kind {
		case "ReplicaSet":
			if h := p.Metadata.Labels["pod-template-hash"]; h != "" && strings.HasSuffix(o.Name, "-"+h) {
				return ns + "/Deployment/" + strings.TrimSuffix(o.Name, "-"+h)
			}
			return ns + "/ReplicaSet/" + o.Name
		case "Job":
			if i := strings.LastIndex(o.Name, "-"); i > 0 && p.Metadata.Labels["batch.kubernetes.io/cronjob-name"] != "" {
				return ns + "/CronJob/" + p.Metadata.Labels["batch.kubernetes.io/cronjob-name"]
			}
			return ns + "/Job/" + o.Name
		default:
			return ns + "/" + o.Kind + "/" + o.Name
		}
	}
	return ns + "/Pod/" + p.Metadata.Name
}

// workloadPods groups pods by workload, keeping one representative each
// (all replicas share the template) plus every pod's container statuses.
func workloadPods(ps []pod) (map[string]pod, []string) {
	m := map[string]pod{}
	for _, p := range ps {
		w := p.workload()
		if _, ok := m[w]; !ok {
			m[w] = p
		}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return m, keys
}

func pods(ctx context.Context, r scanner.Reader, s scanner.Scope) ([]pod, error) {
	objs, err := listAll(ctx, r, kube.Pods, s)
	if err != nil {
		return nil, err
	}
	return decode[pod](objs)
}

// labelSelector is a metav1.LabelSelector.
type labelSelector struct {
	MatchLabels      map[string]string `json:"matchLabels"`
	MatchExpressions []struct {
		Key      string   `json:"key"`
		Operator string   `json:"operator"`
		Values   []string `json:"values"`
	} `json:"matchExpressions"`
}

func (s labelSelector) empty() bool { return len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0 }

func (s labelSelector) matches(labels map[string]string) bool {
	for k, v := range s.MatchLabels {
		if labels[k] != v {
			return false
		}
	}
	for _, e := range s.MatchExpressions {
		v, has := labels[e.Key]
		in := false
		for _, x := range e.Values {
			in = in || x == v
		}
		switch e.Operator {
		case "In":
			if !has || !in {
				return false
			}
		case "NotIn":
			if has && in {
				return false
			}
		case "Exists":
			if !has {
				return false
			}
		case "DoesNotExist":
			if has {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
