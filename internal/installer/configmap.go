package installer

import (
	"context"
	"fmt"
)

// The step ConfigMap (design §3.4): its name, namespace and labels. It
// holds each step's name and state, never a value; anyone who can read the
// namespace sees how far an install got.
const (
	StepConfigMap    = "fair-install"
	StepNamespace    = "fair-platform"
	ManagedByLabel   = "app.kubernetes.io/managed-by"
	ManagedByFairctl = "fairctl"
)

// ConfigMaps reads and writes ConfigMaps. fairctl's implementation (T-18)
// writes through the Helm SDK's Kubernetes client, as every write to the
// cluster does; the read-only kube client never writes. Tests use a fake.
type ConfigMaps interface {
	// GetConfigMap returns the ConfigMap's data, or found false.
	GetConfigMap(ctx context.Context, namespace, name string) (data map[string]string, found bool, err error)
	// ApplyConfigMap creates or replaces the ConfigMap.
	ApplyConfigMap(ctx context.Context, namespace, name string, labels, data map[string]string) error
}

// ConfigMapData is the step ConfigMap's data for p: one key per step, its
// state as the value.
func ConfigMapData(p Progress) map[string]string {
	d := make(map[string]string, len(Steps()))
	for _, s := range Steps() {
		d[string(s)] = string(p.state(s))
	}
	return d
}

// ProgressFromConfigMap reads a step ConfigMap's data, refusing anything
// but step names and states.
func ProgressFromConfigMap(data map[string]string) (Progress, error) {
	p := NewProgress()
	for k, v := range data {
		if !validStep(Step(k)) || !validState(State(v)) {
			return nil, fmt.Errorf("installer: ConfigMap %s holds %q, not a step and its state", StepConfigMap, k)
		}
		p[Step(k)] = State(v)
	}
	return p, nil
}

// Recorder records step states in the install log, then in the step
// ConfigMap once the cluster is reachable (Cluster nil: the log only, for
// the steps that run before fairctl reaches the cluster).
type Recorder struct {
	Log      *Log
	Cluster  ConfigMaps
	Progress Progress
}

// NewRecorder returns a Recorder starting from p (NewProgress for a new
// install, the log's or the ConfigMap's for a resumed one).
func NewRecorder(log *Log, cluster ConfigMaps, p Progress) *Recorder {
	if p == nil {
		p = NewProgress()
	}
	return &Recorder{Log: log, Cluster: cluster, Progress: p}
}

// Set moves a step to state and records it: in the log first (local and
// synced), then in the ConfigMap.
func (r *Recorder) Set(ctx context.Context, step Step, state State) error {
	if err := r.Progress.Set(step, state); err != nil {
		return err
	}
	if r.Log != nil {
		if err := r.Log.Step(step, state); err != nil {
			return err
		}
	}
	return r.Sync(ctx)
}

// Sync writes the ConfigMap from the current progress.
func (r *Recorder) Sync(ctx context.Context) error {
	if r.Cluster == nil {
		return nil
	}
	labels := map[string]string{ManagedByLabel: ManagedByFairctl}
	if err := r.Cluster.ApplyConfigMap(ctx, StepNamespace, StepConfigMap, labels, ConfigMapData(r.Progress)); err != nil {
		return fmt.Errorf("installer: ConfigMap %s/%s: %w", StepNamespace, StepConfigMap, err)
	}
	return nil
}
