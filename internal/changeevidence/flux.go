package changeevidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// FluxEvent is one event Flux's notification-controller sent to the
// operations account's receiver (deploy/fleet/flux/notifications.yaml; the
// generic webhook payload, kept in the Object Lock evidence bucket).
// Metadata carries the source revision and the Alert's eventMetadata, which
// names the instance.
type FluxEvent struct {
	InvolvedObject struct {
		Kind      string `json:"kind"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"involvedObject"`
	Severity  string            `json:"severity"`
	Timestamp time.Time         `json:"timestamp"`
	Message   string            `json:"message"`
	Reason    string            `json:"reason"`
	Metadata  map[string]string `json:"metadata"`

	order int // the read order, to keep equal times stable
}

// Instance is the instance the event came from.
func (e FluxEvent) Instance() string { return e.Metadata["instance"] }

// Revision is the revision the event is about.
func (e FluxEvent) Revision() string { return e.Metadata["revision"] }

// The objects deploy/fleet/flux names.
const (
	// ReleaseSource is the OCIRepository of the signed release artifact.
	ReleaseSource = "fair-release"
	// PlatformStep is the Kustomization whose success means the release's
	// services run (it depends on every earlier step).
	PlatformStep = "fair-platform"
	// FleetSource is the fleet repository's source and root Kustomization.
	FleetSource = "flux-system"
)

// LoadFluxEvents reads every .json and .jsonl file under dir (one or more
// JSON events per file), as copied from the evidence bucket. An event
// without an instance or a time is refused: it cannot be evidence.
func LoadFluxEvents(dir string) ([]FluxEvent, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(p, ".json") || strings.HasSuffix(p, ".jsonl")) {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []FluxEvent
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- the operator's copy of the evidence bucket
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		for i := 1; ; i++ {
			var e FluxEvent
			if err := dec.Decode(&e); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				return nil, fmt.Errorf("changeevidence: %s: event %d: %w", f, i, err)
			}
			if e.Instance() == "" || e.Timestamp.IsZero() || e.InvolvedObject.Kind == "" || e.InvolvedObject.Name == "" {
				return nil, fmt.Errorf("changeevidence: %s: event %d has no instance, time or object", f, i)
			}
			e.order = len(out)
			out = append(out, e)
		}
	}
	return out, nil
}

var (
	releaseRevision = regexp.MustCompile(`^([^@\s]+)@(sha256:[0-9a-f]{64})$`)
	fleetRevision   = regexp.MustCompile(`^[^@\s]+@sha1:([0-9a-f]{40})$`)
)

// deployments derives each instance's rollouts from its events: a rollout
// of release R starts with the first event about R after the instance last
// ran something else, and succeeds when fair-platform reconciles R.
// Events before from only set the starting state; rollouts that start at
// or after to are left out.
func deployments(events []FluxEvent, from, to time.Time) ([]Deployment, []Finding) {
	byInstance := map[string][]FluxEvent{}
	for _, e := range events {
		byInstance[e.Instance()] = append(byInstance[e.Instance()], e)
	}
	names := make([]string, 0, len(byInstance))
	for n := range byInstance {
		names = append(names, n)
	}
	sort.Strings(names)
	var ds []Deployment
	var fs []Finding
	for _, inst := range names {
		evs := byInstance[inst]
		sort.SliceStable(evs, func(a, b int) bool {
			if !evs[a].Timestamp.Equal(evs[b].Timestamp) {
				return evs[a].Timestamp.Before(evs[b].Timestamp)
			}
			return evs[a].order < evs[b].order
		})
		running := "" // the release revision fair-platform last reconciled
		fleet := ""   // the fleet commit last applied
		var cur *Deployment
		refused := map[string]bool{}
		flush := func() {
			if cur == nil {
				return
			}
			if cur.Status == "" {
				cur.Status = "incomplete"
				if cur.Errors > 0 {
					cur.Status = "failed"
				}
			}
			ds = append(ds, *cur)
			cur = nil
		}
		for _, e := range evs {
			if !e.Timestamp.Before(to) {
				break // after the period
			}
			in := !e.Timestamp.Before(from)
			obj := e.InvolvedObject
			if obj.Name == FleetSource && (obj.Kind == "GitRepository" || obj.Kind == "Kustomization") {
				if m := fleetRevision.FindStringSubmatch(e.Revision()); m != nil {
					fleet = m[1]
				}
				continue
			}
			if obj.Kind == "OCIRepository" && obj.Name == ReleaseSource && e.Severity == "error" {
				if in && !refused[e.Message] {
					refused[e.Message] = true
					fs = append(fs, Finding{Code: ReleaseSourceRefused, Subject: Subject("instance", inst), Instance: inst,
						Detail: ts(e.Timestamp) + ": " + e.Message})
				}
				continue
			}
			m := releaseRevision.FindStringSubmatch(e.Revision())
			if obj.Kind != "Kustomization" || m == nil {
				continue
			}
			rev := e.Revision()
			if rev == running {
				continue // what the instance already runs
			}
			if cur == nil || cur.Artifact != m[2] || cur.Release != m[1] {
				flush()
				cur = &Deployment{Instance: inst, Release: m[1], Artifact: m[2], StartedAt: ts(e.Timestamp), FleetCommit: fleet}
				if !in {
					cur.StartedAt = "" // started before the period: state only
				}
			}
			if e.Severity == "error" {
				cur.Errors++
			}
			if obj.Name == PlatformStep && e.Reason == "ReconciliationSucceeded" && e.Severity != "error" {
				cur.Status = "succeeded"
				cur.CompletedAt = ts(e.Timestamp)
				running = rev
				if cur.StartedAt == "" {
					cur = nil // a rollout before the period
				} else {
					flush()
				}
			}
		}
		if cur != nil && cur.StartedAt == "" {
			cur = nil
		}
		flush()
	}
	for i := range ds {
		ds[i].ID = ds[i].Instance + ":" + ds[i].Release + ":" + ds[i].StartedAt
	}
	return ds, fs
}
