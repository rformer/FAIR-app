// Package fleetctl promotes releases through the SaaS fleet (F-012 T-16,
// F-012-AC-20, AC-21; design §3.6). It reads the fleet repository (the
// layout of deploy/fleet), checks health and SLO gates through Sources, and
// writes every pin change as a reviewed change: one git branch per
// instance, never a push.
//
// The fleet repository describes:
//
//	rings/<name>.yaml           ring: <name>, order: <n>, soak: <duration>
//	instances/<id>/rollout.yaml the instance's ring, maintenance window,
//	                            health endpoints and (written here) its
//	                            previous release
//	instances/<id>/kustomization.yaml
//	                            the release pin: the OCIRepository
//	                            fair-release's spec.ref, tag and digest
package fleetctl

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // maintenance windows name IANA zones; the binary carries them

	"go.yaml.in/yaml/v3"
)

var (
	idRE     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	tagRE    = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$`)
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	clockRE  = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)
)

// Pin is a release as an instance pins it: the artifact's tag and digest.
// Flux pulls by digest when one is set (spec.ref.digest takes precedence),
// so a re-pushed tag cannot change what an instance runs.
type Pin struct {
	Tag    string `yaml:"tag" json:"tag"`
	Digest string `yaml:"digest,omitempty" json:"digest,omitempty"`
}

func (p Pin) String() string {
	if p.Digest == "" {
		return p.Tag
	}
	return p.Tag + "@" + p.Digest
}

// IsZero reports whether p is unset.
func (p Pin) IsZero() bool { return p.Tag == "" && p.Digest == "" }

// Check validates p; digest says whether a digest is required.
func (p Pin) Check(digest bool) error {
	if !tagRE.MatchString(p.Tag) {
		return fmt.Errorf("release %q is not vMAJOR.MINOR.PATCH", p.Tag)
	}
	if p.Digest != "" && !digestRE.MatchString(p.Digest) {
		return fmt.Errorf("digest %q is not sha256:<64 hex>", p.Digest)
	}
	if digest && p.Digest == "" {
		return fmt.Errorf("release %s has no digest", p.Tag)
	}
	return nil
}

// Ring is a step of the rollout.
type Ring struct {
	Name  string
	Order int
	Soak  time.Duration // how long each instance must stay healthy before the next ring
}

// Health says where an instance's health is read.
type Health struct {
	Kubernetes string   `yaml:"kubernetes_api" json:"kubernetes_api"` // the cluster's API server (Flux's objects)
	Readyz     []string `yaml:"readyz" json:"readyz"`                 // the instance's readiness URLs
}

// Instance is one instance of the fleet.
type Instance struct {
	ID             string
	Ring           string
	Window         Window
	Health         Health
	Pin            Pin // instances/<id>/kustomization.yaml
	Previous       Pin // the release before Pin (written by promote)
	RolledBackFrom Pin // the release rollback left (promote refuses it again)

	kustomization, rollout string // the files' text
}

// Fleet is the fleet repository's description of rings and instances.
type Fleet struct {
	Rings     []Ring     // by order
	Instances []Instance // by ID
}

// Tree reads the fleet repository: a directory or a git revision.
type Tree interface {
	ReadFile(name string) ([]byte, error)
	ReadDir(name string) ([]Entry, error)
}

// Entry is a directory entry of a Tree.
type Entry struct {
	Name string
	Dir  bool
}

type ringFile struct {
	Ring  string `yaml:"ring"`
	Order int    `yaml:"order"`
	Soak  string `yaml:"soak"`
}

type windowFile struct {
	Timezone string   `yaml:"timezone"`
	Days     []string `yaml:"days"`
	Start    string   `yaml:"start"`
	Duration string   `yaml:"duration"`
}

type rolloutFile struct {
	Ring           string     `yaml:"ring"`
	Window         windowFile `yaml:"maintenance_window"`
	Health         Health     `yaml:"health"`
	Previous       Pin        `yaml:"previous"`
	RolledBackFrom Pin        `yaml:"rolled_back_from"`
}

// Load reads the fleet from t and checks it whole.
func Load(t Tree) (*Fleet, error) {
	f := &Fleet{}
	var errs []error
	rings, err := t.ReadDir("rings")
	if err != nil {
		return nil, fmt.Errorf("fleet: rings: %w", err)
	}
	names, orders := map[string]bool{}, map[int]string{}
	for _, e := range rings {
		if e.Dir || !strings.HasSuffix(e.Name, ".yaml") {
			continue
		}
		b, err := t.ReadFile(path.Join("rings", e.Name))
		if err != nil {
			return nil, err
		}
		var rf ringFile
		if err := strictYAML(b, &rf); err != nil {
			errs = append(errs, fmt.Errorf("rings/%s: %w", e.Name, err))
			continue
		}
		soak, err := time.ParseDuration(rf.Soak)
		switch {
		case !idRE.MatchString(rf.Ring) || rf.Ring+".yaml" != e.Name:
			errs = append(errs, fmt.Errorf("rings/%s: ring %q must be the file's name", e.Name, rf.Ring))
		case rf.Order < 1:
			errs = append(errs, fmt.Errorf("rings/%s: order must be 1 or more", e.Name))
		case orders[rf.Order] != "":
			errs = append(errs, fmt.Errorf("rings/%s: order %d is also %s's", e.Name, rf.Order, orders[rf.Order]))
		case err != nil || soak < 0:
			errs = append(errs, fmt.Errorf("rings/%s: soak %q is not a duration", e.Name, rf.Soak))
		default:
			names[rf.Ring], orders[rf.Order] = true, rf.Ring
			f.Rings = append(f.Rings, Ring{Name: rf.Ring, Order: rf.Order, Soak: soak})
		}
	}
	if len(f.Rings) == 0 && len(errs) == 0 {
		errs = append(errs, errors.New("rings: no ring"))
	}
	sort.Slice(f.Rings, func(i, j int) bool { return f.Rings[i].Order < f.Rings[j].Order })

	dirs, err := t.ReadDir("instances")
	if err != nil {
		return nil, fmt.Errorf("fleet: instances: %w", err)
	}
	for _, e := range dirs {
		if !e.Dir {
			continue
		}
		in, err := loadInstance(t, e.Name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !names[in.Ring] {
			errs = append(errs, fmt.Errorf("instances/%s: ring %q is not in rings/", in.ID, in.Ring))
			continue
		}
		f.Instances = append(f.Instances, in)
	}
	sort.Slice(f.Instances, func(i, j int) bool { return f.Instances[i].ID < f.Instances[j].ID })
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("fleet: %w", err)
	}
	return f, nil
}

func loadInstance(t Tree, id string) (Instance, error) {
	in := Instance{ID: id}
	if !idRE.MatchString(id) {
		return in, fmt.Errorf("instances/%s: not an instance id", id)
	}
	k, err := t.ReadFile(path.Join("instances", id, "kustomization.yaml"))
	if err != nil {
		return in, fmt.Errorf("instances/%s: %w", id, err)
	}
	r, err := t.ReadFile(path.Join("instances", id, "rollout.yaml"))
	if err != nil {
		return in, fmt.Errorf("instances/%s: %w", id, err)
	}
	in.kustomization, in.rollout = string(k), string(r)
	if in.Pin, err = ReadPin(k); err != nil {
		return in, fmt.Errorf("instances/%s/kustomization.yaml: %w", id, err)
	}
	var rf rolloutFile
	if err := strictYAML(r, &rf); err != nil {
		return in, fmt.Errorf("instances/%s/rollout.yaml: %w", id, err)
	}
	in.Ring, in.Health, in.Previous, in.RolledBackFrom = rf.Ring, rf.Health, rf.Previous, rf.RolledBackFrom
	if in.Window, err = parseWindow(rf.Window); err != nil {
		return in, fmt.Errorf("instances/%s/rollout.yaml: maintenance_window: %w", id, err)
	}
	if !strings.HasPrefix(in.Health.Kubernetes, "https://") {
		return in, fmt.Errorf("instances/%s/rollout.yaml: health.kubernetes_api must be an https URL", id)
	}
	if len(in.Health.Readyz) == 0 {
		return in, fmt.Errorf("instances/%s/rollout.yaml: health.readyz names no URL", id)
	}
	for _, u := range in.Health.Readyz {
		if !strings.HasPrefix(u, "https://") {
			return in, fmt.Errorf("instances/%s/rollout.yaml: readyz %q must be an https URL", id, u)
		}
	}
	for what, p := range map[string]Pin{"previous": in.Previous, "rolled_back_from": in.RolledBackFrom} {
		if !p.IsZero() {
			if err := p.Check(false); err != nil {
				return in, fmt.Errorf("instances/%s/rollout.yaml: %s: %w", id, what, err)
			}
		}
	}
	return in, nil
}

func strictYAML(b []byte, v any) error {
	d := yaml.NewDecoder(strings.NewReader(string(b)))
	d.KnownFields(true)
	return d.Decode(v)
}

// Ring returns the named ring.
func (f *Fleet) Ring(name string) (Ring, bool) {
	for _, r := range f.Rings {
		if r.Name == name {
			return r, true
		}
	}
	return Ring{}, false
}

// Instance returns the instance with id.
func (f *Fleet) Instance(id string) (Instance, bool) {
	for _, in := range f.Instances {
		if in.ID == id {
			return in, true
		}
	}
	return Instance{}, false
}

// InRing returns the ring's instances, by ID.
func (f *Fleet) InRing(name string) []Instance {
	var out []Instance
	for _, in := range f.Instances {
		if in.Ring == name {
			out = append(out, in)
		}
	}
	return out
}

// before returns the closest earlier ring that has instances.
func (f *Fleet) before(name string) (Ring, bool) {
	var prev Ring
	found := false
	for _, r := range f.Rings {
		if r.Name == name {
			return prev, found
		}
		if len(f.InRing(r.Name)) > 0 {
			prev, found = r, true
		}
	}
	return Ring{}, false
}

// Window is a weekly maintenance window in the customer's time zone.
type Window struct {
	Location *time.Location
	Days     map[time.Weekday]bool
	Start    time.Duration // after local midnight
	Length   time.Duration
}

var weekdays = map[string]time.Weekday{"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday,
	"wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday}

func parseWindow(w windowFile) (Window, error) {
	var out Window
	loc, err := time.LoadLocation(w.Timezone)
	if err != nil || w.Timezone == "" || w.Timezone == "Local" {
		return out, fmt.Errorf("timezone %q is not an IANA zone", w.Timezone)
	}
	out.Location, out.Days = loc, map[time.Weekday]bool{}
	if len(w.Days) == 0 {
		return out, errors.New("no days")
	}
	for _, d := range w.Days {
		wd, ok := weekdays[d]
		if !ok {
			return out, fmt.Errorf("day %q is not one of sun, mon, … sat", d)
		}
		out.Days[wd] = true
	}
	m := clockRE.FindStringSubmatch(w.Start)
	if m == nil {
		return out, fmt.Errorf("start %q is not HH:MM", w.Start)
	}
	h, _ := strconv.Atoi(m[1])
	mi, _ := strconv.Atoi(m[2])
	out.Start = time.Duration(h)*time.Hour + time.Duration(mi)*time.Minute
	if out.Length, err = time.ParseDuration(w.Duration); err != nil || out.Length <= 0 || out.Length > 24*time.Hour {
		return out, fmt.Errorf("duration %q must be more than 0 and at most 24h", w.Duration)
	}
	return out, nil
}

// Next returns the window open at t, or else the next one to open: its
// start and end. Open reports whether t is inside it.
func (w Window) Next(t time.Time) (start, end time.Time, open bool) {
	lt := t.In(w.Location)
	y, m, d := lt.Date()
	for off := -1; off <= 8; off++ {
		day := time.Date(y, m, d+off, 0, 0, 0, 0, w.Location)
		if !w.Days[day.Weekday()] {
			continue
		}
		s := time.Date(day.Year(), day.Month(), day.Day(), int(w.Start/time.Hour), int(w.Start%time.Hour/time.Minute), 0, 0, w.Location)
		e := s.Add(w.Length)
		if !t.Before(e) {
			continue
		}
		if !t.Before(s) {
			return s, e, true
		}
		if start.IsZero() || s.Before(start) {
			start, end = s, e
		}
	}
	return start, end, false
}

// Version compares release tags by semantic-version precedence: -1, 0, 1.
func Version(a, b string) (int, error) {
	pa, err := parseVersion(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseVersion(b)
	if err != nil {
		return 0, err
	}
	for i := range 3 {
		if pa.n[i] != pb.n[i] {
			return cmpInt(pa.n[i], pb.n[i]), nil
		}
	}
	switch {
	case pa.pre == pb.pre:
		return 0, nil
	case pa.pre == "":
		return 1, nil
	case pb.pre == "":
		return -1, nil
	}
	as, bs := strings.Split(pa.pre, "."), strings.Split(pb.pre, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] == bs[i] {
			continue
		}
		ai, aerr := strconv.Atoi(as[i])
		bi, berr := strconv.Atoi(bs[i])
		switch {
		case aerr == nil && berr == nil:
			return cmpInt(ai, bi), nil
		case aerr == nil:
			return -1, nil
		case berr == nil:
			return 1, nil
		default:
			return strings.Compare(as[i], bs[i]), nil
		}
	}
	return cmpInt(len(as), len(bs)), nil
}

type version struct {
	n   [3]int
	pre string
}

func parseVersion(tag string) (version, error) {
	m := tagRE.FindStringSubmatch(tag)
	if m == nil {
		return version{}, fmt.Errorf("release %q is not vMAJOR.MINOR.PATCH", tag)
	}
	var v version
	for i := range 3 {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return version{}, fmt.Errorf("release %q: %w", tag, err)
		}
		v.n[i] = n
	}
	v.pre = strings.TrimPrefix(m[4], "-")
	return v, nil
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
