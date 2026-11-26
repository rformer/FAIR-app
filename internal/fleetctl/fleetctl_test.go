package fleetctl

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

var (
	d0  = "sha256:" + strings.Repeat("0", 64)
	d1  = "sha256:" + strings.Repeat("1", 64)
	d2  = "sha256:" + strings.Repeat("2", 64)
	v01 = Pin{Tag: "v0.1.0", Digest: d1}
	v02 = Pin{Tag: "v0.2.0", Digest: d2}
	// Saturday 2026-11-28 08:00 UTC: 03:00 in New York (canary-1's window
	// is open), outside general's Sunday window.
	now = time.Date(2026, 11, 28, 8, 0, 0, 0, time.UTC)
)

// fake is a health source per instance; it records what was asked.
type fake struct {
	m     map[string]*health
	calls []string
	overs map[string]time.Duration
}

type health struct {
	flux      Flux
	fluxErr   error
	ready     error
	alerts    []string
	alertsErr error
}

func newFake() *fake { return &fake{m: map[string]*health{}, overs: map[string]time.Duration{}} }

// on makes id healthy on p since t.
func (f *fake) on(id string, p Pin, since time.Time) *health {
	steps := make([]Step, 0, len(fleetSteps)+len(releaseSteps))
	for _, n := range fleetSteps {
		steps = append(steps, Step{Name: n, Ready: true, Revision: "main@sha1:abc"})
	}
	for _, n := range releaseSteps {
		steps = append(steps, Step{Name: n, Ready: true, Revision: p.Tag + "@" + p.Digest})
	}
	h := &health{flux: Flux{Source: Step{Name: "fair-release", Ready: true, Revision: p.Tag + "@" + p.Digest}, Since: since, Steps: steps}}
	f.m[id] = h
	return h
}

func (f *fake) get(id string) *health {
	if h, ok := f.m[id]; ok {
		return h
	}
	return &health{fluxErr: errors.New("unreachable")}
}

func (f *fake) Flux(_ context.Context, in Instance) (Flux, error) {
	f.calls = append(f.calls, "flux "+in.ID)
	h := f.get(in.ID)
	return h.flux, h.fluxErr
}

func (f *fake) Ready(_ context.Context, in Instance) error {
	f.calls = append(f.calls, "ready "+in.ID)
	return f.get(in.ID).ready
}

func (f *fake) Alerts(_ context.Context, in Instance, over time.Duration) ([]string, error) {
	f.calls = append(f.calls, "alerts "+in.ID)
	f.overs[in.ID] = over
	h := f.get(in.ID)
	return h.alerts, h.alertsErr
}

func (f *fake) asked(id string) bool {
	for _, c := range f.calls {
		if strings.HasSuffix(c, " "+id) {
			return true
		}
	}
	return false
}

// fixture returns the fixture fleet's files.
func fixture(t *testing.T) fstest.MapFS {
	t.Helper()
	m := fstest.MapFS{}
	root := os.DirFS(filepath.Join("testdata", "fleet"))
	err := fs.WalkDir(root, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(root, p)
		if err != nil {
			return err
		}
		m[p] = &fstest.MapFile{Data: b}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func load(t *testing.T, m fstest.MapFS) *Fleet {
	t.Helper()
	f, err := Load(FSTree{FS: m})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// merge applies a plan's changes, as merging its pull requests would.
func merge(m fstest.MapFS, p Plan) {
	for _, c := range p.Changes {
		for n, b := range c.Files {
			m[n] = &fstest.MapFile{Data: b}
		}
	}
}

func stopGate(t *testing.T, err error, instance, gate string) {
	t.Helper()
	var se *StopError
	if !errors.As(err, &se) || se.Instance != instance || se.Gate != gate {
		t.Fatalf("err = %v, want a %s stop at %s", err, gate, instance)
	}
}

func TestLoadFixture(t *testing.T) {
	f := load(t, fixture(t))
	if len(f.Rings) != 3 || f.Rings[0].Name != "vendor" || f.Rings[1].Soak != 72*time.Hour || f.Rings[2].Name != "general" {
		t.Fatalf("rings = %+v", f.Rings)
	}
	if len(f.Instances) != 5 {
		t.Fatalf("instances = %d", len(f.Instances))
	}
	g2, _ := f.Instance("general-2")
	if g2.Pin != v01 || g2.Previous.Tag != "v0.0.9" || g2.Previous.Digest != d0 {
		t.Fatalf("general-2 = %+v", g2)
	}
}

// TestLoadDeployFleet: the templates in deploy/fleet are a valid fleet.
func TestLoadDeployFleet(t *testing.T) {
	f, err := Load(FSTree{FS: os.DirFS(filepath.Join("..", "..", "deploy", "fleet"))})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Rings) != 3 || f.Rings[0].Name != "vendor" || f.Rings[0].Soak != 24*time.Hour ||
		f.Rings[1].Name != "canary" || f.Rings[1].Soak != 72*time.Hour || f.Rings[2].Name != "general" {
		t.Errorf("rings = %+v (design §3.6: vendor 24 h, canary 72 h, then general)", f.Rings)
	}
	ex, ok := f.Instance("example")
	if !ok || ex.Pin.Check(true) != nil {
		t.Errorf("the example instance does not pin a release by tag and digest: %+v", ex.Pin)
	}
}

func TestLoadRefuses(t *testing.T) {
	cases := map[string]func(m fstest.MapFS){
		"unknown ring": func(m fstest.MapFS) {
			m["instances/general-1/rollout.yaml"].Data = []byte(strings.Replace(string(m["instances/general-1/rollout.yaml"].Data), "ring: general", "ring: nightly", 1))
		},
		"duplicate order": func(m fstest.MapFS) {
			m["rings/general.yaml"].Data = []byte("ring: general\norder: 2\nsoak: 0s\n")
		},
		"ring name not the file's": func(m fstest.MapFS) { m["rings/general.yaml"].Data = []byte("ring: other\norder: 3\nsoak: 0s\n") },
		"unknown field": func(m fstest.MapFS) {
			m["rings/general.yaml"].Data = []byte("ring: general\norder: 3\nsoak: 0s\nauto: true\n")
		},
		"bad zone": func(m fstest.MapFS) {
			m["instances/general-1/rollout.yaml"].Data = []byte(strings.Replace(string(m["instances/general-1/rollout.yaml"].Data), "timezone: UTC", "timezone: Mars/Olympus", 1))
		},
		"window too long": func(m fstest.MapFS) {
			m["instances/general-1/rollout.yaml"].Data = []byte(strings.Replace(string(m["instances/general-1/rollout.yaml"].Data), "duration: 2h", "duration: 25h", 1))
		},
		"http readyz": func(m fstest.MapFS) {
			m["instances/general-1/rollout.yaml"].Data = []byte(strings.Replace(string(m["instances/general-1/rollout.yaml"].Data), "https://general-1.fair", "http://general-1.fair", 1))
		},
		"no pin": func(m fstest.MapFS) {
			m["instances/general-1/kustomization.yaml"].Data = []byte("resources: [../../flux]\n")
		},
		"no rollout.yaml": func(m fstest.MapFS) { delete(m, "instances/general-1/rollout.yaml") },
		"latest is no pin": func(m fstest.MapFS) {
			m["instances/general-1/kustomization.yaml"].Data = []byte(strings.Replace(string(m["instances/general-1/kustomization.yaml"].Data), "tag: v0.1.0", "tag: latest", 1))
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			m := fixture(t)
			change(m)
			if _, err := Load(FSTree{FS: m}); err == nil {
				t.Fatal("loaded")
			}
		})
	}
}

func TestPin(t *testing.T) {
	old := "patches:\r\n  - target: { kind: OCIRepository, name: fair-release }\r\n    patch: |\r\n      - { op: replace, path: /spec/ref/tag, value: v0.1.0 }\r\n# end\r\n"
	p, err := ReadPin([]byte(old))
	if err != nil || p != (Pin{Tag: "v0.1.0"}) {
		t.Fatalf("T-15 form: %v %v", p, err)
	}
	out, err := WritePin([]byte(old), v02)
	if err != nil {
		t.Fatal(err)
	}
	want := "patches:\r\n  - target: { kind: OCIRepository, name: fair-release }\r\n    patch: |\r\n      - { op: replace, path: /spec/ref, value: { tag: v0.2.0, digest: \"" + d2 + "\" } }\r\n# end\r\n"
	if string(out) != want {
		t.Fatalf("rewritten:\n%q\nwant\n%q", out, want)
	}
	two := old + "  - target: { kind: OCIRepository, name: fair-release }\n    patch: |\n      - { op: replace, path: /spec/ref/tag, value: v0.1.1 }\n"
	if _, err := ReadPin([]byte(two)); err == nil {
		t.Error("two pins read")
	}
	if _, err := WritePin([]byte(two), v02); err == nil {
		t.Error("two pins rewritten")
	}
	semver := "patches:\n  - target: { kind: OCIRepository, name: fair-release }\n    patch: |\n      - { op: replace, path: /spec/ref/semver, value: \">=0.1.0\" }\n"
	if _, err := ReadPin([]byte(semver)); err == nil {
		t.Error("a semver range read as a pin")
	}
	if !v02.Matches("v0.2.0@"+d2) || !v02.Matches(d2) || v02.Matches("v0.2.0@"+d1) || v02.Matches("v0.2.1@"+d2) {
		t.Error("Matches")
	}
}

func TestSetRollout(t *testing.T) {
	in := "ring: general\nprevious: { tag: v0.0.9 }\nmaintenance_window: { timezone: UTC, days: [sun], start: \"03:00\", duration: 2h }\nhealth: { kubernetes_api: https://k, readyz: [https://r] }\n"
	out, err := setRollout(in, v01, Pin{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "previous:") != 1 || !strings.HasSuffix(out, "previous: { tag: v0.1.0, digest: \""+d1+"\" }\n") {
		t.Fatalf("out = %q", out)
	}
	block := strings.Replace(in, "previous: { tag: v0.0.9 }\n", "previous:\n  tag: v0.0.9\n", 1)
	if _, err := setRollout(block, v01, Pin{}); err == nil {
		t.Error("a block-style previous was rewritten")
	}
}

func TestWindow(t *testing.T) {
	f := load(t, fixture(t))
	c1, _ := f.Instance("canary-1") // sat 02:00-06:00 New York
	s, e, open := c1.Window.Next(now)
	if !open || !s.Equal(time.Date(2026, 11, 28, 7, 0, 0, 0, time.UTC)) || !e.Equal(time.Date(2026, 11, 28, 11, 0, 0, 0, time.UTC)) {
		t.Errorf("canary-1 at %s: %s %s %v", now, s, e, open)
	}
	s, _, open = c1.Window.Next(now.Add(4 * time.Hour))
	if open || !s.Equal(time.Date(2026, 12, 5, 7, 0, 0, 0, time.UTC)) {
		t.Errorf("canary-1 after its window: next %s %v", s, open)
	}
	// Daylight saving: 02:00 in New York is 06:00 UTC in summer.
	s, _, _ = c1.Window.Next(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	if !s.Equal(time.Date(2026, 7, 4, 6, 0, 0, 0, time.UTC)) {
		t.Errorf("summer window %s", s)
	}
	// A window across midnight: Saturday 22:00 London for 6 h is open early on Sunday.
	c2, _ := f.Instance("canary-2")
	if _, _, open := c2.Window.Next(time.Date(2026, 11, 29, 2, 0, 0, 0, time.UTC)); !open {
		t.Error("canary-2 closed at Sunday 02:00 London")
	}
	if _, _, open := c2.Window.Next(time.Date(2026, 11, 30, 4, 30, 0, 0, time.UTC)); open {
		t.Error("canary-2 open Monday 04:30")
	}
}

func TestVersion(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"v0.2.0", "v0.1.9", 1}, {"v0.10.0", "v0.9.0", 1}, {"v1.0.0", "v1.0.0", 0},
		{"v1.0.0-rc.1", "v1.0.0", -1}, {"v1.0.0-rc.2", "v1.0.0-rc.10", -1}, {"v0.0.0-test", "v0.0.0-alpha", 1},
	} {
		if got, err := Version(c.a, c.b); err != nil || got != c.want {
			t.Errorf("Version(%s, %s) = %d %v, want %d", c.a, c.b, got, err, c.want)
		}
	}
	if _, err := Version("latest", "v0.1.0"); err == nil {
		t.Error("latest compared")
	}
}

// TestPromoteRings walks v0.2.0 through the fixture fleet: vendor first
// without gates, canary after vendor's 24 h soak, general after canary's
// 72 h.
func TestPromoteRings(t *testing.T) {
	ctx := context.Background()
	m := fixture(t)
	src := newFake()

	plan, err := load(t, m).Promote(ctx, src, now, v02, "")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Ring != "vendor" || len(plan.Gated) != 0 || len(plan.Changes) != 1 || len(src.calls) != 0 {
		t.Fatalf("first ring: %+v, calls %v", plan, src.calls)
	}
	c := plan.Changes[0]
	if c.Branch != "fleet/promote/v0.2.0/vendor-1" || len(c.Files) != 2 {
		t.Fatalf("change %+v", c)
	}
	if p, _ := ReadPin(c.Files["instances/vendor-1/kustomization.yaml"]); p != v02 {
		t.Errorf("pin %v", p)
	}
	for _, s := range []string{"Fleet-Instance: vendor-1", "Fleet-Release: v0.2.0@" + d2, "Fleet-Merge-After: 2026-11-28T00:00:00Z"} {
		if !strings.Contains(c.Message, s) {
			t.Errorf("message lacks %q:\n%s", s, c.Message)
		}
	}
	merge(m, plan)
	f := load(t, m)
	if v, _ := f.Instance("vendor-1"); v.Previous != v01 {
		t.Fatalf("previous = %v", v.Previous)
	}

	// Not yet soaked: 23 h on the release.
	src.on("vendor-1", v02, now.Add(-23*time.Hour))
	_, err = f.Promote(ctx, src, now, v02, "")
	stopGate(t, err, "vendor-1", "soak")

	// Soaked; canary's two instances get branches, each with its window.
	src.on("vendor-1", v02, now.Add(-25*time.Hour))
	plan, err = f.Promote(ctx, src, now, v02, "")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Ring != "canary" || len(plan.Changes) != 2 || plan.Gated[0] != "vendor-1" {
		t.Fatalf("canary plan %+v", plan)
	}
	if src.overs["vendor-1"] != 25*time.Hour {
		t.Errorf("SLO alerts read over %s, want the whole time on the release", src.overs["vendor-1"])
	}
	if !strings.Contains(plan.Changes[0].Message, "Fleet-Merge-After: 2026-11-28T07:00:00Z\nFleet-Merge-Before: 2026-11-28T11:00:00Z") {
		t.Errorf("canary-1's window:\n%s", plan.Changes[0].Message)
	}
	merge(m, plan)
	f = load(t, m)

	// Canary on the release for 72 h: general follows; general-2's
	// previous release becomes v0.1.0.
	src.on("canary-1", v02, now.Add(-73*time.Hour))
	src.on("canary-2", v02, now.Add(-80*time.Hour))
	plan, err = f.Promote(ctx, src, now, v02, "")
	if err != nil || plan.Ring != "general" || len(plan.Changes) != 2 {
		t.Fatalf("general plan %+v %v", plan, err)
	}
	merge(m, plan)
	f = load(t, m)
	if g, _ := f.Instance("general-2"); g.Pin != v02 || g.Previous != v01 {
		t.Errorf("general-2 = %v previous %v", g.Pin, g.Previous)
	}
	plan, err = f.Promote(ctx, src, now, v02, "")
	if err != nil || plan.Ring != "" {
		t.Errorf("after the last ring: %+v %v", plan, err)
	}
}

// TestPromoteStops: each gate stops the rollout at the first failing
// instance; later instances are not even read, and nothing is planned.
func TestPromoteStops(t *testing.T) {
	ctx := context.Background()
	m := fixture(t)
	for _, id := range []string{"vendor-1", "canary-1", "canary-2"} {
		in := load(t, m)
		i, _ := in.Instance(id)
		kz, err := WritePin([]byte(i.kustomization), v02)
		if err != nil {
			t.Fatal(err)
		}
		m["instances/"+id+"/kustomization.yaml"] = &fstest.MapFile{Data: kz}
	}
	f := load(t, m)
	cases := map[string]struct {
		gate string
		fail func(h *health)
	}{
		"migration failed": {"flux", func(h *health) { h.flux.Steps[5].Ready, h.flux.Steps[5].Message = false, "Job iam-migrate failed" }},
		"old revision":     {"flux", func(h *health) { h.flux.Steps[6].Revision = "v0.1.0@" + d1 }},
		"no source":        {"flux", func(h *health) { h.fluxErr = errors.New("403") }},
		"not ready":        {"readyz", func(h *health) { h.ready = errors.New("503") }},
		"slo alert":        {"slo", func(h *health) { h.alerts = []string{"ApiAvailabilityBudgetBurn (gateway)"} }},
		"no prometheus":    {"slo", func(h *health) { h.alertsErr = errors.New("unreachable") }},
		"not soaked":       {"soak", func(h *health) { h.flux.Since = now.Add(-71 * time.Hour) }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			src := newFake()
			src.on("vendor-1", v02, now.Add(-100*time.Hour))
			c.fail(src.on("canary-1", v02, now.Add(-100*time.Hour)))
			src.on("canary-2", v02, now.Add(-100*time.Hour))
			plan, err := f.Promote(ctx, src, now, v02, "general")
			stopGate(t, err, "canary-1", c.gate)
			if src.asked("canary-2") || len(plan.Changes) != 0 {
				t.Errorf("went on after canary-1: %v %+v", src.calls, plan)
			}
		})
	}

	// The earlier ring not yet promoted stops too.
	src := newFake()
	_, err := load(t, fixture(t)).Promote(ctx, src, now, v02, "canary")
	stopGate(t, err, "vendor-1", "pin")
}

func TestPromoteRefuses(t *testing.T) {
	ctx := context.Background()
	f := load(t, fixture(t))
	if _, err := f.Promote(ctx, newFake(), now, Pin{Tag: "v0.2.0"}, ""); err == nil {
		t.Error("a release without its digest promoted")
	}
	if _, err := f.Promote(ctx, newFake(), now, Pin{Tag: "v0.0.8", Digest: d2}, "vendor"); err == nil {
		t.Error("an older release promoted")
	}
	if _, err := f.Promote(ctx, newFake(), now, Pin{Tag: "v0.1.0", Digest: d2}, "vendor"); err == nil {
		t.Error("the same tag with another digest promoted")
	}
	if _, err := f.Promote(ctx, newFake(), now, v02, "nightly"); err == nil {
		t.Error("an unknown ring promoted")
	}
}

// TestRollback: the instance's previous release comes back, and promote
// refuses the release it left.
func TestRollback(t *testing.T) {
	m := fixture(t)
	plan, err := load(t, m).Rollback([]string{"general-2"}, "")
	if err != nil || len(plan.Changes) != 1 || plan.Changes[0].Branch != "fleet/rollback/v0.1.0/general-2" {
		t.Fatalf("%+v %v", plan, err)
	}
	merge(m, plan)
	f := load(t, m)
	g, _ := f.Instance("general-2")
	if g.Pin != (Pin{Tag: "v0.0.9", Digest: d0}) || !g.Previous.IsZero() || g.RolledBackFrom != v01 {
		t.Fatalf("after rollback: %+v", g)
	}
	src := newFake()
	src.on("canary-1", v01, now.Add(-100*time.Hour))
	src.on("canary-2", v01, now.Add(-100*time.Hour))
	_, err = f.Promote(context.Background(), src, now, v01, "general")
	stopGate(t, err, "general-2", "pin")

	// No previous release: nothing is planned, not even for the others.
	if _, err := load(t, fixture(t)).Rollback(nil, "general"); err == nil {
		t.Error("general-1 has no previous release, yet the ring rolled back")
	}
	if _, err := load(t, fixture(t)).Rollback([]string{"nope"}, ""); err == nil {
		t.Error("an unknown instance rolled back")
	}
}

func TestMergeCheck(t *testing.T) {
	ctx := context.Background()
	m := fixture(t)
	base := load(t, m)
	src := newFake()
	src.on("vendor-1", v02, now.Add(-30*time.Hour))
	// vendor-1 on v0.2.0 in base.
	plan, _ := base.Promote(ctx, src, now, v02, "vendor")
	merge(m, plan)
	baseMap := fstest.MapFS{}
	for k, v := range m {
		baseMap[k] = v
	}
	base = load(t, baseMap)
	plan, err := base.Promote(ctx, src, now, v02, "canary")
	if err != nil {
		t.Fatal(err)
	}

	// canary-1's branch: the window is open at now.
	head1 := fstest.MapFS{}
	for k, v := range baseMap {
		head1[k] = v
	}
	merge(head1, Plan{Changes: plan.Changes[:1]})
	if msg, err := MergeCheck(ctx, src, now, base, load(t, head1)); err != nil {
		t.Fatalf("canary-1: %v", err)
	} else if !strings.Contains(msg, "may merge now") {
		t.Error(msg)
	}
	// Outside the window, and with vendor-1 failing since promote.
	_, err = MergeCheck(ctx, src, now.Add(5*time.Hour), base, load(t, head1))
	stopGate(t, err, "canary-1", "window")
	src.m["vendor-1"].alerts = []string{"ServiceUnavailable"}
	_, err = MergeCheck(ctx, src, now, base, load(t, head1))
	stopGate(t, err, "vendor-1", "slo")

	// Both canary branches in one: refused.
	both := fstest.MapFS{}
	for k, v := range baseMap {
		both[k] = v
	}
	merge(both, plan)
	if _, err := MergeCheck(ctx, src, now, base, load(t, both)); err == nil {
		t.Error("two instances in one merge")
	}

	// A rollback merges at once, outside any window and with alerts firing.
	rb, err := base.Rollback([]string{"vendor-1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	headRB := fstest.MapFS{}
	for k, v := range baseMap {
		headRB[k] = v
	}
	merge(headRB, rb)
	if _, err := MergeCheck(ctx, src, now.Add(50*time.Hour), base, load(t, headRB)); err != nil {
		t.Errorf("rollback: %v", err)
	}
}

func TestStatus(t *testing.T) {
	src := newFake()
	src.on("vendor-1", v01, now.Add(-time.Hour))
	src.on("canary-1", v01, now.Add(-time.Hour)).ready = errors.New("https://canary-1.fair.example.test/readyz: 503")
	rows := load(t, fixture(t)).Status(context.Background(), src, now)
	if len(rows) != 5 {
		t.Fatalf("%d rows", len(rows))
	}
	by := map[string]InstanceStatus{}
	for _, r := range rows {
		by[r.Instance] = r
	}
	if r := by["vendor-1"]; !r.Healthy || r.Reconciled != "v0.1.0@"+d1 || r.Pinned != "v0.1.0@"+d1 {
		t.Errorf("vendor-1 %+v", r)
	}
	if r := by["canary-1"]; r.Healthy || !strings.HasPrefix(r.Problem, "readyz:") || !strings.HasPrefix(r.Window, "open until") {
		t.Errorf("canary-1 %+v", r)
	}
	if r := by["general-1"]; r.Healthy || !strings.HasPrefix(r.Problem, "flux:") || r.Window != "opens 2026-11-29T03:00:00Z" {
		t.Errorf("general-1 %+v", r)
	}
	if by["general-2"].Previous != "v0.0.9@"+d0 {
		t.Errorf("general-2 %+v", by["general-2"])
	}
}
