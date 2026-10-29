package authz

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeLoader serves snapshots from a per-user table and counts loads.
type fakeLoader struct {
	mu    sync.Mutex
	snaps map[string]Snapshot
	loads atomic.Int32
	delay time.Duration
}

func (f *fakeLoader) load(_ context.Context, p Principal) (Snapshot, error) {
	f.loads.Add(1)
	time.Sleep(f.delay)
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.snaps[p.UserID]
	if !ok || s.Version != p.ScopeVersion {
		return Snapshot{}, nil // invalid or stale context: nothing
	}
	return s, nil
}

func (f *fakeLoader) set(user string, version int64, perm Permission, bus ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	set := map[string]struct{}{}
	for _, b := range bus {
		set[b] = struct{}{}
	}
	f.snaps[user] = Snapshot{Version: version, Grants: map[Permission]map[string]struct{}{perm: set}}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestCache() (*Cache, *fakeLoader, *clock) {
	f := &fakeLoader{snaps: map[string]Snapshot{}}
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	return NewCache(CacheOptions{Loader: f.load, Now: clk.now}), f, clk
}

func TestCheckAllowsAndDenies(t *testing.T) {
	c, f, _ := newTestCache()
	f.set("u1", 5, "analysis.edit", "bu-a", "bu-b")
	p := Principal{UserID: "u1", ScopeVersion: 5, DBToken: "t"}
	ctx := context.Background()

	if err := c.Check(ctx, p, "analysis.edit", "bu-a"); err != nil {
		t.Fatalf("granted check: %v", err)
	}
	for _, tc := range []struct {
		perm Permission
		bu   string
	}{{"analysis.edit", "bu-z"}, {"acceptance.approve", "bu-a"}} {
		if err := c.Check(ctx, p, tc.perm, tc.bu); !errors.Is(err, ErrDenied) {
			t.Errorf("%s at %s: %v, want ErrDenied", tc.perm, tc.bu, err)
		}
	}
	if n := f.loads.Load(); n != 1 {
		t.Fatalf("loads = %d, want 1 (snapshot cached)", n)
	}
	for name, q := range map[string]Principal{
		"no user":         {ScopeVersion: 5},
		"service account": {UserID: "u1", ScopeVersion: 5, ServiceAcct: true},
		"wrong version":   {UserID: "u1", ScopeVersion: 6},
	} {
		if err := c.Check(ctx, q, "analysis.edit", "bu-a"); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v, want ErrDenied", name, err)
		}
	}
}

func TestScopeChangedEvictsAndMarksStale(t *testing.T) {
	c, f, _ := newTestCache()
	ctx := context.Background()
	f.set("u1", 5, "analysis.edit", "bu-a")
	old := Principal{UserID: "u1", ScopeVersion: 5}
	if err := c.Check(ctx, old, "analysis.edit", "bu-a"); err != nil {
		t.Fatal(err)
	}

	// The grant is revoked: the worker publishes version 6.
	f.set("u1", 6, "analysis.edit")
	if err := c.HandleScopeChanged([]byte(`{"user_id":"u1","scope_version":6,"revoked":false}`)); err != nil {
		t.Fatal(err)
	}
	if err := c.Check(ctx, old, "analysis.edit", "bu-a"); !errors.Is(err, ErrStaleScope) {
		t.Fatalf("old principal after change: %v, want ErrStaleScope", err)
	}
	if err := c.Check(ctx, Principal{UserID: "u1", ScopeVersion: 6}, "analysis.edit", "bu-a"); !errors.Is(err, ErrDenied) {
		t.Fatalf("new principal after revocation: %v, want ErrDenied", err)
	}

	// A revoked scope (user disabled) just evicts.
	if err := c.HandleScopeChanged([]byte(`{"user_id":"u1","scope_version":-1,"revoked":true}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{`, `{"scope_version":1}`} {
		if err := c.HandleScopeChanged([]byte(bad)); err == nil {
			t.Errorf("accepted malformed event %s", bad)
		}
	}
}

// Without any event, a cached snapshot is reloaded after MaxAge (60 s): the
// bound on staleness when messages are lost.
func TestMaxAgeBoundsStaleness(t *testing.T) {
	c, f, clk := newTestCache()
	ctx := context.Background()
	f.set("u1", 5, "analysis.edit", "bu-a")
	p := Principal{UserID: "u1", ScopeVersion: 5}
	if err := c.Check(ctx, p, "analysis.edit", "bu-a"); err != nil {
		t.Fatal(err)
	}
	f.set("u1", 5, "analysis.edit") // changed behind the cache's back
	clk.t = clk.t.Add(59 * time.Second)
	if err := c.Check(ctx, p, "analysis.edit", "bu-a"); err != nil {
		t.Fatalf("within MaxAge the cached snapshot answers: %v", err)
	}
	clk.t = clk.t.Add(2 * time.Second)
	if err := c.Check(ctx, p, "analysis.edit", "bu-a"); !errors.Is(err, ErrDenied) {
		t.Fatalf("after MaxAge: %v, want ErrDenied from a fresh load", err)
	}
}

func TestConcurrentMissesLoadOnce(t *testing.T) {
	c, f, _ := newTestCache()
	f.delay = 50 * time.Millisecond
	f.set("u1", 5, "analysis.edit", "bu-a")
	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- c.Check(context.Background(), Principal{UserID: "u1", ScopeVersion: 5}, "analysis.edit", "bu-a")
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := f.loads.Load(); n != 1 {
		t.Fatalf("loads = %d, want 1", n)
	}
}

func TestLoaderErrorsDeny(t *testing.T) {
	boom := errors.New("db down")
	c := NewCache(CacheOptions{Loader: func(context.Context, Principal) (Snapshot, error) { return Snapshot{}, boom }})
	if err := c.Check(context.Background(), Principal{UserID: "u1", ScopeVersion: 1}, "x.y", "b"); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the loader error (callers treat any error as a denial)", err)
	}
}

func TestMaxEntriesBound(t *testing.T) {
	f := &fakeLoader{snaps: map[string]Snapshot{}}
	c := NewCache(CacheOptions{Loader: f.load, MaxEntries: 3})
	for i := range 10 {
		u := string(rune('a' + i))
		f.set(u, 1, "x.y", "b")
		_ = c.Check(context.Background(), Principal{UserID: u, ScopeVersion: 1}, "x.y", "b")
	}
	if n := len(c.entries); n > 3 {
		t.Fatalf("cache holds %d entries, bound is 3", n)
	}
}

func TestWithDBContextRequiresToken(t *testing.T) {
	if err := WithDBContext(context.Background(), nil, "", nil); !errors.Is(err, ErrNoDBContext) {
		t.Fatalf("err = %v, want ErrNoDBContext", err)
	}
}

// F-015 T-24: a granted check on a BU whose bu.reauth_max_age the sign-in
// exceeds needs step-up; a denial stays a denial; a policy error denies.
func TestCheckStepUp(t *testing.T) {
	f := &fakeLoader{snaps: map[string]Snapshot{}}
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	policyErr := errors.New("settings stale")
	maxAge := map[string]time.Duration{"restricted": 15 * time.Minute, "open": 12 * time.Hour}
	c := NewCache(CacheOptions{Loader: f.load, Now: clk.now, ReauthMaxAge: func(bu string) (time.Duration, error) {
		if bu == "broken" {
			return 0, policyErr
		}
		return maxAge[bu], nil
	}})
	f.set("u1", 1, "risk.view", "restricted", "open", "broken")
	ctx := context.Background()
	at := func(ago time.Duration) Principal {
		return Principal{UserID: "u1", ScopeVersion: 1, DBToken: "t", AuthTime: clk.t.Add(-ago)}
	}

	for _, tc := range []struct {
		name string
		p    Principal
		bu   string
		want error
	}{
		{"fresh sign-in, restricted", at(10 * time.Minute), "restricted", nil},
		{"exactly at the limit", at(15 * time.Minute), "restricted", nil},
		{"stale sign-in, restricted", at(16 * time.Minute), "restricted", ErrStepUpRequired},
		{"same sign-in, unrestricted", at(16 * time.Minute), "open", nil},
		{"older than the session lifetime", at(13 * time.Hour), "open", ErrStepUpRequired},
		{"unknown auth time", Principal{UserID: "u1", ScopeVersion: 1, DBToken: "t"}, "open", ErrStepUpRequired},
		{"no permission: denied, not step-up", at(16 * time.Minute), "other", ErrDenied},
		{"policy unavailable", at(time.Minute), "broken", policyErr},
	} {
		err := c.Check(ctx, tc.p, "risk.view", tc.bu)
		if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
		if errors.Is(err, ErrDenied) && errors.Is(err, ErrStepUpRequired) {
			t.Errorf("%s: both denied and step-up", tc.name)
		}
	}
	var su *StepUpError
	if err := c.Check(ctx, at(time.Hour), "risk.view", "restricted"); !errors.As(err, &su) || su.MaxAge != 15*time.Minute {
		t.Fatalf("step-up error %v, want max age 15m", err)
	}
}

// F-001 T-20: a BU whose session.network_binding is reauthenticate refuses
// a session whose network changed (step-up, sign in again); other BUs and
// unchanged sessions pass; a policy error denies; a denial stays a denial.
func TestCheckNetworkBinding(t *testing.T) {
	f := &fakeLoader{snaps: map[string]Snapshot{}}
	policyErr := errors.New("settings stale")
	c := NewCache(CacheOptions{Loader: f.load, NetworkBinding: func(bu string) (string, error) {
		switch bu {
		case "strict":
			return "reauthenticate", nil
		case "broken":
			return "", policyErr
		}
		return "flag", nil
	}})
	f.set("u1", 1, "risk.view", "strict", "open", "broken")
	ctx := context.Background()
	moved := Principal{UserID: "u1", ScopeVersion: 1, DBToken: "t", NetworkChanged: true}
	home := Principal{UserID: "u1", ScopeVersion: 1, DBToken: "t"}
	for _, tc := range []struct {
		name string
		p    Principal
		bu   string
		want error
	}{
		{"moved, strict BU", moved, "strict", ErrStepUpRequired},
		{"moved, flagging BU", moved, "open", nil},
		{"home network, strict BU", home, "strict", nil},
		{"moved, policy unavailable", moved, "broken", policyErr},
		{"home network, policy unavailable: not consulted", home, "broken", nil},
		{"moved, no permission: denied", moved, "other", ErrDenied},
	} {
		err := c.Check(ctx, tc.p, "risk.view", tc.bu)
		if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	var su *StepUpError
	if err := c.Check(ctx, moved, "risk.view", "strict"); !errors.As(err, &su) || su.MaxAge != 0 {
		t.Fatalf("want a StepUpError with MaxAge 0 (sign in again), got %v", err)
	}
}
