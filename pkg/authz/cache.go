package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Snapshot is a user's effective grants at one scope version: for each
// permission, the BUs where it applies (design §3 effective-access rule).
type Snapshot struct {
	Version int64
	Grants  map[Permission]map[string]struct{}
}

func (s Snapshot) allows(perm Permission, buID string) bool {
	_, ok := s.Grants[perm][buID]
	return ok
}

// Loader fetches the snapshot for a principal. It must return Version 0 and
// no grants when the principal's context is invalid or stale.
type Loader func(ctx context.Context, p Principal) (Snapshot, error)

// CacheOptions configures a Cache.
type CacheOptions struct {
	Loader     Loader
	MaxAge     time.Duration // default 60 s: bounds staleness if an event is missed
	MaxEntries int           // default 10,000 users
	Now        func() time.Time
	// ReauthMaxAge returns the effective bu.reauth_max_age for a BU
	// (settings.Client.ReauthMaxAge; F-015 T-24). When set, Check requires
	// the principal's AuthTime to be at most that old. An error denies.
	// Nil disables the step-up check.
	ReauthMaxAge func(buID string) (time.Duration, error)
}

type entry struct {
	snap     Snapshot
	loadedAt time.Time
}

type call struct {
	done chan struct{}
	snap Snapshot
	err  error
}

// Cache answers Check from in-process grant snapshots keyed by user and scope
// version (design §5.2). iam.scope.changed events (HandleScopeChanged) evict
// a user's snapshot and record their latest version, so a principal carrying
// an older version gets ErrStaleScope.
type Cache struct {
	o        CacheOptions
	mu       sync.Mutex
	entries  map[string]entry
	latest   map[string]int64
	inflight map[string]*call
}

// NewCache returns a Cache with defaults applied.
func NewCache(o CacheOptions) *Cache {
	if o.MaxAge <= 0 {
		o.MaxAge = 60 * time.Second
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = 10_000
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Cache{o: o, entries: map[string]entry{}, latest: map[string]int64{}, inflight: map[string]*call{}}
}

// Check implements Checker. It returns nil, ErrDenied, ErrStaleScope, a
// *StepUpError, or a loader or settings error; any error must be treated as
// a denial. The step-up check runs only once the permission is granted, so
// a stale sign-in never reveals that an out-of-scope BU exists (AC-25).
func (c *Cache) Check(ctx context.Context, p Principal, perm Permission, buID string) error {
	if p.UserID == "" || p.ServiceAcct {
		return ErrDenied // service accounts arrive with T-33
	}
	snap, err := c.snapshot(ctx, p)
	if err != nil {
		return err
	}
	if snap.Version != p.ScopeVersion || !snap.allows(perm, buID) {
		return ErrDenied
	}
	return c.stepUp(p, buID)
}

// stepUp returns a *StepUpError when p authenticated longer ago than the
// BU's effective bu.reauth_max_age (15 minutes under the Restricted BU
// overlay).
func (c *Cache) stepUp(p Principal, buID string) error {
	if c.o.ReauthMaxAge == nil {
		return nil
	}
	maxAge, err := c.o.ReauthMaxAge(buID)
	if err != nil {
		return fmt.Errorf("authz: re-authentication policy for BU %s: %w", buID, err)
	}
	if p.AuthTime.IsZero() || c.o.Now().Sub(p.AuthTime) > maxAge {
		return &StepUpError{MaxAge: maxAge}
	}
	return nil
}

// BUsWith returns the BUs where p holds perm, from the same snapshot Check
// uses (for filtering lists, such as BU overrides, to what p may see).
func (c *Cache) BUsWith(ctx context.Context, p Principal, perm Permission) (map[string]struct{}, error) {
	if p.UserID == "" || p.ServiceAcct {
		return nil, ErrDenied
	}
	snap, err := c.snapshot(ctx, p)
	if err != nil {
		return nil, err
	}
	if snap.Version != p.ScopeVersion {
		return nil, ErrDenied
	}
	out := map[string]struct{}{}
	for bu := range snap.Grants[perm] {
		out[bu] = struct{}{}
	}
	return out, nil
}

func (c *Cache) snapshot(ctx context.Context, p Principal) (Snapshot, error) {
	now := c.o.Now()
	c.mu.Lock()
	if v, ok := c.latest[p.UserID]; ok && p.ScopeVersion < v {
		c.mu.Unlock()
		return Snapshot{}, ErrStaleScope
	}
	if e, ok := c.entries[p.UserID]; ok && e.snap.Version == p.ScopeVersion && now.Sub(e.loadedAt) < c.o.MaxAge {
		c.mu.Unlock()
		return e.snap, nil
	}
	key := fmt.Sprintf("%s/%d", p.UserID, p.ScopeVersion)
	if cl, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		select {
		case <-cl.done:
			return cl.snap, cl.err
		case <-ctx.Done():
			return Snapshot{}, ctx.Err()
		}
	}
	cl := &call{done: make(chan struct{})}
	c.inflight[key] = cl
	c.mu.Unlock()

	cl.snap, cl.err = c.o.Loader(ctx, p)

	c.mu.Lock()
	delete(c.inflight, key)
	// Cache only a snapshot for the version asked about, and only if no
	// newer version was announced while it loaded.
	if cl.err == nil && cl.snap.Version == p.ScopeVersion && cl.snap.Version >= c.latest[p.UserID] {
		if len(c.entries) >= c.o.MaxEntries {
			for k := range c.entries { // evict an arbitrary entry
				delete(c.entries, k)
				break
			}
		}
		c.entries[p.UserID] = entry{snap: cl.snap, loadedAt: now}
	}
	c.mu.Unlock()
	close(cl.done)
	return cl.snap, cl.err
}

// Invalidate records that userID's scope changed to version and drops their
// snapshot. revoked means the user no longer has a scope at all.
func (c *Cache) Invalidate(userID string, version int64, revoked bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, userID)
	if !revoked && version > c.latest[userID] {
		c.latest[userID] = version
	}
}

// HandleScopeChanged applies an iam.scope.changed message (published by the
// scope worker, T-08).
func (c *Cache) HandleScopeChanged(data []byte) error {
	var ev struct {
		UserID       string `json:"user_id"`
		ScopeVersion int64  `json:"scope_version"`
		Revoked      bool   `json:"revoked"`
	}
	if err := json.Unmarshal(data, &ev); err != nil {
		return fmt.Errorf("authz: scope event: %w", err)
	}
	if ev.UserID == "" {
		return fmt.Errorf("authz: scope event without user_id")
	}
	c.Invalidate(ev.UserID, ev.ScopeVersion, ev.Revoked)
	return nil
}
