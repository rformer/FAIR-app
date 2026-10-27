package settings

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeSource is an in-memory posture state.
type fakeSource struct {
	mu        sync.Mutex
	snap      Snapshot
	err       error
	snapshots int // full loads
	polls     int // version polls
}

func (f *fakeSource) Snapshot(context.Context) (Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshots++
	return f.snap, f.err
}

func (f *fakeSource) Version(context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.polls++
	return f.snap.Version, f.err
}

func (f *fakeSource) set(version int64, key string, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	inst := map[string]json.RawMessage{}
	for k, v := range f.snap.Instance {
		inst[k] = v
	}
	inst[key] = json.RawMessage(value)
	f.snap.Instance, f.snap.Version = inst, version
}

type clientClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clientClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clientClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

const buA = "11111111-1111-1111-1111-111111111111"

func newTestClient(t *testing.T) (*Client, *fakeSource, *clientClock) {
	t.Helper()
	src := &fakeSource{snap: Snapshot{
		Version: 7, Profile: ProfileFedRAMPModerate, ProfileVersion: "1.0.0",
		Instance: map[string]json.RawMessage{
			KeySessionIdleTimeout:    json.RawMessage(`"15m0s"`),
			KeyAuthLockoutThreshold:  json.RawMessage(`3`),
			KeyAuditEnabled:          json.RawMessage(`true`),
			KeySessionNetworkBinding: json.RawMessage(`"reauthenticate"`),
		},
		BU: map[string]map[string]json.RawMessage{buA: {
			KeySessionNetworkBinding: json.RawMessage(`"flag"`),
			KeySessionIdleTimeout:    json.RawMessage(`"5m0s"`), // not BU-scopable: ignored
		}},
	}}
	clk := &clientClock{t: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)}
	c := NewClient(ClientOptions{Source: src, Service: "iam", Instance: "iam-0", Now: clk.now})
	if err := c.Register(F001Defs()...); err != nil {
		t.Fatal(err)
	}
	return c, src, clk
}

func TestClientGet(t *testing.T) {
	c, _, _ := newTestClient(t)
	if _, err := c.Get(KeySessionIdleTimeout, ""); !errors.Is(err, ErrNotLoaded) {
		t.Fatalf("before load: %v", err)
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d, err := c.Duration(KeySessionIdleTimeout, ""); err != nil || d != 15*time.Minute {
		t.Errorf("idle timeout %v %v", d, err)
	}
	if d, _ := c.Duration(KeySessionIdleTimeout, buA); d != 15*time.Minute {
		t.Errorf("a BU override of a non-BU-scopable setting applied: %v", d)
	}
	if n, err := c.Int(KeyAuthLockoutThreshold, ""); err != nil || n != 3 {
		t.Errorf("lockout %v %v", n, err)
	}
	if b, err := c.Bool(KeyAuditEnabled, ""); err != nil || !b {
		t.Errorf("audit %v %v", b, err)
	}
	if s, _ := c.Enum(KeySessionNetworkBinding, buA); s != "flag" {
		t.Errorf("BU override of network binding: %q", s)
	}
	if s, _ := c.Enum(KeySessionNetworkBinding, "22222222-2222-2222-2222-222222222222"); s != "reauthenticate" {
		t.Errorf("BU without override: %q", s)
	}
	if _, err := c.Get("no.such", ""); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("unregistered key: %v", err)
	}
	if _, err := c.Get(KeyTLSMinVersion, ""); !errors.Is(err, ErrUnbound) {
		t.Errorf("registered key with no value: %v", err)
	}
	if _, err := c.Int(KeySessionIdleTimeout, ""); !errors.Is(err, ErrType) {
		t.Errorf("wrong accessor: %v", err)
	}
}

func TestClientRejectsBadValues(t *testing.T) {
	c, src, _ := newTestClient(t)
	src.set(8, KeySessionIdleTimeout, `15`)
	src.set(8, KeySessionNetworkBinding, `"sideways"`)
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(KeySessionIdleTimeout, ""); !errors.Is(err, ErrType) {
		t.Errorf("number as duration: %v", err)
	}
	if _, err := c.Get(KeySessionNetworkBinding, ""); err == nil {
		t.Error("enum value outside its order accepted")
	}
}

func TestClientRegister(t *testing.T) {
	c, _, _ := newTestClient(t)
	if err := c.Register(F001Defs()...); err != nil {
		t.Errorf("re-registering the same definitions: %v", err)
	}
	d := F001Defs()[0]
	d.Direction = HigherIsStricter
	if err := c.Register(d); err == nil {
		t.Error("registered a conflicting definition")
	}
	if err := c.Register(Def{Key: "x.y", Kind: KindEnum}); err == nil {
		t.Error("registered an enum without an order")
	}
	if err := c.Register(Def{Key: "x.z", Kind: KindBool, Floor: "yes"}); err == nil {
		t.Error("registered a floor of the wrong type")
	}
}

// Refresh polls the version and reloads only when it moved; events for a
// newer version wake Run.
func TestClientRefreshAndEvents(t *testing.T) {
	c, src, _ := newTestClient(t)
	ctx := context.Background()
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if src.snapshots != 1 || src.polls != 1 {
		t.Fatalf("%d loads, %d polls; an unchanged version must not reload", src.snapshots, src.polls)
	}
	src.set(8, KeySessionIdleTimeout, `"10m0s"`)
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if d, _ := c.Duration(KeySessionIdleTimeout, ""); d != 10*time.Minute || c.Version() != 8 {
		t.Fatalf("after change: %v at version %d", d, c.Version())
	}

	// Old or malformed events do nothing; a newer one wakes the loop once.
	_ = c.HandleChanged([]byte(`{"key":"session.idle_timeout","version":8}`))
	select {
	case <-c.wake:
		t.Fatal("an event for the current version woke a refresh")
	default:
	}
	if err := c.HandleChanged([]byte(`{`)); err == nil {
		t.Error("malformed event accepted")
	}
	_ = c.HandleChanged([]byte(`{"key":"session.idle_timeout","version":9}`))
	_ = c.HandleChanged([]byte(`{"key":"session.idle_timeout","version":10}`))
	if len(c.wake) != 1 {
		t.Fatalf("%d pending wakes, want 1", len(c.wake))
	}
}

// Run applies an announced change at once, and a missed one by the TTL poll.
func TestClientRun(t *testing.T) {
	src := &fakeSource{snap: Snapshot{Version: 1, Instance: map[string]json.RawMessage{KeySessionIdleTimeout: json.RawMessage(`"15m0s"`)}}}
	var beats []Heartbeat
	var mu sync.Mutex
	c := NewClient(ClientOptions{Source: src, Service: "iam", TTL: 50 * time.Millisecond, HeartbeatEvery: 20 * time.Millisecond,
		Publish: func(_ context.Context, h Heartbeat) error {
			mu.Lock()
			beats = append(beats, h)
			mu.Unlock()
			return nil
		}})
	if err := c.Register(F001Defs()...); err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx, func(err error) { t.Error(err) })

	wait := func(want time.Duration, within time.Duration) time.Duration {
		t.Helper()
		start := time.Now()
		for time.Since(start) < within {
			if d, _ := c.Duration(KeySessionIdleTimeout, ""); d == want {
				return time.Since(start)
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("value %v not seen within %v", want, within)
		return 0
	}
	src.set(2, KeySessionIdleTimeout, `"10m0s"`)
	_ = c.HandleChanged([]byte(`{"key":"session.idle_timeout","version":2}`))
	if took := wait(10*time.Minute, time.Second); took > 40*time.Millisecond {
		t.Errorf("announced change took %v; it should not wait for the TTL", took)
	}
	src.set(3, KeySessionIdleTimeout, `"5m0s"`) // no event: the poll must find it
	wait(5*time.Minute, time.Second)

	mu.Lock()
	defer mu.Unlock()
	if len(beats) == 0 || beats[len(beats)-1].Service != "iam" {
		t.Fatalf("heartbeats %+v", beats)
	}
}

// Get fails closed when the snapshot cannot be confirmed for MaxStale.
func TestClientFailsClosedWhenStale(t *testing.T) {
	c, src, clk := newTestClient(t)
	ctx := context.Background()
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	src.err = errors.New("database down")
	clk.add(90 * time.Second)
	if err := c.Refresh(ctx); err == nil {
		t.Fatal("refresh succeeded with the source down")
	}
	if _, err := c.Get(KeySessionIdleTimeout, ""); err != nil {
		t.Fatalf("within MaxStale: %v", err)
	}
	clk.add(31 * time.Second)
	if _, err := c.Get(KeySessionIdleTimeout, ""); !errors.Is(err, ErrStale) {
		t.Fatalf("after MaxStale: %v", err)
	}
	src.err = nil
	if err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(KeySessionIdleTimeout, ""); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
}

func TestClientHeartbeat(t *testing.T) {
	c, src, _ := newTestClient(t)
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := c.Heartbeat()
	if h.Service != "iam" || h.Instance != "iam-0" || h.Version != 7 || len(h.Values) != 4 || h.BUCount != 2 || len(h.Digest) != 64 {
		t.Fatalf("heartbeat %+v", h)
	}
	if again := c.Heartbeat(); again.Digest != h.Digest {
		t.Fatal("digest is not deterministic")
	}
	src.set(8, KeyAuditEnabled, `false`)
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.Heartbeat().Digest == h.Digest {
		t.Fatal("digest did not change with the values")
	}
}

// JSON null must never decode as a zero value (false would switch audit
// off); integral numbers in exponent form are ints, fractions and
// out-of-range numbers are not.
func TestDecodeValue(t *testing.T) {
	audit := Def{Key: "audit.enabled", Kind: KindBool, Direction: TrueIsStricter}
	lockout := Def{Key: "auth.lockout_threshold", Kind: KindInt, Direction: LowerIsStricter}
	idle := Def{Key: "session.idle_timeout", Kind: KindDuration, Direction: LowerIsStricter}
	for _, c := range []struct {
		d    Def
		raw  string
		want any
	}{
		{audit, `null`, nil}, {audit, ` null `, nil}, {audit, ``, nil}, {lockout, `null`, nil}, {idle, `null`, nil},
		{audit, `false`, false}, {lockout, `1e3`, 1000}, {lockout, `3`, 3}, {lockout, `"3"`, nil}, {lockout, `3.5`, nil}, {lockout, `-1`, nil},
		{lockout, `9223372036854775807`, 9223372036854775807}, {lockout, `9223372036854775808`, nil},
		{idle, `"1.5h"`, 90 * time.Minute}, {idle, `"-5m"`, nil}, {idle, `"+5m"`, nil},
	} {
		got, err := DecodeValue(c.d, json.RawMessage(c.raw))
		if c.want == nil {
			if err == nil {
				t.Errorf("%s %q decoded as %v", c.d.Key, c.raw, got)
			}
		} else if err != nil || got != c.want {
			t.Errorf("%s %q = %v, %v; want %v", c.d.Key, c.raw, got, err, c.want)
		}
	}
}
