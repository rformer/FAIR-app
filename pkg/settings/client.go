package settings

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"
)

// Client is the settings library embedded in every service (F-015 design
// §2, T-11). It serves effective values from an in-process snapshot of the
// posture service's state. The snapshot is refreshed when a
// posture.setting.changed event announces a newer version and, as a backstop
// for missed events, whenever a poll every TTL (default 30 s) finds the
// version changed, so a change reaches every service within 60 s.
//
// Get fails closed: if the snapshot could not be refreshed for MaxStale, it
// returns ErrStale rather than serve values that may no longer be in force.
//
// Registry (the T-00b stand-in) remains the in-process evaluator until T-16.
type Client struct {
	o ClientOptions

	mu       sync.RWMutex
	defs     map[string]Def
	snap     Snapshot
	loaded   bool
	verified time.Time // last time the snapshot was confirmed current
	wake     chan struct{}
}

// Snapshot is the posture state at one version (posture.effective_settings).
type Snapshot struct {
	Version        int64                                 `json:"version"`
	Profile        string                                `json:"profile"`
	ProfileVersion string                                `json:"profile_version"`
	Instance       map[string]json.RawMessage            `json:"instance"`
	BU             map[string]map[string]json.RawMessage `json:"bu"`
}

// StateSource reads the posture state (DBSource in production).
type StateSource interface {
	Snapshot(ctx context.Context) (Snapshot, error)
	Version(ctx context.Context) (int64, error)
}

// ClientOptions configures a Client.
type ClientOptions struct {
	Source   StateSource
	Service  string        // e.g. "iam"; reported in heartbeats
	Instance string        // e.g. the pod name
	TTL      time.Duration // version poll interval; default 30 s
	MaxStale time.Duration // Get fails after this long without a confirmed refresh; default 2 min
	// Heartbeat interval and sink (posture.settings.heartbeat); default 60 s.
	// Nil Publish disables heartbeats.
	HeartbeatEvery time.Duration
	Publish        func(ctx context.Context, h Heartbeat) error
	Now            func() time.Time
}

// Errors returned by Client.
var (
	ErrNotLoaded = errors.New("settings: no snapshot loaded yet")
	ErrStale     = errors.New("settings: snapshot is stale; values cannot be confirmed current")
	ErrUnbound   = errors.New("settings: registered setting has no value in force")
)

// NewClient returns a Client with defaults applied. Register definitions,
// then Refresh (or Run) before calling Get.
func NewClient(o ClientOptions) *Client {
	if o.TTL <= 0 {
		o.TTL = 30 * time.Second
	}
	if o.MaxStale <= 0 {
		o.MaxStale = 2 * time.Minute
	}
	if o.HeartbeatEvery <= 0 {
		o.HeartbeatEvery = 60 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Client{o: o, defs: map[string]Def{}, wake: make(chan struct{}, 1)}
}

// Register declares the settings this service reads (F-015 AC-01). It
// validates the definitions locally; registration with the posture service
// and the "missing from the active package" startup check are T-12.
func (c *Client) Register(defs ...Def) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, d := range defs {
		if d.Key == "" {
			return errors.New("settings: definition with empty key")
		}
		if old, dup := c.defs[d.Key]; dup && !sameDef(old, d) {
			return fmt.Errorf("settings: %s registered twice with different definitions", d.Key)
		}
		if d.Kind == KindEnum && len(d.Order) < 2 {
			return fmt.Errorf("settings: enum %s needs an order", d.Key)
		}
		if d.Floor != nil {
			if err := d.Validate(d.Floor); err != nil {
				return fmt.Errorf("settings: floor for %s: %w", d.Key, err)
			}
		}
		c.defs[d.Key] = d
	}
	return nil
}

func sameDef(a, b Def) bool {
	return a.Kind == b.Kind && a.Direction == b.Direction && slices.Equal(a.Order, b.Order) &&
		a.BUScopable == b.BUScopable && fmt.Sprint(a.Floor) == fmt.Sprint(b.Floor) && slices.Equal(a.FloorFamilies, b.FloorFamilies)
}

// Get returns the value in force for key in BU buID ("" for instance-wide),
// typed per its definition: time.Duration, int, bool or string. A BU
// override applies only to BU-scopable settings.
func (c *Client) Get(key, buID string) (any, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	d, ok := c.defs[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s (not registered by this service)", ErrUnknownKey, key)
	}
	if !c.loaded {
		return nil, ErrNotLoaded
	}
	if age := c.o.Now().Sub(c.verified); age > c.o.MaxStale {
		return nil, fmt.Errorf("%w (last confirmed %s ago)", ErrStale, age.Round(time.Second))
	}
	raw, ok := c.snap.BU[buID][key]
	if !ok || buID == "" || !d.BUScopable {
		if raw, ok = c.snap.Instance[key]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnbound, key)
		}
	}
	return DecodeValue(d, raw)
}

// Duration is Get for a duration setting.
func (c *Client) Duration(key, buID string) (time.Duration, error) {
	return typed[time.Duration](c, key, buID)
}

// Int is Get for an int setting.
func (c *Client) Int(key, buID string) (int, error) { return typed[int](c, key, buID) }

// Bool is Get for a bool setting.
func (c *Client) Bool(key, buID string) (bool, error) { return typed[bool](c, key, buID) }

// Enum is Get for an enum setting.
func (c *Client) Enum(key, buID string) (string, error) { return typed[string](c, key, buID) }

func typed[T any](c *Client, key, buID string) (T, error) {
	var zero T
	v, err := c.Get(key, buID)
	if err != nil {
		return zero, err
	}
	t, ok := v.(T)
	if !ok {
		return zero, fmt.Errorf("%w: %s is %T", ErrType, key, v)
	}
	return t, nil
}

// DecodeValue converts a posture JSON value (as stored and in profile
// packages) to the Go type d expects: time.Duration from a Go duration
// string, int from any integral JSON number in int64 range, bool, or an enum
// string. JSON null is always refused: encoding/json would silently decode it
// as a zero value (false, 0), which must never stand in for a setting.
// The database's posture.check_value accepts exactly the same values (a
// property test in db/tests keeps the two equal).
func DecodeValue(d Def, raw json.RawMessage) (any, error) {
	bad := func() (any, error) { return nil, fmt.Errorf("%w: %s: %s", ErrType, d.Key, raw) }
	if t := bytes.TrimSpace(raw); len(t) == 0 || bytes.Equal(t, []byte("null")) {
		return bad()
	}
	var v any
	switch d.Kind {
	case KindDuration:
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || strings.HasPrefix(s, "+") {
			return bad() // durations are unsigned, as time.Duration.String writes them
		}
		dur, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrType, d.Key, err)
		}
		v = dur
	case KindInt:
		// Into any, not json.Number: json.Number also accepts a quoted "3".
		var x any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&x); err != nil {
			return bad()
		}
		num, ok := x.(json.Number)
		if !ok {
			return bad()
		}
		r, ok := new(big.Rat).SetString(num.String())
		if !ok || !r.IsInt() || !r.Num().IsInt64() {
			return bad()
		}
		v = int(r.Num().Int64())
	case KindBool:
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return bad()
		}
		v = b
	case KindEnum:
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return bad()
		}
		v = s
	}
	if err := d.Validate(v); err != nil {
		return nil, err
	}
	return v, nil
}

// Version is the posture version of the current snapshot (0 before the first
// load).
func (c *Client) Version() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snap.Version
}

// Refresh confirms the snapshot is current, reloading it when the posture
// version has moved (or nothing is loaded yet).
func (c *Client) Refresh(ctx context.Context) error {
	c.mu.RLock()
	loaded, have := c.loaded, c.snap.Version
	c.mu.RUnlock()
	if loaded {
		v, err := c.o.Source.Version(ctx)
		if err != nil {
			return fmt.Errorf("settings: version: %w", err)
		}
		if v == have {
			c.mu.Lock()
			c.verified = c.o.Now()
			c.mu.Unlock()
			return nil
		}
	}
	s, err := c.o.Source.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("settings: snapshot: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.loaded || s.Version >= c.snap.Version {
		c.snap, c.loaded = s, true
	}
	c.verified = c.o.Now()
	return nil
}

// ChangedEvent is the posture.setting.changed payload (design §6.2).
type ChangedEvent struct {
	Key     string `json:"key"`
	BUID    string `json:"bu_id,omitempty"`
	Version int64  `json:"version"`
}

// SubjectChanged and SubjectHeartbeat are the NATS subjects the library uses.
const (
	SubjectChanged   = "posture.setting.changed"
	SubjectHeartbeat = "posture.settings.heartbeat"
)

// HandleChanged processes a posture.setting.changed payload: an event for a
// version newer than the snapshot wakes Run to refresh at once.
func (c *Client) HandleChanged(data []byte) error {
	var e ChangedEvent
	if err := json.Unmarshal(data, &e); err != nil {
		return fmt.Errorf("settings: changed event: %w", err)
	}
	if e.Version > c.Version() {
		select {
		case c.wake <- struct{}{}:
		default: // a refresh is already pending
		}
	}
	return nil
}

// Run refreshes on change events and every TTL, and publishes heartbeats,
// until ctx ends. Refresh errors are retried at the next tick; Get fails
// closed once MaxStale passes without a confirmed refresh.
func (c *Client) Run(ctx context.Context, onError func(error)) {
	if onError == nil {
		onError = func(error) {}
	}
	poll := time.NewTicker(c.o.TTL)
	defer poll.Stop()
	beat := time.NewTicker(c.o.HeartbeatEvery)
	defer beat.Stop()
	refresh := func() {
		if err := c.Refresh(ctx); err != nil && ctx.Err() == nil {
			onError(err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.wake:
			refresh()
		case <-poll.C:
			refresh()
		case <-beat.C:
			if c.o.Publish != nil {
				if err := c.o.Publish(ctx, c.Heartbeat()); err != nil && ctx.Err() == nil {
					onError(fmt.Errorf("settings: heartbeat: %w", err))
				}
			}
		}
	}
}

// Heartbeat reports the values this instance enforces (design §6.7 check 4):
// the drift engine compares them with the expected values.
type Heartbeat struct {
	Service  string         `json:"service"`
	Instance string         `json:"instance"`
	Version  int64          `json:"version"`
	Verified time.Time      `json:"verified"`
	Values   map[string]any `json:"values"` // registered keys, instance-wide, as JSON values
	BUCount  int            `json:"bu_overrides"`
	Digest   string         `json:"digest"` // SHA-256 of the whole snapshot's values
}

// Heartbeat builds the current heartbeat.
func (c *Client) Heartbeat() Heartbeat {
	c.mu.RLock()
	defer c.mu.RUnlock()
	h := Heartbeat{Service: c.o.Service, Instance: c.o.Instance, Version: c.snap.Version, Verified: c.verified, Values: map[string]any{}}
	for k := range c.defs {
		if raw, ok := c.snap.Instance[k]; ok {
			h.Values[k] = raw
		}
	}
	for _, m := range c.snap.BU {
		h.BUCount += len(m)
	}
	// encoding/json sorts map keys, so the digest is canonical.
	b, _ := json.Marshal(struct {
		I map[string]json.RawMessage            `json:"instance"`
		B map[string]map[string]json.RawMessage `json:"bu"`
	}{c.snap.Instance, c.snap.BU})
	sum := sha256.Sum256(b)
	h.Digest = hex.EncodeToString(sum[:])
	return h
}
