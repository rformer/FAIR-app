package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Registrar records a service's definitions with the posture service
// (design §6.1). DBRegistrar is the production implementation.
type Registrar interface {
	Register(ctx context.Context, ownerFeature, version string, defs []Def) error
}

// DBRegistrar registers through posture.register_settings, which refuses
// definitions that conflict with what is registered, would weaken a hard
// floor, or are not bound by the active profile. Connect as app_rw.
type DBRegistrar struct{ DB Querier }

// Register implements Registrar.
func (r DBRegistrar) Register(ctx context.Context, ownerFeature, version string, defs []Def) error {
	b, err := EncodeDefs(defs)
	if err != nil {
		return err
	}
	var n int
	return r.DB.QueryRow(ctx, "SELECT posture.register_settings($1, $2, $3::jsonb)", ownerFeature, version, string(b)).Scan(&n)
}

var kindNames = map[Kind]string{KindDuration: "duration", KindInt: "int", KindBool: "bool", KindEnum: "enum"}

var directionNames = map[Direction]string{
	LowerIsStricter: "lower_is_stricter", HigherIsStricter: "higher_is_stricter",
	TrueIsStricter: "true_is_stricter", FalseIsStricter: "false_is_stricter", OrderedEnum: "ordered",
}

// EncodeDefs is the JSON form of definitions that posture.register_settings
// takes; values use the profile package encoding (durations as Go strings).
func EncodeDefs(defs []Def) ([]byte, error) {
	type wire struct {
		Key        string   `json:"key"`
		Type       string   `json:"type"`
		Direction  string   `json:"direction"`
		Order      []string `json:"order,omitempty"`
		BUScopable bool     `json:"bu_scopable"`
		HardFloor  any      `json:"hard_floor"`
		Families   []Family `json:"hard_floor_families"`
		Params     []string `json:"params"`
	}
	out := make([]wire, 0, len(defs))
	for _, d := range defs {
		w := wire{Key: d.Key, Type: kindNames[d.Kind], Direction: directionNames[d.Direction], Order: d.Order,
			BUScopable: d.BUScopable, HardFloor: d.Floor, Families: d.FloorFamilies, Params: d.Params}
		if w.Type == "" || w.Direction == "" {
			return nil, fmt.Errorf("settings: %s has an unknown kind or direction", d.Key)
		}
		if dur, ok := d.Floor.(time.Duration); ok {
			w.HardFloor = dur.String()
		}
		if w.Families == nil {
			w.Families = []Family{}
		}
		if w.Params == nil {
			w.Params = []string{}
		}
		out = append(out, w)
	}
	slices.SortFunc(out, func(a, b wire) int { return strings.Compare(a.Key, b.Key) })
	return json.Marshal(out)
}

// ErrStartup wraps every reason Start refuses to let a service start.
var ErrStartup = errors.New("settings: startup refused")

// Start is a service's startup sequence (design §6.1, F-015 AC-01): register
// every locally registered definition with the posture service as
// ownerFeature (e.g. "F-001") at the service's version, load the snapshot,
// and check that the active profile binds every registered key. Any failure
// is a startup error: the service must not start.
func (c *Client) Start(ctx context.Context, reg Registrar, ownerFeature, version string) error {
	c.mu.RLock()
	defs := make([]Def, 0, len(c.defs))
	for _, d := range c.defs {
		defs = append(defs, d)
	}
	c.mu.RUnlock()
	if len(defs) == 0 {
		return fmt.Errorf("%w: no settings registered", ErrStartup)
	}
	if err := reg.Register(ctx, ownerFeature, version, defs); err != nil {
		return fmt.Errorf("%w: register: %w", ErrStartup, err)
	}
	if err := c.Refresh(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrStartup, err)
	}
	var missing []string
	for _, d := range defs {
		if _, err := c.Get(d.Key, ""); err != nil {
			missing = append(missing, d.Key+" ("+err.Error()+")")
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return fmt.Errorf("%w: %w: %s", ErrStartup, ErrUnbound, strings.Join(missing, ", "))
	}
	return nil
}
