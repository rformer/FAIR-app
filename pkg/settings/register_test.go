package settings

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestEncodeDefs(t *testing.T) {
	b, err := EncodeDefs(F001Defs())
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(F001Defs()) {
		t.Fatalf("%d definitions encoded", len(got))
	}
	byKey := map[string]map[string]any{}
	prev := ""
	for _, d := range got {
		k := d["key"].(string)
		if k < prev {
			t.Errorf("not sorted: %s after %s", k, prev)
		}
		prev = k
		byKey[k] = d
	}
	if d := byKey[KeyTLSMinVersion]; d["type"] != "enum" || d["direction"] != "ordered" || d["hard_floor"] != "1.2" || len(d["order"].([]any)) != 4 {
		t.Errorf("tls.min_version encoded as %v", d)
	}
	if d := byKey[KeyFIPSEnabled]; d["hard_floor"] != true || len(d["hard_floor_families"].([]any)) != 2 {
		t.Errorf("fips.enabled encoded as %v", d)
	}
	if d := byKey[KeySessionIdleTimeout]; d["type"] != "duration" || d["hard_floor"] != nil || d["params"].([]any)[0] != "ac-11_odp.02" {
		t.Errorf("session.idle_timeout encoded as %v", d)
	}
	if _, err := EncodeDefs([]Def{{Key: "x.y", Kind: Kind(99)}}); err == nil {
		t.Error("encoded an unknown kind")
	}
}

type fakeRegistrar struct {
	err  error
	defs []Def
}

func (f *fakeRegistrar) Register(_ context.Context, _, _ string, defs []Def) error {
	f.defs = defs
	return f.err
}

func TestClientStart(t *testing.T) {
	ctx := context.Background()
	c, src, _ := newTestClient(t)
	reg := &fakeRegistrar{err: errors.New("PF006 not bound")}
	if err := c.Start(ctx, reg, "F-001", "1"); !errors.Is(err, ErrStartup) || len(reg.defs) != len(F001Defs()) {
		t.Fatalf("registration refused: %v (%d defs sent)", err, len(reg.defs))
	}

	// The fixture binds only four of the F-001 keys: the rest are unbound.
	reg.err = nil
	err := c.Start(ctx, reg, "F-001", "1")
	if !errors.Is(err, ErrStartup) || !errors.Is(err, ErrUnbound) || !strings.Contains(err.Error(), KeyTLSMinVersion) {
		t.Fatalf("unbound keys: %v", err)
	}

	for _, d := range F001Defs() {
		if _, ok := src.snap.Instance[d.Key]; !ok {
			v := `true`
			switch d.Kind {
			case KindDuration:
				v = `"1h0m0s"`
			case KindInt:
				v = `3`
			case KindEnum:
				v = `"` + d.Order[len(d.Order)-1] + `"`
			}
			src.set(src.snap.Version+1, d.Key, v)
		}
	}
	if err := c.Start(ctx, reg, "F-001", "1"); err != nil {
		t.Fatalf("fully bound: %v", err)
	}
	if err := NewClient(ClientOptions{Source: src}).Start(ctx, reg, "F-001", "1"); !errors.Is(err, ErrStartup) {
		t.Fatalf("nothing registered: %v", err)
	}
}
