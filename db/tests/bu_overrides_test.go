package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-22 (AC-32, AC-35; design §6.6): BU overrides inherit down the tree,
// stop at restricted BUs, and the value in force is the strictest of the
// instance value and every override that reaches the BU. The Restricted BU
// overlay (T-23) is weakened to "off" here, so that it does not mask the rule.

var bindingOrder = []string{"off", "flag", "reauthenticate"} // weakest first

// wantEffective computes effective(network_binding, n) from the model: the
// strictest of the instance value and the overrides at n and at every
// ancestor whose path to n crosses no restricted BU (the ancestor itself may
// be restricted; restriction blocks from above).
func wantEffective(m *model, inst string, overrides map[string]string, n string) string {
	best := slices.Index(bindingOrder, inst)
	blocked := false
	for a := n; a != ""; a = m.parent[a] {
		if v, ok := overrides[a]; ok && !blocked {
			best = max(best, slices.Index(bindingOrder, v))
		}
		if m.restricted[a] {
			blocked = true // a lies on (parent(a), n]
		}
	}
	return bindingOrder[best]
}

// TestBUOverridesProperty builds random trees with random overrides (written
// through the evaluator), then restricts and moves random BUs, and checks
// after each step that posture.current_value, the effective_settings
// snapshot and the settings client all agree with the model.
func TestBUOverridesProperty(t *testing.T) {
	for seed := uint64(1); seed <= 5; seed++ {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			ctx := context.Background()
			rg := registryFixture(t, settings.ProfileEnterpriseBaseline, "self-hosted")
			weakenOverlay(t, rg, "off")
			e := rg.e
			r := rand.New(rand.NewPCG(seed, 0x22)) // #nosec G404 -- seeded for reproducible property tests
			key := settings.KeySessionNetworkBinding

			// Random tree of depth <= 4 under ENTERPRISE; codes are model keys.
			m := &model{parent: map[string]string{"ENTERPRISE": ""}, restricted: map[string]bool{}, archived: map[string]bool{}, maxDepth: 4}
			for i := range 20 {
				var p string
				for p = ""; p == "" || m.depth(p) >= m.maxDepth; {
					ns := m.nodes()
					p = ns[r.IntN(len(ns))]
				}
				c := fmt.Sprintf("N%d", i)
				e.addBU(c, p)
				m.parent[c] = p
			}
			e.drain()
			ids := map[string]string{}
			for _, n := range m.nodes() {
				ids[n] = e.adminQuery("SELECT id FROM iam.bu WHERE code = '" + n + "'")
			}
			admin := e.principal("admin")
			set := func(bu, v string) {
				t.Helper()
				b, _ := json.Marshal(v)
				res, err := rg.set.Set(ctx, admin, settings.Request{Key: key, BUID: ids[bu], Value: json.RawMessage(b), Explanation: "property test"})
				if err != nil || res.Outcome != settings.Applied {
					t.Fatalf("set %s at %q = %s: %+v %v", key, bu, v, res, err)
				}
			}
			inst := bindingOrder[r.IntN(3)]
			set("", inst) // ids[""] is "": the instance value
			overrides := map[string]string{}
			for range 12 {
				ns := m.nodes()
				bu, v := ns[r.IntN(len(ns))], bindingOrder[r.IntN(3)]
				set(bu, v)
				overrides[bu] = v
			}

			check := func(step string) {
				t.Helper()
				var snap struct {
					BU map[string]map[string]string `json:"bu"`
				}
				if err := json.Unmarshal([]byte(e.adminQuery("SELECT posture.effective_settings()")), &snap); err != nil {
					t.Fatal(err)
				}
				if err := rg.client.Refresh(ctx); err != nil {
					t.Fatal(err)
				}
				for _, n := range m.nodes() {
					want := wantEffective(m, inst, overrides, n)
					var got string
					if err := json.Unmarshal([]byte(e.adminQuery(fmt.Sprintf("SELECT posture.current_value('%s', '%s')", key, ids[n]))), &got); err != nil {
						t.Fatal(err)
					}
					if got != want {
						t.Fatalf("%s: current_value at %s = %s, want %s (overrides %v, restricted %v, parents %v)", step, n, got, want, overrides, m.restricted, m.parent)
					}
					if v, ok := snap.BU[ids[n]][key]; ok != (want != inst) || (ok && v != want) {
						t.Fatalf("%s: snapshot at %s = %q (present %t), want %s (instance %s)", step, n, v, ok, want, inst)
					}
					if v, err := rg.client.Enum(key, ids[n]); err != nil || v != want {
						t.Fatalf("%s: client at %s = %s %v, want %s", step, n, v, err, want)
					}
				}
				if v, err := rg.client.Enum(key, ""); err != nil || v != inst {
					t.Fatalf("%s: client instance value = %s %v, want %s", step, v, err, inst)
				}
			}
			check("unrestricted")

			version := func() string { return e.adminQuery("SELECT posture.settings_version()") }
			for i := range 8 {
				ns := m.nodes()[1:] // not ENTERPRISE (sorted first)
				before := version()
				if i%2 == 0 { // toggle a restriction
					n := ns[r.IntN(len(ns))]
					m.restricted[n] = !m.restricted[n]
					e.mustOwner(fmt.Sprintf("UPDATE iam.bu SET restricted = %t WHERE code = '%s'", m.restricted[n], n))
				} else { // move a subtree under a node outside it, within the depth limit
					var n, p string
					for {
						n, p = ns[r.IntN(len(ns))], m.nodes()[r.IntN(len(ns)+1)]
						if p != m.parent[n] && !m.isAncestor(n, p) && m.depth(p)+1+m.height(n) <= m.maxDepth {
							break
						}
					}
					m.parent[n] = p
					e.mustOwner(fmt.Sprintf("UPDATE iam.bu SET parent_id = (SELECT id FROM iam.bu WHERE code = '%s') WHERE code = '%s'", p, n))
				}
				if after := version(); after == before {
					t.Fatalf("step %d: a BU tree change must bump the posture version (%s)", i, before)
				}
				check(fmt.Sprintf("step %d", i))
			}
		})
	}
}

// TestBUOverrideBlockedAtRestricted is a worked example of AC-32: an
// override above a restricted BU stops at it, one on it applies below it, and
// a weaker override never loosens what an ancestor's override sets (AC-35).
func TestBUOverrideBlockedAtRestricted(t *testing.T) {
	ctx := context.Background()
	rg := registryFixture(t, settings.ProfileEnterpriseBaseline, "self-hosted")
	weakenOverlay(t, rg, "off")
	e := rg.e
	e.addBU("A", "ENTERPRISE")
	e.addBU("A1", "A")
	e.addBU("R", "A")
	e.addBU("R1", "R")
	e.drain()
	id := func(code string) string { return e.adminQuery("SELECT id FROM iam.bu WHERE code = '" + code + "'") }
	key := settings.KeySessionNetworkBinding
	admin := e.principal("admin")
	ids := map[string]string{"": ""}
	for _, c := range []string{"ENTERPRISE", "A", "A1", "R", "R1"} {
		ids[c] = id(c)
	}
	for _, w := range []struct{ bu, v string }{{"", "off"}, {"A", "reauthenticate"}, {"A1", "flag"}, {"R", "flag"}} {
		res, err := rg.set.Set(ctx, admin, settings.Request{Key: key, BUID: ids[w.bu], Value: json.RawMessage(`"` + w.v + `"`), Explanation: "x"})
		if err != nil || res.Outcome != settings.Applied {
			t.Fatalf("set %v: %+v %v", w, res, err)
		}
	}
	e.mustOwner("UPDATE iam.bu SET restricted = true WHERE code = 'R'")
	if err := rg.client.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ bu, want string }{
		{"ENTERPRISE", "off"},
		{"A", "reauthenticate"},
		{"A1", "reauthenticate"}, // A's stricter override wins over A1's own
		{"R", "flag"},            // A's override stops at the restricted BU; R's own applies
		{"R1", "flag"},           // and reaches below it
	} {
		if v, err := rg.client.Enum(key, ids[c.bu]); err != nil || v != c.want {
			t.Fatalf("%s = %s %v, want %s", c.bu, v, err, c.want)
		}
	}
}
