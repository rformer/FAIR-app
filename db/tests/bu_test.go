package tests

// F-001 T-04 (AC-15, AC-16) and T-05 (AC-17, AC-59, AC-60): BU tree triggers
// and closure-table invariants.

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// owner runs SQL as fair_owner. No application role has BU privileges yet.
func (e *env) owner(sql string) (string, error) {
	return e.as("app_migrator", "SET ROLE fair_owner;\n"+sql)
}

func (e *env) mustOwner(sql string) string {
	e.t.Helper()
	out, err := e.owner(sql)
	if err != nil {
		e.t.Fatalf("owner SQL failed: %v\n%s\n%s", err, sql, out)
	}
	return out
}

func (e *env) ownerFails(sql, wantSubstr string) {
	e.t.Helper()
	out, err := e.owner(sql)
	if err == nil {
		e.t.Fatalf("expected failure for %q, got success: %s", sql, out)
	}
	if !strings.Contains(out, wantSubstr) {
		e.t.Fatalf("expected %q in error for %q, got: %s", wantSubstr, sql, out)
	}
}

const rootSQL = "(SELECT id FROM iam.bu WHERE parent_id IS NULL)"

// addBU inserts an unrestricted BU under the BU with code parent. Codes
// identify nodes in these tests.
func (e *env) addBU(code, parent string) {
	e.t.Helper()
	e.mustOwner(fmt.Sprintf("INSERT INTO iam.bu (name, code, parent_id, restricted) SELECT '%[1]s', '%[1]s', id, false FROM iam.bu WHERE code = '%[2]s'", code, parent))
}

func TestBUSingleRoot(t *testing.T) {
	e := setup(t)
	if out := e.mustOwner("SELECT code || ':' || depth || ':' || restricted FROM iam.bu"); out != "ENTERPRISE:0:false" {
		t.Fatalf("seeded tree = %q", out)
	}
	e.ownerFails("INSERT INTO iam.bu (name, code) VALUES ('Other', 'OTHER')", "bu_single_root")
	e.addBU("A", "ENTERPRISE")
	e.ownerFails("UPDATE iam.bu SET parent_id = NULL WHERE code = 'A'", "exactly one root")
	e.ownerFails("UPDATE iam.bu SET parent_id = (SELECT id FROM iam.bu WHERE code = 'A') WHERE parent_id IS NULL", "root cannot be moved")
	e.ownerFails("UPDATE iam.bu SET archived_at = now() WHERE parent_id IS NULL", "root cannot be archived")
}

func TestBUNoHardDelete(t *testing.T) {
	e := setup(t)
	e.addBU("A", "ENTERPRISE")
	e.ownerFails("DELETE FROM iam.bu WHERE code = 'A'", "never deleted")
	e.ownerFails("TRUNCATE iam.bu CASCADE", "never deleted")
	e.ownerFails("TRUNCATE iam.bu_closure", "never deleted")
	e.ownerFails("DELETE FROM iam.bu_config", "never deleted")
	e.mustOwner("UPDATE iam.bu SET archived_at = now() WHERE code = 'A'")
	e.ownerFails("INSERT INTO iam.bu (name, code, parent_id) SELECT 'B', 'B', id FROM iam.bu WHERE code = 'A'", "archived")
}

func TestBUMaxDepth(t *testing.T) {
	e := setup(t)
	parent := "ENTERPRISE"
	for i := 1; i <= 6; i++ { // default maximum is 6 (AC-15)
		code := "L" + strconv.Itoa(i)
		e.addBU(code, parent)
		parent = code
	}
	e.ownerFails("INSERT INTO iam.bu (name, code, parent_id) SELECT 'L7', 'L7', id FROM iam.bu WHERE code = 'L6'", "exceeds maximum 6")
	e.ownerFails("UPDATE iam.bu_config SET max_depth = 5", "below the current tree depth")

	// A move must fit the whole subtree, not just the moved node.
	e.addBU("X", "ENTERPRISE")
	e.addBU("Y", "X")
	e.ownerFails("UPDATE iam.bu SET parent_id = (SELECT id FROM iam.bu WHERE code = 'L6') WHERE code = 'X'", "maximum is 6")

	e.mustOwner("UPDATE iam.bu_config SET max_depth = 7")
	e.mustOwner("INSERT INTO iam.bu (name, code, parent_id) SELECT 'L7', 'L7', id FROM iam.bu WHERE code = 'L6'")

	// Depth is derived and cannot be written directly.
	e.mustOwner("UPDATE iam.bu SET depth = 1 WHERE code = 'L7'")
	if out := e.mustOwner("SELECT depth FROM iam.bu WHERE code = 'L7'"); out != "7" {
		t.Fatalf("depth after direct write = %s, want 7", out)
	}
}

func TestBUNoCycles(t *testing.T) {
	e := setup(t)
	e.addBU("A", "ENTERPRISE")
	e.addBU("B", "A")
	e.addBU("C", "B")
	e.ownerFails("UPDATE iam.bu SET parent_id = (SELECT id FROM iam.bu WHERE code = 'C') WHERE code = 'A'", "cycle")
	e.ownerFails("UPDATE iam.bu SET parent_id = id WHERE code = 'B'", "cycle")
	e.mustOwner("UPDATE iam.bu SET parent_id = " + rootSQL + " WHERE code = 'C'")
	if out := e.mustOwner("SELECT depth FROM iam.bu WHERE code = 'C'"); out != "1" {
		t.Fatalf("depth after move = %s, want 1", out)
	}
}

// inheritanceViolationsSQL counts closure rows whose `blocked` flag disagrees
// with a walk up bu.parent_id: a path (a, d] must be blocked iff a restricted
// node lies on it (AC-60). It does not trust bu_closure for the walk.
const inheritanceViolationsSQL = `
WITH RECURSIVE path(a, d, x) AS (
  SELECT ancestor_id, descendant_id, descendant_id FROM iam.bu_closure WHERE depth > 0
  UNION ALL
  SELECT p.a, p.d, b.parent_id FROM path p JOIN iam.bu b ON b.id = p.x WHERE b.parent_id <> p.a
)
SELECT count(*) FROM iam.bu_closure c
WHERE c.blocked <> EXISTS (
  SELECT 1 FROM path p JOIN iam.bu b ON b.id = p.x
  WHERE p.a = c.ancestor_id AND p.d = c.descendant_id AND b.restricted)`

// blocked reports bu_closure.blocked for the pair of BU codes.
func (e *env) blocked(ancestor, descendant string) string {
	e.t.Helper()
	return e.mustOwner(fmt.Sprintf(`SELECT c.blocked FROM iam.bu_closure c
		JOIN iam.bu a ON a.id = c.ancestor_id JOIN iam.bu d ON d.id = c.descendant_id
		WHERE a.code = '%s' AND d.code = '%s'`, ancestor, descendant))
}

// T-05 (AC-59, AC-60): restricting a BU stops inheritance into it and its
// subtree from every ancestor, but not from the BU itself.
func TestBURestrictBlocksInheritance(t *testing.T) {
	e := setup(t)
	if out := e.mustOwner("INSERT INTO iam.bu (name, code, parent_id) SELECT 'D', 'D', id FROM iam.bu WHERE parent_id IS NULL RETURNING restricted"); out != "t" {
		t.Fatalf("new BU restricted = %s, want t (secure default)", out)
	}
	e.addBU("A", "ENTERPRISE")
	e.addBU("B", "A")
	e.addBU("C", "B")
	if got := e.blocked("ENTERPRISE", "C"); got != "f" {
		t.Fatalf("unrestricted path blocked = %s", got)
	}

	e.mustOwner("UPDATE iam.bu SET restricted = true WHERE code = 'B'")
	for _, pair := range [][3]string{
		{"ENTERPRISE", "B", "t"}, {"ENTERPRISE", "C", "t"}, {"A", "B", "t"}, {"A", "C", "t"},
		{"B", "C", "f"}, // an assignment at the restricted node still applies below it
		{"ENTERPRISE", "A", "f"},
	} {
		if got := e.blocked(pair[0], pair[1]); got != pair[2] {
			t.Errorf("after restrict: blocked(%s, %s) = %s, want %s", pair[0], pair[1], got, pair[2])
		}
	}

	// A second restricted node on the path keeps it blocked after the first is lifted.
	e.mustOwner("UPDATE iam.bu SET restricted = true WHERE code = 'C'")
	e.mustOwner("UPDATE iam.bu SET restricted = false WHERE code = 'B'")
	for _, pair := range [][3]string{{"A", "B", "f"}, {"A", "C", "t"}, {"B", "C", "t"}} {
		if got := e.blocked(pair[0], pair[1]); got != pair[2] {
			t.Errorf("after unrestrict: blocked(%s, %s) = %s, want %s", pair[0], pair[1], got, pair[2])
		}
	}

	// Move and restrict in one statement: the restrict rebuild sees the new links.
	e.mustOwner("UPDATE iam.bu SET parent_id = (SELECT id FROM iam.bu WHERE code = 'A'), restricted = false WHERE code = 'C'")
	if got := e.blocked("ENTERPRISE", "C"); got != "f" {
		t.Errorf("after move+unrestrict: blocked(ENTERPRISE, C) = %s, want f", got)
	}
	if out := e.mustOwner(inheritanceViolationsSQL); out != "0" {
		t.Fatalf("%s closure rows disagree with the tree", out)
	}
}

func TestBUNoAppRoleAccess(t *testing.T) {
	e := setup(t)
	for _, role := range []string{"app_rw", "app_engine"} {
		e.mustFail(role, "SELECT * FROM iam.bu", "permission denied")
		e.mustFail(role, "SELECT * FROM iam.bu_closure", "permission denied")
		e.mustFail(role, "UPDATE iam.bu_config SET max_depth = 32", "permission denied")
	}
}

// model mirrors the BU tree in Go so random operations can be checked against
// the database.
type model struct {
	parent     map[string]string // "" for the root
	restricted map[string]bool
	archived   map[string]bool
	maxDepth   int
}

func (m *model) depth(n string) int {
	d := 0
	for m.parent[n] != "" {
		n = m.parent[n]
		d++
	}
	return d
}

// isAncestor reports whether a is n or an ancestor of n.
func (m *model) isAncestor(a, n string) bool {
	for ; n != ""; n = m.parent[n] {
		if n == a {
			return true
		}
	}
	return false
}

func (m *model) height(n string) int {
	h := 0
	for x := range m.parent {
		if m.isAncestor(n, x) {
			h = max(h, m.depth(x)-m.depth(n))
		}
	}
	return h
}

// closure returns "ancestor|descendant|depth|blocked" rows, sorted.
func (m *model) closure() []string {
	var rows []string
	for d := range m.parent {
		blocked := false
		for a, dist := d, 0; a != ""; a, dist = m.parent[a], dist+1 {
			rows = append(rows, fmt.Sprintf("%s|%s|%d|%t", a, d, dist, blocked))
			if m.restricted[a] {
				blocked = true // a is on (parent(a), d]
			}
		}
	}
	slices.Sort(rows)
	return rows
}

func (m *model) nodes() []string {
	ns := make([]string, 0, len(m.parent))
	for n := range m.parent {
		ns = append(ns, n)
	}
	slices.Sort(ns)
	return ns
}

func uuidFrom(r *rand.Rand) string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], r.Uint64())
	binary.BigEndian.PutUint64(b[8:], r.Uint64())
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// TestBUClosureProperty applies random inserts, moves, restricts, unrestricts
// and archives, some of them invalid, and checks that the database accepts exactly the valid ones
// and that bu_closure and bu.depth match the model afterwards.
func TestBUClosureProperty(t *testing.T) {
	e := setup(t)
	for seed := uint64(1); seed <= 8; seed++ {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			r := rand.New(rand.NewPCG(seed, 0xB0)) // #nosec G404 -- seeded for reproducible property tests
			m := &model{parent: map[string]string{}, restricted: map[string]bool{}, archived: map[string]bool{}, maxDepth: 6}

			// Start each seed from an empty table, bypassing the delete guard as owner.
			var script strings.Builder
			script.WriteString("ALTER TABLE iam.bu DISABLE TRIGGER bu_no_delete; DELETE FROM iam.bu_closure; DELETE FROM iam.bu; ALTER TABLE iam.bu ENABLE TRIGGER bu_no_delete;\n")
			rootID := uuidFrom(r)
			fmt.Fprintf(&script, "INSERT INTO iam.bu (id, name, code, restricted) VALUES ('%s', 'Root', 'R', false);\n", rootID)
			m.parent[rootID] = ""

			var want []string
			op := func(sql string, ok bool) {
				i := len(want)
				fmt.Fprintf(&script, "DO $$ BEGIN %s; RAISE NOTICE 'op %% ok', %d; EXCEPTION WHEN others THEN RAISE NOTICE 'op %% err', %d; END $$;\n", sql, i, i)
				if ok {
					want = append(want, fmt.Sprintf("op %d ok", i))
				} else {
					want = append(want, fmt.Sprintf("op %d err", i))
				}
			}

			for i := range 150 {
				ns := m.nodes()
				pick := func() string { return ns[r.IntN(len(ns))] }
				switch k := r.IntN(12); {
				case k < 5: // insert
					p, id, restricted := pick(), uuidFrom(r), r.IntN(3) == 0
					ok := !m.archived[p] && m.depth(p)+1 <= m.maxDepth
					op(fmt.Sprintf("INSERT INTO iam.bu (id, name, code, parent_id, restricted) VALUES ('%s', 'n', 'C%d', '%s', %t)", id, i, p, restricted), ok)
					if ok {
						m.parent[id], m.restricted[id] = p, restricted
					}
				case k < 8: // move
					n, p := pick(), pick()
					ok := m.parent[n] == p || // an unchanged parent is a no-op, even if archived
						m.parent[n] != "" && !m.isAncestor(n, p) && !m.archived[p] && m.depth(p)+1+m.height(n) <= m.maxDepth
					op(fmt.Sprintf("UPDATE iam.bu SET parent_id = '%s' WHERE id = '%s'", p, n), ok)
					if ok {
						m.parent[n] = p
					}
				case k < 10: // restrict or unrestrict (AC-59)
					n := pick()
					op(fmt.Sprintf("UPDATE iam.bu SET restricted = NOT restricted WHERE id = '%s'", n), true)
					m.restricted[n] = !m.restricted[n]
				case k < 11: // move and toggle restriction in one statement
					n, p := pick(), pick()
					ok := m.parent[n] == p ||
						m.parent[n] != "" && !m.isAncestor(n, p) && !m.archived[p] && m.depth(p)+1+m.height(n) <= m.maxDepth
					op(fmt.Sprintf("UPDATE iam.bu SET parent_id = '%s', restricted = NOT restricted WHERE id = '%s'", p, n), ok)
					if ok {
						m.parent[n], m.restricted[n] = p, !m.restricted[n]
					}
				default: // archive
					n := pick()
					ok := m.parent[n] != ""
					op(fmt.Sprintf("UPDATE iam.bu SET archived_at = now() WHERE id = '%s'", n), ok)
					if ok {
						m.archived[n] = true
					}
				}
			}

			out, err := e.owner(script.String())
			if err != nil {
				t.Fatalf("script failed: %v\n%s", err, out)
			}
			var got []string
			for _, line := range strings.Split(out, "\n") {
				if _, after, found := strings.Cut(line, "NOTICE:  "); found {
					got = append(got, strings.TrimSpace(after))
				}
			}
			if !slices.Equal(got, want) {
				for i := range min(len(got), len(want)) {
					if got[i] != want[i] {
						t.Fatalf("first divergence at %d: db %q, model %q", i, got[i], want[i])
					}
				}
				t.Fatalf("db reported %d ops, model %d", len(got), len(want))
			}

			rows := strings.Split(e.mustOwner(`SELECT ancestor_id || '|' || descendant_id || '|' || depth || '|' || blocked::text
				FROM iam.bu_closure`), "\n")
			slices.Sort(rows)
			if wantRows := m.closure(); !slices.Equal(rows, wantRows) {
				t.Fatalf("closure mismatch: db %d rows, model %d rows", len(rows), len(wantRows))
			}
			// AC-60, checked against the tree itself rather than the model.
			if out := e.mustOwner(inheritanceViolationsSQL); out != "0" {
				t.Fatalf("%s closure rows let access inherit across a restricted node (or block it without one)", out)
			}

			depths := strings.Split(e.mustOwner("SELECT id || '|' || depth FROM iam.bu"), "\n")
			slices.Sort(depths) // sort in Go: the server collation may order differently
			var wantDepths []string
			for _, n := range m.nodes() {
				wantDepths = append(wantDepths, fmt.Sprintf("%s|%d", n, m.depth(n)))
			}
			if !slices.Equal(depths, wantDepths) {
				t.Fatal("bu.depth does not match the model")
			}
		})
	}
}
