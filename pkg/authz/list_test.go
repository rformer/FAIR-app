package authz

import (
	"errors"
	"strings"
	"testing"
)

func TestNewestQuerySQL(t *testing.T) {
	q := NewestQuery{Table: "iam.sample_doc", ResourceType: "register", Columns: []string{"id", "title"}, OrderBy: "id", Limit: 50}
	sql, err := q.SQL()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"unnest((SELECT authz.visible_bus('register', 'read'))::uuid[]) AS v(bu)",
		"t.bu_id = v.bu AND (t.id < $1 OR $1 IS NULL) ORDER BY t.id DESC LIMIT 50",
		"WITH f AS MATERIALIZED (SELECT authz.scope_excludes('register', 'read') AS excludes)",
		"WHERE NOT (SELECT excludes FROM f)",
		"WHERE (SELECT excludes FROM f) AND (t.id < $1 OR $1 IS NULL)",
		") q ORDER BY id DESC LIMIT 50",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in\n%s", want, sql)
		}
	}
}

// A filter applies in both forms, after the cursor.
func TestNewestQueryFilter(t *testing.T) {
	q := NewestQuery{Table: "risk.scenario", ResourceType: "scenario", Columns: []string{"id", "seq"}, OrderBy: "seq", Limit: 20,
		Filter: "t.archived_at IS NULL AND t.owner = $2"}
	sql, err := q.SQL()
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(sql, "(t.seq < $1 OR $1 IS NULL) AND (t.archived_at IS NULL AND t.owner = $2)"); n != 2 {
		t.Fatalf("the filter appears %d times, want 2 (both forms): %s", n, sql)
	}
}

// A shared-down table's include form also walks the inherited BUs.
func TestNewestQuerySharedDown(t *testing.T) {
	q := NewestQuery{Table: "risk.library_entry", ResourceType: "library", Columns: []string{"id", "seq"}, OrderBy: "seq", Limit: 20, SharedDown: true}
	sql, err := q.SQL()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, "unnest(array_cat((SELECT authz.visible_bus('library', 'read'))::uuid[], coalesce((SELECT authz.inherited_bus('library'))::uuid[], '{}'))) AS v(bu)") {
		t.Fatalf("no inherited BUs: %s", sql)
	}
	q.SharedDown = false
	if sql, _ := q.SQL(); strings.Contains(sql, "inherited_bus") {
		t.Fatalf("inherited BUs for a plain table: %s", sql)
	}
}

func TestNewestQueryRefusesUnsafeInput(t *testing.T) {
	ok := NewestQuery{Table: "iam.sample_doc", ResourceType: "register", Columns: []string{"id", "title"}, OrderBy: "id", Limit: 50}
	for name, mut := range map[string]func(*NewestQuery){
		"unqualified table":           func(q *NewestQuery) { q.Table = "sample_doc" },
		"quoted table":                func(q *NewestQuery) { q.Table = `iam."x"` },
		"table injection":             func(q *NewestQuery) { q.Table = "iam.x; DROP TABLE iam.bu" },
		"resource quote":              func(q *NewestQuery) { q.ResourceType = "register'); --" },
		"column injection":            func(q *NewestQuery) { q.Columns = []string{"id", "title, (SELECT 1)"} },
		"order not selected":          func(q *NewestQuery) { q.OrderBy = "created_at" },
		"order injection":             func(q *NewestQuery) { q.OrderBy = "id DESC, 1"; q.Columns = []string{"id DESC, 1"} },
		"duplicate column":            func(q *NewestQuery) { q.Columns = []string{"id", "id"} },
		"no columns":                  func(q *NewestQuery) { q.Columns = nil },
		"zero limit":                  func(q *NewestQuery) { q.Limit = 0 },
		"limit over the bound":        func(q *NewestQuery) { q.Limit = MaxListLimit + 1 },
		"upper-case column":           func(q *NewestQuery) { q.Columns = []string{"id", "Title"} },
		"filter with two statements":  func(q *NewestQuery) { q.Filter = "t.x = $2; DROP TABLE iam.bu" },
		"filter with a comment":       func(q *NewestQuery) { q.Filter = "t.x = $2 -- " },
		"filter with a block comment": func(q *NewestQuery) { q.Filter = "t.x = $2 /* */" },
	} {
		q := ok
		q.Columns = append([]string(nil), ok.Columns...)
		mut(&q)
		if _, err := q.SQL(); !errors.Is(err, ErrInvalidListQuery) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ok.SQL(); err != nil {
		t.Fatal(err)
	}
}
