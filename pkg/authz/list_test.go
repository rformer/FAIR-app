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

func TestNewestQueryRefusesUnsafeInput(t *testing.T) {
	ok := NewestQuery{Table: "iam.sample_doc", ResourceType: "register", Columns: []string{"id", "title"}, OrderBy: "id", Limit: 50}
	for name, mut := range map[string]func(*NewestQuery){
		"unqualified table":    func(q *NewestQuery) { q.Table = "sample_doc" },
		"quoted table":         func(q *NewestQuery) { q.Table = `iam."x"` },
		"table injection":      func(q *NewestQuery) { q.Table = "iam.x; DROP TABLE iam.bu" },
		"resource quote":       func(q *NewestQuery) { q.ResourceType = "register'); --" },
		"column injection":     func(q *NewestQuery) { q.Columns = []string{"id", "title, (SELECT 1)"} },
		"order not selected":   func(q *NewestQuery) { q.OrderBy = "created_at" },
		"order injection":      func(q *NewestQuery) { q.OrderBy = "id DESC, 1"; q.Columns = []string{"id DESC, 1"} },
		"duplicate column":     func(q *NewestQuery) { q.Columns = []string{"id", "id"} },
		"no columns":           func(q *NewestQuery) { q.Columns = nil },
		"zero limit":           func(q *NewestQuery) { q.Limit = 0 },
		"limit over the bound": func(q *NewestQuery) { q.Limit = MaxListLimit + 1 },
		"upper-case column":    func(q *NewestQuery) { q.Columns = []string{"id", "Title"} },
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
