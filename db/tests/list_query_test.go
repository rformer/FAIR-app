package tests

import (
	"context"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/authz"
)

// F-001 T-11c: authz.NewestQuery returns exactly the rows, in the order, of
// the plain "newest first" query under the same signed context, page by page,
// in both scope forms; row-level security still decides what it sees.
func TestNewestQuery(t *testing.T) {
	e := docFixture(t)
	e.mustOwner(grant("platform", "user:analyst", "Executive Viewer", "ENTERPRISE"))
	e.drain()
	// 40 more rows per BU, interleaved across BUs.
	e.admin(e.db, `INSERT INTO iam.sample_doc (bu_id, title)
		SELECT b.id, lower(b.code) || '-' || g FROM generate_series(1, 40) g, iam.bu b WHERE b.code IN ('A', 'A1', 'B', 'R', 'R1') ORDER BY g, b.code`)
	q := authz.NewestQuery{Table: "iam.sample_doc", ResourceType: "register", Columns: []string{"id", "title"}, OrderBy: "id", Limit: 7}
	sql, err := q.SQL()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pool := e.appPool()
	ids := func(tok, query string, args ...any) []int64 {
		t.Helper()
		var out []int64
		if err := authz.WithDBContext(ctx, pool, tok, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, query, args...)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var id int64
				var title string
				if err := rows.Scan(&id, &title); err != nil {
					return err
				}
				out = append(out, id)
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	for user, want := range map[string]string{"erin": "include", "analyst": "exclude"} {
		tok := e.mint(user, ctxKey1)
		if f, _ := e.asCtx(tok, "SELECT CASE WHEN authz.scope_excludes('register', 'read') THEN 'exclude' ELSE 'include' END"); f != want {
			t.Fatalf("%s: form %s, want %s", user, f, want)
		}
		all := ids(tok, "SELECT id, title FROM iam.sample_doc ORDER BY id DESC")
		if len(all) < 80 {
			t.Fatalf("%s sees %d rows", user, len(all))
		}
		var paged []int64
		var cursor any // nil: the first page
		for pages := 0; ; pages++ {
			page := ids(tok, sql, cursor)
			if len(page) > q.Limit || pages > len(all) {
				t.Fatalf("%s: page of %d", user, len(page))
			}
			if len(page) == 0 {
				break
			}
			paged = append(paged, page...)
			cursor = page[len(page)-1]
		}
		if !slices.Equal(paged, all) {
			t.Errorf("%s (%s form): paged %v\nplain %v", user, want, paged, all)
		}
	}
	// Nothing outside the scope: mallory sees no BU, so no rows.
	if got := ids(e.mint("mallory", ctxKey1), sql, nil); len(got) != 0 {
		t.Fatalf("mallory: %v", got)
	}
}
