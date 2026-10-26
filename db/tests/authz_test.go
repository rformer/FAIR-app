package tests

// F-001 T-12 (AC-24, NFR): authz library against the real database:
// grant snapshot, Check(), invalidation on iam.scope.changed, and the
// DB-context transaction helper.

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go"

	"github.com/rformer/fair-app/internal/scope"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// principal returns erin-style principals with a freshly minted DB token.
func (e *env) principal(user string) authz.Principal {
	e.t.Helper()
	tok := e.mint(user, ctxKey1)
	parts := strings.Split(tok, ".")
	v, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		e.t.Fatal(err)
	}
	return authz.Principal{UserID: parts[2], ScopeVersion: v, DBToken: tok}
}

// grantsByRule lists "permission|bu" pairs that iam.user_has_permission
// allows for the user: the reference the snapshot must equal.
func (e *env) grantsByRule(user string) []string {
	e.t.Helper()
	out := e.mustOwner(fmt.Sprintf(`SELECT coalesce(string_agg(p.key || '|' || b.id, ',' ORDER BY p.key, b.id), '')
		FROM iam.permission p CROSS JOIN iam.bu b WHERE iam.user_has_permission(%s, p.key, b.id)`, uid(user)))
	if out == "" {
		return nil
	}
	pairs := strings.Split(out, ",")
	slices.Sort(pairs) // compare in Go order, not the server's collation
	return pairs
}

func snapshotPairs(s authz.Snapshot) []string {
	var out []string
	for perm, bus := range s.Grants {
		for b := range bus {
			out = append(out, string(perm)+"|"+b)
		}
	}
	slices.Sort(out)
	return out
}

// The snapshot equals the effective-access rule for every user, after random
// grants, revocations, restrictions, moves and group changes.
func TestGrantSnapshotMatchesEffectiveRule(t *testing.T) {
	e := assignmentFixture(t)
	e.addCtxKey(ctxKey1)
	e.mustOwner("INSERT INTO iam.grp (display_name) VALUES ('G1')")
	users := []string{"erin", "mallory", "analyst", "buadmin2"}
	roles := []string{"Executive Viewer", "Risk Analyst", "Risk Owner", "Directory Reader", "Auditor", "BU Admin"}
	bus := []string{"ENTERPRISE", "A", "A1", "B", "R", "R1"}
	r := rand.New(rand.NewPCG(7, 12)) // #nosec G404 -- seeded for reproducible property tests
	pick := func(xs []string) string { return xs[r.IntN(len(xs))] }
	var script strings.Builder
	for range 40 {
		var sql string
		switch r.IntN(5) {
		case 0, 1:
			sql = grant("platform", "user:"+pick(users), pick(roles), pick(bus))
		case 2:
			sql = grant("platform", "group:G1", pick(roles), pick(bus))
		case 3:
			sql = fmt.Sprintf("INSERT INTO iam.grp_member VALUES (%s, %s) ON CONFLICT DO NOTHING", grpID("G1"), uid(pick(users)))
		default:
			sql = fmt.Sprintf("UPDATE iam.bu SET restricted = NOT restricted WHERE code = '%s'", pick(bus[1:]))
		}
		fmt.Fprintf(&script, "DO $$ BEGIN %s; EXCEPTION WHEN others THEN NULL; END $$;\n", sql)
	}
	e.mustOwner(script.String())
	e.drain()

	loader := authz.DBLoader(e.appPool())
	for _, u := range append(users, "platform") {
		p := e.principal(u)
		snap, err := loader(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		want := e.grantsByRule(u)
		if p.ScopeVersion == 0 { // no scope row: no access at all
			want = nil
		}
		if got := snapshotPairs(snap); !slices.Equal(got, want) {
			t.Errorf("%s: snapshot has %d grants, rule says %d", u, len(got), len(want))
		}
	}
}

// grant_snapshot answers only for the context's own user and only for a
// valid, current token.
func TestGrantSnapshotNeedsValidContext(t *testing.T) {
	e := docFixture(t) // erin: Executive Viewer at A, Risk Owner at A1
	loader := authz.DBLoader(e.appPool())
	good := e.principal("erin")
	snap, err := loader(context.Background(), good)
	if err != nil || snap.Version != good.ScopeVersion || len(snap.Grants) == 0 {
		t.Fatalf("valid context: %+v %v", snap, err)
	}
	for name, tok := range map[string]string{
		"garbage":  "garbage",
		"tampered": good.DBToken[:len(good.DBToken)-1] + "x",
		"expired":  sign(ctxKey1, strings.Replace(strings.Join(strings.Split(good.DBToken, ".")[:6], "."), strings.Split(good.DBToken, ".")[4], "1", 1)),
	} {
		p := good
		p.DBToken = tok
		snap, err := loader(context.Background(), p)
		if err != nil || snap.Version != 0 || len(snap.Grants) != 0 {
			t.Errorf("%s: %+v %v; want an empty snapshot", name, snap, err)
		}
	}
	// No parameter selects another user: the function takes none.
	e.mustFail("app_rw", "SELECT * FROM authz.grant_snapshot('"+good.UserID+"')", "does not exist")
}

func TestCheckEndToEnd(t *testing.T) {
	e := docFixture(t)
	c := authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(e.appPool())})
	p := e.principal("erin")
	a, a1, b := e.mustOwner("SELECT "+buID("A")), e.mustOwner("SELECT "+buID("A1")), e.mustOwner("SELECT "+buID("B"))
	r1 := e.mustOwner("SELECT " + buID("R1"))
	ctx := context.Background()
	for _, tc := range []struct {
		perm authz.Permission
		bu   string
		want error
	}{
		{"register.view", a, nil},
		{"register.view", a1, nil}, // inherited
		{"register.edit", a1, nil}, // Risk Owner at A1
		{"register.edit", a, authz.ErrDenied},
		{"register.view", b, authz.ErrDenied},
		{"register.view", r1, authz.ErrDenied}, // restricted
		{"acceptance.approve", a, authz.ErrDenied},
	} {
		if err := c.Check(ctx, p, tc.perm, tc.bu); !errors.Is(err, tc.want) && (err != nil || tc.want != nil) {
			t.Errorf("%s at %s: %v, want %v", tc.perm, tc.bu, err, tc.want)
		}
	}
}

func TestWithDBContextScopesRLS(t *testing.T) {
	e := docFixture(t)
	p := e.principal("erin")
	var titles []string
	err := authz.WithDBContext(context.Background(), e.appPool(), p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), "SELECT title FROM iam.sample_doc ORDER BY title")
		if err != nil {
			return err
		}
		titles, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err != nil || strings.Join(titles, ",") != "a,a1" {
		t.Fatalf("titles = %v err = %v", titles, err)
	}
	// The setting is local to that transaction.
	if out, _ := e.as("app_rw", "SELECT coalesce(current_setting('authz.ctx', true), '')"); out != "" {
		t.Fatalf("context leaked into a later session: %q", out)
	}
}

// Verification: cache invalidation <= 60 s. A revocation travels through the
// outbox, the scope worker and NATS to the cache, which then treats the old
// principal as stale.
func TestCacheInvalidationViaNATS(t *testing.T) {
	url := os.Getenv("FAIR_TEST_NATS")
	if url == "" {
		t.Skip("set FAIR_TEST_NATS to run the invalidation test")
	}
	e := docFixture(t)
	pub, _ := scopeEvents(t)
	pool := e.appPool()
	w := scope.New(scope.Options{Pool: pool, Publisher: pub, Audit: audit.NewMemory(), DrainEvery: time.Second})
	client, err := w.RiverClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Stop(context.Background()) }()

	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	c := authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)})
	sub, err := c.SubscribeNATS(nc)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	p := e.principal("erin")
	a1 := e.mustOwner("SELECT " + buID("A1"))
	if err := c.Check(ctx, p, "register.edit", a1); err != nil {
		t.Fatalf("before revocation: %v", err)
	}
	start := time.Now()
	e.mustOwner(revoke("platform", "erin", "Risk Owner", "A1"))
	for {
		err := c.Check(ctx, p, "register.edit", a1)
		if errors.Is(err, authz.ErrStaleScope) {
			t.Logf("revocation -> cache invalidated in %v", time.Since(start).Round(time.Millisecond))
			break
		}
		if time.Since(start) > 60*time.Second {
			t.Fatalf("cache still answers %v 60 s after the revocation", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := c.Check(ctx, e.principal("erin"), "register.edit", a1); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("fresh principal after revocation: %v, want ErrDenied", err)
	}
}
