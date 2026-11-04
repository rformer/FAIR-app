package tests

// F-001 T-08: scope worker end to end (River + PostgreSQL + NATS JetStream).
// Needs FAIR_TEST_NATS=<nats url> with JetStream enabled, in addition to the
// database test settings.

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"

	"github.com/rformer/fair-app/internal/dbconn"
	"github.com/rformer/fair-app/internal/natspub"
	"github.com/rformer/fair-app/internal/scope"
)

// appPool connects to the test database as app_rw, as the worker does.
func (e *env) appPool() *pgxpool.Pool {
	e.t.Helper()
	cc, err := dbconn.Config("development", "app_rw", e.secrets["app_rw"], "fair-test")
	if err != nil {
		e.t.Fatal(err)
	}
	cc.Database = e.db
	pc, err := pgxpool.ParseConfig("")
	if err != nil {
		e.t.Fatal(err)
	}
	pc.ConnConfig = cc
	pool, err := pgxpool.NewWithConfig(context.Background(), pc)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(pool.Close)
	return pool
}

// scopeEvents provisions the stream (the installer's job in production) and
// returns a consumer that sees iam.scope.changed messages published from now.
func scopeEvents(t *testing.T) (*natspub.Publisher, jetstream.Consumer) {
	t.Helper()
	url := os.Getenv("FAIR_TEST_NATS")
	if url == "" {
		t.Skip("set FAIR_TEST_NATS to a JetStream-enabled NATS server to run worker tests")
	}
	ctx := context.Background()
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{Name: "IAM_TEST", Subjects: []string{scope.SubjectScopeChanged}})
	if err != nil {
		t.Fatal(err)
	}
	cons, err := stream.OrderedConsumer(ctx, jetstream.OrderedConsumerConfig{DeliverPolicy: jetstream.DeliverNewPolicy})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := natspub.Connect(ctx, natspub.Options{Env: "development", URL: url, Name: "fair-test", Subjects: []string{scope.SubjectScopeChanged}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pub.Close)
	return pub, cons
}

func TestRiverSchemaFullyMigrated(t *testing.T) {
	e := setup(t)
	m, err := rivermigrate.New[pgx.Tx](riverpgxv5.New(e.appPool()), &rivermigrate.Config{Schema: scope.RiverSchema})
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.Validate(context.Background())
	if err != nil || !res.OK {
		t.Fatalf("River schema not fully migrated: ok=%v messages=%v err=%v", res.OK, res.Messages, err)
	}
}

// A grant made in the database reaches user_scope and JetStream through the
// running River client, and a BU move produces its AC-17 audit event.
func TestWorkerEndToEnd(t *testing.T) {
	e := assignmentFixture(t)
	pub, cons := scopeEvents(t)
	w := scope.New(scope.Options{Pool: e.appPool(), Publisher: pub, DrainEvery: time.Second})
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

	erin := e.mustOwner("SELECT " + uid("erin"))
	start := time.Now()
	e.mustOwner(grant("platform", "user:erin", "Executive Viewer", "A"))
	for {
		msg, err := cons.Next(jetstream.FetchMaxWait(15 * time.Second))
		if err != nil {
			t.Fatalf("no iam.scope.changed for erin within 15 s: %v\nriver jobs: %s\noutbox rows: %s, pending events: %s, erin scope row: %s", err,
				e.mustOwner("SELECT string_agg(kind || ':' || state || ':' || coalesce(errors::text, ''), ' | ') FROM river.river_job"),
				e.mustOwner("SELECT count(*) FROM iam.outbox"),
				e.mustOwner("SELECT count(*) FROM iam.event_outbox WHERE published_at IS NULL"),
				e.mustOwner("SELECT count(*) FROM authz.user_scope WHERE user_id = "+uid("erin")))
		}
		var ev struct {
			UserID string `json:"user_id"`
			Ver    int64  `json:"scope_version"`
		}
		if err := json.Unmarshal(msg.Data(), &ev); err != nil {
			t.Fatal(err)
		}
		if ev.UserID == erin {
			t.Logf("grant -> iam.scope.changed in %v (scope_version %d)", time.Since(start).Round(time.Millisecond), ev.Ver)
			if s := e.scopeOf("erin"); s == nil || s.Version != ev.Ver {
				t.Fatalf("published version %d but stored scope is %+v", ev.Ver, s)
			}
			break
		}
	}

	e.mustOwner("UPDATE iam.bu SET parent_id = " + buID("B") + ", updated_by = " + uid("platform") + " WHERE code = 'A1'")
	// The drain records bu.moved in the audit trail, in its own transaction
	// (F-002 T-06).
	moved := func() string {
		return e.adminQuery(`SELECT coalesce(string_agg(body->'attributes'->>'new_parent', ','), '') FROM audit.intake WHERE body->>'type' = 'bu.moved'`)
	}
	deadline := time.Now().Add(15 * time.Second)
	for moved() == "" {
		if time.Now().After(deadline) {
			t.Fatal("no bu.moved audit event within 15 s")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got := moved(); got != e.mustOwner("SELECT "+buID("B")) {
		t.Fatalf("bu.moved new_parent = %q", got)
	}
}

// Audit failures fail closed (F-001 AC-50, F-002 AC-02): when the trail
// refuses the drain's audit event, the drain's transaction records nothing
// (the scope stays queued); once it accepts, the event and the scope change
// are recorded together.
func TestWorkerAuditFailsClosed(t *testing.T) {
	e := assignmentFixture(t)
	pub, _ := scopeEvents(t)
	w := scope.New(scope.Options{Pool: e.appPool(), Publisher: pub})
	e.mustOwner("UPDATE iam.bu SET parent_id = " + buID("B") + " WHERE code = 'A1'")
	queued := e.adminQuery("SELECT count(*) FROM iam.outbox")

	// The trail refuses bu.moved (as it would an event it does not know).
	e.admin(e.db, "UPDATE audit.event_type SET retired_at = now() WHERE type = 'bu.moved'")
	if _, err := w.Drain(context.Background()); err == nil || !strings.Contains(err.Error(), "bu.moved") {
		t.Fatalf("drain with the trail refusing its event: %v", err)
	}
	if got := e.adminQuery("SELECT count(*) FROM iam.outbox"); got != queued || got == "0" {
		t.Fatalf("outbox rows after the refused drain: %s, want %s", got, queued)
	}
	if n := e.adminQuery("SELECT count(*) FROM audit.intake WHERE body->>'type' = 'bu.moved'"); n != "0" {
		t.Fatalf("%s bu.moved events recorded by a failed drain", n)
	}

	e.admin(e.db, "UPDATE audit.event_type SET retired_at = NULL WHERE type = 'bu.moved'")
	if _, err := w.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := e.adminQuery("SELECT count(*) FROM audit.intake WHERE body->>'type' = 'bu.moved'"); n != "1" {
		t.Fatalf("bu.moved events after recovery: %s", n)
	}
	if got := e.adminQuery("SELECT count(*) FROM iam.outbox"); got != "0" {
		t.Fatalf("outbox rows after recovery: %s", got)
	}
}

func TestWorkerReconcileRaisesDriftAlert(t *testing.T) {
	e := assignmentFixture(t)
	pub, _ := scopeEvents(t)
	w := scope.New(scope.Options{Pool: e.appPool(), Publisher: pub})
	e.mustOwner(grant("platform", "user:erin", "Executive Viewer", "A"))
	if _, err := w.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.mustOwner("UPDATE authz.user_scope SET write_bus = '{\"register\": []}' WHERE user_id = " + uid("erin"))
	n, err := w.Reconcile(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("reconcile = %d, %v", n, err)
	}
	if drift := e.adminQuery("SELECT string_agg(body->>'severity', ',') FROM audit.intake WHERE body->>'type' = 'authz.scope.drift'"); drift != "high" {
		t.Fatalf("drift alerts = %q", drift)
	}
}
