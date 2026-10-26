package tests

// F-001 T-08: scope worker end to end (River + PostgreSQL + NATS JetStream).
// Needs FAIR_TEST_NATS=<nats url> with JetStream enabled, in addition to the
// database test settings.

import (
	"context"
	"encoding/json"
	"os"
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
	"github.com/rformer/fair-app/pkg/audit"
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
	mem := audit.NewMemory()
	w := scope.New(scope.Options{Pool: e.appPool(), Publisher: pub, Audit: mem, DrainEvery: time.Second})
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
	deadline := time.Now().Add(15 * time.Second)
	for len(mem.OfType("bu.moved")) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no bu.moved audit event within 15 s")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if ev := mem.OfType("bu.moved")[0]; ev.Attributes["new_parent"] != e.mustOwner("SELECT "+buID("B")) {
		t.Fatalf("bu.moved = %+v", ev)
	}
}

type downEmitter struct{}

func (downEmitter) Emit(context.Context, audit.Event) error { return errorString("audit sink down") }

type errorString string

func (e errorString) Error() string { return string(e) }

// Audit failures fail closed: undelivered audit events stay queued and are
// delivered once the sink recovers.
func TestWorkerAuditFailsClosed(t *testing.T) {
	e := assignmentFixture(t)
	pub, _ := scopeEvents(t)
	pool := e.appPool()
	e.mustOwner("UPDATE iam.bu SET parent_id = " + buID("B") + " WHERE code = 'A1'")

	down := scope.New(scope.Options{Pool: pool, Publisher: pub, Audit: downEmitter{}})
	if _, err := down.Drain(context.Background()); err == nil {
		t.Fatal("drain with a failing audit sink must report the failure")
	}
	if n := e.mustOwner("SELECT count(*) FROM iam.event_outbox WHERE topic = 'audit' AND published_at IS NULL"); n != "1" {
		t.Fatalf("pending audit events after sink failure = %s, want 1", n)
	}

	mem := audit.NewMemory()
	up := scope.New(scope.Options{Pool: pool, Publisher: pub, Audit: mem})
	if err := up.Deliver(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(mem.OfType("bu.moved")) != 1 || e.mustOwner("SELECT count(*) FROM iam.event_outbox WHERE published_at IS NULL") != "0" {
		t.Fatalf("recovered sink got %d bu.moved events", len(mem.OfType("bu.moved")))
	}
}

func TestWorkerReconcileRaisesDriftAlert(t *testing.T) {
	e := assignmentFixture(t)
	pub, _ := scopeEvents(t)
	mem := audit.NewMemory()
	w := scope.New(scope.Options{Pool: e.appPool(), Publisher: pub, Audit: mem})
	e.mustOwner(grant("platform", "user:erin", "Executive Viewer", "A"))
	if _, err := w.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.mustOwner("UPDATE authz.user_scope SET write_bus = '{\"register\": []}' WHERE user_id = " + uid("erin"))
	n, err := w.Reconcile(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("reconcile = %d, %v", n, err)
	}
	drift := mem.OfType("authz.scope.drift")
	if len(drift) != 1 || drift[0].Severity != audit.SeverityHigh {
		t.Fatalf("drift alerts = %+v", drift)
	}
}
