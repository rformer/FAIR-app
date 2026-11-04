package tests

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/migrate"
	"github.com/rformer/fair-app/pkg/audit"
)

// F-002 T-06 (F-002-AC-01, AC-02, AC-36; design §6.1): events reach the
// trail through audit.submit in their producer's transaction, from Go
// (audit.Trail, audit.WithTx) and from SQL (the iam.event_outbox trigger).

func intakeCount(e *env, where string) string {
	return e.adminQuery("SELECT count(*) FROM audit.intake WHERE " + where)
}

func TestAuditTrailFromSQLProducers(t *testing.T) {
	e := setup(t)
	// A SQL producer whose transaction rolls back records nothing.
	before := intakeCount(e, "true")
	if _, err := e.owner("BEGIN; INSERT INTO iam.event_outbox (topic, payload) VALUES ('audit', " +
		`'{"type":"db.migrated","severity":"info","actor":"system:test"}'); ROLLBACK;`); err != nil {
		t.Fatal(err)
	}
	if got := intakeCount(e, "true"); got != before {
		t.Fatalf("a rolled-back event was recorded (%s -> %s)", before, got)
	}
	// Committed, it is in the trail, converted as FromOutbox did, with the
	// DB login as its producer, and never in the outbox.
	e.mustOwner(`INSERT INTO iam.event_outbox (topic, payload) VALUES ('audit',
		'{"type":"db.migrated","severity":"info","actor":"system:test","target":null,"reason":null,
		  "attributes":{"applied":"0001","catalog_version":3,"created_roles":["a"],"catalog_previous":null}}')`)
	row := e.adminQuery(`SELECT producer || '|' || (body->'attributes')::text || '|' || (body ? 'reason') || '|' || (body ? 'time') FROM audit.intake WHERE body->'attributes'->>'applied' = '0001'`)
	if row != `app_migrator|{"applied": "0001", "created_roles": "[\"a\"]", "catalog_version": "3"}|false|true` {
		t.Fatalf("converted event: %s", row)
	}
	if n := e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE topic = 'audit'"); n != "0" {
		t.Fatalf("%s audit rows reached the outbox", n)
	}
	// The outbox row's time is the event's time (rows moved by the
	// migration keep theirs).
	e.mustOwner(`INSERT INTO iam.event_outbox (topic, payload, created_at) VALUES ('audit',
		'{"type":"db.migrated","severity":"info","actor":"system:test","attributes":{"applied":"old"}}', '2026-01-02T03:04:05Z')`)
	if got := e.adminQuery(`SELECT body->>'time' FROM audit.intake WHERE body->'attributes'->>'applied' = 'old'`); got != "2026-01-02T03:04:05.000000Z" {
		t.Fatalf("event time %q", got)
	}
	// A refused event fails the change that produced it (AC-02).
	e.ownerFails(`INSERT INTO iam.event_outbox (topic, payload) VALUES ('audit', '{"type":"no.such_event","severity":"info","actor":"x"}')`,
		"not in the catalog")
	// Other topics still go to the outbox for the worker.
	e.mustOwner(`INSERT INTO iam.event_outbox (topic, payload) VALUES ('iam.scope.changed', '{}')`)
	if n := e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE topic = 'iam.scope.changed' AND payload = '{}'"); n != "1" {
		t.Fatalf("non-audit outbox rows: %s", n)
	}
}

func TestAuditTrailFromGo(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	pool := e.appPool()
	c, err := audit.DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	logged := audit.NewMemory()
	em := audit.WithTrail(audit.Validating{Next: logged, Catalog: c}, audit.Trail{DB: pool})
	ev := func(id string) audit.Event {
		return audit.Event{ID: id, Type: "service.started", Severity: audit.SeverityInfo, Actor: "system:test", Attributes: map[string]string{"env": "test"}}
	}

	// In a transaction (WithTx): recorded only if it commits.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := em.Emit(audit.WithTx(ctx, tx), ev("ev-rollback")); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback(ctx)
	if n := intakeCount(e, "event_id = 'ev-rollback'"); n != "0" {
		t.Fatal("an event in a rolled-back transaction was recorded")
	}
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error { return em.Emit(audit.WithTx(ctx, tx), ev("ev-commit")) })
	if err != nil || intakeCount(e, "event_id = 'ev-commit' AND producer = 'app_rw'") != "1" {
		t.Fatalf("a committed event: %v", err)
	}

	// Without one: its own transaction, before Emit returns. A retry with the
	// same id is recorded once (AC-01).
	for range 3 {
		if err := em.Emit(ctx, ev("ev-retried")); err != nil {
			t.Fatal(err)
		}
	}
	if n := intakeCount(e, "event_id = 'ev-retried'"); n != "1" {
		t.Fatalf("a retried event recorded %s times", n)
	}

	// The trail refusing an event fails the caller and keeps it out of the
	// logs (AC-02): here the database's catalog no longer has the type.
	e.admin(e.db, "UPDATE audit.event_type SET retired_at = now() WHERE type = 'service.started'")
	before := len(logged.Events())
	if err := em.Emit(ctx, ev("ev-refused")); err == nil || !strings.Contains(err.Error(), "not in the catalog") {
		t.Fatalf("a refused event: %v", err)
	}
	if len(logged.Events()) != before {
		t.Fatal("an event the trail refused was written to the logs")
	}
	// Nor can a refused event be committed with a change: the caller's
	// transaction fails.
	tx, _ = pool.Begin(ctx)
	if err := em.Emit(audit.WithTx(ctx, tx), ev("ev-refused-tx")); err == nil {
		t.Fatal("refused in a transaction")
	}
	if err := tx.Commit(ctx); err == nil {
		t.Fatal("a transaction whose event was refused committed")
	}

	// Installer commands record as fair_owner over the migrator's connection;
	// the producer is still the login.
	e.admin(e.db, "UPDATE audit.event_type SET retired_at = NULL WHERE type = 'service.started'")
	mig, err := pgx.ConnectConfig(ctx, migratorConfig(t, e))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mig.Close(ctx) }()
	inst := audit.Trail{DB: mig, Role: "fair_owner"}
	if err := inst.Emit(ctx, ev("ev-installer")); err != nil {
		t.Fatal(err)
	}
	if n := intakeCount(e, "event_id = 'ev-installer' AND producer = 'app_migrator'"); n != "1" {
		t.Fatal("the installer's event was not recorded as app_migrator")
	}
	if err := (audit.Trail{DB: mig}).Emit(ctx, ev("ev-no-role")); err == nil {
		t.Fatal("the migrator recorded without taking fair_owner")
	}
	if err := (audit.Trail{}).Emit(ctx, ev("ev-no-db")); err == nil {
		t.Fatal("a trail without a database accepted an event")
	}
}

// migratorConfig connects as app_migrator, as the installer's commands do.
func migratorConfig(t *testing.T, e *env) *pgx.ConnConfig {
	t.Helper()
	cfg, err := migrate.ConnConfig("development", e.secrets["app_migrator"])
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = e.db
	return cfg
}
