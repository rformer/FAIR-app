package tests

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/audit/integrity"
	"github.com/rformer/fair-app/internal/dbconn"
)

// F-002 T-07 (F-002-AC-03, AC-05, AC-07; design §6.2): the sequencer.

func (e *env) auditPool() *pgxpool.Pool {
	e.t.Helper()
	cc, err := dbconn.Config("development", "app_audit", e.secrets["app_audit"], "fair-test")
	if err != nil {
		e.t.Fatal(err)
	}
	cc.Database = e.db
	pc, _ := pgxpool.ParseConfig("")
	pc.ConnConfig = cc
	p, err := pgxpool.NewWithConfig(context.Background(), pc)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(p.Close)
	return p
}

// drainTrail sequences until the intake is empty.
func drainTrail(t *testing.T, s audit.Sequencer) int {
	t.Helper()
	total := 0
	for {
		n, err := s.Step(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return total
		}
		total += n
	}
}

type trailRecord struct {
	seq                   uint64
	body, leaf, chain     []byte
	eventID, producer     string
	typ, category, bu     string
	requestID, approvalID string
	skew                  bool
}

func (e *env) trailRecords() []trailRecord {
	e.t.Helper()
	out := e.adminQuery(`SELECT coalesce(json_agg(json_build_object('seq', seq, 'body', encode(body, 'hex'), 'leaf', encode(leaf_hash, 'hex'),
		'chain', encode(chain_hash, 'hex'), 'event_id', event_id, 'producer', producer, 'type', type, 'category', category, 'bu', bu_id,
		'request_id', coalesce(request_id, ''), 'approval_id', coalesce(approval_id, ''), 'skew', skew) ORDER BY seq), '[]') FROM audit.record`)
	var rows []struct {
		Seq        uint64 `json:"seq"`
		Body       string `json:"body"`
		Leaf       string `json:"leaf"`
		Chain      string `json:"chain"`
		EventID    string `json:"event_id"`
		Producer   string `json:"producer"`
		Type       string `json:"type"`
		Category   string `json:"category"`
		BU         string `json:"bu"`
		RequestID  string `json:"request_id"`
		ApprovalID string `json:"approval_id"`
		Skew       bool   `json:"skew"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		e.t.Fatal(err)
	}
	recs := make([]trailRecord, len(rows))
	for i, r := range rows {
		b, _ := hex.DecodeString(r.Body)
		l, _ := hex.DecodeString(r.Leaf)
		c, _ := hex.DecodeString(r.Chain)
		recs[i] = trailRecord{seq: r.Seq, body: b, leaf: l, chain: c, eventID: r.EventID, producer: r.Producer, typ: r.Type,
			category: r.Category, bu: r.BU, requestID: r.RequestID, approvalID: r.ApprovalID, skew: r.Skew}
	}
	return recs
}

// verifyTrail checks the whole online trail with the offline primitives:
// positions 1..n without gaps, every leaf and chain hash, from the genesis of
// the instance the head names.
func (e *env) verifyTrail(t *testing.T) []trailRecord {
	t.Helper()
	recs := e.trailRecords()
	instance := e.adminQuery("SELECT instance FROM audit.head")
	in := make([]integrity.Record, len(recs))
	for i, r := range recs {
		var l, c integrity.Hash
		copy(l[:], r.leaf)
		copy(c[:], r.chain)
		in[i] = integrity.Record{Seq: r.seq, Body: r.body, Leaf: l, Chain: c}
	}
	end, err := integrity.VerifyRecords(integrity.Genesis(instance), 1, in)
	if err != nil {
		t.Fatalf("trail does not verify: %v", err)
	}
	head := e.adminQuery("SELECT seq || ':' || encode(chain_hash, 'hex') FROM audit.head")
	if want := fmt.Sprintf("%d:%s", len(recs), end); head != want {
		t.Fatalf("head %s, want %s", head, want)
	}
	if genesis := e.adminQuery("SELECT encode(sha256(convert_to('fair-audit-v1' || instance, 'UTF8')), 'hex') FROM audit.head"); genesis != integrity.Genesis(instance).String() {
		t.Fatalf("SQL and Go disagree on the genesis: %s", genesis)
	}
	return recs
}

func submitAs(t *testing.T, e *env, role string, ev map[string]any) {
	t.Helper()
	b, _ := json.Marshal(ev)
	if _, err := e.as(role, "SELECT audit.submit('"+strings.ReplaceAll(string(b), "'", "''")+"')"); err != nil {
		t.Fatal(err)
	}
}

func TestAuditSequencer(t *testing.T) {
	e := setup(t)
	root := e.mustOwner("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	s := audit.Sequencer{DB: e.auditPool(), Batch: 7}

	// Nothing to do: no head yet, nothing recorded.
	if n := drainTrail(t, s); n != 0 {
		t.Fatalf("sequenced %d from an empty intake", n)
	}
	// Events from several producers, with and without a BU, and some
	// attributes the columns are derived from.
	for i, role := range []string{"app_rw", "app_posture", "app_gateway", "app_audit"} {
		for j := 0; j < 5; j++ {
			ev := map[string]any{"id": fmt.Sprintf("ev-%d-%d", i, j), "type": "setting.change_requested", "severity": "high", "actor": "u1",
				"target": "setting:x", "request_id": fmt.Sprintf("req-%d", j), "attributes": map[string]any{"approval_id": "ap-1"},
				"before": map[string]any{"n": 1.50, "big": json.Number("12345678901234567890")}}
			if j%2 == 0 {
				ev["bu_id"] = root
			}
			submitAs(t, e, role, ev)
		}
	}
	if n := drainTrail(t, s); n != 20 {
		t.Fatalf("sequenced %d events, want 20", n)
	}
	if n := e.adminQuery("SELECT count(*) FROM audit.intake"); n != "0" {
		t.Fatalf("%s events left in intake", n)
	}
	recs := e.verifyTrail(t)
	if len(recs) != 20 {
		t.Fatalf("%d records", len(recs))
	}
	for _, r := range recs {
		var body map[string]any
		if err := json.Unmarshal(r.body, &body); err != nil {
			t.Fatal(err)
		}
		if !integrity.IsBody(r.body) || body["producer"] != r.producer || !strings.HasPrefix(r.producer, "app_") || body["received_at"] == nil ||
			r.bu != root || body["bu_id"] != root || r.typ != "setting.change_requested" || r.category != "configuration" ||
			r.approvalID != "ap-1" || !strings.HasPrefix(r.requestID, "req-") || r.skew {
			t.Fatalf("record %d: %+v\n%s", r.seq, r, r.body)
		}
		// Numbers keep their text through intake and sequencing.
		if !strings.Contains(string(r.body), `"big":12345678901234567890`) {
			t.Fatalf("record %d altered a number: %s", r.seq, r.body)
		}
	}
	// Records are in intake order (the order events were accepted).
	if got := e.adminQuery("SELECT string_agg(event_id, ',' ORDER BY seq) FROM audit.record WHERE producer = 'app_rw'"); got != "ev-0-0,ev-0-1,ev-0-2,ev-0-3,ev-0-4" {
		t.Fatalf("order %s", got)
	}

	// AC-05: events whose time is far from their receipt are flagged.
	submitAs(t, e, "app_rw", map[string]any{"id": "ev-old", "type": "db.migrated", "severity": "info", "actor": "x",
		"time": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)})
	submitAs(t, e, "app_rw", map[string]any{"id": "ev-near", "type": "db.migrated", "severity": "info", "actor": "x",
		"time": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)})
	submitAs(t, e, "app_rw", map[string]any{"id": "ev-mid", "type": "db.migrated", "severity": "info", "actor": "x",
		"time": time.Now().Add(-3 * time.Minute).UTC().Format(time.RFC3339)})
	s.MaxSkew = func() time.Duration { return 2 * time.Minute } // the setting in force, not the 5-minute default
	drainTrail(t, s)
	if got := e.adminQuery("SELECT string_agg(event_id || ':' || skew, ',' ORDER BY seq) FROM audit.record WHERE event_id IN ('ev-old', 'ev-near', 'ev-mid')"); got != "ev-old:true,ev-near:false,ev-mid:true" {
		t.Fatalf("skew flags %s", got)
	}
	// Under the default (5 minutes) the same three minutes are not flagged.
	submitAs(t, e, "app_rw", map[string]any{"id": "ev-mid-default", "type": "db.migrated", "severity": "info", "actor": "x",
		"time": time.Now().Add(-3 * time.Minute).UTC().Format(time.RFC3339)})
	s.MaxSkew = nil
	drainTrail(t, s)
	if got := e.adminQuery("SELECT skew FROM audit.record WHERE event_id = 'ev-mid-default'"); got != "f" {
		t.Fatalf("flagged under the default: %s", got)
	}
	// The record went into the partition of its event time.
	if got := e.adminQuery("SELECT count(*) FROM audit.record_" + time.Now().Add(-time.Hour).UTC().Format("200601") + " WHERE event_id = 'ev-old'"); got != "1" {
		t.Fatal("not in its month's partition")
	}

	// A retry that arrives after its first copy was sequenced is dropped.
	submitAs(t, e, "app_rw", map[string]any{"id": "ev-0-0", "type": "setting.change_requested", "severity": "high", "actor": "u1", "target": "setting:x"})
	if n := drainTrail(t, s); n != 0 || e.adminQuery("SELECT count(*) FROM audit.record WHERE event_id = 'ev-0-0'") != "1" {
		t.Fatalf("a retry was recorded twice (%d)", n)
	}
	if n := e.adminQuery("SELECT count(*) FROM audit.intake"); n != "0" {
		t.Fatalf("the retry stayed in intake: %s", n)
	}
	e.verifyTrail(t)
}

// Events committed after later ones are recorded when they appear, and two
// sequencers never leave a gap or a fork.
func TestAuditSequencerLateAndConcurrent(t *testing.T) {
	e := setup(t)
	s := audit.Sequencer{DB: e.auditPool(), Batch: 3}
	ctx := context.Background()
	app := e.appPool()

	// A producer's transaction holds a lower intake id while a later event
	// commits first.
	slow, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := slow.Exec(ctx, `SELECT audit.submit('{"id":"slow","type":"db.migrated","severity":"info","actor":"x"}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Exec(ctx, `SELECT audit.submit('{"id":"fast","type":"db.migrated","severity":"info","actor":"x"}')`); err != nil {
		t.Fatal(err)
	}
	if n := drainTrail(t, s); n != 1 {
		t.Fatalf("sequenced %d, want only the committed event", n)
	}
	if err := slow.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if n := drainTrail(t, s); n != 1 {
		t.Fatalf("the late event: %d", n)
	}
	if got := e.adminQuery("SELECT string_agg(event_id, ',' ORDER BY seq) FROM audit.record"); got != "fast,slow" {
		t.Fatalf("order %s", got)
	}

	// Two sequencers racing, while producers keep submitting.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var submitted atomic.Int64
	for p := 0; p < 4; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := app.Exec(ctx, "SELECT audit.submit($1)", fmt.Sprintf(`{"id":"race-%d-%d","type":"db.migrated","severity":"info","actor":"x"}`, p, i)); err == nil {
					submitted.Add(1)
				}
			}
		}(p)
	}
	other := audit.Sequencer{DB: e.auditPool(), Batch: 5}
	var errs atomic.Int64
	for _, seq := range []audit.Sequencer{s, other} {
		wg.Add(1)
		go func(seq audit.Sequencer) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := seq.Step(ctx); err != nil {
					errs.Add(1)
				}
			}
		}(seq)
	}
	time.Sleep(3 * time.Second)
	close(stop)
	wg.Wait()
	drainTrail(t, s)
	recs := e.verifyTrail(t)
	if int64(len(recs)) != submitted.Load()+2 {
		t.Fatalf("%d records for %d events", len(recs), submitted.Load()+2)
	}
	t.Logf("%d events sequenced by two racing sequencers (%d refused steps)", submitted.Load(), errs.Load())
}

// sequence_append trusts nothing it is given (AC-05, AC-07): the producer
// and receipt time come from intake, the body must be the intake event, and
// the hashes must follow the head.
func TestAuditSequenceAppendRefusesForgeries(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	pool := e.auditPool()
	submitAs(t, e, "app_posture", map[string]any{"id": "victim", "type": "db.migrated", "severity": "info", "actor": "x"})

	type input struct {
		head          string
		seq           int64
		id            int64
		instance, bu  string
		accepted      time.Time
		intakeBody    map[string]any
		intakeProduce string
	}
	load := func() input {
		var in input
		var head []byte
		var body string
		if err := pool.QueryRow(ctx, "SELECT instance, seq, chain_hash, root_bu::text FROM audit.sequence_head()").Scan(&in.instance, &in.seq, &head, &in.bu); err != nil {
			t.Fatal(err)
		}
		in.head = hex.EncodeToString(head)
		if err := pool.QueryRow(ctx, "SELECT id, body::text, producer, accepted_at FROM audit.sequence_pending(10)").Scan(&in.id, &body, &in.intakeProduce, &in.accepted); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal([]byte(body), &in.intakeBody)
		return in
	}
	build := func(in input, mut func(ev map[string]any)) ([]byte, integrity.Hash, integrity.Hash, integrity.Hash) {
		ev := map[string]any{}
		for k, v := range in.intakeBody {
			ev[k] = v
		}
		ev["producer"] = in.intakeProduce
		ev["received_at"] = in.accepted.UTC().Format(time.RFC3339Nano)
		ev["bu_id"] = in.bu
		if mut != nil {
			mut(ev)
		}
		body, _ := integrity.Body(ev)
		var prev integrity.Hash
		h, _ := hex.DecodeString(in.head)
		copy(prev[:], h)
		leaf := integrity.Leaf(body)
		return body, prev, leaf, integrity.Chain(prev, uint64(in.seq)+1, leaf) // #nosec G115 -- test positions
	}
	try := func(name string, expectSeq int64, prev integrity.Hash, body []byte, leaf, chain integrity.Hash, id int64) {
		t.Helper()
		_, err := pool.Exec(ctx, "SELECT audit.sequence_append($1, $2, $3, $4, $5, $6, NULL)", expectSeq, prev[:], []int64{id}, [][]byte{body},
			[][]byte{leaf[:]}, [][]byte{chain[:]})
		if err == nil || !strings.Contains(err.Error(), "PF013") && !strings.Contains(err.Error(), "audit.sequence_append") {
			t.Errorf("%s: %v", name, err)
		}
	}
	in := load()
	for name, mut := range map[string]func(map[string]any){
		"another producer":       func(ev map[string]any) { ev["producer"] = "app_gateway" },
		"another receipt time":   func(ev map[string]any) { ev["received_at"] = "2026-01-01T00:00:00Z" },
		"changed content":        func(ev map[string]any) { ev["actor"] = "someone else" },
		"an added field":         func(ev map[string]any) { ev["reason"] = "inserted" },
		"another BU":             func(ev map[string]any) { ev["bu_id"] = "00000000-0000-4000-8000-000000000001" },
		"no receipt time":        func(ev map[string]any) { delete(ev, "received_at") },
		"another event id":       func(ev map[string]any) { ev["id"] = "other" },
		"a dropped field (time)": func(ev map[string]any) { delete(ev, "time") },
	} {
		body, prev, leaf, chain := build(in, mut)
		try(name, in.seq, prev, body, leaf, chain, in.id)
	}
	body, prev, leaf, chain := build(in, nil)
	bad := chain
	bad[0] ^= 1
	try("a wrong chain hash", in.seq, prev, body, leaf, bad, in.id)
	badLeaf := leaf
	badLeaf[0] ^= 1
	try("a wrong leaf hash", in.seq, prev, body, badLeaf, chain, in.id)
	try("a stale head", in.seq+1, prev, body, leaf, chain, in.id)
	try("an intake row that does not exist", in.seq, prev, body, leaf, chain, in.id+1000)
	if n := e.adminQuery("SELECT count(*) FROM audit.record"); n != "0" {
		t.Fatalf("%s forged records", n)
	}
	// The honest input is accepted.
	if _, err := pool.Exec(ctx, "SELECT audit.sequence_append($1, $2, $3, $4, $5, $6, NULL)", in.seq, prev[:], []int64{in.id}, [][]byte{body},
		[][]byte{leaf[:]}, [][]byte{chain[:]}); err != nil {
		t.Fatal(err)
	}
	if got := e.adminQuery("SELECT producer FROM audit.record WHERE event_id = 'victim'"); got != "app_posture" {
		t.Fatalf("producer %q", got)
	}
	// Application roles other than app_audit cannot sequence at all.
	for _, role := range []string{"app_rw", "app_posture", "app_gateway"} {
		e.mustFail(role, "SELECT * FROM audit.sequence_head()", "permission denied")
		e.mustFail(role, "SELECT * FROM audit.sequence_pending(1)", "permission denied")
	}
}

// AC-03: while the service is down, events wait in intake; once it is back,
// all of them are recorded, in order, without loss.
func TestAuditIntakeWaitsForTheSequencer(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	app := e.appPool()
	for i := 0; i < 1200; i++ {
		if _, err := app.Exec(ctx, "SELECT audit.submit($1)", fmt.Sprintf(`{"id":"down-%04d","type":"db.migrated","severity":"info","actor":"x"}`, i)); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.adminQuery("SELECT count(*) FROM audit.intake"); n != "1200" {
		t.Fatalf("intake %s", n)
	}
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- (audit.Sequencer{DB: e.auditPool()}).Run(rctx, 50*time.Millisecond, func(err error) { t.Error(err) })
	}()
	deadline := time.Now().Add(30 * time.Second)
	for e.adminQuery("SELECT count(*) FROM audit.intake") != "0" {
		if time.Now().After(deadline) {
			t.Fatal("the backlog did not drain in 30 s")
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	recs := e.verifyTrail(t)
	ids := make([]string, len(recs))
	for i, r := range recs {
		ids[i] = r.eventID
	}
	if !sort.StringsAreSorted(ids) || len(ids) != 1200 {
		t.Fatalf("%d records, in order %v", len(ids), sort.StringsAreSorted(ids))
	}
}

// The sequencer keeps up with the NFR rates (design §10): 200 events/s
// sustained and 2,000/s for 60 s, each searchable within 5 s (p95). Part of
// the benchmark gate (FAIR_BENCH=1).
func TestBenchmarkGateAuditSequencer(t *testing.T) {
	if os.Getenv("FAIR_BENCH") != "1" {
		t.Skip("set FAIR_BENCH=1 to run the benchmark gate")
	}
	e := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cc, _ := dbconn.Config("development", "app_rw", e.secrets["app_rw"], "fair-bench")
	cc.Database = e.db
	pc, _ := pgxpool.ParseConfig("")
	pc.ConnConfig = cc
	pc.MaxConns = 48
	app, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	go func() { _ = (audit.Sequencer{DB: e.auditPool()}).Run(ctx, 50*time.Millisecond, nil) }()

	var worst time.Duration
	sample := func() {
		out := e.adminQuery("SELECT coalesce(extract(epoch FROM clock_timestamp() - min(accepted_at)), 0) FROM audit.intake")
		if age, err := strconv.ParseFloat(out, 64); err == nil {
			if d := time.Duration(age * float64(time.Second)); d > worst {
				worst = d
			}
		}
	}
	phase := func(name string, rate int, d time.Duration) {
		worst = 0
		jobs := make(chan int, rate)
		var wg sync.WaitGroup
		var failed atomic.Int64
		for w := 0; w < 40; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					if _, err := app.Exec(ctx, "SELECT audit.submit($1)", fmt.Sprintf(`{"id":"%s-%d","type":"db.migrated","severity":"info","actor":"bench"}`, name, i)); err != nil {
						failed.Add(1)
					}
				}
			}()
		}
		tick := time.NewTicker(10 * time.Millisecond)
		start, sent := time.Now(), 0
		probe := time.NewTicker(500 * time.Millisecond)
		for time.Since(start) < d {
			select {
			case <-tick.C:
				want := int(time.Since(start).Seconds() * float64(rate))
				for ; sent < want; sent++ {
					jobs <- sent
				}
			case <-probe.C:
				sample()
			}
		}
		tick.Stop()
		probe.Stop()
		close(jobs)
		wg.Wait()
		drainStart := time.Now()
		for e.adminQuery("SELECT count(*) FROM audit.intake") != "0" {
			sample()
			if time.Since(drainStart) > 30*time.Second {
				t.Fatalf("%s: the backlog did not drain", name)
			}
			time.Sleep(100 * time.Millisecond)
		}
		achieved := float64(sent) / time.Since(start).Seconds()
		t.Logf("%s: %d events at %.0f/s offered (%.0f/s achieved), %d failed; oldest waiting event %v; drained %v after the load",
			name, sent, float64(rate), achieved, failed.Load(), worst.Round(time.Millisecond), time.Since(drainStart).Round(time.Millisecond))
		if failed.Load() > 0 {
			t.Errorf("%s: %d submissions failed", name, failed.Load())
		}
		if worst > 5*time.Second {
			t.Errorf("%s: an event waited %v to be sequenced (NFR: 5 s)", name, worst)
		}
	}
	phase("sustained", 200, 30*time.Second)
	phase("burst", 2000, 60*time.Second)
	e.verifyTrail(t)
}
