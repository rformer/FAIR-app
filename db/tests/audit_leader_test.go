package tests

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/dbconn"
)

// F-002 T-05 (design §2): one replica leads; the lead moves when the leader
// stops or loses its database connection.
func TestAuditLeaderElection(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := func() *pgxpool.Pool {
		cc, err := dbconn.Config("development", "app_audit", e.secrets["app_audit"], "fair-test")
		if err != nil {
			t.Fatal(err)
		}
		cc.Database = e.db
		pc, _ := pgxpool.ParseConfig("")
		pc.ConnConfig = cc
		p, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}

	type replica struct {
		name    string
		leading atomic.Bool
		gained  atomic.Int32
		stop    context.CancelFunc
		done    chan struct{}
	}
	var mu sync.Mutex
	var leaders []string
	// Never two leaders at once, at any moment (not only when sampled).
	var current, most atomic.Int32
	start := func(name string) *replica {
		r := &replica{name: name, done: make(chan struct{})}
		rctx, stop := context.WithCancel(ctx)
		r.stop = stop
		l := audit.Leader{Pool: pool(), Every: 100 * time.Millisecond, OnChange: func(leading bool) {
			if leading {
				if n := current.Add(1); n > most.Load() {
					most.Store(n)
				}
			} else {
				current.Add(-1)
			}
			r.leading.Store(leading)
			if leading {
				r.gained.Add(1)
				mu.Lock()
				leaders = append(leaders, name)
				mu.Unlock()
			}
		}}
		go func() {
			defer close(r.done)
			l.Run(rctx, func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }, nil)
		}()
		return r
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if cond() {
				return
			}
		}
		t.Fatalf("timed out waiting for %s", what)
	}

	a, b := start("a"), start("b")
	waitFor("a leader", func() bool { return a.leading.Load() || b.leading.Load() })
	time.Sleep(500 * time.Millisecond) // several rounds: never both
	if a.leading.Load() && b.leading.Load() {
		t.Fatal("two leaders")
	}
	first, second := a, b
	if b.leading.Load() {
		first, second = b, a
	}

	// The leader stops: the other takes over.
	first.stop()
	<-first.done
	waitFor("the second replica to lead", second.leading.Load)

	// The leader's connection dies: it notices and stops leading; a fresh
	// replica can take the lead once the old one lets go.
	c := start("c")
	e.admin(e.db, `SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype = 'advisory' AND granted AND objsubid = 1
		AND ((classid::bigint << 32) | objid::bigint) = `+strconv.FormatInt(audit.LeaderLockKey, 10))
	waitFor("the old leader to step down", func() bool { return !second.leading.Load() })
	waitFor("a new leader", func() bool { return c.leading.Load() || second.leading.Load() })
	time.Sleep(300 * time.Millisecond)
	if c.leading.Load() && second.leading.Load() {
		t.Fatal("two leaders after the failover")
	}
	second.stop()
	c.stop()
	<-second.done
	<-c.done
	if most.Load() > 1 {
		t.Fatalf("%d leaders at once", most.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(leaders) < 3 {
		t.Fatalf("lead changes: %v", leaders)
	}
}
