// Package audittest holds the Emitter contract test suite. Every Emitter
// implementation (the stub sinks now, F-002's hash-chained store later) must
// pass RunContract.
package audittest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/rformer/fair-app/pkg/audit"
)

// Harness is what a sink test provides to the contract suite.
type Harness struct {
	Emitter audit.Emitter
	// Received returns the events the backing system has received so far,
	// decoded back into Events. It may block briefly while delivery completes.
	Received func(t *testing.T, want int) []audit.Event
}

// Factory builds a fresh harness per subtest.
type Factory func(t *testing.T) Harness

// SampleEvent returns a fully populated valid event.
func SampleEvent(n int) audit.Event {
	e := audit.New("setting.changed", audit.SeverityHigh, audit.OutcomeSuccess,
		audit.Actor{Kind: audit.ActorUser, ID: fmt.Sprintf("user-%d", n), IP: "10.0.0.1"},
		audit.Target{Kind: "setting", ID: "session.idle_timeout", BU: "bu-1"})
	e.Reason = `contract "quoted" ] reason`
	e.Before = audit.JSON(map[string]string{"value": "15m"})
	e.After = audit.JSON(map[string]string{"value": "20m"})
	e.RequestID = fmt.Sprintf("req-%d", n)
	e.Attributes = map[string]string{"n": fmt.Sprint(n)}
	e.Time = e.Time.Truncate(time.Microsecond)
	return e
}

// RunContract runs the shared Emitter contract.
func RunContract(t *testing.T, newHarness Factory) {
	t.Helper()
	ctx := context.Background()

	t.Run("delivers valid event with all fields intact", func(t *testing.T) {
		h := newHarness(t)
		defer func() { _ = h.Emitter.Close(ctx) }()
		want := SampleEvent(1)
		if err := h.Emitter.Emit(ctx, want); err != nil {
			t.Fatalf("Emit: %v", err)
		}
		got := h.Received(t, 1)
		if len(got) != 1 {
			t.Fatalf("received %d events, want 1", len(got))
		}
		assertSame(t, want, got[0])
	})

	t.Run("rejects invalid events and delivers nothing", func(t *testing.T) {
		h := newHarness(t)
		defer func() { _ = h.Emitter.Close(ctx) }()
		bad := []audit.Event{
			{},
			func() audit.Event { e := SampleEvent(2); e.Type = "NoDots"; return e }(),
			func() audit.Event { e := SampleEvent(3); e.Severity = "loud"; return e }(),
			func() audit.Event { e := SampleEvent(4); e.Actor.ID = ""; return e }(),
			func() audit.Event { e := SampleEvent(5); e.Before = json.RawMessage("{not json"); return e }(),
		}
		for i, e := range bad {
			err := h.Emitter.Emit(ctx, e)
			if !errors.Is(err, audit.ErrInvalidEvent) {
				t.Errorf("bad[%d]: got %v, want ErrInvalidEvent", i, err)
			}
		}
		// Send one valid event as a marker: it must be the only one received.
		marker := SampleEvent(99)
		if err := h.Emitter.Emit(ctx, marker); err != nil {
			t.Fatalf("Emit marker: %v", err)
		}
		got := h.Received(t, 1)
		if len(got) != 1 || got[0].ID != marker.ID {
			t.Fatalf("invalid events were delivered: %+v", got)
		}
	})

	t.Run("concurrent emits are all delivered", func(t *testing.T) {
		h := newHarness(t)
		defer func() { _ = h.Emitter.Close(ctx) }()
		const n = 25
		var wg sync.WaitGroup
		errs := make(chan error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				errs <- h.Emitter.Emit(ctx, SampleEvent(i))
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("Emit: %v", err)
			}
		}
		got := h.Received(t, n)
		seen := map[string]bool{}
		for _, e := range got {
			seen[e.ID] = true
		}
		if len(seen) != n {
			t.Fatalf("received %d distinct events, want %d", len(seen), n)
		}
	})

	t.Run("close is idempotent and emit after close fails", func(t *testing.T) {
		h := newHarness(t)
		if err := h.Emitter.Close(ctx); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := h.Emitter.Close(ctx); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		if err := h.Emitter.Emit(ctx, SampleEvent(7)); !errors.Is(err, audit.ErrClosed) {
			t.Fatalf("Emit after Close: got %v, want ErrClosed", err)
		}
	})
}

func assertSame(t *testing.T, want, got audit.Event) {
	t.Helper()
	wb, _ := json.Marshal(want)
	gb, _ := json.Marshal(got)
	if string(wb) != string(gb) {
		t.Fatalf("event changed in transit:\nwant %s\n got %s", wb, gb)
	}
}

// Poll calls get until it returns at least want items or the deadline passes.
func Poll[T any](t *testing.T, want int, get func() []T) []T {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		got := get()
		if len(got) >= want || time.Now().After(deadline) {
			// Allow a short settle period to catch over-delivery.
			time.Sleep(20 * time.Millisecond)
			return get()
		}
		time.Sleep(10 * time.Millisecond)
	}
}
