package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

// One loop stopping stops the others, and every error is reported.
func TestRunAll(t *testing.T) {
	boom := errors.New("boom")
	stopped := make(chan struct{})
	err := runAll(context.Background(), []func(context.Context) error{
		func(context.Context) error { return boom },
		func(ctx context.Context) error {
			<-ctx.Done()
			close(stopped)
			return ctx.Err()
		},
	})
	if !errors.Is(err, boom) || !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("the other loop kept running")
	}
	// Cancelling the parent stops all of them.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runAll(ctx, []func(context.Context) error{func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
