package scanner

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	posturev1 "github.com/rformer/fair-app/internal/api/posturev1"
	"github.com/rformer/fair-app/internal/scanner/kube"
)

type fakeReader struct {
	once    sync.Once
	missing map[string]bool // not served (absent CRDs)
	denied  map[string]bool
}

func (f *fakeReader) List(_ context.Context, r kube.Resource, _ string) ([]kube.Object, string, error) {
	switch {
	case f.missing[r.Plural]:
		return nil, "", kube.ErrNotFound
	case f.denied[r.Plural]:
		return nil, "", kube.ErrForbidden
	}
	return nil, "1", nil
}

// Watch sends one change on network policies, then blocks.
func (f *fakeReader) Watch(ctx context.Context, r kube.Resource, _, _ string, fn func(kube.Event) error) error {
	if r == kube.NetworkPolicies {
		f.once.Do(func() {
			_ = fn(kube.Event{Type: "DELETED", Object: kube.Object{Metadata: kube.Metadata{Name: "default-deny"}}})
		})
	}
	<-ctx.Done()
	return nil
}

func TestRunScansAtStartAndAfterChanges(t *testing.T) {
	var reports atomic.Int32
	var mu sync.Mutex
	var last *posturev1.ScanReport
	s := &Scanner{Reader: &fakeReader{missing: map[string]bool{"externalsecrets": true}, denied: map[string]bool{"nodes": true}},
		Scope: Scope{Namespaces: []string{"fair-platform"}}, Instance: "s-0",
		Report: func(_ context.Context, r *posturev1.ScanReport) error {
			mu.Lock()
			last = r
			mu.Unlock()
			reports.Add(1)
			return nil
		},
		Interval: time.Hour, Debounce: 50 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for reports.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if n := reports.Load(); n != 2 {
		t.Fatalf("%d scans, want 2 (start, then the watched change)", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(last.CheckErrors) != 1 || last.CheckErrors[0].CheckId != AccessCheckID || last.ScannerInstance != "s-0" {
		t.Fatalf("access probe errors %v (absent CRDs are not errors; refused reads are)", last.CheckErrors)
	}
}
