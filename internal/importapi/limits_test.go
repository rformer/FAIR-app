package importapi

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/integration"
)

// F-011 design §3.2 (OQ8): a pushed batch and a register file may be 20
// MiB; every other route keeps the platform's 4 MiB.
func TestUploadLimit(t *testing.T) {
	if UploadLimit <= integration.MaxBody {
		t.Fatalf("UploadLimit %d leaves no room above a %d-byte body", UploadLimit, integration.MaxBody)
	}
	for target, want := range map[string]bool{
		"POST /api/v1/imports/7c1e/batches":              true,
		"POST /api/v1/imports/7c1e/batches?dry_run=true": true,
		"POST /api/v1/register/imports":                  true,
		"POST /api/v1/register/imports?dry_run=true":     true,
		"GET /api/v1/imports/runs/7c1e":                  false,
		"POST /api/v1/proposals/accept":                  false,
		"POST /api/v1/proposals/7c1e/accept":             false,
		"POST /api/v1/imports//batches":                  false,
		"POST /api/v1/imports/7c1e/batches/x":            false,
		"POST /api/v1/library/7c1e/derivation":           false,
	} {
		method, path, _ := strings.Cut(target, " ")
		if got := isUpload(httptest.NewRequestWithContext(context.Background(), method, path, nil)); got != want {
			t.Errorf("%s: %v, want %v", target, got, want)
		}
	}
}
