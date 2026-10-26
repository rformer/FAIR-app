package natspub

import (
	"context"
	"strings"
	"testing"
)

func TestProductionRequiresTLS(t *testing.T) {
	for _, url := range []string{"nats://n:4222", "tls://a:4222,nats://b:4222", ""} {
		if _, err := Connect(context.Background(), Options{Env: "production", URL: url}); err == nil {
			t.Errorf("production accepted %q", url)
		} else if url != "" && !strings.Contains(err.Error(), "tls://") {
			t.Errorf("%q: err = %v", url, err)
		}
	}
}
