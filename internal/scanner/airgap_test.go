package scanner

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestInternalOnly(t *testing.T) {
	dns := map[string][]net.IP{
		"ingress.corp.internal": {net.ParseIP("10.20.0.5")},
		"mixed.example":         {net.ParseIP("10.0.0.1"), net.ParseIP("203.0.113.9")},
		"public.example":        {net.ParseIP("198.51.100.7")},
	}
	lookup := func(_ context.Context, h string) ([]net.IP, error) {
		if ips, ok := dns[h]; ok {
			return ips, nil
		}
		return nil, errors.New("no such host")
	}
	ctx := context.Background()
	if err := InternalOnly(ctx, []string{"ingress.corp.internal:443", "192.168.1.10:8443", "[fd00::1]:443", "127.0.0.1:443"}, lookup); err != nil {
		t.Fatalf("internal endpoints refused: %v", err)
	}
	for ep, want := range map[string]string{
		"public.example:443":  "public addresses (198.51.100.7)",
		"mixed.example:443":   "public addresses (203.0.113.9)",
		"8.8.8.8:443":         "public addresses (8.8.8.8)",
		"nowhere.example:443": "does not resolve",
		"no-port":             "missing port",
	} {
		if err := InternalOnly(ctx, []string{ep}, lookup); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", ep, err, want)
		}
	}
}
