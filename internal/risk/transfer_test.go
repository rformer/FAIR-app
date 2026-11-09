package risk

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/risk/canon"
)

func TestTransferEncodeParse(t *testing.T) {
	usd := "USD"
	f := Transfer{Currency: &usd, ExportedAt: time.Date(2026, 11, 9, 10, 0, 0, 123, time.FixedZone("x", 3600))}
	b, d, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := canon.Canonicalize(b); !bytes.Equal(c, b) || canon.Digest(b) != d {
		t.Fatal("not canonical, or the digest is not its own")
	}
	for _, want := range []string{`"format":"fair.risk.v1"`, `"exported_at":"2026-11-09T09:00:00Z"`, `"scenarios":[]`, `"pinned":[]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in %s", want, b)
		}
	}
	back, err := ParseTransfer(b)
	if err != nil || *back.Currency != "USD" {
		t.Fatalf("parse: %v", err)
	}
	if again, d2, _ := back.Encode(); !bytes.Equal(again, b) || d2 != d {
		t.Fatal("a round trip changed the file")
	}
	for name, in := range map[string]string{
		"other format":   strings.Replace(string(b), "fair.risk.v1", "fair.risk.v2", 1),
		"unknown member": strings.Replace(string(b), `"controls":[]`, `"controls":[],"extra":1`, 1),
		"duplicate":      strings.Replace(string(b), `"controls":[]`, `"controls":[],"controls":[]`, 1),
		"not JSON":       "{",
		"too large":      strings.Repeat(" ", MaxTransferBytes+1),
	} {
		if _, err := ParseTransfer([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
