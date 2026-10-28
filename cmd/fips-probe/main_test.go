package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFIPSEnabled(t *testing.T) {
	dir := t.TempDir()
	for content, want := range map[string]string{
		"1\n": "enabled", "1": "enabled", "0\n": "disabled", "": "error", "1 \n": "error", "2\n": "error", "yes": "error",
	} {
		f := filepath.Join(dir, "flag")
		if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		on, err := fipsEnabled(f)
		got := describe(on, err)
		if err != nil {
			got = "error"
		}
		if got != want {
			t.Errorf("%q: %s, want %s", content, got, want)
		}
	}
	// A kernel without FIPS support has no flag file: not confirmed.
	if on, err := fipsEnabled(filepath.Join(dir, "missing")); on || err == nil {
		t.Errorf("missing file: %v %v", on, err)
	}
}
