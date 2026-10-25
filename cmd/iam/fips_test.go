package main

import (
	"crypto/fips140"
	"os"
	"testing"
)

// TestFIPSMode guards constitution S2: CI sets FAIR_REQUIRE_FIPS=1 and runs
// tests with GODEBUG=fips140=on (and builds with GOFIPS140=v1.0.0), so a
// toolchain or flag change that silently drops FIPS mode fails the build.
func TestFIPSMode(t *testing.T) {
	if os.Getenv("FAIR_REQUIRE_FIPS") == "" {
		t.Skip("FAIR_REQUIRE_FIPS not set")
	}
	if !fips140.Enabled() {
		t.Fatal("FIPS 140 mode is not enabled")
	}
}
