package releasemanifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const engineImage = "registry.example/fair/engine@sha256:" + "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"

// A record as `python -m fairsim validate` writes it (fields the manifest
// does not use are ignored).
func record(passed bool) []byte {
	b, _ := json.Marshal(map[string]any{
		"suite_version": "1", "engine_version": "0.1.0", "architecture": "amd64", "passed": passed,
		"run_at_unix_ms": 1762800000000, "seconds": 10.3, "self_check_digest": strings.Repeat("0", 64),
		"detail": map[string]any{"philox_vectors": map[string]any{"passed": passed}},
	})
	return b
}

func engineManifest(t *testing.T, passed bool) *Manifest {
	t.Helper()
	v, err := EngineValidationFromRecord(engineImage, record(passed))
	if err != nil {
		t.Fatal(err)
	}
	return &Manifest{Format: Format, Release: "1.0.0", Images: map[string]string{EngineComponent: engineImage}, EngineValidation: v}
}

// F-005 T-09 (AC-21): release-check passes only a manifest whose engine
// image passed its validation suite; a missing, failed or mismatched record
// is refused.
func TestEngineCheck(t *testing.T) {
	m := engineManifest(t, true)
	detail, err := m.EngineCheck()
	if err != nil || !strings.Contains(detail, "passed validation suite 1") {
		t.Fatalf("a passed record: %q, %v", detail, err)
	}
	if len(m.EngineValidation.RecordSHA256) != 64 {
		t.Error("the record's digest is kept")
	}
	if _, err := engineManifest(t, false).EngineCheck(); err == nil || !strings.Contains(err.Error(), "failed its validation suite") {
		t.Errorf("a failed record: %v", err)
	}
	missing := engineManifest(t, true)
	missing.EngineValidation = nil
	if _, err := missing.EngineCheck(); err == nil {
		t.Error("an engine image without a record")
	}
	other := engineManifest(t, true)
	other.EngineValidation.Image = strings.Replace(engineImage, "ab12", "cd34", 1)
	if err := other.Validate(); err == nil {
		t.Error("a record for another image")
	}
	none := &Manifest{Format: Format, Release: "1.0.0", Images: map[string]string{"risk": engineImage}}
	if err := none.Validate(); err != nil {
		t.Errorf("a manifest without the engine is still valid: %v", err)
	}
	if _, err := none.EngineCheck(); err == nil {
		t.Error("release-check needs the engine image")
	}
	if _, err := EngineValidationFromRecord(engineImage, []byte(`{"suite_version":"1"}`)); err == nil {
		t.Error("an incomplete record")
	}
}

func TestEngineCheckFile(t *testing.T) {
	if _, err := EngineCheckFile(""); err == nil {
		t.Error("no manifest given")
	}
	dir := t.TempDir()
	for name, passed := range map[string]bool{"ok.json": true, "failed.json": false} {
		b, err := Encode(engineManifest(t, passed))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := EngineCheckFile(filepath.Join(dir, "ok.json")); err != nil {
		t.Errorf("passed: %v", err)
	}
	if _, err := EngineCheckFile(filepath.Join(dir, "failed.json")); err == nil {
		t.Error("failed")
	}
	if _, err := EngineCheckFile(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("absent")
	}
}
