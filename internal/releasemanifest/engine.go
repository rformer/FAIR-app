package releasemanifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
)

// EngineComponent is the simulation engine's key in Images (F-005).
const EngineComponent = "engine"

// EngineValidation is the simulation engine image's validation record as
// the release manifest carries it (F-005 T-09, design §3.6, §12): the
// statistical validation suite ran at image build, and release-check
// refuses a release whose engine image did not pass it.
type EngineValidation struct {
	Image         string `json:"image"` // the engine image, as in Images
	SuiteVersion  string `json:"suite_version"`
	EngineVersion string `json:"engine_version"`
	Architecture  string `json:"architecture"`
	Passed        bool   `json:"passed"`
	RunAtUnixMS   int64  `json:"run_at_unix_ms"`
	RecordSHA256  string `json:"record_sha256"` // of /engine/validation.json as the image holds it
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// EngineValidationFromRecord reads the image's /engine/validation.json
// (written by `python -m fairsim validate`) for the engine image.
func EngineValidationFromRecord(image string, record []byte) (*EngineValidation, error) {
	var r struct {
		SuiteVersion  string `json:"suite_version"`
		EngineVersion string `json:"engine_version"`
		Architecture  string `json:"architecture"`
		Passed        *bool  `json:"passed"`
		RunAtUnixMS   int64  `json:"run_at_unix_ms"`
	}
	if err := json.Unmarshal(record, &r); err != nil {
		return nil, fmt.Errorf("releasemanifest: engine validation record: %w", err)
	}
	if r.Passed == nil || r.SuiteVersion == "" || r.EngineVersion == "" || r.Architecture == "" || r.RunAtUnixMS <= 0 {
		return nil, errors.New("releasemanifest: engine validation record: suite_version, engine_version, architecture, passed and run_at_unix_ms are required")
	}
	sum := sha256.Sum256(record)
	return &EngineValidation{
		Image: image, SuiteVersion: r.SuiteVersion, EngineVersion: r.EngineVersion, Architecture: r.Architecture,
		Passed: *r.Passed, RunAtUnixMS: r.RunAtUnixMS, RecordSHA256: hex.EncodeToString(sum[:]),
	}, nil
}

func (v *EngineValidation) validate(images map[string]string) error {
	if v.Image == "" || v.Image != images[EngineComponent] {
		return fmt.Errorf("releasemanifest: the engine validation is for %q, the engine image is %q", v.Image, images[EngineComponent])
	}
	if v.SuiteVersion == "" || v.EngineVersion == "" || v.Architecture == "" || v.RunAtUnixMS <= 0 || !hex64.MatchString(v.RecordSHA256) {
		return errors.New("releasemanifest: the engine validation is incomplete")
	}
	return nil
}

// EngineCheck is the release gate (F-005 AC-21): the manifest names an
// engine image whose validation record passed. It returns a detail line
// for the release-check report.
func (m *Manifest) EngineCheck() (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}
	v := m.EngineValidation
	switch {
	case m.Images[EngineComponent] == "":
		return "", errors.New("the release manifest names no engine image")
	case v == nil:
		return "", errors.New("the release manifest has no engine validation record")
	case !v.Passed:
		return "", fmt.Errorf("the engine image %s failed its validation suite (suite %s)", v.Image, v.SuiteVersion)
	}
	return fmt.Sprintf("engine %s (%s) passed validation suite %s; record sha256 %s", v.EngineVersion, v.Architecture, v.SuiteVersion, v.RecordSHA256), nil
}

// EngineCheckFile reads an (unsigned) manifest file and runs EngineCheck.
func EngineCheckFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("no release manifest given (-manifest): the engine validation record cannot be checked")
	}
	b, err := os.ReadFile(path) // #nosec G304 -- release-pipeline operator input
	if err != nil {
		return "", err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return m.EngineCheck()
}
