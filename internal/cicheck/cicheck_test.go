package cicheck

import (
	"path/filepath"
	"slices"
	"testing"
)

var root = filepath.Join("..", "..")

// F-012 T-03 (F-012-AC-05; design §3.2): the images matrix builds and
// checks every image the Dockerfile defines.
func TestImageMatrixCoversDockerfile(t *testing.T) {
	targets, err := ImageTargets(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(targets, "posture") || slices.Contains(targets, "build") || slices.Contains(targets, "engine-build") {
		t.Fatalf("targets %v", targets)
	}
	w, err := LoadWorkflow(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if got := w.MatrixValues("images", "component"); !slices.Equal(got, targets) {
		t.Errorf("images matrix %v\nDockerfile targets %v", got, targets)
	}
}

// F-012 T-02 (F-012-AC-01; design §3.1): every pull-request job is a
// required check of the branch protection, and every required check is a
// job that reports.
func TestRequiredChecksCoverJobs(t *testing.T) {
	w, err := LoadWorkflow(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	required, err := RequiredChecks(filepath.Join(root, "infra", "github", "variables.tf"))
	if err != nil {
		t.Fatal(err)
	}
	if got := w.CheckNames(); !slices.Equal(got, required) {
		t.Errorf("CI checks %v\nrequired %v", got, required)
	}
}
