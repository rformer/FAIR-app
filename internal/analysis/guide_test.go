package analysis

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// F-005 T-14 (AC-10): the failure codes the risk service records and the
// reproduction outcomes are documented in docs/guides/simulation.md (the
// engine's warning codes are checked by engine/tests/test_guide.py).
func TestGuideDocumentsCodes(t *testing.T) {
	b, err := os.ReadFile("../../docs/guides/simulation.md")
	if err != nil {
		t.Fatal(err)
	}
	guide := strings.ReplaceAll(string(b), "\r\n", "\n")
	table := func(title string) []string {
		_, rest, ok := strings.Cut(guide, "## "+title+"\n")
		if !ok {
			t.Fatalf("no section %q", title)
		}
		section, _, _ := strings.Cut(rest, "\n## ")
		var codes []string
		for _, m := range regexp.MustCompile("(?m)^\\| `([a-z_]+)` \\|").FindAllStringSubmatch(section, -1) {
			codes = append(codes, m[1])
		}
		slices.Sort(codes)
		return codes
	}
	failures := []string{FailInvalidBundle, FailNotValidated, FailUnavailable, FailInvalidResults, FailInternal}
	slices.Sort(failures)
	if got := table("Failure codes"); !slices.Equal(got, failures) {
		t.Errorf("failure codes in the guide %v, recorded %v", got, failures)
	}
	outcomes := []string{"match", "mismatch", "other_architecture", "other_version"}
	if got := table("Reproducibility"); !slices.Equal(got, outcomes) {
		t.Errorf("reproduction outcomes in the guide %v, want %v (analysis.finish_run)", got, outcomes)
	}
}
