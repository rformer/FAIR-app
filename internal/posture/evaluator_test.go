package posture

import (
	"slices"
	"strings"
	"testing"

	"github.com/rformer/fair-app/pkg/settings"
)

func TestControlsForParams(t *testing.T) {
	got := ControlsForParams([]string{"ac-02.03_odp.02", "ac-11_odp.02", "ac-11_odp.01", "ia-02.08_odp", "sc-13_odp.02", "not-a-param"})
	if want := []string{"AC-2(3)", "AC-11", "IA-2(8)", "SC-13"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// Every F-001 parameter names a control.
	for _, d := range settings.F001Defs() {
		if len(ControlsForParams(d.Params)) != distinctControls(d.Params) {
			t.Errorf("%s: params %v give controls %v", d.Key, d.Params, ControlsForParams(d.Params))
		}
	}
}

// distinctControls counts the distinct controls params belong to.
func distinctControls(params []string) int {
	seen := map[string]bool{}
	for _, p := range params {
		c, _, _ := strings.Cut(p, "_odp")
		seen[c] = true
	}
	return len(seen)
}
