package risk

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/internal/risk/model/modeltest"
)

// engineBundleFile is the F-003 corpus scenario as an input bundle, built by
// BuildBundle. The engine's validation suite (F-005 T-09, design §3.6: the
// cross-feature check) simulates exactly these bytes, so the engine is
// validated on what the risk service sends it.
const engineBundleFile = "../../engine/fairsim/validation/f003_corpus_bundle.json"

// TestEngineValidationBundle keeps the engine's copy equal to what
// BuildBundle produces from modeltest. FAIR_UPDATE_GOLDEN=1 rewrites it.
func TestEngineValidationBundle(t *testing.T) {
	b := corpusBundle(t)
	if os.Getenv("FAIR_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(filepath.FromSlash(engineBundleFile), b.Canonical, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(filepath.FromSlash(engineBundleFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, b.Canonical) {
		t.Fatalf("%s is not what BuildBundle makes from modeltest; regenerate with FAIR_UPDATE_GOLDEN=1", engineBundleFile)
	}
}

func corpusBundle(t *testing.T) Bundle {
	t.Helper()
	valid := func(kind string, doc map[string]any) *model.Document {
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		d, problems := model.Validate(kind, raw)
		if len(problems) > 0 {
			t.Fatalf("%s: %v", kind, problems)
		}
		return d
	}
	s := valid(model.KindScenario, modeltest.Scenario())
	docs := map[string]*model.Document{
		model.KindAsset:           valid(model.KindAsset, modeltest.Asset()),
		model.KindThreatCommunity: valid(model.KindThreatCommunity, modeltest.ThreatCommunity()),
		model.KindControl:         valid(model.KindControl, modeltest.Control()),
	}
	pins := make([]BundlePin, 0, len(s.Pins))
	for _, p := range s.Pins {
		d := docs[p.Kind]
		if d == nil {
			t.Fatalf("no corpus document of kind %s", p.Kind)
		}
		pins = append(pins, BundlePin{Pointer: p.Pointer, Kind: p.Kind, ID: p.ID, Version: p.Version, Digest: d.Digest, Document: d.Canonical})
	}
	b, err := BuildBundle("USD", BundleScenario{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Version: 1, Digest: s.Digest, Document: s.Canonical}, pins)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
