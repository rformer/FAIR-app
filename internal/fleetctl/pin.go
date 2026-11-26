package fleetctl

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The pin is one JSON-patch line of the instance's kustomization.yaml:
//
//   - { op: replace, path: /spec/ref, value: { tag: v0.2.0, digest: "sha256:…" } }
//
// T-15's tag-only form (path /spec/ref/tag) is read too and replaced by
// the form above on the first promotion.
var pinLineRE = regexp.MustCompile(`(?m)^([ \t]*)- \{ ?op: replace, path: /spec/ref(?:/tag)?, value: [^\r\n]*?(\r?)$`)

type kustomization struct {
	Patches []struct {
		Target struct {
			Kind string `yaml:"kind"`
			Name string `yaml:"name"`
		} `yaml:"target"`
		Patch string `yaml:"patch"`
	} `yaml:"patches"`
}

// ReadPin returns the release pin of an instance's kustomization.yaml: the
// patch of OCIRepository fair-release that replaces spec.ref.
func ReadPin(b []byte) (Pin, error) {
	var k kustomization
	if err := yaml.Unmarshal(b, &k); err != nil {
		return Pin{}, err
	}
	var pins []Pin
	for _, p := range k.Patches {
		if p.Target.Kind != "OCIRepository" || p.Target.Name != "fair-release" {
			continue
		}
		var ops []struct {
			Op    string    `yaml:"op"`
			Path  string    `yaml:"path"`
			Value yaml.Node `yaml:"value"`
		}
		if err := yaml.Unmarshal([]byte(p.Patch), &ops); err != nil {
			return Pin{}, fmt.Errorf("the fair-release patch: %w", err)
		}
		for _, op := range ops {
			switch {
			case op.Op == "replace" && op.Path == "/spec/ref":
				var pin Pin
				if err := op.Value.Decode(&pin); err != nil {
					return Pin{}, fmt.Errorf("the release pin: %w", err)
				}
				pins = append(pins, pin)
			case op.Op == "replace" && op.Path == "/spec/ref/tag":
				pins = append(pins, Pin{Tag: op.Value.Value})
			case strings.HasPrefix(op.Path, "/spec/ref"):
				return Pin{}, fmt.Errorf("the release pin: unexpected %s %s", op.Op, op.Path)
			}
		}
	}
	if len(pins) != 1 {
		return Pin{}, fmt.Errorf("%d release pins (patches of OCIRepository fair-release on /spec/ref), want 1", len(pins))
	}
	if err := pins[0].Check(false); err != nil {
		return Pin{}, fmt.Errorf("the release pin: %w", err)
	}
	return pins[0], nil
}

// WritePin returns kustomization.yaml with its pin replaced by p, keeping
// every other byte, and checks the result reads back as p.
func WritePin(b []byte, p Pin) ([]byte, error) {
	if err := p.Check(false); err != nil {
		return nil, err
	}
	if n := len(pinLineRE.FindAllIndex(b, -1)); n != 1 {
		return nil, fmt.Errorf("%d release pin lines, want 1 (- { op: replace, path: /spec/ref, value: … } on one line)", n)
	}
	value := "{ tag: " + p.Tag + " }"
	if p.Digest != "" {
		value = "{ tag: " + p.Tag + `, digest: "` + p.Digest + `" }`
	}
	out := pinLineRE.ReplaceAll(b, []byte("${1}- { op: replace, path: /spec/ref, value: "+value+" }${2}"))
	got, err := ReadPin(out)
	if err != nil {
		return nil, err
	}
	if got != p {
		return nil, fmt.Errorf("the rewritten pin reads %s, want %s", got, p)
	}
	return out, nil
}

// setRollout returns rollout.yaml with the top-level keys previous and
// rolled_back_from set (a zero Pin removes the key), as one flow-style line
// each, keeping every other line.
func setRollout(text string, previous, rolledBack Pin) (string, error) {
	nl := "\n"
	if strings.Contains(text, "\r\n") {
		nl = "\r\n"
	}
	for _, kv := range []struct {
		key string
		pin Pin
	}{{"previous", previous}, {"rolled_back_from", rolledBack}} {
		re := regexp.MustCompile(`(?m)^` + kv.key + `:[^\n]*\n?`)
		if n := len(re.FindAllStringIndex(text, -1)); n > 1 {
			return "", fmt.Errorf("rollout.yaml: %s appears %d times", kv.key, n)
		}
		text = re.ReplaceAllString(text, "")
		if !kv.pin.IsZero() {
			if text != "" && !strings.HasSuffix(text, "\n") {
				text += nl
			}
			line := kv.key + ": { tag: " + kv.pin.Tag
			if kv.pin.Digest != "" {
				line += `, digest: "` + kv.pin.Digest + `"`
			}
			text += line + " }" + nl
		}
	}
	var rf rolloutFile
	if err := strictYAML([]byte(text), &rf); err != nil {
		return "", fmt.Errorf("rollout.yaml after the change: %w", err)
	}
	if rf.Previous != previous || rf.RolledBackFrom != rolledBack {
		return "", errors.New("rollout.yaml: previous or rolled_back_from is not on one line; fleetctl writes them as flow mappings")
	}
	return text, nil
}
