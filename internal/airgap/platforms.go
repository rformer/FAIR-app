package airgap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
)

// PlatformsFormat identifies platforms.json (OQ14): the Kubernetes versions
// and distributions a release supports, and how each is verified (the
// install matrix's CI runs, or recorded manual runs; design §3.17).
const PlatformsFormat = "fair.platforms.v1"

// PlatformsDoc is platforms.json.
type PlatformsDoc struct {
	Format     string `json:"format"`
	Kubernetes struct {
		Minimum string   `json:"minimum"`
		Tested  []string `json:"tested"`
	} `json:"kubernetes"`
	Distributions []Distribution `json:"distributions"`
}

// Distribution is one supported distribution.
type Distribution struct {
	Name           string   `json:"name"`
	Title          string   `json:"title"`
	Verification   string   `json:"verification"` // ci or recorded
	Configurations []string `json:"configurations"`
}

var (
	minorRE = regexp.MustCompile(`^1\.([0-9]{2})$`)
	distRE  = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	configs = []string{"bundled", "brought", "connected", "air-gapped"}
)

// ParsePlatforms decodes platforms.json strictly and checks it.
func ParsePlatforms(b []byte) (*PlatformsDoc, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var p PlatformsDoc
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("platforms.json: %w", err)
	}
	var errs []error
	if p.Format != PlatformsFormat {
		errs = append(errs, fmt.Errorf("platforms.json: format %q, want %q", p.Format, PlatformsFormat))
	}
	if !minorRE.MatchString(p.Kubernetes.Minimum) || len(p.Kubernetes.Tested) == 0 {
		errs = append(errs, errors.New("platforms.json: kubernetes.minimum (1.NN) and kubernetes.tested are required"))
	}
	for _, v := range p.Kubernetes.Tested {
		if !minorRE.MatchString(v) || v < p.Kubernetes.Minimum {
			errs = append(errs, fmt.Errorf("platforms.json: tested version %q is not 1.NN at or above the minimum", v))
		}
	}
	seen := map[string]bool{}
	for _, d := range p.Distributions {
		if !distRE.MatchString(d.Name) || seen[d.Name] || d.Title == "" || (d.Verification != "ci" && d.Verification != "recorded") || len(d.Configurations) == 0 {
			errs = append(errs, fmt.Errorf("platforms.json: distribution %q: a unique name, a title, verification ci or recorded, configurations", d.Name))
		}
		seen[d.Name] = true
		for _, c := range d.Configurations {
			if !slices.Contains(configs, c) {
				errs = append(errs, fmt.Errorf("platforms.json: %s: configuration %q", d.Name, c))
			}
		}
	}
	if len(p.Distributions) == 0 {
		errs = append(errs, errors.New("platforms.json: no distributions"))
	}
	return &p, errors.Join(errs...)
}
