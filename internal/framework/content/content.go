// Package content is the control frameworks the platform ships (F-013
// T-04, OQ1, OQ2): NIST SP 800-53 Rev 5 at 5.2.0 and at 5.1.1 (the version
// FedRAMP's baselines and SP 800-171r3's references name), its low,
// moderate, high and privacy baselines, NIST SP 800-171r3, the FedRAMP
// Rev 5 low, moderate, high and LI-SaaS baselines, and a crosswalk from
// 800-171r3 to 800-53 5.1.1 built from the 800-171r3 catalog's own
// references. All of it is public-domain US government content, built from
// the pinned files of third_party/oscal (MANIFEST.json records their
// sources and digests) into shipped.json.gz, embedded here and synced by
// iam migrate (framework.sync_shipped). TestShippedUpToDate rebuilds it;
// FAIR_UPDATE_GOLDEN=1 rewrites it after a pin changes.
package content

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	oscaltypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-2-3"

	"github.com/rformer/fair-app/internal/framework"
)

// Shipped is the release's frameworks.
type Shipped struct {
	Format     string      `json:"format"` // fair.shipped-frameworks.v1
	Versions   []Version   `json:"versions"`
	Baselines  []Baseline  `json:"baselines"`
	Crosswalks []Crosswalk `json:"crosswalks"`
}

// Version is a shipped framework version and its source file's digest.
type Version struct {
	framework.Version
	SHA256 string `json:"sha256"`
	Origin string `json:"origin"` // the pinned file it was built from
}

// Baseline is a shipped baseline, by the version it selects from.
type Baseline struct {
	framework.Baseline
	Version framework.Ref `json:"version"`
	SHA256  string        `json:"sha256"`
	Origin  string        `json:"origin"`
}

// Crosswalk is a shipped crosswalk.
type Crosswalk struct {
	framework.Crosswalk
	SHA256 string `json:"sha256"`
	Origin string `json:"origin"` // the pinned file it was built from
}

// Format is the shipped payload's format.
const Format = "fair.shipped-frameworks.v1"

//go:embed shipped.json.gz
var shipped []byte

// SyncPayload is the embedded content as framework.sync_shipped takes it.
func SyncPayload() ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(shipped))
	if err != nil {
		return nil, fmt.Errorf("content: %w", err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("content: %w", err)
	}
	var s Shipped
	if err := json.Unmarshal(b, &s); err != nil || s.Format != Format {
		return nil, fmt.Errorf("content: not the shipped frameworks (%v)", err)
	}
	return b, nil
}

// Families of the shipped frameworks.
var (
	NIST80053  = framework.Family{Key: "nist-800-53", Title: "NIST SP 800-53, Security and Privacy Controls", Publisher: "NIST"}
	NIST800171 = framework.Family{Key: "nist-800-171", Title: "NIST SP 800-171, Protecting Controlled Unclassified Information", Publisher: "NIST"}
)

// The pinned files (third_party/oscal).
const (
	cat53       = "nist/sp800-53r5/NIST_SP-800-53_rev5_catalog.json"
	cat53v511   = "nist/sp800-53r5-oscal-content-v1.3.0/NIST_SP-800-53_rev5_catalog.json"
	cat171      = "nist/sp800-171r3/NIST_SP800-171_rev3_catalog.json"
	label171    = "Rev 3 (1.1.0)"
	sourceNIST  = "usnistgov/oscal-content"
	sourceFedRA = "OSCAL-Foundation/fedramp-resources"
)

var baselines = []struct{ key, file, source string }{
	{"nist-low", "nist/sp800-53r5/NIST_SP-800-53_rev5_LOW-baseline_profile.json", sourceNIST},
	{"nist-moderate", "nist/sp800-53r5/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json", sourceNIST},
	{"nist-high", "nist/sp800-53r5/NIST_SP-800-53_rev5_HIGH-baseline_profile.json", sourceNIST},
	{"nist-privacy", "nist/sp800-53r5/NIST_SP-800-53_rev5_PRIVACY-baseline_profile.json", sourceNIST},
	{"fedramp-low", "fedramp/rev5/FedRAMP_rev5_LOW-baseline_profile.json", sourceFedRA},
	{"fedramp-moderate", "fedramp/rev5/FedRAMP_rev5_MODERATE-baseline_profile.json", sourceFedRA},
	{"fedramp-high", "fedramp/rev5/FedRAMP_rev5_HIGH-baseline_profile.json", sourceFedRA},
	{"fedramp-li-saas", "fedramp/rev5/FedRAMP_rev5_LI-SaaS-baseline_profile.json", sourceFedRA},
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Build builds the shipped content from the pinned files in pinDir
// (third_party/oscal).
func Build(pinDir string) (*Shipped, error) {
	read := func(rel string) ([]byte, error) {
		return os.ReadFile(filepath.Join(pinDir, filepath.FromSlash(rel))) // #nosec G304 -- the repository's own pinned files
	}
	s := &Shipped{Format: Format}
	catalogs := map[string]*framework.Version{}
	for _, c := range []struct {
		file   string
		family framework.Family
		label  string
	}{{cat53, NIST80053, ""}, {cat53v511, NIST80053, ""}, {cat171, NIST800171, label171}} {
		raw, err := read(c.file)
		if err != nil {
			return nil, err
		}
		v, err := framework.ParseCatalog(raw, c.family)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.file, err)
		}
		if c.label != "" {
			v.Label = c.label
		}
		catalogs[c.file] = v
		s.Versions = append(s.Versions, Version{Version: *v, SHA256: digest(raw), Origin: sourceNIST + ":" + c.file})
	}
	// Imports resolve by file name to the pinned files: the NIST profiles
	// name the current catalog, FedRAMP's the tailoring profile, which names
	// the 5.1.1 catalog (oscal-content v1.3.0). Nothing is fetched.
	lookup := func(href string, res *oscaltypes.Resource) (*framework.Import, error) {
		refs := []string{href}
		if res != nil && res.Rlinks != nil {
			for _, l := range *res.Rlinks {
				refs = append(refs, l.Href)
			}
		}
		for _, r := range refs {
			switch {
			case strings.HasPrefix(path.Base(r), "FedRAMP_rev5_") && strings.HasSuffix(r, "_profile.json"):
				// The tailoring profile, or another FedRAMP baseline (LI-SaaS
				// imports the low baseline), from the same pinned commit.
				raw, err := read("fedramp/rev5/" + path.Base(r))
				if err != nil {
					return nil, err
				}
				return &framework.Import{Profile: raw}, nil
			case path.Base(r) == "NIST_SP-800-53_rev5_catalog.json" && strings.Contains(r, "v1.3.0"):
				return &framework.Import{Catalog: catalogs[cat53v511]}, nil
			case path.Base(r) == "NIST_SP-800-53_rev5_catalog.json":
				return &framework.Import{Catalog: catalogs[cat53]}, nil
			}
		}
		return nil, fmt.Errorf("names no pinned catalog (%s)", href)
	}
	for _, b := range baselines {
		raw, err := read(b.file)
		if err != nil {
			return nil, err
		}
		bl, of, err := framework.ParseProfile(raw, b.key, lookup)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", b.file, err)
		}
		s.Baselines = append(s.Baselines, Baseline{Baseline: *bl, Version: framework.Ref{Family: of.Family.Key, Version: of.Label},
			SHA256: digest(raw), Origin: b.source + ":" + b.file})
	}
	x, raw, err := crosswalk171(read, catalogs[cat171], catalogs[cat53v511])
	if err != nil {
		return nil, err
	}
	s.Crosswalks = append(s.Crosswalks, Crosswalk{Crosswalk: *x, SHA256: digest(raw), Origin: sourceNIST + ":" + cat171})
	return s, nil
}

// 800-53 control labels as 800-171r3 cites them: AC-02, AC-02(03).
var citeRE = regexp.MustCompile(`^([A-Z]{2})-0*(\d+)(?:\(0*(\d+)\))?$`)

// crosswalk171 relates each 800-171r3 requirement to the 800-53 5.1.1
// controls its catalog references (back-matter resources citing SP 800-53
// 5.1.1). NIST does not type these relationships; they are recorded as
// intersects, which coverage never counts as full (design §3.3).
func crosswalk171(read func(string) ([]byte, error), from, to *framework.Version) (*framework.Crosswalk, []byte, error) {
	raw, err := read(cat171)
	if err != nil {
		return nil, nil, err
	}
	var doc struct {
		Catalog oscaltypes.Catalog `json:"catalog"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, err
	}
	cited := map[string]string{} // resource uuid -> 800-53 identifier
	if doc.Catalog.BackMatter != nil && doc.Catalog.BackMatter.Resources != nil {
		for _, r := range *doc.Catalog.BackMatter.Resources {
			if r.Rlinks == nil || !slices.ContainsFunc(*r.Rlinks, func(l oscaltypes.ResourceLink) bool { return strings.Contains(l.Href, "SP_800_53_5_1_1") }) {
				continue
			}
			if m := citeRE.FindStringSubmatch(strings.TrimSpace(r.Title)); m != nil {
				id := strings.ToLower(m[1]) + "-" + m[2]
				if m[3] != "" {
					id += "." + m[3]
				}
				cited[r.UUID] = id
			}
		}
	}
	targets := map[string]bool{}
	for _, r := range to.Requirements {
		targets[r.Identifier] = true
	}
	sources := map[string]bool{}
	for _, r := range from.Requirements {
		if !r.Withdrawn {
			sources[r.Identifier] = true
		}
	}
	x := &framework.Crosswalk{Format: framework.CrosswalkFormat, Title: "NIST SP 800-171r3 to SP 800-53r5 (5.1.1), from the 800-171r3 catalog's references",
		Publisher: "NIST", Label: from.Label, Source: framework.Ref{Family: from.Family.Key, Version: from.Label},
		Target: framework.Ref{Family: to.Family.Key, Version: to.Label}}
	seen := map[[2]string]bool{}
	var walk func(cs *[]oscaltypes.Control)
	walk = func(cs *[]oscaltypes.Control) {
		if cs == nil {
			return
		}
		for _, c := range *cs {
			if sources[c.ID] && c.Links != nil {
				for _, l := range *c.Links {
					t, ok := cited[strings.TrimPrefix(l.Href, "#")]
					if l.Rel != "reference" || !ok || !targets[t] || seen[[2]string{c.ID, t}] {
						continue
					}
					seen[[2]string{c.ID, t}] = true
					x.Relationships = append(x.Relationships, framework.Link{Source: c.ID, Target: t, Relationship: framework.Intersects})
				}
			}
			walk(c.Controls)
		}
	}
	var groups func(gs *[]oscaltypes.Group)
	groups = func(gs *[]oscaltypes.Group) {
		if gs == nil {
			return
		}
		for _, g := range *gs {
			walk(g.Controls)
			groups(g.Groups)
		}
	}
	walk(doc.Catalog.Controls)
	groups(doc.Catalog.Groups)
	if len(x.Relationships) == 0 {
		return nil, nil, fmt.Errorf("%s: no references to SP 800-53 5.1.1 found", cat171)
	}
	return x, raw, nil
}

// Encode is the content as embedded: canonical JSON, gzip without a
// timestamp (deterministic).
func Encode(s *Shipped) ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	zw, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
