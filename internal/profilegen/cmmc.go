package profilegen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// In-repo profiles (F-015 T-04; design §4.2). Both are generated from pinned
// sources so they can be reviewed as diffs and rebuilt reproducibly:
//
//   - cmmc-l2-r2: the 800-53r5 controls that NIST SP 800-171 Rev 2's 110
//     requirements map to. Rev 2 -> Rev 3 comes from NIST's change analysis,
//     Rev 3 -> 800-53r5 from the source controls in NIST's Rev 3 OSCAL
//     catalog; requirements Rev 3 withdrew without a successor come from
//     supplement.yaml (Rev 2 Appendix D). The 110-row table is written to
//     mapping.md for review.
//   - enterprise-baseline: NIST 800-53r5 Moderate's selection, unchanged; its
//     relaxations are setting values in the bindings (T-05), each with a
//     platform_choice rationale.

// Pinned inputs, relative to third_party/oscal.
const (
	pinNIST80053r5Catalog  = "nist/sp800-53r5/NIST_SP-800-53_rev5_catalog.json"
	pinNIST80053r5Moderate = "nist/sp800-53r5/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json"
	pinNIST800171r3Catalog = "nist/sp800-171r3/NIST_SP800-171_rev3_catalog.json"
	pinNIST800171r2to3     = "nist/sp800-171r2/sp800-171r2-to-r3-analysis.xlsx"
	changeAnalysisSheet    = "Change Analysis 800-171 R2-R3"
)

// Supplement is profiles/cmmc-l2-r2/supplement.yaml.
type Supplement struct {
	Profile struct {
		ID        string `yaml:"id"`
		Title     string `yaml:"title"`
		Version   string `yaml:"version"`
		Published string `yaml:"published"`
	} `yaml:"profile"`
	Errata []struct {
		R2ID   string `yaml:"r2_id"`
		Reason string `yaml:"reason"`
	} `yaml:"errata"`
	NoRev3Successor []struct {
		R2ID      string `yaml:"r2_id"`
		Rev3Note  string `yaml:"rev3_note"`
		AppendixD struct {
			Table        string   `yaml:"table"`
			Rev4Controls []string `yaml:"rev4_controls"`
		} `yaml:"appendix_d"`
		Controls []string `yaml:"controls"`
		Review   string   `yaml:"review"`
	} `yaml:"no_rev3_successor"`
	// Signoff records the human review of mapping.md (T-04 verification).
	Signoff *struct {
		By string `yaml:"by"`
		On string `yaml:"on"`
	} `yaml:"signoff"`
}

// MappingRow maps one Rev 2 requirement to 800-53r5 controls.
type MappingRow struct {
	R2ID        string
	Family      string
	Requirement string
	Rev3        []string // Rev 3 requirement ids, e.g. "03.01.12"
	Basis       string   // "rev3" or "appendix-d"
	Controls    []string // 800-53r5 control ids, sorted
	Note        string
}

var (
	r2IDRE   = regexp.MustCompile(`^3\.\d{1,2}\.\d{1,2}$`)
	r3RefRE  = regexp.MustCompile(`\b0\d\.\d{2}[. ]\d{2}\b`)
	ctlRefRE = regexp.MustCompile(`^([A-Z]{2})-(\d{2})(?:\((\d{2})\))?$`)
)

// controlID turns a reference title like "AC-02(03)" into "ac-2.3".
func controlID(title string) (string, bool) {
	m := ctlRefRE.FindStringSubmatch(title)
	if m == nil {
		return "", false
	}
	n, _ := strconv.Atoi(m[2])
	id := fmt.Sprintf("%s-%d", strings.ToLower(m[1]), n)
	if m[3] != "" {
		e, _ := strconv.Atoi(m[3])
		id += fmt.Sprintf(".%d", e)
	}
	return id, true
}

// CMMCMapping builds the 110-row Rev 2 -> 800-53r5 mapping.
func CMMCMapping(pinDir string, sup Supplement) ([]MappingRow, error) {
	rows, err := readSheet(filepath.Join(pinDir, pinNIST800171r2to3), changeAnalysisSheet)
	if err != nil {
		return nil, err
	}
	r3Controls, err := rev3SourceControls(filepath.Join(pinDir, pinNIST800171r3Catalog))
	if err != nil {
		return nil, err
	}
	r5, err := controlIndex(filepath.Join(pinDir, pinNIST80053r5Catalog))
	if err != nil {
		return nil, err
	}

	errata := map[string]bool{}
	for _, e := range sup.Errata {
		errata[e.R2ID] = true
	}
	fallback := map[string]int{}
	for i, s := range sup.NoRev3Successor {
		fallback[s.R2ID] = i
	}
	usedErrata, usedFallback := map[string]bool{}, map[string]bool{}

	var out []MappingRow
	for _, r := range rows[1:] {
		id := strings.TrimSpace(r["C"])
		if id == "" {
			continue
		}
		if !r2IDRE.MatchString(id) {
			return nil, fmt.Errorf("cmmc: unexpected Rev 2 identifier %q", id)
		}
		if errata[id] {
			usedErrata[id] = true
			continue
		}
		row := MappingRow{R2ID: id, Family: strings.TrimSpace(r["A"]), Requirement: normalizeText(r["D"])}
		withdrawn := strings.TrimSpace(r["H"]) == "Withdrawn"
		text := strings.TrimSpace(r["I"])
		switch {
		case !withdrawn:
			row.Rev3 = []string{strings.TrimSpace(r["G"])}
		case strings.Contains(text, "Incorporated into") || strings.Contains(text, "Addressed by"):
			for _, ref := range r3RefRE.FindAllString(text, -1) {
				row.Rev3 = append(row.Rev3, ref[:5]+"."+ref[6:])
			}
		}
		if len(row.Rev3) > 0 {
			row.Basis = "rev3"
			for _, r3 := range row.Rev3 {
				cs, ok := r3Controls[r3]
				if !ok {
					return nil, fmt.Errorf("cmmc: %s maps to Rev 3 %s, which the Rev 3 catalog does not have", id, r3)
				}
				row.Controls = append(row.Controls, cs...)
			}
			if withdrawn {
				row.Note = "Withdrawn in Rev 3: " + normalizeText(text)
			}
		} else {
			i, ok := fallback[id]
			if !ok {
				return nil, fmt.Errorf("cmmc: %s has no Rev 3 successor (%q) and no supplement entry", id, normalizeText(text))
			}
			usedFallback[id] = true
			f := sup.NoRev3Successor[i]
			if normalizeText(f.Rev3Note) != normalizeText(text) {
				return nil, fmt.Errorf("cmmc: supplement for %s says %q, NIST's change analysis says %q", id, f.Rev3Note, normalizeText(text))
			}
			row.Basis = "appendix-d"
			row.Controls = append(row.Controls, f.Controls...)
			row.Note = fmt.Sprintf("Withdrawn in Rev 3 (%s). Appendix %s: %s.", normalizeText(text), f.AppendixD.Table, strings.Join(f.AppendixD.Rev4Controls, ", "))
			if f.Review != "" {
				row.Note += " " + f.Review
			}
			if len(f.Controls) == 0 && f.Review == "" {
				return nil, fmt.Errorf("cmmc: %s maps to no control; the supplement must explain why", id)
			}
		}
		slices.Sort(row.Controls)
		row.Controls = slices.Compact(row.Controls)
		for _, c := range row.Controls {
			st, ok := r5[c]
			if !ok {
				return nil, fmt.Errorf("cmmc: %s maps to %s, which 800-53r5 does not have", id, c)
			}
			if st == "withdrawn" {
				return nil, fmt.Errorf("cmmc: %s maps to %s, which is withdrawn in 800-53r5", id, c)
			}
		}
		out = append(out, row)
	}
	for id := range errata {
		if !usedErrata[id] {
			return nil, fmt.Errorf("cmmc: erratum %s matches no row; remove it", id)
		}
	}
	for id := range fallback {
		if !usedFallback[id] {
			return nil, fmt.Errorf("cmmc: supplement entry %s is not needed (the chain maps it); remove it", id)
		}
	}
	if len(out) != 110 {
		return nil, fmt.Errorf("cmmc: mapped %d Rev 2 requirements, want 110", len(out))
	}
	return out, nil
}

// rev3SourceControls maps each Rev 3 requirement ("03.01.12") to the
// 800-53r5 controls among its references.
func rev3SourceControls(file string) (map[string][]string, error) {
	doc, err := readJSON(file)
	if err != nil {
		return nil, err
	}
	cat := doc["catalog"].(obj)
	titles := map[string]string{}
	for _, r := range resources(cat) {
		titles["#"+str(r.(obj)["uuid"])] = str(r.(obj)["title"])
	}
	out := map[string][]string{}
	var walk func(n obj)
	walk = func(n obj) {
		for _, k := range []string{"groups", "controls"} {
			for _, x := range list(n[k]) {
				x := x.(obj)
				if k == "controls" {
					id := strings.TrimPrefix(str(x["id"]), "SP_800_171_")
					for _, l := range list(x["links"]) {
						if c, ok := controlID(titles[str(l.(obj)["href"])]); ok {
							out[id] = append(out[id], c)
						}
					}
				}
				walk(x)
			}
		}
	}
	walk(cat)
	return out, nil
}

// controlIndex maps every control id in a catalog to its status prop.
func controlIndex(file string) (map[string]string, error) {
	doc, err := readJSON(file)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	var walk func(n obj)
	walk = func(n obj) {
		for _, k := range []string{"groups", "controls"} {
			for _, x := range list(n[k]) {
				x := x.(obj)
				if k == "controls" {
					status := ""
					for _, p := range list(x["props"]) {
						if str(p.(obj)["name"]) == "status" {
							status = str(p.(obj)["value"])
						}
					}
					out[str(x["id"])] = status
				}
				walk(x)
			}
		}
	}
	walk(doc["catalog"].(obj))
	return out, nil
}

func readJSON(file string) (obj, error) {
	b, err := os.ReadFile(file) // #nosec G304 -- pinned build input
	if err != nil {
		return nil, err
	}
	var doc obj
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return doc, nil
}

// LoadSupplement reads and strictly decodes a supplement file.
func LoadSupplement(file string) (Supplement, error) {
	var s Supplement
	b, err := os.ReadFile(file) // #nosec G304 -- build-time input
	if err != nil {
		return s, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return s, fmt.Errorf("%s: %w", file, err)
	}
	return s, nil
}

// profileDocument assembles an OSCAL profile importing one pinned source.
func profileDocument(id, title, version, published, remarks, sourceURL, sourceTitle string, imp obj) obj {
	res := uuidV5("fair-profile-source|" + id + "|" + sourceURL)
	imp["href"] = "#" + res
	return obj{"profile": obj{
		"uuid": uuidV5("fair-profile|" + id + "|" + version),
		"metadata": obj{
			"title": title, "published": published, "last-modified": published, "version": version, "oscal-version": "1.2.3",
			"props":   []any{obj{"name": "resolution-tool", "value": Tool}},
			"remarks": remarks,
		},
		"imports": []any{imp},
		"merge":   obj{"as-is": true},
		"back-matter": obj{"resources": []any{obj{
			"uuid": res, "title": sourceTitle,
			"rlinks": []any{obj{"href": sourceURL, "media-type": "application/oscal+json"}},
		}}},
	}}
}

// CMMCProfile builds the cmmc-l2-r2 profile from the mapping. Selected
// enhancements bring their base control, which the resolver requires.
func CMMCProfile(l *PinnedLoader, sup Supplement, rows []MappingRow) (map[string]any, error) {
	src, ok := l.SourceOf(pinNIST80053r5Catalog)
	if !ok {
		return nil, fmt.Errorf("cmmc: %s is not pinned", pinNIST80053r5Catalog)
	}
	set := map[string]bool{}
	for _, r := range rows {
		for _, c := range r.Controls {
			set[c] = true
			if base, _, isEnh := strings.Cut(c, "."); isEnh {
				set[base] = true
			}
		}
	}
	ids := make([]any, 0, len(set))
	for _, c := range sortControls(set) {
		ids = append(ids, c)
	}
	p := sup.Profile
	return profileDocument(p.ID, p.Title, p.Version, p.Published,
		"Generated by FAIR profilegen from NIST sources: the SP 800-171 Rev 2 to Rev 3 change analysis, the SP 800-171 Rev 3 OSCAL catalog's source controls, and SP 800-171 Rev 2 Appendix D for requirements Rev 3 withdrew (profiles/cmmc-l2-r2/supplement.yaml). Requirement-level mapping: profiles/cmmc-l2-r2/mapping.md. Parameter values are set by the platform's setting bindings.",
		src, "NIST SP 800-53 Rev 5 catalog (usnistgov/oscal-content v1.6.0)",
		obj{"include-controls": []any{obj{"with-ids": ids}}}), nil
}

// EnterpriseProfile builds the enterprise-baseline profile: NIST 800-53r5
// Moderate, unchanged.
func EnterpriseProfile(l *PinnedLoader, version, published string) (map[string]any, error) {
	src, ok := l.SourceOf(pinNIST80053r5Moderate)
	if !ok {
		return nil, fmt.Errorf("enterprise: %s is not pinned", pinNIST80053r5Moderate)
	}
	return profileDocument("enterprise-baseline", "Enterprise Baseline (NIST SP 800-53 Rev 5 Moderate)", version, published,
		"Generated by FAIR profilegen. The control selection is NIST SP 800-53 Rev 5 Moderate, unchanged. Enterprise Baseline relaxations are setting values in the platform's bindings, each with a written platform_choice rationale (F-015 design §4.1-4.2).",
		src, "NIST SP 800-53 Rev 5 Moderate baseline profile (usnistgov/oscal-content v1.6.0)",
		obj{"include-all": obj{}}), nil
}

// sortControls orders control ids by family, number and enhancement.
func sortControls(set map[string]bool) []string {
	ids := make([]string, 0, len(set))
	for c := range set {
		ids = append(ids, c)
	}
	key := func(c string) (string, int, int) {
		fam, rest, _ := strings.Cut(c, "-")
		num, enh, _ := strings.Cut(rest, ".")
		n, _ := strconv.Atoi(num)
		e, _ := strconv.Atoi(enh)
		return fam, n, e
	}
	slices.SortFunc(ids, func(a, b string) int {
		fa, na, ea := key(a)
		fb, nb, eb := key(b)
		if c := strings.Compare(fa, fb); c != 0 {
			return c
		}
		if na != nb {
			return na - nb
		}
		return ea - eb
	})
	return ids
}

// MappingMarkdown renders the review table (T-04 verification).
func MappingMarkdown(sup Supplement, rows []MappingRow, selected int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s: requirement mapping\n\n", sup.Profile.Title)
	b.WriteString("Generated by FAIR profilegen (`internal/profilegen/cmmc.go`); do not edit. Sources are pinned in `third_party/oscal/MANIFEST.json`.\n\n")
	b.WriteString("- **rev3**: NIST's SP 800-171 Rev 2 to Rev 3 change analysis, then the 800-53r5 source controls of the Rev 3 requirement in NIST's Rev 3 OSCAL catalog.\n")
	b.WriteString("- **appendix-d**: Rev 3 withdrew the requirement without a successor; mapped from Rev 2 Appendix D (`profiles/cmmc-l2-r2/supplement.yaml`).\n\n")
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.Basis]++
	}
	fmt.Fprintf(&b, "%d requirements (%d via rev3, %d via appendix-d); the profile selects %d 800-53r5 controls, including base controls of selected enhancements.\n\n", len(rows), counts["rev3"], counts["appendix-d"], selected)
	if s := sup.Signoff; s != nil && s.By != "" && s.On != "" {
		fmt.Fprintf(&b, "**Review (T-04 verification):** reviewed and signed off by %s on %s.\n\n", s.By, s.On)
	} else {
		b.WriteString("**Review (T-04 verification):** reviewed by ______ on ______.\n\n")
	}
	b.WriteString("| Rev 2 | Requirement | Rev 3 | Basis | 800-53r5 controls | Note |\n|---|---|---|---|---|---|\n")
	esc := strings.NewReplacer("|", `\|`, "\n", " ")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", r.R2ID, esc.Replace(r.Requirement), strings.Join(r.Rev3, ", "), r.Basis,
			strings.Join(r.Controls, ", "), esc.Replace(r.Note))
	}
	return b.String()
}

// InRepoProfiles generates every file under profiles/ from the pinned sources
// in pinDir and the hand-authored inputs in profilesDir, keyed by path
// relative to profilesDir. `profilegen profiles` writes them; a test checks
// the committed files match.
func InRepoProfiles(pinDir, profilesDir string) (map[string][]byte, error) {
	l, err := NewPinnedLoader(pinDir)
	if err != nil {
		return nil, err
	}
	sup, err := LoadSupplement(filepath.Join(profilesDir, "cmmc-l2-r2", "supplement.yaml"))
	if err != nil {
		return nil, err
	}
	rows, err := CMMCMapping(pinDir, sup)
	if err != nil {
		return nil, err
	}
	cmmc, err := CMMCProfile(l, sup, rows)
	if err != nil {
		return nil, err
	}
	var meta struct {
		Version   string `yaml:"version"`
		Published string `yaml:"published"`
	}
	mb, err := os.ReadFile(filepath.Join(profilesDir, "enterprise-baseline", "meta.yaml")) // #nosec G304 -- build-time input
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(mb))
	dec.KnownFields(true)
	if err := dec.Decode(&meta); err != nil {
		return nil, fmt.Errorf("enterprise-baseline/meta.yaml: %w", err)
	}
	ent, err := EnterpriseProfile(l, meta.Version, meta.Published)
	if err != nil {
		return nil, err
	}
	enc := func(v any) ([]byte, error) {
		b, err := json.MarshalIndent(v, "", "  ")
		return append(b, '\n'), err
	}
	out := map[string][]byte{}
	if out["cmmc-l2-r2/profile.json"], err = enc(cmmc); err != nil {
		return nil, err
	}
	if out["enterprise-baseline/profile.json"], err = enc(ent); err != nil {
		return nil, err
	}
	selected := len(list(list(cmmc["profile"].(obj)["imports"])[0].(obj)["include-controls"].([]any)[0].(obj)["with-ids"]))
	out["cmmc-l2-r2/mapping.md"] = []byte(MappingMarkdown(sup, rows, selected))
	return out, nil
}
