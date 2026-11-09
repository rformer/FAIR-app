// Package starter is the starter library shipped with each release (F-003
// AC-11; design §6.6): generic threat communities and guidance for each
// Open FAIR form of loss, written from Open FAIR concepts. iam migrate syncs
// it into risk.starter_entry; customers copy entries into a BU and adapt
// them. Every number in it is illustrative, and marked so.
package starter

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/rformer/fair-app/internal/risk/model"
)

//go:embed starter.json
var content []byte

// IllustrativeMark is the phrase every estimate's rationale carries.
const IllustrativeMark = "Illustrative only"

// Entry is one starter entry.
type Entry struct {
	Key          string          `json:"key"`
	Illustrative bool            `json:"illustrative"`
	Guidance     string          `json:"guidance"`
	Document     json.RawMessage `json:"document"`
}

// Library is the starter library of a release.
type Library struct {
	Release string  `json:"release"`
	About   string  `json:"about"`
	Entries []Entry `json:"entries"`
}

var keyRE = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)

// Load parses and checks the embedded library: unique keys, valid library
// documents, guidance, and every estimate marked illustrative.
func Load() (Library, error) {
	return Parse(content)
}

// Parse parses and checks a starter library.
func Parse(b []byte) (Library, error) {
	var l Library
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&l); err != nil {
		return l, fmt.Errorf("starter: %w", err)
	}
	if l.Release == "" || len(l.Entries) == 0 {
		return l, errors.New("starter: a release and entries are required")
	}
	seen := map[string]bool{}
	for _, e := range l.Entries {
		switch {
		case !keyRE.MatchString(e.Key):
			return l, fmt.Errorf("starter: bad key %q", e.Key)
		case seen[e.Key]:
			return l, fmt.Errorf("starter: %s listed twice", e.Key)
		case strings.TrimSpace(e.Guidance) == "" || len(e.Guidance) > model.MaxText:
			return l, fmt.Errorf("starter: %s: guidance is required, at most %d characters", e.Key, model.MaxText)
		}
		seen[e.Key] = true
		var head struct {
			Kind string `json:"kind"`
		}
		_ = json.Unmarshal(e.Document, &head)
		if head.Kind == model.KindScenario || head.Kind == model.KindControl {
			return l, fmt.Errorf("starter: %s: only library kinds", e.Key)
		}
		doc, problems := model.Validate(head.Kind, e.Document)
		if problems != nil {
			return l, fmt.Errorf("starter: %s: %w", e.Key, problems)
		}
		// AC-11: no number presented as industry data. An entry with any
		// estimate is marked illustrative, and so is each estimate.
		if n := bytes.Count(doc.Canonical, []byte(`"unit":`)); n > 0 {
			if !e.Illustrative {
				return l, fmt.Errorf("starter: %s holds example values but is not marked illustrative", e.Key)
			}
			if bytes.Count(doc.Canonical, []byte(`"rationale":"`+IllustrativeMark)) != n {
				return l, fmt.Errorf("starter: %s: every estimate's rationale must begin %q", e.Key, IllustrativeMark)
			}
		}
	}
	return l, nil
}

// SyncPayload is the JSON passed to risk.sync_starter at migrate: the
// release and each entry's canonical document.
func SyncPayload() ([]byte, error) {
	l, err := Load()
	if err != nil {
		return nil, err
	}
	type item struct {
		Key          string `json:"key"`
		Kind         string `json:"kind"`
		Illustrative bool   `json:"illustrative"`
		Guidance     string `json:"guidance"`
		Document     string `json:"document"` // canonical JSON
		Digest       string `json:"digest"`
	}
	out := struct {
		Release string `json:"release"`
		Entries []item `json:"entries"`
	}{Release: l.Release}
	for _, e := range l.Entries {
		var head struct {
			Kind string `json:"kind"`
		}
		_ = json.Unmarshal(e.Document, &head)
		doc, _ := model.Validate(head.Kind, e.Document)
		out.Entries = append(out.Entries, item{e.Key, head.Kind, e.Illustrative, e.Guidance, string(doc.Canonical), doc.Digest})
	}
	return json.Marshal(out)
}
