// Package framework reads control frameworks (F-013): OSCAL catalogs and
// profiles (through internal/oscal, OSCAL 1.2.3), the simple formats
// fair.framework.v1 and fair.crosswalk.v1 (JSON or CSV), and compares
// framework versions. It only parses and checks: nothing is fetched (no
// href is followed, no back-matter resource read), and a file is refused
// whole, naming each problem by JSON pointer (or CSV row and column).
package framework

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Limits (F-013 OQ6; the database checks the same, PF034).
const (
	MaxFile          = 50 << 20
	MaxRequirements  = 20_000
	MaxRelationships = 200_000
	MaxMappings      = 500
	MaxProblems      = 1_000
	MaxProfileDepth  = 3
)

// Formats of the simple files.
const (
	FrameworkFormat = "fair.framework.v1"
	CrosswalkFormat = "fair.crosswalk.v1"
)

// Relationships between requirements (NIST IR 8278 set relationships).
const (
	Equal      = "equal"
	SubsetOf   = "subset_of"
	SupersetOf = "superset_of"
	Intersects = "intersects"
)

// Relationships are the crosswalk relationships.
var Relationships = []string{Equal, SubsetOf, SupersetOf, Intersects}

var (
	keyRE        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	identifierRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:()-]{0,99}$`)
	dateRE       = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// Family is a framework family.
type Family struct {
	Key       string `json:"key"`
	Title     string `json:"title"`
	Publisher string `json:"publisher,omitempty"`
}

// Requirement is a control or enhancement of a framework version.
type Requirement struct {
	Identifier       string   `json:"identifier"`
	Label            string   `json:"label,omitempty"`
	Title            string   `json:"title"`
	Statement        string   `json:"statement,omitempty"`
	Parent           string   `json:"parent,omitempty"`
	Withdrawn        bool     `json:"withdrawn,omitempty"`
	IncorporatedInto []string `json:"incorporated_into,omitempty"`
}

// Version is one framework version, ready to store.
type Version struct {
	Family       Family        `json:"family"`
	Label        string        `json:"label"`
	Title        string        `json:"title"`
	Published    string        `json:"published,omitempty"` // YYYY-MM-DD
	Format       string        `json:"format"`              // oscal or simple
	Requirements []Requirement `json:"requirements"`
}

// Problem is one reason a file is refused.
type Problem struct {
	Pointer string `json:"pointer"`
	Message string `json:"message"`
}

// Problems is a refused file's problems; it is an error.
type Problems []Problem

func (p Problems) Error() string {
	if len(p) == 0 {
		return "framework: no problems"
	}
	return fmt.Sprintf("framework: %d problems, first %s: %s", len(p), p[0].Pointer, p[0].Message)
}

// ErrFile is a file that is not the format at all.
var ErrFile = errors.New("framework: not a framework file")

type checker struct{ problems Problems }

func (c *checker) add(ptr, format string, args ...any) {
	if len(c.problems) < MaxProblems {
		c.problems = append(c.problems, Problem{Pointer: ptr, Message: fmt.Sprintf(format, args...)})
	}
}

func (c *checker) err() error {
	if len(c.problems) == 0 {
		return nil
	}
	return c.problems
}

func (c *checker) text(ptr, s string, min, max int) {
	n := utf8.RuneCountInString(s)
	switch {
	case !utf8.ValidString(s):
		c.add(ptr, "is not UTF-8")
	case strings.ContainsRune(s, 0):
		c.add(ptr, "holds a NUL character")
	case n < min:
		c.add(ptr, "is required")
	case n > max:
		c.add(ptr, "is longer than %d characters", max)
	}
}

// checkVersion applies the database's rules to a parsed version, so a file
// is refused before anything is stored.
func checkVersion(v *Version, c *checker) {
	if !keyRE.MatchString(v.Family.Key) {
		c.add("/family/key", "is lower-case letters, digits and hyphens, at most 63")
	}
	c.text("/family/title", v.Family.Title, 1, 300)
	c.text("/family/publisher", v.Family.Publisher, 0, 300)
	c.text("/version/label", v.Label, 1, 100)
	c.text("/version/title", v.Title, 1, 300)
	if v.Published != "" && !dateRE.MatchString(v.Published) {
		c.add("/version/published", "is a date (YYYY-MM-DD)")
	}
	if len(v.Requirements) == 0 {
		c.add("/requirements", "a version has at least one requirement")
	}
	if len(v.Requirements) > MaxRequirements {
		c.add("/requirements", "at most %d requirements a version", MaxRequirements)
		return
	}
	seen := map[string]int{}
	for i, r := range v.Requirements {
		ptr := fmt.Sprintf("/requirements/%d", i)
		if !identifierRE.MatchString(r.Identifier) {
			c.add(ptr+"/identifier", "is letters, digits and . _ : ( ) -, at most 100, starting with a letter or digit")
		} else if j, dup := seen[r.Identifier]; dup {
			c.add(ptr+"/identifier", "repeats requirement %d", j)
		} else {
			seen[r.Identifier] = i
		}
		c.text(ptr+"/label", r.Label, 0, 100)
		c.text(ptr+"/title", r.Title, 1, 500)
		c.text(ptr+"/statement", r.Statement, 0, 20000)
		if len(r.IncorporatedInto) > 50 {
			c.add(ptr+"/incorporated_into", "at most 50")
		}
	}
	for i, r := range v.Requirements {
		if r.Parent == "" {
			continue
		}
		if _, ok := seen[r.Parent]; !ok {
			c.add(fmt.Sprintf("/requirements/%d/parent", i), "names %q, which is not a requirement of the version", r.Parent)
		}
	}
	// No cycles: every parent chain ends.
	parent := map[string]string{}
	for _, r := range v.Requirements {
		parent[r.Identifier] = r.Parent
	}
	for i, r := range v.Requirements {
		at, steps := r.Identifier, 0
		for parent[at] != "" && steps <= len(v.Requirements) {
			at, steps = parent[at], steps+1
		}
		if steps > len(v.Requirements) {
			c.add(fmt.Sprintf("/requirements/%d/parent", i), "is part of a cycle")
		}
	}
}
