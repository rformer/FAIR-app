// Package vulnex reads security/vuln-exceptions.yaml, the accepted image
// vulnerability findings (F-012 T-03, F-012-AC-07), and writes the ignore
// file the image scan uses for one component. An entry needs an ID, a
// package, the components it applies to, a reason and an expiry at most 90
// days after its review; an expired or malformed entry is an error, so the
// scan fails rather than silently accepting the finding.
package vulnex

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// MaxDays is the longest an exception may run after its review.
const MaxDays = 90

// File is the exceptions file.
type File struct {
	Exceptions []Exception `yaml:"exceptions"`
}

// Exception is one accepted finding.
type Exception struct {
	ID       string   `yaml:"id"`
	Package  string   `yaml:"package"`
	Images   []string `yaml:"images"`
	Reason   string   `yaml:"reason"`
	Expires  string   `yaml:"expires"`
	Reviewed string   `yaml:"reviewed"`
}

var idRE = regexp.MustCompile(`^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|GO-\d{4}-\d{4,})$`)

// Load reads and checks path at time now.
func Load(path string, now time.Time) (*File, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the repository's own file
	if err != nil {
		return nil, err
	}
	return Parse(b, now)
}

// Parse checks the file's contents at time now.
func Parse(b []byte, now time.Time) (*File, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("vulnex: %w", err)
	}
	var errs []error
	today := now.UTC().Truncate(24 * time.Hour)
	seen := map[string]bool{}
	for i, e := range f.Exceptions {
		at := fmt.Sprintf("exception %d (%s)", i+1, e.ID)
		if !idRE.MatchString(e.ID) {
			errs = append(errs, fmt.Errorf("%s: id is a CVE, GHSA or GO identifier", at))
		}
		if strings.TrimSpace(e.Package) == "" || len(e.Images) == 0 || len(strings.TrimSpace(e.Reason)) < 20 {
			errs = append(errs, fmt.Errorf("%s: package, images and a reason (at least 20 characters) are required", at))
		}
		for _, img := range e.Images {
			if img == "" || strings.ContainsAny(img, " \t,") {
				errs = append(errs, fmt.Errorf("%s: images are component names or all", at))
			}
		}
		exp, err1 := time.Parse(time.DateOnly, e.Expires)
		rev, err2 := time.Parse(time.DateOnly, e.Reviewed)
		switch {
		case err1 != nil || err2 != nil:
			errs = append(errs, fmt.Errorf("%s: expires and reviewed are YYYY-MM-DD", at))
		case exp.Before(today):
			errs = append(errs, fmt.Errorf("%s: expired on %s: fix it or review it again", at, e.Expires))
		case exp.Sub(rev) > MaxDays*24*time.Hour:
			errs = append(errs, fmt.Errorf("%s: expires more than %d days after its review", at, MaxDays))
		case rev.After(today):
			errs = append(errs, fmt.Errorf("%s: reviewed in the future", at))
		}
		key := e.ID + "|" + e.Package
		if seen[key] {
			errs = append(errs, fmt.Errorf("%s: listed twice", at))
		}
		seen[key] = true
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return &f, nil
}

// TrivyIgnore is the .trivyignore content for component: the IDs of the
// exceptions that apply to it (or to all), each with its expiry, which
// Trivy also enforces.
func (f *File) TrivyIgnore(component string) []byte {
	var b bytes.Buffer
	b.WriteString("# generated from security/vuln-exceptions.yaml (F-012 T-03); do not edit\n")
	var ids []string
	for _, e := range f.Exceptions {
		if slices.Contains(e.Images, component) || slices.Contains(e.Images, "all") {
			ids = append(ids, fmt.Sprintf("%s exp:%s", e.ID, e.Expires))
		}
	}
	slices.Sort(ids)
	for _, id := range slices.Compact(ids) {
		b.WriteString(id + "\n")
	}
	return b.Bytes()
}
