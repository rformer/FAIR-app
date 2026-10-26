// Package catalog loads and versions the platform permission catalog
// (F-001 T-03; requirements "Permission model", AC-51, AC-57; design §3 Access).
//
// The catalog is a JSON file shipped with each release. It is the only source
// of permissions: custom roles are composed from it (AC-51), and the iam
// service seeds iam.permission from it. A release that changes the catalog
// bumps its version; Diff reports what changed so that upgrade handling
// (T-29) can notify admins of new permissions without adding them to any
// existing custom role (AC-57, deny by default).
package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
)

// Action is the kind of access a permission grants (design §3).
type Action string

// Catalog actions. Approve, admin and export are always privileged (AC-54).
const (
	ActionRead    Action = "read"
	ActionWrite   Action = "write"
	ActionApprove Action = "approve"
	ActionAdmin   Action = "admin"
	ActionExport  Action = "export"
)

// actions lists the valid Action values.
var actions =[]Action{ActionRead, ActionWrite, ActionApprove, ActionAdmin, ActionExport}

// Permission is one catalog entry; it maps 1:1 to a row of iam.permission.
type Permission struct {
	Key          string `json:"key"`           // "<resource_type>.<name>", e.g. "analysis.edit"
	ResourceType string `json:"resource_type"` // e.g. "analysis"
	Action       Action `json:"action"`
	Privileged   bool   `json:"privileged"`    // AC-54
	IntroducedIn int    `json:"introduced_in"` // catalog version that first shipped the key
}

// Catalog is a validated permission catalog. Permissions are sorted by key.
type Catalog struct {
	Version     int          `json:"version"`
	Permissions []Permission `json:"permissions"`
}

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("catalog: invalid")

var keyRE = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)

// Parse decodes and validates a catalog. Unknown fields and trailing data are
// rejected so that a malformed release file fails startup rather than being
// partially applied.
func Parse(r io.Reader) (*Catalog, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var c Catalog
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data after catalog", ErrInvalid)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	slices.SortFunc(c.Permissions, func(a, b Permission) int { return strings.Compare(a.Key, b.Key) })
	return &c, nil
}

// Load reads and validates the catalog file at path.
func Load(path string) (*Catalog, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- path is release-controlled configuration
	if err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	return Parse(bytes.NewReader(b))
}

func (c *Catalog) validate() error {
	if c.Version < 1 {
		return fmt.Errorf("%w: version must be >= 1", ErrInvalid)
	}
	seen := make(map[string]bool, len(c.Permissions))
	for _, p := range c.Permissions {
		if !keyRE.MatchString(p.Key) {
			return fmt.Errorf("%w: key %q must be <resource_type>.<name> in lower snake case", ErrInvalid, p.Key)
		}
		if seen[p.Key] {
			return fmt.Errorf("%w: duplicate key %q", ErrInvalid, p.Key)
		}
		seen[p.Key] = true
		if res, _, _ := strings.Cut(p.Key, "."); res != p.ResourceType {
			return fmt.Errorf("%w: %s: resource_type %q does not match key prefix", ErrInvalid, p.Key, p.ResourceType)
		}
		if !slices.Contains(actions, p.Action) {
			return fmt.Errorf("%w: %s: action %q must be one of %v", ErrInvalid, p.Key, p.Action, actions)
		}
		// AC-54: approval, admin and export permissions are always privileged.
		if !p.Privileged && (p.Action == ActionApprove || p.Action == ActionAdmin || p.Action == ActionExport) {
			return fmt.Errorf("%w: %s: %s permissions must be privileged", ErrInvalid, p.Key, p.Action)
		}
		if p.IntroducedIn < 1 || p.IntroducedIn > c.Version {
			return fmt.Errorf("%w: %s: introduced_in %d must be in [1, %d]", ErrInvalid, p.Key, p.IntroducedIn, c.Version)
		}
	}
	return nil
}

// Lookup returns the permission with the given key.
func (c *Catalog) Lookup(key string) (Permission, bool) {
	i, ok := slices.BinarySearchFunc(c.Permissions, key, func(p Permission, k string) int { return strings.Compare(p.Key, k) })
	if !ok {
		return Permission{}, false
	}
	return c.Permissions[i], true
}

// Change is a permission present in both versions whose definition differs.
type Change struct {
	Old, New Permission
}

// Diff describes how a catalog changed between two versions. Each slice is
// sorted by key.
type Diff struct {
	FromVersion, ToVersion int
	Added                  []Permission // to be announced to admins; never auto-granted (AC-57)
	Removed                []Permission
	Changed                []Change
}

// Empty reports whether the two catalogs define identical permissions.
func (d Diff) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// Compare returns the difference from old to updated.
func Compare(old, updated *Catalog) Diff {
	d := Diff{FromVersion: old.Version, ToVersion: updated.Version}
	for _, p := range updated.Permissions {
		q, ok := old.Lookup(p.Key)
		switch {
		case !ok:
			d.Added = append(d.Added, p)
		case q != p:
			d.Changed = append(d.Changed, Change{Old: q, New: p})
		}
	}
	for _, q := range old.Permissions {
		if _, ok := updated.Lookup(q.Key); !ok {
			d.Removed = append(d.Removed, q)
		}
	}
	return d
}

// ErrVersion wraps every upgrade-ordering failure.
var ErrVersion = errors.New("catalog: version")

// Upgrade checks that updated is a valid successor of old and returns the
// diff. The version must increase whenever the catalog changes, new keys must
// be stamped with a version later than old, and existing keys keep their
// introduced_in. Policy for removed or reclassified permissions belongs to
// catalog upgrade handling (T-29); they are reported, not rejected, here.
func Upgrade(old, updated *Catalog) (Diff, error) {
	d := Compare(old, updated)
	if updated.Version < old.Version {
		return d, fmt.Errorf("%w: cannot go from %d back to %d", ErrVersion, old.Version, updated.Version)
	}
	if updated.Version == old.Version {
		if !d.Empty() {
			return d, fmt.Errorf("%w: catalog changed but version %d was not bumped", ErrVersion, old.Version)
		}
		return d, nil
	}
	for _, p := range d.Added {
		if p.IntroducedIn <= old.Version {
			return d, fmt.Errorf("%w: new permission %s has introduced_in %d, want > %d", ErrVersion, p.Key, p.IntroducedIn, old.Version)
		}
	}
	for _, c := range d.Changed {
		if c.Old.IntroducedIn != c.New.IntroducedIn {
			return d, fmt.Errorf("%w: %s introduced_in changed from %d to %d", ErrVersion, c.New.Key, c.Old.IntroducedIn, c.New.IntroducedIn)
		}
	}
	return d, nil
}
