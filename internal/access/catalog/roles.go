package catalog

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
)

// The release catalog and built-in role templates shipped with this build
// (permission-catalog.md, F-001 T-06).
//
//go:embed release/catalog.json release/builtin_roles.json
var release embed.FS

// BuiltinRole is an immutable role template (AC-52). Permissions are sorted.
type BuiltinRole struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// BuiltinRoles is the set of built-in role templates for one catalog version.
type BuiltinRoles struct {
	CatalogVersion int           `json:"catalog_version"`
	Roles          []BuiltinRole `json:"roles"`
}

// ParseRoles decodes the built-in roles and validates them against c: every
// permission must exist, and no built-in role may combine admin permissions
// with risk-data permissions (AC-30, AC-44).
func ParseRoles(r io.Reader, c *Catalog) (*BuiltinRoles, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var br BuiltinRoles
	if err := dec.Decode(&br); err != nil {
		return nil, fmt.Errorf("%w: roles: %w", ErrInvalid, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: roles: trailing data", ErrInvalid)
	}
	if br.CatalogVersion != c.Version {
		return nil, fmt.Errorf("%w: roles target catalog %d, catalog is %d", ErrInvalid, br.CatalogVersion, c.Version)
	}
	names := map[string]bool{}
	for i, role := range br.Roles {
		if role.Name == "" || names[role.Name] {
			return nil, fmt.Errorf("%w: role name %q is empty or duplicated", ErrInvalid, role.Name)
		}
		names[role.Name] = true
		var admin, risk string
		for _, k := range role.Permissions {
			p, ok := c.Lookup(k)
			if !ok {
				return nil, fmt.Errorf("%w: role %s: unknown permission %q", ErrInvalid, role.Name, k)
			}
			if p.Action == ActionAdmin {
				admin = k
			}
			if p.RiskData {
				risk = k
			}
		}
		if admin != "" && risk != "" {
			return nil, fmt.Errorf("%w: role %s combines admin %s with risk data %s", ErrInvalid, role.Name, admin, risk)
		}
		perms := slices.Clone(role.Permissions)
		slices.Sort(perms)
		if len(slices.Compact(perms)) != len(role.Permissions) {
			return nil, fmt.Errorf("%w: role %s lists a permission twice", ErrInvalid, role.Name)
		}
		br.Roles[i].Permissions = perms
	}
	return &br, nil
}

// Release returns the catalog and built-in roles embedded in this build.
func Release() (*Catalog, *BuiltinRoles, error) {
	cb, err := release.ReadFile("release/catalog.json")
	if err != nil {
		return nil, nil, err
	}
	c, err := Parse(bytes.NewReader(cb))
	if err != nil {
		return nil, nil, err
	}
	rb, err := release.ReadFile("release/builtin_roles.json")
	if err != nil {
		return nil, nil, err
	}
	br, err := ParseRoles(bytes.NewReader(rb), c)
	if err != nil {
		return nil, nil, err
	}
	return c, br, nil
}

// SyncPayload is the JSON document passed to iam.sync_release (migration
// 0004): the catalog and the built-in roles of this build.
func SyncPayload(c *Catalog, br *BuiltinRoles) ([]byte, error) {
	return json.Marshal(struct {
		Version     int           `json:"version"`
		Permissions []Permission  `json:"permissions"`
		Roles       []BuiltinRole `json:"roles"`
	}{c.Version, c.Permissions, br.Roles})
}
