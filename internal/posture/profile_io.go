package posture

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- UUIDv5 name hashing only (see uuidV5)
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/oscal"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// Custom profile versions, diffs, base updates, and JSON/OSCAL export and
// import (F-015 T-20; AC-14, AC-15; design §6.5; migration 0024).

// NewVersion copies a custom profile version into the next numbered draft.
func (s Profiles) NewVersion(ctx context.Context, p authz.Principal, id, fromVersion string) (string, error) {
	var v string
	err := s.audited(ctx, p, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT posture.new_custom_version($1, $2)", id, fromVersion).Scan(&v)
	}, audit.Event{Type: "profile.versioned", Severity: audit.SeverityInfo, Actor: p.UserID, Target: "profile:" + id,
		Attributes: map[string]string{"profile": id, "from_version": fromVersion}})
	return v, err
}

// DiffRow compares one key of two profile versions.
type DiffRow struct {
	Key                                string
	ADefault, ABound, BDefault, BBound json.RawMessage
	Change                             string // tighten, loosen, mixed, unchanged, added, removed, unregistered
}

// Diff compares two profile versions key by key (AC-14).
func (s Profiles) Diff(ctx context.Context, p authz.Principal, aID, aVersion, bID, bVersion string) ([]DiffRow, error) {
	var out []DiffRow
	err := authz.WithDBContext(ctx, s.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT key, a_default, a_bound, b_default, b_bound, change FROM posture.profile_diff($1, $2, $3, $4)",
			aID, aVersion, bID, bVersion)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r DiffRow
			if err := rows.Scan(&r.Key, &r.ADefault, &r.ABound, &r.BDefault, &r.BBound, &r.Change); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, mapErr(err)
}

// BaseEffect is what moving a derived profile to a new base version does
// to one key (AC-15): pinned, proposed, unchanged or added.
type BaseEffect struct {
	ProfileID, Version, Key                              string
	CurrentDefault, CurrentBound, BaseDefault, BaseBound json.RawMessage
	Action                                               string
}

// BaseUpdateEffects shows the effect of a new base version on every
// profile in use that derives from it.
func (s Profiles) BaseUpdateEffects(ctx context.Context, p authz.Principal, baseID, newVersion string) ([]BaseEffect, error) {
	var out []BaseEffect
	err := authz.WithDBContext(ctx, s.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT profile_id, version, key, current_default, current_bound, base_default, base_bound, action
			FROM posture.base_update_effects($1, $2)`, baseID, newVersion)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r BaseEffect
			if err := rows.Scan(&r.ProfileID, &r.Version, &r.Key, &r.CurrentDefault, &r.CurrentBound, &r.BaseDefault, &r.BaseBound, &r.Action); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, mapErr(err)
}

// Rebase creates the next draft version of a custom profile on a new base
// version: pinned keys keep their values, proposed ones too until adopted.
func (s Profiles) Rebase(ctx context.Context, p authz.Principal, id, fromVersion, newBaseVersion string) (string, error) {
	var v string
	err := s.audited(ctx, p, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT posture.rebase_custom_profile($1, $2, $3)", id, fromVersion, newBaseVersion).Scan(&v)
	}, audit.Event{Type: "profile.rebased", Severity: audit.SeverityInfo, Actor: p.UserID, Target: "profile:" + id,
		Attributes: map[string]string{"profile": id, "from_version": fromVersion, "base_version": newBaseVersion}})
	return v, err
}

// CustomProfileFormat identifies the native JSON export.
const CustomProfileFormat = "fair-custom-profile/v1"

// CustomProfileDoc is the native JSON export of a custom profile.
type CustomProfileDoc struct {
	Format   string                   `json:"format"`
	ID       string                   `json:"id"`
	Version  string                   `json:"version"`
	Name     string                   `json:"name"`
	Family   string                   `json:"family"`
	Base     BaseRef                  `json:"base"`
	Deviates bool                     `json:"deviates"`
	Settings map[string]CustomSetting `json:"settings"`
}

// BaseRef names the built-in profile version a custom profile derives from.
type BaseRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Name    string `json:"name,omitempty"`
}

// CustomSetting is one key of a custom profile.
type CustomSetting struct {
	Default       json.RawMessage `json:"default"`
	Bound         json.RawMessage `json:"bound"`
	Justification string          `json:"justification,omitempty"`
}

func (s Profiles) doc(ctx context.Context, tx pgx.Tx, id, version string) (CustomProfileDoc, []ProfileKey, error) {
	d := CustomProfileDoc{Format: CustomProfileFormat, ID: id, Version: version, Settings: map[string]CustomSetting{}}
	var kind string
	if err := tx.QueryRow(ctx, "SELECT name, family, kind, coalesce(base_profile_id, ''), coalesce(base_version, ''), label_deviates, coalesce(base_name, '') FROM posture.profile_meta($1, $2)",
		id, version).Scan(&d.Name, &d.Family, &kind, &d.Base.ID, &d.Base.Version, &d.Deviates, &d.Base.Name); err != nil {
		return d, nil, err
	}
	if kind != "custom" {
		return d, nil, fmt.Errorf("%w: only custom profiles are exported this way (built-in profiles ship as signed packages)", ErrNotApplicable)
	}
	keys, err := viewTx(ctx, tx, id, version)
	if err != nil {
		return d, nil, err
	}
	for _, k := range keys {
		d.Settings[k.Key] = CustomSetting{Default: k.Default, Bound: k.Bound, Justification: k.Justification}
	}
	return d, keys, nil
}

func viewTx(ctx context.Context, tx pgx.Tx, id, version string) ([]ProfileKey, error) {
	rows, err := tx.Query(ctx, `SELECT key, coalesce(type, ''), base_default, base_bound, default_value, bound, direction, loosened,
		coalesce(justification, ''), params FROM posture.custom_profile_view($1, $2)`, id, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProfileKey
	for rows.Next() {
		var k ProfileKey
		if err := rows.Scan(&k.Key, &k.Type, &k.BaseDefault, &k.BaseBound, &k.Default, &k.Bound, &k.Direction, &k.Loosened,
			&k.Justification, &k.Params); err != nil {
			return nil, err
		}
		k.Controls = ControlsForParams(k.Params)
		out = append(out, k)
	}
	return out, rows.Err()
}

func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ExportJSON exports a custom profile version in the native format (AC-14).
func (s Profiles) ExportJSON(ctx context.Context, p authz.Principal, id, version string) ([]byte, error) {
	var out []byte
	err := authz.WithDBContext(ctx, s.DB, p.DBToken, func(tx pgx.Tx) error {
		d, _, err := s.doc(ctx, tx, id, version)
		if err != nil {
			return err
		}
		out, err = canonicalJSON(d)
		return err
	})
	return out, mapErr(err)
}

// OSCAL export (AC-14): an OSCAL profile importing the base, with a
// set-parameters entry for every OSCAL parameter a setting implements
// (values: the default; props fair-bound: the bound, fair-setting: the key,
// fair-justification: why a loosened key is loosened). Settings without an OSCAL parameter cannot be expressed in
// set-parameters, so the native JSON is embedded in back-matter: importing
// our own export is lossless.
const (
	oscalNS      = "urn:fair-app:posture"
	nativeFile   = "fair-custom-profile.json"
	baseHrefStem = "urn:fair-app:profile:"
)

// ExportOSCAL exports a custom profile version as an OSCAL 1.2.3 profile.
func (s Profiles) ExportOSCAL(ctx context.Context, p authz.Principal, id, version string) ([]byte, error) {
	var out []byte
	err := authz.WithDBContext(ctx, s.DB, p.DBToken, func(tx pgx.Tx) error {
		d, keys, err := s.doc(ctx, tx, id, version)
		if err != nil {
			return err
		}
		native, err := canonicalJSON(d)
		if err != nil {
			return err
		}
		var setParams []any
		for _, k := range keys {
			for _, param := range k.Params {
				props := []any{
					map[string]any{"name": "fair-setting", "ns": oscalNS, "value": k.Key},
					map[string]any{"name": "fair-bound", "ns": oscalNS, "value": oscalValue(k.Bound)},
				}
				if k.Justification != "" {
					props = append(props, map[string]any{"name": "fair-justification", "ns": oscalNS, "value": k.Justification})
				}
				setParams = append(setParams, map[string]any{"param-id": param, "values": []string{oscalValue(k.Default)}, "props": props})
			}
		}
		title := d.Name
		if d.Deviates {
			title += " (" + DeviationLabel(d.Base.Name) + ")"
		}
		prof := map[string]any{
			"uuid": uuidV5(id + "@" + version),
			"metadata": map[string]any{
				"title": title, "last-modified": time.Now().UTC().Format(time.RFC3339), "version": version, "oscal-version": oscal.Version,
				"props": []any{
					map[string]any{"name": "fair-profile", "ns": oscalNS, "value": id},
					map[string]any{"name": "fair-deviates", "ns": oscalNS, "value": fmt.Sprint(d.Deviates)},
				},
			},
			"imports": []any{map[string]any{"href": baseHrefStem + d.Base.ID + ":" + d.Base.Version, "include-all": map[string]any{}}},
			"back-matter": map[string]any{"resources": []any{map[string]any{
				"uuid":   uuidV5(id + "@" + version + "/native"),
				"title":  "FAIR custom profile (native JSON)",
				"base64": map[string]any{"filename": nativeFile, "media-type": "application/json", "value": base64.StdEncoding.EncodeToString(native)},
			}}},
		}
		if len(setParams) > 0 {
			prof["modify"] = map[string]any{"set-parameters": setParams}
		}
		b, err := canonicalJSON(map[string]any{"profile": prof})
		if err != nil {
			return err
		}
		if kind, err := oscal.Validate(b); err != nil || kind != oscal.Profile {
			return fmt.Errorf("posture: OSCAL export does not validate: %w", err)
		}
		out = b
		return nil
	})
	return out, mapErr(err)
}

// oscalValue renders a JSON value as an OSCAL string: strings unquoted,
// numbers and booleans as written.
func oscalValue(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

// uuidV5 is a deterministic RFC 9562 version-5 UUID, so exports of the
// same profile version carry the same identifiers. OSCAL's UUID datatype
// accepts only versions 4 and 5; version 5 is defined with SHA-1, used here
// only as the name hash, which FIPS mode (fips140=on) permits.
func uuidV5(name string) string {
	ns := []byte{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8} // URL namespace
	h := sha1.New()                                                                                              // #nosec G401 -- RFC 9562 UUIDv5 name hashing, not a security function
	h.Write(ns)
	h.Write([]byte("urn:fair-app:posture:" + name))
	b := h.Sum(nil)[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ErrImport is returned for an import that cannot be accepted as a whole.
var ErrImport = errors.New("posture: profile import refused")

// ImportJSON imports a native export as a new draft custom profile with id
// newID (AC-14). Every value goes through the edit rules (registered
// definitions, hard floors, justification for loosened keys); any problem
// refuses the whole import. It returns the new version.
func (s Profiles) ImportJSON(ctx context.Context, p authz.Principal, newID string, data []byte) (string, error) {
	var d CustomProfileDoc
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return "", fmt.Errorf("%w: not a %s document: %w", ErrImport, CustomProfileFormat, err)
	}
	if d.Format != CustomProfileFormat {
		return "", fmt.Errorf("%w: format %q, want %s", ErrImport, d.Format, CustomProfileFormat)
	}
	return s.importDoc(ctx, p, newID, d, "json")
}

// ImportOSCAL imports an OSCAL profile as a new draft custom profile. An
// export of ours carries its native JSON and imports losslessly; another
// OSCAL profile must import a base as urn:fair-app:profile:<id>:<version>,
// and its set-parameters are mapped to the settings that implement those
// parameters (the bound is the fair-bound prop, else the value).
func (s Profiles) ImportOSCAL(ctx context.Context, p authz.Principal, newID string, data []byte) (string, error) {
	kind, err := oscal.Validate(data)
	if err != nil {
		return "", fmt.Errorf("%w: not a valid OSCAL document: %w", ErrImport, err)
	}
	if kind != oscal.Profile {
		return "", fmt.Errorf("%w: an OSCAL %s, not a profile", ErrImport, kind)
	}
	var doc struct {
		Profile struct {
			Imports []struct {
				Href string `json:"href"`
			} `json:"imports"`
			Modify struct {
				SetParameters []struct {
					ParamID string   `json:"param-id"`
					Values  []string `json:"values"`
					Props   []struct {
						Name, NS, Value string
					} `json:"props"`
				} `json:"set-parameters"`
			} `json:"modify"`
			BackMatter struct {
				Resources []struct {
					Base64 *struct {
						Filename, Value string
					} `json:"base64"`
				} `json:"resources"`
			} `json:"back-matter"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("%w: %w", ErrImport, err)
	}
	for _, r := range doc.Profile.BackMatter.Resources {
		if r.Base64 != nil && r.Base64.Filename == nativeFile {
			native, err := base64.StdEncoding.DecodeString(r.Base64.Value)
			if err != nil {
				return "", fmt.Errorf("%w: embedded profile: %w", ErrImport, err)
			}
			return s.ImportJSON(ctx, p, newID, native)
		}
	}
	if len(doc.Profile.Imports) != 1 || !strings.HasPrefix(doc.Profile.Imports[0].Href, baseHrefStem) {
		return "", fmt.Errorf("%w: the profile must import one FAIR base profile (%s<id>:<version>)", ErrImport, baseHrefStem)
	}
	base := strings.Split(strings.TrimPrefix(doc.Profile.Imports[0].Href, baseHrefStem), ":")
	if len(base) != 2 {
		return "", fmt.Errorf("%w: bad base reference %q", ErrImport, doc.Profile.Imports[0].Href)
	}
	d := CustomProfileDoc{Format: CustomProfileFormat, Base: BaseRef{ID: base[0], Version: base[1]}, Settings: map[string]CustomSetting{}}
	params := map[string][]string{} // param -> values, plus param+"#bound" and param+"#justification"
	for _, sp := range doc.Profile.Modify.SetParameters {
		if len(sp.Values) != 1 {
			return "", fmt.Errorf("%w: parameter %s needs exactly one value", ErrImport, sp.ParamID)
		}
		params[sp.ParamID] = sp.Values
		for _, pr := range sp.Props {
			if pr.NS == oscalNS && (pr.Name == "fair-bound" || pr.Name == "fair-justification") {
				params[sp.ParamID+"#"+strings.TrimPrefix(pr.Name, "fair-")] = []string{pr.Value}
			}
		}
	}
	d.Name = newID
	return s.importDoc(ctx, p, newID, d, "oscal", params)
}

// importDoc creates the draft from d's base and applies d's settings, or,
// for OSCAL set-parameters, the parameter values mapped to settings.
func (s Profiles) importDoc(ctx context.Context, p authz.Principal, newID string, d CustomProfileDoc, format string, params ...map[string][]string) (string, error) {
	name := d.Name
	if name == "" {
		name = newID
	}
	var version string
	err := authz.WithDBContext(ctx, s.DB, p.DBToken, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT posture.create_custom_profile($1, $2, $3, $4)", d.Base.ID, d.Base.Version, newID, name).Scan(&version); err != nil {
			return err
		}
		keys, err := viewTx(ctx, tx, newID, version)
		if err != nil {
			return err
		}
		want := d.Settings
		if len(params) > 0 {
			if want, err = settingsFromParams(keys, params[0]); err != nil {
				return err
			}
		}
		for key := range want {
			if !slices.ContainsFunc(keys, func(k ProfileKey) bool { return k.Key == key }) {
				return fmt.Errorf("%w: %s is not a setting of base %s %s", ErrImport, key, d.Base.ID, d.Base.Version)
			}
		}
		for _, k := range keys {
			w, ok := want[k.Key]
			if !ok || (jsonEqual(w.Default, k.Default) && jsonEqual(w.Bound, k.Bound)) {
				continue
			}
			var loose bool
			if err := tx.QueryRow(ctx, "SELECT posture.edit_custom_value($1, $2, $3, $4, $5, $6)",
				newID, version, k.Key, []byte(w.Default), []byte(w.Bound), w.Justification).Scan(&loose); err != nil {
				return fmt.Errorf("%s: %w", k.Key, err)
			}
		}
		return s.Audit.Emit(ctx, audit.Event{Type: "profile.imported", Severity: audit.SeverityHigh, Actor: p.UserID, Target: "profile:" + newID,
			Attributes: map[string]string{"profile": newID, "version": version, "base": d.Base.ID, "base_version": d.Base.Version, "format": format}})
	})
	if err != nil && !errors.Is(err, ErrImport) {
		return "", fmt.Errorf("%w: %w", ErrImport, mapErr(err))
	}
	return version, err
}

// settingsFromParams maps OSCAL parameter values to the settings that
// implement those parameters.
func settingsFromParams(keys []ProfileKey, params map[string][]string) (map[string]CustomSetting, error) {
	out := map[string]CustomSetting{}
	used := map[string]bool{}
	for _, k := range keys {
		for _, param := range k.Params {
			vals, ok := params[param]
			if !ok {
				continue
			}
			used[param] = true
			def, err := settingJSON(k, vals[0])
			if err != nil {
				return nil, err
			}
			bound := def
			if b, ok := params[param+"#bound"]; ok {
				if bound, err = settingJSON(k, b[0]); err != nil {
					return nil, err
				}
			}
			if prev, dup := out[k.Key]; dup && (!jsonEqual(prev.Default, def) || !jsonEqual(prev.Bound, bound)) {
				return nil, fmt.Errorf("%w: parameters of %s disagree", ErrImport, k.Key)
			}
			// A loosened key keeps its written justification (fair-justification
			// prop); without one the edit rule refuses it (AC-12).
			var justification string
			if j, ok := params[param+"#justification"]; ok {
				justification = j[0]
			}
			out[k.Key] = CustomSetting{Default: def, Bound: bound, Justification: justification}
		}
	}
	for param := range params {
		if !strings.Contains(param, "#") && !used[param] {
			return nil, fmt.Errorf("%w: parameter %s is not implemented by any setting", ErrImport, param)
		}
	}
	return out, nil
}

// settingJSON turns an OSCAL string value into the setting's JSON value.
func settingJSON(k ProfileKey, s string) (json.RawMessage, error) {
	switch k.Type {
	case "duration", "enum":
		b, _ := json.Marshal(s)
		return b, nil
	case "int", "bool":
		if !json.Valid([]byte(s)) {
			return nil, fmt.Errorf("%w: %s value %q is not a %s", ErrImport, k.Key, s, k.Type)
		}
		return json.RawMessage(s), nil
	}
	return nil, fmt.Errorf("%w: %s has no registered type", ErrImport, k.Key)
}

func jsonEqual(a, b json.RawMessage) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && fmt.Sprint(x) == fmt.Sprint(y)
}
