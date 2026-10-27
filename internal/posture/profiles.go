package posture

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// Custom profiles (F-015 T-19; AC-11 - AC-13; design §6.5). The database
// enforces the rules (migration 0023): profile.manage to create, edit,
// submit and reopen; validation against the registered definitions and hard
// floors; a justification for every loosened key; approval by a different
// holder of profile.approve through the F-001 approvals engine. Activation
// is the profile switch (T-21).

// Profiles manages custom profiles for a signed-in user.
type Profiles struct {
	DB    *pgxpool.Pool
	Audit audit.Emitter
}

// ProfileKey is one row of the per-key editor (AC-13): the base and the new
// value, the direction against the base, and the affected controls.
type ProfileKey struct {
	Key, Type                              string
	BaseDefault, BaseBound, Default, Bound json.RawMessage
	Direction                              string // tighten, loosen, unchanged, or unregistered
	Loosened                               bool
	Justification                          string
	Params, Controls                       []string
}

// DeviationLabel is how a custom profile with loosened keys is labeled
// wherever conformance is shown or exported (AC-13).
func DeviationLabel(baseName string) string { return "Deviates from " + baseName }

func (s Profiles) audited(ctx context.Context, p authz.Principal, fn func(pgx.Tx) error, ev audit.Event) error {
	return mapErr(authz.WithDBContext(ctx, s.DB, p.DBToken, func(tx pgx.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		return s.Audit.Emit(ctx, ev)
	}))
}

// Create clones a built-in profile into a draft custom profile (AC-11) and
// returns its version.
func (s Profiles) Create(ctx context.Context, p authz.Principal, baseID, baseVersion, newID, name string) (string, error) {
	var version string
	err := s.audited(ctx, p, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT posture.create_custom_profile($1, $2, $3, $4)", baseID, baseVersion, newID, name).Scan(&version)
	}, audit.Event{Type: "profile.created", Severity: audit.SeverityInfo, Actor: p.UserID, Target: "profile:" + newID,
		Attributes: map[string]string{"profile": newID, "name": name, "base": baseID, "base_version": baseVersion}})
	return version, err
}

// Edit sets a key's default and bound in a draft. A loosened key needs a
// justification (AC-12). It reports whether the key now deviates.
func (s Profiles) Edit(ctx context.Context, p authz.Principal, id, version, key string, def, bound json.RawMessage, justification string) (bool, error) {
	var loosened bool
	err := authz.WithDBContext(ctx, s.DB, p.DBToken, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT posture.edit_custom_value($1, $2, $3, $4, $5, $6)",
			id, version, key, []byte(def), []byte(bound), justification).Scan(&loosened); err != nil {
			return err
		}
		sev := audit.SeverityInfo
		if loosened {
			sev = audit.SeverityLow
		}
		return s.Audit.Emit(ctx, audit.Event{Type: "profile.value_changed", Severity: sev, Actor: p.UserID, Target: "profile:" + id,
			Reason: justification, Attributes: map[string]string{"profile": id, "version": version, "key": key,
				"default": string(def), "bound": string(bound), "loosened": strconv.FormatBool(loosened)}})
	})
	return loosened, mapErr(err)
}

// View returns the per-key editor and deviation data (AC-13).
func (s Profiles) View(ctx context.Context, p authz.Principal, id, version string) ([]ProfileKey, error) {
	var out []ProfileKey
	err := authz.WithDBContext(ctx, s.DB, p.DBToken, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT key, coalesce(type, ''), base_default, base_bound, default_value, bound, direction, loosened,
			coalesce(justification, ''), params FROM posture.custom_profile_view($1, $2)`, id, version)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k ProfileKey
			if err := rows.Scan(&k.Key, &k.Type, &k.BaseDefault, &k.BaseBound, &k.Default, &k.Bound, &k.Direction, &k.Loosened,
				&k.Justification, &k.Params); err != nil {
				return err
			}
			k.Controls = ControlsForParams(k.Params)
			out = append(out, k)
		}
		return rows.Err()
	})
	return out, mapErr(err)
}

// Submit validates a draft and asks for approval by a different holder of
// profile.approve (AC-12). It returns the approval request id.
func (s Profiles) Submit(ctx context.Context, p authz.Principal, id, version string) (string, error) {
	var approval string
	err := s.audited(ctx, p, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT posture.submit_custom_profile($1, $2)", id, version).Scan(&approval)
	}, audit.Event{Type: "profile.submitted", Severity: audit.SeverityHigh, Actor: p.UserID, Target: "profile:" + id,
		Attributes: map[string]string{"profile": id, "version": version}})
	return approval, err
}

// Approve marks an approved custom profile approved, ready for a switch
// (T-21). The approver comes from the approval; it returns their id.
func (s Profiles) Approve(ctx context.Context, id, version string) (string, error) {
	var approver string
	err := pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT posture.approve_custom_profile($1, $2)::text", id, version).Scan(&approver); err != nil {
			return err
		}
		return s.Audit.Emit(ctx, audit.Event{Type: "profile.approved", Severity: audit.SeverityHigh, Actor: approver, Target: "profile:" + id,
			Attributes: map[string]string{"profile": id, "version": version}})
	})
	return approver, mapErr(err)
}

// Reopen returns a submitted profile to draft (after a rejection, or to make
// changes); its pending approval can no longer be used.
func (s Profiles) Reopen(ctx context.Context, p authz.Principal, id, version string) error {
	return s.audited(ctx, p, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT posture.reopen_custom_profile($1, $2)", id, version)
		return err
	}, audit.Event{Type: "profile.reopened", Severity: audit.SeverityInfo, Actor: p.UserID, Target: "profile:" + id,
		Attributes: map[string]string{"profile": id, "version": version}})
}
