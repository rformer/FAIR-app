package importapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/integration"
	"github.com/rformer/fair-app/internal/register"
	"github.com/rformer/fair-app/internal/registerapi"
	"github.com/rformer/fair-app/internal/risk/model"
	"github.com/rformer/fair-app/internal/riskapi"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-011 T-10 (design §3.4 as amended 2026-11-18): the proposed document,
// merged at review under the reviewer's RLS: the target's current version
// with the record's mapped fields replaced (fields the record does not
// carry are kept), or, for a new record, the record completed with the
// platform's required fields. The record's values are the source's; the
// estimate it makes of a value names the integration as its source.

// review is a proposal as the reviewer reads it.
type review struct {
	ID              string          `json:"id"`
	IntegrationID   string          `json:"integration_id"`
	IntegrationName string          `json:"integration_name"`
	BU              string          `json:"bu_id"`
	TargetType      string          `json:"target_type"`
	TargetID        *string         `json:"target_id"`
	ExternalID      string          `json:"external_id"`
	Action          string          `json:"action"`
	Record          json.RawMessage `json:"record"`
	State           string          `json:"state"`
}

// errUnmergeable: the record cannot make a document yet (an asset group
// whose members are not accepted assets of the integration).
type errUnmergeable struct{ msg string }

func (e errUnmergeable) Error() string { return e.msg }

func sectionOf(targetType string) string {
	if targetType == "control" {
		return riskapi.SectionControls
	}
	return riskapi.SectionLibrary
}

// merged is a proposal's target as the reviewer reads it, and the
// document accepting would write (nil for an archive).
type merged struct {
	exists   bool
	id       string
	version  int
	archived bool
	current  json.RawMessage
	doc      json.RawMessage
}

// validate checks the merged document as its kind's save code will.
func (m merged) validate(targetType string) ([]byte, model.Problems) {
	if targetType == "risk" {
		doc, _, problems := register.Validate(m.doc)
		return doc, problems
	}
	doc, problems := model.Validate(targetType, m.doc)
	if problems != nil {
		return nil, problems
	}
	return doc.Canonical, nil
}

// mergeFor merges proposal pr as p reads its target in tx.
func mergeFor(ctx context.Context, tx pgx.Tx, p authz.Principal, pr review) (merged, error) {
	var m merged
	doc := map[string]any{}
	if pr.TargetID != nil {
		if pr.TargetType == "risk" {
			r, err := registerapi.ReadRisk(ctx, tx, *pr.TargetID)
			if err != nil {
				return m, err
			}
			m = merged{exists: true, id: r.ID, version: r.Version, archived: r.State == "closed", current: r.Document}
		} else {
			h, err := riskapi.ReadHead(ctx, tx, sectionOf(pr.TargetType), *pr.TargetID)
			if err != nil {
				return m, err
			}
			m = merged{exists: true, id: h.ID, version: h.CurrentVersion, archived: h.Archived, current: h.Document}
		}
		if err := json.Unmarshal(m.current, &doc); err != nil {
			return m, err
		}
	}
	if pr.Action == "archive" {
		return m, nil
	}
	source := pr.IntegrationName + ": " + pr.ExternalID
	estimate := func(r *integration.Range) map[string]any {
		conf := string(r.Confidence)
		if conf == "" {
			conf = "0.9"
		}
		rationale := "From " + pr.IntegrationName + "."
		if r.Basis != "" {
			rationale = r.Basis + " (from " + pr.IntegrationName + ")."
		}
		return map[string]any{"min": string(r.Min), "ml": string(r.ML), "max": string(r.Max), "unit": "currency", "confidence": conf,
			"rationale": rationale, "sources": []any{map[string]any{"type": "integration", "ref": source}}}
	}
	switch pr.TargetType {
	case "asset":
		var r integration.Asset
		if err := json.Unmarshal(pr.Record, &r); err != nil {
			return m, err
		}
		doc["kind"], doc["schema_version"] = "asset", 1
		doc["name"], doc["asset_type"] = r.Name, r.AssetType
		if r.Description != "" {
			doc["description"] = r.Description
		}
		switch {
		case r.Value != nil:
			doc["value"] = estimate(r.Value)
			delete(doc, "value_basis")
		case doc["value"] == nil && doc["value_basis"] == nil:
			doc["value_basis"] = "Not valued at the source (" + pr.IntegrationName + ")."
		}
	case "asset_group":
		var r integration.AssetGroup
		if err := json.Unmarshal(pr.Record, &r); err != nil {
			return m, err
		}
		members, err := memberPins(ctx, tx, pr, r.Members)
		if err != nil {
			return m, err
		}
		doc["kind"], doc["schema_version"] = "asset_group", 1
		doc["name"], doc["members"] = r.Name, members
		if r.Description != "" {
			doc["description"] = r.Description
		}
		if r.Value != nil {
			doc["valuation"], doc["value"] = "whole", estimate(r.Value)
		} else {
			doc["valuation"] = "members"
			delete(doc, "value")
		}
	case "control":
		var r integration.ControlStatus
		if err := json.Unmarshal(pr.Record, &r); err != nil {
			return m, err
		}
		if !m.exists {
			return m, errUnmergeable{"a control status updates an existing control"}
		}
		src := map[string]any{"type": "integration", "ref": source}
		if r.Note != "" {
			src["note"] = r.Note
		}
		doc["implementation"] = map[string]any{"status": r.Status, "assessed_on": r.AssessedOn, "source": src}
	case "risk":
		var r integration.Risk
		if err := json.Unmarshal(pr.Record, &r); err != nil {
			return m, err
		}
		doc["schema_version"], doc["title"] = 1, r.Title
		if r.Description != "" {
			doc["description"] = r.Description
		}
		if r.Owner != "" {
			var owner *string
			if err := tx.QueryRow(ctx, "SELECT integration.owner_by_email($1, $2)::text", pr.ID, r.Owner).Scan(&owner); err != nil {
				return m, err
			}
			if owner == nil {
				return m, errUnmergeable{fmt.Sprintf("the owner %s is not an active user who reads the register at this business unit", r.Owner)}
			}
			doc["owner"] = *owner
		} else if doc["owner"] == nil {
			doc["owner"] = p.UserID // the record names none: the accepting reviewer
		}
		if r.Category != "" {
			var cat *string
			if err := tx.QueryRow(ctx, "SELECT id::text FROM register.category WHERE lower(name) = lower($1) AND archived_at IS NULL", r.Category).Scan(&cat); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return m, err
			}
			if cat == nil {
				return m, errUnmergeable{fmt.Sprintf("no register category is called %q", strings.TrimSpace(r.Category))}
			}
			doc["category"] = *cat
		}
		if !m.exists {
			doc["state"], doc["scenarios"] = "open", []any{}
		}
	default:
		return m, errUnmergeable{"proposals of " + pr.TargetType + " are not accepted here"}
	}
	out, err := json.Marshal(doc)
	m.doc = out
	return m, err
}

// memberPins pins each member, an accepted asset of the integration, at its
// current version as the reviewer reads it.
func memberPins(ctx context.Context, tx pgx.Tx, pr review, members []string) ([]any, error) {
	rows, err := tx.Query(ctx, "SELECT external_id, target_id::text FROM integration.members($1, $2)", pr.ID, members)
	if err != nil {
		return nil, err
	}
	targets := map[string]string{}
	for rows.Next() {
		var e, t string
		if err := rows.Scan(&e, &t); err != nil {
			rows.Close()
			return nil, err
		}
		targets[e] = t
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]any, 0, len(members))
	for _, mem := range members {
		t, ok := targets[mem]
		if !ok {
			return nil, errUnmergeable{fmt.Sprintf("member %s is not an accepted asset of this integration yet: accept it first", mem)}
		}
		h, err := riskapi.ReadHead(ctx, tx, riskapi.SectionLibrary, t)
		if errors.Is(err, riskapi.ErrNotFound) {
			return nil, errUnmergeable{fmt.Sprintf("member %s is not visible to you", mem)}
		}
		if err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": h.ID, "version": h.CurrentVersion})
	}
	return out, nil
}
