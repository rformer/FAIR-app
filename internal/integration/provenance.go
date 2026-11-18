package integration

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
)

// F-011 T-10b (F-011-AC-25; design §3.8): where a record's versions came
// from, for the risk and register APIs' version reads.

// Provenance is one version's: the integration, its run, the source's
// external ID, when it was received and who accepted it when.
type Provenance struct {
	Version         int             `json:"version"`
	IntegrationID   string          `json:"integration_id"`
	IntegrationName string          `json:"integration_name"`
	RunID           string          `json:"run_id"`
	ExternalID      string          `json:"external_id"`
	ReceivedAt      json.RawMessage `json:"received_at"`
	AcceptedAt      json.RawMessage `json:"accepted_at"`
	AcceptedByName  *string         `json:"accepted_by_name"`
}

// ProvenanceOf reads the provenance of targetType id's versions in tx, as
// the caller may see it (integration.provenance), by version.
func ProvenanceOf(ctx context.Context, tx pgx.Tx, targetType, id string) (map[int]Provenance, error) {
	var raw []byte
	if err := tx.QueryRow(ctx, "SELECT integration.provenance($1, $2)", targetType, id).Scan(&raw); err != nil {
		return nil, err
	}
	var list []Provenance
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	out := make(map[int]Provenance, len(list))
	for _, p := range list {
		out[p.Version] = p
	}
	return out, nil
}
