package risk

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ErrNoVersion: the scenario version does not exist for the caller.
var ErrNoVersion = errors.New("risk: no such scenario version")

// LoadScenarioBundle builds a scenario version's input bundle inside tx,
// a transaction under the caller's DB context (RLS decides what it sees):
// the version, its own pin rows' documents and the installation currency
// (design §1, T-08). The analysis request (F-005 design §6.1) and the
// bundle route build the same bytes.
func LoadScenarioBundle(ctx context.Context, tx pgx.Tx, id string, version int64) (Bundle, error) {
	s := BundleScenario{ID: id, Version: version}
	err := tx.QueryRow(ctx, "SELECT digest, document FROM risk.scenario_version WHERE scenario_id = $1 AND version = $2", id, version).
		Scan(&s.Digest, &s.Document)
	if errors.Is(err, pgx.ErrNoRows) {
		return Bundle{}, ErrNoVersion
	}
	if err != nil {
		return Bundle{}, err
	}
	rows, err := tx.Query(ctx, "SELECT pointer, to_kind, to_id::text, to_version, to_digest, to_document, coalesce(member_of, '') FROM risk.scenario_pin"+
		" WHERE scenario_id = $1 AND version = $2", id, version)
	if err != nil {
		return Bundle{}, err
	}
	pins, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (BundlePin, error) {
		var b BundlePin
		err := row.Scan(&b.Pointer, &b.Kind, &b.ID, &b.Version, &b.Digest, &b.Document, &b.MemberOf)
		return b, err
	})
	if err != nil {
		return Bundle{}, err
	}
	var currency string
	if err := tx.QueryRow(ctx, "SELECT coalesce((SELECT currency FROM risk.instance), '')").Scan(&currency); err != nil {
		return Bundle{}, err
	}
	return BuildBundle(currency, s, pins)
}
