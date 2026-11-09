package risk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rformer/fair-app/internal/risk/canon"
)

// TransferFormat names the export and import format (F-003 AC-24, AC-25;
// design §6.5; docs/formats/fair-risk-v1.md).
const TransferFormat = "fair.risk.v1"

// MaxTransferBytes bounds an import's file: the API's limit for a
// mutation's body (4 MiB), less room for the request around it.
const MaxTransferBytes = 4<<20 - 64<<10

// TransferVersion is one version of an item, its document canonical.
type TransferVersion struct {
	Version    int64           `json:"version"`
	Digest     string          `json:"digest"`
	ChangeNote string          `json:"change_note"`
	Document   json.RawMessage `json:"document"`
}

// TransferItem is a scenario, library entry or control with its versions,
// in order from 1.
type TransferItem struct {
	ID       string            `json:"id"`
	Kind     string            `json:"kind"`
	Versions []TransferVersion `json:"versions"`
}

// TransferPinned is a version an exported item pins that is not otherwise in
// the file: copied from the pin rows (the exporter may read it only there).
type TransferPinned struct {
	Kind     string          `json:"kind"`
	ID       string          `json:"id"`
	Version  int64           `json:"version"`
	Digest   string          `json:"digest"`
	Document json.RawMessage `json:"document"`
}

// Transfer is a fair.risk.v1 file.
type Transfer struct {
	Format     string           `json:"format"`
	Currency   *string          `json:"currency"`
	ExportedAt time.Time        `json:"exported_at"`
	Scenarios  []TransferItem   `json:"scenarios"`
	Library    []TransferItem   `json:"library"`
	Controls   []TransferItem   `json:"controls"`
	Pinned     []TransferPinned `json:"pinned"`
}

// Encode writes the file in canonical form and returns it with its SHA-256.
func (t Transfer) Encode() ([]byte, string, error) {
	t.Format = TransferFormat
	t.ExportedAt = t.ExportedAt.UTC().Truncate(time.Second)
	for _, l := range []*[]TransferItem{&t.Scenarios, &t.Library, &t.Controls} {
		if *l == nil {
			*l = []TransferItem{}
		}
	}
	if t.Pinned == nil {
		t.Pinned = []TransferPinned{}
	}
	b, err := json.Marshal(t)
	if err != nil {
		return nil, "", err
	}
	if b, err = canon.Canonicalize(b); err != nil {
		return nil, "", err
	}
	return b, canon.Digest(b), nil
}

// ParseTransfer reads a file strictly: no unknown members, the format named.
func ParseTransfer(b []byte) (Transfer, error) {
	var t Transfer
	if len(b) > MaxTransferBytes {
		return t, fmt.Errorf("risk: the file is larger than %d bytes", MaxTransferBytes)
	}
	if _, err := canon.Parse(b); err != nil {
		return t, fmt.Errorf("risk: not a JSON document: %w", err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&t); err != nil {
		return t, fmt.Errorf("risk: %w", err)
	}
	if t.Format != TransferFormat {
		return t, errors.New("risk: the format is not " + TransferFormat)
	}
	return t, nil
}
