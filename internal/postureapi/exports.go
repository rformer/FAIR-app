package postureapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/authz"
)

// --- OSCAL exports (T-35; AC-45 - AC-47) ------------------------------------

func (a *API) exportsSvc() posture.Exports {
	return posture.Exports{DB: a.DB, Audit: a.Audit, Key: a.ExportKey}
}

type exportJSON struct {
	ID             string    `json:"export_id"`
	Kind           string    `json:"kind"`
	AsOf           time.Time `json:"as_of"`
	CreatedAt      time.Time `json:"created_at"`
	CreatedBy      string    `json:"created_by"`
	DocumentSHA256 string    `json:"document_sha256"`
	SnapshotSHA256 string    `json:"snapshot_sha256"`
	KeyID          string    `json:"key_id"`
	// The exact bytes, as strings, so that clients can check the digest and
	// the signature without re-serializing anything.
	Document  string `json:"document,omitempty"`
	Statement string `json:"statement,omitempty"`
	Signature string `json:"signature,omitempty"`
}

func toJSON(e posture.Export) exportJSON {
	return exportJSON{e.ID, e.Kind, e.AsOf, e.CreatedAt, e.CreatedBy, e.DocumentDigest, e.SnapshotDigest, e.KeyID,
		string(e.Document), string(e.Statement), e.Signature}
}

func exportFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, posture.ErrNoPOAMItems):
		problem(w, http.StatusConflict, "nothing_open", "no exception or deviation is open, so there is no POA&M to export", nil)
	case errors.Is(err, posture.ErrExportNotFound):
		problem(w, http.StatusNotFound, "not_found", "no such export", nil)
	case errors.Is(err, posture.ErrNotReproducible):
		problem(w, http.StatusInternalServerError, "export_not_reproducible",
			"the recorded export cannot be reproduced; it has been reported as a critical event", nil)
	default:
		fail(w, err)
	}
}

// listExports: the export history (posture.view).
func (a *API) listExports(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p, "") {
		return
	}
	list, err := a.exportsSvc().List(r.Context(), 100)
	if err != nil {
		fail(w, err)
		return
	}
	out := make([]exportJSON, 0, len(list))
	for _, s := range list {
		out = append(out, exportJSON{ID: s.ID, Kind: s.Kind, AsOf: s.AsOf, CreatedAt: s.CreatedAt, CreatedBy: s.CreatedBy,
			DocumentSHA256: s.DocumentDigest, SnapshotSHA256: s.SnapshotDigest, KeyID: s.KeyID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"exports": out})
}

// createExport: without as_of, export the posture now (201); with as_of,
// reproduce the export of that kind recorded then (200). posture.export.
func (a *API) createExport(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Kind string     `json:"kind"`
		AsOf *time.Time `json:"as_of,omitempty"`
	}
	if !a.view(w, r, p, "") || !decode(w, r, &body) {
		return
	}
	if body.Kind != posture.KindAssessmentResults && body.Kind != posture.KindPOAM {
		problem(w, http.StatusBadRequest, "invalid_request", "kind is assessment_results or poam", nil)
		return
	}
	if body.AsOf != nil {
		e, err := a.exportsSvc().Reproduce(r.Context(), p, body.Kind, *body.AsOf)
		if err != nil {
			exportFail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, toJSON(e))
		return
	}
	e, err := a.exportsSvc().Create(r.Context(), p, body.Kind)
	if err != nil {
		exportFail(w, err)
		return
	}
	w.Header().Set("Location", Prefix+"/exports/"+e.ID)
	writeJSON(w, http.StatusCreated, toJSON(e))
}

// getExport: a recorded export, rebuilt from its snapshot (posture.export).
func (a *API) getExport(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.view(w, r, p, "") {
		return
	}
	e, err := a.exportsSvc().Get(r.Context(), p, r.PathValue("id"))
	if err != nil {
		exportFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toJSON(e))
}
