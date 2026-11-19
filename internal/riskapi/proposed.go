package riskapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"unicode/utf8"

	"github.com/rformer/fair-app/pkg/authz"
)

// F-013 T-09 (F-013-AC-17; design §3.6): a proposed next version of a
// scenario with a control set adding a control, for the analyst to review
// in the editor, save (F-003's save) and run (F-005's request). Nothing is
// saved, no pin changes and nothing runs here.
//
//	GET /api/v1/scenarios/{id}/proposed?add_control={control}[&set={name}]
//
// The new set copies the named set, or the first current one (else the
// first), adds the control at its latest version as proposed, is not
// current, and is named "With <control>" (made unique). scenario.edit at
// the scenario's BU; the control must be readable.
func (a *API) proposeScenario(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewAnywhere(w, r, p, scenarios.view) {
		return
	}
	h, err := a.head(r.Context(), scenarios, p, r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	if !a.editAt(w, r, p, scenarios.edit, h.BUID, true) || !active(w, h) {
		return
	}
	q := r.URL.Query()
	cid := q.Get("add_control")
	if !uuidRE.MatchString(cid) {
		problem(w, http.StatusBadRequest, "invalid_value", "add_control is the control to add", nil)
		return
	}
	ch, err := a.head(r.Context(), controls, p, cid)
	if errors.Is(err, errNotFound) {
		problem(w, http.StatusUnprocessableEntity, "invalid_value", "add_control is not a control you may read", nil)
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	if ch.ArchivedAt != nil {
		problem(w, http.StatusConflict, "archived", "the control is archived", nil)
		return
	}
	cv, _, err := a.version(r.Context(), controls, p, ch.ID, ch.CurrentVersion)
	if err != nil {
		fail(w, err)
		return
	}
	var ctl struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(cv.Document, &ctl); err != nil {
		fail(w, err)
		return
	}
	cur, _, err := a.version(r.Context(), scenarios, p, h.ID, h.CurrentVersion)
	if err != nil {
		fail(w, err)
		return
	}
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(cur.Document))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		fail(w, err)
		return
	}
	sets, _ := doc["control_sets"].([]any)
	if len(sets) == 0 {
		problem(w, http.StatusConflict, "not_applicable", "the scenario has no control set to copy", nil)
		return
	}
	from := -1
	if name := q.Get("set"); name != "" {
		for i, s := range sets {
			if m, _ := s.(map[string]any); m["name"] == name {
				from = i
			}
		}
		if from < 0 {
			problem(w, http.StatusUnprocessableEntity, "invalid_value", "set is not a control set of the scenario's latest version", nil)
			return
		}
	} else {
		for i, s := range sets {
			if m, _ := s.(map[string]any); m["current"] == true && from < 0 {
				from = i
			}
		}
		if from < 0 {
			from = 0
		}
	}
	src := sets[from].(map[string]any)
	ctls, _ := src["controls"].([]any)
	for _, c := range ctls {
		if m, _ := c.(map[string]any); m["id"] == ch.ID {
			problem(w, http.StatusConflict, "already_used", "the set already uses the control", nil)
			return
		}
	}
	added := make([]any, 0, len(ctls)+1)
	added = append(added, ctls...)
	added = append(added, map[string]any{"id": ch.ID, "version": ch.CurrentVersion, "status": "proposed"})
	set := map[string]any{"name": uniqueSetName(sets, "With "+ctl.Name), "current": false, "controls": added}
	doc["control_sets"] = append(sets, set)
	raw, err := json.Marshal(doc)
	if err != nil {
		fail(w, err)
		return
	}
	next := validDocument(w, "scenario", raw)
	if next == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scenario_id": h.ID, "base_version": h.CurrentVersion, "document": json.RawMessage(next.Canonical),
		"set": set["name"], "copied_from": src["name"], "control": map[string]any{"id": ch.ID, "version": ch.CurrentVersion, "name": ctl.Name}})
}

// uniqueSetName is name, clipped to 200 characters, with " (2)", " (3)"…
// when a set already has it.
func uniqueSetName(sets []any, name string) string {
	clip := func(s string, n int) string {
		for utf8.RuneCountInString(s) > n {
			_, size := utf8.DecodeLastRuneInString(s)
			s = s[:len(s)-size]
		}
		return s
	}
	taken := map[string]bool{}
	for _, s := range sets {
		if m, ok := s.(map[string]any); ok {
			if n, ok := m["name"].(string); ok {
				taken[n] = true
			}
		}
	}
	base := clip(name, 190)
	out := base
	for i := 2; taken[out]; i++ {
		out = base + " (" + strconv.Itoa(i) + ")"
	}
	return out
}
