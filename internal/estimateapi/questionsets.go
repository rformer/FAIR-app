package estimateapi

import (
	"net/http"

	"github.com/rformer/fair-app/pkg/authz"
)

// F-004 T-11 (AC-24 to AC-26; design §6.6): question sets, for holders of
// calibration.manage (checked at the root by the database). The shipped
// set is read-only; custom sets are created, filled, activated, retired.

const permCalibrationManage authz.Permission = "calibration.manage"

func (a *API) manager(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	return a.anywhere(w, r, p, []authz.Permission{permCalibrationManage})
}

func (a *API) pathID(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	id := r.PathValue(name)
	if !uuidRE.MatchString(id) {
		fail(w, errNotFound)
		return "", false
	}
	return id, true
}

// listQuestionSets lists every set with its number of current questions.
func (a *API) listQuestionSets(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if a.manager(w, r, p) {
		a.callJSON(w, r, p, http.StatusOK, "SELECT jsonb_build_object('sets', estimate.question_sets())")
	}
}

// getQuestionSet reads a set with its questions' latest versions, answers
// and sources (AC-26: managers only).
func (a *API) getQuestionSet(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.manager(w, r, p) {
		return
	}
	if id, ok := a.pathID(w, r, "id"); ok {
		a.callJSON(w, r, p, http.StatusOK, "SELECT estimate.question_set($1)", id)
	}
}

// createQuestionSet creates a custom set, as a draft (AC-25).
func (a *API) createQuestionSet(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if !a.manager(w, r, p) || !decode(w, r, &body) {
		return
	}
	a.callJSON(w, r, p, http.StatusCreated, "SELECT jsonb_build_object('id', estimate.create_set($1, $2))", body.Name, body.Description)
}

type questionBody struct {
	Kind   string  `json:"kind"`
	Text   string  `json:"text"`
	Unit   *string `json:"unit"`
	Answer string  `json:"answer"`
	Source string  `json:"source"`
}

// addQuestion adds a question to a custom set (AC-25).
func (a *API) addQuestion(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body questionBody
	if !a.manager(w, r, p) || !decode(w, r, &body) {
		return
	}
	if id, ok := a.pathID(w, r, "id"); ok {
		a.callJSON(w, r, p, http.StatusCreated, "SELECT jsonb_build_object('id', estimate.add_question($1, $2, $3, $4, $5, $6))",
			id, body.Kind, body.Text, body.Unit, body.Answer, body.Source)
	}
}

// editQuestion saves a new version of a question of a custom set; its kind
// does not change (AC-25).
func (a *API) editQuestion(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	var body questionBody
	if !a.manager(w, r, p) || !decode(w, r, &body) {
		return
	}
	if body.Kind != "" {
		problem(w, http.StatusBadRequest, "invalid_value", "a question's kind does not change; retire it and add another", nil)
		return
	}
	if id, ok := a.pathID(w, r, "id"); ok {
		a.callJSON(w, r, p, http.StatusOK, "SELECT jsonb_build_object('id', $1::uuid, 'version', estimate.edit_question($1, $2, $3, $4, $5))",
			id, body.Text, body.Unit, body.Answer, body.Source)
	}
}

// retireQuestion retires a question of a custom set: no new exercise asks
// it (AC-25).
func (a *API) retireQuestion(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.manager(w, r, p) {
		return
	}
	if id, ok := a.pathID(w, r, "id"); ok {
		a.callJSON(w, r, p, http.StatusOK, "SELECT jsonb_build_object('id', $1::uuid, 'retired', (estimate.retire_question($1) IS NULL))", id)
	}
}

func (a *API) setStatus(w http.ResponseWriter, r *http.Request, p authz.Principal, status string) {
	if !a.manager(w, r, p) {
		return
	}
	if id, ok := a.pathID(w, r, "id"); ok {
		a.callJSON(w, r, p, http.StatusOK, "SELECT jsonb_build_object('id', $1::uuid, 'status', $2::text, 'done', (estimate.set_set_status($1, $2) IS NULL))", id, status)
	}
}

// activateQuestionSet makes a draft set's questions available to exercises.
func (a *API) activateQuestionSet(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.setStatus(w, r, p, "active")
}

// retireQuestionSet takes a set out of new exercises.
func (a *API) retireQuestionSet(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	a.setStatus(w, r, p, "retired")
}
