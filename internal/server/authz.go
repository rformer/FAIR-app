package server

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/rformer/fair-app/pkg/authz"
)

// WriteAuthzError answers a request that authz.Checker.Check refused:
//   - step-up required (F-015 T-24, design §6.6): 401 with
//     "WWW-Authenticate: step_up max_age=<seconds>", so the frontend re-runs
//     the IdP flow with that maximum authentication age;
//   - any other refusal: 404, because out-of-scope resources must not be
//     distinguishable from missing ones (F-001 AC-25). Errors are never
//     echoed to the client.
func WriteAuthzError(w http.ResponseWriter, err error) {
	var su *authz.StepUpError
	switch {
	case errors.As(err, &su):
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("step_up max_age=%d", int64(su.MaxAge.Seconds())))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "step_up_required"})
	case errors.Is(err, authz.ErrStepUpRequired):
		w.Header().Set("WWW-Authenticate", "step_up")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "step_up_required"})
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	}
}
