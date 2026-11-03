package authn

import (
	"net/http"
	"strconv"
	"time"
)

// Step-up sign-in (F-015 T-24b, AC-33; design §6.6). When a service answers
// 401 step_up, the gateway sends the browser to the IdP's login route with
// step_up=1 and max_age: SAML asks for ForceAuthn, OIDC for prompt=login
// with max_age. The new session replaces the one the user came from, and
// the sign-in must prove a fresh authentication.

// StepUpHeader carries, from the gateway to iam, the handle of the live
// session a step-up sign-in replaces. The gateway sets it from the session
// cookie and drops any copy a client sends.
const StepUpHeader = "X-Fair-Step-Up-Session"

// maxStepUpAge bounds the max_age a step-up may ask for.
const maxStepUpAge = 24 * time.Hour

// stepUp reads a login request's step-up: ?step_up=1&max_age=<seconds>,
// and the session it replaces.
func stepUp(r *http.Request) (force bool, maxAge time.Duration, replaces string) {
	q := r.URL.Query()
	if q.Get("step_up") != "1" {
		return false, 0, ""
	}
	if n, err := strconv.Atoi(q.Get("max_age")); err == nil && n >= 0 && time.Duration(n)*time.Second <= maxStepUpAge {
		maxAge = time.Duration(n) * time.Second
	}
	if h := r.Header.Get(StepUpHeader); uuidRE.MatchString(h) {
		replaces = h
	}
	return true, maxAge, replaces
}

// stepUpFresh reports whether a step-up sign-in proves a new
// authentication: the IdP must report when it authenticated the user, and
// that must not be earlier than when FAIR asked (less clock skew). An IdP
// that ignored ForceAuthn or prompt=login, or reports no time, fails.
func stepUpFresh(authTime *time.Time, asked time.Time, skew time.Duration) bool {
	return authTime != nil && !authTime.Before(asked.Add(-skew))
}

// stepUpFailed refuses a step-up sign-in that does not prove a fresh
// authentication: audited high (authn.step_up_failed), answered like any
// failed sign-in. The session the user came from stays as it was.
func (h *Logins) stepUpFailed(w http.ResponseWriter, r *http.Request, idp string, attrs map[string]any) {
	if err := h.event(r.Context(), "authn.step_up_failed", "high", "anonymous", idp, attrs,
		"the IdP did not report a fresh authentication for a step-up sign-in"); err != nil && h.Logger != nil {
		h.Logger.Error("auditing a failed step-up", "error", err.Error())
	}
	writeFailure(w, http.StatusUnauthorized)
}
