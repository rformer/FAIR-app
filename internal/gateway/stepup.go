package gateway

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

// Step-up (F-015 T-24b, AC-33; design §6.6): a service answers 401 with
// WWW-Authenticate "step_up max_age=<seconds>" when the session's
// authentication is too old for a restricted BU. The gateway keeps the
// header and gives the browser the way back: the login route of the
// session's own IdP with step_up=1 and that max_age, which re-authenticates
// the user (SAML ForceAuthn, OIDC prompt=login) and replaces the session.
// Break-glass sessions sign in again with break-glass; service accounts
// get a new token (their auth time is the token's issue time).

var stepUpRE = regexp.MustCompile(`^step_up(?: max_age=(\d{1,7}))?$`)

// stepUp rewrites a service's step-up answer; other responses pass.
func (g *Gateway) stepUp(resp *http.Response) {
	if resp.StatusCode != http.StatusUnauthorized {
		return
	}
	m := stepUpRE.FindStringSubmatch(resp.Header.Get("WWW-Authenticate"))
	if m == nil {
		return
	}
	body := map[string]any{"error": "step_up_required",
		"detail": "this business unit needs a recent sign-in: sign in again"}
	maxAge := m[1]
	if maxAge != "" {
		n, _ := strconv.Atoi(maxAge)
		body["max_age"] = n
	}
	sess := sessionFrom(resp.Request.Context())
	if (sess.AuthMethod == "saml" || sess.AuthMethod == "oidc") && sess.IDPID != "" && !sess.ServiceAccount {
		q := url.Values{"step_up": {"1"}}
		if maxAge != "" {
			q.Set("max_age", maxAge)
		}
		body["login_url"] = "/api/v1/auth/" + sess.AuthMethod + "/" + url.PathEscape(sess.IDPID) + "/login?" + q.Encode()
	}
	b, err := json.Marshal(body)
	if err != nil {
		return
	}
	replace(resp, http.StatusUnauthorized, "application/json", append(b, '\n'))
}
