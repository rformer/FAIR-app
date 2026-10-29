package gateway

import (
	"bytes"
	"context"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/rformer/fair-app/internal/authn"
	"github.com/rformer/fair-app/internal/authn/saml"
	"github.com/rformer/fair-app/internal/server"
)

// Login routes (F-001 T-15; design §5.1): /api/v1/auth/saml/ is forwarded
// to the iam service without a session (the IdP's POST to the ACS is
// cross-site by design, so it carries neither the session cookie nor a CSRF
// token). A login ticket in iam's response (authn.TicketHeader) is
// verified with iam's public key, redeemed once, and turned into a session;
// the browser gets the cookie and a page that moves it to the requested
// path. A ticket never comes from, or goes to, the browser.

type clientKey struct{}

// loginRoutes forwards the authentication routes to iam.
func (g *Gateway) loginRoutes(iam *url.URL) http.Handler {
	p := &httputil.ReverseProxy{
		Transport: g.Transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(iam)
			pr.Out.URL.Path, pr.Out.URL.RawPath = pr.In.URL.Path, pr.In.URL.RawPath
			pr.SetXForwarded()
			g.forwardedFor(pr)
			for _, h := range []string{"Cookie", "Authorization", server.DBContextHeader, CSRFHeader, authn.TicketHeader} {
				pr.Out.Header.Del(h)
			}
		},
		ModifyResponse: g.redeem,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			g.log(r, "login proxy", err)
			writeError(w, http.StatusBadGateway, "unavailable", "")
		},
	}
	return server.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		var ip net.IP
		if a := g.Sessions.Network.ClientIP(r); a.IsValid() {
			ip = net.IP(a.AsSlice())
		}
		p.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientKey{}, ip)))
	}))
}

// SCIMPrefix is the SCIM service provider (F-001 T-21), served by iam.
const SCIMPrefix = "/scim/v2/"

// scimRoute forwards SCIM to iam without a session: the IdP's SCIM client
// authenticates with its bearer token, which iam checks (AC-08). Browser
// credentials and internal headers never pass.
func (g *Gateway) scimRoute(iam *url.URL) http.Handler {
	p := &httputil.ReverseProxy{
		Transport: g.Transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(iam)
			pr.Out.URL.Path, pr.Out.URL.RawPath = pr.In.URL.Path, pr.In.URL.RawPath
			pr.SetXForwarded()
			g.forwardedFor(pr)
			for _, h := range []string{"Cookie", server.DBContextHeader, CSRFHeader, authn.TicketHeader} {
				pr.Out.Header.Del(h)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Set-Cookie")
			resp.Header.Del(authn.TicketHeader)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			g.log(r, "SCIM proxy", err)
			writeError(w, http.StatusBadGateway, "unavailable", "")
		},
	}
	return server.SecurityHeaders(p)
}

// forwardedFor tells a service the client's address as the trusted proxy
// header gives it (T-20), not the ingress's.
func (g *Gateway) forwardedFor(pr *httputil.ProxyRequest) {
	if a := g.Sessions.Network.ClientIP(pr.In); a.IsValid() {
		pr.Out.Header.Set("X-Forwarded-For", a.String())
	}
}

var landing = template.Must(template.New("landing").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Signed in</title>
<meta http-equiv="refresh" content="0;url={{.}}"></head>
<body><p>You are signed in. <a href="{{.}}">Continue</a>.</p></body></html>
`))

// redeem turns a login ticket into a session. Without a ticket, iam's
// response passes through (minus any cookie it might set).
func (g *Gateway) redeem(resp *http.Response) error {
	resp.Header.Del("Set-Cookie")
	tok := resp.Header.Get(authn.TicketHeader)
	if tok == "" {
		return nil
	}
	resp.Header.Del(authn.TicketHeader)
	ctx := resp.Request.Context()
	fail := func(status int) error {
		replace(resp, status, "application/json", []byte(`{"error":"sign_in_failed"}`+"\n"))
		return nil
	}
	if g.Tickets == nil {
		return fail(http.StatusServiceUnavailable)
	}
	t, err := authn.VerifyTicket(g.Tickets, tok, g.now())
	if err != nil {
		g.log(resp.Request, "login ticket", err)
		return fail(http.StatusUnauthorized)
	}
	var fresh bool
	if err := g.Sessions.DB.QueryRow(ctx, "SELECT iam.login_ticket_use($1, $2)", t.ID, time.Unix(t.Expiry, 0)).Scan(&fresh); err != nil {
		g.log(resp.Request, "redeeming a login ticket", err)
		return fail(http.StatusServiceUnavailable)
	}
	if !fresh {
		g.log(resp.Request, "login ticket", authn.ErrTicket)
		return fail(http.StatusUnauthorized)
	}
	ip, _ := ctx.Value(clientKey{}).(net.IP)
	_, cookie, err := g.Sessions.Create(ctx, Login{UserID: t.UserID, AuthMethod: t.AuthMethod, IDPID: t.IDPID, MFA: t.MFA, IP: ip,
		UserAgent: resp.Request.Header.Get("User-Agent")})
	if err != nil {
		g.log(resp.Request, "creating a session", err)
		return fail(http.StatusUnauthorized)
	}
	to := t.ReturnTo
	if !saml.LocalPath(to) {
		to = "/"
	}
	var page bytes.Buffer
	if err := landing.Execute(&page, to); err != nil {
		return fail(http.StatusInternalServerError)
	}
	replace(resp, http.StatusOK, "text/html; charset=utf-8", page.Bytes())
	resp.Header.Add("Set-Cookie", (&http.Cookie{Name: CookieName, Value: cookie, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode}).String())
	return nil
}

func replace(resp *http.Response, status int, contentType string, body []byte) {
	_ = resp.Body.Close()
	resp.StatusCode, resp.Status = status, strconv.Itoa(status)+" "+http.StatusText(status)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Content-Type", contentType)
	resp.Header.Del("Location")
	resp.Header.Set("Cache-Control", "no-store")
}
