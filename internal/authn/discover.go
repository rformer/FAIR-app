package authn

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/authn/saml"
)

// Discovery is home-realm discovery (F-001 T-17; AC-02; design §5.1 step 1):
// POST /api/v1/auth/discover {"email", "return"} answers, for every email,
// with the same JSON shape: the login URL of the enabled IdP serving the
// email's domain, or none and a generic message. Discovery works on
// domains, which are configuration, so it reveals nothing about users.
// Requests are rate-limited per client.
type Discovery struct {
	Logins
	PerMinute int // requests per client per minute (default 20)

	mu      sync.Mutex
	buckets map[string]*bucket
}

// DiscoverPath is the discovery route.
const DiscoverPath = "/api/v1/auth/discover"

type bucket struct {
	tokens float64
	last   time.Time
}

// allow is a token bucket per client.
func (d *Discovery) allow(client string) bool {
	rate := d.PerMinute
	if rate <= 0 {
		rate = 20
	}
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.buckets == nil {
		d.buckets = map[string]*bucket{}
	}
	if len(d.buckets) > 10000 { // drop idle clients
		for k, b := range d.buckets {
			if now.Sub(b.last) > time.Minute {
				delete(d.buckets, k)
			}
		}
	}
	b, ok := d.buckets[client]
	if !ok {
		b = &bucket{tokens: float64(rate), last: now}
		d.buckets[client] = b
	}
	b.tokens = min(float64(rate), b.tokens+now.Sub(b.last).Minutes()*float64(rate))
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type discovered struct {
	LoginURL *string `json:"login_url"`
	Message  string  `json:"message"`
}

// ServeHTTP answers POST /api/v1/auth/discover.
func (d *Discovery) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !d.allow(clientIP(r)) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":"rate_limited"}`+"\n")
		return
	}
	var in struct {
		Email  string `json:"email"`
		Return string `json:"return"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_request"}`+"\n")
		return
	}
	out := discovered{Message: "Sign-in isn't set up for this email address. Contact your administrator."}
	if addr, err := mail.ParseAddress(strings.TrimSpace(in.Email)); err == nil {
		if at := strings.LastIndex(addr.Address, "@"); at > 0 {
			var id, kind string
			err := d.DB.QueryRow(r.Context(), "SELECT id::text, kind FROM iam.idp_discover($1)", addr.Address[at+1:]).Scan(&id, &kind)
			switch {
			case err == nil:
				proto := "oidc"
				if kind == "saml" {
					proto = "saml"
				}
				ret := in.Return
				if !saml.LocalPath(ret) {
					ret = "/"
				}
				u := "/api/v1/auth/" + proto + "/" + id + "/login?return=" + url.QueryEscape(ret)
				out = discovered{LoginURL: &u, Message: "Continue to your organization's sign-in."}
			case !errors.Is(err, pgx.ErrNoRows):
				d.fail(w, r, "", err)
				return
			}
		}
	}
	_ = json.NewEncoder(w).Encode(out)
}
