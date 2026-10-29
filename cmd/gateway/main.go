// Command gateway is the platform's gateway (F-001 design §2): browser
// sessions, CSRF protection, the session APIs, and the authenticated proxy
// to the services (F-001 T-13).
//
// Environment: as for every service (FAIR_ENV, FAIR_DEPLOYMENT_MODE,
// FAIR_LISTEN_ADDR, FAIR_TLS_CERT_FILE, FAIR_TLS_KEY_FILE, FAIR_REQUIRE_FIPS,
// ...), plus:
//
//	FAIR_DB_PASSWORD_FILE        app_gateway's password (and the libpq variables)
//	FAIR_SESSION_PEPPER_FILE     at least 32 random bytes; session ids are
//	                             stored as HMAC(pepper, token)
//	FAIR_DB_CONTEXT_KEY_ID       the authz.ctx_key the gateway signs with,
//	FAIR_DB_CONTEXT_KEY_FILE     and its secret (at least 32 bytes)
//	FAIR_JWT_KEYS_DIR            the internal-JWT signing keys (PEM per key id)
//	FAIR_PUBLIC_ORIGIN           the platform's origin, e.g. https://fair.example.com
//	FAIR_UPSTREAMS               name=https://host:port,... (/api/v1/<name>/ goes there)
//	FAIR_UPSTREAM_CA_FILE        the CA of the services' certificates
//	FAIR_LOGIN_TICKET_KEYS_DIR   iam's login-ticket public key(s) (PEM per key
//	                             id); with an iam upstream, /api/v1/auth/saml/
//	                             is forwarded and its tickets become sessions
//	FAIR_UI_DIR                  optional: the built web UI (web/dist)
//
// Session network binding (F-001 T-20, design §5.8):
//
//	FAIR_CLIENT_IP_HEADER        the ingress's client address header:
//	                             X-Forwarded-For or X-Real-IP (unset: the
//	                             connection's address)
//	FAIR_TRUSTED_PROXIES         the ingress's addresses (CIDRs, comma
//	                             separated); a header from any other hop is
//	                             ignored. Required with FAIR_CLIENT_IP_HEADER.
//	FAIR_SESSION_PREFIX_V4/_V6   a network's prefix sizes (default 24 and 64)
//	FAIR_ASN_DB_DIR              optional: iptoasn.com's ip2asn-v4.tsv and
//	                             ip2asn-v6.tsv (or .gz); without it the check
//	                             is prefix-only
package main

import (
	"context"
	"crypto/fips140"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/config"
	"github.com/rformer/fair-app/internal/dbconn"
	"github.com/rformer/fair-app/internal/gateway"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gateway:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load("gateway")
	if err != nil {
		return err
	}
	if cfg.RequireFIPS && !fips140.Enabled() {
		return errors.New("FIPS 140 mode is required but not enabled (build with GOFIPS140 and run with GODEBUG=fips140=on)")
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "gateway", "version", version)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pepper, err := readSecret("FAIR_SESSION_PEPPER_FILE", gateway.MinPepperLen)
	if err != nil {
		return err
	}
	ctxSecret, err := readSecret("FAIR_DB_CONTEXT_KEY_FILE", 32)
	if err != nil {
		return err
	}
	keys, err := authz.LoadLocalKeys(os.Getenv("FAIR_JWT_KEYS_DIR"))
	if err != nil {
		return fmt.Errorf("FAIR_JWT_KEYS_DIR: %w", err)
	}
	if _, _, err := keys.SigningKey(); err != nil {
		return fmt.Errorf("FAIR_JWT_KEYS_DIR has no signing key: %w", err)
	}
	origin := os.Getenv("FAIR_PUBLIC_ORIGIN")
	if u, err := url.Parse(origin); err != nil || u.Host == "" || u.Path != "" || !allowedScheme(u.Scheme, cfg.Env) {
		return fmt.Errorf("FAIR_PUBLIC_ORIGIN must be the platform's https origin, e.g. https://fair.example.com: %q", origin)
	}
	upstreams, err := parseUpstreams(os.Getenv("FAIR_UPSTREAMS"), cfg.Env)
	if err != nil {
		return err
	}
	transport, err := upstreamTransport(os.Getenv("FAIR_UPSTREAM_CA_FILE"))
	if err != nil {
		return err
	}
	network, err := networkConfig(os.Getenv)
	if err != nil {
		return err
	}
	if network.ASN != nil {
		logger.Info("ASN database loaded", "ranges", network.ASN.Len())
	} else {
		logger.Info("no ASN database: session network binding checks prefixes only")
	}

	cc, err := dbconn.Config(cfg.Env, "app_gateway", os.Getenv("FAIR_DB_PASSWORD_FILE"), "fair-gateway")
	if err != nil {
		return err
	}
	pc, err := pgxpool.ParseConfig("")
	if err != nil {
		return err
	}
	pc.ConnConfig = cc
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer pool.Close()

	// The session timeouts in force (AC-31), read as every service reads
	// settings; a stale snapshot fails requests closed.
	sc := settings.NewClient(settings.ClientOptions{Source: settings.DBSource{DB: pool}, Service: "gateway", Instance: os.Getenv("POD_NAME")})
	var defs []settings.Def
	for _, d := range settings.F001Defs() {
		switch d.Key {
		case settings.KeySessionIdleTimeout, settings.KeySessionAbsoluteTimeout, settings.KeyBannerEnabled, settings.KeySessionNetworkBinding:
			defs = append(defs, d)
		}
	}
	if err := sc.Register(defs...); err != nil {
		return err
	}
	if err := sc.Refresh(ctx); err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	go sc.Run(ctx, func(err error) { logger.Error("settings refresh", "error", err.Error()) })
	timeouts := func() (time.Duration, time.Duration, error) {
		idle, err := sc.Duration(settings.KeySessionIdleTimeout, "")
		if err != nil {
			return 0, 0, err
		}
		absolute, err := sc.Duration(settings.KeySessionAbsoluteTimeout, "")
		return idle, absolute, err
	}

	g := &gateway.Gateway{
		Sessions:   gateway.Sessions{DB: pool, Pepper: pepper, Timeouts: timeouts, Network: network},
		ContextKey: authz.ContextKey{ID: os.Getenv("FAIR_DB_CONTEXT_KEY_ID"), Secret: ctxSecret},
		JWT:        keys,
		Origin:     origin,
		Upstreams:  upstreams,
		Transport:  transport,
		Logger:     logger,
		// The system-use banner (T-19): required while banner.enabled is on,
		// and whenever the setting cannot be read.
		BannerEnabled: func() (bool, error) { return sc.Bool(settings.KeyBannerEnabled, "") },
		// The instance's session.network_binding (T-20); BU overrides are
		// applied by the services' permission checks.
		NetworkBinding: func() (string, error) { return sc.Enum(settings.KeySessionNetworkBinding, "") },
	}
	if _, ok := upstreams["iam"]; ok {
		if g.Tickets, err = authz.LoadLocalKeys(os.Getenv("FAIR_LOGIN_TICKET_KEYS_DIR")); err != nil {
			return fmt.Errorf("FAIR_LOGIN_TICKET_KEYS_DIR (iam's login-ticket public key): %w", err)
		}
	}
	if dir := os.Getenv("FAIR_UI_DIR"); dir != "" {
		g.UI = http.FileServer(http.Dir(dir))
	}

	srv := server.New(server.Options{Addr: cfg.ListenAddr, TLSCertFile: cfg.TLSCertFile, TLSKeyFile: cfg.TLSKeyFile,
		Plaintext: cfg.AllowPlaintext, Logger: logger})
	srv.Mux().Handle("/", g.Handler())
	srv.AddReadinessCheck(server.ReadinessCheck{Name: "database", Check: func(ctx context.Context) error { return pool.Ping(ctx) }})
	logger.Info("gateway started", "origin", origin, "upstreams", len(upstreams), "fips140", fips140.Enabled())
	return srv.Run(ctx, cfg.ShutdownTimeout)
}

func readSecret(env string, minLen int) ([]byte, error) {
	f := os.Getenv(env)
	if f == "" {
		return nil, fmt.Errorf("%s is required", env)
	}
	b, err := os.ReadFile(f) // #nosec G304 G703 -- operator-supplied secret file
	if err != nil {
		return nil, fmt.Errorf("%s: %w", env, err)
	}
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) < minLen {
		return nil, fmt.Errorf("%s must hold at least %d bytes", env, minLen)
	}
	return b, nil
}

// allowedScheme: https, or plain http in development only.
func allowedScheme(scheme, env string) bool {
	return scheme == "https" || (env == "development" && scheme == "http")
}

var serviceName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func parseUpstreams(s, env string) (map[string]*url.URL, error) {
	out := map[string]*url.URL{}
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		name, raw, ok := strings.Cut(item, "=")
		u, err := url.Parse(raw)
		if !ok || !serviceName.MatchString(name) || err != nil || u.Host == "" || !allowedScheme(u.Scheme, env) {
			return nil, fmt.Errorf("FAIR_UPSTREAMS: %q must be name=https://host:port", item)
		}
		out[name] = u
	}
	return out, nil
}

// upstreamTransport talks TLS 1.2+ to the services, trusting their CA.
func upstreamTransport(caFile string) (http.RoundTripper, error) {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) // #nosec G304 G703 -- operator-supplied CA file
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("FAIR_UPSTREAM_CA_FILE holds no certificate")
		}
		t.TLSClientConfig.RootCAs = pool
	}
	return t, nil
}

// networkConfig reads the session network binding configuration (T-20).
func networkConfig(getenv func(string) string) (gateway.Network, error) {
	n := gateway.Network{Header: strings.TrimSpace(getenv("FAIR_CLIENT_IP_HEADER"))}
	switch http.CanonicalHeaderKey(n.Header) {
	case "", "X-Forwarded-For", "X-Real-Ip":
	default:
		return n, fmt.Errorf("FAIR_CLIENT_IP_HEADER must be X-Forwarded-For or X-Real-IP, not %q", n.Header)
	}
	for _, c := range strings.Split(getenv("FAIR_TRUSTED_PROXIES"), ",") {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			a, aerr := netip.ParseAddr(c)
			if aerr != nil {
				return n, fmt.Errorf("FAIR_TRUSTED_PROXIES: %q is not a CIDR or address", c)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		n.Trusted = append(n.Trusted, p.Masked())
	}
	if n.Header != "" && len(n.Trusted) == 0 {
		return n, errors.New("FAIR_CLIENT_IP_HEADER needs FAIR_TRUSTED_PROXIES (the ingress's addresses): a header from any hop would be believed")
	}
	for _, b := range []struct {
		name     string
		dst      *int
		min, max int
	}{{"FAIR_SESSION_PREFIX_V4", &n.V4Bits, 8, 32}, {"FAIR_SESSION_PREFIX_V6", &n.V6Bits, 16, 128}} {
		v := strings.TrimSpace(getenv(b.name))
		if v == "" {
			continue
		}
		i, err := strconv.Atoi(v)
		if err != nil || i < b.min || i > b.max {
			return n, fmt.Errorf("%s must be %d to %d, not %q", b.name, b.min, b.max, v)
		}
		*b.dst = i
	}
	if dir := getenv("FAIR_ASN_DB_DIR"); dir != "" {
		db, err := gateway.LoadASNDB(dir)
		if err != nil {
			return n, fmt.Errorf("FAIR_ASN_DB_DIR: %w", err)
		}
		n.ASN = db
	}
	return n, nil
}
