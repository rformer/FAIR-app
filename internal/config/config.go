// Package config loads service configuration from the environment.
//
// Secure by default (ADR-006): TLS is required unless plaintext is explicitly
// allowed for local development, and plaintext is never allowed when
// FAIR_ENV=production. Secrets are read from files (mounted from a secret
// store), never from literal environment values.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the runtime configuration for a FAIR platform service.
type Config struct {
	ServiceName string
	Env         string // "production" or "development"
	ListenAddr  string

	TLSCertFile    string
	TLSKeyFile     string
	AllowPlaintext bool // development only; refused in production

	RequireFIPS bool // default true; startup fails if the FIPS module is not active

	// DeploymentMode is ModeSaaS or ModeSelfHosted (ADR-005). Required when
	// FAIR_ENV=production, so a SaaS instance can never run as self-hosted
	// by omission; development defaults to self-hosted.
	DeploymentMode string

	ShutdownTimeout time.Duration
}

// Deployment modes (ADR-005).
const (
	ModeSaaS       = "saas"
	ModeSelfHosted = "self-hosted"
)

// Load reads configuration for the named service from environment variables.
func Load(service string) (Config, error) {
	c := Config{
		ServiceName:     service,
		Env:             getenv("FAIR_ENV", "production"),
		ListenAddr:      getenv("FAIR_LISTEN_ADDR", ":8443"),
		TLSCertFile:     os.Getenv("FAIR_TLS_CERT_FILE"),
		TLSKeyFile:      os.Getenv("FAIR_TLS_KEY_FILE"),
		DeploymentMode:  os.Getenv("FAIR_DEPLOYMENT_MODE"),
		ShutdownTimeout: 20 * time.Second,
	}
	if c.DeploymentMode == "" && c.Env == "development" {
		c.DeploymentMode = ModeSelfHosted
	}

	var err error
	if c.AllowPlaintext, err = getbool("FAIR_ALLOW_PLAINTEXT", false); err != nil {
		return c, err
	}
	if c.RequireFIPS, err = getbool("FAIR_REQUIRE_FIPS", true); err != nil {
		return c, err
	}
	if v := os.Getenv("FAIR_SHUTDOWN_TIMEOUT"); v != "" {
		d, perr := time.ParseDuration(v)
		if perr != nil {
			return c, fmt.Errorf("FAIR_SHUTDOWN_TIMEOUT: %w", perr)
		}
		c.ShutdownTimeout = d
	}
	return c, c.Validate()
}

// Validate enforces secure-by-default rules.
func (c Config) Validate() error {
	var errs []error
	switch c.Env {
	case "production", "development":
	default:
		errs = append(errs, fmt.Errorf("FAIR_ENV must be production or development, got %q", c.Env))
	}
	if c.AllowPlaintext && c.Env == "production" {
		errs = append(errs, errors.New("plaintext listening is not permitted when FAIR_ENV=production"))
	}
	if !c.AllowPlaintext && (c.TLSCertFile == "" || c.TLSKeyFile == "") {
		errs = append(errs, errors.New("FAIR_TLS_CERT_FILE and FAIR_TLS_KEY_FILE are required (TLS is mandatory)"))
	}
	if !c.RequireFIPS && c.Env == "production" {
		errs = append(errs, errors.New("FAIR_REQUIRE_FIPS=false is not permitted when FAIR_ENV=production"))
	}
	switch c.DeploymentMode {
	case ModeSaaS, ModeSelfHosted:
	case "":
		errs = append(errs, errors.New("FAIR_DEPLOYMENT_MODE (saas or self-hosted) is required when FAIR_ENV=production"))
	default:
		errs = append(errs, fmt.Errorf("FAIR_DEPLOYMENT_MODE must be saas or self-hosted, got %q", c.DeploymentMode))
	}
	return errors.Join(errs...)
}

// ReadSecretFile reads a secret from a mounted file and trims trailing newlines.
func ReadSecretFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("secret file path is empty")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading secret file: %w", err)
	}
	s := strings.TrimRight(string(b), "\r\n")
	if s == "" {
		return "", errors.New("secret file is empty")
	}
	return s, nil
}

func getenv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func getbool(k string, def bool) (bool, error) {
	v, ok := os.LookupEnv(k)
	if !ok || v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def, fmt.Errorf("%s: %w", k, err)
	}
	return b, nil
}
