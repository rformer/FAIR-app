// Package config loads iam configuration from the environment.
// Secrets (database URLs with credentials, tokens) come from mounted
// Kubernetes Secrets or an external secrets store, never from values files.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rformer/fair-app/pkg/settings"
)

// Config is the iam service configuration.
type Config struct {
	HTTPAddr        string
	DatabaseURL     string // app_rw connection (serve)
	MigratorURL     string // app_migrator connection (migrate)
	Profile         string
	AuditSinks      []string // log, nats, otlp, syslog
	NATSURL         string
	AuditOTLP       string
	SyslogAddr      string
	SyslogNetwork   string
	ShutdownTimeout time.Duration
	RevertInterval  time.Duration
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envFile(key string) (string, error) {
	// FOO_FILE lets a Secret be mounted as a file instead of an env var.
	if path := os.Getenv(key + "_FILE"); path != "" {
		b, err := os.ReadFile(path) //nolint:gosec // G304: path is operator deployment config (a mounted Secret), never request input
		if err != nil {
			return "", fmt.Errorf("config: read %s_FILE: %w", key, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv(key), nil
}

// Load reads and validates configuration.
func Load() (Config, error) {
	var errs []error
	c := Config{
		HTTPAddr:      env("IAM_HTTP_ADDR", ":8080"),
		Profile:       env("IAM_PROFILE", settings.DefaultProfile),
		NATSURL:       env("NATS_URL", ""),
		AuditOTLP:     env("AUDIT_OTLP_ENDPOINT", ""),
		SyslogAddr:    env("AUDIT_SYSLOG_ADDR", ""),
		SyslogNetwork: env("AUDIT_SYSLOG_NETWORK", "tls"),
	}
	var err error
	if c.DatabaseURL, err = envFile("IAM_DATABASE_URL"); err != nil {
		errs = append(errs, err)
	}
	if c.MigratorURL, err = envFile("IAM_MIGRATOR_DATABASE_URL"); err != nil {
		errs = append(errs, err)
	}
	for _, s := range strings.Split(env("AUDIT_SINKS", "log"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			c.AuditSinks = append(c.AuditSinks, s)
		}
	}
	if c.ShutdownTimeout, err = time.ParseDuration(env("IAM_SHUTDOWN_TIMEOUT", "20s")); err != nil {
		errs = append(errs, fmt.Errorf("config: IAM_SHUTDOWN_TIMEOUT: %w", err))
	}
	if c.RevertInterval, err = time.ParseDuration(env("IAM_EXCEPTION_REVERT_INTERVAL", "1m")); err != nil {
		errs = append(errs, fmt.Errorf("config: IAM_EXCEPTION_REVERT_INTERVAL: %w", err))
	}
	if _, err := settings.LookupProfile(c.Profile); err != nil {
		errs = append(errs, err)
	}
	// Audit logging is on the hard floor: at least one sink is mandatory.
	if len(c.AuditSinks) == 0 {
		errs = append(errs, errors.New("config: AUDIT_SINKS must name at least one sink (audit cannot be disabled)"))
	}
	for _, s := range c.AuditSinks {
		switch s {
		case "log":
		case "nats":
			if c.NATSURL == "" {
				errs = append(errs, errors.New("config: AUDIT_SINKS includes nats but NATS_URL is empty"))
			}
		case "otlp":
			if c.AuditOTLP == "" {
				errs = append(errs, errors.New("config: AUDIT_SINKS includes otlp but AUDIT_OTLP_ENDPOINT is empty"))
			}
		case "syslog":
			if c.SyslogAddr == "" {
				errs = append(errs, errors.New("config: AUDIT_SINKS includes syslog but AUDIT_SYSLOG_ADDR is empty"))
			}
		default:
			errs = append(errs, fmt.Errorf("config: unknown audit sink %q", s))
		}
	}
	return c, errors.Join(errs...)
}
