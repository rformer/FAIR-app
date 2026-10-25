package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/iam/config"
)

func TestDefaults(t *testing.T) {
	c, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Profile != "fedramp-moderate" || c.HTTPAddr != ":8080" || len(c.AuditSinks) != 1 || c.AuditSinks[0] != "log" {
		t.Fatalf("unexpected defaults %+v", c)
	}
}

func TestAuditCannotBeDisabled(t *testing.T) {
	t.Setenv("AUDIT_SINKS", " , ")
	if _, err := config.Load(); err == nil || !strings.Contains(err.Error(), "audit cannot be disabled") {
		t.Fatalf("got %v", err)
	}
}

func TestSinkRequiresEndpoint(t *testing.T) {
	t.Setenv("AUDIT_SINKS", "log,nats,otlp,syslog,carrier-pigeon")
	_, err := config.Load()
	for _, want := range []string{"NATS_URL", "AUDIT_OTLP_ENDPOINT", "AUDIT_SYSLOG_ADDR", "carrier-pigeon"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %s in %v", want, err)
		}
	}
}

func TestUnknownProfileRejected(t *testing.T) {
	t.Setenv("IAM_PROFILE", "anything-goes")
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error")
	}
}

func TestSecretFromFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dburl")
	if err := os.WriteFile(p, []byte("postgres://app_rw@db/fair\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IAM_DATABASE_URL_FILE", p)
	c, err := config.Load()
	if err != nil || c.DatabaseURL != "postgres://app_rw@db/fair" {
		t.Fatalf("got %q, %v", c.DatabaseURL, err)
	}
}
