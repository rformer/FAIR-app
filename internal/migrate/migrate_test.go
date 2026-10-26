package migrate

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func secretFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConnConfigProductionRequiresVerifiedTLS(t *testing.T) {
	pw := secretFile(t, "s3cret\n")
	for _, mode := range []string{"", "disable", "allow", "prefer", "require", "verify-ca"} {
		t.Setenv("PGSSLMODE", mode)
		if _, err := ConnConfig("production", pw); err == nil || !strings.Contains(err.Error(), "verify-full") {
			t.Errorf("PGSSLMODE=%q in production: err = %v", mode, err)
		}
	}

	t.Setenv("PGSSLMODE", "verify-full")
	t.Setenv("PGHOST", "db.example.internal")
	cfg, err := ConnConfig("production", pw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSConfig == nil || cfg.TLSConfig.InsecureSkipVerify || cfg.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS config = %+v", cfg.TLSConfig)
	}
	if len(cfg.Fallbacks) != 0 {
		t.Fatalf("production config has %d fallbacks; plaintext retry must be impossible", len(cfg.Fallbacks))
	}
}

func TestConnConfigIdentityAndSecret(t *testing.T) {
	t.Setenv("PGSSLMODE", "prefer")
	t.Setenv("PGUSER", "postgres")
	t.Setenv("PGPASSWORD", "from-env")
	cfg, err := ConnConfig("development", secretFile(t, "from-file\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.User != "app_migrator" || cfg.Password != "from-file" {
		t.Fatalf("user/password = %q/%q; want app_migrator and the file secret", cfg.User, cfg.Password)
	}
	for _, fb := range cfg.Fallbacks {
		if fb.TLSConfig != nil && fb.TLSConfig.MinVersion != tls.VersionTLS12 {
			t.Fatal("fallback TLS below 1.2")
		}
	}

	for _, path := range []string{"", secretFile(t, "\n"), filepath.Join(t.TempDir(), "missing")} {
		if _, err := ConnConfig("development", path); err == nil {
			t.Errorf("password file %q accepted", path)
		}
	}
}
