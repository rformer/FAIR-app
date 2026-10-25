package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateSecureDefaults(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"production requires TLS files", Config{Env: "production", RequireFIPS: true}, true},
		{"production refuses plaintext", Config{Env: "production", AllowPlaintext: true, RequireFIPS: true}, true},
		{"production refuses FIPS off", Config{Env: "production", TLSCertFile: "c", TLSKeyFile: "k"}, true},
		{"production with TLS and FIPS ok", Config{Env: "production", TLSCertFile: "c", TLSKeyFile: "k", RequireFIPS: true}, false},
		{"development may use plaintext", Config{Env: "development", AllowPlaintext: true}, false},
		{"unknown env rejected", Config{Env: "staging", TLSCertFile: "c", TLSKeyFile: "k", RequireFIPS: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestLoadDefaultsToProduction(t *testing.T) {
	t.Setenv("FAIR_ENV", "")
	t.Setenv("FAIR_TLS_CERT_FILE", "")
	t.Setenv("FAIR_TLS_KEY_FILE", "")
	c, err := Load("iam")
	if c.Env != "production" {
		t.Fatalf("default env = %q, want production", c.Env)
	}
	if !c.RequireFIPS {
		t.Fatal("RequireFIPS must default to true")
	}
	if err == nil {
		t.Fatal("expected error: production without TLS must not load")
	}
}

func TestReadSecretFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s")
	if err := os.WriteFile(p, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := ReadSecretFile(p)
	if err != nil || s != "hunter2" {
		t.Fatalf("got %q, %v", s, err)
	}
	empty := filepath.Join(dir, "e")
	_ = os.WriteFile(empty, []byte("\n"), 0o600)
	if _, err := ReadSecretFile(empty); err == nil {
		t.Fatal("empty secret must error")
	}
}
