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
		{"production requires TLS files", Config{Env: "production", RequireFIPS: true, DeploymentMode: ModeSaaS}, true},
		{"production refuses plaintext", Config{Env: "production", AllowPlaintext: true, RequireFIPS: true, DeploymentMode: ModeSaaS}, true},
		{"production refuses FIPS off", Config{Env: "production", TLSCertFile: "c", TLSKeyFile: "k", DeploymentMode: ModeSaaS}, true},
		{"production with TLS and FIPS ok", Config{Env: "production", TLSCertFile: "c", TLSKeyFile: "k", RequireFIPS: true, DeploymentMode: ModeSaaS}, false},
		{"production requires a deployment mode", Config{Env: "production", TLSCertFile: "c", TLSKeyFile: "k", RequireFIPS: true}, true},
		{"unknown deployment mode rejected", Config{Env: "production", TLSCertFile: "c", TLSKeyFile: "k", RequireFIPS: true, DeploymentMode: "cloud"}, true},
		{"self-hosted ok", Config{Env: "production", TLSCertFile: "c", TLSKeyFile: "k", RequireFIPS: true, DeploymentMode: ModeSelfHosted}, false},
		{"air-gapped ok", Config{Env: "production", TLSCertFile: "c", TLSKeyFile: "k", RequireFIPS: true, DeploymentMode: ModeAirGapped}, false},
		{"development may use plaintext", Config{Env: "development", AllowPlaintext: true, DeploymentMode: ModeSelfHosted}, false},
		{"unknown env rejected", Config{Env: "staging", TLSCertFile: "c", TLSKeyFile: "k", RequireFIPS: true, DeploymentMode: ModeSaaS}, true},
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

func TestDeploymentModeDefaults(t *testing.T) {
	t.Setenv("FAIR_DEPLOYMENT_MODE", "")
	t.Setenv("FAIR_ENV", "development")
	t.Setenv("FAIR_ALLOW_PLAINTEXT", "true")
	c, err := Load("posture")
	if err != nil || c.DeploymentMode != ModeSelfHosted {
		t.Fatalf("development default: %q %v", c.DeploymentMode, err)
	}
	t.Setenv("FAIR_ENV", "production")
	t.Setenv("FAIR_ALLOW_PLAINTEXT", "false")
	t.Setenv("FAIR_TLS_CERT_FILE", "c")
	t.Setenv("FAIR_TLS_KEY_FILE", "k")
	if _, err := Load("posture"); err == nil {
		t.Fatal("production loaded without FAIR_DEPLOYMENT_MODE")
	}
	t.Setenv("FAIR_DEPLOYMENT_MODE", "saas")
	if c, err := Load("posture"); err != nil || c.DeploymentMode != ModeSaaS {
		t.Fatalf("saas: %q %v", c.DeploymentMode, err)
	}
}
