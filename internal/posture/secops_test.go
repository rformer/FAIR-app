package posture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckDeploymentMode(t *testing.T) {
	saas, self := "saas", "self-hosted"
	for _, c := range []struct {
		env, configured string
		recorded        *string
		ok              bool
	}{
		{"production", "saas", &saas, true},
		{"production", "self-hosted", &self, true},
		{"production", "self-hosted", &saas, false}, // a SaaS install configured as self-hosted
		{"production", "saas", nil, false},          // installer step missing
		{"development", "self-hosted", nil, true},
		{"development", "self-hosted", &saas, false},
	} {
		if err := CheckDeploymentMode(c.env, c.configured, c.recorded); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

func TestNewSecOpsWebhook(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	short := filepath.Join(dir, "short")
	_ = os.WriteFile(good, []byte(strings.Repeat("s", 32)+"\n"), 0o600)
	_ = os.WriteFile(short, []byte("too-short"), 0o600)
	if _, err := NewSecOpsWebhook("production", "https://secops.example.test/hook", good); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string][3]string{
		"no URL":         {"production", "", good},
		"plain HTTP":     {"production", "http://secops.example.test/hook", good},
		"short secret":   {"production", "https://secops.example.test/hook", short},
		"no secret file": {"production", "https://secops.example.test/hook", ""},
		"missing secret": {"production", "https://secops.example.test/hook", filepath.Join(dir, "nope")},
	} {
		if _, err := NewSecOpsWebhook(c[0], c[1], c[2]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewSecOpsWebhook("development", "http://localhost:9/hook", good); err != nil {
		t.Errorf("development may use http: %v", err)
	}
}

func TestSecOpsSignature(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	body := []byte(`{"type":"setting.weakened"}`)
	sig := SignSecOps(secret, "1761523200", body)
	if !VerifySecOps(secret, "1761523200", body, sig) {
		t.Fatal("own signature does not verify")
	}
	for name, ok := range map[string]bool{
		"other body":      VerifySecOps(secret, "1761523200", []byte(`{"type":"setting.tightened"}`), sig),
		"other timestamp": VerifySecOps(secret, "1761523201", body, sig),
		"other secret":    VerifySecOps([]byte(strings.Repeat("x", 32)), "1761523200", body, sig),
	} {
		if ok {
			t.Errorf("%s verified", name)
		}
	}
}
