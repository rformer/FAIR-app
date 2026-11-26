package objstore

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// F-012 T-13 (ADR-012 amendment 1): with <prefix>_CREDENTIALS=web-identity
// the store gets short-lived credentials from STS for the service account's
// token, re-read from its file at every exchange, over TLS.
func TestWebIdentityCredentials(t *testing.T) {
	var mu sync.Mutex
	var got []string
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		got = append(got, r.Form.Get("Action")+" "+r.Form.Get("RoleArn")+" "+r.Form.Get("WebIdentityToken"))
		mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		_, _ = fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult>
<Credentials><AccessKeyId>ASIATEST</AccessKeyId><SecretAccessKey>secret</SecretAccessKey><SessionToken>session</SessionToken>
<Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	defer sts.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sts.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("service-account-jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"FAIR_AUDIT_STORE_ENDPOINT": "s3.us-gov-west-1.amazonaws.com:443", "FAIR_AUDIT_STORE_BUCKET": "fair-acme-audit-store",
		"FAIR_AUDIT_STORE_REGION": "us-gov-west-1", "FAIR_AUDIT_STORE_CA_FILE": ca,
		"FAIR_AUDIT_STORE_CREDENTIALS": "web-identity", "FAIR_AUDIT_STORE_STS_ENDPOINT": sts.URL,
		"AWS_WEB_IDENTITY_TOKEN_FILE": token, "AWS_ROLE_ARN": "arn:aws-us-gov:iam::111111111111:role/fair-acme-audit",
	}
	getenv := func(k string) string { return env[k] }
	if err := CredentialsConfigured("FAIR_AUDIT_STORE", getenv); err != nil {
		t.Fatal(err)
	}
	s, err := New(FromEnv("FAIR_AUDIT_STORE", "production", getenv))
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.c.GetCreds()
	if err != nil {
		t.Fatal(err)
	}
	if v.AccessKeyID != "ASIATEST" || v.SessionToken != "session" {
		t.Fatalf("credentials %+v", v)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "AssumeRoleWithWebIdentity arn:aws-us-gov:iam::111111111111:role/fair-acme-audit service-account-jwt" {
		t.Fatalf("STS requests %q", got)
	}
}

func TestWebIdentityConfig(t *testing.T) {
	base := func() map[string]string {
		return map[string]string{"S_ENDPOINT":            // #nosec G101 -- a test fixture: a path and an ARN, no credential
		"s3.us-gov-west-1.amazonaws.com:443", "S_BUCKET": "b", "S_REGION": "us-gov-west-1",
			"S_CREDENTIALS": "web-identity", "AWS_WEB_IDENTITY_TOKEN_FILE": "/var/run/token", "AWS_ROLE_ARN": "arn:aws-us-gov:iam::1:role/r"}
	}
	for name, c := range map[string]struct {
		change map[string]string
		want   string
	}{
		"no role":        {map[string]string{"AWS_ROLE_ARN": ""}, "AWS_ROLE_ARN"},
		"no token file":  {map[string]string{"AWS_WEB_IDENTITY_TOKEN_FILE": ""}, "AWS_WEB_IDENTITY_TOKEN_FILE"},
		"http STS":       {map[string]string{"S_STS_ENDPOINT": "http://sts.example"}, "https URL"},
		"no region, STS": {map[string]string{"S_REGION": ""}, "region"},
	} {
		env := base()
		for k, v := range c.change {
			env[k] = v
		}
		_, err := New(FromEnv("S", "production", func(k string) string { return env[k] }))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v", name, err)
		}
	}
	// Static key files remain the default, and are required without web identity.
	if err := CredentialsConfigured("S", func(k string) string { return map[string]string{}[k] }); err == nil {
		t.Error("no credentials configured passed")
	}
	cfg := FromEnv("S", "production", func(k string) string { return base()[k] })
	if !cfg.WebIdentity || cfg.RoleARN == "" {
		t.Fatalf("FromEnv %+v", cfg)
	}
	if err := checkWebIdentity(&cfg); err != nil || cfg.STSEndpoint != "https://sts.us-gov-west-1.amazonaws.com" {
		t.Fatalf("default STS endpoint %q %v", cfg.STSEndpoint, err)
	}
}
