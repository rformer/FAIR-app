package main

import "testing"

func TestParseUpstreams(t *testing.T) {
	got, err := parseUpstreams(" posture=https://posture.fair-platform:8443 , iam=https://iam.fair-platform:8443", "production")
	if err != nil || len(got) != 2 || got["posture"].Host != "posture.fair-platform:8443" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"posture=http://posture:8080", "posture", "posture=https://", "=https://x", "Pos/ture=https://x"} {
		if _, err := parseUpstreams(bad, "production"); err == nil {
			t.Errorf("%q accepted in production", bad)
		}
	}
	if _, err := parseUpstreams("posture=http://127.0.0.1:8080", "development"); err != nil {
		t.Errorf("plain http refused in development: %v", err)
	}
}

// F-001 T-20: the network binding configuration refuses a client address
// header without trusted proxies (any hop would be believed) and bad values.
func TestNetworkConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	n, err := networkConfig(env(map[string]string{"FAIR_CLIENT_IP_HEADER": "x-forwarded-for", "FAIR_TRUSTED_PROXIES": "10.0.0.0/8, 192.0.2.5, fd00::/8",
		"FAIR_SESSION_PREFIX_V4": "20", "FAIR_SESSION_PREFIX_V6": "56"}))
	if err != nil || len(n.Trusted) != 3 || n.Trusted[1].String() != "192.0.2.5/32" || n.V4Bits != 20 || n.V6Bits != 56 || n.ASN != nil {
		t.Fatalf("%+v %v", n, err)
	}
	if n, err := networkConfig(env(nil)); err != nil || n.Header != "" {
		t.Fatalf("defaults: %+v %v", n, err)
	}
	for name, m := range map[string]map[string]string{
		"header without proxies": {"FAIR_CLIENT_IP_HEADER": "X-Forwarded-For"},
		"unknown header":         {"FAIR_CLIENT_IP_HEADER": "True-Client-IP", "FAIR_TRUSTED_PROXIES": "10.0.0.0/8"},
		"bad proxy":              {"FAIR_TRUSTED_PROXIES": "10.0.0.0/33"},
		"prefix too narrow":      {"FAIR_SESSION_PREFIX_V4": "4"},
		"prefix not a number":    {"FAIR_SESSION_PREFIX_V6": "sixty-four"},
		"missing ASN files":      {"FAIR_ASN_DB_DIR": t.TempDir()},
	} {
		if _, err := networkConfig(env(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
