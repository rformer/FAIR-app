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
