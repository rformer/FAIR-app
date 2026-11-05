package audit

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// F-002 T-16: TLS 1.2 or later, plain TCP only in development (AC-22).
func TestSyslogTLS(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for _, e := range []string{"production", "staging"} {
		if _, err := SyslogTLS(e, env(map[string]string{"FAIR_AUDIT_SYSLOG_PLAINTEXT": "true"})); err == nil {
			t.Errorf("plain TCP accepted in %s", e)
		}
	}
	if tc, err := SyslogTLS("development", env(map[string]string{"FAIR_AUDIT_SYSLOG_PLAINTEXT": "true"})); err != nil || tc != nil {
		t.Fatalf("development plain TCP: %v %v", tc, err)
	}
	tc, err := SyslogTLS("production", env(nil))
	if err != nil || tc == nil || tc.MinVersion != tls.VersionTLS12 || tc.RootCAs != nil {
		t.Fatalf("default: %+v %v", tc, err)
	}
	dir := t.TempDir()
	if _, err := SyslogTLS("production", env(map[string]string{"FAIR_AUDIT_SYSLOG_CA_FILE": filepath.Join(dir, "none.pem")})); err == nil {
		t.Fatal("a missing CA file accepted")
	}
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SyslogTLS("production", env(map[string]string{"FAIR_AUDIT_SYSLOG_CA_FILE": empty})); err == nil {
		t.Fatal("a CA file without a certificate accepted")
	}
}

// RFC 5424 with octet counting; the body exactly as recorded.
func TestSyslogFrame(t *testing.T) {
	body := []byte(`{"actor":"u","id":"e1","severity":"high","time":"2026-11-05T10:00:00.123456Z","type":"setting.changed"}`)
	frame, err := SyslogFrame(42, 3, []byte{0xab, 0xcd}, body, "audit 0\x01")
	if err != nil {
		t.Fatal(err)
	}
	n, msg, ok := strings.Cut(string(frame), " ")
	if !ok || n != strconv.Itoa(len(msg)) {
		t.Fatalf("framing %q", frame[:20])
	}
	want := `<84>1 2026-11-05T10:00:00.123456Z audit0 fair-audit - setting.changed [fair@32473 seq="42" chain="abcd" segment="3"] ` + string(body)
	if msg != want {
		t.Fatalf("message\n got %s\nwant %s", msg, want)
	}
	for sev, pri := range map[string]string{"critical": "<82>", "low": "<85>", "info": "<86>"} {
		f, _ := SyslogFrame(1, 1, nil, []byte(`{"severity":"`+sev+`","type":"x"}`), "")
		if _, m, _ := strings.Cut(string(f), " "); !strings.HasPrefix(m, pri+"1 - - fair-audit - x ") {
			t.Errorf("%s: %s", sev, m)
		}
	}
	if _, err := SyslogFrame(1, 1, nil, []byte("not json"), "h"); err == nil {
		t.Error("a body that is not JSON")
	}
	if _, err := SyslogFrame(1, 1, nil, []byte("{\"type\":\"a\nb\"}"), "h"); err == nil {
		t.Error("a body of two lines")
	}
	long := strings.Repeat("t", 40)
	f, _ := SyslogFrame(1, 1, nil, []byte(`{"type":"`+long+`"}`), "")
	if !strings.Contains(string(f), " "+long[:32]+" [") {
		t.Errorf("MSGID not cut to 32: %s", f)
	}
}
