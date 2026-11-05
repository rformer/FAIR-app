package audit

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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

// F-002 T-17: the OTLP forwarder's TLS follows the same rules.
func TestOTLPTLS(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if _, err := OTLPTLS("production", env(map[string]string{"FAIR_AUDIT_OTLP_PLAINTEXT": "true"})); err == nil {
		t.Fatal("plaintext OTLP accepted in production")
	}
	if tc, err := OTLPTLS("development", env(map[string]string{"FAIR_AUDIT_OTLP_PLAINTEXT": "true"})); err != nil || tc != nil {
		t.Fatalf("development plaintext: %v %v", tc, err)
	}
	if tc, err := OTLPTLS("production", env(nil)); err != nil || tc.MinVersion != tls.VersionTLS12 {
		t.Fatalf("default: %+v %v", tc, err)
	}
	if _, err := OTLPTLS("production", env(map[string]string{"FAIR_AUDIT_OTLP_CA_FILE": filepath.Join(t.TempDir(), "none")})); err == nil ||
		!strings.Contains(err.Error(), "FAIR_AUDIT_OTLP_CA_FILE") {
		t.Fatalf("missing CA: %v", err)
	}
	// The syslog variables do not configure OTLP.
	if tc, err := OTLPTLS("production", env(map[string]string{"FAIR_AUDIT_SYSLOG_PLAINTEXT": "true"})); err != nil || tc == nil {
		t.Fatalf("syslog's variable changed OTLP: %v %v", tc, err)
	}
}

// One log record per record, in order, the body exactly as recorded.
func TestOTLPRequest(t *testing.T) {
	recs := []ForwardRecord{
		{Seq: 7, Segment: 2, Chain: []byte{0x01, 0x02}, Body: []byte(`{"severity":"critical","time":"2026-11-05T10:00:00.000001Z","type":"audit.verification_failed"}`)},
		{Seq: 8, Segment: 2, Chain: []byte{0xff}, Body: []byte(`{"severity":"low","type":"audit.searched"}`)},
		{Seq: 9, Segment: 3, Body: []byte(`{"severity":"high","type":"x"}`)},
		{Seq: 10, Segment: 3, Body: []byte(`{"severity":"info","type":"y"}`)},
	}
	observed := time.Date(2026, 11, 5, 11, 0, 0, 0, time.UTC)
	req, err := OTLPRequest(recs, "audit-0", observed)
	if err != nil {
		t.Fatal(err)
	}
	lrs := req.GetResourceLogs()[0].GetScopeLogs()[0].GetLogRecords()
	if len(lrs) != 4 {
		t.Fatalf("%d log records", len(lrs))
	}
	want := []string{"SEVERITY_NUMBER_ERROR", "SEVERITY_NUMBER_INFO4", "SEVERITY_NUMBER_WARN", "SEVERITY_NUMBER_INFO"}
	for i, lr := range lrs {
		if lr.GetBody().GetStringValue() != string(recs[i].Body) || lr.GetSeverityNumber().String() != want[i] ||
			lr.GetObservedTimeUnixNano() != uint64(observed.UnixNano()) {
			t.Errorf("record %d: %v", i, lr)
		}
		got := map[string]string{}
		for _, kv := range lr.GetAttributes() {
			got[kv.GetKey()] = kv.GetValue().String()
		}
		if !strings.Contains(got["fair.seq"], strconv.FormatInt(recs[i].Seq, 10)) || !strings.Contains(got["fair.segment"], strconv.FormatInt(recs[i].Segment, 10)) {
			t.Errorf("record %d attributes %v", i, got)
		}
	}
	if lrs[0].GetEventName() != "audit.verification_failed" || lrs[0].GetTimeUnixNano() != uint64(time.Date(2026, 11, 5, 10, 0, 0, 1000, time.UTC).UnixNano()) {
		t.Errorf("first record %v", lrs[0])
	}
	if lrs[1].GetTimeUnixNano() != 0 {
		t.Error("a record without a time got one")
	}
	if c := lrs[0].GetAttributes()[1]; c.GetKey() != "fair.chain" || c.GetValue().GetStringValue() != "0102" {
		t.Errorf("chain %v", c)
	}
	if _, err := OTLPRequest([]ForwardRecord{{Seq: 1, Body: []byte("nope")}}, "", observed); err == nil {
		t.Error("a body that is not JSON")
	}
}
