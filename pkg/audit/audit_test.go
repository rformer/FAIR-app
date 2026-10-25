package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNormalizeRejectsIncompleteEvents(t *testing.T) {
	for _, e := range []Event{
		{Severity: SeverityInfo, Actor: "a"},
		{Type: "x", Actor: "a"},
		{Type: "x", Severity: SeverityInfo},
		{Type: "x", Severity: "bogus", Actor: "a"},
	} {
		if _, err := Normalize(e, time.Now()); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("Normalize(%+v) err=%v, want ErrInvalidEvent", e, err)
		}
	}
}

func TestNormalizeFillsIDAndTime(t *testing.T) {
	e, err := Normalize(Event{Type: "x", Severity: SeverityHigh, Actor: "a"}, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(e.ID) != 32 || e.Time.IsZero() {
		t.Fatalf("id=%q time=%v", e.ID, e.Time)
	}
}

func TestJSONLines(t *testing.T) {
	var buf bytes.Buffer
	j := NewJSONLines(&buf)
	if err := j.Emit(context.Background(), Event{Type: "setting.changed", Severity: SeverityHigh, Actor: "u1", Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["kind"] != "audit" || got["type"] != "setting.changed" || got["severity"] != "high" {
		t.Fatalf("unexpected record: %v", got)
	}
}

type failing struct{}

func (failing) Emit(context.Context, Event) error { return errors.New("sink down") }

func TestMultiReportsFailures(t *testing.T) {
	m := NewMemory()
	err := Multi{m, failing{}}.Emit(context.Background(), Event{Type: "x", Severity: SeverityInfo, Actor: "a"})
	if err == nil {
		t.Fatal("Multi must surface sink failures, never drop silently")
	}
	if len(m.Events()) != 1 {
		t.Fatal("healthy sinks must still receive the event")
	}
}

func TestSyslogRFC5424OverTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		lenStr, _ := r.ReadString(' ')
		n, _ := strconv.Atoi(strings.TrimSpace(lenStr))
		buf := make([]byte, n)
		_, _ = r.Read(buf)
		got <- string(buf)
	}()

	s := NewSyslog(ln.Addr().String(), "fair-iam", nil)
	defer s.Close()
	if err := s.Emit(context.Background(), Event{Type: "authn.login.success", Severity: SeverityCritical, Actor: "u1"}); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-got:
		if !strings.HasPrefix(msg, "<82>1 ") { // facility 10*8 + critical(2)
			t.Fatalf("bad PRI/version: %q", msg[:12])
		}
		if !strings.Contains(msg, " fair-iam - authn.login.success - {") {
			t.Fatalf("bad header: %q", msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no syslog message received")
	}
}

func TestMsgIDSanitized(t *testing.T) {
	if got := sanitizeMsgID("a b\x01c" + strings.Repeat("x", 40)); strings.ContainsAny(got, " \x01") || len(got) > 32 {
		t.Fatalf("msgid not sanitized: %q", got)
	}
}
