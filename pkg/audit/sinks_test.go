package audit_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/audit/audittest"
)

func TestMemoryContract(t *testing.T) {
	audittest.RunContract(t, func(t *testing.T) audittest.Harness {
		m := audit.NewMemory()
		return audittest.Harness{Emitter: m, Received: func(t *testing.T, n int) []audit.Event {
			return audittest.Poll(t, n, m.Events)
		}}
	})
}

func TestMultiContract(t *testing.T) {
	audittest.RunContract(t, func(t *testing.T) audittest.Harness {
		a, b := audit.NewMemory(), audit.NewMemory()
		m := audit.NewMulti().Add("a", a).Add("b", b)
		return audittest.Harness{Emitter: m, Received: func(t *testing.T, n int) []audit.Event {
			ga := audittest.Poll(t, n, a.Events)
			if gb := b.Events(); len(gb) != len(ga) {
				t.Fatalf("fan-out mismatch: a=%d b=%d", len(ga), len(gb))
			}
			return ga
		}}
	})
}

type failingSink struct{ audit.Memory }

func (f *failingSink) Emit(context.Context, audit.Event) error { return errors.New("disk full") }

func TestMultiReportsSinkFailureButStillDelivers(t *testing.T) {
	good := audit.NewMemory()
	m := audit.NewMulti().Add("bad", &failingSink{}).Add("good", good)
	err := m.Emit(context.Background(), audittest.SampleEvent(1))
	if err == nil || !strings.Contains(err.Error(), "sink bad") {
		t.Fatalf("want error naming failed sink, got %v", err)
	}
	if len(good.Events()) != 1 {
		t.Fatal("healthy sink should still receive the event")
	}
}

// fakePublisher records NATS publishes.
type fakePublisher struct {
	mu   sync.Mutex
	msgs map[string][][]byte
}

func (f *fakePublisher) Publish(_ context.Context, subject string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.msgs == nil {
		f.msgs = map[string][][]byte{}
	}
	f.msgs[subject] = append(f.msgs[subject], data)
	return nil
}

func (f *fakePublisher) events(t *testing.T) []audit.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []audit.Event
	for subj, list := range f.msgs {
		for _, b := range list {
			var e audit.Event
			if err := json.Unmarshal(b, &e); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if subj != "audit."+e.Type {
				t.Fatalf("event %s published on %s", e.Type, subj)
			}
			out = append(out, e)
		}
	}
	return out
}

func TestNATSSinkContract(t *testing.T) {
	audittest.RunContract(t, func(t *testing.T) audittest.Harness {
		p := &fakePublisher{}
		s := audit.NewNATSSink(p, "", nil)
		return audittest.Harness{Emitter: s, Received: func(t *testing.T, n int) []audit.Event {
			return audittest.Poll(t, n, func() []audit.Event { return p.events(t) })
		}}
	})
}

// fakeCollector is an OTLP/HTTP logs endpoint.
type fakeCollector struct {
	mu      sync.Mutex
	records []audit.OTLPLogRecord
	service []string
}

func (c *fakeCollector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/logs" || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req audit.OTLPLogsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rl := range req.ResourceLogs {
		for _, a := range rl.Resource.Attributes {
			if a.Key == "service.name" {
				c.service = append(c.service, a.Value.StringValue)
			}
		}
		for _, sl := range rl.ScopeLogs {
			c.records = append(c.records, sl.LogRecords...)
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (c *fakeCollector) events(t *testing.T) []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []audit.Event
	for _, r := range c.records {
		var e audit.Event
		if err := json.Unmarshal([]byte(r.Body.StringValue), &e); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if r.EventName != e.Type {
			t.Fatalf("eventName %q != type %q", r.EventName, e.Type)
		}
		if strconv.FormatInt(e.Time.UnixNano(), 10) != r.TimeUnixNano {
			t.Fatalf("timeUnixNano mismatch")
		}
		out = append(out, e)
	}
	return out
}

func TestOTLPSinkContract(t *testing.T) {
	audittest.RunContract(t, func(t *testing.T) audittest.Harness {
		c := &fakeCollector{}
		srv := httptest.NewServer(c)
		t.Cleanup(srv.Close)
		s := audit.NewOTLPSink(audit.OTLPConfig{Endpoint: srv.URL, ServiceName: "iam"})
		return audittest.Harness{Emitter: s, Received: func(t *testing.T, n int) []audit.Event {
			got := audittest.Poll(t, n, func() []audit.Event { return c.events(t) })
			for _, svc := range c.service {
				if svc != "iam" {
					t.Fatalf("service.name = %q", svc)
				}
			}
			return got
		}}
	})
}

func TestOTLPSinkSurfacesCollectorErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	s := audit.NewOTLPSink(audit.OTLPConfig{Endpoint: srv.URL})
	if err := s.Emit(context.Background(), audittest.SampleEvent(1)); err == nil {
		t.Fatal("expected error when collector rejects the export")
	}
}

// fakeSyslog is an RFC 5425-style octet-counted TCP receiver.
type fakeSyslog struct {
	mu   sync.Mutex
	msgs []string
}

var rfc5424 = regexp.MustCompile(`^<(\d+)>1 (\S+) (\S+) (\S+) - (\S+) \[fair@32473 [^\]]*(?:\\\][^\]]*)*\] (\{.*\})$`)

func (f *fakeSyslog) serve(t *testing.T, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			r := bufio.NewReader(c)
			for {
				lenStr, err := r.ReadString(' ')
				if err != nil {
					return
				}
				n, err := strconv.Atoi(strings.TrimSpace(lenStr))
				if err != nil {
					return
				}
				buf := make([]byte, n)
				if _, err := io.ReadFull(r, buf); err != nil {
					return
				}
				f.mu.Lock()
				f.msgs = append(f.msgs, string(buf))
				f.mu.Unlock()
			}
		}(conn)
	}
}

func (f *fakeSyslog) events(t *testing.T) []audit.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []audit.Event
	for _, m := range f.msgs {
		parts := rfc5424.FindStringSubmatch(m)
		if parts == nil {
			t.Fatalf("not RFC 5424: %q", m)
		}
		var e audit.Event
		if err := json.Unmarshal([]byte(parts[6]), &e); err != nil {
			t.Fatalf("decode: %v", err)
		}
		pri, _ := strconv.Atoi(parts[1])
		if pri/8 != 10 {
			t.Fatalf("facility %d, want authpriv(10)", pri/8)
		}
		if parts[5] != e.Type {
			t.Fatalf("MSGID %q != type %q", parts[5], e.Type)
		}
		out = append(out, e)
	}
	return out
}

func TestSyslogSinkContract(t *testing.T) {
	audittest.RunContract(t, func(t *testing.T) audittest.Harness {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		f := &fakeSyslog{}
		go f.serve(t, ln)
		s, err := audit.NewSyslogSink(audit.SyslogConfig{Network: "tcp", Addr: ln.Addr().String(), AppName: "iam"})
		if err != nil {
			t.Fatal(err)
		}
		return audittest.Harness{Emitter: s, Received: func(t *testing.T, n int) []audit.Event {
			return audittest.Poll(t, n, func() []audit.Event { return f.events(t) })
		}}
	})
}

func TestSyslogSinkReportsUnreachableReceiver(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	s, _ := audit.NewSyslogSink(audit.SyslogConfig{Network: "tcp", Addr: addr})
	if err := s.Emit(context.Background(), audittest.SampleEvent(1)); err == nil {
		t.Fatal("expected dial error")
	}
}

func TestEventValidateAcceptsNew(t *testing.T) {
	e := audit.New("authn.login.success", audit.SeverityInfo, audit.OutcomeSuccess,
		audit.Actor{Kind: audit.ActorUser, ID: "u1"}, audit.Target{Kind: "session", ID: "s1"})
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(e.ID) {
		t.Fatalf("ID %q is not a UUIDv4", e.ID)
	}
}

// lockedBuf is a concurrency-safe bytes buffer.
type lockedBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) events(t *testing.T) []audit.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []audit.Event
	for _, line := range strings.Split(strings.TrimSpace(l.b.String()), "\n") {
		if line == "" {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("decode: %v", err)
		}
		out = append(out, e)
	}
	return out
}

func TestWriterSinkContract(t *testing.T) {
	audittest.RunContract(t, func(t *testing.T) audittest.Harness {
		buf := &lockedBuf{}
		s := audit.NewWriterSink(buf)
		return audittest.Harness{Emitter: s, Received: func(t *testing.T, n int) []audit.Event {
			return audittest.Poll(t, n, func() []audit.Event { return buf.events(t) })
		}}
	})
}
