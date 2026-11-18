package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rformer/fair-app/internal/egress"
)

// source is a local HTTPS source: requests are recorded, handler answers.
type source struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []*http.Request
}

func newSource(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *source {
	t.Helper()
	s := &source{}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.reqs = append(s.reqs, r.Clone(context.Background()))
		s.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *source) url(path string) string { return s.srv.URL + path }

// fetcher reaches the loopback test servers only (allowed as 127.0.0.1).
func (s *source) fetcher(allowed ...string) Fetcher {
	pool := x509.NewCertPool()
	pool.AddCert(s.srv.Certificate())
	if allowed == nil {
		allowed = []string{"127.0.0.1"}
	}
	g := egress.Guard{Setting: "integration.allowed_hosts", Allowed: func() []string { return allowed }}.
		AllowingForTest(netip.MustParsePrefix("127.0.0.0/8"))
	return Fetcher{Guard: g, TLS: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
}

func assetsReq(c Connector, mapping string, cred *Credential) TestRequest {
	return TestRequest{IntegrationID: "i-1", Kind: InputAssets, Mapping: json.RawMessage(mapping), Connector: c, Source: cred}
}

const itemMapping = `{"columns": {"/id": "external_id", "/unit": "bu", "/title": "name", "/kind": "asset_type", "/value/low": "value/min",
	"/value/likely": "value/ml", "/value/high": "value/max", "/value/confidence": "value/confidence", "/value/basis": "value/basis"},
	"values": {"asset_type": {"app": "application"}}}`

func records(t *testing.T, f *Fetched) []map[string]any {
	t.Helper()
	var b struct {
		Format   string           `json:"format"`
		Complete bool             `json:"complete"`
		Records  []map[string]any `json:"records"`
	}
	if err := json.Unmarshal(f.Body, &b); err != nil || b.Format != Format || !b.Complete {
		t.Fatalf("batch %s: %v", f.Body, err)
	}
	return b.Records
}

// F-011 T-17 (AC-04; design §3.3): http_json pages by next URL, maps by
// JSON pointers, sends the token, and builds one complete batch.
func TestHTTPJSONNextPaging(t *testing.T) {
	var src *source
	src = newSource(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "":
			fmt.Fprintf(w, `{"data": {"items": [{"id": "a-1", "unit": "A", "title": "Claims", "kind": "app", "value": {"low": 1000, "likely": 2000, "high": 5000, "confidence": 0.8, "basis": "replacement cost"}},
				{"id": "a-2", "unit": "A", "title": "", "kind": "app"}]}, "next": %q}`, src.url("/apps?page=2"))
		case "2":
			fmt.Fprint(w, `{"data": {"items": [{"id": "a-3", "unit": "A1", "title": "Billing", "kind": "app"}]}, "next": null}`)
		}
	})
	c := Connector{Type: ConnectorHTTPJSON, Source: src.url("/apps"), ScheduleMinutes: 60,
		Settings: json.RawMessage(`{"list": "/data/items", "paging": {"next": "/next"}}`)}
	got, err := src.fetcher().Fetch(context.Background(), assetsReq(c, itemMapping, &Credential{Token: "tok-1"}))
	if err != nil {
		t.Fatal(err)
	}
	recs := records(t, got)
	if got.Items != 3 || len(recs) != 3 || recs[0]["external_id"] != "a-1" || recs[0]["asset_type"] != "application" || recs[2]["bu"] != "A1" {
		t.Fatalf("records %v", recs)
	}
	if v := recs[0]["value"].(map[string]any); v["min"] != "1000" || v["ml"] != "2000" || v["basis"] != "replacement cost" {
		t.Errorf("value %v", v)
	}
	if len(got.Batch.Records) != 2 || got.Batch.Refusals != 1 || got.Batch.Refused[0].Pointer != "/name" {
		t.Errorf("checked batch: %d valid, refused %+v", len(got.Batch.Records), got.Batch.Refused)
	}
	for _, r := range src.reqs {
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer tok-1" {
			t.Errorf("request %s %s %q", r.Method, r.URL, r.Header.Get("Authorization"))
		}
	}
	// A test fetches the first page only.
	src.reqs = nil
	res, err := src.fetcher().Test(context.Background(), assetsReq(c, itemMapping, &Credential{Token: "tok-1"}))
	if err != nil || res.Records != 2 || len(res.Problems) != 1 || len(src.reqs) != 1 {
		t.Errorf("test: %+v %v (%d requests)", res, err, len(src.reqs))
	}
}

// Offset paging stops at a short page; basic credentials are sent.
func TestHTTPJSONOffsetPaging(t *testing.T) {
	all := []string{"a-1", "a-2", "a-3", "a-4", "a-5"}
	src := newSource(t, func(w http.ResponseWriter, r *http.Request) {
		off, _ := strconv.Atoi(r.URL.Query().Get("start"))
		n, _ := strconv.Atoi(r.URL.Query().Get("count"))
		var items []string
		for i := off; i < len(all) && i < off+n; i++ {
			items = append(items, fmt.Sprintf(`{"id": %q, "unit": "A", "title": "Asset %d", "kind": "app"}`, all[i], i))
		}
		fmt.Fprintf(w, "[%s]", strings.Join(items, ","))
	})
	c := Connector{Type: ConnectorHTTPJSON, Source: src.url("/assets?filter=active"), ScheduleMinutes: 60,
		Settings: json.RawMessage(`{"paging": {"offset_param": "start", "limit_param": "count", "page_size": 2}}`)}
	got, err := src.fetcher().Fetch(context.Background(), assetsReq(c, itemMapping, &Credential{Username: "svc", Password: "pw"}))
	if err != nil {
		t.Fatal(err)
	}
	if recs := records(t, got); len(recs) != 5 || len(src.reqs) != 3 {
		t.Fatalf("%d records in %d requests", len(recs), len(src.reqs))
	}
	for _, r := range src.reqs {
		if u, p, ok := r.BasicAuth(); !ok || u != "svc" || p != "pw" || r.URL.Query().Get("filter") != "active" {
			t.Errorf("request %s", r.URL)
		}
	}
}

// AC-04: the guard refuses hosts off the allow-list; a next page on another
// host is refused; redirects, failures, oversized pages and too many
// records fail the run.
func TestConnectorRefusals(t *testing.T) {
	ctx := context.Background()
	big := strings.Repeat("x", MaxPageBytes)
	src := newSource(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/elsewhere":
			fmt.Fprint(w, `{"items": [], "next": "https://198.51.100.7/steal"}`)
		case "/redirect":
			http.Redirect(w, r, "https://198.51.100.7/", http.StatusFound)
		case "/broken":
			http.Error(w, "no", http.StatusInternalServerError)
		case "/big":
			fmt.Fprintf(w, `{"items": [], "pad": %q}`, big)
		case "/many":
			var b strings.Builder
			b.WriteString("[")
			for i := range MaxRecords + 1 {
				if i > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, `{"id": "a-%d"}`, i)
			}
			b.WriteString("]")
			fmt.Fprint(w, b.String())
		case "/text":
			fmt.Fprint(w, "<html>")
		default:
			fmt.Fprint(w, `[]`)
		}
	})
	conn := func(path, settings string) Connector {
		return Connector{Type: ConnectorHTTPJSON, Source: src.url(path), ScheduleMinutes: 60, Settings: json.RawMessage(settings)}
	}
	if _, err := src.fetcher("cmdb.example.test").Fetch(ctx, assetsReq(conn("/", ""), itemMapping, nil)); !errors.Is(err, egress.ErrRefused) {
		t.Errorf("a host off the allow-list: %v", err)
	}
	if _, err := src.fetcher().Fetch(ctx, assetsReq(conn("/elsewhere", `{"list": "/items", "paging": {"next": "/next"}}`), itemMapping, nil)); !errors.Is(err, egress.ErrRefused) || !strings.Contains(err.Error(), "another host") {
		t.Errorf("a next page elsewhere: %v", err)
	}
	for path, want := range map[string]string{"/redirect": "redirect", "/broken": "500", "/big": "larger than", "/many": "more than 10000", "/text": "not JSON"} {
		if _, err := src.fetcher().Fetch(ctx, assetsReq(conn(path, ""), itemMapping, nil)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", path, err)
		}
	}
	for _, r := range src.reqs {
		if r.Method != "GET" {
			t.Errorf("a %s to the source", r.Method)
		}
	}
}

func TestCheckSettings(t *testing.T) {
	m := Mapping{Columns: map[string]string{"/id": "external_id"}}
	c := func(typ, settings string) Connector {
		return Connector{Type: typ, Source: "https://cmdb.example.test/api", ScheduleMinutes: 60, Settings: json.RawMessage(settings)}
	}
	for _, ok := range []Connector{c(ConnectorHTTPJSON, ""), c(ConnectorHTTPJSON, `{"list": "/x", "paging": {"next": "/n"}}`),
		c(ConnectorServiceNowCMDB, `{"class": "cmdb_ci_appl", "page_size": 500}`)} {
		if err := CheckSettings(InputAssets, ok, m); err != nil {
			t.Errorf("%s %s: %v", ok.Type, ok.Settings, err)
		}
	}
	if err := CheckSettings(InputAssets, c(ConnectorServiceNowCMDB, ""), Mapping{}); err != nil {
		t.Errorf("servicenow without columns: %v", err)
	}
	for name, tc := range map[string]struct {
		c Connector
		m Mapping
		k string
	}{
		"unknown setting":      {c(ConnectorHTTPJSON, `{"url": "x"}`), m, InputAssets},
		"both pagings":         {c(ConnectorHTTPJSON, `{"paging": {"next": "/n", "offset_param": "o", "limit_param": "l"}}`), m, InputAssets},
		"half offset paging":   {c(ConnectorHTTPJSON, `{"paging": {"offset_param": "o"}}`), m, InputAssets},
		"page size":            {c(ConnectorHTTPJSON, `{"paging": {"offset_param": "o", "limit_param": "l", "page_size": 5000}}`), m, InputAssets},
		"a list not a pointer": {c(ConnectorHTTPJSON, `{"list": "items"}`), m, InputAssets},
		"a column not pointer": {c(ConnectorHTTPJSON, ""), Mapping{Columns: map[string]string{"id": "external_id"}}, InputAssets},
		"a class":              {c(ConnectorServiceNowCMDB, `{"class": "cmdb; drop"}`), m, InputAssets},
		"servicenow risks":     {c(ConnectorServiceNowCMDB, ""), m, InputRisks},
		"servicenow paging":    {c(ConnectorServiceNowCMDB, `{"paging": {"next": "/n"}}`), m, InputAssets},
	} {
		if err := CheckSettings(tc.k, tc.c, tc.m); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The ServiceNow connector against a fixture of the Table API
// (testdata/servicenow_cmdb_business_app.json, two pages in the Table
// API's documented response format): offset paging, display values,
// sys_id as the external ID, the support group mapped to a business unit.
func TestServiceNowFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/servicenow_cmdb_business_app.json")
	if err != nil {
		t.Fatal(err)
	}
	var pages []json.RawMessage
	if err := json.Unmarshal(raw, &pages); err != nil {
		t.Fatal(err)
	}
	src := newSource(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/api/now/table/cmdb_ci_business_app" || q.Get("sysparm_display_value") != "true" || q.Get("sysparm_exclude_reference_link") != "true" ||
			q.Get("sysparm_limit") != "2" {
			http.Error(w, "unexpected "+r.URL.String(), http.StatusBadRequest)
			return
		}
		off, _ := strconv.Atoi(q.Get("sysparm_offset"))
		if off/2 >= len(pages) {
			fmt.Fprint(w, `{"result": []}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(pages[off/2])
	})
	c := Connector{Type: ConnectorServiceNowCMDB, Source: src.url("/"), ScheduleMinutes: 1440, Settings: json.RawMessage(`{"page_size": 2}`)}
	mapping := `{"columns": {"/sys_id": "external_id", "/name": "name", "/short_description": "description", "/support_group": "bu"},
		"values": {"bu": {"Claims IT": "A1", "Underwriting IT": "A"}}, "defaults": {"asset_type": "application"}}`
	got, err := src.fetcher().Fetch(context.Background(), assetsReq(c, mapping, &Credential{Username: "fair.integration", Password: "pw"}))
	if err != nil {
		t.Fatal(err)
	}
	recs := records(t, got)
	if len(recs) != 3 || len(got.Batch.Records) != 3 || got.Batch.Refusals != 0 {
		t.Fatalf("records %v refused %+v", recs, got.Batch.Refused)
	}
	if recs[0]["external_id"] != "0d4a3f1e1b2c4d10a8f5e6c7d8e9f001" || recs[0]["bu"] != "A1" || recs[1]["bu"] != "A" || recs[0]["asset_type"] != "application" {
		t.Errorf("records %v", recs)
	}
	if _, ok := recs[2]["description"]; ok {
		t.Errorf("an empty description was kept: %v", recs[2])
	}
	if fields := src.reqs[0].URL.Query().Get("sysparm_fields"); fields != "name,short_description,support_group,sys_id" {
		t.Errorf("sysparm_fields %q", fields)
	}
	if len(src.reqs) != 2 {
		t.Errorf("%d requests, want 2 (the second page is short)", len(src.reqs))
	}
	// Without mapping columns: sys_id, name and short_description, as
	// applications; the business unit must then come from the mapping's
	// default.
	got, err = src.fetcher().Fetch(context.Background(), assetsReq(c, `{"defaults": {"bu": "A"}}`, nil))
	if err != nil || len(got.Batch.Records) != 3 {
		t.Fatalf("defaults: %v %+v", err, got)
	}
	u, _ := url.Parse(src.reqs[len(src.reqs)-1].URL.String())
	if u.Query().Get("sysparm_fields") != "name,short_description,sys_id" {
		t.Errorf("default fields %q", u.Query().Get("sysparm_fields"))
	}
}
