package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rformer/fair-app/internal/egress"
)

// F-011 T-17 (F-011-AC-04, AC-14; design §3.3, OQ2): the v1 connectors.
// Both only GET, never write to the source, follow no redirects and no
// links to other hosts, and fetch through the destination guard (the
// allow-list, refused ranges, the checked address dialled, TLS 1.2 or
// later with verified certificates). Each page is bounded in bytes and
// time, the run in time and records. Items are mapped to records of the
// integration's input kind by its declarative mapping, whose columns are
// JSON pointers into an item (the same mapping, values and defaults as a
// CSV file's); the result is a complete fair.integration.v1 batch.
//
//	http_json        settings: {"list": "/items", "paging": {"next": "/next"} |
//	                            {"offset_param": "offset", "limit_param": "limit", "page_size": 100}}
//	                 "list" is the pointer to the item array ("" or absent: the body is the array)
//	servicenow_cmdb  settings: {"class": "cmdb_ci_business_app", "page_size": 100}
//	                 the Table API of the source instance (/api/now/table/<class>), offset paging,
//	                 reference fields as display values; without mapping columns: sys_id,
//	                 name, short_description, asset type application

// Bounds of a connector run.
const (
	MaxPageBytes    = 5 << 20
	DefaultPageSize = 100
	MaxPageSize     = 1000
	RunTimeout      = 5 * time.Minute
	maxPages        = 2 * MaxRecords
)

// ServiceNowClass is the default CMDB class.
const ServiceNowClass = "cmdb_ci_business_app"

var classRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,79}$`)

// Fetcher runs connectors. It is the integrations API's Tester and the
// runner's fetch.
type Fetcher struct {
	Guard egress.Guard
	TLS   *tls.Config // the sources' roots (FAIR_INTEGRATE_CA_FILE added to the system's); nil: the system's
}

type httpSettings struct {
	List   *string `json:"list"`
	Paging *struct {
		Next        string `json:"next"`
		OffsetParam string `json:"offset_param"`
		LimitParam  string `json:"limit_param"`
		PageSize    int    `json:"page_size"`
	} `json:"paging"`
	// servicenow_cmdb
	Class    string `json:"class"`
	PageSize int    `json:"page_size"`
}

// plan is how a connector pages: the first URL, the item list's pointer,
// and the paging.
type plan struct {
	first              *url.URL
	list               string
	next               string // a pointer to the next page's URL
	offsetP, limitP    string
	pageSize           int
	mapping            Mapping
	snowFieldsFromPlan bool
}

// ErrConnector is a connector's settings that cannot run.
var ErrConnector = errors.New("integration: connector settings")

func connectorError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrConnector, fmt.Sprintf(format, args...))
}

// CheckSettings refuses a connector's settings it cannot run with, and a
// mapping it cannot map by (the integrations API checks both on save).
func CheckSettings(kind string, c Connector, m Mapping) error {
	_, err := makePlan(kind, c, m)
	return err
}

func makePlan(kind string, c Connector, m Mapping) (*plan, error) {
	src, err := c.SourceURL()
	if err != nil {
		return nil, err
	}
	var s httpSettings
	if len(c.Settings) > 0 {
		dec := json.NewDecoder(bytes.NewReader(c.Settings))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&s); err != nil {
			return nil, connectorError("unknown or malformed settings (%v)", err)
		}
	}
	p := &plan{first: src, mapping: m}
	switch c.Type {
	case ConnectorHTTPJSON:
		if s.Class != "" || s.PageSize != 0 {
			return nil, connectorError("class and page_size are servicenow_cmdb settings")
		}
		if s.List != nil {
			p.list = *s.List
		}
		if s.Paging != nil {
			switch g := s.Paging; {
			case g.Next != "" && (g.OffsetParam != "" || g.LimitParam != "" || g.PageSize != 0):
				return nil, connectorError("paging is by a next URL or by offset and limit, not both")
			case g.Next != "":
				p.next = g.Next
			case g.OffsetParam != "" && g.LimitParam != "" && g.OffsetParam != g.LimitParam:
				p.offsetP, p.limitP, p.pageSize = g.OffsetParam, g.LimitParam, g.PageSize
			default:
				return nil, connectorError("paging names next, or offset_param and limit_param")
			}
		}
	case ConnectorServiceNowCMDB:
		if s.List != nil || s.Paging != nil {
			return nil, connectorError("list and paging are http_json settings")
		}
		if kind != InputAssets {
			return nil, connectorError("servicenow_cmdb brings assets")
		}
		class := s.Class
		if class == "" {
			class = ServiceNowClass
		}
		if !classRE.MatchString(class) {
			return nil, connectorError("the CMDB class is a table name (lower case letters, digits, underscores)")
		}
		u := *src
		u.Path = strings.TrimSuffix(u.Path, "/") + "/api/now/table/" + class
		u.RawQuery = ""
		p.first, p.list, p.offsetP, p.limitP, p.pageSize = &u, "/result", "sysparm_offset", "sysparm_limit", s.PageSize
		if len(p.mapping.Columns) == 0 {
			p.mapping = Mapping{Columns: map[string]string{"/sys_id": "external_id", "/name": "name", "/short_description": "description"},
				Values: m.Values, Defaults: m.Defaults}
			if p.mapping.Defaults == nil {
				p.mapping.Defaults = map[string]string{}
			}
			if p.mapping.Defaults["asset_type"] == "" {
				p.mapping.Defaults["asset_type"] = "application"
			}
		}
		p.snowFieldsFromPlan = true
	default:
		return nil, connectorError("unknown connector type %q", c.Type)
	}
	if p.offsetP != "" {
		if p.pageSize == 0 {
			p.pageSize = DefaultPageSize
		}
		if p.pageSize < 1 || p.pageSize > MaxPageSize {
			return nil, connectorError("page_size is 1 to %d", MaxPageSize)
		}
	}
	for _, ptr := range []string{p.list, p.next} {
		if ptr != "" && !strings.HasPrefix(ptr, "/") {
			return nil, connectorError("%q is not a JSON pointer", ptr)
		}
	}
	if err := CheckMapping(kind, p.mapping); err != nil {
		return nil, err
	}
	for col := range p.mapping.Columns {
		if !strings.HasPrefix(col, "/") {
			return nil, connectorError("a connector's mapping columns are JSON pointers into an item, not %q", col)
		}
	}
	return p, nil
}

// Fetched is a connector's result.
type Fetched struct {
	Items int    // items the source answered
	Body  []byte // the complete fair.integration.v1 batch
	Batch *Batch // the batch as the platform will check it
}

// Test fetches the first page and maps it; nothing is submitted (the
// integrations API's Tester).
func (f Fetcher) Test(ctx context.Context, req TestRequest) (TestResult, error) {
	got, err := f.fetch(ctx, req, true)
	if err != nil {
		return TestResult{}, err
	}
	res := TestResult{Records: got.Items, Problems: got.Batch.Refused}
	if len(res.Problems) > MaxTestProblems {
		res.Problems = res.Problems[:MaxTestProblems]
	}
	return res, nil
}

// Fetch fetches every page and maps the items into a complete batch.
func (f Fetcher) Fetch(ctx context.Context, req TestRequest) (*Fetched, error) {
	return f.fetch(ctx, req, false)
}

func (f Fetcher) fetch(ctx context.Context, req TestRequest, firstOnly bool) (*Fetched, error) {
	var m Mapping
	if len(req.Mapping) > 0 {
		if err := json.Unmarshal(req.Mapping, &m); err != nil {
			return nil, connectorError("the mapping is not the declarative form")
		}
	}
	p, err := makePlan(req.Kind, req.Connector, m)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, RunTimeout)
	defer cancel()
	client := f.Guard.HTTPClient(f.TLS)
	kind := RecordKinds[req.Kind][0]
	sep := ";"
	if p.mapping.Separator != "" {
		sep = p.mapping.Separator
	}
	var records []any
	items := 0
	next := p.first
	if p.snowFieldsFromPlan {
		next = withQuery(next, map[string]string{"sysparm_display_value": "true", "sysparm_exclude_reference_link": "true",
			"sysparm_fields": snowFields(p.mapping)})
	}
	offset := 0
	seen := map[string]bool{}
pages:
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("integration: more than %d pages", maxPages)
		}
		u := next
		if p.offsetP != "" {
			u = withQuery(next, map[string]string{p.offsetP: strconv.Itoa(offset), p.limitP: strconv.Itoa(p.pageSize)})
		}
		if seen[u.String()] {
			return nil, errors.New("integration: the source's paging repeats a page")
		}
		seen[u.String()] = true
		body, err := f.get(ctx, client, u, req.Source)
		if err != nil {
			return nil, err
		}
		list, err := pointer(body, p.list)
		if err != nil {
			return nil, err
		}
		arr, ok := list.([]any)
		if !ok {
			return nil, fmt.Errorf("integration: the source's page has no item list at %q", p.list)
		}
		items += len(arr)
		if items > MaxRecords {
			return nil, fmt.Errorf("integration: the source holds more than %d records; at most %d in a run", MaxRecords, MaxRecords)
		}
		for _, it := range arr {
			records = append(records, mapRecord(kind, p.mapping, sep, func(col string) string {
				v, err := pointer(it, col)
				if err != nil {
					return ""
				}
				return scalar(v, sep)
			}))
		}
		if firstOnly {
			break
		}
		switch {
		case p.next != "":
			v, _ := pointer(body, p.next)
			s, _ := v.(string)
			if s == "" {
				break pages
			}
			n, err := u.Parse(s)
			if err != nil {
				return nil, fmt.Errorf("integration: the source's next page %q is not a URL", s)
			}
			if n.Scheme != "https" || !strings.EqualFold(n.Host, p.first.Host) || n.User != nil {
				return nil, fmt.Errorf("%w: the source's next page is on another host (%s); a connector follows no links to other hosts", egress.ErrRefused, n.Host)
			}
			n.Fragment = ""
			next = n
		case p.offsetP != "":
			if len(arr) < p.pageSize {
				break pages
			}
			offset += len(arr)
		default:
			break pages
		}
	}
	if records == nil {
		records = []any{}
	}
	out, err := json.Marshal(map[string]any{"format": Format, "complete": true, "records": records})
	if err != nil {
		return nil, err
	}
	if len(out) > MaxBody {
		return nil, fmt.Errorf("integration: the mapped batch is larger than %d bytes", MaxBody)
	}
	b, err := ParseJSON(out, req.Kind)
	if err != nil {
		return nil, err
	}
	return &Fetched{Items: items, Body: out, Batch: b}, nil
}

// get fetches one page: GET only, the credential as a bearer token or
// basic authentication, 200 with JSON, at most MaxPageBytes.
func (f Fetcher) get(ctx context.Context, client *http.Client, u *url.URL, cred *Credential) (any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "fair-integrate")
	if cred != nil {
		switch {
		case cred.Token != "":
			req.Header.Set("Authorization", "Bearer "+cred.Token)
		case cred.Username != "":
			req.SetBasicAuth(cred.Username, cred.Password)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL may carry a query; the cause is enough
		}
		return nil, fmt.Errorf("integration: fetching %s: %w", u.Host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, fmt.Errorf("integration: the source answered %d (a redirect; a connector follows none)", resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("integration: the source answered %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxPageBytes+1))
	if err != nil {
		return nil, fmt.Errorf("integration: reading the source's page: %w", err)
	}
	if len(raw) > MaxPageBytes {
		return nil, fmt.Errorf("integration: a page of the source is larger than %d bytes", MaxPageBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, errors.New("integration: the source's page is not JSON")
	}
	return v, nil
}

func withQuery(u *url.URL, set map[string]string) *url.URL {
	c := *u
	q := c.Query()
	for k, v := range set {
		q.Set(k, v)
	}
	c.RawQuery = q.Encode()
	return &c
}

// snowFields are the item fields the mapping reads (sysparm_fields).
func snowFields(m Mapping) string {
	var out []string
	seen := map[string]bool{}
	for col := range m.Columns {
		f := strings.SplitN(strings.TrimPrefix(col, "/"), "/", 2)[0]
		f = strings.NewReplacer("~1", "/", "~0", "~").Replace(f)
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// pointer resolves an RFC 6901 JSON pointer in v.
func pointer(v any, p string) (any, error) {
	if p == "" {
		return v, nil
	}
	if !strings.HasPrefix(p, "/") {
		return nil, fmt.Errorf("integration: %q is not a JSON pointer", p)
	}
	for _, tok := range strings.Split(p[1:], "/") {
		tok = strings.NewReplacer("~1", "/", "~0", "~").Replace(tok)
		switch x := v.(type) {
		case map[string]any:
			var ok bool
			if v, ok = x[tok]; !ok {
				return nil, fmt.Errorf("integration: no %q", p)
			}
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(x) || (len(tok) > 1 && tok[0] == '0') {
				return nil, fmt.Errorf("integration: no %q", p)
			}
			v = x[i]
		default:
			return nil, fmt.Errorf("integration: no %q", p)
		}
	}
	return v, nil
}

// scalar is a value as a mapped field's text: strings as they are, numbers
// in their source form, booleans, lists of scalars joined by sep; objects
// and nulls are empty.
func scalar(v any, sep string) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	case []any:
		var parts []string
		for _, e := range x {
			if s := scalar(e, sep); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, sep)
	}
	return ""
}
