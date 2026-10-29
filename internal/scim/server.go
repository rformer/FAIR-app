package scim

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Prefix is where the service provider is served (the gateway forwards it
// without a session; the bearer token is the credential, AC-08).
const Prefix = "/scim/v2"

// Limits (advertised in /ServiceProviderConfig).
const (
	MaxOperations  = 100     // per Bulk request
	MaxPayloadSize = 1 << 20 // bytes, per request
	MaxResults     = 1000    // per page
	DefaultCount   = 100
)

// Server is the SCIM service provider.
type Server struct {
	Store     Store
	Origin    string // the platform's public origin (resource locations)
	PerMinute int    // requests per token per minute (default 1200)
	Logger    *slog.Logger
	Now       func() time.Time

	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) base() string { return strings.TrimSuffix(s.Origin, "/") + Prefix }

// allow is a token bucket per bearer token (design §7: rate limits per
// token).
func (s *Server) allow(th []byte) bool {
	rate := float64(s.PerMinute)
	if rate <= 0 {
		rate = 1200
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buckets == nil {
		s.buckets = map[string]*tokenBucket{}
	}
	if len(s.buckets) > 10000 {
		for k, b := range s.buckets {
			if now.Sub(b.last) > time.Minute {
				delete(s.buckets, k)
			}
		}
	}
	b, ok := s.buckets[string(th)]
	if !ok {
		b = &tokenBucket{tokens: rate, last: now}
		s.buckets[string(th)] = b
	}
	b.tokens = min(rate, b.tokens+now.Sub(b.last).Minutes()*rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// call is an authenticated request's context.
type call struct {
	th   []byte
	prov provider
}

type callKey struct{}

// Handler serves Prefix.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		auth := r.Header.Get("Authorization")
		scheme, token, _ := strings.Cut(auth, " ")
		if !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
			s.unauthorized(w)
			return
		}
		sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
		th := sum[:]
		if !s.allow(th) {
			w.Header().Set("Retry-After", "60")
			writeErr(w, &Error{Status: http.StatusTooManyRequests, Detail: "too many requests for this token"})
			return
		}
		prov, err := s.Store.provider(r.Context(), th)
		if errors.Is(err, errUnauthorized) {
			s.unauthorized(w)
			return
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodDelete && r.ContentLength != 0 {
			if ct := r.Header.Get("Content-Type"); ct != "" {
				mt, _, _ := mime.ParseMediaType(ct)
				if mt != "application/scim+json" && mt != "application/json" {
					writeErr(w, &Error{Status: http.StatusUnsupportedMediaType, Detail: "use application/scim+json"})
					return
				}
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxPayloadSize)
		s.route(w, r.WithContext(context.WithValue(r.Context(), callKey{}, call{th: th, prov: prov})))
	})
}

func (s *Server) unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="fair-scim"`)
	writeErr(w, &Error{Status: http.StatusUnauthorized, Detail: "a valid SCIM bearer token is required"})
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Context().Value(callKey{}).(call)
	rest := strings.TrimPrefix(r.URL.Path, Prefix)
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "ServiceProviderConfig" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, s.spConfig())
	case len(parts) >= 1 && parts[0] == "ResourceTypes" && r.Method == http.MethodGet:
		s.resourceTypes(w, parts[1:])
	case len(parts) >= 1 && parts[0] == "Schemas" && r.Method == http.MethodGet:
		s.schemas(w, parts[1:])
	case len(parts) == 1 && parts[0] == "Bulk" && r.Method == http.MethodPost:
		s.bulk(w, r, c)
	case len(parts) >= 1 && parts[0] == "Me":
		writeErr(w, &Error{Status: http.StatusNotImplemented, Detail: "/Me is not supported"})
	case len(parts) >= 1 && (parts[0] == "Users" || parts[0] == "Groups"):
		k := userKind
		if parts[0] == "Groups" {
			k = groupKind
		}
		s.resource(w, r, c, k, parts[1:])
	default:
		writeErr(w, &Error{Status: http.StatusNotFound, Detail: "no such endpoint"})
	}
}

func (s *Server) resource(w http.ResponseWriter, r *http.Request, c call, k kind, parts []string) {
	ctx := r.Context()
	switch {
	case len(parts) == 0 && r.Method == http.MethodGet:
		q := r.URL.Query()
		s.list(w, r, c, k, searchRequest{Filter: q.Get("filter"), StartIndex: q.Get("startIndex"), Count: q.Get("count"),
			Attributes: q.Get("attributes"), Excluded: q.Get("excludedAttributes")})
	case len(parts) == 1 && parts[0] == ".search" && r.Method == http.MethodPost:
		var body struct {
			Schemas    []string `json:"schemas"`
			Filter     string   `json:"filter"`
			StartIndex *int     `json:"startIndex"`
			Count      *int     `json:"count"`
			Attributes []string `json:"attributes"`
			Excluded   []string `json:"excludedAttributes"`
		}
		if err := decodeJSON(r.Body, &body); err != nil {
			writeErr(w, err)
			return
		}
		sr := searchRequest{Filter: body.Filter, Attributes: strings.Join(body.Attributes, ","), Excluded: strings.Join(body.Excluded, ",")}
		if body.StartIndex != nil {
			sr.StartIndex = strconv.Itoa(*body.StartIndex)
		}
		if body.Count != nil {
			sr.Count = strconv.Itoa(*body.Count)
		}
		s.list(w, r, c, k, sr)
	case len(parts) == 0 && r.Method == http.MethodPost:
		var body map[string]any
		if err := decodeJSON(r.Body, &body); err != nil {
			writeErr(w, err)
			return
		}
		doc, err := s.create(ctx, c, k, body)
		if err != nil {
			s.answerErr(w, r, err)
			return
		}
		meta := doc["meta"].(map[string]any)
		w.Header().Set("Location", meta["location"].(string))
		w.Header().Set("ETag", meta["version"].(string))
		writeJSON(w, http.StatusCreated, doc)
	case len(parts) == 1 && uuidRE.MatchString(parts[0]):
		id := strings.ToLower(parts[0])
		ifVersion, ok := parseETag(r.Header.Get("If-Match"))
		if !ok {
			writeErr(w, bad("invalidVers", "If-Match is not a version this server issued"))
			return
		}
		var doc map[string]any
		var err error
		switch r.Method {
		case http.MethodGet:
			doc, err = s.get(ctx, c, k, id)
			if err == nil {
				if inm := r.Header.Get("If-None-Match"); inm != "" && inm == doc["meta"].(map[string]any)["version"] {
					w.WriteHeader(http.StatusNotModified)
					return
				}
				q := r.URL.Query()
				attrs, err1 := parsePaths(q.Get("attributes"))
				excl, err2 := parsePaths(q.Get("excludedAttributes"))
				if err = errors.Join(err1, err2); err == nil {
					w.Header().Set("ETag", doc["meta"].(map[string]any)["version"].(string))
					writeJSON(w, http.StatusOK, project(doc, attrs, excl))
					return
				}
			}
		case http.MethodPut:
			var body map[string]any
			if err = decodeJSON(r.Body, &body); err == nil {
				doc, err = s.replace(ctx, c, k, id, ifVersion, body)
			}
		case http.MethodPatch:
			var body struct {
				Schemas    []string  `json:"schemas"`
				Operations []PatchOp `json:"Operations"`
			}
			if err = decodeJSON(r.Body, &body); err == nil {
				if !containsFold(body.Schemas, SchemaPatch) {
					err = bad("invalidSyntax", "schemas must be [%q]", SchemaPatch)
				} else {
					doc, err = s.patch(ctx, c, k, id, ifVersion, body.Operations)
				}
			}
		case http.MethodDelete:
			if err = s.Store.remove(ctx, c.th, k, id, ifVersion); err == nil {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		default:
			err = &Error{Status: http.StatusMethodNotAllowed, Detail: r.Method + " is not supported here"}
		}
		if err != nil {
			s.answerErr(w, r, err)
			return
		}
		w.Header().Set("ETag", doc["meta"].(map[string]any)["version"].(string))
		writeJSON(w, http.StatusOK, doc)
	case len(parts) == 1:
		writeErr(w, &Error{Status: http.StatusNotFound, Detail: "no such resource"})
	default:
		writeErr(w, &Error{Status: http.StatusMethodNotAllowed, Detail: r.Method + " is not supported here"})
	}
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// --- operations (shared with Bulk) -------------------------------------------

func (s *Server) get(ctx context.Context, c call, k kind, id string) (map[string]any, error) {
	recs, err := s.Store.list(ctx, c.th, k, id)
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, &Error{Status: http.StatusNotFound, Detail: "no such resource"}
	}
	return render(k, recs[0], s.base()), nil
}

func (s *Server) write(ctx context.Context, c call, k kind, id string, ifVersion *int, body map[string]any) (map[string]any, error) {
	res, members, err := prepare(k, body)
	if err != nil {
		return nil, err
	}
	var rec record
	if k.Name == "Group" {
		name, _ := lookup(res, "displayName")
		dn, _ := name.(string)
		if strings.TrimSpace(dn) == "" {
			return nil, bad("invalidValue", "displayName is required")
		}
		ext, _ := lookup(res, "externalId")
		es, _ := ext.(string)
		rec, err = s.Store.writeGroup(ctx, c.th, id, ifVersion, res, dn, es, members)
	} else {
		f, ferr := userFieldsOf(res, c.prov.SubjectAttribute)
		if ferr != nil {
			return nil, ferr
		}
		rec, err = s.Store.writeUser(ctx, c.th, id, ifVersion, res, f)
	}
	if err != nil {
		return nil, err
	}
	return s.get(ctx, c, k, rec.ID)
}

func (s *Server) create(ctx context.Context, c call, k kind, body map[string]any) (map[string]any, error) {
	return s.write(ctx, c, k, "", nil, body)
}

func (s *Server) replace(ctx context.Context, c call, k kind, id string, ifVersion *int, body map[string]any) (map[string]any, error) {
	return s.write(ctx, c, k, id, ifVersion, body)
}

// patch applies operations to the current resource and stores it under
// the version it read (or the client's If-Match); a concurrent change
// without If-Match is retried.
func (s *Server) patch(ctx context.Context, c call, k kind, id string, ifVersion *int, ops []PatchOp) (map[string]any, error) {
	for attempt := 0; ; attempt++ {
		recs, err := s.Store.list(ctx, c.th, k, id)
		if err != nil {
			return nil, err
		}
		if len(recs) == 0 {
			return nil, &Error{Status: http.StatusNotFound, Detail: "no such resource"}
		}
		rec := recs[0]
		if ifVersion != nil && *ifVersion != rec.Version {
			return nil, &Error{Status: http.StatusPreconditionFailed, Detail: "the resource changed"}
		}
		doc := render(k, rec, s.base())
		if err := (patcher{k: k}).Apply(doc, ops); err != nil {
			return nil, err
		}
		v := rec.Version
		out, err := s.write(ctx, c, k, id, &v, doc)
		var se *Error
		if errors.As(err, &se) && se.Status == http.StatusPreconditionFailed && ifVersion == nil && attempt < 3 {
			continue
		}
		return out, err
	}
}

// --- listing -----------------------------------------------------------------

type searchRequest struct {
	Filter, StartIndex, Count, Attributes, Excluded string
}

func (s *Server) list(w http.ResponseWriter, r *http.Request, c call, k kind, sr searchRequest) {
	var f filter
	if strings.TrimSpace(sr.Filter) != "" {
		var err error
		if f, err = parseFilter(sr.Filter); err != nil {
			writeErr(w, bad("invalidFilter", "%v", err))
			return
		}
	}
	start, count := 1, DefaultCount
	if sr.StartIndex != "" {
		n, err := strconv.Atoi(sr.StartIndex)
		if err != nil {
			writeErr(w, bad("invalidValue", "startIndex must be an integer"))
			return
		}
		start = max(n, 1)
	}
	if sr.Count != "" {
		n, err := strconv.Atoi(sr.Count)
		if err != nil {
			writeErr(w, bad("invalidValue", "count must be an integer"))
			return
		}
		count = min(max(n, 0), MaxResults)
	}
	attrs, err1 := parsePaths(sr.Attributes)
	excl, err2 := parsePaths(sr.Excluded)
	if err := errors.Join(err1, err2); err != nil {
		writeErr(w, err)
		return
	}
	recs, err := s.Store.list(r.Context(), c.th, k, "")
	if err != nil {
		s.answerErr(w, r, err)
		return
	}
	sc := scope{k: k}
	var hits []map[string]any
	for _, rec := range recs {
		doc := render(k, rec, s.base())
		if f == nil || sc.eval(f, doc) {
			hits = append(hits, doc)
		}
	}
	page := []any{}
	for i := start - 1; i < len(hits) && len(page) < count; i++ {
		page = append(page, project(hits[i], attrs, excl))
	}
	writeJSON(w, http.StatusOK, map[string]any{"schemas": []string{SchemaList}, "totalResults": len(hits),
		"startIndex": start, "itemsPerPage": len(page), "Resources": page})
}

// --- discovery (RFC 7644 §4) -------------------------------------------------

func (s *Server) spConfig() map[string]any {
	return map[string]any{
		"schemas":          []string{SchemaSPConfig},
		"documentationUri": "https://www.rfc-editor.org/rfc/rfc7644",
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": true, "maxOperations": MaxOperations, "maxPayloadSize": MaxPayloadSize},
		"filter":           map[string]any{"supported": true, "maxResults": MaxResults},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": true},
		"authenticationSchemes": []any{map[string]any{"type": "oauthbearertoken", "name": "OAuth Bearer Token", "primary": true,
			"description": "A SCIM token issued for one identity provider (POST /api/v1/idps/{id}/scim-tokens)",
			"specUri":     "https://www.rfc-editor.org/rfc/rfc6750"}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig", "location": s.base() + "/ServiceProviderConfig"},
	}
}

func (s *Server) resourceType(k kind) map[string]any {
	ext := []any{}
	for _, e := range k.Extensions {
		ext = append(ext, map[string]any{"schema": e.ID, "required": false})
	}
	return map[string]any{"schemas": []string{SchemaResType}, "id": k.Name, "name": k.Name, "endpoint": k.Endpoint,
		"description": k.Schema.Description, "schema": k.Schema.ID, "schemaExtensions": ext,
		"meta": map[string]any{"resourceType": "ResourceType", "location": s.base() + "/ResourceTypes/" + k.Name}}
}

func (s *Server) resourceTypes(w http.ResponseWriter, parts []string) {
	all := []map[string]any{s.resourceType(userKind), s.resourceType(groupKind)}
	if len(parts) == 1 {
		for _, rt := range all {
			if rt["id"] == parts[0] {
				writeJSON(w, http.StatusOK, rt)
				return
			}
		}
		writeErr(w, &Error{Status: http.StatusNotFound, Detail: "no such resource type"})
		return
	}
	writeJSON(w, http.StatusOK, listOf(all))
}

func attrJSON(a Attr) map[string]any {
	m := map[string]any{"name": a.Name, "type": a.Type, "multiValued": a.Multi, "description": a.Description,
		"required": a.Required, "caseExact": a.CaseExact, "mutability": a.mutability(), "returned": orDefault(a.Returned, "default"),
		"uniqueness": orDefault(a.Uniqueness, "none")}
	if len(a.RefTypes) > 0 {
		m["referenceTypes"] = a.RefTypes
	}
	if len(a.Sub) > 0 {
		var subs []any
		for _, sa := range a.Sub {
			subs = append(subs, attrJSON(sa))
		}
		m["subAttributes"] = subs
	}
	return m
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func (s *Server) schemaJSON(sc Schema) map[string]any {
	var attrs []any
	for _, a := range sc.Attrs {
		attrs = append(attrs, attrJSON(a))
	}
	return map[string]any{"schemas": []string{SchemaSchema}, "id": sc.ID, "name": sc.Name, "description": sc.Description,
		"attributes": attrs, "meta": map[string]any{"resourceType": "Schema", "location": s.base() + "/Schemas/" + sc.ID}}
}

func (s *Server) schemas(w http.ResponseWriter, parts []string) {
	all := []map[string]any{s.schemaJSON(userSchema), s.schemaJSON(enterpriseSchema), s.schemaJSON(groupSchema)}
	if len(parts) == 1 {
		for _, sc := range all {
			if strings.EqualFold(sc["id"].(string), parts[0]) {
				writeJSON(w, http.StatusOK, sc)
				return
			}
		}
		writeErr(w, &Error{Status: http.StatusNotFound, Detail: "no such schema"})
		return
	}
	writeJSON(w, http.StatusOK, listOf(all))
}

func listOf(items []map[string]any) map[string]any {
	res := make([]any, len(items))
	for i, it := range items {
		res[i] = it
	}
	return map[string]any{"schemas": []string{SchemaList}, "totalResults": len(items), "startIndex": 1,
		"itemsPerPage": len(items), "Resources": res}
}

// --- responses ---------------------------------------------------------------

func decodeJSON(r io.Reader, v any) error {
	dec := json.NewDecoder(r)
	if err := dec.Decode(v); err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			return &Error{Status: http.StatusRequestEntityTooLarge, Detail: "the request is larger than 1 MiB"}
		}
		return bad("invalidSyntax", "the body is not valid JSON: %v", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errBody(e *Error) map[string]any {
	body := map[string]any{"schemas": []string{SchemaError}, "status": strconv.Itoa(e.Status)}
	if e.ScimType != "" {
		body["scimType"] = e.ScimType
	}
	if e.Detail != "" {
		body["detail"] = e.Detail
	}
	return body
}

func writeErr(w http.ResponseWriter, err error) {
	var e *Error
	if !errors.As(err, &e) {
		e = &Error{Status: http.StatusInternalServerError, Detail: "internal error"}
	}
	writeJSON(w, e.Status, errBody(e))
}

// answerErr writes a SCIM error, logging unexpected ones.
func (s *Server) answerErr(w http.ResponseWriter, r *http.Request, err error) {
	var e *Error
	switch {
	case errors.As(err, &e):
		writeErr(w, e)
	case errors.Is(err, errUnauthorized):
		s.unauthorized(w)
	default:
		s.fail(w, r, err)
	}
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	if s.Logger != nil {
		s.Logger.Error("SCIM", "path", r.URL.Path, "method", r.Method, "error", err.Error())
	}
	writeErr(w, &Error{Status: http.StatusInternalServerError, Detail: "internal error"})
}
