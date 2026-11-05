// Package auditapi serves the Audit API (F-002 T-12, AC-15 to AC-20; design
// §5; contract api/openapi/audit.yaml) under /api/v1/audit, in the audit
// service.
//
// Every route needs audit.view: without it anywhere the API does not exist
// for the caller (404, F-001 AC-25), and /status needs it at the root.
// Exports (T-15) also need audit.export; an export is visible to its
// requester and to holders of audit.export at the root. The
// records a caller sees are chosen by the database, from the signed DB
// context (audit.search and the other read functions; AC-19). Every read is
// recorded in the trail in the same transaction as the read, so a read that
// cannot be recorded is not answered (fail closed, ADR-006; AC-20).
package auditapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rformer/fair-app/internal/audit/integrity"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// Prefix is where the API is served.
const Prefix = "/api/v1/audit"

// Page sizes.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// Authorizer checks grants (authz.Cache).
type Authorizer interface {
	authz.Checker
	BUsWith(ctx context.Context, p authz.Principal, perm authz.Permission) (map[string]struct{}, error)
}

// API serves the Audit API.
type API struct {
	DB    *pgxpool.Pool // app_audit
	Authz Authorizer
	Audit audit.Emitter
	// Enqueue queues an export job in the request's transaction (the audit
	// service's River client, audit.Enqueuer); Bundles reads stored
	// bundles. Without them exports answer 503 (T-15).
	Enqueue func(ctx context.Context, tx pgx.Tx, id string) error
	Bundles BundleOpener

	rootOnce sync.Once
	root     string
	rootErr  error
}

type route struct {
	method, path string
	h            func(*API, http.ResponseWriter, *http.Request, authz.Principal)
}

var routes = []route{
	{"GET", "/records", (*API).search},
	{"GET", "/records/{seq}", (*API).record},
	{"GET", "/history", (*API).history},
	{"GET", "/requests/{id}", (*API).request},
	{"GET", "/approvals/{id}", (*API).approval},
	{"GET", "/checkpoints", (*API).checkpoints},
	{"GET", "/keys", (*API).keys},
	{"GET", "/status", (*API).status},
	{"POST", "/exports", (*API).createExport},
	{"GET", "/exports/{id}", (*API).getExport},
	{"GET", "/exports/{id}/bundle", (*API).exportBundle},
}

// Routes lists "METHOD /path" of every route (for the OpenAPI document).
func Routes() []string {
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		out = append(out, r.method+" "+Prefix+r.path)
	}
	sort.Strings(out)
	return out
}

// Handler returns the API with authentication in front (the gateway's
// internal JWT, audience "audit", and the DB context it carries) and
// Idempotency-Key on every mutation (server.Idempotent).
func (a *API) Handler(kp authz.KeyProvider, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	for _, rt := range routes {
		h := rt.h
		mux.HandleFunc(rt.method+" "+Prefix+rt.path, func(w http.ResponseWriter, r *http.Request) {
			p, _ := server.PrincipalFrom(r.Context())
			h(a, w, r, p)
		})
	}
	return server.Authenticate(kp, "audit", now)(server.Idempotent(IdempotencyStore{DB: a.DB})(mux))
}

// --- helpers --------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func problem(w http.ResponseWriter, status int, code, detail string) {
	body := map[string]any{"error": code}
	if detail != "" {
		body["detail"] = detail
	}
	writeJSON(w, status, body)
}

func notFound(w http.ResponseWriter) { problem(w, http.StatusNotFound, "not_found", "") }

// fail answers a database or audit error: a refused filter is the caller's
// (400); anything else, including a read that could not be recorded, is
// 503.
func fail(w http.ResponseWriter, err error) {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "PF004" {
		problem(w, http.StatusBadRequest, "invalid_request", pe.Message)
		return
	}
	problem(w, http.StatusServiceUnavailable, "unavailable", "")
}

func (a *API) rootBU(ctx context.Context) (string, error) {
	a.rootOnce.Do(func() { a.rootErr = a.DB.QueryRow(ctx, "SELECT audit.root_bu()::text").Scan(&a.root) })
	return a.root, a.rootErr
}

// viewer requires audit.view at some BU; without it the API is 404.
func (a *API) viewer(w http.ResponseWriter, r *http.Request, p authz.Principal) bool {
	bus, err := a.Authz.BUsWith(r.Context(), p, "audit.view")
	if err != nil {
		server.WriteAuthzError(w, err)
		return false
	}
	if len(bus) == 0 {
		notFound(w)
		return false
	}
	return true
}

func limit(w http.ResponseWriter, r *http.Request) (int, bool) {
	s := r.URL.Query().Get("limit")
	if s == "" {
		return DefaultLimit, true
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > MaxLimit {
		problem(w, http.StatusBadRequest, "invalid_request", "limit is 1 to 200")
		return 0, false
	}
	return n, true
}

// cursor reads an optional positive sequence number parameter.
func cursor(w http.ResponseWriter, r *http.Request, name string) (*int64, bool) {
	s := r.URL.Query().Get(name)
	if s == "" {
		return nil, true
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 1 {
		problem(w, http.StatusBadRequest, "invalid_request", name+" is a record position")
		return nil, false
	}
	return &n, true
}

// read runs fn in the caller's DB context and records the read as event
// (with its result count) in the same transaction.
func (a *API) read(ctx context.Context, p authz.Principal, ev audit.Event, fn func(tx pgx.Tx) (int, error)) error {
	return authz.WithDBContext(ctx, a.DB, p.DBToken, func(tx pgx.Tx) error {
		n, err := fn(tx)
		if err != nil {
			return err
		}
		if ev.Attributes == nil {
			ev.Attributes = map[string]string{}
		}
		ev.Attributes["result_count"] = strconv.Itoa(n)
		ev.Actor, ev.Severity = p.UserID, audit.SeverityLow
		return a.Audit.Emit(audit.WithTx(ctx, tx), ev)
	})
}

// Record is one record as the API shows it.
type Record struct {
	Seq        int64             `json:"seq"`
	EventID    string            `json:"event_id"`
	Time       time.Time         `json:"time"`
	ReceivedAt time.Time         `json:"received_at"`
	Producer   string            `json:"producer"`
	Type       string            `json:"type"`
	Category   string            `json:"category"`
	Severity   string            `json:"severity"`
	Actor      string            `json:"actor"`
	Target     *string           `json:"target"`
	BUID       string            `json:"bu_id"`
	RequestID  *string           `json:"request_id"`
	SourceIP   *string           `json:"source_ip"`
	ApprovalID *string           `json:"approval_id"`
	Skew       bool              `json:"skew"`
	Segment    int64             `json:"segment"`
	Integrity  string            `json:"integrity"` // verified, pending or failed
	Names      map[string]string `json:"names"`     // current display names of the users it names
	Event      json.RawMessage   `json:"event"`     // the record's body, as recorded
}

const recordCols = "seq, event_id, event_time, received_at, producer, type, category, severity, actor, target, bu_id::text, request_id, host(source_ip), approval_id, skew, segment, body, integrity, names"

func scanRecords(rows pgx.Rows) ([]Record, error) {
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Record, error) {
		var rec Record
		var names []byte
		err := r.Scan(&rec.Seq, &rec.EventID, &rec.Time, &rec.ReceivedAt, &rec.Producer, &rec.Type, &rec.Category, &rec.Severity, &rec.Actor,
			&rec.Target, &rec.BUID, &rec.RequestID, &rec.SourceIP, &rec.ApprovalID, &rec.Skew, &rec.Segment, &rec.Event, &rec.Integrity, &names)
		if err == nil {
			err = json.Unmarshal(names, &rec.Names)
		}
		return rec, err
	})
}

// filterKeys are the search filters (AC-15).
var filterKeys = []string{"from", "to", "type", "category", "severity", "actor", "target", "bu", "request_id", "source_ip"}

// --- handlers ---------------------------------------------------------------

// search: GET /records (AC-15, AC-18, AC-20).
func (a *API) search(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewer(w, r, p) {
		return
	}
	q := r.URL.Query()
	filter := map[string]string{}
	for k := range q {
		known := k == "limit" || k == "before"
		for _, f := range filterKeys {
			known = known || k == f
		}
		if !known {
			problem(w, http.StatusBadRequest, "invalid_request", "unknown parameter "+k)
			return
		}
	}
	for _, k := range filterKeys {
		if v := q.Get(k); v != "" {
			filter[k] = v
		}
	}
	for _, k := range []string{"from", "to"} {
		if v, ok := filter[k]; ok {
			if _, err := time.Parse(time.RFC3339, v); err != nil {
				problem(w, http.StatusBadRequest, "invalid_request", k+" is an RFC 3339 time")
				return
			}
		}
	}
	if v, ok := filter["source_ip"]; ok {
		if _, err := netip.ParsePrefix(v); err != nil {
			if _, err := netip.ParseAddr(v); err != nil {
				problem(w, http.StatusBadRequest, "invalid_request", "source_ip is an address or a CIDR range")
				return
			}
		}
	}
	n, ok := limit(w, r)
	if !ok {
		return
	}
	before, ok := cursor(w, r, "before")
	if !ok {
		return
	}
	fj, _ := json.Marshal(filter)
	var recs []Record
	err := a.read(r.Context(), p, audit.Event{Type: "audit.searched", Attributes: map[string]string{"view": "records", "filter": string(fj)}},
		func(tx pgx.Tx) (int, error) {
			rows, err := tx.Query(r.Context(), "SELECT "+recordCols+" FROM audit.search($1, $2, $3)", fj, before, n)
			if err != nil {
				return 0, err
			}
			recs, err = scanRecords(rows)
			return len(recs), err
		})
	if err != nil {
		fail(w, err)
		return
	}
	var next *int64
	if len(recs) == n {
		next = &recs[len(recs)-1].Seq
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": nonNil(recs), "filter": filter, "next_before": next})
}

func nonNil(r []Record) []Record {
	if r == nil {
		return []Record{}
	}
	return r
}

// Proof proves a record against its segment's signed checkpoint (ADR-011).
type Proof struct {
	Segment   int64            `json:"segment"`
	LeafIndex uint64           `json:"leaf_index"`
	TreeSize  uint64           `json:"tree_size"`
	LeafHash  integrity.Hash   `json:"leaf_hash"`
	Path      []integrity.Hash `json:"path"`
	Statement string           `json:"statement"` // the checkpoint statement, exactly as signed
	Signature string           `json:"signature"` // base64 ASN.1 ECDSA P-256 over SHA-256 of statement
}

// record: GET /records/{seq}, with its proof once its segment is closed.
func (a *API) record(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewer(w, r, p) {
		return
	}
	seq, err := strconv.ParseInt(r.PathValue("seq"), 10, 64)
	if err != nil || seq < 1 {
		notFound(w)
		return
	}
	var rec *Record
	var proof *Proof
	fj, _ := json.Marshal(map[string]int64{"seq": seq})
	err = a.read(r.Context(), p, audit.Event{Type: "audit.searched", Target: "audit:record:" + strconv.FormatInt(seq, 10),
		Attributes: map[string]string{"view": "record", "filter": string(fj)}},
		func(tx pgx.Tx) (int, error) {
			rows, err := tx.Query(r.Context(), "SELECT "+recordCols+" FROM audit.search('{}', $1, 1) WHERE seq = $2", seq+1, seq)
			if err != nil {
				return 0, err
			}
			recs, err := scanRecords(rows)
			if err != nil || len(recs) == 0 {
				return 0, err
			}
			rec = &recs[0]
			var segment int64
			var from *int64
			var leaves [][]byte
			var statement, signature []byte
			if err := tx.QueryRow(r.Context(), "SELECT segment, seq_from, leaves, statement, signature FROM audit.record_proof($1)", seq).
				Scan(&segment, &from, &leaves, &statement, &signature); err != nil {
				return 0, err
			}
			if from != nil { // the segment is closed
				pf, err := prove(seq, *from, segment, leaves, statement, signature)
				if err != nil {
					return 0, err
				}
				proof = pf
			}
			return 1, nil
		})
	if err != nil {
		fail(w, err)
		return
	}
	if rec == nil {
		notFound(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"record": rec, "proof": proof})
}

func prove(seq, from, segment int64, leaves [][]byte, statement, signature []byte) (*Proof, error) {
	hs := make([]integrity.Hash, len(leaves))
	for i, l := range leaves {
		copy(hs[i][:], l)
	}
	idx := uint64(seq - from) // #nosec G115 -- seq is in the segment
	path, err := integrity.NewTree(hs).Path(idx)
	if err != nil {
		return nil, err
	}
	if path == nil {
		path = []integrity.Hash{}
	}
	return &Proof{Segment: segment, LeafIndex: idx, TreeSize: uint64(len(hs)), LeafHash: hs[idx], Path: path,
		Statement: string(statement), Signature: base64.StdEncoding.EncodeToString(signature)}, nil
}

// history: GET /history?target= or ?actor= (AC-16), in order.
func (a *API) history(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewer(w, r, p) {
		return
	}
	q := r.URL.Query()
	target, actor := q.Get("target"), q.Get("actor")
	if (target == "") == (actor == "") {
		problem(w, http.StatusBadRequest, "invalid_request", "give a target or an actor")
		return
	}
	n, ok := limit(w, r)
	if !ok {
		return
	}
	after, ok := cursor(w, r, "after")
	if !ok {
		return
	}
	filter := map[string]string{}
	var tArg, aArg *string
	if target != "" {
		filter["target"], tArg = target, &target
	} else {
		filter["actor"], aArg = actor, &actor
	}
	fj, _ := json.Marshal(filter)
	var recs []Record
	err := a.read(r.Context(), p, audit.Event{Type: "audit.history_viewed", Attributes: map[string]string{"filter": string(fj)}},
		func(tx pgx.Tx) (int, error) {
			rows, err := tx.Query(r.Context(), "SELECT "+recordCols+" FROM audit.history($1, $2, $3, $4)", tArg, aArg, after, n)
			if err != nil {
				return 0, err
			}
			recs, err = scanRecords(rows)
			return len(recs), err
		})
	if err != nil {
		fail(w, err)
		return
	}
	var next *int64
	if len(recs) == n {
		next = &recs[len(recs)-1].Seq
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": nonNil(recs), "filter": filter, "next_after": next})
}

// request: GET /requests/{id} (AC-17): one request's records across
// services, in order; 404 when none is visible.
func (a *API) request(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewer(w, r, p) {
		return
	}
	id := r.PathValue("id")
	n, ok := limit(w, r)
	if !ok {
		return
	}
	after, ok := cursor(w, r, "after")
	if !ok {
		return
	}
	fj, _ := json.Marshal(map[string]string{"request_id": id})
	var recs []Record
	err := a.read(r.Context(), p, audit.Event{Type: "audit.searched", Attributes: map[string]string{"view": "request", "filter": string(fj)}},
		func(tx pgx.Tx) (int, error) {
			rows, err := tx.Query(r.Context(), "SELECT "+recordCols+" FROM audit.request($1, $2, $3)", id, after, n)
			if err != nil {
				return 0, err
			}
			recs, err = scanRecords(rows)
			return len(recs), err
		})
	if err != nil {
		fail(w, err)
		return
	}
	if len(recs) == 0 && after == nil {
		notFound(w)
		return
	}
	var next *int64
	if len(recs) == n {
		next = &recs[len(recs)-1].Seq
	}
	writeJSON(w, http.StatusOK, map[string]any{"request_id": id, "records": nonNil(recs), "next_after": next})
}

// Party is a user named by an approval.
type Party struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// approval: GET /approvals/{id} (AC-35): one approval's evidence from the
// trail, in order: the request, the decision, its use, and the records
// naming it (the change requested and the change applied). 404 when none is
// visible.
func (a *API) approval(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewer(w, r, p) {
		return
	}
	id := strings.ToLower(r.PathValue("id"))
	if !isUUID(id) {
		notFound(w)
		return
	}
	n, ok := limit(w, r)
	if !ok {
		return
	}
	after, ok := cursor(w, r, "after")
	if !ok {
		return
	}
	fj, _ := json.Marshal(map[string]string{"approval_id": id})
	var recs []Record
	err := a.read(r.Context(), p, audit.Event{Type: "audit.searched", Target: "audit:approval:" + id,
		Attributes: map[string]string{"view": "approval", "filter": string(fj)}},
		func(tx pgx.Tx) (int, error) {
			rows, err := tx.Query(r.Context(), "SELECT "+recordCols+" FROM audit.approval_evidence($1, $2, $3)", id, after, n)
			if err != nil {
				return 0, err
			}
			recs, err = scanRecords(rows)
			return len(recs), err
		})
	if err != nil {
		fail(w, err)
		return
	}
	if len(recs) == 0 && after == nil {
		notFound(w)
		return
	}
	out := map[string]any{"approval_id": id, "kind": nil, "target_ref": nil, "status": nil, "requested_by": nil, "decided_by": nil,
		"request": nil, "decision": nil, "applied": nil}
	changes := []Record{}
	for i := range recs {
		rec := &recs[i]
		if rec.Target == nil || *rec.Target != "approval:"+id || !strings.HasPrefix(rec.Type, "approval.") {
			changes = append(changes, *rec)
			continue
		}
		switch rec.Type {
		case "approval.requested":
			out["request"] = rec
		case "approval.consumed":
			out["applied"] = rec
		default: // approved, rejected, expired
			out["decision"] = rec
		}
		// The latest approval event states the approval as it stands.
		var body struct {
			Attributes map[string]string `json:"attributes"`
		}
		if json.Unmarshal(rec.Event, &body) != nil {
			continue
		}
		for _, k := range []string{"kind", "target_ref", "status"} {
			if v := body.Attributes[k]; v != "" {
				out[k] = v
			}
		}
		for _, k := range []string{"requested_by", "decided_by"} {
			if v := body.Attributes[k]; v != "" {
				out[k] = Party{ID: v, Name: rec.Names[v]}
			}
		}
	}
	out["changes"] = changes
	var next *int64
	if len(recs) == n {
		next = &recs[len(recs)-1].Seq
	}
	out["next_after"] = next
	writeJSON(w, http.StatusOK, out)
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F'):
			return false
		}
	}
	return true
}

// checkpoints: GET /checkpoints?from=&limit= (for verifiers).
func (a *API) checkpoints(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewer(w, r, p) {
		return
	}
	from, ok := cursor(w, r, "from")
	if !ok {
		return
	}
	n, ok := limit(w, r)
	if !ok {
		return
	}
	type cp struct {
		Segment   int64  `json:"segment"`
		Statement string `json:"statement"`
		Signature string `json:"signature"`
	}
	var out []cp
	fj, _ := json.Marshal(map[string]any{"from": from})
	err := a.read(r.Context(), p, audit.Event{Type: "audit.searched", Attributes: map[string]string{"view": "checkpoints", "filter": string(fj)}},
		func(tx pgx.Tx) (int, error) {
			rows, err := tx.Query(r.Context(), "SELECT segment, statement, signature FROM audit.checkpoints($1, $2)", from, n)
			if err != nil {
				return 0, err
			}
			out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (cp, error) {
				var c cp
				var st, sig []byte
				err := row.Scan(&c.Segment, &st, &sig)
				c.Statement, c.Signature = string(st), base64.StdEncoding.EncodeToString(sig)
				return c, err
			})
			return len(out), err
		})
	if err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []cp{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"checkpoints": out})
}

// keys: GET /keys, every checkpoint key, retired ones included.
func (a *API) keys(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	if !a.viewer(w, r, p) {
		return
	}
	type key struct {
		KeyID      string     `json:"key_id"`
		PublicPEM  string     `json:"public_pem"`
		ActiveFrom time.Time  `json:"active_from"`
		RetiredAt  *time.Time `json:"retired_at"`
	}
	var out []key
	err := a.read(r.Context(), p, audit.Event{Type: "audit.searched", Attributes: map[string]string{"view": "keys", "filter": "{}"}},
		func(tx pgx.Tx) (int, error) {
			rows, err := tx.Query(r.Context(), "SELECT key_id, public_pem, active_from, retired_at FROM audit.keys()")
			if err != nil {
				return 0, err
			}
			out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[key])
			return len(out), err
		})
	if err != nil {
		fail(w, err)
		return
	}
	if out == nil {
		out = []key{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

// status: GET /status, for holders of audit.view at the root (the Posture
// API serves the same to posture.view holders).
func (a *API) status(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	root, err := a.rootBU(r.Context())
	if err != nil {
		problem(w, http.StatusServiceUnavailable, "unavailable", "")
		return
	}
	if err := a.Authz.Check(r.Context(), p, "audit.view", root); err != nil {
		server.WriteAuthzError(w, err)
		return
	}
	var status json.RawMessage
	err = a.read(r.Context(), p, audit.Event{Type: "audit.searched", Attributes: map[string]string{"view": "status", "filter": "{}"}},
		func(tx pgx.Tx) (int, error) {
			return 1, tx.QueryRow(r.Context(), "SELECT audit.status()").Scan(&status)
		})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}
