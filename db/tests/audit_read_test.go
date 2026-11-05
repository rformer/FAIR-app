package tests

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	auditsvc "github.com/rformer/fair-app/internal/audit"
	"github.com/rformer/fair-app/internal/audit/integrity"
	"github.com/rformer/fair-app/internal/auditapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-002 T-12 (F-002-AC-15 to AC-20; design §4.3, §5): reading the trail.

type auditAPIEnv struct {
	e    *env
	pool *pgxpool.Pool
	url  string
	keys *authz.LocalKeys
	seq  auditsvc.Sequencer
}

// auditAPIFixture: BUs A and R (restricted) under the root; auditors at the
// root, at A and at R; nobody without audit.view; and records filed under
// each BU and under none (the root).
func auditAPIFixture(t *testing.T) auditAPIEnv {
	t.Helper()
	e := setup(t)
	postureAdmins(e)
	e.addBU("A", "ENTERPRISE")
	e.addBU("R", "ENTERPRISE")
	e.mustOwner("UPDATE iam.bu SET restricted = true WHERE code = 'R'")
	e.mustOwner(`INSERT INTO iam.app_user (email, display_name) VALUES ('rootaud@example.test', 'Root Auditor'),
		('aaud@example.test', 'A Auditor'), ('raud@example.test', 'R Auditor'), ('nobody@example.test', 'Nobody'), ('ann@example.test', 'Ann Actor')`)
	e.mustOwner(grant("admin", "user:rootaud", "Auditor", "ENTERPRISE"))
	e.mustOwner(grant("admin", "user:aaud", "Auditor", "A"))
	e.mustOwner(grant("admin", "user:raud", "Auditor", "R"))
	e.mustOwner(grant("admin", "user:nobody", "Executive Viewer", "ENTERPRISE"))
	e.drain()

	pool := e.auditPool()
	dir := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(filepath.Join(dir, "gw-1.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := authz.LoadLocalKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	api := &auditapi.API{DB: pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(pool)}),
		Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: pool})}
	srv := httptest.NewServer(api.Handler(keys, nil))
	t.Cleanup(srv.Close)
	ae := auditAPIEnv{e: e, pool: pool, url: srv.URL, keys: keys, seq: auditsvc.Sequencer{DB: pool}}

	a, r, root := e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A'"), e.adminQuery("SELECT id FROM iam.bu WHERE code = 'R'"),
		e.adminQuery("SELECT id FROM iam.bu WHERE code = 'ENTERPRISE'")
	ann, admin2 := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'ann@example.test'"), e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'admin2@example.test'")
	ev := func(id, bu, target, req, ip string) map[string]any {
		m := map[string]any{"id": id, "type": "setting.change_requested", "severity": "high", "actor": ann, "target": target}
		if bu != "" {
			m["bu_id"] = bu
		}
		if req != "" {
			m["request_id"] = req
		}
		if ip != "" {
			m["source_ip"] = ip
		}
		return m
	}
	submitAs(t, e, "app_rw", ev("a1", a, "test:a", "req-1", "10.0.0.1"))
	submitAs(t, e, "app_posture", ev("r1", r, "test:r", "req-1", "10.0.0.2"))
	submitAs(t, e, "app_rw", ev("root1", "", "test:root", "req-1", "192.168.1.5"))
	submitAs(t, e, "app_rw", ev("a2", a, "test:a", "req-2", ""))
	submitAs(t, e, "app_rw", ev("r2", r, "test:r", "req-r", ""))
	submitAs(t, e, "app_gateway", map[string]any{"id": "bg1", "type": "breakglass.enabled", "severity": "high", "actor": "system:iam",
		"target": "test:breakglass", "bu_id": root, "attributes": map[string]any{"approved_by": admin2, "reason": "drill"}})
	drainTrail(t, ae.seq)
	return ae
}

// get calls the API as user ("" = unauthenticated).
func (ae auditAPIEnv) get(t *testing.T, user, path string) apiResp {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), "GET", ae.url+auditapi.Prefix+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if user != "" {
		p := ae.e.principal(user)
		tok, err := authz.MintJWT(ae.keys, authz.Claims{Subject: p.UserID, ScopeVersion: p.ScopeVersion, AuthTime: time.Now().Unix(),
			DBContext: authz.DBContextHash(p.DBToken)}, "audit", 5*time.Minute, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set(server.DBContextHeader, p.DBToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return apiResp{code: resp.StatusCode, body: m, raw: string(raw), hdr: resp.Header}
}

// ids lists the event ids of a response's records, in order.
func eventIDs(r apiResp) string {
	recs, _ := r.body["records"].([]any)
	out := make([]string, 0, len(recs))
	for _, x := range recs {
		ev, _ := x.(map[string]any)["event"].(map[string]any)
		out = append(out, fmt.Sprint(ev["id"]))
	}
	return strings.Join(out, ",")
}

func sortedIDs(r apiResp) string {
	s := strings.Split(eventIDs(r), ",")
	sort.Strings(s)
	return strings.Join(s, ",")
}

func TestAuditReadVisibility(t *testing.T) {
	ae := auditAPIFixture(t)
	q := "/records?type=setting.change_requested&limit=200"
	for user, want := range map[string]string{
		"rootaud": "a1,a2,root1", // the root, A; not the restricted R
		"aaud":    "a1,a2",       // A only; not the root's
		"raud":    "r1,r2",       // R, with an assignment there
	} {
		if r := ae.get(t, user, q); r.code != 200 || sortedIDs(r) != want {
			t.Errorf("%s: %d %s, want %s (%s)", user, r.code, sortedIDs(r), want, r.raw)
		}
	}
	// Without audit.view anywhere the API does not exist; unauthenticated is 401.
	for _, path := range []string{"/records", "/records/1", "/history?target=test:a", "/requests/req-1", "/checkpoints", "/keys", "/status"} {
		if r := ae.get(t, "nobody", path); r.code != 404 {
			t.Errorf("nobody %s: %d", path, r.code)
		}
		if r := ae.get(t, "", path); r.code != 401 {
			t.Errorf("unauthenticated %s: %d", path, r.code)
		}
	}
	// One request across BUs: each caller sees their part (AC-17).
	for user, want := range map[string]string{"rootaud": "a1,root1", "aaud": "a1", "raud": "r1"} {
		if r := ae.get(t, user, "/requests/req-1"); r.code != 200 || eventIDs(r) != want {
			t.Errorf("%s request: %d %s, want %s", user, r.code, eventIDs(r), want)
		}
	}
	// A request with nothing visible, and an unknown one, are 404 alike.
	for _, id := range []string{"req-r", "no-such-request"} {
		if r := ae.get(t, "aaud", "/requests/"+id); r.code != 404 {
			t.Errorf("aaud request %s: %d", id, r.code)
		}
	}
	// One record: unseen ones are 404, like ones that do not exist.
	rSeq := ae.e.adminQuery("SELECT seq FROM audit.record WHERE event_id = 'r1'")
	rootSeq := ae.e.adminQuery("SELECT seq FROM audit.record WHERE event_id = 'root1'")
	for _, c := range []struct {
		user, seq string
		code      int
	}{
		{"rootaud", rSeq, 404}, {"raud", rSeq, 200}, {"aaud", rootSeq, 404}, {"rootaud", rootSeq, 200}, {"rootaud", "999999", 404}, {"rootaud", "x", 404},
	} {
		if r := ae.get(t, c.user, "/records/"+c.seq); r.code != c.code {
			t.Errorf("%s /records/%s: %d, want %d", c.user, c.seq, r.code, c.code)
		}
	}
	// History follows the same visibility.
	if r := ae.get(t, "rootaud", "/history?target=test:r"); r.code != 200 || eventIDs(r) != "" {
		t.Errorf("rootaud history of an R target: %s", r.raw)
	}
	// Status needs audit.view at the root; checkpoints and keys anywhere.
	if r := ae.get(t, "aaud", "/status"); r.code != 404 {
		t.Errorf("aaud status: %d", r.code)
	}
	if r := ae.get(t, "rootaud", "/status"); r.code != 200 || r.body["state"] == nil {
		t.Errorf("rootaud status: %d %s", r.code, r.raw)
	}
	for _, path := range []string{"/checkpoints", "/keys"} {
		if r := ae.get(t, "aaud", path); r.code != 200 {
			t.Errorf("aaud %s: %d", path, r.code)
		}
	}
	// The database decides on its own too: without a context, or for a
	// user without audit.view, the read functions return nothing.
	if out := ae.e.adminQuery("SELECT count(*) FROM audit.search('{}', NULL, 100)"); out != "0" {
		t.Errorf("no context: %s records", out)
	}
	if out, err := ae.e.asUser("app_audit", "nobody", "SELECT count(*) FROM audit.search('{}', NULL, 100)"); err != nil || out != "0" {
		t.Errorf("nobody's context: %s %v", out, err)
	}
	ae.e.mustFail("app_rw", "SELECT * FROM audit.search('{}', NULL, 1)", "permission denied")
	// The functions refuse unknown filters themselves, and give checkpoints
	// and keys only to holders of audit.view.
	if out, err := ae.e.asUser("app_audit", "rootaud", `SELECT count(*) FROM audit.search('{"colour":"red"}', NULL, 1)`); err == nil || !strings.Contains(out, "unknown filter") {
		t.Errorf("unknown filter in SQL: %v %s", err, out)
	}
	checkpointer(t, ae.pool, newCheckpointKey(t))
	for user, want := range map[string]string{"rootaud": "1", "nobody": "0"} {
		if out, err := ae.e.asUser("app_audit", user, "SELECT count(*) FROM audit.keys()"); err != nil || out != want {
			t.Errorf("%s keys: %s %v", user, out, err)
		}
	}
	ae.e.mustFail("app_audit", "SELECT * FROM iam.user_display_names(ARRAY[gen_random_uuid()])", "permission denied")
}

func TestAuditReadFilters(t *testing.T) {
	ae := auditAPIFixture(t)
	a := ae.e.adminQuery("SELECT id FROM iam.bu WHERE code = 'A'")
	ann := ae.e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'ann@example.test'")
	base := "/records?type=setting.change_requested&"
	for name, c := range map[string]struct{ q, want string }{
		"target":            {"target=test:a", "a1,a2"},
		"actor":             {"actor=" + ann, "a1,a2,root1"},
		"bu":                {"bu=" + a, "a1,a2"},
		"request":           {"request_id=req-1", "a1,root1"},
		"address":           {"source_ip=10.0.0.1", "a1"},
		"range":             {"source_ip=" + url.QueryEscape("10.0.0.0/8"), "a1"},
		"category":          {"category=configuration", "a1,a2,root1"},
		"severity":          {"severity=high", "a1,a2,root1"},
		"severity, none":    {"severity=low", ""},
		"time":              {"from=" + url.QueryEscape(time.Now().Add(-time.Hour).Format(time.RFC3339)) + "&to=" + url.QueryEscape(time.Now().Add(time.Hour).Format(time.RFC3339)), "a1,a2,root1"},
		"time, past":        {"to=" + url.QueryEscape(time.Now().Add(-time.Hour).Format(time.RFC3339)), ""},
		"time, future":      {"from=" + url.QueryEscape(time.Now().Add(time.Hour).Format(time.RFC3339)), ""},
		"category, other":   {"category=access", ""},
		"combined":          {"target=test:a&request_id=req-2&bu=" + a, "a2"},
		"combined, no rows": {"target=test:root&bu=" + a, ""},
	} {
		r := ae.get(t, "rootaud", base+c.q)
		if r.code != 200 || sortedIDs(r) != c.want {
			t.Errorf("%s: %d %q, want %q (%s)", name, r.code, sortedIDs(r), c.want, r.raw)
		}
	}
	// Newest first, paged by cursor.
	p1 := ae.get(t, "rootaud", base+"limit=2")
	if eventIDs(p1) != "a2,root1" || p1.body["next_before"] == nil {
		t.Fatalf("page 1: %s", p1.raw)
	}
	p2 := ae.get(t, "rootaud", fmt.Sprintf("%slimit=2&before=%v", base, p1.body["next_before"]))
	if eventIDs(p2) != "a1" || p2.body["next_before"] != nil {
		t.Fatalf("page 2: %s", p2.raw)
	}
	// History is in order, with its own cursor (AC-16).
	h := ae.get(t, "rootaud", "/history?target=test:a&limit=1")
	if eventIDs(h) != "a1" || h.body["next_after"] == nil {
		t.Fatalf("history page 1: %s", h.raw)
	}
	if h2 := ae.get(t, "rootaud", fmt.Sprintf("/history?target=test:a&limit=1&after=%v", h.body["next_after"])); eventIDs(h2) != "a2" {
		t.Fatalf("history page 2: %s", h2.raw)
	}
	if h := ae.get(t, "rootaud", "/history?actor="+ann); eventIDs(h) != "a1,root1,a2" {
		t.Fatalf("actor history: %s", eventIDs(h))
	}
	// Refused requests.
	for _, q := range []string{"/records?colour=red", "/records?from=yesterday", "/records?bu=not-a-uuid", "/records?source_ip=10.0.0",
		"/records?limit=0", "/records?limit=500", "/records?before=-1", "/history", "/history?target=x&actor=y"} {
		if r := ae.get(t, "rootaud", q); r.code != 400 {
			t.Errorf("%s: %d %s", q, r.code, r.raw)
		}
	}
	// Display names (AC-18): the actor and an approver, by current name.
	ae.e.mustOwner("UPDATE iam.app_user SET display_name = 'Ann Renamed' WHERE email = 'ann@example.test'")
	r := ae.get(t, "rootaud", "/records?target=test:a&limit=1")
	recs := r.body["records"].([]any)
	if names := recs[0].(map[string]any)["names"].(map[string]any); names[ann] != "Ann Renamed" || len(names) != 1 {
		t.Fatalf("names %v", names)
	}
	admin2 := ae.e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'admin2@example.test'")
	r = ae.get(t, "rootaud", "/records?target=test:breakglass")
	if names := r.body["records"].([]any)[0].(map[string]any)["names"].(map[string]any); names[admin2] != "Admin 2" {
		t.Fatalf("approver name: %v", names)
	}
}

// AC-20: every read leaves a record, with its filter and result count;
// a read that cannot be recorded is not answered.
func TestAuditReadsAreRecorded(t *testing.T) {
	ae := auditAPIFixture(t)
	count := func() int {
		var n int
		_, _ = fmt.Sscan(ae.e.adminQuery("SELECT count(*) FROM audit.intake WHERE body->>'type' IN ('audit.searched', 'audit.history_viewed')"), &n)
		return n
	}
	rootaud := ae.e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'rootaud@example.test'")
	seq := ae.e.adminQuery("SELECT seq FROM audit.record WHERE event_id = 'a1'")
	for _, c := range []struct{ path, typ, view, filter string }{
		{"/records?target=test:a&request_id=req-1", "audit.searched", "records", `{"request_id":"req-1","target":"test:a"}`},
		{"/records/" + seq, "audit.searched", "record", `{"seq":` + seq + `}`},
		{"/history?target=test:a", "audit.history_viewed", "", `{"target":"test:a"}`},
		{"/requests/req-1", "audit.searched", "request", `{"request_id":"req-1"}`},
		{"/checkpoints", "audit.searched", "checkpoints", `{"from":null}`},
		{"/keys", "audit.searched", "keys", `{}`},
		{"/status", "audit.searched", "status", `{}`},
		{"/requests/nothing-here", "audit.searched", "request", `{"request_id":"nothing-here"}`}, // a 404 read is recorded too
	} {
		before := count()
		ae.get(t, "rootaud", c.path)
		if count() != before+1 {
			t.Fatalf("%s: not recorded", c.path)
		}
		body := ae.e.adminQuery("SELECT body::text FROM audit.intake WHERE body->>'type' IN ('audit.searched', 'audit.history_viewed') ORDER BY id DESC LIMIT 1")
		var ev struct {
			Type, Actor, Severity string
			Attributes            map[string]string
		}
		_ = json.Unmarshal([]byte(body), &ev)
		if ev.Type != c.typ || ev.Actor != rootaud || ev.Severity != "low" || ev.Attributes["filter"] != c.filter || ev.Attributes["result_count"] == "" ||
			(c.view != "" && ev.Attributes["view"] != c.view) {
			t.Errorf("%s: %s", c.path, body)
		}
	}
	// Refused before reading (no audit.view): nothing to record.
	before := count()
	ae.get(t, "nobody", "/records")
	if count() != before {
		t.Error("a refused read was recorded as a read")
	}
	// Fail closed: with the trail unavailable, reads are refused.
	api := &auditapi.API{DB: ae.pool, Authz: authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(ae.pool)}), Audit: failingEmitter{}}
	srv := httptest.NewServer(api.Handler(ae.keys, nil))
	defer srv.Close()
	broken := ae
	broken.url = srv.URL
	for _, path := range []string{"/records", "/history?target=test:a", "/keys"} {
		if r := broken.get(t, "rootaud", path); r.code != 503 || strings.Contains(r.raw, "test:a") {
			t.Errorf("%s with the trail down: %d %s", path, r.code, r.raw)
		}
	}
}

// AC-18: each record's integrity, and a record's proof once its segment is
// closed, which verifies against the signed checkpoint.
func TestAuditReadIntegrityAndProof(t *testing.T) {
	ae := auditAPIFixture(t)
	ctx := context.Background()
	integrityOf := func(id string) string {
		r := ae.get(t, "rootaud", "/records?type=setting.change_requested&limit=200")
		for _, x := range r.body["records"].([]any) {
			rec := x.(map[string]any)
			if rec["event_id"] == id {
				return fmt.Sprint(rec["integrity"])
			}
		}
		return "absent"
	}
	if got := integrityOf("a1"); got != "pending" {
		t.Fatalf("before verification: %s", got)
	}
	seq := ae.e.adminQuery("SELECT seq FROM audit.record WHERE event_id = 'a1'")
	r := ae.get(t, "rootaud", "/records/"+seq)
	if r.code != 200 || r.body["proof"] != nil {
		t.Fatalf("open segment: %s", r.raw)
	}
	key := newCheckpointKey(t)
	c := checkpointer(t, ae.pool, key)
	if _, err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	v := auditsvc.Verifier{DB: ae.pool, Audit: audit.WithTrail(audit.NewMemory(), audit.Trail{DB: ae.pool})}
	if res, err := v.Full(ctx); err != nil || !res.OK {
		t.Fatalf("%+v %v", res, err)
	}
	if got := integrityOf("a1"); got != "verified" {
		t.Fatalf("after verification: %s", got)
	}
	// The proof: the record's body hashes to the leaf, the path leads to
	// the root in the signed statement, and the signature is the key's.
	r = ae.get(t, "rootaud", "/records/"+seq)
	proof, _ := r.body["proof"].(map[string]any)
	if proof == nil {
		t.Fatalf("closed segment without a proof: %s", r.raw)
	}
	body := ae.e.adminQuery("SELECT encode(body, 'escape') FROM audit.record WHERE seq = " + seq)
	leaf := integrity.Leaf([]byte(body))
	if proof["leaf_hash"] != leaf.String() {
		t.Fatalf("leaf %v, want %s", proof["leaf_hash"], leaf)
	}
	var path []integrity.Hash
	for _, p := range proof["path"].([]any) {
		h, err := integrity.ParseHash(p.(string))
		if err != nil {
			t.Fatal(err)
		}
		path = append(path, h)
	}
	st, err := integrity.ParseStatement([]byte(proof["statement"].(string)))
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.StdEncoding.DecodeString(proof["signature"].(string))
	if !integrity.VerifySignature(&key.PublicKey, []byte(proof["statement"].(string)), sig) {
		t.Fatal("signature")
	}
	if !integrity.VerifyInclusion(leaf, uint64(proof["leaf_index"].(float64)), uint64(proof["tree_size"].(float64)), path, st.MerkleRoot) {
		t.Fatal("inclusion proof does not verify")
	}
	// Checkpoints and keys for verifiers.
	cps := ae.get(t, "aaud", "/checkpoints?from=1")
	if list := cps.body["checkpoints"].([]any); len(list) != 1 || !bytes.Equal([]byte(list[0].(map[string]any)["statement"].(string)), []byte(proof["statement"].(string))) {
		t.Fatalf("checkpoints: %s", cps.raw)
	}
	keyID, _ := integrity.KeyID(&key.PublicKey)
	if ks := ae.get(t, "aaud", "/keys"); !strings.Contains(ks.raw, keyID) {
		t.Fatalf("keys: %s", ks.raw)
	}
	// A failed verification marks records from its position on.
	ae.e.tamper("UPDATE audit.record SET body = convert_to('{}', 'UTF8') WHERE event_id = 'a2'")
	if res, err := v.Full(ctx); err != nil || res.OK {
		t.Fatalf("%+v %v", res, err)
	}
	if a1, root1, a2 := integrityOf("a1"), integrityOf("root1"), integrityOf("a2"); a1 != "verified" || root1 != "verified" || a2 != "failed" {
		t.Fatalf("after a failure at a2: a1 %s, root1 %s, a2 %s", a1, root1, a2)
	}
}
