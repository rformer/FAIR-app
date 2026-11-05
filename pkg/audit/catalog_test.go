package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// F-001 T-37 (AC-50): the catalog lists exactly the event types the code
// can emit. The scan finds every type in the migrations (audit rows of
// iam.event_outbox, and the event arguments of the audit helpers) and in
// the Go code (audit.Event literals and the authn event helper); every one
// must be catalogued, and every catalogued type must be emitted somewhere.

const typePat = `[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+`

// sqlHelpers are the migrations' audit helpers and the argument (0-based)
// that names the event type.
var sqlHelpers = map[string]int{
	"iam.approval_audit": 0, "iam.authn_event": 0, "iam.breakglass_event": 0, "iam.bu_event": 0, "iam.catalog_audit": 0, "iam.claim_group_event": 0,
	"iam.idp_event": 0, "iam.mapping_event": 0, "iam.role_event": 0, "iam.sa_event": 0, "iam.scim_event": 0,
	"iam.session_event": 0, "iam.sod_event": 0, "iam.role_write_version": 4, "iam.review_event": 0,
}

// dynamicTypes are types built at run time from a fixed set of parts.
var dynamicTypes = map[string][]string{
	// internal/posture/k8saccess.go: "posture.k8s_access_" + the new state.
	`"posture.k8s_access_" + state`: {"posture.k8s_access_granted", "posture.k8s_access_declined", "posture.k8s_access_requested",
		"posture.k8s_access_revoked"},
}

// args splits a call's argument list (from just after its "(") into its
// top-level arguments.
func args(s string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return append(out, s[start:])
			}
			i += j + 1
		case '(':
			depth++
		case ')':
			if depth == 0 {
				return append(out, s[start:i])
			}
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

var (
	litRE    = regexp.MustCompile(`'(` + typePat + `)'`)
	prefixRE = regexp.MustCompile(`'([a-z_]+\.)'\s*\|\|\s*CASE`)
	thenRE   = regexp.MustCompile(`(?:THEN|ELSE)\s+'([a-z_]+)'`)
	bareRE   = regexp.MustCompile(`^\s*[a-z_]+\s*$`)
)

// sqlTypes are the types an SQL expression can produce, and whether it is
// a plain parameter (the helper's own definition passing `event` along).
func sqlTypes(expr string) ([]string, bool) {
	if bareRE.MatchString(expr) {
		return nil, true
	}
	if m := prefixRE.FindStringSubmatch(expr); m != nil { // 'user.' || CASE ... THEN 'disabled' ...
		var out []string
		for _, t := range thenRE.FindAllStringSubmatch(expr, -1) {
			out = append(out, m[1]+t[1])
		}
		return out, false
	}
	var out []string
	for _, m := range litRE.FindAllStringSubmatch(expr, -1) {
		out = append(out, m[1])
	}
	return out, false
}

func scan(t *testing.T) map[string][]string {
	t.Helper()
	found := map[string][]string{}
	add := func(typ, where string) {
		if !slices.Contains(found[typ], where) {
			found[typ] = append(found[typ], where)
		}
	}
	migs, _ := filepath.Glob("../../db/migrations/*.sql")
	if len(migs) == 0 {
		t.Fatal("no migrations found")
	}
	typeKey := regexp.MustCompile(`'type',\s*`)
	for _, f := range migs {
		b, err := os.ReadFile(f) // #nosec G304 -- the repository's migrations
		if err != nil {
			t.Fatal(err)
		}
		s, name := string(b), filepath.Base(f)
		for _, m := range typeKey.FindAllStringIndex(s, -1) {
			a := args(s[m[1]:])
			if len(a) == 0 {
				continue
			}
			types, param := sqlTypes(a[0])
			if len(types) == 0 && !param {
				t.Errorf("%s: an audit type the scan cannot read: %.80s", name, a[0])
			}
			for _, ty := range types {
				add(ty, name)
			}
		}
		for h, pos := range sqlHelpers {
			re := regexp.MustCompile(regexp.QuoteMeta(h) + `\(`)
			for _, m := range re.FindAllStringIndex(s, -1) {
				if strings.Contains(s[max(0, m[0]-40):m[0]], "FUNCTION ") {
					continue // the helper's definition
				}
				a := args(s[m[1]:])
				if len(a) <= pos {
					continue
				}
				types, param := sqlTypes(a[pos])
				if len(types) == 0 && !param {
					t.Errorf("%s: %s with an event the scan cannot read: %.80s", name, h, a[pos])
				}
				for _, ty := range types {
					add(ty, name)
				}
			}
		}
	}
	goType := regexp.MustCompile(`Type:\s*("[a-z0-9_.]+"\s*\+\s*[a-zA-Z.]+|"` + typePat + `"|[A-Za-z_][A-Za-z0-9_]*)`)
	goAssign := regexp.MustCompile(`\.Type\s*(?:,\s*[\w.]+\s*)*=\s*("` + typePat + `"|[A-Za-z_][A-Za-z0-9_]*)`)
	goEvent := regexp.MustCompile(`(?:\.event\([^,()]*(?:\(\))?,|iam\.authn_event\([^"]*",)\s*"(` + typePat + `)"`)
	// Identifiers holding a type: constants and variables assigned a type
	// literal, by package directory (constants) and by file (locals).
	defRE := func(name string) *regexp.Regexp {
		return regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*:?=\s*"(` + typePat + `)"`)
	}
	files := map[string]string{}
	for _, dir := range []string{"../../cmd", "../../internal", "../../pkg"} {
		err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") ||
				strings.Contains(filepath.ToSlash(p), "/webauthntest/") || strings.Contains(filepath.ToSlash(p), "/samltest/") ||
				strings.Contains(filepath.ToSlash(p), "/oidctest/") {
				return err
			}
			b, err := os.ReadFile(p) // #nosec G304 G122 -- the repository's Go files, read by a test
			files[filepath.ToSlash(p)] = string(b)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	resolve := func(file, ident string) []string {
		var out []string
		for p, s := range files {
			if p != file && filepath.Dir(p) != filepath.Dir(file) {
				continue
			}
			for _, m := range defRE(ident).FindAllStringSubmatch(s, -1) {
				if !slices.Contains(out, m[1]) {
					out = append(out, m[1])
				}
			}
		}
		return out
	}
	for name, s := range files {
		var refs []string
		for _, m := range goType.FindAllStringSubmatch(s, -1) {
			refs = append(refs, m[1])
		}
		for _, m := range goAssign.FindAllStringSubmatch(s, -1) {
			refs = append(refs, m[1])
		}
		for _, ref := range refs {
			switch {
			case dynamicTypes[ref] != nil:
				for _, ty := range dynamicTypes[ref] {
					add(ty, name)
				}
			case strings.Contains(ref, "+"):
				t.Errorf("%s: a dynamic event type the scan does not know: %s", name, ref)
			case strings.HasPrefix(ref, `"`):
				add(strings.Trim(ref, `"`), name)
			default:
				// An identifier: an audit type when it resolves to type
				// literals (other Type fields, e.g. protocol types, do not).
				for _, ty := range resolve(name, ref) {
					add(ty, name)
				}
			}
		}
		for _, m := range goEvent.FindAllStringSubmatch(s, -1) {
			add(m[1], name)
		}
	}
	return found
}

func TestCatalogMatchesCode(t *testing.T) {
	c, err := DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	found := scan(t)
	var missing, unused []string
	for ty, where := range found {
		if _, ok := c.Entries[ty]; !ok {
			sort.Strings(where)
			missing = append(missing, ty+" ("+strings.Join(where, ", ")+")")
		}
	}
	for _, ty := range c.Types() {
		if _, ok := found[ty]; !ok {
			unused = append(unused, ty)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("emitted but not catalogued:\n  %s", strings.Join(missing, "\n  "))
	}
	if len(unused) > 0 {
		t.Errorf("catalogued but never emitted:\n  %s", strings.Join(unused, "\n  "))
	}
	if len(found) < 100 {
		t.Errorf("the scan found only %d types; it is missing emitters", len(found))
	}
}

// AC-50: every category has events; AC-54: adding a privileged permission
// is a high-severity event; AC-43: break-glass logins are high.
func TestCatalogCoverage(t *testing.T) {
	c, err := DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	per := map[string]int{}
	for _, e := range c.Entries {
		per[e.Category]++
	}
	for _, cat := range Categories {
		if per[cat] == 0 {
			t.Errorf("no events in category %s", cat)
		}
	}
	for ty, sev := range map[string]Severity{"role.privileged_added": SeverityHigh, "breakglass.login": SeverityHigh,
		"breakglass.emergency_enabled": SeverityCritical} {
		if e := c.Entries[ty]; !slices.Equal(e.Severities, []Severity{sev}) {
			t.Errorf("%s severities %v, want only %s", ty, e.Severities, sev)
		}
	}
}

func TestValidate(t *testing.T) {
	c, err := DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	ok, _ := Normalize(Event{Type: "breakglass.login", Severity: SeverityHigh, Actor: "u1", Target: "user:u1"}, time.Now())
	if err := c.Validate(ok); err != nil {
		t.Fatalf("a good event: %v", err)
	}
	for name, mut := range map[string]func(*Event){
		"unknown type":   func(e *Event) { e.Type = "breakglass.dance" },
		"wrong severity": func(e *Event) { e.Severity = SeverityLow },
		"no target":      func(e *Event) { e.Target = "" },
		"bad type":       func(e *Event) { e.Type = "Breakglass" },
		"no actor":       func(e *Event) { e.Actor = "" },
	} {
		e := ok
		mut(&e)
		if err := c.Validate(e); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The emitters refuse what the catalog does not describe.
	mem := NewMemory()
	v := Validating{Next: mem, Catalog: c}
	if err := v.Emit(t.Context(), Event{Type: "made.up", Severity: SeverityInfo, Actor: "x"}); err == nil || len(mem.OfType("made.up")) != 0 ||
		len(mem.OfType("audit.invalid_event")) != 1 {
		t.Fatal("an uncatalogued event was emitted, or its refusal not recorded")
	}
	SetStrict(true)
	defer SetStrict(false)
	if err := mem.Emit(t.Context(), Event{Type: "made.up", Severity: SeverityInfo, Actor: "x"}); err == nil {
		t.Fatal("a strict Memory took an uncatalogued event")
	}
}

func TestFromOutbox(t *testing.T) {
	e, err := FromOutbox(7, []byte(`{"type": "role.retired", "severity": "high", "actor": "u", "target": "role:r", "reason": "old",
		"attributes": {"name": "R", "n": 3, "list": ["a"], "none": null}}`))
	if err != nil {
		t.Fatal(err)
	}
	if e.Target != "role:r" || e.Reason != "old" || e.Attributes["n"] != "3" || e.Attributes["list"] != `["a"]` || e.Attributes["event_id"] != "7" {
		t.Fatalf("%+v", e)
	}
	if _, ok := e.Attributes["none"]; ok {
		t.Fatal("null attribute kept")
	}
	// F-002 T-03: a top-level bu_id becomes the envelope's.
	e, err = FromOutbox(8, []byte(`{"type": "bu.created", "severity": "high", "actor": "u", "target": "bu:b", "bu_id": "00000000-0000-4000-8000-000000000001"}`))
	if err != nil || e.BUID != "00000000-0000-4000-8000-000000000001" {
		t.Fatalf("bu_id: %+v %v", e, err)
	}
}

func TestFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	// F-002 T-16: per-service syslog is retired; a leftover address refuses.
	for _, e := range []string{"production", "development"} {
		if _, err := FromEnv(e, "x", env(map[string]string{"FAIR_AUDIT_SYSLOG_ADDR": "siem:6514"})); err == nil ||
			!strings.Contains(err.Error(), "audit.syslog_destination") {
			t.Fatalf("%s with FAIR_AUDIT_SYSLOG_ADDR: %v", e, err)
		}
	}
	e, err := FromEnv("production", "x", env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := e.(Validating); !ok {
		t.Fatalf("%T is not validating", e)
	}
}

func TestCheckDeclaredEvents(t *testing.T) {
	list := func(s ...string) *[]string { return &s }
	if err := CheckDeclaredEvents(list("role.created", "role.privileged_added"), ""); err != nil {
		t.Fatal(err)
	}
	if err := CheckDeclaredEvents(list(), "a lookup; nothing changes"); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		events *[]string
		note   string
	}{
		"undeclared":        {nil, ""},
		"empty, no note":    {list(), " "},
		"not in catalog":    {list("role.created", "role.dance"), ""},
		"misspelled prefix": {list("roles.created"), ""},
	} {
		if err := CheckDeclaredEvents(c.events, c.note); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// F-002 T-02: the catalog as audit.sync_event_types takes it.
func TestSyncPayload(t *testing.T) {
	c, err := DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.SyncPayload()
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Events []struct {
			Type        string   `json:"type"`
			Category    string   `json:"category"`
			Severities  []string `json:"severities"`
			Requires    []string `json:"requires"`
			BU          string   `json:"bu"`
			Attributes  []string `json:"attributes"`
			Description string   `json:"description"`
		} `json:"events"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		t.Fatal(err)
	}
	if len(p.Events) != len(c.Entries) {
		t.Fatalf("%d events, catalog has %d", len(p.Events), len(c.Entries))
	}
	if !bytes.Contains(b, []byte(`"requires":[]`)) {
		t.Fatal("an entry without requirements must carry an empty list, not null")
	}
	for i, e := range p.Events {
		if i > 0 && p.Events[i-1].Type >= e.Type {
			t.Fatalf("not sorted at %s", e.Type)
		}
		want := c.Entries[e.Type]
		if e.Category != want.Category || e.Description != want.Description || len(e.Severities) != len(want.Severities) || len(e.Requires) != len(want.Requires) ||
			e.BU != want.BU || !slices.Equal(e.Attributes, want.Attributes) || (e.BU != BURequired && e.BU != BUOptional) || e.Attributes == nil {
			t.Fatalf("%s differs from the catalog", e.Type)
		}
	}
}

// F-002 T-03: every entry declares bu and its attributes, and names that
// would carry a secret are refused.
func TestCatalogBUAndAttributes(t *testing.T) {
	entry := func(extra string) []byte {
		return []byte("events:\n  - type: a.b\n    category: system\n    severities: [info]\n" + extra + "    description: d\n")
	}
	if _, err := ParseCatalog(entry("    attributes: [x]\n")); err != nil {
		t.Fatal(err)
	}
	c, _ := ParseCatalog(entry("    attributes: []\n"))
	if e := c.Entries["a.b"]; e.BU != BUOptional || e.Attributes == nil {
		t.Fatalf("defaults: %+v", e)
	}
	for name, extra := range map[string]string{
		"no attributes list":  "",
		"bad bu":              "    bu: sometimes\n    attributes: []\n",
		"bad attribute name":  "    attributes: [Bad]\n",
		"reserved attribute":  "    attributes: [event_id]\n",
		"duplicate attribute": "    attributes: [x, x]\n",
		"password":            "    attributes: [new_password]\n",
		"token":               "    attributes: [access_token]\n",
		"secret":              "    attributes: [client_secret]\n",
		"cookie":              "    attributes: [cookie]\n",
		"authorization":       "    attributes: [authorization]\n",
	} {
		if _, err := ParseCatalog(entry(extra)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	def, err := DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	root := "00000000-0000-4000-8000-000000000001"
	ev := func(ty string) Event {
		ent := def.Entries[ty]
		e := Event{ID: "t1", Time: time.Now(), Type: ty, Severity: ent.Severities[0], Actor: "system:test", Target: "x:1", Reason: "r", Attributes: map[string]string{}}
		if ent.BU == BURequired {
			e.BUID = root
		}
		return e
	}
	// bu: required types need bu_id; others take one or not.
	e := ev("bu.created")
	if err := def.Validate(e); err != nil {
		t.Fatal(err)
	}
	e.BUID = ""
	if err := def.Validate(e); err == nil {
		t.Fatal("bu.created without bu_id accepted")
	}
	e = ev("setting.changed")
	if err := def.Validate(e); err != nil {
		t.Fatal(err)
	}
	e.BUID = "not-a-uuid"
	if err := def.Validate(e); err == nil {
		t.Fatal("a bu_id that is not a UUID accepted")
	}
	// Unlisted attributes are refused; the reserved event_id is not.
	e = ev("service.stopped")
	e.Attributes["anything"] = "x"
	if err := def.Validate(e); err == nil {
		t.Fatal("an unlisted attribute accepted")
	}
	e.Attributes = map[string]string{"event_id": "7"}
	if err := def.Validate(e); err != nil {
		t.Fatal(err)
	}
}

// F-002-AC-06: no event type can carry a secret. Every listed attribute of
// every type takes an ordinary value, and refuses each secret-looking one;
// so do target, reason, before and after.
func TestNoSecretsInEvents(t *testing.T) {
	c, err := DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{
		"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1MSJ9.c2ln",
		"-----BEGIN EC PRIVATE KEY-----\nMHc=\n-----END EC PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----",
		"Bearer abcdefghijklmnopqrstuvwxyz012345",
		"Authorization: Basic dXNlcjpwYXNzd29yZDEyMzQ1Ng==",
		"__Host-sid=6f1a2b3c",
	}
	for _, ty := range c.Types() {
		ent := c.Entries[ty]
		base := func() Event {
			e := Event{ID: "t1", Time: time.Now(), Type: ty, Severity: ent.Severities[0], Actor: "system:test", Target: "x:1", Reason: "because", Attributes: map[string]string{}}
			if ent.BU == BURequired {
				e.BUID = "00000000-0000-4000-8000-000000000001"
			}
			for _, a := range ent.Attributes {
				e.Attributes[a] = "ordinary value 42"
			}
			return e
		}
		if err := c.Validate(base()); err != nil {
			t.Fatalf("%s with every attribute: %v", ty, err)
		}
		for _, s := range secrets {
			for _, a := range ent.Attributes {
				e := base()
				e.Attributes[a] = s
				if err := c.Validate(e); err == nil {
					t.Fatalf("%s: attribute %s took %q", ty, a, s)
				}
			}
			for _, f := range []func(*Event){
				func(e *Event) { e.Target = s }, func(e *Event) { e.Reason = s },
				func(e *Event) { e.Before = map[string]any{"v": s} }, func(e *Event) { e.After = []any{s} },
			} {
				e := base()
				f(&e)
				if err := c.Validate(e); err == nil {
					t.Fatalf("%s took %q outside its attributes", ty, s)
				}
			}
		}
	}
	// Ordinary values that resemble the patterns are not refused.
	for _, s := range []string{"eyJ", "-----BEGIN PUBLIC KEY-----", "basic plan", "bearer of news", "sid=1"} {
		if LooksSecret(s) {
			t.Errorf("%q looks secret", s)
		}
	}
}

// sqlAttrArgs is, per SQL audit helper, the argument (0-based) carrying
// extra attributes that the helper merges into its own.
var sqlAttrArgs = map[string]int{
	"iam.authn_event": 4, "iam.breakglass_event": 4, "iam.bu_event": 4, "iam.catalog_audit": 3, "iam.idp_event": 4,
	"iam.review_event": 5, "iam.role_event": 5, "iam.sa_event": 5, "iam.scim_event": 5, "iam.sod_event": 4,
}

// jsonbKeys are the literal keys of a jsonb_build_object(...) call, given
// the text just after its "(" (nil when it is not such a call).
func jsonbKeys(call string) []string {
	var out []string
	for i, a := range args(call) {
		if i%2 == 0 {
			if k := strings.TrimSpace(a); len(k) > 2 && k[0] == '\'' && k[len(k)-1] == '\'' {
				out = append(out, k[1:len(k)-1])
			}
		}
	}
	return out
}

// F-002 T-03 (AC-06): every attribute an emission site writes literally is
// in its type's catalog list, so an untested path cannot fail closed in
// production on an unlisted attribute. Checks Go audit.Event literals,
// direct SQL payloads, and SQL helper calls (the helper's own keys plus
// the extra attributes passed to it).
func TestCatalogAttributesMatchCode(t *testing.T) {
	c, err := DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	check := func(where string, types, keys []string) {
		for _, ty := range types {
			ent, ok := c.Entries[ty]
			if !ok {
				continue // TestCatalogMatchesCode reports it
			}
			for _, k := range keys {
				checked++
				if !slices.Contains(ent.Attributes, k) && !slices.Contains(ReservedAttributes, k) {
					t.Errorf("%s: %s writes attribute %q, not in its catalog list", where, ty, k)
				}
			}
		}
	}
	attrCall := regexp.MustCompile(`'attributes',\s*jsonb_build_object\(`)
	migs, _ := filepath.Glob("../../db/migrations/*.sql")
	sort.Strings(migs)
	// The helpers' own keys, from their latest definitions.
	helperKeys := map[string][]string{}
	for _, f := range migs {
		b, _ := os.ReadFile(f) // #nosec G304 -- the repository's migrations
		s := string(b)
		for h := range sqlHelpers {
			re := regexp.MustCompile(`CREATE (?:OR REPLACE )?FUNCTION ` + regexp.QuoteMeta(h) + `\(`)
			for _, m := range re.FindAllStringIndex(s, -1) {
				body := s[m[1]:]
				if end := strings.Index(body, "$$;"); end > 0 {
					body = body[:end]
				}
				var keys []string
				for _, a := range attrCall.FindAllStringIndex(body, -1) {
					keys = append(keys, jsonbKeys(body[a[1]:])...)
				}
				helperKeys[h] = keys
			}
		}
	}
	typeKey := regexp.MustCompile(`'type',\s*`)
	for _, f := range migs {
		b, _ := os.ReadFile(f) // #nosec G304 -- the repository's migrations
		s, name := string(b), filepath.Base(f)
		// Direct payloads: the attributes object after a literal type, within
		// the same statement.
		for _, m := range typeKey.FindAllStringIndex(s, -1) {
			a := args(s[m[1]:])
			if len(a) == 0 {
				continue
			}
			types, _ := sqlTypes(a[0])
			stmt := s[m[1]:]
			if end := strings.IndexByte(stmt, ';'); end > 0 {
				stmt = stmt[:end]
			}
			if next := typeKey.FindStringIndex(stmt); next != nil {
				stmt = stmt[:next[0]]
			}
			if loc := attrCall.FindStringIndex(stmt); loc != nil {
				check(name, types, jsonbKeys(stmt[loc[1]:]))
			}
		}
		// Helper calls.
		for h, pos := range sqlHelpers {
			re := regexp.MustCompile(regexp.QuoteMeta(h) + `\(`)
			for _, m := range re.FindAllStringIndex(s, -1) {
				if strings.Contains(s[max(0, m[0]-40):m[0]], "FUNCTION ") {
					continue
				}
				a := args(s[m[1]:])
				if pos >= len(a) {
					continue
				}
				types, _ := sqlTypes(a[pos])
				keys := append([]string(nil), helperKeys[h]...)
				if ap, ok := sqlAttrArgs[h]; ok && ap < len(a) {
					if x := strings.TrimSpace(a[ap]); strings.HasPrefix(x, "jsonb_build_object(") {
						keys = append(keys, jsonbKeys(x[len("jsonb_build_object("):])...)
					}
				}
				check(name+" "+h, types, keys)
			}
		}
	}
	// Go: audit.Event literals with a literal type and a literal attribute map.
	evRE := regexp.MustCompile(`audit\.Event\{`)
	tyRE := regexp.MustCompile(`Type:\s*"(` + typePat + `)"`)
	mapRE := regexp.MustCompile(`Attributes:\s*map\[string\]string\{`)
	keyRE := regexp.MustCompile(`(?m)(?:^|[{,])\s*"([a-z][a-z0-9_]*)"\s*:`)
	for _, dir := range []string{"../../cmd", "../../internal", "../../pkg"} {
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			b, _ := os.ReadFile(p) // #nosec G304 G122 -- the repository's Go files, read by a test
			s := string(b)
			for _, m := range evRE.FindAllStringIndex(s, -1) {
				lit := braced(s[m[1]-1:])
				tm := tyRE.FindStringSubmatch(lit)
				am := mapRE.FindStringIndex(lit)
				if tm == nil || am == nil {
					continue
				}
				var keys []string
				for _, k := range keyRE.FindAllStringSubmatch(braced(lit[am[1]-1:]), -1) {
					keys = append(keys, k[1])
				}
				check(filepath.ToSlash(p), []string{tm[1]}, keys)
			}
			return nil
		})
	}
	if checked < 300 {
		t.Errorf("only %d attribute writes checked; the scan is missing emitters", checked)
	}
}

// braced returns s from its first "{" to the matching "}".
func braced(s string) string {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[:i+1]
			}
		case '"':
			for j := i + 1; j < len(s); j++ {
				if s[j] == '\\' {
					j++
				} else if s[j] == '"' {
					i = j
					break
				}
			}
		}
	}
	return s
}

// F-002 T-06 (design §6.1): an event the catalog refuses is refused to the
// caller and recorded as audit.invalid_event (critical, the original
// attached), outside the caller's transaction.
func TestValidatingRecordsInvalidEvents(t *testing.T) {
	c, err := DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	mem := NewMemory()
	var sawTx []bool
	v := Validating{Next: Multi{mem, emitFunc(func(ctx context.Context, _ Event) error {
		tx, _ := ctx.Value(txKey{}).(Execer)
		sawTx = append(sawTx, tx != nil)
		return nil
	})}, Catalog: c}
	ctx := WithTx(t.Context(), fakeExecer{})
	if err := v.Emit(ctx, Event{Type: "role.dance", Severity: SeverityHigh, Actor: "u1", Target: "role:r1"}); !errors.Is(err, ErrUncatalogued) {
		t.Fatalf("an uncatalogued event: %v", err)
	}
	inv := mem.OfType("audit.invalid_event")
	if len(inv) != 1 || inv[0].Severity != SeverityCritical || !strings.Contains(inv[0].Attributes["payload"], "role.dance") || len(mem.OfType("role.dance")) != 0 {
		t.Fatalf("%+v", mem.Events())
	}
	if len(sawTx) != 1 || sawTx[0] {
		t.Fatalf("the invalid event was recorded in the caller's transaction: %v", sawTx)
	}
	// An original that looks like a secret is not copied anywhere.
	mem2 := NewMemory()
	v.Next = mem2
	_ = v.Emit(t.Context(), Event{Type: "role.retired", Severity: SeverityHigh, Actor: "u1", Target: "role:r1",
		Reason: "Bearer abcdefghijklmnopqrstuvwxyz0123"})
	if len(mem2.Events()) != 0 {
		t.Fatalf("a secret-looking event was recorded: %+v", mem2.Events())
	}
}

type emitFunc func(context.Context, Event) error

func (f emitFunc) Emit(ctx context.Context, e Event) error { return f(ctx, e) }

type fakeExecer struct{}

func (fakeExecer) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}
