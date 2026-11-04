package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
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
	if err := v.Emit(t.Context(), Event{Type: "made.up", Severity: SeverityInfo, Actor: "x"}); err == nil || len(mem.Events()) != 0 {
		t.Fatal("an uncatalogued event was emitted")
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
}

func TestFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if _, err := FromEnv("production", "x", env(map[string]string{"FAIR_AUDIT_SYSLOG_ADDR": "siem:6514", "FAIR_AUDIT_SYSLOG_PLAINTEXT": "true"})); err == nil {
		t.Fatal("plain TCP syslog accepted in production")
	}
	if _, err := FromEnv("development", "x", env(map[string]string{"FAIR_AUDIT_SYSLOG_ADDR": "relay:514", "FAIR_AUDIT_SYSLOG_PLAINTEXT": "true"})); err != nil {
		t.Fatal(err)
	}
	if _, err := FromEnv("production", "x", env(map[string]string{"FAIR_AUDIT_SYSLOG_ADDR": "siem:6514", "FAIR_AUDIT_SYSLOG_CA_FILE": "/nonexistent"})); err == nil {
		t.Fatal("a missing CA file accepted")
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
		if e.Category != want.Category || e.Description != want.Description || len(e.Severities) != len(want.Severities) || len(e.Requires) != len(want.Requires) {
			t.Fatalf("%s differs from the catalog", e.Type)
		}
	}
}
