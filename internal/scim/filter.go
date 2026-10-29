package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// Filters (RFC 7644 §3.4.2.2): attribute expressions (eq, ne, co, sw, ew,
// gt, ge, lt, le, pr), and, or, not, grouping and value paths
// (emails[type eq "work"]), with the precedence not > and > or; operators
// and attribute names are case-insensitive.

// errFilter is a malformed filter (400 invalidFilter).
var errFilter = errors.New("scim: invalid filter")

func filterErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errFilter, fmt.Sprintf(format, a...))
}

// path is an attribute path: [urn:]name[.sub].
type path struct {
	URN, Name, Sub string
}

func (p path) String() string {
	s := p.Name
	if p.URN != "" {
		s = p.URN + ":" + s
	}
	if p.Sub != "" {
		s += "." + p.Sub
	}
	return s
}

// parsePath reads an attrPath. A schema URN prefix is everything up to the
// last colon.
func parsePath(s string) (path, error) {
	var p path
	if len(s) > 4 && strings.EqualFold(s[:4], "urn:") {
		i := strings.LastIndex(s, ":")
		p.URN, s = s[:i], s[i+1:]
	}
	name, sub, _ := strings.Cut(s, ".")
	if !attrName(name) || (sub != "" && !attrName(sub)) || strings.Contains(sub, ".") {
		return path{}, fmt.Errorf("invalid attribute path %q", s)
	}
	p.Name, p.Sub = name, sub
	return p, nil
}

// attrName: ALPHA *(nameChar), nameChar = "-" / "_" / DIGIT / ALPHA, and
// "$ref".
func attrName(s string) bool {
	if s == "$ref" {
		return true
	}
	if s == "" || !isAlpha(rune(s[0])) {
		return false
	}
	for _, r := range s {
		if !isAlpha(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func isAlpha(r rune) bool { return r < 128 && unicode.IsLetter(r) }

// --- the AST -----------------------------------------------------------------

type filter interface{ isFilter() }

type logical struct {
	And         bool
	Left, Right filter
}
type not struct{ X filter }
type compare struct {
	Path  path
	Op    string // eq ne co sw ew gt ge lt le pr
	Value any    // string, float64, bool, nil
}
type valuePath struct {
	Path   path
	Filter filter
}

func (logical) isFilter()   {}
func (not) isFilter()       {}
func (compare) isFilter()   {}
func (valuePath) isFilter() {}

// --- the lexer ---------------------------------------------------------------

type token struct {
	kind string // word, string, (, ), [, ]
	text string
	val  any // the string's value
}

func lex(s string) ([]token, error) {
	var out []token
	for i := 0; i < len(s); {
		c := s[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			i++
		case '(', ')', '[', ']':
			out = append(out, token{kind: string(c), text: string(c)})
			i++
		case '"':
			j := i + 1
			for ; j < len(s); j++ {
				if s[j] == '\\' {
					j++
					continue
				}
				if s[j] == '"' {
					break
				}
			}
			if j >= len(s) {
				return nil, filterErr("unterminated string")
			}
			var v string
			if err := json.Unmarshal([]byte(s[i:j+1]), &v); err != nil {
				return nil, filterErr("bad string %s", s[i:j+1])
			}
			out = append(out, token{kind: "string", text: s[i : j+1], val: v})
			i = j + 1
		default:
			j := i
			for j < len(s) && !strings.ContainsRune(" \t\r\n()[]\"", rune(s[j])) {
				j++
			}
			out = append(out, token{kind: "word", text: s[i:j]})
			i = j
		}
	}
	return out, nil
}

// --- the parser --------------------------------------------------------------

type parser struct {
	toks []token
	pos  int
}

// parseFilter parses a filter expression.
func parseFilter(s string) (filter, error) {
	if strings.TrimSpace(s) == "" {
		return nil, filterErr("empty")
	}
	if len(s) > 4096 {
		return nil, filterErr("longer than 4096 characters")
	}
	toks, err := lex(s)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	f, err := p.or(0)
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, filterErr("unexpected %q", p.toks[p.pos].text)
	}
	return f, nil
}

func (p *parser) peek() (token, bool) {
	if p.pos < len(p.toks) {
		return p.toks[p.pos], true
	}
	return token{}, false
}

func (p *parser) keyword(k string) bool {
	t, ok := p.peek()
	return ok && t.kind == "word" && strings.EqualFold(t.text, k)
}

func (p *parser) or(depth int) (filter, error) {
	if depth > 32 {
		return nil, filterErr("nested too deeply")
	}
	left, err := p.and(depth)
	if err != nil {
		return nil, err
	}
	for p.keyword("or") {
		p.pos++
		right, err := p.and(depth)
		if err != nil {
			return nil, err
		}
		left = logical{And: false, Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) and(depth int) (filter, error) {
	left, err := p.unary(depth)
	if err != nil {
		return nil, err
	}
	for p.keyword("and") {
		p.pos++
		right, err := p.unary(depth)
		if err != nil {
			return nil, err
		}
		left = logical{And: true, Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) expect(kind string) error {
	t, ok := p.peek()
	if !ok || t.kind != kind {
		return filterErr("expected %q", kind)
	}
	p.pos++
	return nil
}

func (p *parser) unary(depth int) (filter, error) {
	if p.keyword("not") {
		p.pos++
		if err := p.expect("("); err != nil {
			return nil, err
		}
		x, err := p.or(depth + 1)
		if err != nil {
			return nil, err
		}
		return not{X: x}, p.expect(")")
	}
	t, ok := p.peek()
	if !ok {
		return nil, filterErr("unexpected end")
	}
	if t.kind == "(" {
		p.pos++
		x, err := p.or(depth + 1)
		if err != nil {
			return nil, err
		}
		return x, p.expect(")")
	}
	if t.kind != "word" {
		return nil, filterErr("expected an attribute, got %q", t.text)
	}
	p.pos++
	ap, err := parsePath(t.text)
	if err != nil {
		return nil, filterErr("%v", err)
	}
	if n, ok := p.peek(); ok && n.kind == "[" {
		if ap.Sub != "" {
			return nil, filterErr("a value path filters a multi-valued attribute, not %s", ap)
		}
		p.pos++
		inner, err := p.or(depth + 1)
		if err != nil {
			return nil, err
		}
		if err := p.expect("]"); err != nil {
			return nil, err
		}
		return valuePath{Path: ap, Filter: inner}, nil
	}
	opTok, ok := p.peek()
	if !ok || opTok.kind != "word" {
		return nil, filterErr("expected an operator after %s", ap)
	}
	op := strings.ToLower(opTok.text)
	p.pos++
	switch op {
	case "pr":
		return compare{Path: ap, Op: "pr"}, nil
	case "eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le":
	default:
		return nil, filterErr("unknown operator %q", opTok.text)
	}
	vt, ok := p.peek()
	if !ok {
		return nil, filterErr("expected a value after %s %s", ap, op)
	}
	p.pos++
	var v any
	switch {
	case vt.kind == "string":
		v = vt.val
	case vt.kind == "word" && strings.EqualFold(vt.text, "true"):
		v = true
	case vt.kind == "word" && strings.EqualFold(vt.text, "false"):
		v = false
	case vt.kind == "word" && strings.EqualFold(vt.text, "null"):
		v = nil
	case vt.kind == "word":
		var n float64
		if err := json.Unmarshal([]byte(vt.text), &n); err != nil {
			return nil, filterErr("bad value %q", vt.text)
		}
		v = n
	default:
		return nil, filterErr("bad value %q", vt.text)
	}
	switch v.(type) {
	case bool, nil:
		if op != "eq" && op != "ne" {
			return nil, filterErr("%s cannot compare %v", op, v)
		}
	case float64:
		if op == "co" || op == "sw" || op == "ew" {
			return nil, filterErr("%s needs a string", op)
		}
	}
	return compare{Path: ap, Op: op, Value: v}, nil
}

// --- evaluation --------------------------------------------------------------

// lookup returns m's member key, case-insensitively.
func lookup(m map[string]any, key string) (any, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

// scope is where a filter is evaluated: a resource of a kind, or an
// element of a multi-valued attribute (parent set).
type scope struct {
	k      kind
	parent *Attr
}

// def is the definition of p in the scope (zero when unknown).
func (s scope) def(p path) Attr {
	if s.parent != nil {
		a, _ := s.parent.sub(p.Name)
		return a
	}
	a, _ := s.k.attr(p.URN, p.Name)
	if p.Sub != "" {
		sa, _ := a.sub(p.Sub)
		sa.Multi = a.Multi
		return sa
	}
	return a
}

// values returns the values at p in doc, flattening multi-valued
// attributes; a multi-valued complex attribute without a sub-attribute
// yields its elements' "value".
func (s scope) values(doc map[string]any, p path) []any {
	base := doc
	if s.parent == nil && p.URN != "" {
		if _, ext := s.k.extension(p.URN); ext {
			e, _ := lookup(doc, p.URN)
			m, ok := e.(map[string]any)
			if !ok {
				return nil
			}
			base = m
		}
	}
	v, ok := lookup(base, p.Name)
	if !ok || v == nil {
		return nil
	}
	items := []any{v}
	if arr, isArr := v.([]any); isArr {
		items = arr
	}
	var out []any
	for _, it := range items {
		sub := p.Sub
		if sub == "" {
			if m, isMap := it.(map[string]any); isMap {
				if _, isArr := v.([]any); isArr {
					sub = "value"
				} else {
					out = append(out, m)
					continue
				}
			}
		}
		if sub != "" {
			m, isMap := it.(map[string]any)
			if !isMap {
				continue
			}
			sv, ok := lookup(m, sub)
			if !ok || sv == nil {
				continue
			}
			it = sv
		}
		out = append(out, it)
	}
	return out
}

func (s scope) eval(f filter, doc map[string]any) bool {
	switch x := f.(type) {
	case logical:
		if x.And {
			return s.eval(x.Left, doc) && s.eval(x.Right, doc)
		}
		return s.eval(x.Left, doc) || s.eval(x.Right, doc)
	case not:
		return !s.eval(x.X, doc)
	case valuePath:
		a := s.def(x.Path)
		inner := scope{k: s.k, parent: &a}
		v, _ := lookup(s.base(doc, x.Path), x.Path.Name)
		arr, ok := v.([]any)
		if !ok {
			if m, isMap := v.(map[string]any); isMap {
				arr = []any{m}
			}
		}
		for _, el := range arr {
			if m, isMap := el.(map[string]any); isMap && inner.eval(x.Filter, m) {
				return true
			}
		}
		return false
	case compare:
		vals := s.values(doc, x.Path)
		if x.Op == "pr" {
			for _, v := range vals {
				if present(v) {
					return true
				}
			}
			return false
		}
		if x.Op == "ne" {
			return !s.eval(compare{Path: x.Path, Op: "eq", Value: x.Value}, doc)
		}
		if x.Value == nil { // eq null: absent
			return len(vals) == 0
		}
		exact := s.def(x.Path).CaseExact
		for _, v := range vals {
			if match(x.Op, v, x.Value, exact) {
				return true
			}
		}
	}
	return false
}

func (s scope) base(doc map[string]any, p path) map[string]any {
	if s.parent == nil && p.URN != "" {
		if _, ext := s.k.extension(p.URN); ext {
			if e, _ := lookup(doc, p.URN); e != nil {
				if m, ok := e.(map[string]any); ok {
					return m
				}
			}
			return map[string]any{}
		}
	}
	return doc
}

func present(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

func match(op string, have, want any, exact bool) bool {
	switch w := want.(type) {
	case bool:
		h, ok := have.(bool)
		return ok && op == "eq" && h == w
	case float64:
		h, ok := have.(float64)
		if !ok {
			return false
		}
		return ordered(op, cmpFloat(h, w))
	case string:
		h, ok := have.(string)
		if !ok {
			return false
		}
		// Ordering: as times when both are dateTimes, else as strings.
		if op == "gt" || op == "ge" || op == "lt" || op == "le" {
			if ht, err1 := time.Parse(time.RFC3339Nano, h); err1 == nil {
				if wt, err2 := time.Parse(time.RFC3339Nano, w); err2 == nil {
					return ordered(op, ht.Compare(wt))
				}
			}
		}
		if !exact {
			h, w = strings.ToLower(h), strings.ToLower(w)
		}
		switch op {
		case "eq":
			return h == w
		case "co":
			return strings.Contains(h, w)
		case "sw":
			return strings.HasPrefix(h, w)
		case "ew":
			return strings.HasSuffix(h, w)
		}
		return ordered(op, strings.Compare(h, w))
	}
	return false
}

func cmpFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func ordered(op string, c int) bool {
	switch op {
	case "eq":
		return c == 0
	case "gt":
		return c > 0
	case "ge":
		return c >= 0
	case "lt":
		return c < 0
	case "le":
		return c <= 0
	}
	return false
}
