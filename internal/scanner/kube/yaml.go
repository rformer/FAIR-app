package kube

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// parseYAML reads the YAML subset kubeconfig files are written in (kubectl,
// kind, k3s, RKE2, the cloud providers' tools): block mappings and
// sequences, plain, single- and double-quoted scalars on one line, empty
// flow collections and flow sequences of scalars, comments, one document.
// Anchors, aliases, tags, block scalars, complex keys and multi-line
// scalars are refused, naming the line; `kubectl config view --raw
// --flatten -o json` writes any kubeconfig in a form this reads (a JSON
// document is read as such). The result holds map[string]any, []any,
// string, bool and nil (plain scalars other than booleans and null stay
// strings: the kubeconfig fields read are strings or booleans).
func parseYAML(b []byte) (any, error) {
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("not UTF-8")
	}
	p := &yamlParser{}
	started := false
	for i, raw := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		n := i + 1
		text := stripComment(raw)
		if strings.TrimSpace(text) == "" {
			continue
		}
		indent := len(text) - len(strings.TrimLeft(text, " "))
		if strings.HasPrefix(strings.TrimLeft(text, " "), "\t") {
			return nil, fmt.Errorf("line %d: tab in indentation", n)
		}
		body := strings.TrimRight(text[indent:], " \t")
		switch {
		case body == "---" && indent == 0:
			if started || len(p.lines) > 0 {
				return nil, fmt.Errorf("line %d: more than one document", n)
			}
			started = true
			continue
		case body == "..." && indent == 0:
			return nil, fmt.Errorf("line %d: document end marker", n)
		case strings.HasPrefix(body, "%"):
			return nil, fmt.Errorf("line %d: directives are not read", n)
		}
		p.lines = append(p.lines, yamlLine{n: n, indent: indent, text: body})
	}
	if len(p.lines) == 0 {
		return map[string]any{}, nil
	}
	v, err := p.node(p.lines[0].indent)
	if err != nil {
		return nil, err
	}
	if p.i < len(p.lines) {
		return nil, fmt.Errorf("line %d: unexpected indentation", p.lines[p.i].n)
	}
	return v, nil
}

type yamlLine struct {
	n, indent int
	text      string
}

type yamlParser struct {
	lines []yamlLine
	i     int
}

func isSeqItem(s string) bool { return s == "-" || strings.HasPrefix(s, "- ") }

func (p *yamlParser) node(indent int) (any, error) {
	l := p.lines[p.i]
	if l.indent != indent {
		return nil, fmt.Errorf("line %d: unexpected indentation", l.n)
	}
	if isSeqItem(l.text) {
		return p.sequence(indent)
	}
	return p.mapping(indent)
}

func (p *yamlParser) sequence(indent int) (any, error) {
	out := []any{}
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent < indent || (l.indent == indent && !isSeqItem(l.text)) {
			break // the sequence ends; its parent mapping continues
		}
		if l.indent > indent {
			return nil, fmt.Errorf("line %d: unexpected indentation", l.n)
		}
		rest := strings.TrimLeft(strings.TrimPrefix(l.text, "-"), " ")
		if rest == "" {
			p.i++
			if p.i < len(p.lines) && p.lines[p.i].indent > indent {
				v, err := p.node(p.lines[p.i].indent)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			} else {
				out = append(out, nil)
			}
			continue
		}
		// "- key: value" or "- - x": the rest is a node at its own column.
		col := l.indent + len(l.text) - len(rest)
		if isSeqItem(rest) || mappingKey(rest) >= 0 {
			p.lines[p.i] = yamlLine{n: l.n, indent: col, text: rest}
			v, err := p.node(col)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		v, err := scalar(rest, l.n)
		if err != nil {
			return nil, err
		}
		p.i++
		if p.i < len(p.lines) && p.lines[p.i].indent > indent {
			return nil, fmt.Errorf("line %d: multi-line scalars are not read", p.lines[p.i].n)
		}
		out = append(out, v)
	}
	return out, nil
}

func (p *yamlParser) mapping(indent int) (any, error) {
	out := map[string]any{}
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent < indent {
			break
		}
		if l.indent > indent {
			return nil, fmt.Errorf("line %d: unexpected indentation", l.n)
		}
		if isSeqItem(l.text) {
			break // a sequence item at a parent key's column ends this mapping
		}
		k := mappingKey(l.text)
		if k < 0 {
			return nil, fmt.Errorf("line %d: expected \"key: value\"", l.n)
		}
		keyText := strings.TrimSpace(l.text[:k])
		if strings.HasPrefix(keyText, "? ") || keyText == "?" {
			return nil, fmt.Errorf("line %d: complex keys are not read", l.n)
		}
		kv, err := scalar(keyText, l.n)
		if err != nil {
			return nil, err
		}
		key, ok := kv.(string)
		if !ok {
			key = keyText
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate key %q", l.n, key)
		}
		rest := strings.TrimSpace(l.text[k+1:])
		p.i++
		if rest != "" {
			v, err := scalar(rest, l.n)
			if err != nil {
				return nil, err
			}
			if p.i < len(p.lines) && p.lines[p.i].indent > indent {
				return nil, fmt.Errorf("line %d: multi-line scalars are not read", p.lines[p.i].n)
			}
			out[key] = v
			continue
		}
		switch {
		case p.i < len(p.lines) && p.lines[p.i].indent > indent:
			v, err := p.node(p.lines[p.i].indent)
			if err != nil {
				return nil, err
			}
			out[key] = v
		case p.i < len(p.lines) && p.lines[p.i].indent == indent && isSeqItem(p.lines[p.i].text):
			v, err := p.sequence(indent)
			if err != nil {
				return nil, err
			}
			out[key] = v
		default:
			out[key] = nil
		}
	}
	return out, nil
}

// mappingKey returns the index of the colon ending s's key, or -1: the
// first ':' followed by a space or the end of the line, outside quotes, in
// a line that does not start a flow collection or a quoted scalar spanning
// the colon.
func mappingKey(s string) int {
	if s == "" || s[0] == '[' || s[0] == '{' {
		return -1
	}
	quote := byte(0)
	if s[0] == '"' || s[0] == '\'' {
		quote = s[0]
		end := closingQuote(s, quote)
		if end < 0 {
			return -1
		}
		rest := s[end+1:]
		j := strings.IndexFunc(rest, func(r rune) bool { return r != ' ' })
		if j >= 0 && rest[j] == ':' && (j+1 == len(rest) || rest[j+1] == ' ') {
			return end + 1 + j
		}
		return -1
	}
	for i := 0; i < len(s); i++ {
		if s[i] == ':' && (i+1 == len(s) || s[i+1] == ' ') {
			return i
		}
	}
	return -1
}

func closingQuote(s string, q byte) int {
	for i := 1; i < len(s); i++ {
		switch {
		case q == '"' && s[i] == '\\':
			i++
		case q == '\'' && s[i] == '\'' && i+1 < len(s) && s[i+1] == '\'':
			i++
		case s[i] == q:
			return i
		}
	}
	return -1
}

// stripComment removes a comment: '#' at the start or after a space,
// outside quotes.
func stripComment(s string) string {
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '"' && c == '\\':
			i++
		case quote != 0:
			if c == quote {
				if quote == '\'' && i+1 < len(s) && s[i+1] == '\'' {
					i++
				} else {
					quote = 0
				}
			}
		case (c == '"' || c == '\'') && (i == 0 || strings.ContainsRune(" :-[{,", rune(s[i-1]))):
			quote = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

// scalar reads a one-line value.
func scalar(s string, n int) (any, error) {
	switch s[0] {
	case '&', '*':
		return nil, fmt.Errorf("line %d: anchors and aliases are not read", n)
	case '!':
		return nil, fmt.Errorf("line %d: tags are not read", n)
	case '|', '>':
		return nil, fmt.Errorf("line %d: block scalars are not read", n)
	case '@', '`':
		return nil, fmt.Errorf("line %d: reserved indicator %q", n, s[0])
	case '"', '\'':
		end := closingQuote(s, s[0])
		if end < 0 {
			return nil, fmt.Errorf("line %d: multi-line scalars are not read", n)
		}
		if strings.TrimSpace(s[end+1:]) != "" {
			return nil, fmt.Errorf("line %d: text after a quoted scalar", n)
		}
		return unquote(s[:end+1], n)
	case '[':
		return flowSequence(s, n)
	case '{':
		if strings.TrimSpace(s[1:]) == "}" {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("line %d: flow mappings are not read (only {})", n)
	}
	switch s {
	case "true", "True", "TRUE":
		return true, nil
	case "false", "False", "FALSE":
		return false, nil
	case "null", "Null", "NULL", "~":
		return nil, nil
	}
	return s, nil
}

func unquote(s string, n int) (string, error) {
	if s[0] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
	}
	var b strings.Builder
	body := s[1 : len(s)-1]
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i == len(body) {
			return "", fmt.Errorf("line %d: bad escape", n)
		}
		switch body[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '0':
			b.WriteByte(0)
		case '"', '\\', '/', ' ':
			b.WriteByte(body[i])
		case 'u', 'U', 'x':
			size := map[byte]int{'x': 2, 'u': 4, 'U': 8}[body[i]]
			if i+1+size > len(body) {
				return "", fmt.Errorf("line %d: bad escape", n)
			}
			r, err := strconv.ParseUint(body[i+1:i+1+size], 16, 32)
			if err != nil || r > utf8.MaxRune {
				return "", fmt.Errorf("line %d: bad escape", n)
			}
			b.WriteRune(rune(r)) // #nosec G115 -- at most utf8.MaxRune
			i += size
		default:
			return "", fmt.Errorf("line %d: escape \\%c is not read", n, body[i])
		}
	}
	return b.String(), nil
}

func flowSequence(s string, n int) (any, error) {
	if s[len(s)-1] != ']' {
		return nil, fmt.Errorf("line %d: multi-line flow sequences are not read", n)
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	out := []any{}
	if inner == "" {
		return out, nil
	}
	for len(inner) > 0 {
		var item string
		if inner[0] == '"' || inner[0] == '\'' {
			end := closingQuote(inner, inner[0])
			if end < 0 {
				return nil, fmt.Errorf("line %d: unterminated quote", n)
			}
			item, inner = inner[:end+1], strings.TrimSpace(inner[end+1:])
			if inner != "" && inner[0] != ',' {
				return nil, fmt.Errorf("line %d: text after a quoted scalar", n)
			}
		} else {
			j := strings.IndexByte(inner, ',')
			if j < 0 {
				j = len(inner)
			}
			item, inner = strings.TrimSpace(inner[:j]), inner[j:]
		}
		inner = strings.TrimSpace(strings.TrimPrefix(inner, ","))
		if item == "" || strings.ContainsAny(item[:1], "[{") {
			return nil, fmt.Errorf("line %d: nested flow collections are not read", n)
		}
		v, err := scalar(item, n)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
