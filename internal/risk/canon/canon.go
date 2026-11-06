// Package canon is the canonical JSON form of F-003 documents (design §3.2,
// §4.2): the subset of RFC 8785 (JCS) the risk service emits, and SHA-256
// digests over it.
//
// The subset: objects with members sorted by their names' UTF-16 code
// units, no insignificant whitespace, strings escaped as JCS requires, and
// numbers only as integers of at most 2^53-1 in magnitude, written plainly.
// Fractional values are never JSON numbers in a document: they are decimal
// strings in the form Decimal returns, so the digest never depends on how a
// float is formatted. Parse refuses what JCS cannot represent faithfully:
// invalid UTF-8, duplicate member names, and excessive nesting.
package canon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxDepth bounds the nesting of objects and arrays.
const MaxDepth = 32

// MaxSafeInteger is the largest integer a canonical document may hold (the
// largest integer every JSON parser represents exactly).
const MaxSafeInteger = 1<<53 - 1

// Parse decodes one JSON value into maps, slices, strings, json.Number,
// bools and nil, refusing invalid UTF-8, duplicate member names, nesting
// deeper than MaxDepth and trailing data.
func Parse(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("not valid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := parseValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("data after the JSON value")
	}
	return v, nil
}

func parseValue(d *json.Decoder, depth int) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t := t.(type) {
	case json.Delim:
		if depth >= MaxDepth {
			return nil, fmt.Errorf("nested deeper than %d", MaxDepth)
		}
		switch t {
		case '{':
			m := map[string]any{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return nil, err
				}
				key := k.(string)
				if _, dup := m[key]; dup {
					return nil, fmt.Errorf("duplicate member %q", key)
				}
				v, err := parseValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[key] = v
			}
			_, err := d.Token() // '}'
			return m, err
		case '[':
			a := []any{}
			for d.More() {
				v, err := parseValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err := d.Token() // ']'
			return a, err
		}
		return nil, fmt.Errorf("unexpected %v", t)
	default:
		return t, nil
	}
}

// Marshal writes a value produced by Parse (or built from the same types,
// plus int and int64) in canonical form.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := write(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Canonicalize parses raw JSON and returns its canonical form.
func Canonicalize(raw []byte) ([]byte, error) {
	v, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	return Marshal(v)
}

// Digest is the lowercase hex SHA-256 of b.
func Digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func write(b *bytes.Buffer, v any) error {
	switch v := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(v))
	case string:
		writeString(b, v)
	case int:
		return writeInt(b, int64(v))
	case int64:
		return writeInt(b, v)
	case json.Number:
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil || strconv.FormatInt(n, 10) != string(v) {
			return fmt.Errorf("number %s: only plain integers are allowed (fractions are decimal strings)", v)
		}
		return writeInt(b, n)
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, compareUTF16)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := write(b, v[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, x := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := write(b, x); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	default:
		return fmt.Errorf("cannot write %T", v)
	}
	return nil
}

func writeInt(b *bytes.Buffer, n int64) error {
	if n > MaxSafeInteger || n < -MaxSafeInteger {
		return fmt.Errorf("integer %d is outside ±(2^53-1)", n)
	}
	b.WriteString(strconv.FormatInt(n, 10))
	return nil
}

// compareUTF16 orders member names by their UTF-16 code units (RFC 8785
// §3.2.3).
func compareUTF16(a, b string) int {
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
}

// writeString escapes as RFC 8785 §3.2.2.2 (ECMAScript JSON.stringify):
// quote and backslash, the short escapes for \b \t \n \f \r, \u00xx in
// lowercase hex for other control characters, everything else literal.
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// Decimal limits: the input's length, and the canonical value's digits.
const (
	MaxDecimalInput  = 64
	MaxDecimalDigits = 34 // decimal128's precision; ample for any estimate
)

// Decimal returns the canonical form of a decimal number given as JSON
// number text or a string: plain notation (no exponent), no leading zeros
// before the integer digits, no trailing zeros after the point, no point
// without fraction digits, and "0" for any zero.
func Decimal(s string) (string, error) {
	if len(s) == 0 || len(s) > MaxDecimalInput {
		return "", fmt.Errorf("%q is not a decimal number of at most %d characters", s, MaxDecimalInput)
	}
	if !decimalSyntax(s) {
		return "", fmt.Errorf("%q is not a decimal number", s)
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return "", fmt.Errorf("%q is not a decimal number", s)
	}
	out := r.FloatString(MaxDecimalDigits + 1)
	if strings.Contains(out, ".") {
		out = strings.TrimRight(strings.TrimRight(out, "0"), ".")
	}
	// The exact value must survive: no rounding allowed.
	if back, _ := new(big.Rat).SetString(out); back.Cmp(r) != 0 {
		return "", fmt.Errorf("%q has more than %d fraction digits", s, MaxDecimalDigits)
	}
	if digits := len(strings.NewReplacer("-", "", ".", "").Replace(strings.TrimLeft(strings.TrimPrefix(out, "-"), "0."))); digits > MaxDecimalDigits {
		return "", fmt.Errorf("%q has more than %d significant digits", s, MaxDecimalDigits)
	}
	return out, nil
}

// decimalSyntax is the JSON number grammar (RFC 8259 §6), which big.Rat's
// SetString is more lenient than (it takes fractions like "1/3", hex and
// underscores).
func decimalSyntax(s string) bool {
	i := 0
	if i < len(s) && s[i] == '-' {
		i++
	}
	switch {
	case i < len(s) && s[i] == '0':
		i++
	case i < len(s) && s[i] >= '1' && s[i] <= '9':
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	default:
		return false
	}
	if i < len(s) && s[i] == '.' {
		i++
		start := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == start {
			return false
		}
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		start := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		// At most three exponent digits: big.Rat would otherwise build
		// 10^e for an exponent of any size (a denial of service).
		if i == start || i-start > 3 {
			return false
		}
	}
	return i == len(s)
}
