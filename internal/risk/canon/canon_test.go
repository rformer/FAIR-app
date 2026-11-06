package canon

import (
	"bytes"
	"encoding/json"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

// RFC 8785 §3.2.3: members sorted by UTF-16 code units, so U+1F600 (a
// surrogate pair starting 0xD83D) sorts before U+FB33. (The RFC's values are
// numbers; strings here, as our subset requires.)
func TestRFC8785Sorting(t *testing.T) {
	in := `{"\u20ac": "Euro Sign", "\r": "Carriage Return", "\ufb33": "Hebrew Letter Dalet With Dagesh",
		"1": "One", "\ud83d\ude00": "Emoji: Grinning Face", "\u0080": "Control", "\u00f6": "Latin Small Letter O With Diaeresis"}`
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\"," +
		"\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// RFC 8785 §3.2.2.2: string escaping.
func TestRFC8785Strings(t *testing.T) {
	in := `{"literals": [null, true, false], "string": "\u20ac$\u000f\u000aA'\u0042\u0022\u005c\\\"\/", "esc": "\b\t\f\u001f\u007f"}`
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"esc\":\"\\b\\t\\f\\u001f\u007f\",\"literals\":[null,true,false],\"string\":\"\u20ac$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestParseRefuses(t *testing.T) {
	for name, in := range map[string]string{
		"duplicate member": `{"a": "1", "a": "2"}`,
		"nested duplicate": `{"x": {"a": 1, "b": 2, "a": 3}}`,
		"invalid UTF-8":    "{\"a\": \"\xff\"}",
		"trailing data":    `{"a": 1} {"b": 2}`,
		"not JSON":         `{a: 1}`,
		"too deep":         strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1),
	} {
		if _, err := Canonicalize([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Canonicalize([]byte(strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth))); err != nil {
		t.Errorf("depth %d refused: %v", MaxDepth, err)
	}
}

func TestNumbers(t *testing.T) {
	for in, want := range map[string]string{
		`[0, 1, -1, 9007199254740991, -9007199254740991]`: `[0,1,-1,9007199254740991,-9007199254740991]`,
	} {
		got, err := Canonicalize([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("%s: %s %v", in, got, err)
		}
	}
	for _, in := range []string{`[1.5]`, `[1e3]`, `[1.0]`, `[-0]`, `[9007199254740992]`, `[0.1]`} {
		if got, err := Canonicalize([]byte(in)); err == nil {
			t.Errorf("%s accepted as %s", in, got)
		}
	}
}

func TestDecimal(t *testing.T) {
	for in, want := range map[string]string{
		"0": "0", "-0": "0", "0.0": "0", "-0.000": "0", "1": "1", "1.0": "1", "1.50": "1.5", "-2.25": "-2.25",
		"1e3": "1000", "1E+3": "1000", "1.5e-3": "0.0015", "12345e-5": "0.12345", "100": "100", "0.000001": "0.000001",
		"250000000": "250000000", "0.9": "0.9",
	} {
		got, err := Decimal(in)
		if err != nil || got != want {
			t.Errorf("Decimal(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "01", "1.", ".5", "+1", "1/3", "0x10", "1_000", "NaN", "Inf", "1e", "1e1000", " 1", "1 ",
		"1e-999", strings.Repeat("9", 35), "0." + strings.Repeat("1", 35), strings.Repeat("1", MaxDecimalInput+1)} {
		if got, err := Decimal(in); err == nil {
			t.Errorf("Decimal(%q) accepted as %q", in, got)
		}
	}
	// Huge exponents are refused by syntax, at once, never computed.
	start := time.Now()
	for _, in := range []string{"1e999999", "1e-999999", "9e99999", "1e99999999"} {
		if _, err := Decimal(in); err == nil {
			t.Errorf("Decimal(%q) accepted", in)
		}
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("refusing huge exponents took %v", d)
	}
	// Canonical decimals are fixed points.
	for _, in := range []string{"0", "1", "1.5", "-0.0015", "123456789.987654321"} {
		if got, _ := Decimal(in); got != in {
			t.Errorf("Decimal(%q) = %q, not a fixed point", in, got)
		}
	}
}

// Property: canonicalisation is idempotent, independent of member order and
// whitespace, and the digest changes with any value.
func TestCanonicalProperties(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 500; i++ {
		v := randomValue(r, 0)
		a, err := Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		// Re-parse and re-emit: identical bytes.
		b, err := Canonicalize(a)
		if err != nil || !bytes.Equal(a, b) {
			t.Fatalf("not idempotent: %s / %s %v", a, b, err)
		}
		// Indented, standard-library output (other member order and
		// whitespace, HTML escapes) canonicalises to the same bytes.
		std, _ := json.MarshalIndent(v, "", "  ")
		if c, err := Canonicalize(std); err != nil || !bytes.Equal(a, c) {
			t.Fatalf("std form differs: %s / %s %v", a, c, err)
		}
		// Changing one leaf changes the digest.
		if m, ok := v.(map[string]any); ok && len(m) > 0 {
			for k := range m {
				m[k] = []any{m[k]}
				break
			}
			d, _ := Marshal(m)
			if Digest(d) == Digest(a) {
				t.Fatalf("digest unchanged after a change: %s", a)
			}
		}
	}
}

func randomValue(r *rand.Rand, depth int) any {
	n := r.IntN(7)
	if depth > 3 {
		n = r.IntN(4)
	}
	switch n {
	case 0:
		return nil
	case 1:
		return r.IntN(2) == 0
	case 2:
		return json.Number(itoa(r.Int64N(1<<53) - 1<<52))
	case 3:
		return randString(r)
	case 4, 5:
		m := map[string]any{}
		for j := r.IntN(5); j > 0; j-- {
			m[randString(r)+itoa(int64(j))] = randomValue(r, depth+1)
		}
		return m
	default:
		a := []any{}
		for j := r.IntN(4); j > 0; j-- {
			a = append(a, randomValue(r, depth+1))
		}
		return a
	}
}

func randString(r *rand.Rand) string {
	rs := []rune("ab<>&\"\\\n\x01é€😀")
	var b strings.Builder
	for j := r.IntN(6); j > 0; j-- {
		b.WriteRune(rs[r.IntN(len(rs))])
	}
	return b.String()
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }
