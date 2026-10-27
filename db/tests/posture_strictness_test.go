package tests

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-13: the database and pkg/settings agree on validity, comparison
// and strictest-of, so a value the service accepts is one the database
// accepts and ranks the same way.

type strictCase struct {
	def   settings.Def
	dir   string // posture direction name
	order string // SQL array literal or NULL
}

func strictCases() []strictCase {
	order := []string{"off", "flag", "warn", "reauthenticate"}
	return []strictCase{
		{settings.Def{Key: "p.duration_lower", Kind: settings.KindDuration, Direction: settings.LowerIsStricter}, "lower_is_stricter", "NULL"},
		{settings.Def{Key: "p.duration_higher", Kind: settings.KindDuration, Direction: settings.HigherIsStricter}, "higher_is_stricter", "NULL"},
		{settings.Def{Key: "p.int_lower", Kind: settings.KindInt, Direction: settings.LowerIsStricter}, "lower_is_stricter", "NULL"},
		{settings.Def{Key: "p.int_higher", Kind: settings.KindInt, Direction: settings.HigherIsStricter}, "higher_is_stricter", "NULL"},
		{settings.Def{Key: "p.bool_true", Kind: settings.KindBool, Direction: settings.TrueIsStricter}, "true_is_stricter", "NULL"},
		{settings.Def{Key: "p.bool_false", Kind: settings.KindBool, Direction: settings.FalseIsStricter}, "false_is_stricter", "NULL"},
		{settings.Def{Key: "p.enum", Kind: settings.KindEnum, Direction: settings.OrderedEnum, Order: order}, "ordered", "ARRAY['off','flag','warn','reauthenticate']"},
	}
}

func kindName(k settings.Kind) string {
	return map[settings.Kind]string{settings.KindDuration: "duration", settings.KindInt: "int", settings.KindBool: "bool", settings.KindEnum: "enum"}[k]
}

func randomStrictValue(r *rand.Rand, d settings.Def) any {
	switch d.Kind {
	case settings.KindDuration:
		units := []time.Duration{time.Millisecond, time.Second, time.Minute, 90 * time.Minute, 24 * time.Hour}
		return time.Duration(r.IntN(5)) * units[r.IntN(len(units))]
	case settings.KindInt:
		return r.IntN(6)
	case settings.KindBool:
		return r.IntN(2) == 1
	default:
		return d.Order[r.IntN(len(d.Order))]
	}
}

// jsonValue encodes a value as posture stores it (durations as Go strings).
func jsonValue(v any) string {
	if d, ok := v.(time.Duration); ok {
		v = d.String()
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func sqlJSON(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'::jsonb" }

// goAccepts is the Go side of validity: the settings client's own decoder.
func goAccepts(d settings.Def, raw string) bool {
	_, err := settings.DecodeValue(d, json.RawMessage(raw))
	return err == nil
}

func TestPostureStrictnessParity(t *testing.T) {
	e := setup(t)
	for _, c := range strictCases() {
		e.admin(e.db, fmt.Sprintf(`INSERT INTO posture.setting_def (key, type, direction, enum_order, owner_feature, registered_version)
			VALUES ('%s', '%s', '%s', %s, 'F-015', '1')`, c.def.Key, kindName(c.def.Kind), c.dir, c.order))
	}

	// Validity: the same values are accepted and refused on both sides.
	candidates := map[settings.Kind][]string{
		settings.KindDuration: {`"15m0s"`, `"0s"`, `"0"`, `"1.5h"`, `"500ms"`, `"2160h0m0s"`, `"-5m"`, `"15"`, `15`, `"15 minutes"`,
			`"2562047h47m16s"`, `"9999999h"`, `null`, `true`, `"+5m"`, `"5.m"`, `"1µs"`, `"1us"`, `"1h 2m"`, `".5m"`, `"1H"`},
		settings.KindInt:  {`3`, `0`, `-1`, `3.5`, `"3"`, `9223372036854775807`, `9223372036854775808`, `1e3`, `null`, `true`},
		settings.KindBool: {`true`, `false`, `"true"`, `1`, `null`},
		settings.KindEnum: {`"flag"`, `"off"`, `"Flag"`, `"block"`, `1`, `null`},
	}
	for _, c := range strictCases() {
		for _, raw := range candidates[c.def.Kind] {
			sqlOK := e.adminState(fmt.Sprintf("PERFORM posture.check_value('%s', %s)", c.def.Key, sqlJSON(raw))) == "ok"
			if goOK := goAccepts(c.def, raw); sqlOK != goOK {
				t.Errorf("%s: %s: database accepts=%v, Go accepts=%v", c.def.Key, raw, sqlOK, goOK)
			}
		}
	}

	// Comparison and strictest-of on random values.
	r := rand.New(rand.NewPCG(20261026, 13)) // #nosec G404 -- seeded, reproducible test data
	for _, c := range strictCases() {
		var rows, want []string
		for i := range 300 {
			a, b := randomStrictValue(r, c.def), randomStrictValue(r, c.def)
			got, err := c.def.Compare(a, b)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, fmt.Sprintf("(%d, %s, %s)", i, sqlJSON(jsonValue(a)), sqlJSON(jsonValue(b))))
			want = append(want, fmt.Sprint(got))
		}
		got := e.adminQuery(fmt.Sprintf(`SELECT string_agg(posture.compare(d, x.a, x.b)::text, ',' ORDER BY x.i)
			FROM posture.setting_def d, (VALUES %s) x(i, a, b) WHERE d.key = '%s'`, strings.Join(rows, ","), c.def.Key))
		if got != strings.Join(want, ",") {
			t.Errorf("%s: database and Go compare differently\n db: %s\n go: %s", c.def.Key, got, strings.Join(want, ","))
		}

		rows, want = nil, nil
		for i := range 100 {
			vals := make([]any, 1+r.IntN(5))
			var arr []string
			for j := range vals {
				vals[j] = randomStrictValue(r, c.def)
				arr = append(arr, sqlJSON(jsonValue(vals[j])))
			}
			s, err := c.def.Strictest(vals...)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, fmt.Sprintf("(%d, ARRAY[%s])", i, strings.Join(arr, ",")))
			want = append(want, jsonValue(s))
		}
		got = e.adminQuery(fmt.Sprintf(`SELECT string_agg(posture.strictest(d, x.v)::text, '|' ORDER BY x.i)
			FROM posture.setting_def d, (VALUES %s) x(i, v) WHERE d.key = '%s'`, strings.Join(rows, ","), c.def.Key))
		if got != strings.Join(want, "|") {
			t.Errorf("%s: database and Go strictest-of differ\n db: %s\n go: %s", c.def.Key, got, strings.Join(want, "|"))
		}
	}
	if got := e.adminQuery(`SELECT coalesce(posture.strictest(d, '{}'), 'null') FROM posture.setting_def d WHERE key = 'p.int_lower'`); got != "null" {
		t.Errorf("strictest of nothing: %s", got)
	}
	e.wantState("app_posture", "PERFORM posture.strictest(NULL::posture.setting_def, '{}')", "42501")
}
