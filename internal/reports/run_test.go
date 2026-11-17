package reports

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/pkg/settings"
)

func TestCheckFormats(t *testing.T) {
	if got, err := CheckFormats([]string{"json", "pdf"}); err != nil || !slices.Equal(got, []string{"pdf", "json"}) {
		t.Errorf("ordered: %v %v", got, err)
	}
	for _, bad := range [][]string{nil, {}, {"pdf", "pdf"}, {"xlsx"}, {"pdf", "docx"}} {
		if _, err := CheckFormats(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	for _, f := range Formats {
		if FileName(f) == "" || MediaType(f) == "" {
			t.Errorf("%s: no file name or media type", f)
		}
	}
}

func TestCheckParams(t *testing.T) {
	none := Kind{Name: "treatment"}
	for _, raw := range []string{"", "null", "{}"} {
		if got, err := none.CheckParams(json.RawMessage(raw)); err != nil || string(got) != "{}" {
			t.Errorf("%q: %s %v", raw, got, err)
		}
	}
	if _, err := none.CheckParams(json.RawMessage(`{"owner":"x"}`)); !errors.Is(err, ErrParams) {
		t.Errorf("parameters for a kind without any: %v", err)
	}
	k := Kind{Name: "register", Params: func(json.RawMessage) (json.RawMessage, error) { return nil, errors.New("status is open or closed") }}
	if _, err := k.CheckParams(json.RawMessage(`{"status":"x"}`)); !errors.Is(err, ErrParams) {
		t.Errorf("refused parameters: %v", err)
	}
}

type fakeReasons struct {
	inst bool
	bus  map[string]any
	err  error
}

func (f fakeReasons) Bool(string, string) (bool, error)       { return f.inst, f.err }
func (f fakeReasons) BUValues(string) (map[string]any, error) { return f.bus, f.err }
func (q *subtreeQuery) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	q.asked = args[1].([]string)
	return fakeRow{q.answer}
}

type subtreeQuery struct {
	answer bool
	asked  []string
}

type fakeRow struct{ v bool }

func (r fakeRow) Scan(dest ...any) error {
	*(dest[0].(*bool)) = r.v
	return nil
}

// The reason rule: the instance value decides alone when true; otherwise
// the BUs where it is true are asked about the subtree; errors fail closed.
func TestReasonRequired(t *testing.T) {
	ctx := context.Background()
	q := &subtreeQuery{answer: true}
	if got, err := ReasonRequired(ctx, q, fakeReasons{inst: true}, "bu"); err != nil || !got || q.asked != nil {
		t.Errorf("instance-wide: %v %v %v", got, err, q.asked)
	}
	if got, err := ReasonRequired(ctx, q, fakeReasons{bus: map[string]any{"b2": false}}, "bu"); err != nil || got || q.asked != nil {
		t.Errorf("no BU requires it: %v %v", got, err)
	}
	if got, err := ReasonRequired(ctx, q, fakeReasons{bus: map[string]any{"b2": true, "b1": true, "b3": false}}, "bu"); err != nil || !got ||
		!slices.Equal(q.asked, []string{"b1", "b2"}) {
		t.Errorf("BUs requiring it: %v %v %v", got, err, q.asked)
	}
	q.answer = false
	if got, _ := ReasonRequired(ctx, q, fakeReasons{bus: map[string]any{"b1": true}}, "bu"); got {
		t.Error("outside the subtree")
	}
	if _, err := ReasonRequired(ctx, q, fakeReasons{err: settings.ErrStale}, "bu"); !errors.Is(err, settings.ErrStale) {
		t.Errorf("stale settings: %v", err)
	}
}

// The built-in kinds' parameters come back canonical (sorted keys); bad
// values are refused.
func TestBuiltinParams(t *testing.T) {
	for _, c := range []struct {
		k        Kind
		in, want string
	}{
		{RegisterKind, `{"status":"current","decision":"accept"}`, `{"decision":"accept","status":"current"}`},
		{RegisterKind, ``, `{}`},
		{AcceptancesKind, `{"expiring_within":30,"decided_to":"2026-01-31"}`, `{"decided_to":"2026-01-31","expiring_within":30}`},
		{TreatmentKind, `{}`, `{}`},
	} {
		got, err := c.k.CheckParams(json.RawMessage(c.in))
		if err != nil || string(got) != c.want {
			t.Errorf("%s %s: %s %v", c.k.Name, c.in, got, err)
		}
	}
	for _, c := range []struct {
		k  Kind
		in string
	}{
		{RegisterKind, `{"status":"red"}`}, {RegisterKind, `{"x":1}`}, {RegisterKind, `{} {}`},
		{AcceptancesKind, `{"expiring_within":-1}`}, {AcceptancesKind, `{"decided_from":"soon"}`}, {TreatmentKind, `{"owner":"me"}`},
	} {
		if _, err := c.k.CheckParams(json.RawMessage(c.in)); !errors.Is(err, ErrParams) {
			t.Errorf("%s %s accepted: %v", c.k.Name, c.in, err)
		}
	}
	if len(Kinds()) != 3 {
		t.Errorf("kinds: %v", Kinds())
	}
}
