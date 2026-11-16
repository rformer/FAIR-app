package tests

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rformer/fair-app/internal/notify"
	"github.com/rformer/fair-app/internal/notifyapi"
)

// notifyAPI serves the notifications API as app_notify, on the risk env's
// keys, its tokens minted for the audience "notify".
func notifyAPI(t *testing.T, ra *riskAPIEnv) *riskAPIEnv {
	t.Helper()
	srv := httptest.NewServer((&notifyapi.API{DB: notifyPool(t, ra.env)}).Handler(ra.keys, nil))
	t.Cleanup(srv.Close)
	na := *ra
	na.url, na.aud = srv.URL, "notify"
	na.n += 900000
	return &na
}

// F-009 T-06 (F-009-AC-02, AC-18, AC-19, AC-21; design §3.8, §6): each user
// reads, counts and marks their own notifications, and sets their mutes and
// digest; mandatory kinds cannot be muted; changes are audited.
func TestNotifyAPI(t *testing.T) {
	a := acceptanceFixture(t)
	ra := a.ra
	na := notifyAPI(t, ra)
	pool := notifyPool(t, ra.env)
	step := func() {
		t.Helper()
		if _, _, err := (notify.Collector{DB: pool}).Collect(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := (notify.FanOut{DB: pool}).Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	step()
	// Three acceptance requests: appA1 is asked to decide each.
	var accs []string
	for i := range 3 {
		risk := a.accepted(t, fmt.Sprintf("Claims notice %d", i), "owen")
		id, code := a.request(t, "owen", risk, "Within appetite", days(90), "")
		if code != "" {
			t.Fatal(code)
		}
		accs = append(accs, id)
	}
	step()

	list := func(user, q string) apiResp {
		t.Helper()
		got := na.call(t, "GET", user, "/api/v1/notifications"+q, nil)
		if got.code != 200 {
			t.Fatalf("list %s as %s: %d %s", q, user, got.code, got.raw)
		}
		return got
	}
	count := func(user string) float64 {
		t.Helper()
		return na.call(t, "GET", user, "/api/v1/notifications/count", nil).body["unread"].(float64)
	}
	base := count("appA1")
	if base < 3 {
		t.Fatalf("appA1 has %v unread", base)
	}
	got := list("appA1", "?limit=2")
	items := got.body["notifications"].([]any)
	first := items[0].(map[string]any)
	if len(items) != 2 || got.body["more"] != true || first["kind"] != "acceptance.decision_needed" || first["mandatory"] != true || first["read_at"] != nil {
		t.Fatalf("page: %s", got.raw)
	}
	if link := first["envelope"].(map[string]any)["item"].(map[string]any)["link"]; link != "/acceptances/"+accs[2] {
		t.Errorf("newest first: %v", link)
	}
	older := list("appA1", fmt.Sprintf("?limit=2&before=%v", items[1].(map[string]any)["id"]))
	if n := len(older.body["notifications"].([]any)); n < 1 {
		t.Errorf("older page: %s", older.raw)
	}
	// owen requested them: none for owen, and nothing of appA1's is owen's.
	for _, x := range list("owen", "").body["notifications"].([]any) {
		if x.(map[string]any)["kind"] == "acceptance.decision_needed" {
			t.Errorf("owen asked to decide his own request")
		}
	}

	// Mark read: one, then all.
	id := first["id"]
	if got := na.call(t, "POST", "appA1", "/api/v1/notifications/read", map[string]any{"ids": []any{id}}); got.code != 200 || got.body["marked"] != 1.0 {
		t.Fatalf("mark one: %d %s", got.code, got.raw)
	}
	if count("appA1") != base-1 {
		t.Errorf("after one: %v", count("appA1"))
	}
	// Another user's id marks nothing.
	if got := na.call(t, "POST", "appA", "/api/v1/notifications/read", map[string]any{"ids": []any{items[1].(map[string]any)["id"]}}); got.body["marked"] != 0.0 {
		t.Errorf("appA marked appA1's: %s", got.raw)
	}
	unread := list("appA1", "?unread=true").body["notifications"].([]any)
	for _, x := range unread {
		if x.(map[string]any)["id"] == id {
			t.Error("a read notification listed as unread")
		}
	}
	for name, body := range map[string]map[string]any{"neither": {}, "both": {"ids": []any{1}, "all": true}, "unknown field": {"all": true, "x": 1}} {
		if got := na.call(t, "POST", "appA1", "/api/v1/notifications/read", body); got.code != 400 {
			t.Errorf("%s: %d", name, got.code)
		}
	}
	if got := na.call(t, "POST", "appA1", "/api/v1/notifications/read", map[string]any{"all": true}); got.code != 200 || count("appA1") != 0 {
		t.Errorf("mark all: %d %s, %v left", got.code, got.raw, count("appA1"))
	}
	for _, q := range []string{"?limit=0", "?limit=201", "?before=x", "?unread=maybe"} {
		if got := na.call(t, "GET", "appA1", "/api/v1/notifications"+q, nil); got.code != 400 {
			t.Errorf("%s: %d", q, got.code)
		}
	}

	// Preferences: optional kinds mute; mandatory ones cannot.
	prefs := na.call(t, "GET", "appA1", "/api/v1/notifications/preferences", nil)
	if prefs.code != 200 || prefs.body["digest"] != false || prefs.body["digest_hour"] != 7.0 || len(prefs.body["kinds"].([]any)) != len(notify.Kinds)-1 {
		t.Fatalf("preferences: %d %s", prefs.code, prefs.raw)
	}
	set := func(body map[string]any) apiResp {
		return na.call(t, "PUT", "appA1", "/api/v1/notifications/preferences", body)
	}
	if got := set(map[string]any{"mutes": map[string]any{"acceptance.decision_needed": true}, "digest": false, "digest_hour": 7}); got.code != 409 || got.body["error"] != "mandatory" {
		t.Errorf("muting a mandatory kind: %d %s", got.code, got.raw)
	}
	for name, body := range map[string]map[string]any{
		"unknown kind": {"mutes": map[string]any{"mail.spam": true}, "digest": false, "digest_hour": 7},
		"bad hour":     {"digest": true, "digest_hour": 24},
		"no digest":    {"digest_hour": 7},
	} {
		if got := set(body); got.code != 400 {
			t.Errorf("%s: %d %s", name, got.code, got.raw)
		}
	}
	got = set(map[string]any{"mutes": map[string]any{"acceptance.decided": true, "risk.stale": true}, "digest": true, "digest_hour": 6})
	if got.code != 200 || got.body["digest"] != true || got.body["digest_hour"] != 6.0 {
		t.Fatalf("set: %d %s", got.code, got.raw)
	}
	muted := []string{}
	for _, k := range got.body["kinds"].([]any) {
		if m := k.(map[string]any); m["email_muted"] == true {
			muted = append(muted, m["kind"].(string))
		}
	}
	if strings.Join(muted, ",") != "acceptance.decided,risk.stale" {
		t.Errorf("muted: %v", muted)
	}
	// Unmute one; kinds left out keep their setting.
	got = set(map[string]any{"mutes": map[string]any{"risk.stale": false}, "digest": true, "digest_hour": 6})
	if got.code != 200 || !strings.Contains(got.raw, `"kind": "acceptance.decided", "label"`) && !strings.Contains(got.raw, `acceptance.decided`) {
		t.Fatalf("unmute: %d %s", got.code, got.raw)
	}
	appA1 := a.userID("appA1")
	if got := ra.adminQuery("SELECT string_agg(kind, ',' ORDER BY kind) FROM notify.preference WHERE user_id = '" + appA1 + "'"); got != "acceptance.decided" {
		t.Errorf("stored mutes: %s", got)
	}
	// Audited, the same values again not.
	events := func() string {
		return ra.adminQuery(`SELECT count(*) || '|' || coalesce(max(body #>> '{attributes,muted}'), '') FROM audit.intake
			WHERE body ->> 'type' = 'notification.preferences_changed' AND body ->> 'actor' = '` + appA1 + "'")
	}
	if got := events(); got != "2|acceptance.decided,risk.stale" {
		t.Errorf("events: %s", got)
	}
	set(map[string]any{"digest": true, "digest_hour": 6})
	if got := events(); !strings.HasPrefix(got, "2|") {
		t.Errorf("an unchanged save recorded: %s", got)
	}
	// Each user's own: appA's preferences untouched.
	if got := na.call(t, "GET", "appA", "/api/v1/notifications/preferences", nil); got.body["digest"] != false {
		t.Errorf("appA's: %s", got.raw)
	}
	// Without a token, nothing.
	if got := na.call(t, "GET", "", "/api/v1/notifications", nil); got.code != 401 {
		t.Errorf("anonymous: %d", got.code)
	}
}
