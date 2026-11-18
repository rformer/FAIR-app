package tests

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rformer/fair-app/internal/notify"
)

// F-009 T-02 (F-009-AC-01, AC-13; design §5): the notify schema: roles,
// the state rules (PF028), the release's notice kinds, the outbox grants.
func TestNotifySchema(t *testing.T) {
	e := setup(t)
	// The install synced every kind.
	if got := len(e.install.Kinds.Added); got != len(notify.Kinds) {
		t.Fatalf("install synced %d kinds, want %d", got, len(notify.Kinds))
	}
	if got := e.adminQuery("SELECT count(*) FILTER (WHERE mandatory) || '/' || count(*) FILTER (WHERE security) || '/' || count(*) FROM notify.kind"); got != "13/6/24" { // F-011 T-17: integration.run_failed
		t.Errorf("kinds mandatory/security/total = %s", got)
	}

	// No application role reaches the tables; notify_definer does.
	for _, role := range []string{"app_rw", "app_notify", "app_posture", "app_audit", "app_gateway"} {
		for _, q := range []string{
			"PERFORM count(*) FROM notify.notice", "PERFORM count(*) FROM notify.inbox", "PERFORM count(*) FROM notify.channel",
			"PERFORM count(*) FROM notify.delivery", "PERFORM count(*) FROM notify.kind",
			"INSERT INTO notify.preference (user_id, kind, email_muted) SELECT id, 'risk.stale', true FROM iam.app_user LIMIT 1",
		} {
			if got := e.adminState("SET ROLE " + role + "; " + q); got != "42501" {
				t.Errorf("%s: %s: %s", role, q, got)
			}
		}
	}
	if got := e.adminState("SET ROLE notify_definer; PERFORM count(*) FROM notify.notice"); got != "ok" {
		t.Errorf("notify_definer reads notices: %s", got)
	}
	if got := e.adminState("SET ROLE app_rw; PERFORM notify.sync_kinds('{\"kinds\": []}')"); got != "42501" {
		t.Errorf("app_rw syncs kinds: %s", got)
	}

	// The state rules, for every role (as the owner here).
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('nina@example.test', 'Nina')")
	user := e.adminQuery("SELECT id FROM iam.app_user WHERE email = 'nina@example.test'")
	root := e.adminQuery("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	notice := e.adminQuery(`INSERT INTO notify.notice (kind, source, source_id, envelope, recipients, queued_at)
		VALUES ('risk.stale', 'register', '1', '{"kind": "risk.stale"}', '{"users": []}', now()) RETURNING id`)
	if got := e.adminState(`INSERT INTO notify.notice (kind, source, source_id, envelope, recipients, queued_at)
		VALUES ('risk.stale', 'register', '1', '{}', '{}', now())`); got != "23505" {
		t.Errorf("the same source row twice: %s", got)
	}
	for _, c := range []struct{ name, sql, want string }{
		{"notice envelope", "UPDATE notify.notice SET envelope = '{}' WHERE id = '" + notice + "'", "PF028"},
		{"notice fanned", "UPDATE notify.notice SET fanned_out_at = now() WHERE id = '" + notice + "'", "ok"},
		{"notice refan", "UPDATE notify.notice SET fanned_out_at = now() + interval '1 hour' WHERE id = '" + notice + "'", "PF028"},
		{"unknown kind", `INSERT INTO notify.notice (kind, source, source_id, envelope, recipients, queued_at)
			VALUES ('mail.spam', 'register', '2', '{}', '{}', now())`, "23503"},
	} {
		if got := e.adminState(c.sql); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	inbox := e.adminQuery("INSERT INTO notify.inbox (notice_id, user_id) VALUES ('" + notice + "', '" + user + "') RETURNING id")
	for _, c := range []struct{ name, sql, want string }{
		{"unread again", "UPDATE notify.inbox SET read_at = NULL WHERE id = " + inbox, "PF028"},
		{"read", "UPDATE notify.inbox SET read_at = now() WHERE id = " + inbox, "ok"},
		{"read again", "UPDATE notify.inbox SET read_at = now() + interval '1 hour' WHERE id = " + inbox, "PF028"},
	} {
		if got := e.adminState(c.sql); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	for _, c := range []struct{ name, sql, want string }{
		{"webhook without a secret", "INSERT INTO notify.channel (kind, name, config, bu_id, kinds) VALUES ('webhook', 'w', '{}', '" + root + "', '{risk.stale}')", "23514"},
		{"smtp with a BU", "INSERT INTO notify.channel (kind, name, config, bu_id) VALUES ('smtp', 's', '{}', '" + root + "')", "23514"},
		{"smtp", "INSERT INTO notify.channel (kind, name, config) VALUES ('smtp', 'relay', '{}')", "ok"},
		{"a second smtp", "INSERT INTO notify.channel (kind, name, config) VALUES ('smtp', 'relay 2', '{}')", "23505"},
	} {
		if got := e.adminState(c.sql); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	smtp := e.adminQuery("SELECT id FROM notify.channel WHERE kind = 'smtp'")
	delivery := e.adminQuery("INSERT INTO notify.delivery (notice_id, channel_id, user_id) VALUES ('" + notice + "', '" + smtp + "', '" + user + "') RETURNING id")
	if got := e.adminState("INSERT INTO notify.delivery (notice_id, channel_id, user_id) VALUES ('" + notice + "', '" + smtp + "', '" + user + "')"); got != "23505" {
		t.Errorf("a second delivery: %s", got)
	}
	for _, c := range []struct{ name, sql, want string }{
		{"claim without a token", "UPDATE notify.delivery SET state = 'sending' WHERE id = '" + delivery + "'", "23514"},
		{"claim", "UPDATE notify.delivery SET state = 'sending', token = gen_random_uuid(), claimed_at = now(), attempts = 1 WHERE id = '" + delivery + "'", "ok"},
		{"fewer attempts", "UPDATE notify.delivery SET attempts = 0 WHERE id = '" + delivery + "'", "PF028"},
		{"another recipient", "UPDATE notify.delivery SET user_id = NULL WHERE id = '" + delivery + "'", "PF028"},
		{"failed without a reason", "UPDATE notify.delivery SET state = 'failed', token = NULL, claimed_at = NULL WHERE id = '" + delivery + "'", "23514"},
		{"sent", "UPDATE notify.delivery SET state = 'sent', token = NULL, claimed_at = NULL, sent_at = now() WHERE id = '" + delivery + "'", "ok"},
		{"sent is final", "UPDATE notify.delivery SET state = 'pending', sent_at = NULL WHERE id = '" + delivery + "'", "PF028"},
	} {
		if got := e.adminState(c.sql); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}

	// The outboxes: notify_definer reads them and marks them delivered, and
	// changes nothing else.
	for _, ob := range []string{"iam", "posture", "estimate", "acceptance"} {
		if got := e.adminState("SET ROLE notify_definer; UPDATE " + ob + ".notice_outbox SET delivered_at = now() WHERE false"); got != "ok" {
			t.Errorf("%s outbox delivered_at: %s", ob, got)
		}
		if got := e.adminState("SET ROLE notify_definer; UPDATE " + ob + ".notice_outbox SET kind = 'x' WHERE false"); got != "42501" {
			t.Errorf("%s outbox kind: %s", ob, got)
		}
		if got := e.adminState("SET ROLE notify_definer; DELETE FROM " + ob + ".notice_outbox WHERE false"); got != "42501" {
			t.Errorf("%s outbox delete: %s", ob, got)
		}
	}

	// Syncing a release: a changed label, a retired kind, a returning one;
	// a source cannot change; a mandatory kind cannot stay muted.
	sync := func(ks []notify.Kind) (map[string][]string, string) {
		t.Helper()
		b, _ := json.Marshal(map[string]any{"kinds": ks})
		var out []byte
		conn := e.adminConn()
		defer func() { _ = conn.Close(context.Background()) }()
		err := pgx.BeginFunc(context.Background(), conn, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), "SELECT notify.sync_kinds($1::jsonb)", string(b)).Scan(&out)
		})
		if err != nil {
			return nil, pgCode(err)
		}
		var r map[string][]string
		_ = json.Unmarshal(out, &r)
		return r, ""
	}
	if r, code := sync(notify.Kinds); code != "" || len(r["added"])+len(r["changed"])+len(r["retired"]) != 0 {
		t.Errorf("the same release again: %v %s", r, code)
	}
	e.admin(e.db, "INSERT INTO notify.preference (user_id, kind, email_muted) VALUES ('"+user+"', 'risk.stale', true)")
	next := append([]notify.Kind{}, notify.Kinds...)
	for i := range next {
		if next[i].Kind == "risk.stale" {
			next[i].Mandatory, next[i].Label = true, "Stale"
		}
	}
	next = next[1:] // estimate.assigned leaves the release
	r, code := sync(next)
	if code != "" || strings.Join(r["changed"], ",") != "risk.stale" || strings.Join(r["retired"], ",") != "estimate.assigned" || len(r["added"]) != 0 {
		t.Errorf("a later release: %v %s", r, code)
	}
	if got := e.adminQuery("SELECT count(*) FROM notify.preference"); got != "0" {
		t.Errorf("a mandatory kind left muted: %s", got)
	}
	if r, _ := sync(notify.Kinds); strings.Join(r["changed"], ",") != "estimate.assigned,risk.stale" {
		t.Errorf("the kind returns: %v", r)
	}
	moved := append([]notify.Kind{}, notify.Kinds...)
	moved[0].SourceKind = "added"
	if _, code := sync(moved); !strings.HasPrefix(code, "PF028") {
		t.Errorf("a source kind changed: %s", code)
	}
	if got := e.adminQuery("SELECT count(*) FROM notify.kind WHERE retired_at IS NULL"); got != strconv.Itoa(len(notify.Kinds)) {
		t.Errorf("live kinds: %s", got)
	}
}

// F-009 T-03 (design §2): app_notify, the notify service's role, records
// its own events, registers and reads settings, and loads grants for the
// API; it reads no notify table and nothing else of the platform.
func TestNotifyServiceRole(t *testing.T) {
	e := setup(t)
	got := e.adminQuery(`SELECT string_agg(f || ':' || has_function_privilege('app_notify', f, 'EXECUTE'), ',' ORDER BY f) FROM unnest(ARRAY[
		'audit.submit(jsonb)', 'posture.effective_settings()', 'posture.settings_version()', 'posture.register_settings(text, text, jsonb)',
		'authz.grant_snapshot()', 'notify.sync_kinds(jsonb)', 'posture.audit_finding(boolean, jsonb)']) f`)
	want := "audit.submit(jsonb):true,authz.grant_snapshot():true,notify.sync_kinds(jsonb):false,posture.audit_finding(boolean, jsonb):false," +
		"posture.effective_settings():true,posture.register_settings(text, text, jsonb):true,posture.settings_version():true"
	if got != want {
		t.Errorf("functions:\n got %s\nwant %s", got, want)
	}
	if got := e.adminQuery(`SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = 'app_notify'`); got != "0" {
		t.Errorf("app_notify holds %s table grants", got)
	}
	if got := e.adminQuery(`SELECT rolcanlogin || ':' || rolbypassrls || ':' || coalesce(array_to_string(rolconfig, ','), '') FROM pg_roles WHERE rolname = 'app_notify'`); got != "true:false:row_security=on" {
		t.Errorf("app_notify: %s", got)
	}
}
