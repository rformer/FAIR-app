package tests

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/rformer/fair-app/internal/gateway"
	"github.com/rformer/fair-app/internal/natspub"
	"github.com/rformer/fair-app/internal/scim"
	"github.com/rformer/fair-app/internal/scope"
	"github.com/rformer/fair-app/pkg/audit"
)

// F-001 T-22 (AC-10; design §5.3): a user deactivated through SCIM loses
// every session and its scope in the same transaction, so the next request
// is refused; the revocations are audited and announced.

// provisioned creates a SCIM user with access and two signed-in,
// acknowledged sessions; it returns the user's id and the cookies.
func (ie *idpEnv) provisioned(t *testing.T, tok, name string) (string, []string) {
	t.Helper()
	r := ie.scimDo(t, tok, "POST", "/Users", user(name, nil), nil)
	if r.code != 201 {
		t.Fatalf("provision %s: %d %s", name, r.code, r.raw)
	}
	id := r.body["id"].(string)
	ie.e.mustOwner(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by)
		VALUES ('user', '` + id + `', ` + roleID("Executive Viewer") + `, ` + buID("ENTERPRISE") + `, ` + uid("admin") + `)`)
	ie.e.drain()
	var cookies []string
	for range 2 {
		_, tok, err := ie.g.Sessions.Create(context.Background(), gateway.Login{UserID: id, AuthMethod: "oidc", IP: net.ParseIP(loginIP)})
		if err != nil {
			t.Fatal(err)
		}
		ie.e.mustOwner("UPDATE iam.session SET banner_ack_at = now() WHERE id_hmac = '\\x" + hmacSID(ie.g.Sessions.Pepper, tok) + "'")
		if r := ie.do(t, "GET", "/api/v1/posture/settings", tok, nil, nil); r.code != http.StatusTeapot {
			t.Fatalf("before deactivation: %d %s", r.code, r.raw)
		}
		<-ie.upstream
		cookies = append(cookies, tok)
	}
	if got := ie.e.adminQuery("SELECT count(*) FROM authz.user_scope WHERE user_id = '" + id + "'"); got != "1" {
		t.Fatal("the user has no scope to lose")
	}
	return id, cookies
}

func TestDeactivationPropagation(t *testing.T) {
	ie := idpFixture(t)
	e := ie.e
	tok := ie.scimToken(t, ie.create(t, "oidc", "Corp", "corp.example"))
	dana, sessions := ie.provisioned(t, tok, "dana@corp.example")

	// Deactivate as Entra ID does, then use the sessions at once.
	deactivate := map[string]any{"schemas": []string{scim.SchemaPatch},
		"Operations": []any{map[string]any{"op": "Replace", "path": "active", "value": "False"}}}
	start := time.Now()
	if r := ie.scimDo(t, tok, "PATCH", "/Users/"+dana, deactivate, nil); r.code != 200 {
		t.Fatalf("deactivate: %d %s", r.code, r.raw)
	}
	for _, c := range sessions {
		if r := ie.do(t, "GET", "/api/v1/posture/settings", c, nil, nil); r.code != http.StatusUnauthorized {
			t.Fatalf("a session after deactivation: %d %s", r.code, r.raw)
		}
	}
	elapsed := time.Since(start)
	t.Logf("SCIM deactivation -> sessions refused in %v (AC-10: <= 60 s)", elapsed.Round(time.Millisecond))
	if elapsed > 60*time.Second {
		t.Fatalf("took %v", elapsed)
	}
	select {
	case r := <-ie.upstream:
		t.Fatalf("a request reached the service after deactivation: %s", r.URL)
	default:
	}
	// Revoked in the same transaction (not lazily at the next lookup), the
	// scope gone, everything audited and announced.
	if got := e.adminQuery("SELECT string_agg(DISTINCT revoked_reason, ',') || ':' || count(*) FROM iam.session WHERE user_id = '" + dana + "' AND revoked_at <= (SELECT scim_updated_at FROM iam.app_user WHERE id = '" + dana + "')"); got != "user_disabled:2" {
		t.Fatalf("sessions %q", got)
	}
	if got := e.adminQuery("SELECT count(*) FROM authz.user_scope WHERE user_id = '" + dana + "'"); got != "0" {
		t.Fatal("the scope survived the deactivation")
	}
	events := e.adminQuery(`SELECT string_agg(CASE WHEN topic = 'audit' THEN payload->>'type' || ':' || (payload->>'severity') ELSE topic END, ',' ORDER BY id)
		FROM iam.event_outbox WHERE payload::text LIKE '%` + dana + `%' AND (topic <> 'audit' OR payload->>'type' LIKE 'session.revoked%')`)
	for _, want := range []string{"session.revoked:high", "iam.session.revoked", "iam.user.deactivated"} {
		if strings.Count(events, want+",")+strings.Count(events+",", want+",") == 0 {
			t.Errorf("events %q lack %s", events, want)
		}
	}
	if n := strings.Count(events, "iam.session.revoked"); n != 2 {
		t.Errorf("%d iam.session.revoked events, want 2: %s", n, events)
	}
	// Services drop their cached grants on the revoked scope event.
	if got := e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE topic = 'iam.scope.changed' AND payload->>'user_id' = '" + dana + "' AND (payload->>'revoked')::boolean"); got != "1" {
		t.Fatalf("%s revoked scope events", got)
	}
	if got := e.adminQuery("SELECT payload->>'sessions_revoked' FROM iam.event_outbox WHERE topic = 'iam.user.deactivated' AND payload->>'user_id' = '" + dana + "'"); got != "2" {
		t.Fatalf("iam.user.deactivated sessions_revoked %q", got)
	}
	// Reactivation does not bring sessions back.
	reactivate := map[string]any{"schemas": []string{scim.SchemaPatch},
		"Operations": []any{map[string]any{"op": "Replace", "path": "active", "value": true}}}
	ie.scimDo(t, tok, "PATCH", "/Users/"+dana, reactivate, nil)
	if r := ie.do(t, "GET", "/api/v1/me", sessions[0], nil, nil); r.code != http.StatusUnauthorized {
		t.Fatalf("a revoked session after reactivation: %d", r.code)
	}

	// SCIM DELETE, Bulk deactivation and any other path (a lockout here) do the same.
	erin, es := ie.provisioned(t, tok, "erin@corp.example")
	ie.scimDo(t, tok, "DELETE", "/Users/"+erin, nil, nil)
	frank, fs := ie.provisioned(t, tok, "frank@corp.example")
	ie.scimDo(t, tok, "POST", "/Bulk", map[string]any{"schemas": []string{scim.SchemaBulkReq}, "Operations": []any{
		map[string]any{"method": "PATCH", "path": "/Users/" + frank, "data": deactivate}}}, nil)
	gina, gs := ie.provisioned(t, tok, "gina@corp.example")
	e.mustOwner("UPDATE iam.app_user SET status = 'locked' WHERE id = '" + gina + "'")
	for name, c := range map[string][]string{"deleted": es, "bulk": fs, "locked": gs} {
		for _, s := range c {
			if r := ie.do(t, "GET", "/api/v1/me", s, nil, nil); r.code != http.StatusUnauthorized {
				t.Errorf("%s: a session survived: %d", name, r.code)
			}
		}
	}
	for _, u := range []string{erin, frank, gina} {
		if got := e.adminQuery("SELECT count(*) FROM iam.session WHERE user_id = '" + u + "' AND revoked_reason = 'user_disabled'"); got != "2" {
			t.Errorf("user %s: %s sessions revoked", u, got)
		}
	}
	// Changing other attributes of an inactive user revokes nothing more.
	before := e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE topic = 'iam.user.deactivated'")
	e.mustOwner("UPDATE iam.app_user SET status = 'disabled' WHERE id = '" + gina + "'")
	if after := e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE topic = 'iam.user.deactivated'"); after != before {
		t.Fatal("an inactive user was deactivated again")
	}
}

// The announcements reach JetStream, and the worker refuses to start
// without a stream for every subject it publishes.
func TestDeactivationEventsPublished(t *testing.T) {
	url := os.Getenv("FAIR_TEST_NATS")
	if url == "" {
		t.Skip("set FAIR_TEST_NATS to a JetStream-enabled NATS server")
	}
	ctx := context.Background()
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{Name: "IAM_TEST", Subjects: scope.Subjects})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := natspub.Connect(ctx, natspub.Options{Env: "development", URL: url, Name: "fair-test",
		Subjects: append([]string{"iam.nothing.captures.this"}, scope.Subjects...)}); err == nil {
		t.Fatal("a publisher started without a stream for one of its subjects")
	}
	pub, err := natspub.Connect(ctx, natspub.Options{Env: "development", URL: url, Name: "fair-test", Subjects: scope.Subjects})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pub.Close)

	ie := idpFixture(t)
	tok := ie.scimToken(t, ie.create(t, "oidc", "Corp", "corp.example"))
	dana, _ := ie.provisioned(t, tok, "dana@corp.example")
	ie.scimDo(t, tok, "PATCH", "/Users/"+dana, map[string]any{"schemas": []string{scim.SchemaPatch},
		"Operations": []any{map[string]any{"op": "replace", "path": "active", "value": false}}}, nil)
	// Read from the stream's next message on: an ordered consumer exists on
	// the server only from its first fetch, after delivery here.
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cons, err := stream.OrderedConsumer(ctx, jetstream.OrderedConsumerConfig{DeliverPolicy: jetstream.DeliverByStartSequencePolicy,
		OptStartSeq: info.State.LastSeq + 1, FilterSubjects: []string{"iam.session.revoked", "iam.user.deactivated"}})
	if err != nil {
		t.Fatal(err)
	}
	w := scope.New(scope.Options{Pool: ie.e.appPool(), Publisher: pub, Audit: audit.NewMemory()})
	start := time.Now()
	if err := w.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for got["iam.session.revoked"] < 2 || got["iam.user.deactivated"] < 1 {
		msg, err := cons.Next(jetstream.FetchMaxWait(15 * time.Second))
		if err != nil {
			t.Fatalf("announcements so far %v: %v", got, err)
		}
		var ev map[string]any
		_ = json.Unmarshal(msg.Data(), &ev)
		if ev["user_id"] == dana {
			got[msg.Subject()]++
		}
	}
	t.Logf("deactivation announced on JetStream in %v", time.Since(start).Round(time.Millisecond))
	if n := ie.e.adminQuery("SELECT count(*) FROM iam.event_outbox WHERE published_at IS NULL"); n != "0" {
		t.Fatalf("%s events left undelivered", n)
	}
}
