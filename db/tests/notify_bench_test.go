package tests

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/notify"
	"github.com/rformer/fair-app/internal/notifyapi"
	"github.com/rformer/fair-app/internal/server"
	"github.com/rformer/fair-app/pkg/authz"
)

// F-009 T-14 (requirements NFR "Performance"; design §3, §5): at the F-001
// target scale (2,011 BUs, 10,000 users), an hour's notices (10,000, risk.stale
// from the register's outbox, to 1,000 risk owners) queued at once reach
// their recipients' in-app lists within 1 minute and are handed to email and
// a webhook within 2 minutes, with the service's own loops: the leader's
// collection cycle (notify.Cycle, every notify.Every) and two replicas'
// delivery workers (deploy/k8s/notify.yaml), the senders being fakes that
// accept at once. The notification list (and the header's count) of a user
// with 20,000 notifications opens in <= 1 s p95 through the notify API.

const (
	notifyBenchNotices    = 10_000
	notifyBenchOwners     = 1_000
	notifyBenchRisks      = 1_000
	notifyBenchHistory    = 20_000
	notifyBenchRuns       = 20
	notifyBenchAppBudget  = time.Minute
	notifyBenchSentBudget = 2 * time.Minute
	notifyBenchListBudget = time.Second
)

func TestBenchmarkGateNotifications(t *testing.T) {
	if os.Getenv("FAIR_BENCH") != "1" {
		t.Skip("set FAIR_BENCH=1 to run the benchmark gate")
	}
	e := benchSetup(t)
	ctx := context.Background()
	notices := notifyBenchNotices
	if n := os.Getenv("FAIR_BENCH_NOTICES"); n != "" { // a smaller run, by hand
		notices, _ = strconv.Atoi(n)
	}
	start := time.Now()
	seedRegisterBench(t, e, notifyBenchRisks)
	root := e.mustOwner("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	granter := e.mustOwner("SELECT a.principal_id FROM iam.assignment a JOIN iam.role r ON r.id = a.role_id WHERE r.name = 'Platform Admin' LIMIT 1")
	// The recipients: 1,000 of the scale's users own risks (at the root).
	e.mustOwner(fmt.Sprintf(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by)
		SELECT 'user', u.id, (SELECT id FROM iam.role WHERE name = 'Risk Owner'), '%s', '%s' FROM iam.app_user u
		WHERE u.email ~ '^u[0-9]+@scale\.test$' AND substring(u.email from 2 for position('@' in u.email) - 2)::int <= %d
		ON CONFLICT DO NOTHING`, root, granter, notifyBenchOwners))
	e.mustOwner("SELECT count(*) FROM authz.reconcile_scopes()")
	e.mustOwner("DELETE FROM iam.outbox")
	t.Logf("register and owners: %v", time.Since(start).Round(time.Second))

	pool := notifyPool(t, e)
	keys, err := notify.NewKeyring(map[string][]byte{"whk-1": []byte("bench-webhook-secrets-key-32-by!")})
	if err != nil {
		t.Fatal(err)
	}
	cycle := notify.Cycle{Collector: notify.Collector{DB: pool}, FanOut: notify.FanOut{DB: pool}}
	queue := func(users string, n int) {
		t.Helper()
		e.adminQuery(fmt.Sprintf(`WITH u AS (SELECT id, row_number() OVER (ORDER BY email) - 1 AS i FROM iam.app_user WHERE %s),
			r AS (SELECT id, row_number() OVER (ORDER BY id) - 1 AS i FROM register.risk WHERE state = 'open' AND owner IS NOT NULL),
			nu AS (SELECT count(*) AS n FROM u), nr AS (SELECT count(*) AS n FROM r)
			INSERT INTO register.notice_outbox (kind, user_id, risk_id)
			SELECT 'risk.stale', u.id, r.id FROM generate_series(0, %d - 1) g, nu, nr
			JOIN u ON true JOIN r ON true WHERE u.i = g %% nu.n AND r.i = g %% nr.n`, users, n))
	}

	// The history: 20,000 notifications for one user (optional kinds in a
	// digest, so nothing waits to be sent), fanned out before the channels exist.
	owner := e.mustOwner("SELECT id FROM iam.app_user WHERE email = 'benchowner@example.test'")
	e.mustOwner("INSERT INTO notify.user_option (user_id, digest) VALUES ('" + owner + "', true)")
	start = time.Now()
	queue("email = 'benchowner@example.test'", notifyBenchHistory)
	for {
		n, err := cycle.Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
	}
	e.mustOwner("UPDATE notify.inbox SET read_at = now() WHERE user_id = '" + owner + "' AND id % 2 = 0")
	t.Logf("history: %s notifications in %v", e.adminQuery("SELECT count(*) FROM notify.inbox WHERE user_id = '"+owner+"'"), time.Since(start).Round(time.Second))

	// The channels: the relay, and a webhook taking risk.stale for the whole tree.
	e.mustOwner(`INSERT INTO notify.channel (kind, name, config) VALUES ('smtp', 'SMTP relay',
		'{"host":"203.0.113.10","port":465,"tls_mode":"implicit","from":"FAIR <fair@example.com>"}')`)
	e.mustOwner(fmt.Sprintf(`INSERT INTO notify.channel (kind, name, config, bu_id, kinds, secret_ct)
		VALUES ('webhook', 'Tickets', '{"url":"https://203.0.113.10/fair"}', '%s', '{risk.stale}', decode('%s', 'hex'))`,
		root, hex.EncodeToString(keys.Seal("whsec_"+strings.Repeat("A", 43)))))

	// The service's loops: the leader's cycle, two replicas delivering.
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	sends := &fakeSends{}
	worker := notify.Worker{DB: pool, Composer: func() notify.Composer { return notify.Composer{Base: "https://fair.example.com"} },
		Mail: fakeMailer{sends}, Post: &fakePoster{fakeSends: sends}, Keys: keys, RetryHours: func() int { return 24 }}
	for range 2 {
		go worker.RunDelivery(runCtx, 5*time.Second, func(err error) { t.Logf("delivery: %v", err) })
	}
	go func() {
		for runCtx.Err() == nil {
			if _, err := cycle.Run(runCtx); err != nil && runCtx.Err() == nil {
				t.Logf("cycle: %v", err)
			}
			select {
			case <-runCtx.Done():
			case <-time.After(notify.Every):
			}
		}
	}()

	// An hour's notices, at once.
	users := fmt.Sprintf(`email ~ '^u[0-9]+@scale\.test$' AND substring(email from 2 for position('@' in email) - 2)::int <= %d`, notifyBenchOwners)
	burst := e.mustOwner("SELECT coalesce(max(id), 0) FROM register.notice_outbox")
	t0 := time.Now()
	queue(users, notices)
	var inApp, handed time.Duration
	want := strconv.Itoa(notices)
	wantDeliveries := strconv.Itoa(2 * notices) // an email and a webhook post each
	scope := "n.source = 'register' AND n.source_id::bigint > " + burst
	for time.Since(t0) < 5*time.Minute && (inApp == 0 || handed == 0) {
		time.Sleep(time.Second)
		if inApp == 0 && e.adminQuery("SELECT count(*) FROM notify.inbox i JOIN notify.notice n ON n.id = i.notice_id WHERE "+scope) == want {
			inApp = time.Since(t0)
		}
		if handed == 0 && e.adminQuery("SELECT count(*) FROM notify.delivery d JOIN notify.notice n ON n.id = d.notice_id WHERE d.state = 'sent' AND "+scope) == wantDeliveries {
			handed = time.Since(t0)
		}
	}
	stop()
	if inApp == 0 || handed == 0 {
		t.Fatalf("after 5 minutes: %s in the app, %s deliveries sent (want %s and %s); %s",
			e.adminQuery("SELECT count(*) FROM notify.inbox i JOIN notify.notice n ON n.id = i.notice_id WHERE "+scope),
			e.adminQuery("SELECT count(*) FROM notify.delivery d JOIN notify.notice n ON n.id = d.notice_id WHERE d.state = 'sent' AND "+scope), want, wantDeliveries,
			e.adminQuery("SELECT string_agg(state || ':' || coalesce(reason, '-') || '=' || c, ', ') FROM (SELECT d.state, d.reason, count(*) c FROM notify.delivery d JOIN notify.notice n ON n.id = d.notice_id WHERE "+scope+" GROUP BY 1, 2) x"))
	}
	// Each notice's own latency, from the database's clocks.
	latest := e.adminQuery(`SELECT round(extract(epoch FROM max(i.created_at - n.queued_at)) * 1000)::text || ' ms in the app, '
		|| round(extract(epoch FROM max(d.sent_at - n.queued_at)) * 1000)::text || ' ms handed over'
		FROM notify.notice n JOIN notify.inbox i ON i.notice_id = n.id JOIN notify.delivery d ON d.notice_id = n.id WHERE ` + scope)

	// The list, as the user with the history sees it.
	jwtKeys := newBenchEstimateAPI(t, e).keys // a fresh local signing key
	srv := httptest.NewServer((&notifyapi.API{DB: pool}).Handler(jwtKeys, nil))
	t.Cleanup(srv.Close)
	get := func(path string) (time.Duration, int, string) {
		t.Helper()
		p := e.principal("benchowner")
		tok, err := authz.MintJWT(jwtKeys, authz.Claims{Subject: p.UserID, ScopeVersion: p.ScopeVersion, AuthTime: time.Now().Unix(),
			DBContext: authz.DBContextHash(p.DBToken)}, "notify", 5*time.Minute, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set(server.DBContextHeader, p.DBToken)
		t1 := time.Now()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return time.Since(t1), resp.StatusCode, string(out)
	}
	middle := e.adminQuery("SELECT id FROM notify.inbox WHERE user_id = '" + owner + "' ORDER BY id OFFSET 10000 LIMIT 1")
	cases := []struct{ name, path, check string }{
		{"the list, newest 50", "/api/v1/notifications", `"notifications"`},
		{"the list, unread", "/api/v1/notifications?unread=true", `"notifications"`},
		{"the list, older than the 10,000th", "/api/v1/notifications?before=" + middle, `"notifications"`},
		{"the header's count", "/api/v1/notifications/count", `"unread"`},
	}
	var results []benchResult
	failed := inApp > notifyBenchAppBudget || handed > notifyBenchSentBudget
	for _, c := range cases {
		ds := make([]time.Duration, 0, notifyBenchRuns)
		for i := range notifyBenchRuns + 3 {
			d, code, body := get(c.path)
			if code != http.StatusOK || !strings.Contains(body, c.check) {
				t.Fatalf("%s: %d %s", c.name, code, body[:min(len(body), 300)])
			}
			if i >= 3 {
				ds = append(ds, d)
			}
		}
		r := summarize("notify API: "+c.name, ds, notifyBenchListBudget)
		results = append(results, r)
		failed = failed || r.P95ms > r.Budget
	}

	var rep strings.Builder
	fmt.Fprintf(&rep, "F-009 notifications: %d notices queued at once to %d owners (an email and a webhook post each); the list of a user with %d notifications; %d runs after warm-up\n",
		notices, notifyBenchOwners, notifyBenchHistory, notifyBenchRuns)
	fmt.Fprintf(&rep, "- every notice in the app after %v (budget %v); every delivery handed over after %v (budget %v); latest per notice: %s\n",
		inApp.Round(time.Second), notifyBenchAppBudget, handed.Round(time.Second), notifyBenchSentBudget, latest)
	fmt.Fprintln(&rep, "| Measurement | p50 ms | p95 ms | Budget ms |")
	fmt.Fprintln(&rep, "|---|---:|---:|---:|")
	for _, r := range results {
		fmt.Fprintf(&rep, "| %s | %.2f | %.2f | %.0f |\n", r.Name, r.P50ms, r.P95ms, r.Budget)
	}
	t.Log("\n" + rep.String())
	if failed {
		t.Fatal("notifications over budget")
	}
}
