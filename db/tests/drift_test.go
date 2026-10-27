package tests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/approvals"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-25 (AC-36, AC-37; design §6.7): the application drift engine.

type driftEnv struct {
	registryEnv
	d   posture.Drift
	mem *audit.Memory
}

func driftFixture(t *testing.T) driftEnv {
	rg := registryFixture(t, settings.ProfileFedRAMPModerate, "self-hosted")
	mem := audit.NewMemory()
	return driftEnv{registryEnv: rg, d: posture.Drift{DB: rg.e.posturePool(), Audit: mem}, mem: mem}
}

func (de driftEnv) scan(t *testing.T) posture.ScanResult {
	t.Helper()
	res, err := de.d.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// ids lists findings as "check_id subject", sorted.
func ids(fs []posture.Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.CheckID+" "+f.Subject)
	}
	slices.Sort(out)
	return out
}

func (de driftEnv) open(t *testing.T) []string {
	t.Helper()
	fs, err := posture.OpenFindings(context.Background(), de.e.posturePool())
	if err != nil {
		t.Fatal(err)
	}
	return ids(fs)
}

func wantIDs(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	slices.Sort(want)
	if want == nil {
		want = []string{}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%s:\n got %v\nwant %v", what, got, want)
	}
}

// Verification for T-25: a direct database edit is detected (row MAC and,
// as here, an unapproved weakening), audited high/critical, kept open while
// it lasts, and resolved once the value is set properly again.
func TestDriftDetectsDirectDBEdit(t *testing.T) {
	ctx := context.Background()
	de := driftFixture(t)
	e := de.e
	wantIDs(t, "clean install", ids(de.scan(t).Findings))

	v0 := e.adminQuery("SELECT version FROM posture.state")
	e.admin(e.db, `UPDATE posture.setting_value SET value = '"1h0m0s"' WHERE key = 'session.idle_timeout' AND bu_id IS NULL`)
	if v1 := e.adminQuery("SELECT version FROM posture.state"); v1 == v0 {
		t.Fatal("a direct edit must move the posture version (it wakes the drift loop)")
	}
	res := de.scan(t)
	wantIDs(t, "opened", ids(res.Opened), "row_mac_mismatch setting:session.idle_timeout", "unapproved_deviation setting:session.idle_timeout")
	ev := de.mem.OfType("posture.drift_detected")
	var sev []string
	for _, x := range ev {
		sev = append(sev, x.Attributes["check_id"]+":"+string(x.Severity))
	}
	slices.Sort(sev)
	if !slices.Equal(sev, []string{"row_mac_mismatch:critical", "unapproved_deviation:high"}) || ev[0].Actor != posture.DriftActor {
		t.Fatalf("drift audit %v", sev)
	}

	// Still there: refreshed, not reopened or re-audited.
	if res := de.scan(t); len(res.Opened) != 0 || len(res.Resolved) != 0 {
		t.Fatalf("second scan changed findings: %+v", res)
	}
	wantIDs(t, "open", de.open(t), "row_mac_mismatch setting:session.idle_timeout", "unapproved_deviation setting:session.idle_timeout")

	// A hard-floor violation is critical, exception or not.
	e.admin(e.db, `UPDATE posture.setting_value SET value = '"1.0"' WHERE key = 'tls.min_version' AND bu_id IS NULL`)
	wantIDs(t, "floor", ids(de.scan(t).Opened), "hard_floor_violation setting:tls.min_version", "row_mac_mismatch setting:tls.min_version")

	// Setting the values properly again resolves everything.
	for k, v := range map[string]string{settings.KeySessionIdleTimeout: `"10m0s"`, settings.KeyTLSMinVersion: `"1.3"`} {
		if res, err := de.set.Set(ctx, e.principal("admin"), settings.Request{Key: k, Value: json.RawMessage(v)}); err != nil || res.Outcome != settings.Applied {
			t.Fatalf("fix %s: %+v %v", k, res, err)
		}
	}
	res = de.scan(t)
	if len(res.Resolved) != 4 || len(de.mem.OfType("posture.drift_resolved")) != 4 {
		t.Fatalf("resolved %v", ids(res.Resolved))
	}
	wantIDs(t, "open after fix", de.open(t))
}

// Approved exceptions are not drift; an expired one that was not reverted
// is (missed_revert), until the revert runs.
func TestDriftExceptionsAndMissedRevert(t *testing.T) {
	ctx := context.Background()
	de := driftFixture(t)
	e := de.e
	res, err := de.set.Set(ctx, e.principal("admin"), settings.Request{Key: settings.KeySessionIdleTimeout, Value: json.RawMessage(`"30m0s"`), Explanation: "call centre"})
	if err != nil || res.Outcome != settings.PendingApproval {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := (approvals.Service{DB: e.appPool()}).Decide(ctx, e.principal("admin2"), res.ApprovalID, true, ""); err != nil {
		t.Fatal(err)
	}
	x, err := de.set.ApplyApproved(ctx, res.ChangeID)
	if err != nil {
		t.Fatal(err)
	}
	wantIDs(t, "approved exception", ids(de.scan(t).Findings))

	// Expired 1 s ago: within the revert loop's grace.
	expire(e, x.ID)
	wantIDs(t, "just expired", ids(de.scan(t).Findings))
	e.admin(e.db, "UPDATE posture.exception SET expires_at = now() - interval '2 minutes' WHERE id = '"+x.ID+"'")
	wantIDs(t, "missed revert", ids(de.scan(t).Opened), "missed_revert exception:"+x.ID)

	if out, err := posture.RevertDue(ctx, e.posturePool(), audit.NewMemory(), nil); err != nil || len(out) != 1 || out[0].Err != nil {
		t.Fatalf("revert %+v %v", out, err)
	}
	wantIDs(t, "resolved by the revert", ids(de.scan(t).Resolved), "missed_revert exception:"+x.ID)
	wantIDs(t, "open", de.open(t))
}

// The Restricted BU overlay is checked against its default.
func TestDriftOverlay(t *testing.T) {
	ctx := context.Background()
	de := driftFixture(t)
	e := de.e
	ov := posture.Overlay{DB: e.posturePool(), Audit: audit.NewMemory()}
	if res, err := ov.Change(ctx, e.principal("admin"), settings.KeySessionNetworkBinding, json.RawMessage(`"reauthenticate"`), "", 0); err != nil || res.Outcome != posture.Applied {
		t.Fatalf("%+v %v", res, err)
	}
	wantIDs(t, "overlay row", ids(de.scan(t).Findings))
	e.admin(e.db, `UPDATE posture.overlay_value SET value = '"off"'`)
	wantIDs(t, "tampered overlay", ids(de.scan(t).Opened),
		"row_mac_mismatch overlay:session.network_binding", "unapproved_deviation overlay:session.network_binding")
}

// Check 4: service heartbeats must report the snapshot in force.
func TestDriftHeartbeats(t *testing.T) {
	ctx := context.Background()
	de := driftFixture(t)
	e := de.e
	pool := e.posturePool()
	beat := func(h settings.Heartbeat) {
		t.Helper()
		b, _ := json.Marshal(h)
		if err := posture.RecordHeartbeat(ctx, pool, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := de.client.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	good := de.client.Heartbeat()
	good.Instance = "iam-0"
	beat(good)
	wantIDs(t, "matching heartbeat", ids(de.scan(t).Findings))

	rogue := de.client.Heartbeat()
	rogue.Instance = "iam-1"
	rogue.Values[settings.KeySessionIdleTimeout] = json.RawMessage(`"1h0m0s"`)
	rogue.Digest = fmt.Sprintf("%064x", 1)
	beat(rogue)
	res := de.scan(t)
	wantIDs(t, "rogue", ids(res.Opened), "settings_mismatch service:iam/iam-1")
	var detail struct {
		Keys []string `json:"differing_keys"`
	}
	_ = json.Unmarshal(res.Opened[0].Detail, &detail)
	if !slices.Equal(detail.Keys, []string{settings.KeySessionIdleTimeout}) || res.Opened[0].Severity != "critical" {
		t.Fatalf("mismatch finding %s %s", res.Opened[0].Severity, res.Opened[0].Detail)
	}

	// A change moves the version: services still on the old one are stale
	// once the refresh window has passed (shortened here).
	if r, err := de.set.Set(ctx, e.principal("admin"), settings.Request{Key: settings.KeySessionIdleTimeout, Value: json.RawMessage(`"10m0s"`)}); err != nil || r.Outcome != settings.Applied {
		t.Fatalf("%+v %v", r, err)
	}
	beat(good) // still the old version
	de.d.StaleAfter = time.Nanosecond
	res = de.scan(t)
	wantIDs(t, "stale", ids(res.Findings), "stale_settings_cache service:iam/iam-0", "stale_settings_cache service:iam/iam-1")
	wantIDs(t, "mismatch gone (now stale instead)", ids(res.Resolved), "settings_mismatch service:iam/iam-1")

	// Refreshed services report the new snapshot; a silent instance drops out.
	if err := de.client.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	fresh := de.client.Heartbeat()
	fresh.Instance = "iam-0"
	beat(fresh)
	e.admin(e.db, "UPDATE posture.service_heartbeat SET received_at = now() - interval '4 minutes' WHERE instance = 'iam-1'")
	wantIDs(t, "recovered", ids(de.scan(t).Findings))

	// Heartbeats are untrusted input.
	for _, bad := range []string{`not json`, `{"service": "iam"}`, `{"service": "iam x", "instance": "a", "version": 1, "digest": "` + fmt.Sprintf("%064x", 2) + `", "bu_overrides": 0}`,
		`{"service": "iam", "instance": "a", "version": 1, "digest": "short", "bu_overrides": 0}`} {
		if err := posture.RecordHeartbeat(ctx, pool, []byte(bad)); !errors.Is(err, posture.ErrInvalidValue) {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

// The loop notices a direct edit through the version poll, without an event.
func TestRunDriftDetectsDirectEdit(t *testing.T) {
	de := driftFixture(t)
	e := de.e
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 10)
	go posture.RunDrift(ctx, de.d, 200*time.Millisecond, nil, func(err error) { errs <- err })
	time.Sleep(time.Second) // the first scan
	start := time.Now()
	e.admin(e.db, `UPDATE posture.setting_value SET value = '"20m0s"' WHERE key = 'session.idle_timeout' AND bu_id IS NULL`)
	for time.Since(start) < 10*time.Second {
		if slices.Contains(de.open(t), "row_mac_mismatch setting:session.idle_timeout") {
			t.Logf("direct edit detected in %v", time.Since(start).Round(time.Millisecond))
			return
		}
		select {
		case err := <-errs:
			t.Fatal(err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("direct edit not detected within 10 s")
}

// Only the posture service runs scans and records heartbeats and findings.
func TestDriftAccess(t *testing.T) {
	de := driftFixture(t)
	e := de.e
	for _, sql := range []string{"PERFORM * FROM posture.drift_scan()", "PERFORM posture.record_heartbeat('{}')",
		"PERFORM * FROM posture.sync_drift_findings(ARRAY['row_mac_mismatch'], '[]')", "PERFORM * FROM posture.drift_findings()",
		"PERFORM * FROM posture.acknowledge_drift(gen_random_uuid(), 'x')"} {
		e.wantState("app_rw", sql, "42501")
	}
	e.wantState("app_posture", "PERFORM * FROM posture.sync_drift_findings(ARRAY['revert_failed'], '[]')", "PF004")
	e.mustFail("app_posture", "UPDATE posture.drift_finding SET status = 'resolved'", "permission denied")
	e.mustFail("app_posture", "SELECT * FROM posture.service_heartbeat", "permission denied")
}

// Verification for T-25: a scan completes in ≤ 30 s at target scale (F-001:
// 2,000 BUs), here with two BU-scopable overrides on every BU and 100
// reporting service instances.
func TestDriftScanAtScale(t *testing.T) {
	if os.Getenv("FAIR_TEST_SCALE") != "1" {
		t.Skip("set FAIR_TEST_SCALE=1 to run the T-25 scale test")
	}
	ctx := context.Background()
	de := driftFixture(t)
	e := de.e
	e.mustOwner(`DO $$
DECLARE r uuid; a uuid; b uuid; i int; j int; k int;
BEGIN
  SELECT id INTO r FROM iam.bu WHERE parent_id IS NULL;
  FOR i IN 1..10 LOOP
    INSERT INTO iam.bu (name, code, parent_id, restricted) VALUES ('a', 'L1_' || i, r, false) RETURNING id INTO a;
    FOR j IN 1..10 LOOP
      INSERT INTO iam.bu (name, code, parent_id, restricted) VALUES ('b', 'L2_' || i || '_' || j, a, false) RETURNING id INTO b;
      FOR k IN 1..19 LOOP
        INSERT INTO iam.bu (name, code, parent_id, restricted) VALUES ('c', 'L3_' || i || '_' || j || '_' || k, b, (i * j * k) % 20 = 0);
      END LOOP;
    END LOOP;
  END LOOP;
END $$`)
	// Bulk-load overrides with valid MACs (the evaluator path is not what
	// this measures).
	e.admin(e.db, `SELECT posture.write_value(k, b.id, v, 'profile', NULL, NULL)
		FROM iam.bu b CROSS JOIN (VALUES ('session.network_binding', '"reauthenticate"'::jsonb), ('bu.reauth_max_age', '"1h0m0s"'::jsonb)) x(k, v)
		WHERE b.parent_id IS NOT NULL`)
	if err := de.client.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	pool := e.posturePool()
	for i := range 100 {
		h := de.client.Heartbeat()
		h.Instance = fmt.Sprintf("svc-%d", i)
		b, _ := json.Marshal(h)
		if err := posture.RecordHeartbeat(ctx, pool, b); err != nil {
			t.Fatal(err)
		}
	}
	counts := e.adminQuery("SELECT (SELECT count(*) FROM iam.bu) || ' BUs, ' || (SELECT count(*) FROM posture.setting_value) || ' setting values'")
	start := time.Now()
	res := de.scan(t)
	took := time.Since(start)
	t.Logf("%s: drift scan in %v (%d findings)", counts, took.Round(time.Millisecond), len(res.Findings))
	if len(res.Findings) != 0 {
		t.Fatalf("findings at scale: %v", ids(res.Findings)[:min(5, len(res.Findings))])
	}
	if took > 30*time.Second {
		t.Fatalf("drift scan took %v, requirement 30 s", took)
	}
}
