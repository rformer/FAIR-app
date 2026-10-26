package tests

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/rformer/fair-app/internal/natspub"
	"github.com/rformer/fair-app/internal/posture"
	"github.com/rformer/fair-app/pkg/audit"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-11 (AC-01, NFR 60 s): the settings library against the database.

// seededPosture loads the release (migrate), adds a MAC key, seeds FedRAMP
// Moderate and registers session.idle_timeout so it can be changed.
func seededPosture(e *env) {
	e.t.Helper()
	addMACKey(e, "k1")
	if _, err := posture.Seed(context.Background(), e.posturePool(), audit.NewMemory(), "system:installer", posture.DefaultProfile, ""); err != nil {
		e.t.Fatal(err)
	}
	// Registration is T-12; insert the definition as it will.
	e.admin(e.db, `INSERT INTO posture.setting_def (key, type, direction, owner_feature, registered_version)
		VALUES ('session.idle_timeout', 'duration', 'lower_is_stricter', 'F-001', '1')`)
}

// change requests and applies a change as the posture service does.
func change(e *env, key, value string) {
	e.t.Helper()
	user := e.adminQuery("INSERT INTO iam.app_user (email) VALUES ('" + randHex(4) + "@example.test') RETURNING id")
	id := mustAs(e, "app_posture", "SELECT "+request(key, "NULL", value, "NULL", user, "NULL"))
	e.wantState("app_posture", "PERFORM posture.apply_change('"+id+"')", "ok")
}

func TestPostureEffectiveSettings(t *testing.T) {
	e := setup(t)
	pool := e.appPool()
	ctx := context.Background()
	src := settings.DBSource{DB: pool}

	// Before the seed: no profile, nothing in force.
	snap, err := src.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Profile != "" || len(snap.Instance) != 0 {
		t.Fatalf("unseeded snapshot %+v", snap)
	}
	seededPosture(e)
	if snap, err = src.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if snap.Profile != "fedramp-moderate" || snap.ProfileVersion != "1.0.0" || len(snap.Instance) != 19 ||
		string(snap.Instance["session.idle_timeout"]) != `"15m0s"` {
		t.Fatalf("seeded snapshot: profile %s %s, %d values, idle %s", snap.Profile, snap.ProfileVersion, len(snap.Instance), snap.Instance["session.idle_timeout"])
	}

	// Every write moves the version, including an out-of-band edit.
	v0, _ := src.Version(ctx)
	change(e, "session.idle_timeout", `"10m0s"`)
	v1, _ := src.Version(ctx)
	e.admin(e.db, `UPDATE posture.setting_value SET value = '"1h0m0s"' WHERE key = 'session.idle_timeout'`)
	v2, _ := src.Version(ctx)
	if v0 >= v1 || v1 >= v2 {
		t.Fatalf("versions %d, %d, %d must increase", v0, v1, v2)
	}
	if snap, _ = src.Snapshot(ctx); snap.Version != v2 {
		t.Fatalf("snapshot version %d, current %d", snap.Version, v2)
	}

	// BU overrides arrive under their BU.
	root := e.adminQuery("SELECT id FROM iam.bu WHERE parent_id IS NULL")
	e.admin(e.db, `INSERT INTO posture.setting_def (key, type, direction, enum_order, bu_scopable, owner_feature, registered_version)
		VALUES ('session.network_binding', 'enum', 'ordered', ARRAY['off','flag','reauthenticate'], true, 'F-001', '1')`)
	user := e.adminQuery("SELECT id FROM iam.app_user LIMIT 1")
	id := mustAs(e, "app_posture", "SELECT "+request("session.network_binding", "'"+root+"'", `"reauthenticate"`, "NULL", user, "NULL"))
	e.wantState("app_posture", "PERFORM posture.apply_change('"+id+"')", "ok")
	if snap, _ = src.Snapshot(ctx); string(snap.BU[root]["session.network_binding"]) != `"reauthenticate"` {
		t.Fatalf("BU overrides %v", snap.BU)
	}

	// Still no table access for services, only the read functions.
	e.mustFail("app_rw", "SELECT * FROM posture.state", "permission denied")
	e.mustFail("app_rw", "UPDATE posture.state SET version = 0", "permission denied")
}

// Verification for T-11: a change reaches three services at once when it is
// announced, and within 60 s through the TTL poll when the event is lost.
func TestPosturePropagationAcrossServices(t *testing.T) {
	url := os.Getenv("FAIR_TEST_NATS")
	if url == "" {
		t.Skip("set FAIR_TEST_NATS to a JetStream-enabled NATS server to run propagation tests")
	}
	e := setup(t)
	seededPosture(e)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The installer provisions the stream in production.
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{Name: "POSTURE_TEST", Subjects: []string{settings.SubjectChanged}}); err != nil {
		t.Fatal(err)
	}
	pub, err := natspub.Connect(ctx, natspub.Options{Env: "development", URL: url, Name: "fair-posture-test", Subjects: []string{settings.SubjectChanged}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pub.Close)

	// Three services, each with its own pool, NATS connection and default
	// (30 s) TTL.
	var clients []*settings.Client
	for i, svc := range []string{"iam", "risk", "posture"} {
		c := settings.NewClient(settings.ClientOptions{Source: settings.DBSource{DB: e.appPool()}, Service: svc, Instance: fmt.Sprint(svc, "-", i)})
		if err := c.Register(settings.F001Defs()...); err != nil {
			t.Fatal(err)
		}
		if err := c.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		snc, err := nats.Connect(url)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(snc.Close)
		if _, err := c.SubscribeNATS(snc); err != nil {
			t.Fatal(err)
		}
		if err := snc.Flush(); err != nil {
			t.Fatal(err)
		}
		go c.Run(ctx, func(err error) { t.Errorf("%s: %v", svc, err) })
		clients = append(clients, c)
	}
	waitAll := func(want time.Duration, within time.Duration) time.Duration {
		t.Helper()
		start := time.Now()
		for _, c := range clients {
			for {
				if d, err := c.Duration(settings.KeySessionIdleTimeout, ""); err == nil && d == want {
					break
				}
				if time.Since(start) > within {
					d, err := c.Duration(settings.KeySessionIdleTimeout, "")
					t.Fatalf("%s still has %v (%v) after %v, want %v", c.Heartbeat().Service, d, err, within, want)
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
		return time.Since(start)
	}
	waitAll(15*time.Minute, time.Second)

	// Announced: the posture service publishes after commit.
	change(e, "session.idle_timeout", `"10m0s"`)
	if err := posture.PublishChanged(ctx, e.posturePool(), pub, settings.KeySessionIdleTimeout, ""); err != nil {
		t.Fatal(err)
	}
	took := waitAll(10*time.Minute, 5*time.Second)
	t.Logf("announced change reached 3 services in %v", took)

	// Lost event: nothing is published; the TTL poll must find it.
	change(e, "session.idle_timeout", `"5m0s"`)
	took = waitAll(5*time.Minute, 60*time.Second)
	t.Logf("unannounced change reached 3 services in %v (SLA 60 s)", took)

	for _, c := range clients {
		if h := c.Heartbeat(); h.Version != clients[0].Version() || h.Digest != clients[0].Heartbeat().Digest {
			t.Errorf("%s heartbeat %d/%s disagrees with %d/%s", h.Service, h.Version, h.Digest, clients[0].Version(), clients[0].Heartbeat().Digest)
		}
	}
}
