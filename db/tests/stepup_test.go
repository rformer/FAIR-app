package tests

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/rformer/fair-app/pkg/authz"
	"github.com/rformer/fair-app/pkg/settings"
)

// F-015 T-24 (AC-33, design §6.6): authz.Check asks for step-up when the
// sign-in is older than the BU's effective bu.reauth_max_age: 15 minutes
// under the Restricted BU overlay, the session absolute timeout elsewhere,
// and any stricter per-BU override. The session's auth_time and the IdP
// re-authentication arrive with T-24b; here the principal carries AuthTime.
func TestStepUpOnRestrictedBU(t *testing.T) {
	ctx := context.Background()
	o := overlayFixture(t, "self-hosted") // Enterprise Baseline: bu.reauth_max_age 12h
	e := o.e
	e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('analyst@example.test', 'Analyst')")
	e.mustOwner(grant("admin", "user:analyst", "Executive Viewer", "ENTERPRISE"))
	e.mustOwner(grant("admin", "user:analyst", "Executive Viewer", "R")) // inheritance stops at the restricted BU
	e.drain()
	if err := o.client.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	c := authz.NewCache(authz.CacheOptions{Loader: authz.DBLoader(e.appPool()), ReauthMaxAge: o.client.ReauthMaxAge})
	signedIn := func(ago time.Duration) authz.Principal {
		p := e.principal("analyst")
		p.AuthTime = time.Now().Add(-ago)
		return p
	}
	check := func(name string, p authz.Principal, bu string, want time.Duration) {
		t.Helper()
		err := c.Check(ctx, p, "register.view", bu)
		var su *authz.StepUpError
		switch {
		case want == 0 && err != nil:
			t.Errorf("%s: %v, want access", name, err)
		case want != 0 && (!errors.As(err, &su) || su.MaxAge != want):
			t.Errorf("%s: %v, want step-up within %v", name, err, want)
		}
	}

	check("fresh sign-in, restricted BU", signedIn(5*time.Minute), o.r, 0)
	check("20-minute-old sign-in, restricted BU", signedIn(20*time.Minute), o.r, 15*time.Minute)
	check("20-minute-old sign-in, below the restricted BU", signedIn(20*time.Minute), o.r1, 15*time.Minute)
	check("20-minute-old sign-in, unrestricted BU", signedIn(20*time.Minute), o.free, 0)
	check("sign-in older than the session lifetime", signedIn(13*time.Hour), o.free, 12*time.Hour)

	// A stricter per-BU override applies too (AC-35).
	res, err := o.set.Set(ctx, e.principal("admin"), settings.Request{Key: settings.KeyBUReauthMaxAge, BUID: o.free, Value: json.RawMessage(`"1h0m0s"`)})
	if err != nil || res.Outcome != settings.Applied {
		t.Fatalf("override: %+v %v", res, err)
	}
	if err := o.client.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	check("2-hour-old sign-in, BU override 1h", signedIn(2*time.Hour), o.free, time.Hour)

	// Unrestricting the BU removes the overlay's requirement.
	e.mustOwner("UPDATE iam.bu SET restricted = false WHERE code = 'R'")
	e.drain()
	if err := o.client.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	check("20-minute-old sign-in, after unrestrict", signedIn(20*time.Minute), o.r1, 0)
}
