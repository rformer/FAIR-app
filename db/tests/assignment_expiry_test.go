package tests

import (
	"context"
	"testing"

	"github.com/rformer/fair-app/internal/scope"
)

// F-001 T-32 (AC-23): expired assignments are revoked by the sweep, and the
// user's scope is recomputed without them.
func TestAssignmentExpirySweep(t *testing.T) {
	e := setup(t)
	e.addBU("A", "ENTERPRISE")
	for _, u := range []string{"platform", "ann", "bob"} {
		e.mustOwner("INSERT INTO iam.app_user (email, display_name) VALUES ('" + u + "@example.test', '" + u + "')")
	}
	e.mustOwner("SELECT iam.bootstrap_platform_admin(" + uid("platform") + ")")
	e.mustOwner(`WITH r AS (INSERT INTO iam.role (name) VALUES ('Register Viewer') RETURNING id)
		INSERT INTO iam.role_version (role_id, version, permissions, change_reason) SELECT id, 1, ARRAY['register.view'], 'test' FROM r`)
	// Ann's assignment expires; Bob's has no expiry.
	e.mustOwner(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by, expires_at)
		VALUES ('user', ` + uid("ann") + `, ` + roleID("Register Viewer") + `, ` + buID("A") + `, ` + uid("platform") + `, now() + interval '1 hour')`)
	e.mustOwner(grant("platform", "user:bob", "Register Viewer", "A"))
	e.drain()
	if s := e.scopeOf("ann"); s == nil || len(s.Read["register"]) != 1 || s.Read["register"][0] != "A" {
		t.Fatalf("ann's scope before expiry: %+v", s)
	}

	w := scope.New(scope.Options{Pool: e.appPool()})
	ctx := context.Background()
	if n, err := w.SweepExpired(ctx); err != nil || n != 0 {
		t.Fatalf("sweep before expiry: %d %v", n, err)
	}
	// An unexpired assignment cannot end without a revoker.
	e.ownerFails("UPDATE iam.assignment SET revoked_at = now() WHERE principal_id = "+uid("ann"),
		"only expired assignments end without a revoker")
	// Nor can one be granted already expired.
	e.ownerFails(`INSERT INTO iam.assignment (principal_kind, principal_id, role_id, bu_id, granted_by, expires_at)
		VALUES ('user', `+uid("bob")+`, `+roleID("Register Viewer")+`, `+buID("ENTERPRISE")+`, `+uid("platform")+`, now() - interval '1 minute')`,
		"violates check constraint")

	// Time passes (the triggers are bypassed only to move the clock).
	e.admin(e.db, "SET session_replication_role = replica; UPDATE iam.assignment SET granted_at = now() - interval '2 hours', expires_at = now() - interval '1 second' WHERE principal_id = "+uid("ann"))
	if got := e.adminQuery("SELECT iam.user_has_permission(" + uid("ann") + ", 'register.view', " + buID("A") + ")"); got != "f" {
		t.Fatal("an expired assignment still grants")
	}
	if n, err := w.SweepExpired(ctx); err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if got := e.adminQuery("SELECT (revoked_at IS NOT NULL) || ':' || (revoked_by IS NULL) FROM iam.assignment WHERE principal_id = " + uid("ann")); got != "true:true" {
		t.Fatalf("ann's assignment after the sweep: %s", got)
	}
	if got := e.adminQuery(`SELECT payload->>'severity' || ':' || (payload->>'actor') || ':' || (payload->>'target' = 'user:' || ` + uid("ann") + `::text)
		FROM (SELECT id, 'audit' AS topic, body AS payload FROM audit.intake) ev WHERE payload->>'type' = 'access.assignment_expired'`); got != "low:system:iam:true" {
		t.Fatalf("expiry audit: %q", got)
	}
	e.drain()
	if s := e.scopeOf("ann"); s != nil && len(s.Read["register"]) > 0 {
		t.Fatalf("ann keeps the expired assignment's scope: %+v", s)
	}
	if s := e.scopeOf("bob"); s == nil || len(s.Read["register"]) != 1 {
		t.Fatalf("bob's unexpiring assignment was touched: %+v", s)
	}
	if n, _ := w.SweepExpired(ctx); n != 0 {
		t.Fatalf("second sweep revoked %d", n)
	}
	// Only the sweep's definer function revokes as the system.
	e.mustFail("app_rw", "UPDATE iam.assignment SET revoked_at = now()", "permission denied")
}
