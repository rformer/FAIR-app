package tests

import (
	"strings"
	"testing"
)

// F-011 T-17c (design §3.3 as amended 2026-11-18): a connector pushes as a
// service account that authenticates with a client secret; one that
// requires mTLS is refused at save and not offered by the form.
func TestConnectorServiceAccountAuth(t *testing.T) {
	ia := integrateAPI(t)
	ia.mustOwner(`WITH u AS (INSERT INTO iam.app_user (email, display_name, source) VALUES ('sa-mtls@service.invalid', 'sa-mtls', 'service') RETURNING id),
		r AS (INSERT INTO iam.role (name) VALUES ('sa role sa-mtls') RETURNING id)
		INSERT INTO iam.service_account (id, name, bu_id, role_id, auth_method, created_by)
		SELECT u.id, 'sa-mtls', ` + buID("ENTERPRISE") + `, r.id, 'mtls', ` + uid("platform") + ` FROM u, r`)
	body := func(sa string) map[string]any {
		return map[string]any{"bu_id": ia.bu["A"], "name": "CMDB " + sa, "kind": "assets", "delivery": "connector",
			"service_account_id": ia.adminQuery("SELECT id FROM iam.service_account WHERE name = '" + sa + "'"),
			"mapping":            map[string]any{"columns": map[string]any{"/id": "external_id", "/name": "name"}},
			"connector":          map[string]any{"type": "http_json", "source": "https://cmdb.example.test/apps", "schedule_minutes": 60}}
	}
	got := ia.call(t, "POST", "platform", "/api/v1/integrations", body("sa-mtls"))
	if got.code != 422 || got.body["error"] != "invalid_integration" || !strings.Contains(got.raw, "client secret") {
		t.Errorf("an mTLS service account: %d %s", got.code, got.raw)
	}
	if got := ia.call(t, "POST", "platform", "/api/v1/integrations", body("sa-root")); got.code != 201 {
		t.Errorf("a client-secret service account: %d %s", got.code, got.raw)
	}
	opts := ia.call(t, "GET", "platform", "/api/v1/integrations/options", nil)
	if opts.code != 200 || strings.Contains(opts.raw, "sa-mtls") || !strings.Contains(opts.raw, "sa-root") {
		t.Errorf("options: %d %s", opts.code, opts.raw)
	}
}
