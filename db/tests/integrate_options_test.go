package tests

import (
	"fmt"
	"strings"
	"testing"
)

// F-011 T-18 (F-011-AC-01, AC-02): the integration form's options: the
// business units where the caller manages integrations (a grant above a
// restricted business unit does not reach it) and the service accounts a
// connector there may push as.
func TestIntegrationOptions(t *testing.T) {
	ia := integrateAPI(t)
	names := func(user string) (string, string) {
		t.Helper()
		got := ia.call(t, "GET", user, "/api/v1/integrations/options", nil)
		if got.code != 200 {
			t.Fatalf("options as %s: %d %s", user, got.code, got.raw)
		}
		var bus, sas []string
		for _, b := range got.body["bus"].([]any) {
			bus = append(bus, b.(map[string]any)["code"].(string))
		}
		for _, s := range got.body["service_accounts"].([]any) {
			sas = append(sas, fmt.Sprint(s.(map[string]any)["name"]))
		}
		return strings.Join(bus, ","), strings.Join(sas, ",")
	}
	// platform (Platform Admin at the root) manages everywhere but inside R;
	// sa-root (root) and sa-b (B) push there.
	if bus, sas := names("platform"); bus != "A,A1,B,ENTERPRISE" || sas != "sa-b,sa-root" {
		t.Errorf("platform: %s / %s", bus, sas)
	}
	// rman manages inside R only; no service account is at R or above it on
	// an unblocked path (sa-root's path into the restricted R is blocked).
	if bus, sas := names("rman"); bus != "R,R1" || sas != "" {
		t.Errorf("rman: %s / %s", bus, sas)
	}
	// aud views but manages nowhere; mallory holds neither.
	for _, u := range []string{"aud", "mallory"} {
		if bus, sas := names(u); bus != "" || sas != "" {
			t.Errorf("%s: %s / %s", u, bus, sas)
		}
	}
}
