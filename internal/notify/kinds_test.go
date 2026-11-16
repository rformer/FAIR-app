package notify

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestKinds(t *testing.T) {
	if err := CheckKinds(Kinds); err != nil {
		t.Fatal(err)
	}
	b, err := SyncPayload()
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Kinds []Kind `json:"kinds"`
	}
	if err := json.Unmarshal(b, &p); err != nil || len(p.Kinds) != len(Kinds) {
		t.Fatalf("payload: %v %d", err, len(p.Kinds))
	}
	// Every source has a kind; security kinds are those of posture,
	// break-glass and findings (OQ5).
	for _, s := range Sources {
		found := false
		for _, k := range Kinds {
			if k.Source == s {
				found = true
				if want := s == "posture" || s == "iam" || s == "finding"; k.Security != want {
					t.Errorf("%s: security %v", k.Kind, k.Security)
				}
			}
		}
		if !found {
			t.Errorf("source %s has no kind", s)
		}
	}
	if k, ok := KindOf("acceptance.decision_needed"); !ok || !k.Mandatory {
		t.Errorf("KindOf: %+v %v", k, ok)
	}
}

func TestCheckKindsRefuses(t *testing.T) {
	ok := Kind{"a.b", "notify", "b", false, false, "x"}
	for name, c := range map[string]struct {
		ks   []Kind
		want string
	}{
		"bad name":          {[]Kind{{"A.b", "notify", "b", false, false, "x"}}, "dotted"},
		"undotted":          {[]Kind{{"ab", "notify", "b", false, false, "x"}}, "dotted"},
		"twice":             {[]Kind{ok, ok}, "twice"},
		"unknown source":    {[]Kind{{"a.b", "mail", "b", false, false, "x"}}, "unknown source"},
		"source kind taken": {[]Kind{ok, {"a.c", "notify", "b", false, false, "x"}}, "taken"},
		"no label":          {[]Kind{{"a.b", "notify", "b", false, false, ""}}, "label"},
		"security, mutable": {[]Kind{{"a.b", "notify", "b", false, true, "x"}}, "must be mandatory"},
		"no source kind":    {[]Kind{{"a.b", "notify", "", false, false, "x"}}, "missing"},
	} {
		if err := CheckKinds(c.ks); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
