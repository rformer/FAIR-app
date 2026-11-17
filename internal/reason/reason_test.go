package reason

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAtBUs(t *testing.T) {
	s := Static{BUs: []string{"a1"}}
	for bus, want := range map[string]bool{"a": false, "a,a1": true, "": false} {
		got, err := AtBUs(s, strings.Split(bus, ","))
		if err != nil || got != want {
			t.Errorf("%q: %v %v", bus, got, err)
		}
	}
	if got, _ := AtBUs(Static{On: true}, nil); !got {
		t.Error("on everywhere")
	}
	if _, err := AtBUs(nil, []string{"a"}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no settings: %v", err)
	}
}

func TestFromRequest(t *testing.T) {
	for raw, want := range map[string]string{"": "", "  Q4 pack ": "Q4 pack", "Q4%20pack%20%E2%80%94%20done": "Q4 pack — done"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set(Header, raw)
		if got, err := FromRequest(r); err != nil || got != want {
			t.Errorf("%q: %q %v", raw, got, err)
		}
	}
	for _, raw := range []string{"50%", "a%0Ab", "%FF", strings.Repeat("x", 501)} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set(Header, raw)
		if _, err := FromRequest(r); !errors.Is(err, ErrTooLong) {
			t.Errorf("%q accepted: %v", raw, err)
		}
	}
}
