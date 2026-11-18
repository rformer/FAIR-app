package integration

import (
	"bytes"
	"strings"
	"testing"
)

// F-011 T-16 (AC-03): credentials are sealed under the newest key, open
// under any, and only for their own integration and purpose.
func TestKeyring(t *testing.T) {
	old, err := NewKeyring(map[string][]byte{"k-20261101": []byte("first secret, thirty-two bytes!!")})
	if err != nil {
		t.Fatal(err)
	}
	both, err := NewKeyring(map[string][]byte{"k-20261101": []byte("first secret, thirty-two bytes!!"), "k-20261118": []byte("second secret, thirty-two bytes!")})
	if err != nil {
		t.Fatal(err)
	}
	c := Credential{Token: "tok-123"}
	s, err := old.Seal("i-1", PurposeSource, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Nonce) != 12 || bytes.Contains(s.Ciphertext, []byte("tok-123")) {
		t.Fatalf("sealed %+v", s)
	}
	if got, err := both.Open("i-1", PurposeSource, s); err != nil || got != c {
		t.Errorf("an older key's credential after rotation: %+v %v", got, err)
	}
	s2, _ := both.Seal("i-1", PurposeSource, c)
	if s2.KeyID != "k-20261118" {
		t.Errorf("sealed under %s, want the newest", s2.KeyID)
	}
	if _, err := old.Open("i-1", PurposeSource, s2); err == nil || !strings.Contains(err.Error(), "FAIR_INTEGRATE_SECRETS_DIR") {
		t.Errorf("a missing key: %v", err)
	}
	for name, open := range map[string]func() error{
		"another integration": func() error { _, err := both.Open("i-2", PurposeSource, s); return err },
		"another purpose":     func() error { _, err := both.Open("i-1", PurposeClient, s); return err },
		"another key id": func() error {
			x := s
			x.KeyID = "k-20261118"
			_, err := both.Open("i-1", PurposeSource, x)
			return err
		},
		"a changed byte": func() error {
			x := s
			x.Ciphertext = bytes.Clone(s.Ciphertext)
			x.Ciphertext[0] ^= 1
			_, err := both.Open("i-1", PurposeSource, x)
			return err
		},
	} {
		if err := open(); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	if _, err := NewKeyring(nil); err == nil {
		t.Error("an empty keyring")
	}
}

func TestCredentialCheck(t *testing.T) {
	for _, tc := range []struct {
		c       Credential
		purpose string
		ok      bool
	}{
		{Credential{Token: "t"}, PurposeSource, true},
		{Credential{Username: "u", Password: "p"}, PurposeSource, true},
		{Credential{ClientSecret: "s"}, PurposeClient, true},
		{Credential{}, PurposeSource, false},
		{Credential{Token: "t", Username: "u", Password: "p"}, PurposeSource, false},
		{Credential{Username: "u"}, PurposeSource, false},
		{Credential{Username: "a:b", Password: "p"}, PurposeSource, false},
		{Credential{ClientSecret: "s"}, PurposeSource, false},
		{Credential{Token: "t"}, PurposeClient, false},
		{Credential{ClientSecret: "s", Token: "t"}, PurposeClient, false},
		{Credential{Token: "a\nb"}, PurposeSource, false},
		{Credential{Token: strings.Repeat("x", 4097)}, PurposeSource, false},
		{Credential{Token: "t"}, "other", false},
	} {
		if err := tc.c.Check(tc.purpose); (err == nil) != tc.ok {
			t.Errorf("%+v as %s: %v", tc.c, tc.purpose, err)
		}
	}
}

func TestParseConnector(t *testing.T) {
	ok := `{"type": "http_json", "source": "https://cmdb.example.com/api/apps", "schedule_minutes": 60, "settings": {"list": "/items"}}`
	c, err := ParseConnector([]byte(ok))
	if err != nil || c.Host() != "cmdb.example.com" {
		t.Fatalf("%+v %v", c, err)
	}
	for _, bad := range []string{
		`{"type": "ftp", "source": "https://cmdb.example.com", "schedule_minutes": 60}`,
		`{"type": "http_json", "source": "http://cmdb.example.com", "schedule_minutes": 60}`,
		`{"type": "http_json", "source": "https://u:p@cmdb.example.com", "schedule_minutes": 60}`,
		`{"type": "http_json", "source": "https://cmdb.example.com/#x", "schedule_minutes": 60}`,
		`{"type": "http_json", "source": "https://cmdb.example.com:99999", "schedule_minutes": 60}`,
		`{"type": "http_json", "source": "https://cmdb.example.com", "schedule_minutes": 5}`,
		`{"type": "http_json", "source": "https://cmdb.example.com", "schedule_minutes": 2000}`,
		`{"type": "http_json", "source": "https://cmdb.example.com", "schedule_minutes": 60, "settings": [1]}`,
		`{"type": "http_json", "source": "https://cmdb.example.com", "schedule_minutes": 60, "other": 1}`,
		`{"type": "servicenow_cmdb", "source": "https://` + strings.Repeat("a", 2048) + `.example.com", "schedule_minutes": 60}`,
	} {
		if _, err := ParseConnector([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad[:min(len(bad), 120)])
		}
	}
}
