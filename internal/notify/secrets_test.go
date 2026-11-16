package notify

import (
	"strings"
	"testing"
	"time"
)

func TestKeyring(t *testing.T) {
	k1, err := NewKeyring(map[string][]byte{"whk-20261101T000000Z": []byte("first-secret-of-thirty-two-bytes")})
	if err != nil {
		t.Fatal(err)
	}
	ct := k1.Seal("whsec_abc")
	if strings.Contains(string(ct), "whsec_abc") {
		t.Fatal("the secret is in the ciphertext")
	}
	if got, err := k1.Open(ct); err != nil || got != "whsec_abc" {
		t.Fatalf("open: %q %v", got, err)
	}
	if ct2 := k1.Seal("whsec_abc"); string(ct2) == string(ct) {
		t.Error("the same ciphertext twice (nonces repeat)")
	}
	// After a rotation the newest key seals, the older still opens.
	k2, _ := NewKeyring(map[string][]byte{"whk-20261101T000000Z": []byte("first-secret-of-thirty-two-bytes"),
		"whk-20261201T000000Z": []byte("second-secret-of-thirty-two-byte")})
	if got, err := k2.Open(ct); err != nil || got != "whsec_abc" {
		t.Errorf("an older key: %q %v", got, err)
	}
	if !strings.HasPrefix(string(k2.Seal("x")), "whk-20261201T000000Z\x00") {
		t.Error("not sealed under the newest key")
	}
	// A missing key, a tampered ciphertext, a ciphertext moved to another key id.
	k3, _ := NewKeyring(map[string][]byte{"whk-other": []byte("another-secret-of-thirty-two-byt")})
	if _, err := k3.Open(ct); err == nil {
		t.Error("opened without its key")
	}
	bad := append([]byte{}, ct...)
	bad[len(bad)-1] ^= 1
	if _, err := k1.Open(bad); err == nil {
		t.Error("a tampered ciphertext opened")
	}
	moved := append([]byte("whk-20261201T000000Z"), ct[len("whk-20261101T000000Z"):]...)
	if _, err := k2.Open(moved); err == nil {
		t.Error("a ciphertext under another key id opened")
	}
	if _, err := NewKeyring(nil); err == nil {
		t.Error("an empty keyring")
	}
}

func TestDigest(t *testing.T) {
	e := sampleEnvelope()
	e2 := sampleEnvelope()
	e2.Title, e2.At = "<b>Claims</b>", e2.At.Add(time.Hour)
	m, err := composer.Digest([]DigestItem{{e, "A risk acceptance you requested was decided"}, {e2, "The exposure of a risk you own is stale"}})
	if err != nil {
		t.Fatal(err)
	}
	if m.Subject != "[FAIR] Your daily digest: 2 notices" || strings.Count(m.Text, "https://fair.example.com/acceptances/") != 2 {
		t.Errorf("digest: %q\n%s", m.Subject, m.Text)
	}
	if strings.Contains(m.HTML, "<b>Claims</b>") || !strings.Contains(m.HTML, "&lt;b&gt;Claims&lt;/b&gt;") {
		t.Errorf("not escaped:\n%s", m.HTML)
	}
}
