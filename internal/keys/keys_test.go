package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rformer/fair-app/internal/authn"
	"github.com/rformer/fair-app/pkg/authz"
)

var t0 = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

func load(t *testing.T, dir ...string) *authz.LocalKeys {
	t.Helper()
	k, err := authz.LoadLocalKeys(filepath.Join(dir...))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func jwt(t *testing.T, dir string, now time.Time) string {
	t.Helper()
	tok, err := authz.MintJWT(load(t, dir, Gateway, JWTDir), authz.Claims{Subject: "00000000-0000-4000-8000-000000000001", ScopeVersion: 1, DBContext: "x"}, "iam", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func ticket(t *testing.T, dir string, now time.Time) string {
	t.Helper()
	tok, err := authn.IssueTicket(load(t, dir, IAM, TicketDir), authn.Ticket{UserID: "00000000-0000-4000-8000-000000000001", AuthMethod: "oidc", ReturnTo: "/"}, now)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// verify: iam and posture accept the gateway's JWT; the gateway accepts
// iam's ticket.
func verify(t *testing.T, dir, jwtTok, ticketTok string, now time.Time) {
	t.Helper()
	for _, svc := range []string{IAM, Posture} {
		if _, err := authz.VerifyJWT(load(t, dir, svc, JWTDir), jwtTok, "iam", now); err != nil {
			t.Errorf("%s rejects the gateway's JWT: %v", svc, err)
		}
	}
	if _, err := authn.VerifyTicket(load(t, dir, Gateway, TicketDir), ticketTok, now); err != nil {
		t.Errorf("the gateway rejects iam's ticket: %v", err)
	}
}

// The keys init writes are the keys the services load, and they work
// across services.
func TestInitLoadsInEveryService(t *testing.T) {
	dir := t.TempDir()
	s, err := Init(dir, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(dir); err != nil {
		t.Fatal(err)
	}
	verify(t, dir, jwt(t, dir, t0), ticket(t, dir, t0), t0)
	// Each verifier holds only public keys.
	for _, d := range []string{filepath.Join(IAM, JWTDir), filepath.Join(Posture, JWTDir), filepath.Join(Gateway, TicketDir)} {
		if p, _ := privateKeys(filepath.Join(dir, d)); len(p) != 0 {
			t.Errorf("%s holds a private key", d)
		}
	}
	if id, _ := ReadID(filepath.Join(dir, Gateway, SecretsDir, DBContextID)); id != s.DBContext {
		t.Errorf("db-context.id %q, want %q", id, s.DBContext)
	}
	sec, err := ReadSecret(filepath.Join(dir, Gateway, SecretsDir, DBContextKey), SecretLen)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authz.MintDBContext(authz.ContextKey{ID: s.DBContext, Secret: sec}, "00000000-0000-4000-8000-000000000001", 1, time.Minute, t0); err != nil {
		t.Errorf("the DB-context key does not mint: %v", err)
	}
	// Distinct secrets; the token pepper is shared.
	sp, _ := ReadSecret(filepath.Join(dir, Gateway, SecretsDir, SessionPepper), SecretLen)
	tp, _ := ReadSecret(filepath.Join(dir, Gateway, SecretsDir, TokenPepper), SecretLen)
	if string(sp) == string(tp) || string(sp) == string(sec) {
		t.Error("secrets repeat")
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(dir, Gateway, SecretsDir, SessionPepper))
		di, _ := os.Stat(filepath.Join(dir, Gateway))
		if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
			t.Errorf("modes %v %v", fi.Mode(), di.Mode())
		}
	}
	// Never overwrites.
	if _, err := Init(dir, t0.Add(time.Hour)); err == nil {
		t.Fatal("init over an existing key directory")
	}
	if got, _ := ReadSecret(filepath.Join(dir, Gateway, SecretsDir, SessionPepper), SecretLen); string(got) != string(sp) {
		t.Fatal("init overwrote a key")
	}
}

// Rotation: tokens signed before verify after; new ones use the new key;
// the directory stays consistent.
func TestRotate(t *testing.T) {
	dir := t.TempDir()
	s, err := Init(dir, t0)
	if err != nil {
		t.Fatal(err)
	}
	oldJWT, oldTicket := jwt(t, dir, t0), ticket(t, dir, t0)
	t1 := t0.Add(time.Second)
	newJWT, err := Rotate(dir, KindJWT, t1)
	if err != nil {
		t.Fatal(err)
	}
	newTicket, err := Rotate(dir, KindTicket, t1)
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(dir); err != nil {
		t.Fatal(err)
	}
	verify(t, dir, oldJWT, oldTicket, t1)
	verify(t, dir, jwt(t, dir, t1), ticket(t, dir, t1), t1)
	if id, _, _ := load(t, dir, Gateway, JWTDir).SigningKey(); id != newJWT || newJWT == s.JWT {
		t.Errorf("the gateway signs with %s, want %s", id, newJWT)
	}
	if id, _, _ := load(t, dir, IAM, TicketDir).SigningKey(); id != newTicket {
		t.Errorf("iam signs tickets with %s, want %s", id, newTicket)
	}
	if p, _ := privateKeys(filepath.Join(dir, Gateway, JWTDir)); len(p) != 1 {
		t.Errorf("%d private JWT keys after rotation", len(p))
	}
	// The same second twice: refused, nothing changed.
	if _, err := Rotate(dir, KindJWT, t1); err == nil {
		t.Error("a second rotation in the same second")
	}
	ctx, err := Rotate(dir, KindDBContext, t1)
	if err != nil || ctx == s.DBContext {
		t.Fatalf("db-context rotation: %q %v", ctx, err)
	}
	if id, _ := ReadID(filepath.Join(dir, Gateway, SecretsDir, DBContextID)); id != ctx {
		t.Errorf("db-context.id %q", id)
	}
	if _, err := Rotate(dir, "session-pepper", t1); err == nil {
		t.Error("peppers do not rotate")
	}
	if err := Check(dir); err != nil {
		t.Fatal(err)
	}
}

func TestCheckRefuses(t *testing.T) {
	for _, c := range []struct {
		name, want string
		spoil      func(dir string)
	}{
		{"token peppers differ", "token peppers differ", func(dir string) {
			_ = os.WriteFile(filepath.Join(dir, IAM, SecretsDir, TokenPepper), []byte(strings.Repeat("x", 43)), 0o600)
		}},
		{"a verifier without the signing key", "lacks the public key", func(dir string) {
			ps, _ := filepath.Glob(filepath.Join(dir, Posture, JWTDir, "*.pem"))
			_ = os.Remove(ps[0])
		}},
		{"another installation's public key", "lacks the public key", func(dir string) {
			other := filepath.Join(dir, "other")
			_, _ = Init(other, t0)
			src, _ := filepath.Glob(filepath.Join(other, IAM, JWTDir, "*.pem"))
			dst, _ := filepath.Glob(filepath.Join(dir, IAM, JWTDir, "*.pem"))
			b, _ := os.ReadFile(src[0])        // #nosec G304 G703 -- the test's own temporary keys
			_ = os.WriteFile(dst[0], b, 0o600) // #nosec G703 -- the test's own temporary keys
		}},
		{"two signing keys", "exactly one private key", func(dir string) {
			src, _ := filepath.Glob(filepath.Join(dir, Gateway, JWTDir, "*.pem"))
			b, _ := os.ReadFile(src[0])                                               // #nosec G304 G703 -- the test's own temporary keys
			_ = os.WriteFile(filepath.Join(dir, Gateway, JWTDir, "zz.pem"), b, 0o600) // #nosec G703 -- the test's own temporary keys
		}},
		{"a short secret", "at least 32 bytes", func(dir string) {
			_ = os.WriteFile(filepath.Join(dir, Gateway, SecretsDir, SessionPepper), []byte("short\n"), 0o600)
		}},
		{"a bad key id", "must match", func(dir string) {
			_ = os.WriteFile(filepath.Join(dir, Gateway, SecretsDir, DBContextID), []byte("ctx.1\n"), 0o600)
		}},
		{"a missing file", DBContextKey, func(dir string) { _ = os.Remove(filepath.Join(dir, Gateway, SecretsDir, DBContextKey)) }},
	} {
		dir := t.TempDir()
		if _, err := Init(dir, t0); err != nil {
			t.Fatal(err)
		}
		c.spoil(dir)
		if err := Check(dir); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

func TestCheckMounted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no permission bits on Windows")
	}
	dir := t.TempDir()
	if _, err := Init(dir, t0); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"FAIR_JWT_KEYS_DIR": filepath.Join(dir, Gateway, JWTDir), "FAIR_SESSION_PEPPER_FILE": filepath.Join(dir, Gateway, SecretsDir, SessionPepper)}
	if err := CheckMounted("production", func(k string) string { return env[k] }); err != nil {
		t.Fatal(err)
	}
	// Kubernetes' 0440 passes; its default 0644 does not; outside
	// production nothing is checked.
	_ = os.Chmod(env["FAIR_SESSION_PEPPER_FILE"], 0o440) // #nosec G302 -- the mode under test
	if err := CheckMounted("production", func(k string) string { return env[k] }); err != nil {
		t.Fatal(err)
	}
	ps, _ := filepath.Glob(filepath.Join(env["FAIR_JWT_KEYS_DIR"], "*.pem"))
	_ = os.Chmod(ps[0], 0o644) // #nosec G302 -- the mode under test
	if err := CheckMounted("production", func(k string) string { return env[k] }); err == nil || !strings.Contains(err.Error(), "open to other users") {
		t.Fatalf("a world-readable key: %v", err)
	}
	if err := CheckMounted("development", func(k string) string { return env[k] }); err != nil {
		t.Fatal(err)
	}
	if err := Check(dir); err == nil {
		t.Fatal("Check passes a world-readable key")
	}
	// Projected secret volumes: ..data symlinks are followed, not walked.
	vol := filepath.Join(t.TempDir(), "vol")
	data := filepath.Join(vol, "..2026_11_02")
	_ = os.MkdirAll(data, 0o755)                                                                    // #nosec G301 -- as the kubelet makes it
	_ = os.WriteFile(filepath.Join(data, "session-pepper"), []byte(strings.Repeat("s", 43)), 0o440) // #nosec G306 -- the mode under test
	_ = os.Symlink("..2026_11_02", filepath.Join(vol, "..data"))
	_ = os.Symlink(filepath.Join("..data", "session-pepper"), filepath.Join(vol, "session-pepper"))
	if err := CheckPermissions(vol); err != nil {
		t.Fatalf("a projected volume with 0440: %v", err)
	}
}

// F-002 T-05: the audit service's keys: the gateway's internal-JWT public
// keys and the checkpoint signing key, in new and in older directories.
func TestAuditKeys(t *testing.T) {
	dir := t.TempDir()
	s, err := Init(dir, t0)
	if err != nil {
		t.Fatal(err)
	}
	k, id, err := CheckpointKey(filepath.Join(dir, Audit, CheckpointDir))
	if err != nil || id != s.Checkpoint || k == nil {
		t.Fatalf("checkpoint key %s: %v", id, err)
	}
	signer, _ := privateKeys(filepath.Join(dir, Gateway, JWTDir))
	pub, err := publicKey(filepath.Join(dir, Audit, JWTDir, s.JWT+".pem"))
	if err != nil || !pub.Equal(&signer[s.JWT].PublicKey) {
		t.Fatalf("audit lacks the gateway's JWT public key: %v", err)
	}
	if p, _ := privateKeys(filepath.Join(dir, Audit, JWTDir)); len(p) != 0 {
		t.Fatal("audit holds a JWT private key")
	}
	// A JWT rotation reaches the audit service too.
	t1 := t0.Add(time.Hour)
	jid, err := Rotate(dir, KindJWT, t1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publicKey(filepath.Join(dir, Audit, JWTDir, jid+".pem")); err != nil {
		t.Fatalf("rotated JWT key not given to audit: %v", err)
	}
	// Checkpoint rotation: one private key, the old one public.
	cid, err := Rotate(dir, KindCheckpoint, t1)
	if err != nil {
		t.Fatal(err)
	}
	if _, now, err := CheckpointKey(filepath.Join(dir, Audit, CheckpointDir)); err != nil || now != cid {
		t.Fatalf("after rotation: %s %v", now, err)
	}
	if old, err := publicKey(filepath.Join(dir, Audit, CheckpointDir, s.Checkpoint+".pem")); err != nil || !old.Equal(&k.PublicKey) {
		t.Fatalf("the old checkpoint key is not kept public: %v", err)
	}
	if _, err := Rotate(dir, KindCheckpoint, t1); err == nil {
		t.Fatal("a second rotation in the same second overwrote a key")
	}
	if err := Check(dir); err != nil {
		t.Fatal(err)
	}
	// Check wants exactly one checkpoint private key.
	_ = os.Remove(filepath.Join(dir, Audit, CheckpointDir, cid+".pem"))
	if err := Check(dir); err == nil || !strings.Contains(err.Error(), "audit/checkpoint") {
		t.Fatalf("no checkpoint key passed: %v", err)
	}
	if _, _, err := CheckpointKey(filepath.Join(dir, Audit, CheckpointDir)); err == nil {
		t.Fatal("CheckpointKey with no private key")
	}
	// Two private keys are as wrong as none.
	two := t.TempDir()
	for _, id := range []string{"a", "b"} {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		w := &writer{}
		w.private(filepath.Join(two, id+".pem"), k)
		if w.err != nil {
			t.Fatal(w.err)
		}
	}
	if _, _, err := CheckpointKey(two); err == nil {
		t.Fatal("CheckpointKey with two private keys")
	}
	// The startup check covers the checkpoint directory (outside Windows).
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Join(two, "a.pem"), 0o644); err != nil { // #nosec G302 -- deliberately too open, to be refused
			t.Fatal(err)
		}
		env := map[string]string{"FAIR_AUDIT_CHECKPOINT_KEYS_DIR": two}
		if err := CheckMounted("production", func(k string) string { return env[k] }); err == nil {
			t.Fatal("a checkpoint key open to others passed the startup check")
		}
	}

	// A directory made before F-002 gets audit/ from upgrade, once.
	old := t.TempDir()
	if _, err := Init(old, t0); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(old, Audit)); err != nil {
		t.Fatal(err)
	}
	if err := Check(old); err == nil {
		t.Fatal("a directory without audit/ passed")
	}
	if _, err := Init(old, t1); err == nil {
		t.Fatal("init over an existing directory")
	}
	added, err := Upgrade(old, t1)
	if err != nil || len(added) != 1 || added[0] != Audit {
		t.Fatalf("upgrade: %v %v", added, err)
	}
	if err := Check(old); err != nil {
		t.Fatal(err)
	}
	if again, err := Upgrade(old, t1); err != nil || len(again) != 0 {
		t.Fatalf("second upgrade: %v %v", again, err)
	}
	if _, err := Upgrade(t.TempDir(), t1); err == nil {
		t.Fatal("upgrade of an empty directory")
	}

	// A directory made before F-003 (and one before F-002) gets risk/ with
	// every public key the gateway holds, after a rotation too, and the
	// engine channel (F-005).
	for _, gone := range [][]string{{Risk, EngineGate}, {Audit, Risk, EngineGate}} {
		d := t.TempDir()
		s, err := Init(d, t0)
		if err != nil {
			t.Fatal(err)
		}
		rotated, err := Rotate(d, KindJWT, t1)
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range gone {
			if err := os.RemoveAll(filepath.Join(d, g)); err != nil {
				t.Fatal(err)
			}
		}
		if err := Check(d); err == nil {
			t.Fatalf("a directory without %v passed", gone)
		}
		added, err := Upgrade(d, t1)
		if err != nil || !slices.Equal(added, gone) {
			t.Fatalf("upgrade: %v %v, want %v", added, err, gone)
		}
		for _, id := range []string{s.JWT, rotated} {
			if _, err := publicKey(filepath.Join(d, Risk, JWTDir, id+".pem")); err != nil {
				t.Errorf("risk/ lacks the gateway's key %s: %v", id, err)
			}
		}
		if p, _ := privateKeys(filepath.Join(d, Risk, JWTDir)); len(p) != 0 {
			t.Error("risk/ holds a private key")
		}
		if err := Check(d); err != nil {
			t.Fatal(err)
		}
	}
}

// F-005 T-10: the engine channel's keys. Init makes both sides, each pinning
// the other; rotation keeps the previous pins; an upgrade adds the channel
// to a directory without it, and refuses a directory with only one side.
func TestEngineKeys(t *testing.T) {
	d := t.TempDir()
	now := time.Now()
	if _, err := Init(d, now); err != nil {
		t.Fatal(err)
	}
	if err := Check(d); err != nil {
		t.Fatal(err)
	}
	gatePins := filepath.Join(d, EngineGate, TLSDir, ClientPins)
	first, err := ReadPins(gatePins)
	if err != nil || len(first) != 1 {
		t.Fatalf("pins: %v %v", first, err)
	}
	if _, err := Rotate(d, KindEngine, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	second, _ := ReadPins(gatePins)
	if len(second) != 2 || second[1] != first[0] {
		t.Errorf("after rotation the gate pins %v, want the new and %v", second, first)
	}
	if _, err := Rotate(d, KindEngine, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if third, _ := ReadPins(gatePins); len(third) != 2 || third[1] != second[0] {
		t.Errorf("a second rotation keeps only the previous pin: %v", third)
	}
	if err := Check(d); err != nil {
		t.Fatal(err)
	}

	// A pin file that does not pin the other side's certificate.
	if err := os.WriteFile(gatePins, []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Check(d); err == nil || !strings.Contains(err.Error(), "does not pin") {
		t.Errorf("an unpinned client passed: %v", err)
	}
	// Expired certificates.
	if err := checkEngine(d, now.Add(EngineCertValidity+time.Hour)); err == nil {
		t.Error("expired certificates passed")
	}

	// Upgrade: no channel yet, then only one side.
	u := t.TempDir()
	if _, err := Init(u, now); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(u, EngineGate), filepath.Join(u, Risk, EngineClientDir)} {
		if err := os.RemoveAll(p); err != nil {
			t.Fatal(err)
		}
	}
	if added, err := Upgrade(u, now); err != nil || !slices.Equal(added, []string{EngineGate}) {
		t.Fatalf("upgrade: %v %v", added, err)
	}
	if err := Check(u); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(u, EngineGate)); err != nil {
		t.Fatal(err)
	}
	if _, err := Upgrade(u, now); err == nil {
		t.Error("an upgrade with only one side of the channel")
	}
}
