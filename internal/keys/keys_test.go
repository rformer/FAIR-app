package keys

import (
	"os"
	"path/filepath"
	"runtime"
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
