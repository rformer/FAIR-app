// Package keys creates, rotates and checks the installation's F-001 keys
// (F-001 T-41, design §10). Keys are files in every deployment mode: the
// mode's secret store (cloud KMS-backed secrets through the External Secrets
// Operator in SaaS, Vault or OpenBao self-hosted, a Kubernetes Secret from
// `iam keys init` air-gapped) delivers them into each service's key
// directory, and the services read them as files. Nothing per request leaves
// the process.
//
// The layout: a directory per service, and in it one directory per store
// entry and mount (deploy/k8s/keys):
//
//	gateway/jwt/<kid>.pem                internal-JWT signing key (ES256, private)  FAIR_JWT_KEYS_DIR
//	gateway/login-ticket/<kid>.pem       iam's login-ticket keys (public)           FAIR_LOGIN_TICKET_KEYS_DIR
//	gateway/secrets/session-pepper       session ids are HMAC(pepper, token)        FAIR_SESSION_PEPPER_FILE
//	gateway/secrets/token-pepper         service-account secrets (= iam's)          FAIR_TOKEN_PEPPER_FILE
//	gateway/secrets/db-context.key       signed DB context secret (authz.ctx_key)   FAIR_DB_CONTEXT_KEY_FILE
//	gateway/secrets/db-context.id        its key id                                 FAIR_DB_CONTEXT_KEY_ID_FILE
//	iam/jwt/<kid>.pem                    the gateway's JWT keys (public)            FAIR_JWT_KEYS_DIR
//	iam/login-ticket/<kid>.pem           login-ticket signing key (ES256, private)  FAIR_LOGIN_TICKET_KEYS_DIR
//	iam/secrets/token-pepper             service-account secrets (= the gateway's)  FAIR_TOKEN_PEPPER_FILE
//	posture/jwt/<kid>.pem                the gateway's JWT keys (public)            FAIR_JWT_KEYS_DIR
//	risk/engine-client/...               the engine channel's client side (engine.go)
//	risk/secrets/report-context.key      delegated report DB context (F-010)        FAIR_REPORT_CONTEXT_KEY_FILE
//	risk/secrets/report-context.id       its key id (authz.ctx_key, purpose report) FAIR_REPORT_CONTEXT_KEY_ID_FILE
//	notify/jwt/<kid>.pem                 the gateway's JWT keys (public)            FAIR_JWT_KEYS_DIR
//	notify/webhook-secrets/<kid>.key     webhook secrets' AES-256 keys (F-009)      FAIR_NOTIFY_SECRETS_DIR
//	integrate/jwt/<kid>.pem              the gateway's JWT keys (public)            FAIR_JWT_KEYS_DIR
//	integrate/secrets/<kid>.key          connector credentials' AES-256 keys (F-011) FAIR_INTEGRATE_SECRETS_DIR
//	engine-gate/tls/...                  the engine channel's server side (engine.go)
//
// Secrets are base64url text (32 random bytes), so every store carries them
// unchanged. Each signing directory holds exactly one private key; rotation
// adds a new one and turns the old one public, so tokens it signed verify
// until they expire.
package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
)

// Services with keys.
const (
	Gateway = "gateway"
	IAM     = "iam"
	Posture = "posture"
	Audit   = "audit"  // F-002 T-05
	Risk    = "risk"   // F-003 T-04
	Notify  = "notify" // F-009 T-03
	// Integrate is the integrate service (F-011 T-15): connectors.
	Integrate = "integrate"
)

// Files and directories in a service's key directory.
const (
	JWTDir        = "jwt"
	TicketDir     = "login-ticket"
	SecretsDir    = "secrets"
	SessionPepper = "session-pepper"
	TokenPepper   = "token-pepper"
	DBContextKey  = "db-context.key"
	DBContextID   = "db-context.id"
	// ReportContextKey and ReportContextID are the risk service's delegated
	// read-only DB context key for report jobs (F-010 design §3.3; ADR-007
	// amendment 6), registered in authz.ctx_key with purpose report.
	ReportContextKey = "report-context.key"
	ReportContextID  = "report-context.id"
	CheckpointDir    = "checkpoint" // the audit trail's checkpoint signing key (F-002 design §6.3)
	// WebhookSecretsDir holds the AES-256-GCM keys the notify service keeps
	// webhook secrets under (F-009 design §1): the newest encrypts, all decrypt.
	WebhookSecretsDir = "webhook-secrets"
)

// MountRoot is where every store delivers a service's key directories.
const MountRoot = "/keys"

// Mount is one store entry: a service's directory, delivered at
// MountRoot/<Dir> in every mode, and the environment pointing at it. The
// manifests in deploy/k8s/keys follow this table (TestDeployManifests).
type Mount struct {
	Service, Dir string
	Env          map[string]string
}

// Mounts lists every store entry.
var Mounts = []Mount{
	{Gateway, JWTDir, map[string]string{"FAIR_JWT_KEYS_DIR": MountRoot + "/jwt"}},
	{Gateway, TicketDir, map[string]string{"FAIR_LOGIN_TICKET_KEYS_DIR": MountRoot + "/login-ticket"}},
	{Gateway, SecretsDir, map[string]string{
		"FAIR_SESSION_PEPPER_FILE":    MountRoot + "/secrets/" + SessionPepper,
		"FAIR_TOKEN_PEPPER_FILE":      MountRoot + "/secrets/" + TokenPepper,
		"FAIR_DB_CONTEXT_KEY_FILE":    MountRoot + "/secrets/" + DBContextKey,
		"FAIR_DB_CONTEXT_KEY_ID_FILE": MountRoot + "/secrets/" + DBContextID,
	}},
	{IAM, JWTDir, map[string]string{"FAIR_JWT_KEYS_DIR": MountRoot + "/jwt"}},
	{IAM, TicketDir, map[string]string{"FAIR_LOGIN_TICKET_KEYS_DIR": MountRoot + "/login-ticket"}},
	{IAM, SecretsDir, map[string]string{"FAIR_TOKEN_PEPPER_FILE": MountRoot + "/secrets/" + TokenPepper}},
	{Posture, JWTDir, map[string]string{"FAIR_JWT_KEYS_DIR": MountRoot + "/jwt"}},
	{Audit, JWTDir, map[string]string{"FAIR_JWT_KEYS_DIR": MountRoot + "/jwt"}},
	{Audit, CheckpointDir, map[string]string{"FAIR_AUDIT_CHECKPOINT_KEYS_DIR": MountRoot + "/checkpoint"}},
	{Risk, JWTDir, map[string]string{"FAIR_JWT_KEYS_DIR": MountRoot + "/jwt"}},
	{Risk, EngineClientDir, map[string]string{"FAIR_ENGINE_CLIENT_DIR": MountRoot + "/" + EngineClientDir}}, // F-005 T-10
	{Risk, SecretsDir, map[string]string{ // F-010 T-04
		"FAIR_REPORT_CONTEXT_KEY_FILE":    MountRoot + "/secrets/" + ReportContextKey,
		"FAIR_REPORT_CONTEXT_KEY_ID_FILE": MountRoot + "/secrets/" + ReportContextID,
	}},
	{Notify, JWTDir, map[string]string{"FAIR_JWT_KEYS_DIR": MountRoot + "/jwt"}}, // F-009 T-03
	{Notify, WebhookSecretsDir, map[string]string{"FAIR_NOTIFY_SECRETS_DIR": MountRoot + "/" + WebhookSecretsDir}},
	{Integrate, JWTDir, map[string]string{"FAIR_JWT_KEYS_DIR": MountRoot + "/jwt"}}, // F-011 T-15
	{Integrate, SecretsDir, map[string]string{"FAIR_INTEGRATE_SECRETS_DIR": MountRoot + "/" + SecretsDir}},
	{EngineGate, TLSDir, map[string]string{"FAIR_ENGINE_GATE_TLS_DIR": MountRoot + "/" + TLSDir}},
}

// SecretLen is the random bytes in each pepper and the DB-context secret.
const SecretLen = 32

// Kinds of key that rotate.
const (
	KindJWT        = "jwt"
	KindTicket     = "login-ticket"
	KindDBContext  = "db-context"
	KindCheckpoint = "checkpoint"
	KindNotify     = "notify-secrets"    // a new webhook-secrets key (F-009 T-03)
	KindReportCtx  = "report-context"    // a new delegated report DB context key (F-010 T-04)
	KindIntegrate  = "integrate-secrets" // a new connector-credentials key (F-011 T-15)
	// KindEngine (engine.go) rotates the engine channel's certificates.
)

// jwtVerifiers hold the gateway's internal-JWT public keys.
var jwtVerifiers = []string{IAM, Posture, Audit, Risk, Notify, Integrate}

var kidRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Set names the keys Init created or Rotate added.
type Set struct {
	JWT, Ticket, DBContext, Checkpoint, ReportContext string // key ids
}

// Init creates every key into dir (one subdirectory per service). It never
// overwrites: an existing file is an error and nothing is written over it.
func Init(dir string, now time.Time) (Set, error) {
	for _, p := range []string{Gateway, IAM, Posture, Audit, Risk, Notify, Integrate, EngineGate} {
		if _, err := os.Stat(filepath.Join(dir, p)); err == nil {
			return Set{}, fmt.Errorf("keys: %s already exists; keys are never overwritten (use rotate, or upgrade to add a new service's keys)", filepath.Join(dir, p))
		}
	}
	s := Set{JWT: kid("jwt", now), Ticket: kid("ticket", now), DBContext: kid("ctx", now), Checkpoint: kid("checkpoint", now), ReportContext: kid("rctx", now)}
	jwt, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Set{}, err
	}
	ticket, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Set{}, err
	}
	token := secret()
	w := &writer{}
	checkpoint, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Set{}, err
	}
	w.private(filepath.Join(dir, Gateway, JWTDir, s.JWT+".pem"), jwt)
	for _, v := range jwtVerifiers {
		w.public(filepath.Join(dir, v, JWTDir, s.JWT+".pem"), &jwt.PublicKey)
	}
	w.private(filepath.Join(dir, Audit, CheckpointDir, s.Checkpoint+".pem"), checkpoint)
	w.file(filepath.Join(dir, Notify, WebhookSecretsDir, kid("whk", now)+".key"), secret())
	w.file(filepath.Join(dir, Integrate, SecretsDir, kid("isk", now)+".key"), secret())
	w.private(filepath.Join(dir, IAM, TicketDir, s.Ticket+".pem"), ticket)
	w.public(filepath.Join(dir, Gateway, TicketDir, s.Ticket+".pem"), &ticket.PublicKey)
	w.file(filepath.Join(dir, Gateway, SecretsDir, SessionPepper), secret())
	w.file(filepath.Join(dir, Gateway, SecretsDir, TokenPepper), token)
	w.file(filepath.Join(dir, IAM, SecretsDir, TokenPepper), token)
	w.file(filepath.Join(dir, Gateway, SecretsDir, DBContextKey), secret())
	w.file(filepath.Join(dir, Gateway, SecretsDir, DBContextID), []byte(s.DBContext+"\n"))
	w.file(filepath.Join(dir, Risk, SecretsDir, ReportContextKey), secret())
	w.file(filepath.Join(dir, Risk, SecretsDir, ReportContextID), []byte(s.ReportContext+"\n"))
	writeEngine(w, dir, now, nil, nil)
	return s, w.err
}

// Upgrade adds the key directories of services newer than a key directory:
// audit/ (F-002 T-05: the gateway's internal-JWT public keys and a new
// checkpoint signing key), risk/ (F-003 T-04: the internal-JWT public
// keys), the engine channel (F-005 T-10: risk/engine-client/ and
// engine-gate/), notify/ (F-009 T-03: the internal-JWT public keys and
// a webhook-secrets key) and integrate/ (F-011 T-15: the internal-JWT public
// keys and a connector-credentials key). It returns what it added; nothing when the directory is
// complete. It never overwrites.
func Upgrade(dir string, now time.Time) ([]string, error) {
	for _, p := range []string{Gateway, IAM, Posture} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			return nil, fmt.Errorf("keys: %s is not a key directory (no %s/; use init)", dir, p)
		}
	}
	var missing []string
	for _, p := range []string{Audit, Risk, Notify, Integrate} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			missing = append(missing, p)
		}
	}
	_, errClient := os.Stat(filepath.Join(dir, Risk, EngineClientDir))
	_, errGate := os.Stat(filepath.Join(dir, EngineGate))
	if (errClient == nil) != (errGate == nil) {
		return nil, fmt.Errorf("keys: only one side of the engine channel exists (%s/%s, %s/); restore the other from the store", Risk, EngineClientDir, EngineGate)
	}
	engine := errGate != nil
	// F-010 T-04: the risk service's report context key.
	_, errReport := os.Stat(filepath.Join(dir, Risk, SecretsDir, ReportContextKey))
	report := errReport != nil
	if len(missing) == 0 && !engine && !report {
		return nil, nil
	}
	if len(missing) == 0 {
		w := &writer{}
		var added []string
		if engine {
			writeEngine(w, dir, now, nil, nil)
			added = append(added, EngineGate)
		}
		if report {
			writeReportContext(w, dir, now)
			added = append(added, Risk+"/"+SecretsDir)
		}
		return added, w.err
	}
	signers, err := privateKeys(filepath.Join(dir, Gateway, JWTDir))
	if err != nil {
		return nil, fmt.Errorf("keys: %s/%s: %w", Gateway, JWTDir, err)
	}
	if len(signers) != 1 {
		return nil, fmt.Errorf("keys: %s/%s: want exactly one private key, found %d", Gateway, JWTDir, len(signers))
	}
	pubs, err := filepath.Glob(filepath.Join(dir, Gateway, JWTDir, "*.pem"))
	if err != nil {
		return nil, err
	}
	w := &writer{}
	for _, svc := range missing {
		// Every key the gateway holds, as a public key: the signing key and
		// the ones it signed with before.
		for _, f := range pubs {
			id := strings.TrimSuffix(filepath.Base(f), ".pem")
			if k, ok := signers[id]; ok {
				w.public(filepath.Join(dir, svc, JWTDir, id+".pem"), &k.PublicKey)
				continue
			}
			k, err := publicKey(f)
			if err != nil {
				return nil, err
			}
			w.public(filepath.Join(dir, svc, JWTDir, id+".pem"), k)
		}
		if svc == Audit {
			checkpoint, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, err
			}
			w.private(filepath.Join(dir, Audit, CheckpointDir, kid("checkpoint", now)+".pem"), checkpoint)
		}
		if svc == Notify {
			w.file(filepath.Join(dir, Notify, WebhookSecretsDir, kid("whk", now)+".key"), secret())
		}
		if svc == Integrate {
			w.file(filepath.Join(dir, Integrate, SecretsDir, kid("isk", now)+".key"), secret())
		}
	}
	if engine {
		writeEngine(w, dir, now, nil, nil)
		missing = append(missing, EngineGate)
	}
	if report {
		writeReportContext(w, dir, now)
		if !slices.Contains(missing, Risk) {
			missing = append(missing, Risk+"/"+SecretsDir)
		}
	}
	if w.err != nil {
		return nil, w.err
	}
	return missing, nil
}

// writeReportContext writes a new report context key and its id.
func writeReportContext(w *writer, dir string, now time.Time) {
	w.file(filepath.Join(dir, Risk, SecretsDir, ReportContextKey), secret())
	w.file(filepath.Join(dir, Risk, SecretsDir, ReportContextID), []byte(kid("rctx", now)+"\n"))
}

// WebhookSecretKeys reads the notify service's webhook-secrets keys in dir
// (FAIR_NOTIFY_SECRETS_DIR): each <kid>.key file is a secret of at least
// SecretLen bytes, used as an AES-256 key (the first 32 bytes of its
// SHA-256: the files hold base64url text). The newest id sorts last.
func WebhookSecretKeys(dir string) (map[string][]byte, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.key"))
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, f := range files {
		id := strings.TrimSuffix(filepath.Base(f), ".key")
		if !kidRE.MatchString(id) {
			return nil, fmt.Errorf("keys: %s: not a key id", f)
		}
		b, err := ReadSecret(f, SecretLen)
		if err != nil {
			return nil, err
		}
		out[id] = b
	}
	return out, nil
}

// IntegrateSecretKeys reads the integrate service's connector-credentials
// keys in dir (FAIR_INTEGRATE_SECRETS_DIR; F-011 T-15), as
// WebhookSecretKeys: <kid>.key files, the newest id sorting last.
func IntegrateSecretKeys(dir string) (map[string][]byte, error) {
	return WebhookSecretKeys(dir)
}

// CheckpointKey reads the audit trail's checkpoint signing key: the one
// private key in dir (FAIR_AUDIT_CHECKPOINT_KEYS_DIR), with its id.
func CheckpointKey(dir string) (*ecdsa.PrivateKey, string, error) {
	keys, err := privateKeys(dir)
	if err != nil {
		return nil, "", err
	}
	if len(keys) != 1 {
		return nil, "", fmt.Errorf("keys: %s: want exactly one private key, found %d", dir, len(keys))
	}
	for id, k := range keys {
		return k, id, nil
	}
	return nil, "", nil
}

// Rotate adds a new key of kind and returns its id:
//   - jwt: a new gateway signing key; the old one becomes public. Roll out
//     iam and posture (which now accept it) before the gateway.
//   - login-ticket: a new iam signing key; the old one becomes public. Roll
//     out the gateway before iam.
//   - db-context: a new secret and id for the gateway. Register it (iam keys
//     register) before rolling out the gateway; retire the old id after.
//   - checkpoint: a new audit checkpoint signing key; the old one becomes
//     public. The audit service records each key's public half (F-002 §6.3),
//     so checkpoints signed before stay verifiable.
//   - notify-secrets: a new webhook-secrets key, which the notify service
//     encrypts with from then on; the old keys stay, so the secrets kept
//     under them still decrypt (F-009 design §1).
//   - report-context: a new secret and id for the risk service's report
//     jobs. Register it (iam keys register) before rolling out the risk
//     service; retire the old id after (F-010 design §3.3).
//
// The peppers do not rotate: a new session pepper ends every session and a
// new token pepper invalidates every service-account secret.
func Rotate(dir, kind string, now time.Time) (string, error) {
	w := &writer{overwrite: true}
	switch kind {
	case KindJWT, KindTicket:
		signer, verifiers, prefix := Gateway, jwtVerifiers, "jwt"
		sub := JWTDir
		if kind == KindTicket {
			signer, verifiers, prefix, sub = IAM, []string{Gateway}, "ticket", TicketDir
		}
		id := kid(prefix, now)
		sdir := filepath.Join(dir, signer, sub)
		if _, err := os.Stat(filepath.Join(sdir, id+".pem")); err == nil {
			return "", fmt.Errorf("keys: %s already exists", id)
		}
		olds, err := privateKeys(sdir)
		if err != nil {
			return "", err
		}
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", err
		}
		// The verifiers first: if writing stops half way, nothing signs
		// with a key they do not hold.
		for _, v := range verifiers {
			w.public(filepath.Join(dir, v, sub, id+".pem"), &k.PublicKey)
		}
		w.private(filepath.Join(sdir, id+".pem"), k)
		for old, ok := range olds {
			w.public(filepath.Join(sdir, old+".pem"), &ok.PublicKey)
		}
		return id, w.err
	case KindCheckpoint:
		id := kid("checkpoint", now)
		sdir := filepath.Join(dir, Audit, CheckpointDir)
		if _, err := os.Stat(filepath.Join(sdir, id+".pem")); err == nil {
			return "", fmt.Errorf("keys: %s already exists", id)
		}
		olds, err := privateKeys(sdir)
		if err != nil {
			return "", err
		}
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", err
		}
		w.private(filepath.Join(sdir, id+".pem"), k)
		for old, ok := range olds {
			w.public(filepath.Join(sdir, old+".pem"), &ok.PublicKey)
		}
		return id, w.err
	case KindEngine:
		return rotateEngine(dir, now)
	case KindNotify:
		id := kid("whk", now)
		p := filepath.Join(dir, Notify, WebhookSecretsDir, id+".key")
		if _, err := os.Stat(p); err == nil {
			return "", fmt.Errorf("keys: %s already exists", id)
		}
		w.file(p, secret())
		return id, w.err
	case KindIntegrate:
		id := kid("isk", now)
		p := filepath.Join(dir, Integrate, SecretsDir, id+".key")
		if _, err := os.Stat(p); err == nil {
			return "", fmt.Errorf("keys: %s already exists", id)
		}
		w.file(p, secret())
		return id, w.err
	case KindReportCtx:
		id := kid("rctx", now)
		w.file(filepath.Join(dir, Risk, SecretsDir, ReportContextKey), secret())
		w.file(filepath.Join(dir, Risk, SecretsDir, ReportContextID), []byte(id+"\n"))
		return id, w.err
	case KindDBContext:
		id := kid("ctx", now)
		w.file(filepath.Join(dir, Gateway, SecretsDir, DBContextKey), secret())
		w.file(filepath.Join(dir, Gateway, SecretsDir, DBContextID), []byte(id+"\n"))
		return id, w.err
	}
	return "", fmt.Errorf("keys: unknown kind %q (jwt, login-ticket, db-context, checkpoint, engine, notify-secrets, report-context or integrate-secrets)", kind)
}

// Check verifies a key directory as a whole: every file each service needs
// is there and well formed, each signer holds exactly one private key whose
// public key its verifiers hold, the token pepper is the same for iam and
// the gateway, and (outside Windows) no key file is open to other users.
func Check(dir string) error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	pair := func(signer, sub string, verifiers ...string) {
		priv, err := privateKeys(filepath.Join(dir, signer, sub))
		if err != nil || len(priv) != 1 {
			bad("%s/%s: want exactly one private key, found %d (%v)", signer, sub, len(priv), err)
			return
		}
		for id, k := range priv {
			for _, v := range verifiers {
				pub, err := publicKey(filepath.Join(dir, v, sub, id+".pem"))
				if err != nil || !pub.Equal(&k.PublicKey) {
					bad("%s/%s: lacks the public key of %s's signing key %s (%v)", v, sub, signer, id, err)
				}
			}
		}
	}
	pair(Gateway, JWTDir, jwtVerifiers...)
	pair(IAM, TicketDir, Gateway)
	pair(Audit, CheckpointDir)
	if ks, err := WebhookSecretKeys(filepath.Join(dir, Notify, WebhookSecretsDir)); err != nil || len(ks) == 0 {
		bad("%s/%s: want at least one key (%v)", Notify, WebhookSecretsDir, err)
	}
	if ks, err := IntegrateSecretKeys(filepath.Join(dir, Integrate, SecretsDir)); err != nil || len(ks) == 0 {
		bad("%s/%s: want at least one key (%v)", Integrate, SecretsDir, err)
	}
	for _, f := range []string{filepath.Join(Gateway, SecretsDir, SessionPepper), filepath.Join(Gateway, SecretsDir, TokenPepper), filepath.Join(IAM, SecretsDir, TokenPepper),
		filepath.Join(Gateway, SecretsDir, DBContextKey), filepath.Join(Risk, SecretsDir, ReportContextKey)} {
		if b, err := ReadSecret(filepath.Join(dir, f), SecretLen); err != nil {
			bad("%s: %v", f, err)
		} else if bytes.Count(b, []byte{0}) > 0 {
			bad("%s: not text", f)
		}
	}
	a, _ := ReadSecret(filepath.Join(dir, Gateway, SecretsDir, TokenPepper), SecretLen)
	b, _ := ReadSecret(filepath.Join(dir, IAM, SecretsDir, TokenPepper), SecretLen)
	if a != nil && b != nil && !bytes.Equal(a, b) {
		bad("the gateway's and iam's token peppers differ: service-account secrets would not verify")
	}
	for _, f := range []string{filepath.Join(Gateway, SecretsDir, DBContextID), filepath.Join(Risk, SecretsDir, ReportContextID)} {
		if id, err := ReadID(filepath.Join(dir, f)); err != nil {
			bad("%s: %v", f, err)
		} else if id == "" {
			bad("%s: empty", f)
		}
	}
	if a, _ := ReadSecret(filepath.Join(dir, Gateway, SecretsDir, DBContextKey), SecretLen); a != nil {
		if b, _ := ReadSecret(filepath.Join(dir, Risk, SecretsDir, ReportContextKey), SecretLen); b != nil && bytes.Equal(a, b) {
			bad("the gateway's DB-context key and the report context key are the same secret")
		}
	}
	errs = append(errs, checkEngine(dir, time.Now()), CheckPermissions(dir))
	return errors.Join(errs...)
}

// CheckPermissions refuses key files (or, for a directory, the files in
// it) that other users may read or write. Kubernetes secret volumes with
// defaultMode 0440 or 0400 pass; the default 0644 does not. Skipped on
// Windows, which has no such bits.
func CheckPermissions(paths ...string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	var errs []error
	for _, p := range paths {
		if p == "" {
			continue
		}
		err := filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			// Kubernetes projects secrets through ..data symlinks; Stat
			// follows them to the file itself.
			if strings.HasPrefix(d.Name(), "..") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			fi, err := os.Stat(path)
			if err != nil {
				return err
			}
			if fi.Mode().IsRegular() && fi.Mode().Perm()&0o007 != 0 {
				errs = append(errs, fmt.Errorf("%s is open to other users (mode %04o; want no access for others, e.g. 0440 or 0640)", path, fi.Mode().Perm()))
			}
			return nil
		})
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// SecretVars are the environment variables naming key and secret files or
// directories, in every service.
var SecretVars = []string{
	"FAIR_JWT_KEYS_DIR", "FAIR_LOGIN_TICKET_KEYS_DIR", "FAIR_SESSION_PEPPER_FILE", "FAIR_TOKEN_PEPPER_FILE",
	"FAIR_DB_CONTEXT_KEY_FILE", "FAIR_DB_PASSWORD_FILE", "FAIR_TLS_KEY_FILE", "FAIR_EXPORT_SIGNING_KEY_FILE",
	"FAIR_SECOPS_SECRET_FILE", "FAIR_SCANNER_GRPC_KEY_FILE", "FAIR_AUDIT_CHECKPOINT_KEYS_DIR",
	"FAIR_AUDIT_WORM_ACCESS_KEY_FILE", "FAIR_AUDIT_WORM_SECRET_KEY_FILE",
	"FAIR_ENGINE_CLIENT_DIR", "FAIR_ENGINE_GATE_TLS_DIR",
}

// CheckMounted is the services' startup check (production): the key and
// secret files the environment names are not open to other users,
// however the mode's store delivered them.
func CheckMounted(env string, getenv func(string) string) error {
	if env != "production" {
		return nil
	}
	var paths []string
	for _, v := range SecretVars {
		paths = append(paths, getenv(v))
	}
	return CheckPermissions(paths...)
}

// ReadSecret reads a secret file: trimmed, at least minLen bytes.
func ReadSecret(file string, minLen int) ([]byte, error) {
	b, err := os.ReadFile(file) // #nosec G304 -- operator-supplied key file
	if err != nil {
		return nil, err
	}
	b = bytes.TrimSpace(b)
	if len(b) < minLen {
		return nil, fmt.Errorf("must hold at least %d bytes", minLen)
	}
	return b, nil
}

// ReadID reads a key id file.
func ReadID(file string) (string, error) {
	b, err := os.ReadFile(file) // #nosec G304 -- operator-supplied key file
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if !kidRE.MatchString(id) {
		return "", fmt.Errorf("key id %q must match %s", id, kidRE)
	}
	return id, nil
}

func kid(prefix string, now time.Time) string {
	return prefix + "-" + now.UTC().Format("20060102T150405Z")
}

func secret() []byte {
	b := make([]byte, SecretLen)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return []byte(base64.RawURLEncoding.EncodeToString(b) + "\n")
}

// privateKeys reads the private keys in a key directory, by id.
func privateKeys(dir string) (map[string]*ecdsa.PrivateKey, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.pem"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	out := map[string]*ecdsa.PrivateKey{}
	for _, f := range files {
		blk, err := readPEM(f)
		if err != nil {
			return nil, err
		}
		if !slices.Contains([]string{"PRIVATE KEY", "EC PRIVATE KEY"}, blk.Type) {
			continue
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			if k, err = x509.ParseECPrivateKey(blk.Bytes); err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
		}
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok || ek.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%s: want an ECDSA P-256 key", f)
		}
		out[strings.TrimSuffix(filepath.Base(f), ".pem")] = ek
	}
	return out, nil
}

func publicKey(file string) (*ecdsa.PublicKey, error) {
	blk, err := readPEM(file)
	if err != nil {
		return nil, err
	}
	if blk.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%s: want a PUBLIC KEY, found %s", file, blk.Type)
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s: want an ECDSA P-256 key", file)
	}
	return ek, nil
}

func readPEM(file string) (*pem.Block, error) {
	b, err := os.ReadFile(file) // #nosec G304 -- operator-supplied key file
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s is not PEM", file)
	}
	return blk, nil
}

// writer writes key files 0600 in 0700 directories, stopping at the first
// error. Without overwrite it refuses existing files.
type writer struct {
	overwrite bool
	err       error
}

func (w *writer) file(path string, b []byte) {
	if w.err != nil {
		return
	}
	if w.err = os.MkdirAll(filepath.Dir(path), 0o700); w.err != nil {
		return
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if w.overwrite {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600) // #nosec G304 -- the operator's key directory
	if err != nil {
		w.err = err
		return
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		w.err = err
		return
	}
	w.err = f.Close()
}

func (w *writer) private(path string, k *ecdsa.PrivateKey) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		w.err = errors.Join(w.err, err)
		return
	}
	w.file(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func (w *writer) public(path string, k *ecdsa.PublicKey) {
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		w.err = errors.Join(w.err, err)
		return
	}
	w.file(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
