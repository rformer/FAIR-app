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
}

// SecretLen is the random bytes in each pepper and the DB-context secret.
const SecretLen = 32

// Kinds of key that rotate.
const (
	KindJWT       = "jwt"
	KindTicket    = "login-ticket"
	KindDBContext = "db-context"
)

var kidRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Set names the keys Init created or Rotate added.
type Set struct {
	JWT, Ticket, DBContext string // key ids
}

// Init creates every key into dir (one subdirectory per service). It never
// overwrites: an existing file is an error and nothing is written over it.
func Init(dir string, now time.Time) (Set, error) {
	for _, p := range []string{Gateway, IAM, Posture} {
		if _, err := os.Stat(filepath.Join(dir, p)); err == nil {
			return Set{}, fmt.Errorf("keys: %s already exists; keys are never overwritten (use rotate)", filepath.Join(dir, p))
		}
	}
	s := Set{JWT: kid("jwt", now), Ticket: kid("ticket", now), DBContext: kid("ctx", now)}
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
	w.private(filepath.Join(dir, Gateway, JWTDir, s.JWT+".pem"), jwt)
	w.public(filepath.Join(dir, IAM, JWTDir, s.JWT+".pem"), &jwt.PublicKey)
	w.public(filepath.Join(dir, Posture, JWTDir, s.JWT+".pem"), &jwt.PublicKey)
	w.private(filepath.Join(dir, IAM, TicketDir, s.Ticket+".pem"), ticket)
	w.public(filepath.Join(dir, Gateway, TicketDir, s.Ticket+".pem"), &ticket.PublicKey)
	w.file(filepath.Join(dir, Gateway, SecretsDir, SessionPepper), secret())
	w.file(filepath.Join(dir, Gateway, SecretsDir, TokenPepper), token)
	w.file(filepath.Join(dir, IAM, SecretsDir, TokenPepper), token)
	w.file(filepath.Join(dir, Gateway, SecretsDir, DBContextKey), secret())
	w.file(filepath.Join(dir, Gateway, SecretsDir, DBContextID), []byte(s.DBContext+"\n"))
	return s, w.err
}

// Rotate adds a new key of kind and returns its id:
//   - jwt: a new gateway signing key; the old one becomes public. Roll out
//     iam and posture (which now accept it) before the gateway.
//   - login-ticket: a new iam signing key; the old one becomes public. Roll
//     out the gateway before iam.
//   - db-context: a new secret and id for the gateway. Register it (iam keys
//     register) before rolling out the gateway; retire the old id after.
//
// The peppers do not rotate: a new session pepper ends every session and a
// new token pepper invalidates every service-account secret.
func Rotate(dir, kind string, now time.Time) (string, error) {
	w := &writer{overwrite: true}
	switch kind {
	case KindJWT, KindTicket:
		signer, verifiers, prefix := Gateway, []string{IAM, Posture}, "jwt"
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
	case KindDBContext:
		id := kid("ctx", now)
		w.file(filepath.Join(dir, Gateway, SecretsDir, DBContextKey), secret())
		w.file(filepath.Join(dir, Gateway, SecretsDir, DBContextID), []byte(id+"\n"))
		return id, w.err
	}
	return "", fmt.Errorf("keys: unknown kind %q (jwt, login-ticket or db-context)", kind)
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
	pair(Gateway, JWTDir, IAM, Posture)
	pair(IAM, TicketDir, Gateway)
	for _, f := range []string{filepath.Join(Gateway, SecretsDir, SessionPepper), filepath.Join(Gateway, SecretsDir, TokenPepper), filepath.Join(IAM, SecretsDir, TokenPepper),
		filepath.Join(Gateway, SecretsDir, DBContextKey)} {
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
	if id, err := ReadID(filepath.Join(dir, Gateway, SecretsDir, DBContextID)); err != nil {
		bad("%s: %v", filepath.Join(Gateway, SecretsDir, DBContextID), err)
	} else if id == "" {
		bad("%s: empty", filepath.Join(Gateway, SecretsDir, DBContextID))
	}
	errs = append(errs, CheckPermissions(dir))
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
	"FAIR_SECOPS_SECRET_FILE", "FAIR_SCANNER_GRPC_KEY_FILE",
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
