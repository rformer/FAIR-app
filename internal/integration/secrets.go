package integration

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/rformer/fair-app/internal/keys"
)

// F-011 T-16 (F-011-AC-03; design §3.1): a connector's credentials are kept
// only as AES-256-GCM ciphertext (random nonces, the FIPS 140-3 approved
// form) under the keys of integrate/secrets (FAIR_INTEGRATE_SECRETS_DIR),
// as F-009 keeps webhook secrets. The newest key seals; every key opens, so
// a rotation (iam keys rotate -kind integrate-secrets) strands nothing.
// The sealed form is bound to its integration and purpose (the additional
// data), so a ciphertext copied to another integration or purpose does not
// open.

// Credential purposes (integration.secret.purpose).
const (
	PurposeSource = "source" // the source's token, or user and password
	PurposeClient = "client" // the integration's service account's client secret
)

// Credential is a connector credential as accepted (once) and as the runner
// opens it. A source credential is a bearer token or a user and password; a
// client credential is the service account's client secret.
type Credential struct {
	Token        string `json:"token,omitempty"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
}

// Check refuses a credential that is not one of its purpose's forms.
func (c Credential) Check(purpose string) error {
	for _, v := range []string{c.Token, c.Username, c.Password, c.ClientSecret} {
		if len(v) > 4096 || !utf8.ValidString(v) || strings.ContainsAny(v, "\x00\r\n") {
			return errors.New("integration: a credential's values are at most 4,096 characters of one line")
		}
	}
	switch purpose {
	case PurposeSource:
		token, basic := c.Token != "", c.Username != "" || c.Password != ""
		switch {
		case c.ClientSecret != "":
			return errors.New("integration: a source credential is a token, or a username and password")
		case token == basic:
			return errors.New("integration: a source credential is a token, or a username and password (one of the two)")
		case basic && (c.Username == "" || c.Password == ""):
			return errors.New("integration: a basic credential needs both its username and its password")
		case basic && strings.Contains(c.Username, ":"):
			return errors.New("integration: a basic credential's username has no colon")
		}
	case PurposeClient:
		if c.ClientSecret == "" || c.Token != "" || c.Username != "" || c.Password != "" {
			return errors.New("integration: a client credential is the service account's client_secret alone")
		}
	default:
		return fmt.Errorf("integration: %q is not a credential purpose (source, client)", purpose)
	}
	return nil
}

// Sealed is a credential as stored: the key id, the nonce and the
// ciphertext with its tag.
type Sealed struct {
	KeyID      string
	Nonce      []byte
	Ciphertext []byte
}

// Keyring holds the connector-credentials keys.
type Keyring struct {
	keys   map[string]cipher.AEAD
	newest string
}

// LoadKeyring reads the keys in dir (FAIR_INTEGRATE_SECRETS_DIR).
func LoadKeyring(dir string) (*Keyring, error) {
	raw, err := keys.IntegrateSecretKeys(dir)
	if err != nil {
		return nil, err
	}
	return NewKeyring(raw)
}

// NewKeyring makes a keyring of key id to secret file contents; each AES
// key is the SHA-256 of its file's secret.
func NewKeyring(raw map[string][]byte) (*Keyring, error) {
	if len(raw) == 0 {
		return nil, errors.New("integration: no connector-credentials key")
	}
	k := &Keyring{keys: map[string]cipher.AEAD{}}
	ids := make([]string, 0, len(raw))
	for id, secret := range raw {
		if id == "" || len(id) > 64 {
			return nil, fmt.Errorf("integration: key id %q is not 1 to 64 characters", id)
		}
		sum := sha256.Sum256(secret)
		block, err := aes.NewCipher(sum[:])
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCMWithRandomNonce(block)
		if err != nil {
			return nil, err
		}
		k.keys[id] = aead
		ids = append(ids, id)
	}
	slices.Sort(ids) // key ids sort by their time (keys.kid)
	k.newest = ids[len(ids)-1]
	return k, nil
}

const nonceSize = 12

func additional(keyID, integrationID, purpose string) []byte {
	return []byte("fair.integration.credential.v1\x00" + keyID + "\x00" + integrationID + "\x00" + purpose)
}

// Seal encrypts c for the integration and purpose under the newest key.
func (k *Keyring) Seal(integrationID, purpose string, c Credential) (Sealed, error) {
	if err := c.Check(purpose); err != nil {
		return Sealed{}, err
	}
	pt, err := json.Marshal(c) // #nosec G117 -- marshalled only to be sealed at once (AES-256-GCM)
	if err != nil {
		return Sealed{}, err
	}
	out := k.keys[k.newest].Seal(nil, nil, pt, additional(k.newest, integrationID, purpose)) // #nosec G407 -- NewGCMWithRandomNonce draws the nonce; Seal takes nil
	return Sealed{KeyID: k.newest, Nonce: out[:nonceSize], Ciphertext: out[nonceSize:]}, nil
}

// Open decrypts a sealed credential of the integration and purpose.
func (k *Keyring) Open(integrationID, purpose string, s Sealed) (Credential, error) {
	aead, ok := k.keys[s.KeyID]
	if !ok {
		return Credential{}, fmt.Errorf("integration: the connector-credentials key %s is not in FAIR_INTEGRATE_SECRETS_DIR", s.KeyID)
	}
	if len(s.Nonce) != nonceSize {
		return Credential{}, errors.New("integration: not a sealed credential")
	}
	pt, err := aead.Open(nil, nil, append(slices.Clone(s.Nonce), s.Ciphertext...), additional(s.KeyID, integrationID, purpose))
	if err != nil {
		return Credential{}, errors.New("integration: a sealed credential does not open")
	}
	var c Credential
	if err := json.Unmarshal(pt, &c); err != nil {
		return Credential{}, errors.New("integration: a sealed credential does not open")
	}
	return c, nil
}
