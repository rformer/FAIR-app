package notify

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/rformer/fair-app/internal/keys"
)

// F-009 T-10, T-11 (design §1): webhook secrets are kept only as
// AES-256-GCM ciphertext (random nonces, the FIPS 140-3 approved form)
// under the keys of notify/webhook-secrets (FAIR_NOTIFY_SECRETS_DIR). The
// newest key encrypts; every key decrypts, so a rotation (iam keys rotate
// -kind notify-secrets) never strands a secret. A ciphertext names its key:
// the key id, a 0 byte, then the sealed secret.

// Keyring holds the webhook-secrets keys.
type Keyring struct {
	keys   map[string]cipher.AEAD
	newest string
}

// LoadKeyring reads the keys in dir.
func LoadKeyring(dir string) (*Keyring, error) {
	raw, err := keys.WebhookSecretKeys(dir)
	if err != nil {
		return nil, err
	}
	return NewKeyring(raw)
}

// NewKeyring makes a keyring of key id to secret file contents; each AES
// key is the SHA-256 of its file's secret.
func NewKeyring(raw map[string][]byte) (*Keyring, error) {
	if len(raw) == 0 {
		return nil, errors.New("notify: no webhook-secrets key")
	}
	k := &Keyring{keys: map[string]cipher.AEAD{}}
	ids := make([]string, 0, len(raw))
	for id, secret := range raw {
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

// Seal encrypts a webhook secret under the newest key.
func (k *Keyring) Seal(secret string) []byte {
	aead := k.keys[k.newest]
	out := append([]byte(k.newest), 0)
	return aead.Seal(out, nil, []byte(secret), []byte(k.newest)) // #nosec G407 -- NewGCMWithRandomNonce draws the nonce; Seal takes nil
}

// Open decrypts a sealed webhook secret.
func (k *Keyring) Open(ct []byte) (string, error) {
	i := slices.Index(ct, 0)
	if i <= 0 {
		return "", errors.New("notify: not a sealed secret")
	}
	id := string(ct[:i])
	aead, ok := k.keys[id]
	if !ok {
		return "", fmt.Errorf("notify: the webhook-secrets key %s is not in FAIR_NOTIFY_SECRETS_DIR", id)
	}
	pt, err := aead.Open(nil, nil, ct[i+1:], []byte(id))
	if err != nil {
		return "", errors.New("notify: a sealed secret does not open")
	}
	return string(pt), nil
}
