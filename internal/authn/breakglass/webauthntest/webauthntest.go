// Package webauthntest is a software WebAuthn authenticator for tests
// (F-001 T-34): it answers the registration and assertion options the
// break-glass routes send, like a security key with a resident ES256
// credential, "none" attestation and user verification. Its fields let a
// test make the answers wrong in one way at a time.
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

var b64 = base64.RawURLEncoding

// Authenticator holds one credential.
type Authenticator struct {
	Key        *ecdsa.PrivateKey
	CredID     []byte
	UserHandle []byte // set by Register from the options
	Count      uint32 // the signature counter; incremented per assertion unless FixedCount
	FixedCount bool

	// Faults.
	Origin       string // the origin the client reports (default: the one given to New)
	RPID         string // the relying party id hashed into the authenticator data
	NoUV         bool   // user present but not verified
	NoUP         bool   // not even user presence
	WrongType    bool   // clientData type of the other ceremony
	Challenge    []byte // overrides the challenge
	CorruptSig   bool   // a signature that does not verify
	OtherKey     *ecdsa.PrivateKey
	UserOverride []byte // another user handle in the assertion
}

// New returns an authenticator for the relying party.
func New(rpID, origin string) *Authenticator {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &Authenticator{Key: k, CredID: id, Origin: origin, RPID: rpID}
}

type options struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		RPID string `json:"rpId"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"publicKey"`
}

func (a *Authenticator) clientData(typ, challenge string) []byte {
	if a.WrongType {
		if typ == "webauthn.create" {
			typ = "webauthn.get"
		} else {
			typ = "webauthn.create"
		}
	}
	if a.Challenge != nil {
		challenge = b64.EncodeToString(a.Challenge)
	}
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.Origin, "crossOrigin": false})
	return b
}

func (a *Authenticator) flags(attested bool) byte {
	var f byte
	if !a.NoUP {
		f |= 0x01
	}
	if !a.NoUV {
		f |= 0x04
	}
	if attested {
		f |= 0x40
	}
	return f
}

func (a *Authenticator) authData(attested bool) []byte {
	rp := sha256.Sum256([]byte(a.RPID))
	out := append([]byte{}, rp[:]...)
	out = append(out, a.flags(attested))
	out = binary.BigEndian.AppendUint32(out, a.Count)
	if attested {
		out = append(out, make([]byte, 16)...)                          // AAGUID
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.CredID))) // #nosec G115 -- a test credential id of 32 bytes
		out = append(out, a.CredID...)
		x, y := a.Key.X.FillBytes(make([]byte, 32)), a.Key.Y.FillBytes(make([]byte, 32))
		key, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		out = append(out, key...)
	}
	return out
}

// Register answers a registration's options (the JSON the begin route
// returned under "options").
func (a *Authenticator) Register(optionsJSON []byte) ([]byte, error) {
	var o options
	if err := json.Unmarshal(optionsJSON, &o); err != nil {
		return nil, err
	}
	if o.PublicKey.Challenge == "" {
		return nil, errors.New("webauthntest: no challenge")
	}
	uh, err := b64.DecodeString(o.PublicKey.User.ID)
	if err != nil {
		return nil, err
	}
	a.UserHandle = uh
	cd := a.clientData("webauthn.create", o.PublicKey.Challenge)
	att, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(true)})
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"id": b64.EncodeToString(a.CredID), "rawId": b64.EncodeToString(a.CredID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(cd), "attestationObject": b64.EncodeToString(att)}})
}

// Assert answers an assertion's options.
func (a *Authenticator) Assert(optionsJSON []byte) ([]byte, error) {
	var o options
	if err := json.Unmarshal(optionsJSON, &o); err != nil {
		return nil, err
	}
	if !a.FixedCount {
		a.Count++
	}
	cd := a.clientData("webauthn.get", o.PublicKey.Challenge)
	ad := a.authData(false)
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	key := a.Key
	if a.OtherKey != nil {
		key = a.OtherKey
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	if a.CorruptSig {
		sig[len(sig)-1] ^= 0xff
	}
	uh := a.UserHandle
	if a.UserOverride != nil {
		uh = a.UserOverride
	}
	return json.Marshal(map[string]any{"id": b64.EncodeToString(a.CredID), "rawId": b64.EncodeToString(a.CredID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(ad),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString(uh)}})
}
