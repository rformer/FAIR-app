# ADR-010 WebAuthn library: go-webauthn/webauthn
Status: Accepted (Robert Former, 2026-11-02; F-001 T-34)
Date: 2026-11-02

## Context
Break-glass sign-in is WebAuthn only (F-001 AC-42, design §5.7): one or two
local accounts enroll a security key with a one-time code and then sign in with
it, when every IdP may be down. WebAuthn verification parses CBOR attestation
objects, COSE keys and authenticator data and checks challenge, origin,
relying-party hash, flags, signature and counter. That parsing is
security-critical. Two options were weighed: our own minimal implementation
(ES256/RS256, "none" and self "packed" attestation), as F-001 did for SCIM, or
the maintained Go library.

Facts as of 2026-11-02 (module proxy and the module's go.mod):
- `github.com/go-webauthn/webauthn` v0.18.2, released 2026-09-19; the
  reference WebAuthn relying-party implementation for Go (the successor of
  duo-labs/webauthn).
- Direct dependencies: `fxamacker/cbor/v2` (CBOR), `go-webauthn/x`,
  `golang-jwt/jwt/v5` (FIDO metadata), `google/go-tpm` (TPM attestation),
  `google/uuid`, `tinylib/msgp`, `go-viper/mapstructure/v2`. It declares
  `go 1.26.0`, our toolchain.
- Signatures are verified with Go's standard crypto, so in our binaries they run
  in the FIPS 140 module (`GOFIPS140=v1.0.0`, `fips140=on`).

## Decision
Use **`go-webauthn/webauthn` v0.18.2** for break-glass, wrapped in
`internal/authn/breakglass` so it can be replaced. F-001 constrains it:
- **Algorithms:** credentials must use ES256, ES384, RS256 or PS256 (FIPS 186
  signatures); others are not offered at registration and are refused.
- **User verification required** at registration and login, and checked again
  on the verified result; **discoverable credentials required**, so sign-in
  starts without naming an account and reveals none.
- **No attestation requested** ("none" accepted): the holder is vetted by the
  enrollment code, not the key's make.
- **Ceremonies** are stored server-side, single use, for 5 minutes; the
  relying party is the platform's public origin.
- **The counter must advance** (checked in the database); a counter that does
  not is treated as a cloned key and counts as a failure.
- A software authenticator (`internal/authn/breakglass/webauthntest`) produces
  correct and deliberately wrong registrations and assertions for the tests.

## Consequences
- New dependencies are vendored through the module cache like the others; the
  release gate's SBOM covers them.
- Library updates are reviewed like the SAML library's (ADR-009): changelog and
  advisories, then the break-glass tests.
