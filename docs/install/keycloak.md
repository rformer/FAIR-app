# The bundled Keycloak

F-001 AC-06 (T-36). Self-hosted installations whose organization has no IdP
of its own can use the bundled Keycloak (26.0.x). Its realm is
`deploy/keycloak/fair-realm.json`.

## What the realm allows
- A **smart card** (X.509: PIV/CAC), or a **password and a second factor**:
  a **security key** (WebAuthn, user verification required, ES256/ES384/RS256/PS256),
  or **TOTP** for users who were asked to enroll it.
- New users register a security key on first sign-in. TOTP enrollment is
  never a default; an administrator asks a user for it (required action
  *Configure OTP*).
- Each step reports an RFC 8176 `amr` value in the ID token: `pwd`, `hwk`
  (security key), `otp` (TOTP), `sc` (smart card).
- Password policy: 14 characters, history 5, PBKDF2-SHA512. TOTP uses
  HMAC-SHA-256, and a code is never accepted twice. Three failed attempts in
  15 minutes lock the user for 15 minutes. Self-registration and password
  reset by email are off. User and admin events are kept for 90 days.

## What FAIR enforces
Keycloak doesn't know FAIR's roles or settings, so FAIR decides at each login
from the `amr`:
- **TOTP** counts as a factor only while `auth.totp_enabled` is on. It is off
  in every profile, and only a Platform Admin can turn it on, through the
  Posture page or API.
- A user holding any **privileged** permission must sign in with a security
  key or smart card, whatever else they used. Otherwise the login is refused
  and audited (`authn.mfa_missing`).

## Installing
1. Fill in the two placeholders: `${FAIR_PUBLIC_ORIGIN}` (e.g.
   `https://fair.example.com`) and `${FAIR_KEYCLOAK_CLIENT_SECRET}` (at least
   32 random characters; also put it in the file named by the IdP's
   `client_secret_file`). Keycloak's import substitutes environment
   variables of these names, or fill them in before importing.
2. Import: `kc.sh import --file fair-realm.json`, or start Keycloak with
   `--import-realm` and the file in `/opt/keycloak/data/import/`.
3. For smart cards, give Keycloak's TLS listener the PIV/CAC issuing CAs as a
   truststore, and an OCSP responder reachable from Keycloak. The realm
   checks OCSP and refuses when it cannot (fail closed).
4. In FAIR, create the IdP of kind `keycloak` (`POST /api/v1/idps`), then
   `PUT /api/v1/idps/{id}/metadata` with the realm's discovery document
   (`/realms/fair/.well-known/openid-configuration`). Set `client_id`
   `fair-platform`, `client_secret_file`, `subject_claim` (`email`, or `sub`
   with SCIM), and the email domains.
5. If people will use smart cards alone, set the IdP's MFA evidence rule so
   that `sc` counts as MFA (the card's PIN is the second factor):
   `PATCH /api/v1/idps/{id}` with
   `{"mfa_evidence_rule": {"amr": ["mfa", "sc"], "amr_two_categories": true}, "reason": "..."}`.

## When TOTP is enabled
Turning `auth.totp_enabled` on lets non-privileged users sign in with a
password and TOTP. Privileged users still need a key or card. To offer TOTP
in Keycloak, set the *Configure OTP* required action on those users. To stop
offering it after turning the setting off, remove their OTP credentials. FAIR
refuses TOTP logins as soon as the setting is off, whatever Keycloak still
offers.

## Verification
`internal/authn` `TestKeycloakRealm` checks the file: its flows, amr
references, policies and client. `scripts/sso-e2e-keycloak.sh` runs
`TestKeycloakRealmPolicy`. It imports the file into Keycloak 26.0.7, reads
the policies back, and signs in with a password and TOTP: refused while TOTP
is off, accepted for an ordinary user once it is on, refused for a Platform
Admin.
