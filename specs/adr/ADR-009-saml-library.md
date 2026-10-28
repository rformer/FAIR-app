# ADR-009 SAML service provider library: russellhaering/gosaml2
Status: Accepted (Robert Former, 2026-10-28; F-001 T-15, D-OQ1)
Date: 2026-10-28

## Context
F-001 needs a SAML 2.0 service provider (AC-01, AC-04): SP- and IdP-initiated
logins against Entra ID, Okta and Ping, with signature, issuer, audience and
time checks, replay protection and resistance to XML signature wrapping (XSW).
Design §12 D-OQ1 names two candidates and three criteria: maintenance record,
CVE history, and FIPS-only algorithms. Both candidates verify signatures with
the same library, `russellhaering/goxmldsig`, so its fixes reach a candidate only
if the candidate tracks it.

Facts as of 2026-10-28 (GitHub releases, tags, commits and security advisories):

| | `crewjam/saml` | `russellhaering/gosaml2` |
|---|---|---|
| Scope | SP and IdP | SP only (what F-001 needs) |
| Latest release | v0.5.1, 2025-04-14 | v0.12.0, 2026-08-05 |
| Latest commit on main | 2025-05-09 | 2026-08-05 |
| goxmldsig it requires | v1.4.0 (2023) | v1.6.1 (2026-08-04, the latest) |
| Advisories | 5: signature validation bypass (critical, 2020); XML processing (high, 2020); signature bypass via multiple Assertion elements (critical, 2022); deflate bomb (moderate, 2023); XSS via Binding (moderate, 2023) | 9: signature validation bypass and authentication bypass (critical, 2020); nil dereference DoS (2022); deflate bomb (2023); unsigned LogoutRequest accepted and CBC padding panic (high, 2026-03); EncryptedAssertion panic (high), unsigned LogoutResponse and round-trip allocation (moderate, 2026-08) |
| Security practice | Dependabot | oss-fuzz integration (2026-03); XML token limit; assertion signatures inside signed Responses verified (2026-03 hardening) |
| Go version | 1.22 | 1.25 |

goxmldsig's own advisories: signature validation bypass (critical, 2020),
signature bypass through loop variable capture (high, 2026-03, fixed in v1.6.0),
quadratic memory in canonicalization (high, 2026-08, fixed in v1.6.1).
`crewjam/saml` as released requires goxmldsig v1.4.0, before both 2026 fixes.

## Decision
Use **`russellhaering/gosaml2` v0.12.0** with **`goxmldsig` v1.6.1** for the SAML
SP, wrapped in `internal/authn/saml` so it can be replaced:
- It is maintained (2026 releases from the goxmldsig author), fuzzed, and tracks
  goxmldsig's security fixes; `crewjam/saml` has had no release for 18 months
  and pins a goxmldsig version with known signature-validation and memory
  issues.
- Its recent advisories are a cost of scrutiny, and each was fixed within the
  advisory; the logout-message advisories do not affect F-001, which uses no
  SAML single logout.
- SP-only scope is what F-001 needs; `crewjam/saml`'s IdP half would be unused
  attack surface.

Whatever the library, F-001 adds its own checks around it (design §7), and the
XSW corpus (T-15) tests them together:
- **FIPS-only algorithms:** only RSA-SHA256/384/512 and ECDSA-SHA256/384/512
  signatures and SHA-256+ digests are accepted (checked on the XML before the
  library verifies it); SHA-1 and DSA are refused, and the binary runs with
  the FIPS 140 module (fips140=on).
- Exactly one Assertion; the signature must cover the Response or that
  Assertion, against the IdP certificate pinned from its metadata.
- Issuer, Audience, Destination, Recipient, InResponseTo (SP-initiated),
  NotBefore/NotOnOrAfter with ±2 min skew, and a replay cache of assertion
  IDs until they expire.
- Size and token limits, and no DTDs.

**Consequence for the toolchain:** gosaml2 requires Go 1.25. The repository is
on Go 1.24, which left support when Go 1.26 was released, so the module and
the build image move to **Go 1.26** (supported), still building with the FIPS
140 module `GOFIPS140=v1.0.0`.

## Alternatives
- **`crewjam/saml`:** rejected for its maintenance record (no release since
  2025-04) and its pinned goxmldsig v1.4.0; it would need a fork or a
  dependency override to get current signature fixes.
- **Our own SP on `goxmldsig` directly:** more code we own in the most
  attack-prone part of SAML (response and assertion validation), for no gain
  over gosaml2, which is a thin SP over the same library.

## Consequences
- New dependencies: `russellhaering/gosaml2`, `russellhaering/goxmldsig`,
  `beevik/etree`, `mattermost/xml-roundtrip-validator`, `jonboulle/clockwork`
  (and govulncheck in CI covers them).
- Go 1.26 for the module, CI (`go-version-file`), the Dockerfile and the test
  image.
- Library updates are reviewed against goxmldsig's and gosaml2's advisories;
  the XSW corpus runs in CI on every change.
