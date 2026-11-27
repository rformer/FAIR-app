# ADR-021 Licences: signed files, a dedicated KMS key, offline verification, a limited state that never touches security
Status: Accepted (Robert Former, 2026-11-26; F-014 T-03, with the F-014 design approved 2026-11-26)
Date: 2026-11-26

## Context
ADR-005 requires licensing to work fully offline with signed files, and ADR-006 that security controls ship in every edition. F-014 R-04 and its open questions fixed what a licence is:
- **OQ6:** the vendor issues the first licence with a new installation identifier; the installer records it; later licences must carry it; a restore onto a new cluster keeps it. Copying a licence to a second installation cannot be detected offline and is a contractual matter.
- **OQ7:** a dedicated ECDSA P-256 key in the vendor's KMS (FIPS 140-validated HSM, as ADR-018), never the release key, its public key shipped in every release; a new key ships in a release before it signs; the previous key stays until every licence it signed has ended.
- **OQ8:** a licence limits its term, the installation, the deployment modes and the update entitlement (patch releases of a covered minor release are always installable). No feature editions; a named-user count is shown and reported, never enforced.
- **OQ9:** 30 days' grace; then a limited state that refuses only new simulation runs, new scenarios, library entries, controls and register risks, imports and connector runs, and new report schedules.
- **OQ16:** SaaS instances carry a licence too, issued at onboarding and renewed by the fleet, so the code path is the same in every mode.
- **D-OQ5:** in the limited state, new versions of existing items and the register's aggregates continue.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| Signed licence file verified offline (chosen) | Works air-gapped; nothing calls the vendor | Copying between installations is undetectable offline (contractual) |
| Online activation or periodic checks | Detects copies | Fails A7 and air-gapped installs (rejected by ADR-005) |
| Feature editions | Commercial flexibility | Security would vary by edition, against ADR-006 (OQ8) |
| Sign licences with the release key | No second key | A licence-issuing role could sign releases; one compromise breaks both |
| Hard stop at expiry | Simple | Stops governance and evidence; data held hostage (OQ9) |

## Decision
- **Format** `fair.license-file.v1`: one JSON file with `license` (canonical as `profilepkg.Encode`), `signature` (base64 ASN.1 DER ECDSA over the SHA-256 of the canonical licence, exactly `profilepkg.Sign`'s format) and `key_id` (SHA-256 of the key's SPKI). The licence carries `format`, `license_id`, `customer {id, name}`, `installation_id`, `modes` (a subset of `saas`, `self-hosted`, `air-gapped`), `not_before`, `not_after`, `updates_until`, an optional `named_users` and `issued_at` (design §3.9).
- **Key.** A dedicated `ECC_NIST_P256` `SIGN_VERIFY` KMS key, separate from the release key (ADR-016, ADR-018), with its own sign-only role that only vendor licensing may assume. Licences are signed with `releasegen sign -any -kms` through `internal/kmssign`, so no new SDK is linked. The key, its role and the signer's use for licences are recorded as an ADR-018 amendment with T-20.
- **Rotation.** Public keys are embedded in `internal/license/keys/` (covered by the image digests and the signed release manifest), each with a "valid for licences issued until" date. A new key ships in a release before it signs anything; an old key stays in releases until every licence it signed has ended.
- **Verification** in every mode, offline, in Go: the signature with a shipped key valid for the licence's `issued_at`, the schema, the installation identifier equal to the recorded one (the first licence brings it), the current mode permitted, `not_before` reached. A refusal is recorded (`license.refused`) with its reason, never the file. Nothing calls the vendor.
- **States**, computed on read from the current licence and the clock: `valid`, `expiring` (60 days or fewer left), `grace` (30 days after `not_after`), `limited`, and `none`. Transitions are recorded once with audit events, and Platform Admins are notified at 60, 30, 14 and 7 days and at grace and limited (F-009 source `install`). The thresholds and grace are constants, not settings: no security control depends on them.
- **Update entitlement.** `fairctl upgrade` refuses a release whose minor line was first released after `updates_until`, except patch releases of a covered minor line, so security fixes are never withheld.
- **Limited state.** One gate, `license.Gate` in the risk and integrate services' middleware, refuses with 409 `license_limited` exactly the OQ9 creations; everything else continues (sign-in, reads, new versions of existing items, acceptances, treatment, reports, exports, audit, posture, notifications, backups). `TestLicenseNeverGatesSecurity` requires the gated operations to be exactly that list and none of them in the iam, gateway, posture, audit or notify services or tagged with a security event. The licence never reads or writes a setting, and nothing is deleted or hidden.
- **Installing** a renewed licence: `fairctl license install FILE` or `PUT /api/v1/posture/license` (`license.manage`, privileged, with a reason), applied without a restart.
- **SaaS:** onboarding issues the instance's licence (installation identifier = the instance id) and the fleet renews it; the same code verifies it.

## Consequences
- The vendor's licensing operation needs the KMS key and role in the shared account (an F-012 infrastructure change) and a record of issued licences outside the platform.
- An installation's identifier is permanent; a restore onto a new cluster keeps it (ADR-022).
- Prose says "licence"; identifiers say `license` (D-OQ11).
