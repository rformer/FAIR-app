# ADR-018 KMS release signing: the AWS SDK for Go v2, in releasegen only
Status: Accepted (Robert Former, 2026-11-20; F-012 T-06)
Date: 2026-11-20

## Context
F-012 signs each release twice (design §3.3, OQ6):
- keylessly, with Sigstore;
- with a release key held in AWS KMS: ECDSA P-256, in a FIPS 140-validated HSM, in the shared-services account.

The KMS key's signatures let an air-gapped customer verify a release offline with `cosign.pub` alone.

cosign signs and attests the images itself (`--key awskms:///…`). The release manifest, `SHA256SUMS` and the profile packages are signed by `releasegen`. Those signatures must keep the format file keys already produce: base64 ASN.1 DER over SHA-256 (`profilepkg.Sign`). Then `releasegen verify`, the posture scanner and the offline verifier check them unchanged.

`internal/kmssign` therefore has to:
- call KMS `GetPublicKey` and `Sign` (message type DIGEST, `ECDSA_SHA_256`);
- authenticate as a sign-only role, assumed with the release workflow's GitHub OIDC token through STS `AssumeRoleWithWebIdentity`;
- use FIPS endpoints only, since GovCloud SCPs deny the others.

Three clients were weighed with the user on 2026-11-20:
- **The AWS SDK for Go v2**: only `service/kms`, `service/sts` and `credentials/stscreds`, without the `config` package and its SSO and IMDS providers.
- **An own minimal SigV4 client**: one signed KMS call and one unsigned STS call, standard library only. ADR-012 weighed this approach for S3 and rejected it, because we would maintain request signing ourselves.
- **Shelling out to `cosign sign-blob --key awskms://`**: no Go KMS code at all. But the design names `internal/kmssign`, so this needed a design change.

Facts as of 2026-11-20 (module proxy). The newest releases at least two weeks old were chosen:
- `github.com/aws/aws-sdk-go-v2/service/kms` v1.62.4, `service/sts` v1.51.8 and `credentials` v1.20.15, all released 2026-11-05.
- Minimum version selection then gives `aws-sdk-go-v2` v1.47.7 and `aws/smithy-go` v1.28.8, plus the SDK's internal modules (`internal/configsources`, `internal/endpoints/v2`, `internal/v4a`, `service/internal/accept-encoding`, `service/internal/presigned-url`).
- **Signing:** SigV4 uses Go's `crypto/hmac` and `crypto/sha256`, so it runs in the FIPS module when built with `GOFIPS140=v1.0.0`. The SDK's `internal/v4a` (SigV4a, ECDSA) is linked but never used for KMS or STS.
- **Where it is linked:** only `cmd/releasegen` imports `internal/kmssign`, and no service binary links the SDK (checked with `go list -deps ./cmd/...`). The service images, their SBOMs and their vulnerability scans are unchanged.

## Decision
Use the **AWS SDK for Go v2**: `service/kms`, `service/sts` and `credentials/stscreds` at the versions above. It is wrapped in `internal/kmssign`, so the rest of the code sees only `kmssign.API` (`GetPublicKey`, `Sign`), and tests use a fake.

`internal/kmssign` constrains it:
- **Key check:** `New` refuses any key whose spec is not `ECC_NIST_P256` or whose usage is not `SIGN_VERIFY`, before anything is signed.
- **Signature check:** every signature KMS returns is verified against the key's public half before it is returned. A wrong key or a corrupted answer therefore never becomes a release signature.
- **Credentials:** only a web identity token file (`AWS_WEB_IDENTITY_TOKEN_FILE`, the job's OIDC token) for the role `AWS_ROLE_ARN`. No access keys are read from the environment or from configuration files.
- **Endpoints:** both KMS and STS use their FIPS endpoints (`UseFIPSEndpoint`).
- **Format:** the output is exactly `profilepkg.Sign`'s: base64 DER plus a newline.

## Consequences
- `go.mod` gains the SDK modules listed above. Dependabot updates them with the other Go modules, and `govulncheck` covers them.
- `releasegen sign -kms KEY -region R` and `releasegen public` work in the release workflow (`.github/workflows/release-sign.yml`). Until the shared-services account and its key exist (F-012 T-12), they are exercised only against the fake in `internal/kmssign` tests.
- If the SDK has to be replaced, only `internal/kmssign.Client` changes.
- F-012 T-18 (2026-11-26): `cmd/accessctl` (just-in-time operator access, design §3.9) adds `service/ssoadmin` v1.52.4, `service/eks` v1.105.4 and `service/iam` v1.64.8, of the same SDK release as `service/kms` v1.62.4 (2026-11-05), so the core stays at v1.47.7. They are wrapped in `internal/accessctl` behind small interfaces with fakes in tests, with credentials only from the web identity token file and FIPS endpoints, as above. Only `cmd/accessctl` links them, and the SDK is linked only into `cmd/accessctl` and `cmd/releasegen` (`TestSDKLinkedOnlyIntoTools`, over `go list -deps ./cmd/...`).
