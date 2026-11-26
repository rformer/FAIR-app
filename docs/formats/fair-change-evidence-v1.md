# fair.change-evidence.v1: change evidence

F-012 T-17 (F-012-AC-26; design §3.8, §6 "T, R: unreviewed or unattributed production changes"). `cmd/evidence` exports, for a period and optionally one instance, the chain behind every production change: the pull request, its approver (never its author), the required checks, the release and its signatures, and the deployment to each instance. Every gap in the chain is a **finding**. A gap never fails the export: finding gaps is what the export is for.

```
evidence -repo OWNER/NAME -fleet-repo OWNER/FLEET -from 2026-11-01 -to 2026-11-30 [-instance ID] \
  -token-file /run/secrets/github-token -release-pub cosign.pub \
  -flux-events ./flux-events -key evidence.pem -out ./evidence-2026-11
```

- **Inputs.** The GitHub REST API (read only; the token comes from `-token-file`, never from the environment; HTTPS with TLS 1.2 or later; every page of every list) and Flux's events. The operations account's receiver keeps Flux's events in the Object Lock evidence bucket (`deploy/fleet/flux/notifications.yaml`, `infra/modules/observability`). Copy the period's objects to a directory and pass it as `-flux-events`. The tool reads every `.json` and `.jsonl` file there, each holding one or more events.
- **Days** are UTC. `-from` is the first day and `-to` the last day (inclusive). In the file, `from` is inclusive and `to` exclusive.
- **Required checks** come from `-checks` (default `infra/github/variables.tf`, the branch rule's `required_checks`). **Release jobs** come from `-release-jobs` (default `build,provenance,sign,publish,verify`).
- **Output.** `change-evidence.json` and `change-evidence.csv` in `-out`. Each has a detached signature, `.sig`: base64 ASN.1 DER ECDSA P-256 over SHA-256, the `releasegen sign` format. The key is the evidence key, a PEM file (`-key`). Use a key dedicated to evidence (design §3.8), not the release key. For an evidence key in AWS KMS, export with `-unsigned` and sign each file with `releasegen sign -any -kms KEY -region REGION -in FILE`, which writes the same format (ADR-018 keeps the AWS SDK in `releasegen` alone). Check a file with `releasegen verify -any -pub evidence.pub -in change-evidence.json`.
- **Determinism.** The same inputs always give the same bytes. Lists are sorted, nothing records when the export ran, and times are RFC 3339 UTC.
- **Exit code.** 0 when both files are written, whether or not there are findings (a summary goes to stderr). 1 on an error, such as an API failure, a bad key or a malformed event. On an error nothing is written.

## What is collected

- **Pull requests**: every pull request merged into the branch (`-branch`, default `main`) of the repository and of the fleet repository during the period. A release also brings in the pull requests of all its commits, including any merged earlier. Each entry records its reviews and its **approvers**. An approver is a reviewer whose latest review approved the merged head commit, and who is neither the pull request's author nor the author of any of its commits. For the platform repository, each entry also records the required checks' latest runs on the merged head. GitHub accepts `success`, `neutral` and `skipped` for a required check.
- **Releases**: published (not draft) releases from the period, releases deployed during the period, and releases named by `-release`. For each one, the tool reads `release-manifest.json`, `SHA256SUMS` and their `.sig` files and checks them against the release key (`-release-pub`). It also checks that the release's `cosign.pub` is that key, and records the images the signed manifest names. It records the release workflow's latest run for the tag and its jobs. `build` (keyless signature and SBOM attestation), `provenance` (SLSA Build L3), `sign` (the release key's signatures and attestations), `publish`, and `verify` (`scripts/verify-release.sh` online and offline, which verifies every image's signatures and SPDX and SLSA attestations) must each have succeeded. A matrix job `name (x)` or a reusable workflow job `name / x` counts as `name`. Every commit since the previous release (`compare`) must have come from a merged pull request. For the first release, `-first-base` names the commit to count from.
- **Deployments**: the rollouts of a release to each instance, derived from Flux's events. A rollout starts with the first `Kustomization` event about a release revision (`vX.Y.Z@sha256:…`) other than the one the instance runs. It succeeds when `fair-platform` reports `ReconciliationSucceeded` for that revision. Otherwise it is `failed` (error events only) or `incomplete` (no outcome by the period's end). Events from before the period only set the starting state. `fleet_commit` is the fleet repository's commit (`flux-system`, `…@sha1:…`) last applied before the rollout started. `fleet_pull_request` is the merged pull request that brought that commit in.
- **Infrastructure applies**: each `apply (<instance>)` job of `infra-instances.yml`'s push runs on the branch during the period, with the approvals of the protected environment `instances` and the pull request behind the run's commit. Runs with no apply job are left out.
- **`-instance ID`** keeps only that instance's deployments and applies, the releases it ran, the pull requests behind them, and the findings about any of these.

## The file

```json
{
  "format": "fair.change-evidence.v1",
  "repository": "acme/fair",
  "fleet_repository": "acme/fleet",
  "from": "2026-11-01T00:00:00Z",
  "to": "2026-12-01T00:00:00Z",
  "required_checks": ["lint", "test"],
  "release_jobs": ["build", "provenance", "publish", "sign", "verify"],
  "pull_requests": [{
    "id": "acme/fair#12", "repository": "acme/fair", "number": 12, "title": "…", "url": "…",
    "author": "alice", "merged_at": "…", "merge_commit": "…", "head": "…",
    "approvers": ["bob"],
    "reviews": [{ "user": "bob", "state": "APPROVED", "commit": "…", "submitted_at": "…" }],
    "checks": [{ "name": "lint", "conclusion": "success", "url": "…" }]
  }],
  "releases": [{
    "tag": "v0.2.0", "url": "…", "published_at": "…", "prerelease": false, "commit": "…", "previous": "v0.1.1",
    "manifest": "<sha256 of release-manifest.json>",
    "manifest_signature": "verified", "sums_signature": "verified", "release_key": "matches",
    "images": { "iam": "ghcr.io/…/fair-iam@sha256:…" },
    "run": { "id": 500, "url": "…", "commit": "…", "conclusion": "success", "jobs": [{ "name": "verify", "conclusion": "success" }] },
    "commits": 2, "pull_requests": ["acme/fair#11", "acme/fair#12"]
  }],
  "deployments": [{
    "id": "alpha:v0.2.0:2026-11-22T10:01:00Z", "instance": "alpha", "release": "v0.2.0", "artifact": "sha256:…",
    "status": "succeeded", "started_at": "…", "completed_at": "…", "errors": 0,
    "fleet_commit": "…", "fleet_pull_request": "acme/fleet#3"
  }],
  "infrastructure_applies": [{
    "id": "alpha:700", "instance": "alpha", "run": 700, "url": "…", "commit": "…", "created_at": "…",
    "triggered_by": "alice", "conclusion": "success", "pull_request": "acme/fair#12",
    "approvals": [{ "user": "bob", "state": "approved", "comment": "plan reviewed" }]
  }],
  "findings": [{ "code": "no_approval", "subject": "pull_request:acme/fair#9", "detail": "merged without an approving review" }]
}
```

`manifest_signature` and `sums_signature` are `verified`, `missing` or `invalid`. `release_key` is `matches`, `missing` or `differs`. A check's `conclusion` is GitHub's conclusion, the run's status while it has not completed, or `missing`. A finding's `subject` is `pull_request:<id>`, `release:<tag>`, `deployment:<id>`, `apply:<id>`, `commit:<repository>@<sha>` or `instance:<id>`. `instance` and `release` appear on a finding when it concerns one.

## The CSV

There is one header row, then one row per pull request, release, deployment and apply, then one row per finding. The columns are `record,id,instance,time,actor,approvers,release,status,url,findings`. On item rows, `findings` lists the codes of the findings about that item, separated by `;`. On finding rows, `status` is the code and `findings` is the detail. A cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return is prefixed with `'`, so a spreadsheet never reads it as a formula.

## Findings

| Code | Gap |
|---|---|
| `no_approval` | Merged without an approving review |
| `self_approval` | Approved only by its author or by an author of one of its commits |
| `stale_approval` | Approved, but not on the merged head commit |
| `check_missing` | A required check has no run on the merged head |
| `check_failed` | A required check did not pass |
| `commit_without_pull_request` | A release commit came from no merged pull request (a direct push) |
| `release_not_found` | A deployed or named release is not a published GitHub release |
| `release_base_unknown` | The first release, with no `-first-base`: its commits are not paired |
| `release_unsigned` | `release-manifest.json` or its signature is missing |
| `release_signature_invalid` | The manifest's signature does not verify with the release key |
| `release_manifest_mismatch` | The signed manifest names another release |
| `release_sums_unsigned` | `SHA256SUMS` or its signature is missing |
| `release_sums_invalid` | `SHA256SUMS`'s signature does not verify, or the file does not list the manifest with its digest |
| `release_key_mismatch` | The release's `cosign.pub` is missing or is not the release key |
| `release_run_missing` | No release workflow run for the tag |
| `release_job_missing` | A required release job is not in the run |
| `release_job_failed` | A required release job did not succeed |
| `release_source_refused` | An instance's Flux refused the release artifact (for example, its signature did not verify) |
| `deployment_failed` | A rollout produced only errors |
| `deployment_incomplete` | A rollout had no outcome by the period's end |
| `deployment_unknown_release` | The instance ran a revision that is no published release |
| `deployment_unsigned_release` | The deployed release's manifest is not verified |
| `deployment_without_fleet_commit` | No fleet repository revision was applied before the rollout |
| `deployment_without_pull_request` | The fleet commit came from no merged pull request |
| `deployment_unapproved` | The fleet pull request has no approver other than its authors |
| `fleet_change_not_checked` | No `-fleet-repo` was given, so the rollout's fleet commit could not be paired |
| `apply_unapproved` | An apply ran without an approval of the environment `instances` |
| `apply_self_approved` | An apply was approved only by the person who started the run |
| `apply_failed` | An apply failed |
| `apply_not_completed` | A merged change was not applied: cancelled, skipped, rejected or still waiting |
| `apply_without_pull_request` | The applied commit came from no merged pull request |
