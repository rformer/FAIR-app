# Branch protection (F-012 T-02, F-012-AC-01)

`infra/github/` holds the repository's rules for `main` as OpenTofu: changes
arrive only by pull request; every CI gate is a required check
(`required_checks`), run on the branch as it will merge; one approval from a
code owner (`.github/CODEOWNERS`) who did not push the last change; a new push
dismisses earlier approvals; review threads resolved; linear, signed history;
no force pushes or deletion. Nobody bypasses the rules unless
`bypass_actors` names a repository role, and GitHub records every bypass.

CI checks the code on every change (`infra` job: `tofu fmt`, `validate` and
`tofu test` with a mock provider). Applying it is a deliberate step, not CI's:

```sh
cd infra/github
export GITHUB_TOKEN=...   # a token that may administer the repository, from a secret store
tofu init -lockfile=readonly
tofu plan -out ruleset.plan   # review it
tofu apply ruleset.plan
```

Once applied, direct pushes to `main` stop: every change, including the
maintainer's own, needs a second engineer's approval. Apply it when a second
engineer is a code owner. Until then, the CI gates still run on every push,
and the evidence export (`cmd/evidence`, `docs/formats/fair-change-evidence-v1.md`)
reports each change merged without an approving review as a finding.

When a CI job is renamed or added, update `required_checks` in the same pull
request, or the rule waits for a check that never reports.
