# Installation keys

F-001 T-41 (design §10), extended by F-002 T-05 and F-003 T-04. This guide covers the keys and secrets that F-001's services, the audit service (F-002) and the risk service (F-003) hold: where they come from in each deployment mode, how to install them, and how to rotate them. F-015's own keys (the posture MAC key and the export signing key) are covered in the README.

## The rule

Every key is a file in every mode. The mode's secret store is the system of record and delivers the files into each service's `/keys` directory. The services only read files; nothing per request leaves the process.

| Mode | Store | Delivered by |
|---|---|---|
| SaaS | Cloud secret manager, encrypted under the instance's own KMS key | External Secrets Operator → Kubernetes Secrets (`deploy/k8s/keys/saas/external-secrets.yaml`, `secret-mounts.yaml`) |
| Self-hosted | OpenBao or Vault (KV v2) | OpenBao Agent native sidecar (`deploy/k8s/keys/openbao/`) |
| Self-hosted without OpenBao, or air-gapped | Kubernetes Secrets, with etcd envelope encryption | The installer, from `iam keys init` (`secret-mounts.yaml`) |

In production every service refuses to start if a key or secret file it is given is open to other users. A Secret mount needs `defaultMode` 0440; the agent writes 0640.

## The keys

`iam keys init -dir DIR` creates all of them. It uses the FIPS module's random source and writes files 0600 in 0700 directories. It never overwrites an existing file.

| Directory (store entry) | Files | Environment (all modes) |
|---|---|---|
| `gateway/jwt` | `<kid>.pem`: the internal-JWT signing key (ES256) | `FAIR_JWT_KEYS_DIR=/keys/jwt` |
| `gateway/login-ticket` | `<kid>.pem`: iam's ticket keys, public | `FAIR_LOGIN_TICKET_KEYS_DIR=/keys/login-ticket` |
| `gateway/secrets` | `session-pepper`, `token-pepper`, `db-context.key`, `db-context.id` | `FAIR_SESSION_PEPPER_FILE`, `FAIR_TOKEN_PEPPER_FILE`, `FAIR_DB_CONTEXT_KEY_FILE`, `FAIR_DB_CONTEXT_KEY_ID_FILE` (each `/keys/secrets/<file>`) |
| `iam/jwt` | the gateway's JWT keys, public | `FAIR_JWT_KEYS_DIR=/keys/jwt` |
| `iam/login-ticket` | `<kid>.pem`: the login-ticket signing key (ES256) | `FAIR_LOGIN_TICKET_KEYS_DIR=/keys/login-ticket` |
| `iam/secrets` | `token-pepper` (the gateway's) | `FAIR_TOKEN_PEPPER_FILE=/keys/secrets/token-pepper` |
| `posture/jwt` | the gateway's JWT keys, public | `FAIR_JWT_KEYS_DIR=/keys/jwt` |
| `audit/jwt` | the gateway's JWT keys, public | `FAIR_JWT_KEYS_DIR=/keys/jwt` |
| `audit/checkpoint` | `<kid>.pem`: the audit trail's checkpoint signing key (ECDSA P-256, F-002 design §6.3), plus earlier keys, public | `FAIR_AUDIT_CHECKPOINT_KEYS_DIR=/keys/checkpoint` |
| `risk/jwt` | the gateway's JWT keys, public | `FAIR_JWT_KEYS_DIR=/keys/jwt` |

A key directory made before F-002 has no `audit/`, and one made before F-003 no `risk/`: `iam keys upgrade -dir DIR` adds what is missing (`audit/` with the gateway's JWT public keys and a new checkpoint key, `risk/` with the JWT public keys) and changes nothing else. Load the new directories into the store as below.

`iam keys check -dir DIR` checks a whole set:
- every file is present;
- each signer holds exactly one private key, and its verifiers hold the matching public key;
- the token peppers match;
- nothing is open to other users.

## Installing

1. **Create the keys.** On a trusted workstation, or in an install Job:

   ```sh
   iam keys init -dir ./fair-keys
   ```

2. **Register the DB-context key** in the database, as `app_migrator`, like `iam migrate`. It is audited to the install log.

   ```sh
   PGDATABASE=fair PGSSLMODE=verify-full FAIR_MIGRATOR_PASSWORD_FILE=... iam keys register -dir ./fair-keys
   ```

3. **Load the store.**
   - **SaaS.** Create one secret per directory, `fair/<instance>/<service>/<dir>`: a JSON object with one field per file, encrypted with the instance's KMS key. With AWS:

     ```sh
     umask 077
     for d in gateway/jwt gateway/login-ticket gateway/secrets iam/jwt iam/login-ticket iam/secrets posture/jwt audit/jwt audit/checkpoint risk/jwt; do
       echo '{}' > entry.json
       for f in ./fair-keys/$d/*; do
         jq --arg k "$(basename "$f")" --rawfile v "$f" '. + {($k): $v}' entry.json > next.json && mv next.json entry.json
       done
       aws secretsmanager create-secret --name "fair/$INSTANCE/$d" --kms-key-id "$INSTANCE_KMS_KEY" --secret-string file://entry.json
     done
     rm entry.json
     ```

     The secret values go through files, never through command-line arguments.

     Then apply `saas/external-secrets.yaml` (with your instance id and region) and `secret-mounts.yaml`. The ExternalSecrets use workload identity, never static credentials.
   - **OpenBao or Vault.** Load each directory as one KV v2 entry, then apply the policies and enable Kubernetes auth:

     ```sh
     for d in gateway/jwt gateway/login-ticket gateway/secrets iam/jwt iam/login-ticket iam/secrets posture/jwt audit/jwt audit/checkpoint risk/jwt; do
       args=""; for f in ./fair-keys/$d/*; do args="$args $(basename "$f")=@$f"; done
       bao kv put "secret/fair/$d" $args
     done
     for s in gateway iam posture audit risk; do
       bao policy write "fair-$s" deploy/k8s/keys/openbao/policy-$s.hcl
       bao write "auth/kubernetes/role/fair-$s" bound_service_account_names="$s" \
         bound_service_account_namespaces=fair-platform audience=openbao token_policies="fair-$s" token_ttl=10m
     done
     ```

     Each service's role reads only its own entries. Put OpenBao's CA certificate in the ConfigMap `openbao-ca` (`ca.crt`), then apply `kubectl apply -k deploy/k8s/keys/openbao` and `sidecars.yaml`.
   - **Kubernetes Secrets** (air-gapped, or self-hosted without OpenBao):

     ```sh
     for d in gateway/jwt gateway/login-ticket gateway/secrets iam/jwt iam/login-ticket iam/secrets posture/jwt audit/jwt audit/checkpoint risk/jwt; do
       kubectl -n fair-platform create secret generic "fair-${d%%/*}-${d#*/}" --from-file="./fair-keys/$d"
     done
     ```

     Then apply `secret-mounts.yaml`. Enable etcd encryption at rest for Secrets (the F-015 deployment checks report it).

4. **Delete `./fair-keys`.** The store now holds the only copy.

## Rotating

Work on a copy of the key directory, taken from the store. Rotation adds a key; the old one keeps verifying until its tokens have expired.

| Kind | Command | Then |
|---|---|---|
| Internal JWT | `iam keys rotate -dir DIR -kind jwt` | Reload `gateway/jwt`, `iam/jwt`, `posture/jwt`, `audit/jwt` and `risk/jwt`. The old signing key becomes public, and the new key signs once the gateway picks it up. With OpenBao, all five refresh within a minute. With Secrets, roll out iam, posture, audit and risk before the gateway. |
| Login ticket | `iam keys rotate -dir DIR -kind login-ticket` | Reload `iam/login-ticket` and `gateway/login-ticket`. With Secrets, roll out the gateway before iam. |
| Audit checkpoint | `iam keys rotate -dir DIR -kind checkpoint` | Reload `audit/checkpoint` and roll out the audit service. The old key becomes public; the service records every key's public half, so checkpoints signed before stay verifiable. Never delete an old checkpoint key from the store. |
| DB context | `iam keys rotate -dir DIR -kind db-context` | `iam keys register -dir DIR`, reload `gateway/secrets` and roll out the gateway. Then `iam keys retire-db-context -id <old>`: contexts the old key signed stay valid for ten minutes, and the last active key cannot be retired. |

- **Removing old keys:** delete the old public `<kid>.pem` files from the store after the tokens they signed have expired (at most the JWT and ticket lifetimes). With OpenBao, a pod restart drops them from `/keys`.
- **Peppers do not rotate.** A new session pepper ends every session; a new token pepper invalidates every service-account secret. Replace them only after a compromise, and then expect that effect.

## Evidence

The CI job `deployment-modes` runs, per mode:
- `TestDeploymentModeMatrix`: keys from `iam keys init` registered and verifying; rotation; IdP metadata by URL refused only when air-gapped; break-glass SecOps alerts only in SaaS.
- `TestDeployManifests`: each mode's manifests deliver exactly this layout.
- In self-hosted mode, `scripts/openbao-e2e.sh`: a live OpenBao, the agent templates rendering the keys, `iam keys check`, least-privilege policies and an in-place rotation.
