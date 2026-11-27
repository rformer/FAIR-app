# fair.install-decisions.v1: the decisions file

F-014 T-12 (design §3.4, AC-14). `fairctl install -decisions FILE` and `fairctl preflight -decisions FILE` read every install-time decision from a YAML file instead of asking. `internal/installer.Decisions` is the authority.

## Rules
- **Strict.** One YAML document; unknown fields, aliases and a second document are refused. Every problem is listed by field, not only the first.
- **No secrets.** Credentials are given as the paths of files that hold them (the `*_file` fields), never as values. Before the file is decoded, every key and value is checked: a value that looks secret (a JWT, any PEM block, a bearer or basic credential, a URL with a password, a provider token such as `AKIA…`, `ghp_…`, `hvs.…`, or a long random string mixing upper case, lower case and digits), or a field naming a secret (`password`, `secret`, `token`, `credential`, `access_key`, …) that is not a `*_file` path, refuses the whole file before anything runs. The refusal names the line and field, never the value.
- **Relative paths** resolve against the decisions file's directory.
- Decisions recorded at install are never replaced: resuming with the same value is accepted, a different one refused (`install.record_decision`).

## Fields
| Field | Values |
|---|---|
| `format` | `fair.install-decisions.v1` |
| `operator` | the operator's name, recorded as `operator:<name>` |
| `mode` | `saas`, `self-hosted` or `air-gapped` |
| `profile` | a built-in posture profile |
| `currency` | ISO 4217, e.g. `USD` |
| `idp` | `kind` (`saml`: `metadata_file`; `oidc`: `issuer`, `client_id`, `client_secret_file`; `keycloak`: the bundled Keycloak), `name`, `domains` |
| `admin` | the first Platform Admin: `email`, `subject` (their IdP subject) |
| `scanner` | `access`: `grant` (with `manifest_sha256`, the permission manifest accepted) or `decline` |
| `node_fips` | `evidence`: `probe`, or `attest` with a `reason` |
| `attestations` | `pod_security` (`reason`), `storage_encryption` (`class`, `reason` each); recorded "attested, not verified" |
| `break_glass` | `enabled`; when on, `reason` and `holders` (emails) |
| `overrides` | `check`, `subject`, `reason` each; never the hard floor; none in SaaS |
| `sizes` | `audit_storage_quota` (`500Gi`), `replicas` (Deployment: 2 to 20) |
| `hosts` | `platform`, `ingress`, `keycloak` (bundled Keycloak only), `ingress_cidr`, `api_server_cidr` (IPv4, /8 to /32) |
| `registry` | the private registry holding the images |
| `key_store` | `kind`: `kubernetes-secrets` or `openbao` (brought: `address`, `ca_file`, `token_file`; bundled: none) |
| `tls` | `issuer`: `installation-ca` (default), `cert-manager` (`cert_manager_issuer`) or `files` (`ca_file`, `cert_file`, `key_file`) |
| `dependencies` | `postgres`, `nats`, `object_store`, `keycloak`, `openbao`, `collector`: `bundled: true`, or the brought dependency's endpoint and credential files (below) |

Brought dependencies: `postgres` (`host`, `port`, `database`, `admin_user`, `admin_password_file`, `ca_file`; the administrative connection is used only to bootstrap the roles), `nats` (`url` `tls://` or `nats://`, `ca_file`, `credentials_file`), `object_store` (`endpoint` https, `region`, `access_key_file`, `secret_key_file`, `ca_file`, `create_buckets`); for both forms `audit_bucket`, `report_bucket` and, where F-002 requires it, `worm_bucket`. `collector` brought: an optional `endpoint`. Air-gapped installations refuse public addresses.

## Example
```yaml
format: fair.install-decisions.v1
operator: Jane Admin
mode: self-hosted
profile: fedramp-moderate
currency: USD
idp:
  kind: oidc
  name: Corporate SSO
  issuer: https://login.example.com/
  client_id: fair-platform
  client_secret_file: secrets/oidc-client-secret
  domains: [example.com]
admin:
  email: jane.admin@example.com
  subject: "00u1a2b3c4d5e6f7g8h9"
scanner:
  access: grant
  manifest_sha256: 3f5b9c8a6e0d1f2a4b7c9e0d1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2
node_fips:
  evidence: probe
attestations:
  pod_security:
    reason: Restricted pod security is enforced cluster-wide by the platform team's admission policy
  storage_encryption:
    - class: gp3-encrypted
      reason: The storage class uses KMS-encrypted volumes
break_glass:
  enabled: false
overrides: []
sizes:
  audit_storage_quota: 500Gi
  replicas:
    gateway: 3
hosts:
  platform: fair.example.com
  ingress_cidr: 10.20.0.0/16
  api_server_cidr: 10.0.0.0/24
registry: registry.example.com/fair
key_store:
  kind: openbao
  address: https://openbao.example.com:8200
  ca_file: certs/openbao-ca.pem
  token_file: secrets/openbao-admin-token
tls:
  issuer: installation-ca
dependencies:
  postgres:
    host: db.example.com
    port: 5432
    database: fair
    admin_user: fair_admin
    admin_password_file: secrets/postgres-admin-password
    ca_file: certs/postgres-ca.pem
  nats:
    bundled: true
  object_store:
    endpoint: https://s3.example.com
    region: us-east-1
    audit_bucket: fair-audit
    report_bucket: fair-reports
    worm_bucket: fair-audit-worm
    access_key_file: secrets/s3-access-key
    secret_key_file: secrets/s3-secret-key
  keycloak:
    bundled: false
  openbao:
    bundled: false
  collector:
    bundled: true
```
