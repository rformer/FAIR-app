# fair.install-log.v1: the install log and the `fair-install` ConfigMap

F-014 T-12 (design §3.4). `fairctl install` records every step twice: in the local install log, which the operator keeps, and in the ConfigMap `fair-install`, which anyone who can read the platform namespace sees. Neither holds a value: the decisions are in the installation records (schema `install`), the credentials only in the mode's key store.

## The steps
In order; each is idempotent, and `install -resume` starts at the first step not `done`.

| Step | What it does |
|---|---|
| `verify` | verifies the package offline (`fairctl verify`, design §3.5) |
| `decisions` | reads the decisions (`-decisions FILE` or the prompts) |
| `preflight` | runs preflight; overrides from the command line or the decisions |
| `credentials` | generates the credentials and loads the key store |
| `database` | bootstraps the database roles |
| `provision` | creates the buckets and the JetStream streams |
| `chart` | installs the chart (hooks: in-cluster preflight, `iam migrate`) |
| `record` | records the installation, decisions, posture seed, consent, FIPS evidence, break-glass |
| `events` | replays the install log's events into the audit trail |
| `report` | writes the install report |

States: `pending`, `running`, `done`, `failed`. A step runs only after every earlier one is done, and a done step never runs again. A step interrupted while `running` stays so until it runs again.

## The install log
`fair-install.log` (or `-log FILE`), created with mode 0600 and appended one line at a time, each synced before the step goes on. Every line is a JSON object (`fair-install-log-v1.schema.json`):

```json
{"format":"fair.install-log.v1","time":"2026-11-27T10:00:00Z","kind":"step","step":"verify","state":"done"}
{"format":"fair.install-log.v1","time":"2026-11-27T10:00:05Z","kind":"event","event":{"id":"5f0c…","time":"2026-11-27T10:00:05Z","type":"install.decision_recorded","severity":"high","actor":"operator:Jane Admin","target":"install:decision","attributes":{"attested":"false","key":"mode"}}}
```

- `kind: step`: a step's new state.
- `kind: event`: an event for the audit trail, in the shape `install.submit_events` accepts: `id` and `time` fixed when it is logged (the replay keeps both, so replaying after an interruption records nothing twice), an installer type (`install.*`, `license.*`, `posture.deployment_exception_*`) described by the event catalog, the actor `operator:<name>` (the operator's stated name), `target`, `attributes`. The `events` step submits them in batches of at most 1,000.
- A line that looks secret (`installer.LooksSecret`: JWTs, PEM blocks, bearer and basic credentials, provider token shapes, long random strings) is refused, and the step fails, rather than written.
- A last line cut short by an interruption is ignored when the log is read; any other malformed line is an error.

## The `fair-install` ConfigMap
In namespace `fair-platform`, labelled `app.kubernetes.io/managed-by: fairctl`, written after each step's log line once the cluster is reachable:

```yaml
data:
  verify: done
  decisions: done
  preflight: done
  credentials: running
  database: pending
  provision: pending
  chart: pending
  record: pending
  events: pending
  report: pending
```

Keys are the step names and values their states; fairctl refuses to read a ConfigMap holding anything else. It writes it through the Helm SDK's Kubernetes client, as it does every write to the cluster; the read-only kube client never writes.
