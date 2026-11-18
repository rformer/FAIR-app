import { useEffect, useState } from "react";
import { describe, send } from "../api";
import { Badge, ReasonAction, Section, Status, useApi, type Tone } from "../components";
import { auditHref } from "../links";
import { Counts } from "./Runs";
import {
  dateTime,
  DELIVERY_LABEL,
  KIND_LABEL,
  TRIGGER_LABEL,
  type Connector,
  type Delivery,
  type InputKind,
  type Integration,
  type Run,
} from "./types";

// F-011 T-18 (F-011-AC-01 to AC-05, AC-08; design §3.1, §6.1): integrations,
// served by the integrate service. Who may do what is the database's
// (integration.view or integration.manage at the integration's business
// unit); the pages offer what the API would accept and show its refusals.
// Credentials are write-only: the page says when each was set, never what
// it is.

interface Options {
  bus: { id: string; code: string; name: string }[];
  service_accounts: { id: string; name: string; bu_id: string; bu_name: string }[];
}

const STATE_TONE: Record<Integration["state"], Tone> = { active: "ok", paused: "warn", deleted: "muted" };
const STATE_LABEL: Record<Integration["state"], string> = { active: "Active", paused: "Paused", deleted: "Deleted" };

export function StateBadge({ state }: { state: Integration["state"] }) {
  return <Badge tone={STATE_TONE[state]}>{STATE_LABEL[state]}</Badge>;
}

function Crumbs({ children }: { children?: React.ReactNode }) {
  return (
    <nav aria-label="Breadcrumb" className="crumbs">
      <a href="/integrations">Integrations</a>
      {children ? <> / {children}</> : null}
    </nav>
  );
}

export function IntegrationsPage() {
  const [deleted, setDeleted] = useState(false);
  const list = useApi<{ integrations: Integration[] }>(`/api/v1/integrations${deleted ? "?deleted=true" : ""}`);
  const options = useApi<Options>("/api/v1/integrations/options");
  useEffect(() => {
    document.title = "Integrations · FAIR Risk Platform";
  }, []);
  return (
    <>
      <h1>Integrations</h1>
      <p className="lede">
        Sources of assets, loss events, risks and control status. What they send is checked record by record and proposed for
        review; nothing an analysis uses changes until someone accepts it.
      </p>
      <p className="actions">
        {options.data && options.data.bus.length > 0 ? (
          <a className="react-aria-Button primary" href="/integrations/new">
            New integration
          </a>
        ) : null}
        <a className="react-aria-Button" href="/integrations/proposals">
          Review proposed changes
        </a>
        <a className="react-aria-Button" href="/integrations/loss-events">
          Loss events
        </a>
      </p>
      <Section id="integrations" title="Integrations">
        <div className="filters">
          <label>
            <input type="checkbox" checked={deleted} onChange={(e) => setDeleted(e.target.checked)} /> Include deleted integrations
          </label>
        </div>
        <Status loaded={list}>
          {(d) =>
            d.integrations.length === 0 ? (
              <p>No integrations you can see.</p>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <caption className="sr-only">Integrations by name</caption>
                  <thead>
                    <tr>
                      <th scope="col">Name</th>
                      <th scope="col">Business unit</th>
                      <th scope="col">Brings</th>
                      <th scope="col">Delivery</th>
                      <th scope="col">State</th>
                      <th scope="col">Last run</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.integrations.map((i) => (
                      <tr key={i.id}>
                        <td>
                          <a href={`/integrations/${i.id}`}>{i.name}</a>
                        </td>
                        <td>{i.bu_name ?? "—"}</td>
                        <td>{KIND_LABEL[i.kind]}</td>
                        <td>{DELIVERY_LABEL[i.delivery]}</td>
                        <td>
                          <StateBadge state={i.state} />
                          {i.failures > 0 ? (
                            <>
                              {" "}
                              <Badge tone="bad">{i.failures === 1 ? "1 failed run" : `${i.failures} failed runs`}</Badge>
                            </>
                          ) : null}
                        </td>
                        <td>{dateTime(i.last_run_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          }
        </Status>
      </Section>
    </>
  );
}

interface Draft {
  bu_id: string;
  name: string;
  kind: InputKind;
  delivery: Delivery;
  mapping: string;
  type: Connector["type"];
  source: string;
  schedule: string;
  settings: string;
  service_account_id: string;
  auto_accept: boolean;
}

function draftOf(i?: Integration): Draft {
  return {
    bu_id: i?.bu_id ?? "",
    name: i?.name ?? "",
    kind: i?.kind ?? "assets",
    delivery: i?.delivery ?? "push",
    mapping: i && Object.keys(i.mapping).length > 0 ? JSON.stringify(i.mapping, null, 2) : "",
    type: i?.connector?.type ?? "http_json",
    source: i?.connector?.source ?? "",
    schedule: String(i?.connector?.schedule_minutes ?? 60),
    settings: i?.connector?.settings ? JSON.stringify(i.connector.settings, null, 2) : "",
    service_account_id: i?.service_account_id ?? "",
    auto_accept: i?.auto_accept ?? false,
  };
}

/** The body the API takes, or the field that does not parse. */
function bodyOf(d: Draft): { body?: Record<string, unknown>; error?: string } {
  const parse = (label: string, s: string): { v?: unknown; error?: string } => {
    if (!s.trim()) return { v: undefined };
    try {
      return { v: JSON.parse(s) };
    } catch {
      return { error: `${label} is not valid JSON.` };
    }
  };
  const m = parse("The mapping", d.mapping);
  if (m.error) return { error: m.error };
  const body: Record<string, unknown> = {
    name: d.name.trim(),
    mapping: m.v ?? {},
    auto_accept: d.auto_accept,
    service_account_id: d.service_account_id || null,
  };
  if (d.delivery === "connector") {
    const s = parse("The connector settings", d.settings);
    if (s.error) return { error: s.error };
    body.connector = { type: d.type, source: d.source.trim(), schedule_minutes: Number(d.schedule), ...(s.v ? { settings: s.v } : {}) };
  }
  return { body };
}

export function IntegrationForm({ id }: { id?: string }) {
  const existing = useApi<Integration>(id ? `/api/v1/integrations/${id}` : null);
  const options = useApi<Options>("/api/v1/integrations/options");
  const [d, setD] = useState<Draft>(() => draftOf());
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    document.title = `${id ? "Change integration" : "New integration"} · Integrations · FAIR Risk Platform`;
  }, [id]);
  useEffect(() => {
    if (existing.data) setD(draftOf(existing.data));
  }, [existing.data]);
  useEffect(() => {
    if (!id && options.data && !d.bu_id && options.data.bus[0]) setD((x) => ({ ...x, bu_id: options.data?.bus[0]?.id ?? "" }));
  }, [id, options.data, d.bu_id]);
  const set = (p: Partial<Draft>) => setD((x) => ({ ...x, ...p }));
  const accounts = options.data?.service_accounts ?? [];
  return (
    <>
      <Crumbs>{existing.data ? <a href={`/integrations/${existing.data.id}`}>{existing.data.name}</a> : null}</Crumbs>
      <h1>{id ? "Change integration" : "New integration"}</h1>
      {id ? (
        <p className="lede">The business unit, what it brings and how it is delivered stay as created.</p>
      ) : (
        <p className="lede">
          An integration writes only into its business unit's subtree, and only records of its kind. Inside a restricted business
          unit, only someone who manages integrations there may create one.
        </p>
      )}
      <Status loaded={options}>
        {(o) =>
          o.bus.length === 0 ? (
            <p>Managing integrations needs integration.manage, which you do not hold at any business unit.</p>
          ) : (
            <Section id="integration" title="The integration">
              <form
                className="form"
                onSubmit={async (e) => {
                  e.preventDefault();
                  const { body, error: bad } = bodyOf(d);
                  if (!body) {
                    setError(bad);
                    return;
                  }
                  setBusy(true);
                  setError(undefined);
                  try {
                    const saved = id
                      ? await send<Integration>("PUT", `/api/v1/integrations/${id}`, { ...body, expected_version: existing.data?.version })
                      : await send<Integration>("POST", "/api/v1/integrations", { ...body, bu_id: d.bu_id, kind: d.kind, delivery: d.delivery });
                    window.location.assign(`/integrations/${saved.id}`);
                  } catch (err) {
                    setError(describe(err));
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                <div className="field">
                  <label htmlFor="i-name">Name</label>
                  <input id="i-name" required maxLength={100} value={d.name} onChange={(e) => set({ name: e.target.value })} />
                </div>
                <div className="field">
                  <label htmlFor="i-bu">Business unit</label>
                  <select id="i-bu" value={d.bu_id} disabled={!!id} onChange={(e) => set({ bu_id: e.target.value })}>
                    {id && existing.data ? <option value={existing.data.bu_id}>{existing.data.bu_name}</option> : null}
                    {o.bus.map((b) => (
                      <option key={b.id} value={b.id}>
                        {b.name} ({b.code})
                      </option>
                    ))}
                  </select>
                </div>
                <div className="field">
                  <label htmlFor="i-kind">Brings</label>
                  <select id="i-kind" value={d.kind} disabled={!!id} onChange={(e) => set({ kind: e.target.value as InputKind })}>
                    {(Object.keys(KIND_LABEL) as InputKind[]).map((k) => (
                      <option key={k} value={k}>
                        {KIND_LABEL[k]}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="field">
                  <label htmlFor="i-delivery">Delivery</label>
                  <select id="i-delivery" value={d.delivery} disabled={!!id} onChange={(e) => set({ delivery: e.target.value as Delivery })}>
                    {(Object.keys(DELIVERY_LABEL) as Delivery[]).map((k) => (
                      <option key={k} value={k}>
                        {DELIVERY_LABEL[k]}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="field wide">
                  <label htmlFor="i-mapping">Mapping (JSON)</label>
                  <textarea
                    id="i-mapping"
                    rows={6}
                    className="mono"
                    value={d.mapping}
                    onChange={(e) => set({ mapping: e.target.value })}
                    aria-describedby="i-mapping-hint"
                  />
                  <p id="i-mapping-hint" className="muted">
                    Columns to fields, value tables and defaults; no expressions. For files the columns are CSV column names, for a
                    connector JSON pointers into each item (for example {'{"columns": {"/id": "external_id", "/name": "name"}}'}).
                    Pushed batches in the documented format need none.
                  </p>
                </div>
                {d.delivery === "connector" ? (
                  <fieldset className="wide">
                    <legend>Connector</legend>
                    <div className="field">
                      <label htmlFor="i-type">Connector</label>
                      <select id="i-type" value={d.type} onChange={(e) => set({ type: e.target.value as Connector["type"] })}>
                        <option value="http_json">HTTPS JSON</option>
                        <option value="servicenow_cmdb">ServiceNow CMDB</option>
                      </select>
                    </div>
                    <div className="field">
                      <label htmlFor="i-source">Source URL</label>
                      <input
                        id="i-source"
                        type="url"
                        required
                        maxLength={2048}
                        value={d.source}
                        onChange={(e) => set({ source: e.target.value })}
                        aria-describedby="i-source-hint"
                      />
                      <p id="i-source-hint" className="muted">
                        HTTPS only. Its host must be on the allow-list (integration.allowed_hosts); internal addresses are refused.
                      </p>
                    </div>
                    <div className="field">
                      <label htmlFor="i-schedule">Every (minutes)</label>
                      <input id="i-schedule" type="number" min={15} max={1440} required value={d.schedule} onChange={(e) => set({ schedule: e.target.value })} />
                    </div>
                    <div className="field wide">
                      <label htmlFor="i-settings">Settings (JSON)</label>
                      <textarea id="i-settings" rows={4} className="mono" value={d.settings} onChange={(e) => set({ settings: e.target.value })} />
                    </div>
                  </fieldset>
                ) : null}
                <div className="field">
                  <label htmlFor="i-sa">Service account</label>
                  <select id="i-sa" value={d.service_account_id} onChange={(e) => set({ service_account_id: e.target.value })} aria-describedby="i-sa-hint">
                    <option value="">None</option>
                    {accounts.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.name} ({a.bu_name})
                      </option>
                    ))}
                  </select>
                  <p id="i-sa-hint" className="muted">
                    A connector submits what it fetches as this service account, at the business unit or above it.
                  </p>
                </div>
                <div className="field">
                  <label>
                    <input type="checkbox" checked={d.auto_accept} onChange={(e) => set({ auto_accept: e.target.checked })} /> Accept changes
                    to names and descriptions at once
                  </label>
                </div>
                {error ? (
                  <p role="alert" className="error-text">
                    {error}
                  </p>
                ) : null}
                <div className="actions">
                  <button className="react-aria-Button primary" type="submit" disabled={busy}>
                    {id ? "Save changes" : "Create integration"}
                  </button>
                  <a className="react-aria-Button" href={id ? `/integrations/${id}` : "/integrations"}>
                    Cancel
                  </a>
                </div>
              </form>
            </Section>
          )
        }
      </Status>
    </>
  );
}

export function IntegrationPage({ id }: { id: string }) {
  const it = useApi<Integration>(`/api/v1/integrations/${id}`);
  const runs = useApi<{ runs: Run[]; more: boolean }>(`/api/v1/integrations/${id}/runs?limit=50`);
  const [notice, setNotice] = useState<string>();
  const [error, setError] = useState<string>();
  useEffect(() => {
    document.title = `${it.data?.name ?? "Integration"} · Integrations · FAIR Risk Platform`;
  }, [it.data]);
  const act = async (method: "POST" | "DELETE", path: string, body: unknown, done: string) => {
    setError(undefined);
    await send<Integration>(method, `/api/v1/integrations/${id}${path}`, body);
    setNotice(done);
    it.reload();
    runs.reload();
  };
  const tryAct = (method: "POST" | "DELETE", path: string, done: string) => async () => {
    try {
      await act(method, path, {}, done);
    } catch (err) {
      setError(describe(err));
    }
  };
  return (
    <>
      <Crumbs />
      <Status loaded={it}>
        {(i) => (
          <>
            <h1>{i.name}</h1>
            <p className="lede">
              <StateBadge state={i.state} /> {KIND_LABEL[i.kind]} into {i.bu_name ?? "its business unit"} and below, {DELIVERY_LABEL[i.delivery].toLowerCase()}.
            </p>
            <div aria-live="polite">
              {notice ? <p className="ok-text">{notice}</p> : null}
              {error ? (
                <p role="alert" className="error-text">
                  {error}
                </p>
              ) : null}
            </div>
            {i.state !== "deleted" ? (
              <div className="actions">
                <a className="react-aria-Button" href={`/integrations/${i.id}/edit`}>
                  Change
                </a>
                {i.state === "active" ? (
                  <button className="react-aria-Button" type="button" onClick={tryAct("POST", "/pause", "Paused: batches and runs are refused until it resumes.")}>
                    Pause
                  </button>
                ) : (
                  <button className="react-aria-Button" type="button" onClick={tryAct("POST", "/resume", "Resumed.")}>
                    Resume
                  </button>
                )}
                {i.delivery === "connector" && i.state === "active" ? (
                  <>
                    <button className="react-aria-Button" type="button" onClick={tryAct("POST", "/run", "A run was queued; it starts within a minute.")}>
                      Run now
                    </button>
                    <TestAction id={i.id} />
                  </>
                ) : null}
                <a className="react-aria-Button" href={`/integrations/proposals?integration=${i.id}`}>
                  Proposed changes
                </a>
                <ReasonAction
                  label="Delete"
                  title={`Delete ${i.name}`}
                  fieldLabel="Why it is deleted"
                  description="Its credentials are removed. Its runs, and where every record it brought in came from, are kept."
                  submitLabel="Delete integration"
                  onSubmit={async (reason) => act("DELETE", "", { reason }, "Deleted.")}
                />
              </div>
            ) : (
              <p>Deleted {dateTime(i.deleted_at)}. Its runs and the provenance of what it brought in are kept.</p>
            )}
            <Section id="details" title="Details">
              <dl className="facts">
                <dt>Service account</dt>
                <dd>{i.service_account_name ?? "None"}</dd>
                <dt>Accepts name and description changes at once</dt>
                <dd>{i.auto_accept ? "Yes" : "No"}</dd>
                {i.connector ? (
                  <>
                    <dt>Connector</dt>
                    <dd>{i.connector.type === "servicenow_cmdb" ? "ServiceNow CMDB" : "HTTPS JSON"}</dd>
                    <dt>Source</dt>
                    <dd className="mono">{i.connector.source}</dd>
                    <dt>Runs every</dt>
                    <dd>{i.connector.schedule_minutes} minutes</dd>
                    <dt>Next run</dt>
                    <dd>{i.run_requested_at ? "Requested, starting soon" : dateTime(i.next_run_at)}</dd>
                  </>
                ) : null}
                <dt>Failed runs in a row</dt>
                <dd>
                  {i.failures}
                  {i.last_failure ? <> (last: {i.last_failure})</> : null}
                </dd>
                <dt>Version</dt>
                <dd>{i.version}</dd>
                <dt>History</dt>
                <dd>
                  <a href={auditHref(`integration:${i.id}`)}>Audit trail of this integration</a>
                </dd>
              </dl>
            </Section>
            {i.delivery === "connector" ? <Credentials i={i} onChange={() => it.reload()} disabled={i.state === "deleted"} /> : null}
          </>
        )}
      </Status>
      <Section id="runs" title="Runs" intro="Each batch received, with its counts; a connector's failed runs too.">
        <Status loaded={runs}>
          {(d) =>
            d.runs.length === 0 ? (
              <p>No runs yet.</p>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <caption className="sr-only">Runs, newest first</caption>
                  <thead>
                    <tr>
                      <th scope="col">Started</th>
                      <th scope="col">How</th>
                      <th scope="col">By</th>
                      <th scope="col">Outcome</th>
                      <th scope="col">Counts</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.runs.map((r) => (
                      <tr key={r.id}>
                        <td>
                          <a href={`/integrations/${id}/runs/${r.id}`}>{dateTime(r.started_at)}</a>
                        </td>
                        <td>{TRIGGER_LABEL[r.trigger]}</td>
                        <td>{r.actor_name ?? "—"}</td>
                        <td>
                          {r.state === "succeeded" ? <Badge tone="ok">Received</Badge> : r.state === "failed" ? <Badge tone="bad">Failed</Badge> : <Badge tone="info">Running</Badge>}
                          {r.failure ? <> {r.failure}</> : null}
                        </td>
                        <td>{r.counts ? <Counts c={r.counts} inline /> : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          }
        </Status>
      </Section>
    </>
  );
}

/** Fetches the first page through the guard and maps it; nothing is submitted. */
function TestAction({ id }: { id: string }) {
  const [result, setResult] = useState<{ records: number; problems: { n: number; pointer: string; message: string }[] }>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  return (
    <>
      <button
        className="react-aria-Button"
        type="button"
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          setError(undefined);
          setResult(undefined);
          try {
            setResult(await send("POST", `/api/v1/integrations/${id}/test`, {}));
          } catch (err) {
            setError(describe(err));
          } finally {
            setBusy(false);
          }
        }}
      >
        Test the source
      </button>
      <div aria-live="polite" className="wide">
        {result ? (
          <>
            <p className="ok-text">
              The first page held {result.records} {result.records === 1 ? "record" : "records"}
              {result.problems.length === 0 ? ", all of which map. Nothing was submitted." : ". Nothing was submitted. The first problems:"}
            </p>
            {result.problems.length > 0 ? (
              <ul>
                {result.problems.map((p) => (
                  <li key={`${p.n}${p.pointer}`}>
                    Record {p.n}, <span className="mono">{p.pointer || "/"}</span>: {p.message}
                  </li>
                ))}
              </ul>
            ) : null}
          </>
        ) : null}
        {error ? (
          <p role="alert" className="error-text">
            The test failed: {error}
          </p>
        ) : null}
      </div>
    </>
  );
}

/** AC-03: write-only credentials; the page shows only when each was set. */
function Credentials({ i, onChange, disabled }: { i: Integration; onChange: () => void; disabled: boolean }) {
  const [purpose, setPurpose] = useState<"source" | "client">("source");
  const [form, setForm] = useState<"token" | "basic">("token");
  const [values, setValues] = useState({ token: "", username: "", password: "", client_secret: "" });
  const [msg, setMsg] = useState<{ ok?: string; error?: string }>({});
  const setAt = (p: string) => i.credentials.find((c) => c.purpose === p)?.set_at;
  const remove = async (p: "source" | "client") => {
    try {
      await send("DELETE", `/api/v1/integrations/${i.id}/credentials/${p}`, {});
      setMsg({ ok: `The ${p === "source" ? "source" : "service account"} credential was removed.` });
      onChange();
    } catch (err) {
      setMsg({ error: describe(err) });
    }
  };
  return (
    <Section id="credentials" title="Credentials" intro="Kept encrypted and never shown again once saved: replace or remove them.">
      <dl className="facts">
        <dt>Source credential</dt>
        <dd>{setAt("source") ? `Set ${dateTime(setAt("source"))}` : "Not set"}</dd>
        <dt>Service account's client secret</dt>
        <dd>{setAt("client") ? `Set ${dateTime(setAt("client"))}` : "Not set"}</dd>
      </dl>
      {!disabled ? (
        <form
          className="form"
          aria-label="Set a credential"
          autoComplete="off"
          onSubmit={async (e) => {
            e.preventDefault();
            const body =
              purpose === "client"
                ? { client_secret: values.client_secret }
                : form === "token"
                  ? { token: values.token }
                  : { username: values.username, password: values.password };
            try {
              await send("PUT", `/api/v1/integrations/${i.id}/credentials/${purpose}`, body);
              setValues({ token: "", username: "", password: "", client_secret: "" });
              setMsg({ ok: "Saved. It is not shown again." });
              onChange();
            } catch (err) {
              setMsg({ error: describe(err) });
            }
          }}
        >
          <div className="field">
            <label htmlFor="c-purpose">Credential</label>
            <select id="c-purpose" value={purpose} onChange={(e) => setPurpose(e.target.value as "source" | "client")}>
              <option value="source">The source's</option>
              <option value="client">The service account's client secret</option>
            </select>
          </div>
          {purpose === "source" ? (
            <div className="field">
              <label htmlFor="c-form">Form</label>
              <select id="c-form" value={form} onChange={(e) => setForm(e.target.value as "token" | "basic")}>
                <option value="token">Bearer token</option>
                <option value="basic">Username and password</option>
              </select>
            </div>
          ) : null}
          {purpose === "client" ? (
            <div className="field">
              <label htmlFor="c-secret">Client secret</label>
              <input id="c-secret" type="password" required value={values.client_secret} onChange={(e) => setValues({ ...values, client_secret: e.target.value })} />
            </div>
          ) : form === "token" ? (
            <div className="field">
              <label htmlFor="c-token">Token</label>
              <input id="c-token" type="password" required value={values.token} onChange={(e) => setValues({ ...values, token: e.target.value })} />
            </div>
          ) : (
            <>
              <div className="field">
                <label htmlFor="c-user">Username</label>
                <input id="c-user" required value={values.username} onChange={(e) => setValues({ ...values, username: e.target.value })} />
              </div>
              <div className="field">
                <label htmlFor="c-password">Password</label>
                <input id="c-password" type="password" required value={values.password} onChange={(e) => setValues({ ...values, password: e.target.value })} />
              </div>
            </>
          )}
          <div className="actions">
            <button className="react-aria-Button primary" type="submit">
              Save credential
            </button>
            {setAt("source") ? (
              <button className="react-aria-Button" type="button" onClick={() => void remove("source")}>
                Remove the source credential
              </button>
            ) : null}
            {setAt("client") ? (
              <button className="react-aria-Button" type="button" onClick={() => void remove("client")}>
                Remove the client secret
              </button>
            ) : null}
          </div>
        </form>
      ) : null}
      <div aria-live="polite">
        {msg.ok ? <p className="ok-text">{msg.ok}</p> : null}
        {msg.error ? (
          <p role="alert" className="error-text">
            {msg.error}
          </p>
        ) : null}
      </div>
    </Section>
  );
}
