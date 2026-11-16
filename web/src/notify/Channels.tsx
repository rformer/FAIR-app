import { useEffect, useState } from "react";
import { ApiError, describe, send } from "../api";
import { Badge, ReasonAction, Section, Status, useApi } from "../components";

// F-009 T-13 (F-009-AC-08 to AC-12, AC-17): the SMTP relay and webhooks,
// with their state, for notification.manage (changes) and notification.view
// (reads), and the delivery log.

interface Channel {
  id: string;
  kind: "smtp" | "webhook";
  name: string;
  config: Record<string, unknown>;
  bu_id: string | null;
  bu_name: string | null;
  kinds: string[];
  enabled: boolean;
  version: number;
  rotation_until: string | null;
  last_success: string | null;
  last_failure: string | null;
  last_error: string | null;
  backlog: number;
  failed_24h: number;
}

interface Delivery {
  id: string;
  created_at: string;
  kind: string;
  link: string;
  bu_name: string;
  channel_kind: string;
  channel_name: string;
  recipient: string | null;
  state: string;
  attempts: number;
  outcome: string | null;
  reason: string | null;
}

interface Kind {
  kind: string;
  label: string;
}

function when(s: string | null): string {
  if (!s) return "—";
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? s : d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

function problem(err: unknown): string {
  if (err instanceof ApiError && err.detail) return err.detail;
  return describe(err);
}

const STATE_TONE: Record<string, "ok" | "info" | "warn" | "bad" | "muted"> = { sent: "ok", pending: "info", sending: "info", failed: "bad", dropped: "muted" };

export function ChannelsPage() {
  useEffect(() => {
    document.title = "Notification channels · FAIR Risk Platform";
  }, []);
  const channels = useApi<{ channels: Channel[] }>("/api/v1/notifications/channels");
  const kinds = useApi<{ kinds: Kind[] }>("/api/v1/notifications/preferences");
  const bus = useApi<{ bus: { id: string; name: string; restricted: boolean }[] }>("/api/v1/notifications/bus");
  const [secret, setSecret] = useState<{ name: string; value: string }>();
  const [testResult, setTestResult] = useState<string>();
  if (channels.error instanceof ApiError && channels.error.status === 404) {
    return (
      <>
        <h1>Notification channels</h1>
        <p role="alert">Not found, or not visible to you.</p>
      </>
    );
  }
  const relay = channels.data?.channels.find((c) => c.kind === "smtp");
  const hooks = channels.data?.channels.filter((c) => c.kind === "webhook") ?? [];
  const test = async (c: Channel) => {
    setTestResult(undefined);
    try {
      const r = await send<{ sent: boolean; tls_version?: string; detail?: string }>("POST", `/api/v1/notifications/channels/${c.id}/test`, {});
      setTestResult(r.sent ? `Test message sent through ${c.name} (${r.tls_version ?? "TLS"}).` : `Test message to ${c.name} failed: ${r.detail ?? "unknown"}`);
      channels.reload();
    } catch (err) {
      setTestResult(problem(err));
    }
  };
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/notifications">Notifications</a>
      </nav>
      <h1>Notification channels</h1>
      <p className="lede">Where notices go besides the app. Destinations must be allowed by the setting notification.allowed_hosts.</p>
      <p className="actions">
        <a href="/notifications/deliveries">Delivery log</a>
      </p>
      {secret ? (
        <div className="banner warn" role="status">
          <p>
            The signing secret of {secret.name}, shown this once. Give it to the receiving system now; it cannot be shown again.
          </p>
          <p className="mono">{secret.value}</p>
        </div>
      ) : null}
      {testResult ? <p role="status">{testResult}</p> : null}
      <Status loaded={channels}>
        {() => (
          <>
            <Section id="relay" title="SMTP relay" intro="Email always over TLS 1.2 or later; the password is a file on the service, named here.">
              {relay ? <ChannelState c={relay} onTest={test} onChanged={channels.reload} /> : <p>No relay is configured: notices go to the app only.</p>}
              <RelayForm relay={relay} onSaved={channels.reload} />
            </Section>
            <Section id="webhooks" title="Webhooks" intro="Signed HTTPS posts of the notice kinds each takes, for a business unit subtree.">
              {hooks.length === 0 ? <p>No webhooks.</p> : hooks.map((h) => <ChannelState key={h.id} c={h} onTest={test} onChanged={channels.reload} onSecret={setSecret} />)}
              <WebhookForm kinds={kinds.data?.kinds ?? []} bus={bus.data?.bus ?? []} onCreated={(name, value) => (setSecret({ name, value }), channels.reload())} />
            </Section>
          </>
        )}
      </Status>
    </>
  );
}

function ChannelState({ c, onTest, onChanged, onSecret }: { c: Channel; onTest: (c: Channel) => void; onChanged: () => void; onSecret?: (s: { name: string; value: string }) => void }) {
  const act = (action: string) => async (reason: string) => {
    await send("POST", `/api/v1/notifications/channels/${c.id}/${action}`, { reason });
    onChanged();
  };
  return (
    <div className="card nested" role="group" aria-label={c.name}>
      <h3>
        {c.name} {c.enabled ? <Badge tone="ok">Enabled</Badge> : <Badge tone="muted">Disabled</Badge>}
      </h3>
      <dl className="summary">
        <div>
          <dt>Destination</dt>
          <dd className="mono">{c.kind === "smtp" ? `${String(c.config.host)}:${String(c.config.port)} (${String(c.config.tls_mode)})` : String(c.config.url)}</dd>
        </div>
        {c.kind === "webhook" ? (
          <>
            <div>
              <dt>Business unit</dt>
              <dd>{c.bu_name ?? "—"}</dd>
            </div>
            <div>
              <dt>Notices</dt>
              <dd>{c.kinds.join(", ")}</dd>
            </div>
          </>
        ) : null}
        <div>
          <dt>Last delivered</dt>
          <dd>{when(c.last_success)}</dd>
        </div>
        <div>
          <dt>Last failure</dt>
          <dd>{c.last_failure ? `${when(c.last_failure)}: ${c.last_error ?? ""}` : "—"}</dd>
        </div>
        <div>
          <dt>Waiting</dt>
          <dd>
            {c.backlog} pending{c.failed_24h > 0 ? `, ${c.failed_24h} failed in 24 hours` : ""}
          </dd>
        </div>
      </dl>
      <p className="actions">
        <button className="btn" type="button" onClick={() => onTest(c)}>
          Send a test message through {c.name}
        </button>
        {c.enabled ? (
          <ReasonAction label={`Disable ${c.name}`} title={`Disable ${c.name}`} fieldLabel="Reason" submitLabel="Disable" onSubmit={act("disable")} />
        ) : (
          <ReasonAction label={`Enable ${c.name}`} title={`Enable ${c.name}`} fieldLabel="Reason" submitLabel="Enable" onSubmit={act("enable")} />
        )}
        {c.kind === "webhook" && onSecret ? (
          <ReasonAction
            label={`Rotate the secret of ${c.name}`}
            title={`Rotate the secret of ${c.name}`}
            fieldLabel="Reason"
            description={<p>A new secret signs from now on; the current one also signs for 24 hours, while the receiver changes over.</p>}
            submitLabel="Rotate"
            onSubmit={async (reason) => {
              const r = await send<{ secret: string }>("POST", `/api/v1/notifications/channels/webhooks/${c.id}/rotate-secret`, { reason });
              onSecret({ name: c.name, value: r.secret });
              onChanged();
            }}
          />
        ) : null}
        <ReasonAction
          label={`Remove ${c.name}`}
          title={`Remove ${c.name}`}
          fieldLabel="Reason"
          description={<p>Notices it would have taken stay in the app; its pending deliveries are dropped.</p>}
          submitLabel="Remove"
          onSubmit={act("remove")}
        />
      </p>
    </div>
  );
}

function RelayForm({ relay, onSaved }: { relay?: Channel; onSaved: () => void }) {
  const c = relay?.config ?? {};
  const [host, setHost] = useState(String(c.host ?? ""));
  const [port, setPort] = useState(String(c.port ?? "587"));
  const [mode, setMode] = useState(String(c.tls_mode ?? "starttls"));
  const [from, setFrom] = useState(String(c.from ?? ""));
  const [user, setUser] = useState(String(c.username ?? ""));
  const [file, setFile] = useState(String(c.password_file ?? ""));
  const [anchors, setAnchors] = useState(String(c.trust_anchors ?? ""));
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string>();
  const save = async () => {
    setError(undefined);
    const config: Record<string, unknown> = { host, port: Number(port), tls_mode: mode, from };
    if (user) Object.assign(config, { username: user, password_file: file });
    if (anchors.trim()) config.trust_anchors = anchors;
    try {
      await send("PUT", "/api/v1/notifications/channels/smtp", { config, expected_version: relay?.version ?? 0, reason });
      setReason("");
      onSaved();
    } catch (err) {
      setError(problem(err));
    }
  };
  return (
    <form
      aria-label="Configure the SMTP relay"
      onSubmit={(e) => {
        e.preventDefault();
        void save();
      }}
    >
      <div className="filters">
        <div className="field">
          <label htmlFor="relay-host">Relay host</label>
          <input id="relay-host" value={host} onChange={(e) => setHost(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="relay-port">Port</label>
          <input id="relay-port" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="relay-tls">TLS</label>
          <select id="relay-tls" value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="starttls">STARTTLS (required)</option>
            <option value="implicit">Implicit TLS</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="relay-from">From address</label>
          <input id="relay-from" value={from} onChange={(e) => setFrom(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="relay-user">Username (optional)</label>
          <input id="relay-user" value={user} onChange={(e) => setUser(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="relay-file">Password file name</label>
          <input id="relay-file" value={file} onChange={(e) => setFile(e.target.value)} aria-describedby="relay-file-help" />
          <p id="relay-file-help" className="muted">
            A file in the service's SMTP directory; passwords are never entered here.
          </p>
        </div>
      </div>
      <div className="field">
        <label htmlFor="relay-anchors">Trust anchors (PEM, optional)</label>
        <textarea id="relay-anchors" rows={3} value={anchors} onChange={(e) => setAnchors(e.target.value)} />
      </div>
      <div className="field">
        <label htmlFor="relay-reason">Reason</label>
        <input id="relay-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
      </div>
      {error ? (
        <p role="alert" className="error-text">
          {error}
        </p>
      ) : null}
      <div className="actions">
        <button className="react-aria-Button primary" type="submit">
          Save the relay
        </button>
      </div>
    </form>
  );
}

function WebhookForm({ kinds, bus, onCreated }: { kinds: Kind[]; bus: { id: string; name: string; restricted: boolean }[]; onCreated: (name: string, secret: string) => void }) {
  const [name, setName] = useState("");
  const [url, setURL] = useState("https://");
  const [bu, setBU] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string>();
  useEffect(() => {
    if (!bu && bus[0]) setBU(bus[0].id);
  }, [bus, bu]);
  const save = async () => {
    setError(undefined);
    try {
      const r = await send<{ secret: string }>("POST", "/api/v1/notifications/channels/webhooks", { name, url, bu_id: bu, kinds: picked, reason });
      onCreated(name, r.secret);
      setName("");
      setURL("https://");
      setPicked([]);
      setReason("");
    } catch (err) {
      setError(problem(err));
    }
  };
  return (
    <form
      aria-label="Add a webhook"
      onSubmit={(e) => {
        e.preventDefault();
        void save();
      }}
    >
      <h3>Add a webhook</h3>
      <div className="filters">
        <div className="field">
          <label htmlFor="hook-name">Name</label>
          <input id="hook-name" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="hook-url">URL (https)</label>
          <input id="hook-url" value={url} onChange={(e) => setURL(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="hook-bu">Business unit (with its subtree)</label>
          <select id="hook-bu" value={bu} onChange={(e) => setBU(e.target.value)}>
            {bus.map((b) => (
              <option key={b.id} value={b.id}>
                {b.name}
                {b.restricted ? " (restricted)" : ""}
              </option>
            ))}
          </select>
        </div>
      </div>
      <fieldset className="inline-choice">
        <legend>Notices it takes</legend>
        {kinds.filter((k) => k.kind !== "notify.test").map((k) => (
          <label key={k.kind}>
            <input
              type="checkbox"
              checked={picked.includes(k.kind)}
              onChange={(e) => setPicked(e.target.checked ? [...picked, k.kind] : picked.filter((x) => x !== k.kind))}
            />{" "}
            {k.label}
          </label>
        ))}
      </fieldset>
      <div className="field">
        <label htmlFor="hook-reason">Reason</label>
        <input id="hook-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
      </div>
      {error ? (
        <p role="alert" className="error-text">
          {error}
        </p>
      ) : null}
      <div className="actions">
        <button className="react-aria-Button primary" type="submit">
          Add the webhook
        </button>
      </div>
    </form>
  );
}

export function DeliveriesPage({ search = window.location.search }: { search?: string }) {
  useEffect(() => {
    document.title = "Delivery log · FAIR Risk Platform";
  }, []);
  const q = new URLSearchParams(search);
  const [state, setState] = useState(q.get("state") ?? "");
  const path = `/api/v1/notifications/deliveries?limit=100${q.get("state") ? `&state=${encodeURIComponent(q.get("state") ?? "")}` : ""}`;
  const log = useApi<{ deliveries: Delivery[]; more: boolean }>(path);
  if (log.error instanceof ApiError && log.error.status === 404) {
    return (
      <>
        <h1>Delivery log</h1>
        <p role="alert">Not found, or not visible to you.</p>
      </>
    );
  }
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/notifications">Notifications</a> / <a href="/notifications/channels">Channels</a>
      </nav>
      <h1>Delivery log</h1>
      <p className="lede">Each email and webhook delivery, newest first: the notice kind, where it links, who received it, and how it went. Never its content.</p>
      <form
        className="filters"
        aria-label="Filter deliveries"
        onSubmit={(e) => {
          e.preventDefault();
          window.location.assign(`/notifications/deliveries${state ? `?state=${state}` : ""}`);
        }}
      >
        <div className="field">
          <label htmlFor="f-state">State</label>
          <select id="f-state" value={state} onChange={(e) => setState(e.target.value)}>
            <option value="">Any</option>
            {["pending", "sent", "failed", "dropped"].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
        <div className="actions">
          <button className="btn" type="submit">
            Apply
          </button>
        </div>
      </form>
      <Section id="deliveries" title="Deliveries">
        <Status loaded={log}>
          {(data) =>
            data.deliveries.length === 0 ? (
              <p>No deliveries.</p>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <caption className="sr-only">Deliveries</caption>
                  <thead>
                    <tr>
                      <th scope="col">When</th>
                      <th scope="col">Notice</th>
                      <th scope="col">Channel</th>
                      <th scope="col">Recipient</th>
                      <th scope="col">State</th>
                      <th scope="col">Outcome</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.deliveries.map((d) => (
                      <tr key={d.id}>
                        <td>{when(d.created_at)}</td>
                        <td>
                          {d.kind}
                          <br />
                          <span className="muted">{d.bu_name}</span>
                        </td>
                        <td>{d.channel_name}</td>
                        <td>{d.recipient ?? "—"}</td>
                        <td>
                          <Badge tone={STATE_TONE[d.state] ?? "muted"}>{d.state}</Badge>
                          {d.reason ? <span className="muted"> {d.reason}</span> : null}
                        </td>
                        <td>
                          {d.attempts} {d.attempts === 1 ? "attempt" : "attempts"}
                          {d.outcome ? <span className="muted">: {d.outcome}</span> : null}
                        </td>
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
