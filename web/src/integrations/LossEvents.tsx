import { useEffect, useState } from "react";
import { ApiError, describe, send } from "../api";
import { Section, Status, useApi } from "../components";
import { date } from "../links";

// F-011 T-18 (F-011-AC-17 to AC-19; design §3.5): loss events, as the
// reader's library.view lets them see (restricted units' events only to
// readers inside), and a reference class's derivation from them. A
// derivation never writes the class: when the data it computes differs, a
// new version is proposed for review.

interface LossEvent {
  id: string;
  bu_id: string;
  integration_id: string;
  integration_name?: string;
  external_id: string;
  occurred_on: string;
  event_type: string;
  description: string | null;
  amounts: Record<string, string>;
  archived_at: string | null;
}

interface Derivation {
  reference_class_id: string;
  bu_id: string;
  filter: { bu_id: string; event_types: string[]; from: string; to: string; granularity?: string; forms?: string[] };
  data_kind: "counts" | "losses";
  set_by_name: string | null;
  set_at: string;
  pending_proposal: string | null;
  proposed?: boolean;
  computed?: Record<string, unknown>;
}

const FORMS = ["productivity", "response", "replacement", "fines_judgments", "competitive_advantage", "reputation"];

function total(a: Record<string, string>): string {
  // Canonical decimals: summed only for display, as text.
  const n = Object.values(a).reduce((s, v) => s + Number(v), 0);
  return Number.isFinite(n) ? n.toLocaleString() : "—";
}

export function LossEventsPage() {
  const [type, setType] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [archived, setArchived] = useState(false);
  const q = new URLSearchParams({ limit: "200" });
  if (type.trim()) q.set("type", type.trim());
  if (from) q.set("from", from);
  if (to) q.set("to", to);
  if (archived) q.set("archived", "true");
  const list = useApi<{ loss_events: LossEvent[] }>(`/api/v1/loss-events?${q.toString()}`);
  useEffect(() => {
    document.title = "Loss events · Integrations · FAIR Risk Platform";
  }, []);
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/integrations">Integrations</a>
      </nav>
      <h1>Loss events</h1>
      <p className="lede">
        Observed losses that integrations bring in. They are data, not analysis inputs: reference classes derived from them get
        proposed versions you review.
      </p>
      <form className="filters" aria-label="Filter loss events" onSubmit={(e) => e.preventDefault()}>
        <div className="field">
          <label htmlFor="le-type">Event type</label>
          <input id="le-type" value={type} maxLength={100} onChange={(e) => setType(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="le-from">From</label>
          <input id="le-from" type="date" value={from} onChange={(e) => setFrom(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="le-to">Before</label>
          <input id="le-to" type="date" value={to} onChange={(e) => setTo(e.target.value)} />
        </div>
        <div className="field">
          <label>
            <input type="checkbox" checked={archived} onChange={(e) => setArchived(e.target.checked)} /> Include events no longer in their source
          </label>
        </div>
      </form>
      <Section id="events" title="Events">
        <Status loaded={list}>
          {(d) =>
            d.loss_events.length === 0 ? (
              <p>No loss events you can see.</p>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <caption className="sr-only">Loss events, newest first</caption>
                  <thead>
                    <tr>
                      <th scope="col">Occurred</th>
                      <th scope="col">Type</th>
                      <th scope="col">Description</th>
                      <th scope="col" className="num">
                        Loss
                      </th>
                      <th scope="col">Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.loss_events.map((e) => (
                      <tr key={e.id}>
                        <td>{date(e.occurred_on)}</td>
                        <td>{e.event_type}</td>
                        <td>
                          {e.description ?? "—"}
                          {e.archived_at ? <span className="muted"> (no longer in the source)</span> : null}
                        </td>
                        <td className="num">{total(e.amounts)}</td>
                        <td className="mono">{e.external_id}</td>
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

/** AC-18: a reference class's derivation, on its library page. */
export function DerivationSection({ id, buId, canEdit }: { id: string; buId: string; canEdit: boolean }) {
  const der = useApi<Derivation>(`/api/v1/library/${id}/derivation`);
  const none = der.error instanceof ApiError && der.error.status === 404;
  const [editing, setEditing] = useState(false);
  const [msg, setMsg] = useState<{ ok?: string; error?: string }>({});
  const d = der.data;
  const [form, setForm] = useState({ kind: "counts" as "counts" | "losses", types: "", from: "", to: "", granularity: "year", forms: FORMS });
  useEffect(() => {
    if (d)
      setForm({
        kind: d.data_kind,
        types: d.filter.event_types.join(", "),
        from: d.filter.from,
        to: d.filter.to,
        granularity: d.filter.granularity ?? "year",
        forms: d.filter.forms ?? FORMS,
      });
  }, [d]);
  return (
    <Section id="derivation" title="Derived from loss events" intro="When the data computed from loss events differs from the class's, a new version is proposed for review.">
      {none ? (
        <p>This reference class is not derived from loss events.</p>
      ) : (
        <Status loaded={der}>
          {(x) => (
            <dl className="facts">
              <dt>Data</dt>
              <dd>{x.data_kind === "counts" ? `Event counts per ${x.filter.granularity ?? "period"}` : "Loss totals"}</dd>
              <dt>Event types</dt>
              <dd>{x.filter.event_types.join(", ")}</dd>
              <dt>Period</dt>
              <dd>
                {date(x.filter.from)} to before {date(x.filter.to)}
              </dd>
              <dt>Set</dt>
              <dd>
                {date(x.set_at)}
                {x.set_by_name ? ` by ${x.set_by_name}` : ""}
              </dd>
              <dt>Proposed version</dt>
              <dd>{x.pending_proposal ? <a href={`/integrations/proposals/${x.pending_proposal}`}>Waiting for review</a> : "None waiting"}</dd>
            </dl>
          )}
        </Status>
      )}
      <div aria-live="polite">
        {msg.ok ? <p className="ok-text">{msg.ok}</p> : null}
        {msg.error ? (
          <p role="alert" className="error-text">
            {msg.error}
          </p>
        ) : null}
      </div>
      {canEdit && !editing ? (
        <div className="actions">
          <button className="react-aria-Button" type="button" onClick={() => setEditing(true)}>
            {none ? "Derive from loss events" : "Change the derivation"}
          </button>
          {!none && d ? (
            <button
              className="react-aria-Button"
              type="button"
              onClick={async () => {
                try {
                  await send("DELETE", `/api/v1/library/${id}/derivation`, {});
                  setMsg({ ok: "The derivation was removed; the class's versions are kept." });
                  der.reload();
                } catch (err) {
                  setMsg({ error: describe(err) });
                }
              }}
            >
              Stop deriving
            </button>
          ) : null}
        </div>
      ) : null}
      {editing ? (
        <form
          className="form"
          aria-label="The derivation"
          onSubmit={async (e) => {
            e.preventDefault();
            const types = form.types
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean);
            const filter: Record<string, unknown> = { bu_id: d?.filter.bu_id ?? buId, event_types: types, from: form.from, to: form.to };
            if (form.kind === "counts") filter.granularity = form.granularity;
            else filter.forms = form.forms;
            try {
              const r = await send<Derivation>("PUT", `/api/v1/library/${id}/derivation`, { data_kind: form.kind, filter });
              setMsg({ ok: r.proposed ? "Saved; a new version of the class is proposed for review." : "Saved; the class already holds this data." });
              setEditing(false);
              der.reload();
            } catch (err) {
              setMsg({ error: describe(err) });
            }
          }}
        >
          <div className="field">
            <label htmlFor="dv-kind">Data</label>
            <select id="dv-kind" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value as "counts" | "losses" })}>
              <option value="counts">Event counts per period</option>
              <option value="losses">Loss totals</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor="dv-types">Event types (comma separated)</label>
            <input id="dv-types" required value={form.types} onChange={(e) => setForm({ ...form, types: e.target.value })} />
          </div>
          <div className="field">
            <label htmlFor="dv-from">From</label>
            <input id="dv-from" type="date" required value={form.from} onChange={(e) => setForm({ ...form, from: e.target.value })} />
          </div>
          <div className="field">
            <label htmlFor="dv-to">Before</label>
            <input id="dv-to" type="date" required value={form.to} onChange={(e) => setForm({ ...form, to: e.target.value })} />
          </div>
          {form.kind === "counts" ? (
            <div className="field">
              <label htmlFor="dv-gran">Per</label>
              <select id="dv-gran" value={form.granularity} onChange={(e) => setForm({ ...form, granularity: e.target.value })}>
                <option value="month">Month</option>
                <option value="quarter">Quarter</option>
                <option value="year">Year</option>
              </select>
            </div>
          ) : (
            <fieldset>
              <legend>Forms of loss summed</legend>
              {FORMS.map((f) => (
                <label key={f}>
                  <input
                    type="checkbox"
                    checked={form.forms.includes(f)}
                    onChange={(e) => setForm({ ...form, forms: e.target.checked ? [...form.forms, f] : form.forms.filter((x) => x !== f) })}
                  />{" "}
                  {f.replace(/_/g, " ")}
                </label>
              ))}
            </fieldset>
          )}
          <div className="actions">
            <button className="react-aria-Button primary" type="submit">
              Save the derivation
            </button>
            <button className="react-aria-Button" type="button" onClick={() => setEditing(false)}>
              Cancel
            </button>
          </div>
        </form>
      ) : null}
    </Section>
  );
}
