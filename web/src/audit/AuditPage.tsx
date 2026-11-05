import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { ApiError } from "../api";
import { Badge, Section, Status, useApi, type Loaded, type Tone } from "../components";
import { actorHref, auditHref, evidenceHref, recordHref, requestHref } from "../links";
import {
  AUDIT_API,
  CATEGORIES,
  FILTERS,
  SEVERITIES,
  type ApprovalEvidence,
  type AuditRecord,
  type FilterKey,
  type Integrity,
  type Party,
  type Proof,
  type RecordPage,
} from "./types";

// F-002 T-14 (AC-15 to AC-18, AC-21, AC-35, AC-37): the audit trail's pages,
// for audit.view holders. One route, /audit, whose query chooses the view:
//   ?target= or ?actor=   history, in order (AC-16; the Posture page's links)
//   ?request=             every visible record of one request (AC-17)
//   ?approval=            one approval's evidence (AC-35)
//   ?record=              one record and its proof
//   otherwise             search, newest first (?view=search&<filters>)
// What a user sees is decided by the API (AC-19); every read is recorded
// there (AC-20).

export type View =
  | { kind: "search"; filter: Partial<Record<FilterKey, string>>; before?: string }
  | { kind: "history"; by: "target" | "actor"; value: string; after?: string }
  | { kind: "request"; id: string; after?: string }
  | { kind: "approval"; id: string; after?: string }
  | { kind: "record"; seq: string };

export function viewOf(search: string): View {
  const p = new URLSearchParams(search);
  const opt = (k: string) => p.get(k) || undefined;
  const record = opt("record");
  if (record) return { kind: "record", seq: record };
  const approval = opt("approval");
  if (approval) return { kind: "approval", id: approval, after: opt("after") };
  const request = opt("request");
  if (request) return { kind: "request", id: request, after: opt("after") };
  if (p.get("view") !== "search") {
    const target = opt("target");
    if (target) return { kind: "history", by: "target", value: target, after: opt("after") };
    const actor = opt("actor");
    if (actor) return { kind: "history", by: "actor", value: actor, after: opt("after") };
  }
  const filter: Partial<Record<FilterKey, string>> = {};
  for (const k of FILTERS) {
    const v = opt(k);
    if (v) filter[k] = v;
  }
  return { kind: "search", filter, before: opt("before") };
}

function titleOf(v: View): string {
  switch (v.kind) {
    case "search":
      return "Audit trail";
    case "history":
      return v.by === "target" ? `History of ${v.value}` : `Activity of ${v.value}`;
    case "request":
      return `Request ${v.id}`;
    case "approval":
      return "Approval evidence";
    case "record":
      return `Audit record ${v.seq}`;
  }
}

export function AuditPage({ search = window.location.search }: { search?: string }) {
  const view = viewOf(search);
  const title = titleOf(view);
  useEffect(() => {
    document.title = `${title} · FAIR Risk Platform`;
  }, [title]);
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/audit">Audit trail</a>
      </nav>
      {view.kind === "search" ? <SearchView view={view} /> : null}
      {view.kind === "history" ? <HistoryView view={view} title={title} /> : null}
      {view.kind === "request" ? <RequestView view={view} title={title} /> : null}
      {view.kind === "approval" ? <ApprovalView view={view} /> : null}
      {view.kind === "record" ? <RecordView seq={view.seq} title={title} /> : null}
    </>
  );
}

// --- shared pieces -----------------------------------------------------------

/** Without audit.view anywhere, every Audit API route is 404 (F-001 AC-25). */
function NoAccess({ title }: { title: string }) {
  return (
    <>
      <h1>{title}</h1>
      <p role="alert">You do not have access to the audit trail (it needs the audit.view permission).</p>
    </>
  );
}

function isNotFound(l: Loaded<unknown>): boolean {
  return l.error instanceof ApiError && l.error.status === 404;
}

/** Times as UTC, to the second, the same for every reader. */
export function utc(s: string): string {
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? s : `${d.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

const integrityLabel: Record<Integrity, [string, Tone]> = {
  verified: ["Verified", "ok"],
  pending: ["Pending", "muted"],
  failed: ["Failed", "bad"],
};

/** AC-18: each record's integrity status, as text. */
export function IntegrityBadge({ value }: { value: Integrity }) {
  const [label, tone] = integrityLabel[value] ?? [value, "muted"];
  return <Badge tone={tone}>{label}</Badge>;
}

const severityTone: Record<string, Tone> = { critical: "bad", high: "warn", low: "info", info: "muted" };

/** AC-18: a user by current display name, alongside the stable id. */
export function Person({ id, names }: { id: string; names: Record<string, string> }) {
  const name = names[id];
  if (!name) return <span className="mono">{id}</span>;
  return (
    <>
      {name} <span className="mono id">{id}</span>
    </>
  );
}

function IntegrityLegend() {
  return (
    <p className="muted legend">
      Integrity: <IntegrityBadge value="verified" /> a passed verification run covered the record;{" "}
      <IntegrityBadge value="pending" /> not yet verified; <IntegrityBadge value="failed" /> at or after a position where
      verification failed.
    </p>
  );
}

function RecordsTable({ records, caption }: { records: AuditRecord[]; caption: string }) {
  if (records.length === 0) return <p>No records.</p>;
  return (
    <div className="table-wrap">
      <table className="data records">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">Record</th>
            <th scope="col">Time</th>
            <th scope="col">Event</th>
            <th scope="col">Actor</th>
            <th scope="col">Target</th>
            <th scope="col">Related</th>
            <th scope="col">Integrity</th>
          </tr>
        </thead>
        <tbody>
          {records.map((r) => (
            <tr key={r.seq}>
              <th scope="row">
                <a href={recordHref(r.seq)}>
                  <span className="sr-only">Record </span>
                  {r.seq}
                </a>
              </th>
              <td className="nowrap">{utc(r.time)}</td>
              <td>
                <span className="mono">{r.type}</span> <Badge tone={severityTone[r.severity] ?? "muted"}>{r.severity}</Badge>
                {r.event.reason ? <div className="muted">{r.event.reason}</div> : null}
              </td>
              <td>
                <a href={actorHref(r.actor)}>
                  <Person id={r.actor} names={r.names} />
                </a>
              </td>
              <td>{r.target ? <a href={auditHref(r.target)}>{r.target}</a> : "—"}</td>
              <td>
                {r.request_id ? (
                  <div>
                    <a href={requestHref(r.request_id)}>
                      Request<span className="sr-only"> {r.request_id}</span>
                    </a>
                  </div>
                ) : null}
                {r.approval_id ? (
                  <div>
                    <a href={evidenceHref(r.approval_id)}>
                      Approval<span className="sr-only"> {r.approval_id}</span>
                    </a>
                  </div>
                ) : null}
              </td>
              <td>
                <IntegrityBadge value={r.integrity} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** A link to the next page, keeping the view's other parameters. */
function More({ search, param, value, label }: { search: string; param: string; value: number | null | undefined; label: string }) {
  if (value === null || value === undefined) return null;
  const p = new URLSearchParams(search);
  p.set(param, String(value));
  return (
    <p>
      <a href={`/audit?${p.toString()}`}>{label}</a>
    </p>
  );
}

// --- search (AC-15) --------------------------------------------------------------

const filterLabel: Record<FilterKey, string> = {
  from: "From",
  to: "To",
  type: "Event type",
  category: "Category",
  severity: "Severity",
  actor: "Actor (user id or service)",
  target: "Target",
  bu: "Business unit id",
  request_id: "Request id",
  source_ip: "Source address or CIDR range",
};

/** An RFC 3339 time as a datetime-local value, in the browser's zone. */
function toLocalInput(iso: string | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function SearchForm({ filter }: { filter: Partial<Record<FilterKey, string>> }) {
  const [error, setError] = useState<string>();
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const data = new FormData(e.currentTarget);
    const q = new URLSearchParams({ view: "search" });
    for (const k of FILTERS) {
      let v = String(data.get(k) ?? "").trim();
      if (!v) continue;
      if (k === "from" || k === "to") {
        const d = new Date(v);
        if (Number.isNaN(d.getTime())) {
          setError(`${filterLabel[k]} is not a valid time.`);
          return;
        }
        v = d.toISOString();
      }
      q.set(k, v);
    }
    window.location.assign(`/audit?${q.toString()}`);
  };
  const text = (k: FilterKey) => (
    <div className="field" key={k}>
      <label htmlFor={`f-${k}`}>{filterLabel[k]}</label>
      <input id={`f-${k}`} name={k} type="text" defaultValue={filter[k] ?? ""} spellCheck={false} autoComplete="off" />
    </div>
  );
  return (
    <form className="filters" onSubmit={submit} aria-label="Search the audit trail">
      <div className="field">
        <label htmlFor="f-from">{filterLabel.from}</label>
        <input id="f-from" name="from" type="datetime-local" defaultValue={toLocalInput(filter.from)} />
      </div>
      <div className="field">
        <label htmlFor="f-to">{filterLabel.to}</label>
        <input id="f-to" name="to" type="datetime-local" defaultValue={toLocalInput(filter.to)} />
      </div>
      {text("type")}
      <div className="field">
        <label htmlFor="f-category">{filterLabel.category}</label>
        <select id="f-category" name="category" defaultValue={filter.category ?? ""}>
          <option value="">Any</option>
          {CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      </div>
      <div className="field">
        <label htmlFor="f-severity">{filterLabel.severity}</label>
        <select id="f-severity" name="severity" defaultValue={filter.severity ?? ""}>
          <option value="">Any</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>
      {text("actor")}
      {text("target")}
      {text("bu")}
      {text("request_id")}
      {text("source_ip")}
      {error ? (
        <p role="alert" className="error-text">
          {error}
        </p>
      ) : null}
      <div className="actions">
        <button type="submit" className="btn primary">
          Search
        </button>
        <a className="btn" href="/audit">
          Clear filters
        </a>
      </div>
    </form>
  );
}

function SearchView({ view }: { view: Extract<View, { kind: "search" }> }) {
  const q = new URLSearchParams();
  for (const k of FILTERS) {
    const v = view.filter[k];
    if (v) q.set(k, v);
  }
  if (view.before) q.set("before", view.before);
  q.set("limit", "50");
  const page = useApi<RecordPage>(`${AUDIT_API}/records?${q.toString()}`);
  if (isNotFound(page)) return <NoAccess title="Audit trail" />;
  const filtered = Object.keys(view.filter).length > 0;
  return (
    <>
      <h1>Audit trail</h1>
      <p className="lede">Search the security events you may see, newest first. Filters combine.</p>
      <Section id="filters" title="Filters">
        <SearchForm filter={view.filter} />
      </Section>
      <Section id="results" title={filtered ? "Matching records" : "Latest records"}>
        <IntegrityLegend />
        <Status loaded={page}>
          {(d) => (
            <>
              <RecordsTable records={d.records} caption={filtered ? "Matching records, newest first" : "Latest records, newest first"} />
              <More search={window.location.search} param="before" value={d.next_before} label="Older records" />
            </>
          )}
        </Status>
      </Section>
    </>
  );
}

// --- history (AC-16, AC-37) and request (AC-17) ---------------------------------

function HistoryView({ view, title }: { view: Extract<View, { kind: "history" }>; title: string }) {
  const q = new URLSearchParams({ [view.by]: view.value, limit: "50" });
  if (view.after) q.set("after", view.after);
  const page = useApi<RecordPage>(`${AUDIT_API}/history?${q.toString()}`);
  if (isNotFound(page)) return <NoAccess title={title} />;
  const name = page.data?.records.find((r) => r.names[view.value])?.names[view.value];
  return (
    <>
      <h1>{view.by === "actor" && name ? `Activity of ${name}` : title}</h1>
      <p className="lede">
        {view.by === "target" ? "Every visible record about this target, oldest first." : "Every visible record of this actor, oldest first."}{" "}
        {view.by === "actor" && name ? <span className="mono">{view.value}</span> : null}
      </p>
      <Section id="history" title="Records">
        <IntegrityLegend />
        <Status loaded={page}>
          {(d) => (
            <>
              <RecordsTable records={d.records} caption={`${title}, oldest first`} />
              <More search={window.location.search} param="after" value={d.next_after} label="Later records" />
            </>
          )}
        </Status>
      </Section>
    </>
  );
}

function RequestView({ view, title }: { view: Extract<View, { kind: "request" }>; title: string }) {
  const q = new URLSearchParams({ limit: "50" });
  if (view.after) q.set("after", view.after);
  const page = useApi<RecordPage>(`${AUDIT_API}/requests/${encodeURIComponent(view.id)}?${q.toString()}`);
  return (
    <>
      <h1>{title}</h1>
      <p className="lede">Every visible record of this request, across services, in order.</p>
      <Section id="request" title="Records">
        <IntegrityLegend />
        <Status loaded={page}>
          {(d) => (
            <>
              <RecordsTable records={d.records} caption={`Records of request ${view.id}, in order`} />
              <More search={window.location.search} param="after" value={d.next_after} label="Later records" />
            </>
          )}
        </Status>
      </Section>
    </>
  );
}

// --- approval evidence (AC-35) -------------------------------------------------

function PartyView({ p }: { p: Party | null }) {
  if (!p) return <>—</>;
  return (
    <a href={actorHref(p.id)}>
      <Person id={p.id} names={p.name ? { [p.id]: p.name } : {}} />
    </a>
  );
}

function Step({ id, title, record, missing }: { id: string; title: string; record: AuditRecord | null; missing: string }) {
  return (
    <Section id={id} title={title}>
      {record ? <RecordsTable records={[record]} caption={title} /> : <p className="muted">{missing}</p>}
    </Section>
  );
}

function ApprovalView({ view }: { view: Extract<View, { kind: "approval" }> }) {
  const q = new URLSearchParams({ limit: "200" });
  if (view.after) q.set("after", view.after);
  const ev = useApi<ApprovalEvidence>(`${AUDIT_API}/approvals/${encodeURIComponent(view.id)}?${q.toString()}`);
  return (
    <>
      <h1>Approval evidence</h1>
      <p className="lede">
        One approval as the audit trail records it: the request, both parties, the decision, and the change it applied.
      </p>
      <Status loaded={ev}>
        {(d) => (
          <>
            <Section id="summary" title="Approval">
              <dl className="facts">
                <dt>Approval</dt>
                <dd className="mono">{d.approval_id}</dd>
                <dt>Kind</dt>
                <dd className="mono">{d.kind ?? "—"}</dd>
                <dt>What it approves</dt>
                <dd>{d.target_ref ? <a href={auditHref(d.target_ref)}>{d.target_ref}</a> : "—"}</dd>
                <dt>Status</dt>
                <dd>{d.status ?? "—"}</dd>
                <dt>Requested by</dt>
                <dd>
                  <PartyView p={d.requested_by} />
                </dd>
                <dt>Decided by</dt>
                <dd>
                  <PartyView p={d.decided_by} />
                </dd>
              </dl>
            </Section>
            <IntegrityLegend />
            <Step id="request" title="Request" record={d.request} missing="The request is not on this page or not visible to you." />
            <Step id="decision" title="Decision" record={d.decision} missing="Not decided yet, or not visible to you." />
            <Step id="applied" title="Applied" record={d.applied} missing="Not applied yet, or not visible to you." />
            <Section id="changes" title="Changes naming this approval">
              <RecordsTable records={d.changes} caption="Changes naming this approval, in order" />
              <More search={window.location.search} param="after" value={d.next_after} label="Later records" />
            </Section>
          </>
        )}
      </Status>
    </>
  );
}

// --- one record and its proof ----------------------------------------------------

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </>
  );
}

function RecordView({ seq, title }: { seq: string; title: string }) {
  const r = useApi<{ record: AuditRecord; proof: Proof | null }>(`${AUDIT_API}/records/${encodeURIComponent(seq)}`);
  return (
    <>
      <h1>{title}</h1>
      <Status loaded={r}>
        {({ record: x, proof }) => (
          <>
            <Section id="record" title="Record">
              <dl className="facts">
                <Fact label="Position">{x.seq}</Fact>
                <Fact label="Event id">
                  <span className="mono">{x.event_id}</span>
                </Fact>
                <Fact label="Time">{utc(x.time)}</Fact>
                <Fact label="Received">
                  {utc(x.received_at)}
                  {x.skew ? (
                    <>
                      {" "}
                      <Badge tone="warn">Clock skew</Badge>
                    </>
                  ) : null}
                </Fact>
                <Fact label="Type">
                  <span className="mono">{x.type}</span>
                </Fact>
                <Fact label="Category">{x.category}</Fact>
                <Fact label="Severity">
                  <Badge tone={severityTone[x.severity] ?? "muted"}>{x.severity}</Badge>
                </Fact>
                <Fact label="Actor">
                  <a href={actorHref(x.actor)}>
                    <Person id={x.actor} names={x.names} />
                  </a>
                </Fact>
                <Fact label="Target">{x.target ? <a href={auditHref(x.target)}>{x.target}</a> : "—"}</Fact>
                <Fact label="Business unit">
                  <span className="mono">{x.bu_id}</span>
                </Fact>
                <Fact label="Request">{x.request_id ? <a href={requestHref(x.request_id)}>{x.request_id}</a> : "—"}</Fact>
                <Fact label="Approval">{x.approval_id ? <a href={evidenceHref(x.approval_id)}>{x.approval_id}</a> : "—"}</Fact>
                <Fact label="Source address">{x.source_ip ?? "—"}</Fact>
                <Fact label="Producer">
                  <span className="mono">{x.producer}</span>
                </Fact>
                <Fact label="Reason">{x.event.reason ?? "—"}</Fact>
                <Fact label="Integrity">
                  <IntegrityBadge value={x.integrity} />
                </Fact>
              </dl>
              {x.event.attributes && Object.keys(x.event.attributes).length > 0 ? (
                <div className="table-wrap">
                  <table className="data">
                    <caption>Attributes</caption>
                    <thead>
                      <tr>
                        <th scope="col">Name</th>
                        <th scope="col">Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(x.event.attributes).map(([k, v]) => (
                        <tr key={k}>
                          <th scope="row" className="mono">
                            {k}
                          </th>
                          <td className="mono wrap">{x.names[v] ? <Person id={v} names={x.names} /> : v}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}
              <h3>As recorded</h3>
              <pre className="json" tabIndex={0} aria-label="The record's body as recorded">
                {JSON.stringify(x.event, null, 2)}
              </pre>
            </Section>
            <Section id="proof" title="Proof">
              {proof ? (
                <>
                  <p>
                    The record is leaf {proof.leaf_index} of {proof.tree_size} in segment {proof.segment}, whose signed checkpoint
                    is below. <span className="mono">fair-audit-verify</span> checks such proofs offline.
                  </p>
                  <dl className="facts">
                    <Fact label="Leaf hash">
                      <span className="mono wrap">{proof.leaf_hash}</span>
                    </Fact>
                    <Fact label="Path">
                      {proof.path.length === 0 ? (
                        "— (the segment's only record)"
                      ) : (
                        <ol className="mono wrap path">
                          {proof.path.map((h, i) => (
                            <li key={i}>{h}</li>
                          ))}
                        </ol>
                      )}
                    </Fact>
                    <Fact label="Signature">
                      <span className="mono wrap">{proof.signature}</span>
                    </Fact>
                  </dl>
                  <h3>Checkpoint statement</h3>
                  <pre className="json" tabIndex={0} aria-label="The signed checkpoint statement">
                    {proof.statement}
                  </pre>
                </>
              ) : (
                <p>
                  The record's segment is still open. Its proof is available once the segment's checkpoint is signed (at most 15
                  minutes).
                </p>
              )}
            </Section>
          </>
        )}
      </Status>
    </>
  );
}
