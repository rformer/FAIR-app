import { useEffect, useState } from "react";
import { describe, send } from "../api";
import { usePolling } from "../analysis/Runs";
import { Badge, Section, Status, useApi } from "../components";
import { auditHref } from "../links";
import { DownloadButton, withReason } from "../reason";
import type { Category, RiskHead } from "../register/types";
import { useReportBUs } from "./Dashboard";
import {
  bytes,
  dateTime,
  failureText,
  FILE_NAME,
  FORMAT_LABEL,
  KIND_INTRO,
  KIND_LABEL,
  leftOutText,
  paramsText,
  STATE,
  type Format,
  type KindName,
  type Kinds,
  type Report,
} from "./types";

// F-010 T-17 (F-010-AC-08 to AC-18; design §3.4 to §3.6): requesting a
// report, the requester's own reports, and one report with its progress,
// files, sizes and SHA-256 digests. A report is generated in the background
// under the requester's own access; where export.reason_required covers its
// scope the service asks for a reason (the prompt, or the form's field).

const FORMATS: Format[] = ["pdf", "csv", "json"];

export type ParamValues = Record<string, string>;

/** The kind's parameters as the API takes them (numbers as numbers, blanks left out). */
export function paramsOf(kind: KindName, v: ParamValues): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const keys: Record<KindName, string[]> = {
    register: ["status", "decision", "acceptance", "owner", "category"],
    portfolio: ["period_days"],
    acceptances: ["expiring_within", "decided_from", "decided_to"],
    treatment: [],
    risk: ["risk"],
  };
  for (const k of keys[kind]) {
    const x = (v[k] ?? "").trim();
    if (!x) continue;
    out[k] = k === "period_days" || k === "expiring_within" ? Number(x) : x;
  }
  return out;
}

function Select({ id, label, value, onChange, options }: { id: string; label: string; value: string; onChange: (v: string) => void; options: [string, string][] }) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map(([v, l]) => (
          <option key={v} value={v}>
            {l}
          </option>
        ))}
      </select>
    </div>
  );
}

function Input({ id, label, value, onChange, type = "text", hint, min, max }: { id: string; label: string; value: string; onChange: (v: string) => void; type?: string; hint?: string; min?: number; max?: number }) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input id={id} type={type} value={value} min={min} max={max} onChange={(e) => onChange(e.target.value)} aria-describedby={hint ? `${id}-hint` : undefined} />
      {hint ? (
        <p id={`${id}-hint`} className="muted">
          {hint}
        </p>
      ) : null}
    </div>
  );
}

/** A kind's filters (design §3.4). The register's risks give the owners and the risks to choose from. */
export function ParamsFields({ kind, bu, value, onChange, idPrefix = "p" }: { kind: KindName; bu: string; value: ParamValues; onChange: (v: ParamValues) => void; idPrefix?: string }) {
  const needsRisks = (kind === "register" || kind === "risk") && bu !== "";
  const risks = useApi<{ risks: RiskHead[] }>(needsRisks ? `/api/v1/register/risks?bu=${bu}&state=open&limit=200` : null);
  const categories = useApi<{ categories: Category[] }>(kind === "register" ? "/api/v1/register/categories" : null);
  const set = (k: string) => (x: string) => onChange({ ...value, [k]: x });
  const id = (k: string) => `${idPrefix}-${k}`;
  const owners = new Map<string, string>();
  for (const r of risks.data?.risks ?? []) if (r.owner) owners.set(r.owner, r.owner_name ?? r.owner);
  switch (kind) {
    case "register":
      return (
        <>
          <Select
            id={id("status")}
            label="Exposure status"
            value={value["status"] ?? ""}
            onChange={set("status")}
            options={[
              ["", "Any"],
              ["current", "Current"],
              ["stale", "Stale"],
              ["computing", "Computing"],
              ["unquantified", "Unquantified"],
            ]}
          />
          <Select
            id={id("decision")}
            label="Treatment decision"
            value={value["decision"] ?? ""}
            onChange={set("decision")}
            options={[
              ["", "Any"],
              ["mitigate", "Mitigate"],
              ["transfer", "Transfer"],
              ["avoid", "Avoid"],
              ["accept", "Accept"],
              ["none", "Not decided"],
            ]}
          />
          <Select
            id={id("acceptance")}
            label="Acceptance"
            value={value["acceptance"] ?? ""}
            onChange={set("acceptance")}
            options={[
              ["", "Any"],
              ["active", "Accepted"],
              ["expiring", "Expiring within 30 days"],
              ["pending", "Awaiting decision"],
              ["suspended", "Suspended for review"],
              ["expired", "Expired"],
              ["needs_review", "Needs review"],
              ["none", "None"],
            ]}
          />
          <Select id={id("owner")} label="Owner" value={value["owner"] ?? ""} onChange={set("owner")} options={[["", "Any"], ...[...owners.entries()].sort((a, b) => a[1].localeCompare(b[1]))]} />
          <Select
            id={id("category")}
            label="Category"
            value={value["category"] ?? ""}
            onChange={set("category")}
            options={[["", "Any"], ...(categories.data?.categories ?? []).filter((c) => !c.archived_at).map((c): [string, string] => [c.id, c.name])]}
          />
        </>
      );
    case "portfolio":
      return <Input id={id("period_days")} label="Trend period, in days" type="number" min={1} max={3650} value={value["period_days"] ?? ""} onChange={set("period_days")} hint="1 to 3,650; a year when left empty." />;
    case "acceptances":
      return (
        <>
          <Input id={id("expiring_within")} label="Expiring within, in days" type="number" min={0} max={3650} value={value["expiring_within"] ?? ""} onChange={set("expiring_within")} hint="Left empty: 30 days." />
          <Input id={id("decided_from")} label="Decisions from" type="date" value={value["decided_from"] ?? ""} onChange={set("decided_from")} hint="Left empty: 90 days before the end." />
          <Input id={id("decided_to")} label="Decisions to" type="date" value={value["decided_to"] ?? ""} onChange={set("decided_to")} hint="Left empty: today." />
        </>
      );
    case "treatment":
      return <p className="muted wide">Every open action in the business unit and below it, overdue ones first.</p>;
    case "risk":
      return (
        <Select
          id={id("risk")}
          label="Risk"
          value={value["risk"] ?? ""}
          onChange={set("risk")}
          options={[["", risks.loading ? "Loading…" : "Choose a risk"], ...(risks.data?.risks ?? []).map((r): [string, string] => [r.id, r.title ?? r.id])]}
        />
      );
  }
}

export function FormatChoice({ value, onChange }: { value: Format[]; onChange: (v: Format[]) => void }) {
  return (
    <fieldset className="wide">
      <legend>Formats</legend>
      {FORMATS.map((f) => (
        <label key={f} className="check">
          <input type="checkbox" checked={value.includes(f)} onChange={(e) => onChange(e.target.checked ? [...value, f] : value.filter((x) => x !== f))} /> {FORMAT_LABEL[f]}
        </label>
      ))}
    </fieldset>
  );
}

export function NewReportPage({ search = window.location.search }: { search?: string }) {
  const q = new URLSearchParams(search);
  const kinds = useApi<Kinds>("/api/v1/reports/kinds");
  const bus = useReportBUs("report.export");
  const [kind, setKind] = useState<KindName>((q.get("kind") as KindName | null) ?? "register");
  const [bu, setBu] = useState(q.get("bu") ?? "");
  const [params, setParams] = useState<ParamValues>(() => Object.fromEntries(q.get("risk") ? [["risk", q.get("risk") ?? ""]] : []));
  const [formats, setFormats] = useState<Format[]>(["pdf"]);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    document.title = "Generate a report · Reports · FAIR Risk Platform";
  }, []);
  useEffect(() => {
    if (bus.data && !bus.data.bus.some((b) => b.id === bu) && bus.data.bus[0]) setBu(bus.data.bus[0].id);
  }, [bu, bus.data]);
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/reports">Portfolio dashboard</a>
      </nav>
      <h1>Generate a report</h1>
      <p className="lede">A report is built from one reading of the data you can see when it is generated, in the background. It is listed to you alone and kept for the retention period.</p>
      <Status loaded={bus}>
        {(b) =>
          b.bus.length === 0 ? (
            <p>Generating reports needs report.export, which you do not hold at any business unit.</p>
          ) : (
            <Section id="request" title="The report">
              <form
                className="filters"
                aria-label="The report to generate"
                onSubmit={async (e) => {
                  e.preventDefault();
                  setError(undefined);
                  if (formats.length === 0) {
                    setError("Choose at least one format.");
                    return;
                  }
                  if (kind === "risk" && !params["risk"]) {
                    setError("Choose the risk.");
                    return;
                  }
                  setBusy(true);
                  try {
                    const run = await withReason((asked) =>
                      send<Report>("POST", "/api/v1/reports", { kind, bu_id: bu, params: paramsOf(kind, params), formats, reason: asked ?? reason.trim() }),
                    );
                    window.location.assign(`/reports/${run.id}`);
                  } catch (err) {
                    setError(describe(err));
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                <Select
                  id="r-kind"
                  label="Report"
                  value={kind}
                  onChange={(v) => {
                    setKind(v as KindName);
                    setParams({});
                  }}
                  options={(kinds.data?.kinds ?? []).map((k): [string, string] => [k.kind, KIND_LABEL[k.kind] ?? k.title])}
                />
                <Select id="r-bu" label="Business unit (with everything below it)" value={bu} onChange={setBu} options={b.bus.map((x): [string, string] => [x.id, x.name])} />
                <p className="muted wide">{KIND_INTRO[kind]}</p>
                <ParamsFields kind={kind} bu={bu} value={params} onChange={setParams} />
                <FormatChoice value={formats} onChange={setFormats} />
                <div className="field wide">
                  <label htmlFor="r-reason">Reason</label>
                  <textarea id="r-reason" rows={2} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} aria-describedby="r-reason-hint" />
                  <p id="r-reason-hint" className="muted">
                    Required where the data's business units ask every export for a reason (restricted ones do); recorded with the report.
                  </p>
                </div>
                {kinds.data ? (
                  <p className="muted wide">
                    Limits: at most {kinds.data.limits.risks.toLocaleString("en-US")} risks in a report, {bytes(kinds.data.limits.file_bytes)} per file, and{" "}
                    {kinds.data.limits.running} of your reports generating at once.
                  </p>
                ) : null}
                {error ? (
                  <p role="alert" className="error-text">
                    {error}
                  </p>
                ) : null}
                <div className="actions">
                  <button className="react-aria-Button primary" type="submit" disabled={busy || !bu}>
                    Generate
                  </button>
                  <a href={`/reports/schedules/new?kind=${kind}${bu ? `&bu=${bu}` : ""}`}>Schedule it instead</a>
                </div>
              </form>
            </Section>
          )
        }
      </Status>
    </>
  );
}

export function StateBadge({ r }: { r: Pick<Report, "state" | "progress"> }) {
  return (
    <Badge tone={STATE[r.state].tone}>
      {STATE[r.state].label}
      {r.state === "running" ? ` (${r.progress}%)` : ""}
    </Badge>
  );
}

const PAGE = 50;

export function MyReportsPage({ search = window.location.search }: { search?: string }) {
  const offset = Number(new URLSearchParams(search).get("offset") ?? "0") || 0;
  const list = useApi<{ reports: Report[]; more: boolean }>(`/api/v1/reports?limit=${PAGE}&offset=${offset}`);
  usePolling(list.data?.reports.some((r) => r.state === "queued" || r.state === "running") ?? false, list.reload);
  useEffect(() => {
    document.title = "My reports · Reports · FAIR Risk Platform";
  }, []);
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/reports">Portfolio dashboard</a>
      </nav>
      <h1>My reports</h1>
      <p className="lede">The reports you requested or scheduled, newest first. No one else sees them here.</p>
      <p className="actions">
        <a className="react-aria-Button primary" href="/reports/new">
          Generate a report
        </a>{" "}
        <a href="/reports/schedules">Scheduled reports</a>
      </p>
      <Section id="reports" title="Reports">
        <Status loaded={list}>
          {(d) =>
            d.reports.length === 0 ? (
              <p>You have no reports.</p>
            ) : (
              <>
                <div className="table-wrap">
                  <table className="data">
                    <caption className="sr-only">Your reports, newest first</caption>
                    <thead>
                      <tr>
                        <th scope="col">Report</th>
                        <th scope="col">Business unit</th>
                        <th scope="col">Filters</th>
                        <th scope="col">Requested</th>
                        <th scope="col">State</th>
                      </tr>
                    </thead>
                    <tbody>
                      {d.reports.map((r) => (
                        <tr key={r.id}>
                          <td>
                            <a href={`/reports/${r.id}`}>{KIND_LABEL[r.kind]}</a>
                            {r.schedule_id ? <span className="muted"> (scheduled)</span> : null}
                          </td>
                          <td>{r.bu_name ?? "—"}</td>
                          <td>{paramsText(r.kind, r.params)}</td>
                          <td>{dateTime(r.requested_at)}</td>
                          <td>
                            <StateBadge r={r} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="actions">
                  {offset > 0 ? <a href={`/reports/mine?offset=${Math.max(0, offset - PAGE)}`}>Newer reports</a> : null}
                  {d.more ? <a href={`/reports/mine?offset=${offset + PAGE}`}>Older reports</a> : null}
                </p>
              </>
            )
          }
        </Status>
      </Section>
    </>
  );
}

export function ReportPage({ id }: { id: string }) {
  const r = useApi<Report>(`/api/v1/reports/${id}`);
  usePolling(r.data?.state === "queued" || r.data?.state === "running", r.reload);
  const [digest, setDigest] = useState<string>();
  useEffect(() => {
    if (r.data) document.title = `${KIND_LABEL[r.data.kind]} report · Reports · FAIR Risk Platform`;
  }, [r.data]);
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/reports">Portfolio dashboard</a> / <a href="/reports/mine">My reports</a>
      </nav>
      <Status loaded={r}>
        {(x) => {
          const left = leftOutText(x.left_out);
          return (
            <>
              <h1>
                {KIND_LABEL[x.kind]} report{x.bu_name ? ` of ${x.bu_name}` : ""}
              </h1>
              <p className="lede">
                Requested {dateTime(x.requested_at)} · <StateBadge r={x} />
              </p>
              {x.state === "queued" || x.state === "running" ? (
                <p role="status">
                  <label htmlFor="r-progress">Generating: </label>
                  <progress id="r-progress" max={100} value={x.progress}>
                    {x.progress}%
                  </progress>{" "}
                  {x.progress}%
                </p>
              ) : null}
              {x.state === "failed" ? (
                <p role="alert" className="error-text">
                  {failureText(x.failure)}
                </p>
              ) : null}
              <Section id="about" title="About this report">
                <dl className="summary">
                  <div>
                    <dt>Report</dt>
                    <dd>{KIND_LABEL[x.kind]}</dd>
                  </div>
                  <div>
                    <dt>Business unit</dt>
                    <dd>{x.bu_name ?? "—"} and everything below it</dd>
                  </div>
                  <div>
                    <dt>Filters</dt>
                    <dd>{paramsText(x.kind, x.params)}</dd>
                  </div>
                  <div>
                    <dt>Formats</dt>
                    <dd>{x.formats.map((f) => f.toUpperCase()).join(", ")}</dd>
                  </div>
                  {x.reason ? (
                    <div>
                      <dt>Reason</dt>
                      <dd>{x.reason}</dd>
                    </div>
                  ) : null}
                  {x.schedule_id ? (
                    <div>
                      <dt>Schedule</dt>
                      <dd>
                        <a href={`/reports/schedules/${x.schedule_id}`}>The schedule that made it</a>
                      </dd>
                    </div>
                  ) : null}
                  <div>
                    <dt>Data as of</dt>
                    <dd>{dateTime(x.data_as_of)}</dd>
                  </div>
                  <div>
                    <dt>Risks covered</dt>
                    <dd>{x.risk_count ?? "—"}</dd>
                  </div>
                  <div>
                    <dt>Left out</dt>
                    <dd>{x.state !== "succeeded" ? "—" : left.length ? left.join("; ") : "Nothing"}</dd>
                  </div>
                  <div>
                    <dt>Finished</dt>
                    <dd>{dateTime(x.finished_at)}</dd>
                  </div>
                </dl>
              </Section>
              {x.state === "succeeded" ? (
                <Section id="files" title="Files" intro="Each download is recorded, and needs report.export at the business unit at the time. Check a copy against its SHA-256 digest.">
                  <div className="table-wrap">
                    <table className="data">
                      <caption className="sr-only">The report's files</caption>
                      <thead>
                        <tr>
                          <th scope="col">Format</th>
                          <th scope="col">Size</th>
                          <th scope="col">SHA-256</th>
                          <th scope="col">Download</th>
                        </tr>
                      </thead>
                      <tbody>
                        {x.files.map((f) => (
                          <tr key={f.format}>
                            <th scope="row">{f.format.toUpperCase()}</th>
                            <td>{bytes(f.size)}</td>
                            <td>
                              <span className="mono">{f.sha256}</span>
                            </td>
                            <td>
                              {f.purged ? (
                                "Deleted after the retention period"
                              ) : (
                                <DownloadButton
                                  href={`/api/v1/reports/${x.id}/files/${f.format}`}
                                  fallbackName={FILE_NAME[f.format]}
                                  onDone={(resp) => setDigest(resp.headers.get("X-Fair-Digest")?.replace(/^sha256=/, "") ?? "")}
                                >
                                  Download {f.format.toUpperCase()}
                                </DownloadButton>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div aria-live="polite">
                    {digest ? (
                      <p role="status">
                        Downloaded. SHA-256 of the file: <span className="mono">{digest}</span>
                      </p>
                    ) : null}
                  </div>
                </Section>
              ) : null}
              <p className="actions">
                <a href={`/reports/new?kind=${x.kind}&bu=${x.bu_id}`}>Generate another</a> · <a href={auditHref(`report_run:${x.id}`)}>Audit history of this report</a>
              </p>
            </>
          );
        }}
      </Status>
    </>
  );
}
