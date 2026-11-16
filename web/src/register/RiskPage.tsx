import { useEffect, useState, type ReactNode } from "react";
import { Button, Dialog, DialogTrigger, Heading, Modal } from "react-aria-components";
import { describe, getJSON, send } from "../api";
import { usePolling } from "../analysis/Runs";
import { money, percent } from "../analysis/types";
import { ChartFigure } from "../charts/ChartFigure.tsx";
import { describeExceedance, exceedanceTable, type CurveSeries } from "../charts/describe.ts";
import { ExceedanceChart } from "../charts/ExceedanceChart.tsx";
import type { StoredCurve } from "../charts/curve.ts";
import { Badge, ReasonAction, Section, Status, useApi } from "../components";
import { auditHref, date, show } from "../links";
import type { BU } from "../risk/types";
import { AcceptanceSection } from "../acceptance/RiskAcceptance";
import { TreatmentSection } from "./Treatment";
import { REASON_LABEL, STATUS_LABEL, type LinkView, type RiskView } from "./types";

// F-007 T-08 (F-007-AC-02 to AC-10, AC-19): one risk: what it is, the
// scenarios it covers with the analyses pinned for them (and newer ones to
// adopt), its exposure with the F-006 views of the result, whether that is
// current and why not, and its history; closing, reopening and moving.

function useCurrency(): string | null {
  return useApi<{ currency: string | null }>("/api/v1/risk/settings").data?.currency ?? null;
}

export function RiskPage({ id }: { id: string }) {
  const view = useApi<RiskView>(`/api/v1/register/risks/${id}`);
  const bus = useApi<{ bus: BU[] }>("/api/v1/register/bus?permission=register.view");
  const editable = useApi<{ bus: BU[] }>("/api/v1/register/bus?permission=register.edit");
  const currency = useCurrency();
  usePolling(view.data?.risk.status?.status === "computing", view.reload);
  const title = view.data?.risk.title ?? "Risk";
  useEffect(() => {
    document.title = `${title} · Risk register · FAIR Risk Platform`;
  }, [title]);

  return (
    <Status loaded={view}>
      {(v) => {
        const r = v.risk;
        const doc = v.version.document;
        const bu = bus.data?.bus.find((b) => b.id === r.bu_id)?.name ?? r.bu_id;
        // Changes need register.edit at the risk's BU; the API decides, the
        // page offers only what it would allow.
        const mayEdit = editable.data?.bus.some((b) => b.id === r.bu_id) ?? false;
        const open = r.state === "open";
        const st = r.status ? STATUS_LABEL[r.status.status] : undefined;
        return (
          <>
            <nav aria-label="Breadcrumb" className="crumbs">
              <a href="/register">Risk register</a>
            </nav>
            <h1>{doc.title}</h1>
            <p className="lede">
              {bu} · version {r.current_version} · {open ? <Badge tone="ok">Open</Badge> : <Badge tone="muted">Closed</Badge>}
              {st ? (
                <>
                  {" "}
                  · Exposure <Badge tone={st.tone}>{st.label}</Badge>
                </>
              ) : null}
            </p>
            <p className="actions">
              {mayEdit && open ? (
                <a className="react-aria-Button" href={`/register/risks/${id}/edit`}>
                  Edit
                </a>
              ) : null}
              {mayEdit ? (
                open ? (
                  <ReasonAction
                    label="Close"
                    title="Close this risk"
                    fieldLabel="Reason"
                    description={<p>It is kept, with its history and last exposure, read-only until reopened. Its scenarios can then be linked to other risks.</p>}
                    submitLabel="Close"
                    onSubmit={async (reason) => {
                      await send("POST", `/api/v1/register/risks/${id}/close`, { reason });
                      view.reload();
                    }}
                  />
                ) : (
                  <ReasonAction
                    label="Reopen"
                    title="Reopen this risk"
                    fieldLabel="Reason"
                    description={<p>It becomes open again, as it was when closed.</p>}
                    submitLabel="Reopen"
                    onSubmit={async (reason) => {
                      await send("POST", `/api/v1/register/risks/${id}/reopen`, { reason });
                      view.reload();
                    }}
                  />
                )
              ) : null}
              {mayEdit && open ? <MoveRisk id={id} from={r.bu_id} bus={editable.data?.bus ?? []} onDone={view.reload} /> : null}
              <a href={auditHref(`register_risk:${id}`)}>Audit history of this risk</a>
            </p>
            {r.status && r.status.status === "stale" ? (
              <div className="banner warn" role="status">
                <p>The exposure is stale:</p>
                <ul>
                  {r.status.reasons.map((x, i) => (
                    <li key={i}>
                      {REASON_LABEL[x.reason]}
                      {x.scenario_id ? ` (${v.links.find((l) => l.scenario_id === x.scenario_id)?.scenario_name ?? x.scenario_id})` : ""}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
            <Summary v={v} />
            <Scenarios v={v} id={id} canAdopt={mayEdit && open} onAdopted={view.reload} />
            <ExposureView v={v} currency={currency} />
            <TreatmentSection v={v} />
            <AcceptanceSection v={v} />
            <RiskHistory key={r.current_version} id={id} current={r.current_version} />
          </>
        );
      }}
    </Status>
  );
}

function Summary({ v }: { v: RiskView }) {
  const doc = v.version.document;
  const row = (label: string, value: ReactNode) => (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
  return (
    <Section id="summary" title="Risk">
      <dl className="summary">
        {doc.description ? row("Description", doc.description) : null}
        {row("Owner", v.risk.owner_name ?? "—")}
        {row("Category", v.risk.category?.name ?? "—")}
        {doc.state === "closed" && doc.close_reason ? row("Closed because", doc.close_reason) : null}
        {row("Last change", `${v.version.change_note} (${date(v.version.created_at)})`)}
      </dl>
    </Section>
  );
}

/** AC-02, AC-06, AC-10: the scenarios, their pins, and newer runs to adopt. */
function Scenarios({ v, id, canAdopt, onAdopted }: { v: RiskView; id: string; canAdopt: boolean; onAdopted: () => void }) {
  const newer = v.links.filter((l) => l.pin && l.newer_runs.length > 0);
  return (
    <Section id="scenarios" title="Scenarios and pinned analyses" intro="Each linked scenario's exposure is the analysis pinned for it; a newer run changes nothing until it is adopted.">
      {newer.length > 0 && canAdopt ? (
        <div className="banner warn" role="status">
          <p>
            {newer.length === 1 ? "A newer run is available" : `Newer runs are available for ${newer.length} scenarios`}.
          </p>
          <ReasonAction
            label="Adopt newer runs"
            title="Adopt newer runs"
            fieldLabel="Change note"
            description={<p>Saves a new version of the risk pinning the newest run of each scenario that has one, with nothing else changed.</p>}
            submitLabel="Adopt"
            onSubmit={async (note) => {
              await send("POST", `/api/v1/register/risks/${id}/adopt`, { expected_version: v.risk.current_version, change_note: note });
              onAdopted();
            }}
          />
        </div>
      ) : null}
      {v.links.length === 0 ? (
        <p>No scenarios are linked: the risk is unquantified.</p>
      ) : (
        <div className="table-wrap">
          <table className="data">
            <caption className="sr-only">Linked scenarios and their pinned analyses</caption>
            <thead>
              <tr>
                <th scope="col">Scenario</th>
                <th scope="col">Pinned analysis</th>
                <th scope="col">Control set</th>
                <th scope="col">Pinned</th>
                <th scope="col">Newer runs</th>
              </tr>
            </thead>
            <tbody>
              {v.links.map((l) => (
                <ScenarioRow key={l.scenario_id} l={l} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Section>
  );
}

function ScenarioRow({ l }: { l: LinkView }) {
  const p = l.pin;
  return (
    <tr>
      <td>
        <a href={`/scenarios/${l.scenario_id}`}>{l.scenario_name ?? l.scenario_id}</a>
        {l.scenario_archived ? (
          <>
            {" "}
            <Badge tone="muted">Archived</Badge>
          </>
        ) : null}
      </td>
      <td>
        {p ? (
          <>
            <a href={`/analyses/runs/${p.run_id}`}>Run of version {p.run_scenario_version ?? "?"}</a>, finished {date(p.run_finished_at)}
            {p.run_scenario_version !== null && l.scenario_version !== null && p.run_scenario_version < l.scenario_version ? (
              <>
                {" "}
                <Badge tone="warn">Scenario now at version {l.scenario_version}</Badge>
              </>
            ) : null}
          </>
        ) : (
          <Badge tone="warn">No pinned analysis</Badge>
        )}
      </td>
      <td>
        {p ? p.control_set : "—"}
        {p?.reason ? <span className="muted"> ({p.reason})</span> : null}
      </td>
      <td>{p ? `version ${p.pinned_version}, ${date(p.pinned_at)}` : "—"}</td>
      <td>{l.newer_runs.length > 0 ? <Badge tone="info">{l.newer_runs.length === 1 ? "1 newer run" : `${l.newer_runs.length} newer runs`}</Badge> : "—"}</td>
    </tr>
  );
}

/** AC-07: the exposure, with the F-006 views of its result. */
function ExposureView({ v, currency }: { v: RiskView; currency: string | null }) {
  const e = v.exposure;
  const s = e.summary;
  const views = e.kind === "run" ? `/analyses/runs/${e.run_id}` : e.aggregate_id ? `/analyses/aggregates/${e.aggregate_id}` : undefined;
  const series: CurveSeries[] = s
    ? [{ label: v.risk.title ?? "Exposure", curve: s.curve as StoredCurve | undefined, percentiles: s.ale.percentiles, anyLoss: s.ale.p_positive ?? undefined }]
    : [];
  return (
    <Section
      id="exposure"
      title="Exposure"
      intro={
        e.kind === "aggregate"
          ? "The scenarios' pinned results combined (F-005), assuming their losses are independent: correlations between them are not modelled."
          : e.kind === "run"
            ? "The pinned result of the risk's one scenario."
            : undefined
      }
    >
      {e.kind === "none" ? (
        <p>No analysis is pinned, so the risk has no exposure yet.</p>
      ) : !e.visible || !s ? (
        <p role="status">
          {e.kind === "aggregate" && (e.state === "queued" || e.state === "running" || v.risk.status?.status === "computing")
            ? "The combined exposure is being computed."
            : "The exposure's result is not visible to you."}
        </p>
      ) : (
        <>
          <dl className="summary">
            <div>
              <dt>Mean annual loss</dt>
              <dd>{money(s.ale.mean, currency)}</dd>
            </div>
            <div>
              <dt>Median year</dt>
              <dd>{money(s.ale.percentiles.p50, currency)}</dd>
            </div>
            <div>
              <dt>1 year in 10 (90th percentile)</dt>
              <dd>{money(s.ale.percentiles.p90, currency)}</dd>
            </div>
            <div>
              <dt>1 year in 20 (95th percentile)</dt>
              <dd>{money(s.ale.percentiles.p95, currency)}</dd>
            </div>
            {s.ale.p_positive !== undefined ? (
              <div>
                <dt>Chance of any loss in a year</dt>
                <dd>{percent(s.ale.p_positive)}</dd>
              </div>
            ) : null}
          </dl>
          {s.curve ? (
            <ChartFigure title={`Loss exceedance, ${v.risk.title ?? "exposure"}`} description={describeExceedance(series, currency)} table={exceedanceTable(series, currency)}>
              {(ids) => <ExceedanceChart series={series} currency={currency} scale="log" {...ids} />}
            </ChartFigure>
          ) : null}
          {views ? (
            <p>
              <a href={views}>Every view of this result, with comparisons and downloads</a>
            </p>
          ) : null}
        </>
      )}
    </Section>
  );
}

/** Move the risk to another BU where the user may edit the register (AC-05). */
function MoveRisk({ id, from, bus, onDone }: { id: string; from: string; bus: BU[]; onDone: () => void }) {
  const targets = bus.filter((b) => b.id !== from);
  const [to, setTo] = useState(targets[0]?.id ?? "");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  if (targets.length === 0) return null;
  return (
    <DialogTrigger onOpenChange={() => setError(undefined)}>
      <Button>Move</Button>
      <Modal isDismissable>
        <Dialog>
          {({ close }) => (
            <form
              onSubmit={async (ev) => {
                ev.preventDefault();
                if (!reason.trim()) {
                  setError("A reason is required.");
                  return;
                }
                setBusy(true);
                try {
                  await send("POST", `/api/v1/register/risks/${id}/move`, { to_bu_id: to, reason });
                  close();
                  onDone();
                } catch (err) {
                  setError(describe(err));
                } finally {
                  setBusy(false);
                }
              }}
            >
              <Heading slot="title">Move this risk</Heading>
              <p>Its versions, scenarios and treatment move with it. Every linked scenario must be in the new business unit or below it.</p>
              <div className="field">
                <label htmlFor="move-to">Move to</label>
                <select id="move-to" value={to} onChange={(e) => setTo(e.target.value)}>
                  {targets.map((b) => (
                    <option key={b.id} value={b.id}>
                      {b.name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="field">
                <label htmlFor="move-reason">Reason</label>
                <textarea id="move-reason" rows={3} value={reason} onChange={(e) => setReason(e.target.value)} />
              </div>
              {error ? (
                <p role="alert" className="error-text">
                  {error}
                </p>
              ) : null}
              <div className="actions">
                <Button type="submit" className="react-aria-Button primary" isDisabled={busy}>
                  Move
                </Button>
                <Button slot="close">Cancel</Button>
              </div>
            </form>
          )}
        </Dialog>
      </Modal>
    </DialogTrigger>
  );
}

interface VersionRow {
  stream: "risk" | "treatment";
  version: number;
  change_note: string;
  created_at: string;
}

interface Change {
  pointer: string;
  kind: "added" | "removed" | "changed";
  from?: unknown;
  to?: unknown;
}

/** AC-03: every version of the risk (and of its treatment, to those who see it), and what changed. */
function RiskHistory({ id, current }: { id: string; current: number }) {
  const versions = useApi<{ versions: VersionRow[] }>(`/api/v1/register/risks/${id}/versions`);
  const [stream, setStream] = useState<"risk" | "treatment">("risk");
  const [from, setFrom] = useState(Math.max(1, current - 1));
  const [to, setTo] = useState(current);
  const [diff, setDiff] = useState<{ changes?: Change[]; title?: string; error?: string }>({});
  return (
    <Section id="history" title="History">
      <Status loaded={versions}>
        {(data) => {
          const of = data.versions.filter((x) => x.stream === stream).map((x) => x.version);
          return (
            <>
              <div className="table-wrap">
                <table className="data">
                  <caption className="sr-only">Versions, newest first</caption>
                  <thead>
                    <tr>
                      <th scope="col">Of</th>
                      <th scope="col">Version</th>
                      <th scope="col">Saved</th>
                      <th scope="col">Change note</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.versions.map((x) => (
                      <tr key={`${x.stream}-${x.version}`}>
                        <td>{x.stream === "risk" ? "Risk" : "Treatment"}</td>
                        <td>{x.version}</td>
                        <td>{date(x.created_at)}</td>
                        <td>{x.change_note}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {data.versions.length > 1 ? (
                <form
                  className="filters"
                  aria-label="Compare versions"
                  onSubmit={(e) => {
                    e.preventDefault();
                    getJSON<{ changes: Change[] }>(`/api/v1/register/risks/${id}/diff?stream=${stream}&from=${from}&to=${to}`).then(
                      (d) => setDiff({ changes: d.changes, title: `Changes to the ${stream} from version ${from} to ${to}` }),
                      (err: unknown) => setDiff({ error: describe(err) }),
                    );
                  }}
                >
                  {data.versions.some((x) => x.stream === "treatment") ? (
                    <div className="field">
                      <label htmlFor="diff-stream">Of</label>
                      <select id="diff-stream" value={stream} onChange={(e) => setStream(e.target.value as "risk" | "treatment")}>
                        <option value="risk">Risk</option>
                        <option value="treatment">Treatment</option>
                      </select>
                    </div>
                  ) : null}
                  <div className="field">
                    <label htmlFor="diff-from">From version</label>
                    <select id="diff-from" value={from} onChange={(e) => setFrom(Number(e.target.value))}>
                      {of.map((x) => (
                        <option key={x} value={x}>
                          {x}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="field">
                    <label htmlFor="diff-to">To version</label>
                    <select id="diff-to" value={to} onChange={(e) => setTo(Number(e.target.value))}>
                      {of.map((x) => (
                        <option key={x} value={x}>
                          {x}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="actions">
                    <button className="btn" type="submit">
                      Compare
                    </button>
                  </div>
                </form>
              ) : null}
              {diff.error ? (
                <p role="alert" className="error-text">
                  {diff.error}
                </p>
              ) : null}
              {diff.changes && diff.title ? (
                <div role="region" aria-label={diff.title} aria-live="polite">
                  <h3>{diff.title}</h3>
                  {diff.changes.length === 0 ? (
                    <p>No differences.</p>
                  ) : (
                    <div className="table-wrap">
                      <table className="data">
                        <caption className="sr-only">Changes</caption>
                        <thead>
                          <tr>
                            <th scope="col">Where</th>
                            <th scope="col">Change</th>
                            <th scope="col">Before</th>
                            <th scope="col">After</th>
                          </tr>
                        </thead>
                        <tbody>
                          {diff.changes.map((c) => (
                            <tr key={c.pointer}>
                              <td className="mono">{c.pointer}</td>
                              <td>{{ added: "Added", removed: "Removed", changed: "Changed" }[c.kind]}</td>
                              <td className="mono">{c.from === undefined ? "—" : show(c.from)}</td>
                              <td className="mono">{c.to === undefined ? "—" : show(c.to)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              ) : null}
            </>
          );
        }}
      </Status>
    </Section>
  );
}
