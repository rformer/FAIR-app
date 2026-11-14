import { useEffect, useState, type FormEvent } from "react";
import { ApiError, describe, getJSON, send } from "../api";
import { Badge, Section, Status, useApi, type Tone } from "../components";
import { auditHref, date } from "../links";
import type { BU, Head } from "../risk/types";
import { Bars } from "../charts/Bars.tsx";
import { ChartFigure, type ChartDownloads } from "../charts/ChartFigure.tsx";
import { barsTable, describeBars, describeExceedance, describeHistogram, exceedanceTable, histogramTable, type CurveSeries, type HistogramData } from "../charts/describe.ts";
import { ExceedanceChart } from "../charts/ExceedanceChart.tsx";
import { Histogram } from "../charts/Histogram.tsx";
import type { ScaleKind } from "../charts/scale.ts";
import { aggregateItem } from "./basket";
import { AddToComparison, BasketLink } from "./Compare";
import { usePolling } from "./Runs";
import { active, FAILURE_LABELS, money, percent, type Aggregate, type Run } from "./types";

// F-005 T-13 (AC-18, AC-19): aggregates of runs across scenarios: the list
// (only aggregates whose every member the reader sees), a request form and
// one aggregate with its members' contributions.

const TONE: Record<Aggregate["state"], Tone> = { queued: "muted", running: "info", succeeded: "ok", failed: "bad" };
const LABEL: Record<Aggregate["state"], string> = { queued: "Queued", running: "Running", succeeded: "Succeeded", failed: "Failed" };

function useCurrency() {
  return useApi<{ currency: string | null }>("/api/v1/risk/settings").data?.currency ?? null;
}

export function AggregatesPage() {
  const list = useApi<{ aggregates: Aggregate[] }>("/api/v1/analyses/aggregates");
  const runBUs = useApi<{ bus: BU[] }>("/api/v1/risk/bus?permission=analysis.run");
  const viewBUs = useApi<{ bus: BU[] }>("/api/v1/risk/bus?permission=analysis.view");
  const busy = list.data?.aggregates.some((a) => active(a.state)) ?? false;
  usePolling(busy, list.reload);
  useEffect(() => {
    document.title = "Aggregates · FAIR Risk Platform";
  }, []);
  const buName = (id: string) => viewBUs.data?.bus.find((b) => b.id === id)?.name ?? id;
  return (
    <>
      <h1>Aggregates</h1>
      <p className="lede">Annualized loss across several scenarios&apos; runs, combined as independent.</p>
      {(runBUs.data?.bus.length ?? 0) > 0 ? (
        <p className="actions">
          <a className="react-aria-Button primary" href="/analyses/aggregates/new">
            New aggregate
          </a>
        </p>
      ) : null}
      <Section id="aggregates" title="Aggregates" intro="Only aggregates whose every member run you can see are listed.">
        <Status loaded={list}>
          {(d) =>
            d.aggregates.length === 0 ? (
              <p>No aggregates yet.</p>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <caption className="sr-only">Aggregates, newest first</caption>
                  <thead>
                    <tr>
                      <th scope="col">Name</th>
                      <th scope="col">Business unit</th>
                      <th scope="col">Requested</th>
                      <th scope="col">Iterations</th>
                      <th scope="col">State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.aggregates.map((a) => (
                      <tr key={a.id}>
                        <td>
                          <a href={`/analyses/aggregates/${a.id}`}>{a.name}</a>
                        </td>
                        <td>{buName(a.bu_id)}</td>
                        <td>{date(a.requested_at)}</td>
                        <td>{a.iterations.toLocaleString("en-US")}</td>
                        <td>
                          <Badge tone={TONE[a.state]}>{LABEL[a.state]}</Badge>
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

interface MemberRow {
  scenario: string;
  run: string;
  set: string;
}

export function AggregateForm() {
  const runBUs = useApi<{ bus: BU[] }>("/api/v1/risk/bus?permission=analysis.run");
  const scenarios = useApi<{ scenarios: Head[] }>("/api/v1/scenarios?archived=false");
  const [bu, setBU] = useState("");
  const [name, setName] = useState("");
  const [rows, setRows] = useState<MemberRow[]>([
    { scenario: "", run: "", set: "" },
    { scenario: "", run: "", set: "" },
  ]);
  const [runs, setRuns] = useState<Record<string, Run[]>>({});
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    document.title = "New aggregate · FAIR Risk Platform";
  }, []);
  useEffect(() => {
    const first = runBUs.data?.bus[0];
    if (!bu && first) setBU(first.id);
  }, [bu, runBUs.data]);
  // Each chosen scenario's succeeded runs, once.
  useEffect(() => {
    for (const r of rows) {
      if (r.scenario && runs[r.scenario] === undefined) {
        setRuns((m) => ({ ...m, [r.scenario]: [] }));
        void getJSON<{ runs: Run[] }>(`/api/v1/analyses/runs?scenario=${r.scenario}`).then(
          (d) => setRuns((m) => ({ ...m, [r.scenario]: d.runs.filter((x) => x.state === "succeeded") })),
          () => undefined,
        );
      }
    }
  }, [rows, runs]);
  const update = (i: number, patch: Partial<MemberRow>) => setRows(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(undefined);
    const members = rows.filter((r) => r.run && r.set).map((r) => ({ run_id: r.run, control_set: r.set }));
    if (!name.trim() || members.length < 2) {
      setError("Name the aggregate and choose at least two members.");
      return;
    }
    setBusy(true);
    try {
      const a = await send<Aggregate>("POST", "/api/v1/analyses/aggregates", { bu_id: bu, name: name.trim(), members });
      window.location.assign(`/analyses/aggregates/${a.id}`);
    } catch (err) {
      setError(err instanceof ApiError && err.status === 409 ? (err.detail || describe(err)) : describe(err));
      setBusy(false);
    }
  };
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/analyses/aggregates">Aggregates</a>
      </nav>
      <h1>New aggregate</h1>
      <p className="lede">
        Members are control sets of succeeded runs, inside the business unit you choose, all with the same number of iterations. They are
        combined as independent: each member&apos;s years are shuffled by the aggregate&apos;s seed.
      </p>
      <form onSubmit={submit}>
        <Section id="aggregate" title="Aggregate">
          <div className="fields">
            <div className="field">
              <label htmlFor="agg-bu">Business unit</label>
              <select id="agg-bu" value={bu} onChange={(e) => setBU(e.target.value)}>
                {(runBUs.data?.bus ?? []).map((b) => (
                  <option key={b.id} value={b.id}>
                    {b.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="agg-name">Name</label>
              <input id="agg-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={200} />
            </div>
          </div>
        </Section>
        <Section id="members" title="Members">
          {rows.map((r, i) => {
            const n = i + 1;
            const theirs = runs[r.scenario] ?? [];
            const run = theirs.find((x) => x.id === r.run);
            return (
              <fieldset key={i} className="member">
                <legend>Member {n}</legend>
                <div className="fields">
                  <div className="field">
                    <label htmlFor={`m${n}-scenario`}>Member {n} scenario</label>
                    <select id={`m${n}-scenario`} value={r.scenario} onChange={(e) => update(i, { scenario: e.target.value, run: "", set: "" })}>
                      <option value="">Choose a scenario</option>
                      {(scenarios.data?.scenarios ?? []).map((s) => (
                        <option key={s.id} value={s.id}>
                          {s.name ?? s.id}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="field">
                    <label htmlFor={`m${n}-run`}>Member {n} run</label>
                    <select
                      id={`m${n}-run`}
                      value={r.run}
                      disabled={!r.scenario}
                      onChange={(e) => {
                        const chosen = theirs.find((x) => x.id === e.target.value);
                        update(i, { run: e.target.value, set: chosen?.control_sets[0] ?? "" });
                      }}
                    >
                      <option value="">Choose a succeeded run</option>
                      {theirs.map((x) => (
                        <option key={x.id} value={x.id}>
                          {date(x.requested_at)}: version {x.scenario_version}, {x.iterations.toLocaleString("en-US")} iterations, seed {x.seed}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="field">
                    <label htmlFor={`m${n}-set`}>Member {n} control set</label>
                    <select id={`m${n}-set`} value={r.set} disabled={!run} onChange={(e) => update(i, { set: e.target.value })}>
                      {(run?.control_sets ?? []).map((s) => (
                        <option key={s} value={s}>
                          {s}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
              </fieldset>
            );
          })}
          <p className="actions">
            <button type="button" className="btn" onClick={() => setRows([...rows, { scenario: "", run: "", set: "" }])} disabled={rows.length >= 200}>
              Add a member
            </button>
          </p>
        </Section>
        {error ? (
          <p role="alert" className="error-text">
            {error}
          </p>
        ) : null}
        <div className="actions">
          <button type="submit" className="btn primary" disabled={busy}>
            Request the aggregate
          </button>
          <a href="/analyses/aggregates">Cancel</a>
        </div>
      </form>
    </>
  );
}

export function AggregatePage({ id }: { id: string }) {
  const agg = useApi<Aggregate>(`/api/v1/analyses/aggregates/${id}`);
  const currency = useCurrency();
  usePolling(agg.data ? active(agg.data.state) : false, agg.reload);
  useEffect(() => {
    if (agg.data) document.title = `${agg.data.name} · Aggregates · FAIR Risk Platform`;
  }, [agg.data]);
  return (
    <Status loaded={agg}>
      {(a) => {
        const s = a.summary;
        const label = new Map(
          (a.members ?? []).map((m) => [m.position, m.aggregate_id ? (m.aggregate_name ?? m.aggregate_id) : `${m.scenario_name || m.scenario_id} (${m.control_set})`]),
        );
        return (
          <>
            <nav aria-label="Breadcrumb" className="crumbs">
              <a href="/analyses/aggregates">Aggregates</a>
            </nav>
            <h1>{a.name}</h1>
            <p className="lede">
              {a.iterations.toLocaleString("en-US")} iterations · seed {a.seed} · <Badge tone={TONE[a.state]}>{LABEL[a.state]}</Badge>
              {a.mixed_engine_versions ? (
                <>
                  {" "}
                  · <Badge tone="warn">Members from different engine versions</Badge>
                </>
              ) : null}
            </p>
            {a.failure ? (
              <p role="alert" className="error-text">
                {FAILURE_LABELS[a.failure] ?? a.failure}
                {a.failure_detail ? ` (${a.failure_detail})` : ""}
              </p>
            ) : null}
            {s ? (
              <Section id="result" title="Annualized loss" intro={s.independence}>
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
                    <dt>1 year in 20 (95th percentile)</dt>
                    <dd>{money(s.ale.percentiles.p95, currency)}</dd>
                  </div>
                  <div>
                    <dt>1 year in 100 (99th percentile)</dt>
                    <dd>{money(s.ale.percentiles.p99, currency)}</dd>
                  </div>
                  <div>
                    <dt>Chance of any loss in a year</dt>
                    <dd>{percent(s.ale.p_positive ?? null)}</dd>
                  </div>
                  <div>
                    <dt>Results digest</dt>
                    <dd className="mono">{a.result_digest}</dd>
                  </div>
                </dl>
              </Section>
            ) : null}
            {s && a.state === "succeeded" ? <AggregateCharts a={a} currency={currency} /> : null}
            <Section id="members" title="Members">
              <div className="table-wrap">
                <table className="data">
                  <caption className="sr-only">Members of the aggregate and what each contributes</caption>
                  <thead>
                    <tr>
                      <th scope="col">Member</th>
                      <th scope="col">Engine</th>
                      <th scope="col">Mean annual loss</th>
                      <th scope="col">Share of the 1-in-20 year</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(a.members ?? []).map((m) => {
                      const c = s?.contributions.find((x) => x.position === m.position);
                      return (
                        <tr key={m.position}>
                          <td>
                            <a href={m.aggregate_id ? `/analyses/aggregates/${m.aggregate_id}` : `/scenarios/${m.scenario_id}`}>{label.get(m.position)}</a>
                          </td>
                          <td>{m.engine_version ?? "—"}</td>
                          <td>{c ? money(c.mean, currency) : "—"}</td>
                          <td>{c ? percent(c.share_of_p95_year) : "—"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <p>
                <a href={auditHref(`analysis_aggregate:${a.id}`)}>Audit history of this aggregate</a>
              </p>
            </Section>
          </>
        );
      }}
    </Status>
  );
}

// F-006 T-06 (F-006-AC-07, AC-08, AC-14 to AC-17; design §4): an
// aggregate's views: its exceedance curve and annual loss distribution,
// each member's contribution, with the members, the independence statement
// and the mixed-engine notice beside them; each chart downloadable.
function AggregateCharts({ a, currency }: { a: Aggregate; currency: string | null }) {
  const s = a.summary!;
  const [scale, setScale] = useState<ScaleKind>("log");
  const h = useApi<HistogramData & { markers: { mean?: number | null; percentiles?: Record<string, number | null> } | null }>(
    `/api/v1/analyses/aggregates/${a.id}/histogram?scale=${scale}`,
  );
  const series: CurveSeries[] = [{ label: a.name, curve: s.curve, percentiles: s.ale.percentiles, anyLoss: s.ale.p_positive ?? undefined }];
  const members = (a.members ?? []).map((m) =>
    m.aggregate_id ? (m.aggregate_name ?? m.aggregate_id) : `${m.scenario_name || m.scenario_id} v${m.scenario_version} (${m.control_set})`,
  );
  const contributions = [...s.contributions]
    .sort((x, y) => y.mean - x.mean)
    .map((c) => ({ label: c.label, value: c.mean, share: c.share_of_p95_year }));
  const downloads = (view: string, chart: string, extra = ""): ChartDownloads => ({
    record: async (format) => (await send<{ download_id: string }>("POST", "/api/v1/analyses/downloads", { subject: "aggregate", id: a.id, view, format })).download_id,
    footer: (downloadId) => [
      `${chart}: ${a.name}`,
      `Members: ${members.join("; ")}`,
      `Aggregate ${a.id}; ${a.iterations.toLocaleString("en-US")} iterations, seed ${a.seed}; currency ${currency ?? "not set"}.`,
      `Results ${a.result_digest ?? "—"}`,
      s.independence,
      ...(a.mixed_engine_versions ? [`Members from engine versions ${(a.member_engine_versions ?? []).join(", ")}.`] : []),
      `Download ${downloadId}`,
    ],
    file: { subject: "aggregate", id: a.id, view },
    csvHref: `/api/v1/analyses/aggregates/${a.id}/data.csv?view=${view}${extra}`,
  });
  return (
    <>
      <Section id="aggregate-views" title="Views" intro={s.independence}>
        {a.mixed_engine_versions ? (
          <div className="callout warn" role="note" aria-label="Engine versions">
            <p>Its members were computed by different engine versions: {(a.member_engine_versions ?? []).join(", ")}.</p>
          </div>
        ) : null}
        <p>Members: {members.join("; ")}.</p>
        <fieldset className="inline-choice">
          <legend>Amount scale</legend>
          {(["log", "linear"] as const).map((k) => (
            <label key={k}>
              <input type="radio" name="aggregate-scale" value={k} checked={scale === k} onChange={() => setScale(k)} /> {k === "log" ? "Logarithmic" : "Linear"}
            </label>
          ))}
        </fieldset>
        <ChartFigure title={`Loss exceedance, ${a.name}`} description={describeExceedance(series, currency)} table={exceedanceTable(series, currency)} downloads={downloads("curve", "Loss exceedance")}>
          {(ids) => <ExceedanceChart series={series} currency={currency} scale={scale} {...ids} />}
        </ChartFigure>
        <Status loaded={h}>
          {(d) => (
            <ChartFigure title={`Annual loss, ${a.name}`} description={describeHistogram(d, currency, false)} table={histogramTable(d, currency, false)} downloads={downloads("histogram", "Annual loss", `&scale=${scale}`)}>
              {(ids) => <Histogram data={d} currency={currency} markers={d.markers} {...ids} />}
            </ChartFigure>
          )}
        </Status>
        <ChartFigure
          title="What each member contributes"
          description={describeBars("Mean annual loss of each member, with its share of the 1-in-20 year", contributions, currency)}
          table={barsTable("Each member's mean annual loss and share of the 1-in-20 year", contributions, currency)}
          downloads={downloads("contributions", "What each member contributes")}
        >
          {(ids) => <Bars bars={contributions} currency={currency} {...ids} />}
        </ChartFigure>
      </Section>
      <Section id="compare" title="Compare" intro="Compare this aggregate with runs or other aggregates.">
        <p className="actions">
          <AddToComparison item={aggregateItem(a.id)} label="this aggregate" />
        </p>
        <BasketLink />
      </Section>
    </>
  );
}
