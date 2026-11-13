import { useMemo, useState, type FormEvent } from "react";
import { send } from "../api";
import { Badge, Section, Status, useApi } from "../components";
import { auditHref, date } from "../links";
import { amountAt, probabilityAt, type Reading } from "../charts/curve.ts";
import { Bars, Tornado } from "../charts/Bars.tsx";
import { ChartFigure, type ChartDownloads } from "../charts/ChartFigure.tsx";
import {
  barsTable,
  describeBars,
  describeExceedance,
  describeHistogram,
  describeTornado,
  exceedanceTable,
  histogramTable,
  seriesPoints,
  signed,
  tornadoTable,
  type BarDatum,
  type CurveSeries,
  type HistogramData,
  type TornadoDatum,
} from "../charts/describe.ts";
import { ExceedanceChart } from "../charts/ExceedanceChart.tsx";
import { Histogram } from "../charts/Histogram.tsx";
import { formatAmountFull, formatProbability, formatShare, type ScaleKind } from "../charts/scale.ts";
import { factorLabel, FORM_LABELS, type Form } from "../risk/types";
import { runItem } from "./basket";
import { AddToComparison, BasketLink } from "./Compare";
import { RunStateBadge, usePolling } from "./Runs";
import { active, FAILURE_LABELS, type Run, type SetSummary } from "./types";

// F-006 T-05 (F-006-AC-01 to AC-06, AC-09, AC-14 to AC-17; design §4,
// §6.1): a run's page. The record (AC-06), then the views: exceedance
// curves with the cursor and lookups, the distribution of annual loss,
// the breakdown, the inputs that drive it, and each control set against
// the current one. Every chart has its text alternative, data table and
// downloads (images recorded first, CSV from the service).

interface HistogramResponse extends HistogramData {
  markers: { mean?: number | null; percentiles?: Record<string, number | null> } | null;
}

/** The label of a sensitivity input: the deepest pointer segment people have a name for. */
export function inputLabel(pointer: string, kind: string, factor: string | null): string {
  if (kind === "control_effect" && factor) return `Control effect on ${factorLabel(factor).toLowerCase()}`;
  const parts = pointer.split("/").filter(Boolean).reverse();
  for (const p of parts) {
    if (p in FORM_LABELS) return FORM_LABELS[p as Form];
    const l = factorLabel(p);
    if (l !== p) return l;
  }
  return pointer || "Input";
}

function useCurrency(): string | null {
  return useApi<{ currency: string | null }>("/api/v1/risk/settings").data?.currency ?? null;
}

export function RunPage({ id }: { id: string }) {
  const run = useApi<Run>(`/api/v1/analyses/runs/${id}`);
  usePolling(run.data ? active(run.data.state) : false, run.reload);
  const currency = useCurrency();
  return (
    <Status loaded={run}>
      {(r) => <RunView run={r} currency={currency} />}
    </Status>
  );
}

function RunView({ run, currency }: { run: Run; currency: string | null }) {
  const scenario = useApi<{ scenario: { name: string | null } }>(`/api/v1/scenarios/${run.scenario_id}`);
  const name = scenario.data?.scenario.name ?? "Scenario";
  const title = `${name}, version ${run.scenario_version}`;
  const results = run.results ?? [];
  const sets = results.map((x) => x.control_set);
  const independence = results[0]?.summary.independence ?? "Every input is sampled independently.";

  /** Downloads of a view: the image recorded first, its footer, the CSV link. */
  const downloads = (view: string, chart: string, set?: string, extra = ""): ChartDownloads => ({
    record: async (format) => (await send<{ download_id: string }>("POST", "/api/v1/analyses/downloads", { subject: "run", id: run.id, view, format })).download_id,
    footer: (downloadId) => [
      `${chart}: ${title}`,
      `Control sets: ${set ?? sets.join(", ")}. Currency: ${currency ?? "not set"}.`,
      `Run ${run.id}; ${run.iterations.toLocaleString("en-US")} iterations, seed ${run.seed}; engine ${run.engine?.version ?? "?"} (${run.engine?.architecture ?? "?"}).`,
      `Input bundle ${run.bundle_digest}`,
      `Results ${run.result_digest ?? "—"}`,
      independence,
      `Download ${downloadId}`,
    ],
    file: { subject: "run", id: run.id, view },
    csvHref: `/api/v1/analyses/runs/${run.id}/data.csv?view=${view}${set ? `&set=${encodeURIComponent(set)}` : ""}${extra}`,
  });

  return (
    <>
      <h1>Simulation of {title}</h1>
      <p>
        <a href={`/scenarios/${run.scenario_id}`}>Back to the scenario</a> · <a href={auditHref(`analysis_run:${run.id}`)}>Audit history of this run</a>
      </p>
      <Record run={run} name={name} independence={independence} />
      {run.state === "succeeded" ? (
        <Section id="compare" title="Compare" intro="Compare a control set of this run with other runs or aggregates. The comparison collects here until you open it.">
          <p className="actions">
            {sets.map((s) => (
              <AddToComparison key={s} item={runItem(run.id, s)} label={s} />
            ))}
          </p>
          <BasketLink />
        </Section>
      ) : null}
      {run.state !== "succeeded" ? (
        <p role="status">
          {active(run.state) ? "The views appear when the run succeeds." : "This run has no results."}
        </p>
      ) : (
        <>
          <Exceedance run={run} currency={currency} downloads={downloads("curve", "Loss exceedance curves")} />
          <Distribution run={run} currency={currency} downloads={downloads} />
          <Breakdown run={run} currency={currency} downloads={downloads("breakdown", "Annual loss by part")} />
          <Drivers run={run} currency={currency} downloads={downloads} />
          {sets.length > 1 ? <ControlSets run={run} currency={currency} downloads={downloads} /> : null}
        </>
      )}
    </>
  );
}

/** The run's record (AC-06). */
function Record({ run, name, independence }: { run: Run; name: string; independence: string }) {
  return (
    <Section id="record" title="What was simulated">
      <p className="callout">{independence}</p>
      <dl className="summary">
        <div>
          <dt>State</dt>
          <dd>
            <RunStateBadge run={run} />
            {run.failure ? <span> {FAILURE_LABELS[run.failure] ?? run.failure}</span> : null}
          </dd>
        </div>
        <div>
          <dt>Scenario</dt>
          <dd>
            <a href={`/scenarios/${run.scenario_id}`}>{name}</a>, version {run.scenario_version}
          </dd>
        </div>
        <div>
          <dt>Control sets</dt>
          <dd>{run.control_sets.join(", ")}</dd>
        </div>
        <div>
          <dt>Iterations and seed</dt>
          <dd>
            {run.iterations.toLocaleString("en-US")} iterations, seed {run.seed}
          </dd>
        </div>
        <div>
          <dt>Requested</dt>
          <dd>{date(run.requested_at)}</dd>
        </div>
        <div>
          <dt>Engine</dt>
          <dd>{run.engine ? `${run.engine.version} on ${run.engine.architecture ?? "unknown"}` : "—"}</dd>
        </div>
        <div>
          <dt>Input bundle digest</dt>
          <dd className="mono wrap">{run.bundle_digest}</dd>
        </div>
        <div>
          <dt>Results digest</dt>
          <dd className="mono wrap">{run.result_digest ?? "—"}</dd>
        </div>
        {(run.results ?? []).map((x) => (
          <div key={x.control_set}>
            <dt>Convergence ({x.control_set})</dt>
            <dd>
              {x.summary.convergence.converged ? <Badge tone="ok">Converged</Badge> : <Badge tone="warn">Not converged</Badge>}{" "}
              <span className="muted">
                standard error of the mean {formatAmountFull(x.summary.convergence.se, null)}
                {x.summary.convergence.rse === null ? "" : `, relative ${formatShare(Math.abs(x.summary.convergence.rse))}`}
              </span>
            </dd>
          </div>
        ))}
      </dl>
      {run.warnings.length > 0 ? (
        <>
          <h3>Warnings</h3>
          <ul>
            {run.warnings.map((w, i) => (
              <li key={i}>
                <span className="mono">{w.code}</span>
                {w.control_set ? ` (${w.control_set})` : ""}
                {w.pointer ? (
                  <>
                    {" "}
                    at <span className="mono">{w.pointer}</span>
                  </>
                ) : null}
                {w.detail ? `: ${w.detail}` : ""}
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </Section>
  );
}

function ScaleChoice({ value, onChange, name }: { value: ScaleKind; onChange: (s: ScaleKind) => void; name: string }) {
  return (
    <fieldset className="inline-choice">
      <legend>Amount scale</legend>
      {(["log", "linear"] as const).map((s) => (
        <label key={s}>
          <input type="radio" name={name} value={s} checked={value === s} onChange={() => onChange(s)} /> {s === "log" ? "Logarithmic" : "Linear"}
        </label>
      ))}
    </fieldset>
  );
}

function SetChoice({ sets, value, onChange, label }: { sets: string[]; value: string; onChange: (s: string) => void; label: string }) {
  return (
    <label className="field">
      {label}{" "}
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        {sets.map((s) => (
          <option key={s} value={s}>
            {s}
          </option>
        ))}
      </select>
    </label>
  );
}

function curveSeries(run: Run): CurveSeries[] {
  return (run.results ?? []).map((x) => ({
    label: x.control_set,
    curve: x.summary.curve,
    percentiles: x.summary.ale.percentiles,
    anyLoss: x.summary.ale.p_positive ?? undefined,
  }));
}

/** Exceedance curves, the cursor and the lookups (AC-01, AC-05). */
function Exceedance({ run, currency, downloads }: { run: Run; currency: string | null; downloads: ChartDownloads }) {
  const [scale, setScale] = useState<ScaleKind>("log");
  const series = useMemo(() => curveSeries(run), [run]);
  return (
    <Section id="exceedance" title="Loss exceedance" intro="The chance that a year's loss exceeds an amount, for each control set. The current set is the solid line.">
      <ScaleChoice value={scale} onChange={setScale} name="exceedance-scale" />
      <ChartFigure title="Loss exceedance curves" description={describeExceedance(series, currency)} table={exceedanceTable(series, currency)} downloads={downloads}>
        {(ids) => <ExceedanceChart series={series} currency={currency} scale={scale} {...ids} />}
      </ChartFigure>
      <Lookups series={series} currency={currency} />
    </Section>
  );
}

function reading(r: Reading, show: (v: number) => string): string {
  switch (r.kind) {
    case "exact":
      return r.percentile ? `${show(r.value)} (exact, ${r.percentile})` : show(r.value);
    case "interpolated":
      return `${show(r.value)} (read from the curve)`;
    case "between":
      return `between ${show(r.low)} and ${show(r.high)}`;
    case "none_exceeded":
      return "no simulated year exceeded it";
    case "invalid":
      return "—";
  }
}

/** Amount to probability and probability to amount, read from the curves (AC-05). */
function Lookups({ series, currency }: { series: CurveSeries[]; currency: string | null }) {
  const [amount, setAmount] = useState("");
  const [prob, setProb] = useState("");
  const [shown, setShown] = useState<{ amount?: number; prob?: number }>({});
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const a = amount.trim() === "" ? undefined : Number(amount.replace(/[, ]/g, ""));
    const p = prob.trim() === "" ? undefined : Number(prob.replace("%", "")) / 100;
    setShown({ amount: a, prob: p });
  };
  return (
    <form className="lookups" onSubmit={submit} aria-labelledby="lookups-h">
      <h3 id="lookups-h">Read the curves</h3>
      <label className="field">
        Annual loss{currency ? ` (${currency})` : ""}
        <input inputMode="decimal" value={amount} onChange={(e) => setAmount(e.target.value)} />
      </label>
      <label className="field">
        Chance of exceeding (%)
        <input inputMode="decimal" value={prob} onChange={(e) => setProb(e.target.value)} />
      </label>
      <button type="submit" className="btn">
        Read
      </button>
      {shown.amount !== undefined || shown.prob !== undefined ? (
        <div role="status" className="lookup-results">
          {shown.amount !== undefined ? (
            <p>
              Chance of losing more than {Number.isFinite(shown.amount) ? formatAmountFull(shown.amount, currency) : amount} in a year:{" "}
              {series.map((s, i) => `${i ? "; " : ""}${s.label} ${reading(probabilityAt(seriesPoints(s), shown.amount ?? NaN, s.anyLoss), formatProbability)}`).join("")}.
            </p>
          ) : null}
          {shown.prob !== undefined ? (
            <p>
              Annual loss exceeded with a {Number.isFinite(shown.prob) ? formatProbability(shown.prob) : prob} chance:{" "}
              {series.map((s, i) => `${i ? "; " : ""}${s.label} ${reading(amountAt(seriesPoints(s), shown.prob ?? NaN, s.anyLoss), (v) => formatAmountFull(v, currency))}`).join("")}.
            </p>
          ) : null}
        </div>
      ) : null}
    </form>
  );
}

/** A set's annual loss distribution (AC-02). */
function Distribution({ run, currency, downloads }: { run: Run; currency: string | null; downloads: (view: string, chart: string, set?: string, extra?: string) => ChartDownloads }) {
  const sets = (run.results ?? []).map((x) => x.control_set);
  const [set, setSet] = useState(sets[0] ?? "");
  const [scale, setScale] = useState<ScaleKind>("log");
  const h = useApi<HistogramResponse>(`/api/v1/analyses/runs/${run.id}/histogram?set=${encodeURIComponent(set)}&scale=${scale}`);
  return (
    <Section id="distribution" title="Distribution of annual loss" intro="How often each amount of loss occurs in a simulated year. Years with no loss are counted apart.">
      <div className="chart-controls">
        <SetChoice sets={sets} value={set} onChange={setSet} label="Control set" />
        <ScaleChoice value={scale} onChange={setScale} name="distribution-scale" />
      </div>
      <Status loaded={h}>
        {(d) => (
          <ChartFigure
            title={`Annual loss, ${set}`}
            description={describeHistogram(d, currency, false)}
            table={histogramTable(d, currency, false)}
            downloads={downloads("histogram", `Annual loss, ${set}`, set, `&scale=${scale}`)}
          >
            {(ids) => <Histogram data={d} currency={currency} markers={d.markers} {...ids} />}
          </ChartFigure>
        )}
      </Status>
    </Section>
  );
}

function breakdownBars(s: SetSummary): BarDatum[] {
  const b = s.breakdown;
  const total = (b.primary ?? 0) + (b.secondary ?? 0);
  const share = (v: number | null) => (v === null || total === 0 ? null : v / total);
  const out: BarDatum[] = [
    { label: "Primary loss", value: b.primary ?? 0, share: share(b.primary) },
    { label: "Secondary loss", value: b.secondary ?? 0, share: share(b.secondary) },
  ];
  for (const [f, v] of Object.entries(b.forms ?? {})) out.push({ label: FORM_LABELS[f as Form] ?? f, value: v ?? 0, share: share(v) });
  for (const [g, v] of Object.entries(b.stakeholders ?? {})) out.push({ label: `Stakeholders: ${g}`, value: v ?? 0, share: share(v) });
  return out;
}

/** The split of annual loss, per set (AC-03). */
function Breakdown({ run, currency, downloads }: { run: Run; currency: string | null; downloads: ChartDownloads }) {
  return (
    <Section id="breakdown" title="Annual loss by part" intro="The mean annual loss split into primary and secondary loss, and by form of loss.">
      {(run.results ?? []).map((x) => {
        const bars = breakdownBars(x.summary);
        return (
          <ChartFigure key={x.control_set} title={`Mean annual loss by part, ${x.control_set}`} description={describeBars(`Mean annual loss by part, ${x.control_set}`, bars, currency)} table={barsTable(`Mean annual loss by part, ${x.control_set}`, bars, currency)} downloads={downloads}>
            {(ids) => <Bars bars={bars} currency={currency} {...ids} />}
          </ChartFigure>
        );
      })}
    </Section>
  );
}

/** The inputs that drive annual loss, per set (AC-04). */
function Drivers({ run, currency, downloads }: { run: Run; currency: string | null; downloads: (view: string, chart: string, set?: string) => ChartDownloads }) {
  const sets = (run.results ?? []).map((x) => x.control_set);
  const [set, setSet] = useState(sets[0] ?? "");
  const s = (run.results ?? []).find((x) => x.control_set === set)?.summary;
  const inputs: TornadoDatum[] = (s?.sensitivity?.inputs ?? []).map((i) => ({
    label: inputLabel(i.pointer, i.kind, i.factor),
    pointer: i.pointer,
    low: i.low.change,
    high: i.high.change,
    spearman: i.spearman,
  }));
  return (
    <Section id="drivers" title="What drives the result" intro="The change in mean annual loss when each input is held at the low (5th percentile) and high (95th percentile) end of its range, strongest first.">
      <SetChoice sets={sets} value={set} onChange={setSet} label="Control set" />
      <ChartFigure title={`Inputs that drive annual loss, ${set}`} description={describeTornado(inputs, currency)} table={tornadoTable(inputs, currency)} downloads={downloads("sensitivity", `Inputs that drive annual loss, ${set}`, set)}>
        {(ids) => <Tornado inputs={inputs} currency={currency} {...ids} />}
      </ChartFigure>
    </Section>
  );
}

const COMPARED = [
  ["mean", "Mean annual loss"],
  ["p50", "Median year"],
  ["p90", "1 year in 10"],
  ["p95", "1 year in 20"],
  ["p99", "1 year in 100"],
] as const;

/** Each set against the current one (AC-09). */
function ControlSets({ run, currency, downloads }: { run: Run; currency: string | null; downloads: (view: string, chart: string, set?: string, extra?: string) => ChartDownloads }) {
  const results = run.results ?? [];
  const current = results[0];
  const others = results.slice(1);
  const [set, setSet] = useState(others[0]?.control_set ?? "");
  const h = useApi<HistogramResponse>(
    `/api/v1/analyses/runs/${run.id}/histogram?set=${encodeURIComponent(set)}&relative_to=${encodeURIComponent(current?.control_set ?? "")}`,
  );
  if (!current) return null;
  const base = (k: string) => (k === "mean" ? current.summary.ale.mean : current.summary.ale.percentiles[k]) ?? null;
  return (
    <Section id="control-sets" title={`Control sets against ${current.control_set}`} intro="Each control set against the current one. Control sets of one run share their random numbers, so differences come from the controls.">
      <div className="table-wrap">
        <table className="data">
          <caption>Differences from {current.control_set}</caption>
          <thead>
            <tr>
              <th scope="col">Control set</th>
              {COMPARED.map(([, l]) => (
                <th key={l} scope="col">
                  {l}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {others.map((x) => {
              const c = x.summary.comparison;
              return (
                <tr key={x.control_set}>
                  <th scope="row">{x.control_set}</th>
                  {COMPARED.map(([k]) => {
                    const d = c ? (k === "mean" ? c.mean : c.percentiles[k]) : undefined;
                    const b = base(k);
                    if (d === undefined || d === null) return <td key={k}>—</td>;
                    const word = d < 0 ? "reduction" : d > 0 ? "increase" : "no change";
                    return (
                      <td key={k}>
                        {signed(d, currency)} <span className="muted">({word}{b ? `, ${formatShare(Math.abs(d / b))}` : ""})</span>
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <SetChoice sets={others.map((x) => x.control_set)} value={set} onChange={setSet} label="Year-by-year difference for" />
      <Status loaded={h}>
        {(d) => (
          <ChartFigure
            title={`Year-by-year difference, ${set} minus ${current.control_set}`}
            description={`${describeHistogram(d, currency, true)} A negative difference is a reduction.`}
            table={histogramTable(d, currency, true)}
            downloads={downloads("histogram", `Year-by-year difference, ${set} minus ${current.control_set}`, set, `&scale=linear&relative_to=${encodeURIComponent(current.control_set)}`)}
          >
            {(ids) => <Histogram data={d} currency={currency} difference markers={d.markers} {...ids} />}
          </ChartFigure>
        )}
      </Status>
    </Section>
  );
}
