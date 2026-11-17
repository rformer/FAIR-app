import { useEffect, useState } from "react";
import { describe, send } from "../api";
import { useCurrency } from "../acceptance/Acceptances";
import { money } from "../analysis/types";
import { Bars } from "../charts/Bars.tsx";
import { ChartFigure } from "../charts/ChartFigure.tsx";
import type { StoredCurve } from "../charts/curve.ts";
import { barsTable, describeBars, describeExceedance, exceedanceTable, type CurveSeries } from "../charts/describe.ts";
import { ExceedanceChart } from "../charts/ExceedanceChart.tsx";
import { Lines } from "../charts/Lines.tsx";
import { formatAmount } from "../charts/scale.ts";
import { Badge, Section, Status, useApi, type Tone } from "../components";
import type { BU } from "../risk/types";
import { dateTime, leftOutText } from "./types";
import { coverageSeries, describeCoverageTrend, describeExposureTrend, exposureSeries, trendTable, type TrendPoint } from "./trend";

// F-010 T-17 (F-010-AC-01 to AC-07; design §3.1, §3.2): the portfolio
// dashboard of a business unit subtree, as the viewer sees it: the latest
// roll-up as a distribution (never a score), the largest risks, the units
// below, coverage, acceptances and treatment, what is left out and why, and
// the trends. Every chart has its text alternative and data table, and
// every figure links to what it summarizes (the viewer's own permissions
// apply there).

interface Dashboard {
  bu_id: string;
  as_of: string;
  rollup: null | {
    id: string;
    finished_at: string;
    stale: boolean;
    summary: { ale: { mean: number | null; percentiles: Record<string, number | null>; p_positive?: number | null }; curve?: unknown };
    covers: number;
    left_out: Record<string, number>;
    left_out_total: number;
    excluded_bus: number;
  };
  largest: { id: string; title: string; owner: string; mean: number | null; p10: number | null; p90: number | null; status: string }[];
  children: { bu_id: string; name: string; open_risks: number; quantified: number; mean_sum: number; rollup_p90: number | null }[];
  coverage: { open: number; current: number; stale: number; computing: number; unquantified: number };
  acceptances: Record<string, number>;
  treatment: Record<string, number>;
  restricted: null | { units: number; open_risks: number; current: number; stale: number; computing: number; unquantified: number; mean_sum: number; label: string };
  left_out: Record<string, number>;
}

const STATUS: Record<string, { label: string; tone: Tone }> = {
  current: { label: "Current", tone: "ok" },
  stale: { label: "Stale", tone: "warn" },
  computing: { label: "Computing", tone: "info" },
  unquantified: { label: "Unquantified", tone: "muted" },
};

const PERIODS: [string, string][] = [
  ["90", "The last 90 days"],
  ["365", "The last year"],
  ["1095", "The last three years"],
];

export function useReportBUs(permission: "report.view" | "report.export") {
  return useApi<{ bus: BU[] }>(`/api/v1/reports/bus?permission=${permission}`);
}

function Tile({ n, label, href }: { n: number; label: string; href?: string }) {
  return (
    <li>
      <span className="n">{n}</span> {href ? <a href={href}>{label}</a> : label}
    </li>
  );
}

export function DashboardPage({ search = window.location.search }: { search?: string }) {
  const q = new URLSearchParams(search);
  const bus = useReportBUs("report.view");
  const [bu, setBu] = useState(q.get("bu") ?? "");
  useEffect(() => {
    if (!bu && bus.data?.bus[0]) setBu(bus.data.bus[0].id);
  }, [bu, bus.data]);
  const name = bus.data?.bus.find((b) => b.id === bu)?.name ?? "";
  useEffect(() => {
    document.title = `${name ? `${name} · ` : ""}Portfolio dashboard · FAIR Risk Platform`;
  }, [name]);
  return (
    <>
      <h1>Portfolio dashboard</h1>
      <p className="lede">A business unit and everything below it, from the data you can see: exposure as a distribution of annual loss, the register's coverage, acceptances and treatment, and how they have moved.</p>
      <p className="actions">
        <a href={`/reports/new${bu ? `?bu=${bu}` : ""}`}>Generate a report</a> · <a href="/reports/mine">My reports</a> · <a href="/reports/schedules">Scheduled reports</a>
      </p>
      <Status loaded={bus}>
        {(d) =>
          d.bus.length === 0 ? (
            <p>You do not hold report.view at any business unit.</p>
          ) : (
            <>
              <form className="filters" aria-label="Choose the business unit" onSubmit={(e) => e.preventDefault()}>
                <div className="field">
                  <label htmlFor="dash-bu">Business unit (with everything below it)</label>
                  <select
                    id="dash-bu"
                    value={bu}
                    onChange={(e) => {
                      setBu(e.target.value);
                      window.history.replaceState(null, "", `/reports?bu=${e.target.value}`);
                    }}
                  >
                    {d.bus.map((b) => (
                      <option key={b.id} value={b.id}>
                        {b.name}
                      </option>
                    ))}
                  </select>
                </div>
              </form>
              {bu ? <DashboardBody key={bu} bu={bu} name={name} /> : null}
            </>
          )
        }
      </Status>
    </>
  );
}

function DashboardBody({ bu, name }: { bu: string; name: string }) {
  const dash = useApi<Dashboard>(`/api/v1/reports/dashboard?bu=${bu}`);
  const currency = useCurrency();
  return (
    <Status loaded={dash}>
      {(d) => (
        <>
          <p className="muted">Read at {dateTime(d.as_of)}.</p>
          <Exposure d={d} name={name} currency={currency} />
          <Largest d={d} currency={currency} />
          <Children d={d} currency={currency} />
          <Section id="coverage" title="Coverage" intro="Open risks by whether their exposure comes from a current analysis.">
            <ul className="tiles">
              <Tile n={d.coverage.open} label="Open risks" href={`/register?bu=${bu}`} />
              <Tile n={d.coverage.current} label="Current" href={`/register?bu=${bu}&status=current`} />
              <Tile n={d.coverage.stale} label="Stale" href={`/register?bu=${bu}&status=stale`} />
              <Tile n={d.coverage.computing} label="Computing" href={`/register?bu=${bu}&status=computing`} />
              <Tile n={d.coverage.unquantified} label="Unquantified" href={`/register?bu=${bu}&status=unquantified`} />
            </ul>
          </Section>
          <Section id="acceptances" title="Acceptances">
            <ul className="tiles">
              <Tile n={d.acceptances["active"] ?? 0} label="Active" href={`/acceptances?bu=${bu}&state=active`} />
              <Tile n={d.acceptances["expiring"] ?? 0} label="Expiring within 30 days" href={`/acceptances?bu=${bu}&expiring_within=30`} />
              <Tile n={d.acceptances["expired"] ?? 0} label="Expired" href={`/acceptances?bu=${bu}&state=expired`} />
              <Tile n={d.acceptances["pending"] ?? 0} label="Awaiting decision" href={`/acceptances?bu=${bu}&state=pending`} />
              <Tile n={d.acceptances["suspended"] ?? 0} label="Suspended for review" href={`/acceptances?bu=${bu}&state=suspended`} />
            </ul>
          </Section>
          <Section id="treatment" title="Treatment">
            <ul className="tiles">
              <Tile n={d.treatment["open"] ?? 0} label="Open actions" />
              <Tile n={d.treatment["overdue"] ?? 0} label="Overdue actions" href={`/register?bu=${bu}&overdue=true`} />
            </ul>
          </Section>
          <Section id="left-out" title="What this leaves out">
            {d.restricted ? (
              <p>
                {d.restricted.label.charAt(0).toUpperCase() + d.restricted.label.slice(1)}: {d.restricted.units} business units, {d.restricted.open_risks} open risks (
                {d.restricted.current} current, {d.restricted.stale} stale, {d.restricted.unquantified} unquantified), whose means sum to{" "}
                {money(d.restricted.mean_sum, currency)}. Their risks are not shown.
              </p>
            ) : null}
            {leftOutText(d.left_out).length ? (
              <ul>
                {leftOutText(d.left_out).map((t) => (
                  <li key={t}>{t}</li>
                ))}
              </ul>
            ) : (
              <p>Nothing: every open risk below this business unit is visible to you and quantified.</p>
            )}
          </Section>
          <Trend bu={bu} currency={currency} />
        </>
      )}
    </Status>
  );
}

function Exposure({ d, name, currency }: { d: Dashboard; name: string; currency: string | null }) {
  const [requested, setRequested] = useState<{ id?: string; error?: string }>({});
  const r = d.rollup;
  if (!r) {
    return (
      <Section id="exposure" title="Exposure" intro="Exposure comes from a roll-up of the business unit: the open risks' results simulated together.">
        <p>You have no roll-up of {name || "this business unit"} yet, so there is no total exposure to show.</p>
        {requested.id ? (
          <p role="status">
            Requested. <a href={`/register/rollups/${requested.id}`}>Follow the roll-up</a>, then come back to this page.
          </p>
        ) : (
          <button
            type="button"
            className="react-aria-Button primary"
            onClick={async () => {
              try {
                const x = await send<{ id: string }>("POST", "/api/v1/register/rollups", { bu_id: d.bu_id });
                setRequested({ id: x.id });
              } catch (err) {
                setRequested({ error: describe(err) });
              }
            }}
          >
            Request a roll-up
          </button>
        )}
        {requested.error ? (
          <p role="alert" className="error-text">
            {requested.error}
          </p>
        ) : null}
      </Section>
    );
  }
  const s = r.summary;
  const series: CurveSeries[] = [{ label: `Roll-up of ${name}`, curve: s.curve as StoredCurve | undefined, percentiles: s.ale.percentiles, anyLoss: s.ale.p_positive ?? undefined }];
  return (
    <Section id="exposure" title="Exposure">
      <p>
        From <a href={`/register/rollups/${r.id}`}>your roll-up of {dateTime(r.finished_at)}</a>, covering {r.covers} risks
        {r.left_out_total ? ` and leaving out ${r.left_out_total}` : ""}
        {r.excluded_bus ? `; ${r.excluded_bus} business units are excluded by their roll-up mode` : ""}.{" "}
        {r.stale ? <Badge tone="warn">Stale</Badge> : <Badge tone="ok">Up to date</Badge>}
      </p>
      {r.stale ? (
        <div className="banner warn" role="status">
          <p>A roll-up now would include something else: a pin changed, or a risk was closed, added or became stale. Request a new one from the roll-up's page.</p>
        </div>
      ) : null}
      <dl className="summary">
        <div>
          <dt>Mean annual loss</dt>
          <dd>{money(s.ale.mean, currency)}</dd>
        </div>
        <div>
          <dt>1 year in 10 is below (10th percentile)</dt>
          <dd>{money(s.ale.percentiles["p10"], currency)}</dd>
        </div>
        <div>
          <dt>Median (50th percentile)</dt>
          <dd>{money(s.ale.percentiles["p50"], currency)}</dd>
        </div>
        <div>
          <dt>1 year in 10 is above (90th percentile)</dt>
          <dd>{money(s.ale.percentiles["p90"], currency)}</dd>
        </div>
        <div>
          <dt>1 year in 100 is above (99th percentile)</dt>
          <dd>{money(s.ale.percentiles["p99"], currency)}</dd>
        </div>
      </dl>
      {s.curve ? (
        <ChartFigure title={`Loss exceedance, roll-up of ${name}`} description={describeExceedance(series, currency)} table={exceedanceTable(series, currency)}>
          {(ids) => <ExceedanceChart series={series} currency={currency} scale="log" {...ids} />}
        </ChartFigure>
      ) : null}
    </Section>
  );
}

function Largest({ d, currency }: { d: Dashboard; currency: string | null }) {
  const bars = d.largest.filter((x) => x.mean !== null).map((x) => ({ label: x.title, value: x.mean as number }));
  return (
    <Section id="largest" title="Largest open risks" intro="By mean annual loss, with the range from the 10th to the 90th percentile.">
      {d.largest.length === 0 ? (
        <p>No open risk is quantified.</p>
      ) : (
        <>
          <div className="table-wrap">
            <table className="data">
              <caption className="sr-only">Largest open risks by mean annual loss</caption>
              <thead>
                <tr>
                  <th scope="col">Risk</th>
                  <th scope="col">Owner</th>
                  <th scope="col">Mean annual loss</th>
                  <th scope="col">10th percentile</th>
                  <th scope="col">90th percentile</th>
                  <th scope="col">Exposure</th>
                </tr>
              </thead>
              <tbody>
                {d.largest.map((x) => (
                  <tr key={x.id}>
                    <td>
                      <a href={`/register/risks/${x.id}`}>{x.title}</a>
                    </td>
                    <td>{x.owner || "—"}</td>
                    <td>{money(x.mean, currency)}</td>
                    <td>{money(x.p10, currency)}</td>
                    <td>{money(x.p90, currency)}</td>
                    <td>
                      <Badge tone={STATUS[x.status]?.tone ?? "muted"}>{STATUS[x.status]?.label ?? x.status}</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {bars.length ? (
            <ChartFigure title="Mean annual loss of the largest risks" description={describeBars("Mean annual loss of the largest open risks", bars, currency)} table={barsTable("The largest open risks' mean annual loss", bars, currency)}>
              {(ids) => <Bars bars={bars} currency={currency} {...ids} />}
            </ChartFigure>
          ) : null}
        </>
      )}
    </Section>
  );
}

function Children({ d, currency }: { d: Dashboard; currency: string | null }) {
  if (d.children.length === 0) return null;
  const bars = d.children.map((c) => ({ label: c.name, value: c.mean_sum }));
  return (
    <Section id="children" title="Business units below" intro="Each unit's open risks and the sum of their means. A sum of means is not a percentile of the unit's total; the 90th percentile is from your own roll-up of the unit, where you have one.">
      <div className="table-wrap">
        <table className="data">
          <caption className="sr-only">Business units below, with their open risks</caption>
          <thead>
            <tr>
              <th scope="col">Business unit</th>
              <th scope="col">Open risks</th>
              <th scope="col">Quantified</th>
              <th scope="col">Sum of means</th>
              <th scope="col">Roll-up 90th percentile</th>
            </tr>
          </thead>
          <tbody>
            {d.children.map((c) => (
              <tr key={c.bu_id}>
                <td>
                  <a href={`/reports?bu=${c.bu_id}`}>{c.name}</a>
                </td>
                <td>
                  <a href={`/register?bu=${c.bu_id}`}>{c.open_risks}</a>
                </td>
                <td>{c.quantified}</td>
                <td>{money(c.mean_sum, currency)}</td>
                <td>{c.rollup_p90 === null ? "No roll-up of yours" : money(c.rollup_p90, currency)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ChartFigure title="Sum of the open risks' means, by business unit" description={describeBars("Sum of the open risks' means in each business unit below", bars, currency)} table={barsTable("Each business unit's sum of means", bars, currency, "Sum of means")}>
        {(ids) => <Bars bars={bars} currency={currency} {...ids} />}
      </ChartFigure>
    </Section>
  );
}

function Trend({ bu, currency }: { bu: string; currency: string | null }) {
  const [days, setDays] = useState("365");
  const from = new Date(Date.now() - Number(days) * 86_400_000).toISOString().slice(0, 10);
  const trend = useApi<{ snapshots: TrendPoint[] }>(`/api/v1/reports/dashboard/trend?bu=${bu}&from=${from}`);
  return (
    <Section id="trend" title="Over time" intro="From the portfolio snapshots taken at regular intervals. A snapshot's roll-up shows only when you can see every risk it included.">
      <div className="field">
        <label htmlFor="trend-period">Period</label>
        <select id="trend-period" value={days} onChange={(e) => setDays(e.target.value)}>
          {PERIODS.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </select>
      </div>
      <Status loaded={trend}>
        {(t) => {
          const pts = t.snapshots;
          if (pts.length === 0) return <p>No snapshot in this period yet.</p>;
          const exp = exposureSeries(pts);
          const cov = coverageSeries(pts);
          const table = trendTable(pts, currency);
          return (
            <>
              <ChartFigure title="Exposure over time" description={describeExposureTrend(pts, currency)} table={table}>
                {(ids) => <Lines series={exp} format={(v) => formatAmount(v, currency)} yTitle="Annual loss" {...ids} />}
              </ChartFigure>
              <ChartFigure title="Coverage over time" description={describeCoverageTrend(pts)} table={table}>
                {(ids) => <Lines series={cov} format={(v) => String(Math.round(v))} yTitle="Open risks" {...ids} />}
              </ChartFigure>
            </>
          );
        }}
      </Status>
    </Section>
  );
}
