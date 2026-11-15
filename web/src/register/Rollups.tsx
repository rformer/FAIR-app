import { useEffect, useState } from "react";
import { describe, send } from "../api";
import { usePolling } from "../analysis/Runs";
import { FAILURE_LABELS, money } from "../analysis/types";
import { Bars } from "../charts/Bars.tsx";
import { ChartFigure } from "../charts/ChartFigure.tsx";
import type { StoredCurve } from "../charts/curve.ts";
import { barsTable, describeBars, describeExceedance, exceedanceTable, type CurveSeries } from "../charts/describe.ts";
import { ExceedanceChart } from "../charts/ExceedanceChart.tsx";
import { Badge, Section, Status, useApi, type Tone } from "../components";
import { auditHref, date } from "../links";
import type { BU } from "../risk/types";

// F-007 T-09 (F-007-AC-11 to AC-14): business unit roll-ups: requesting one,
// following it, and reading it: its loss exceedance curve, each risk's
// mean, 90th percentile and share, what it left out and why, and what
// restricted business units contributed by their roll-up mode. A roll-up is
// its requester's own.

interface RollupRow {
  id: string;
  bu_id: string;
  state: "queued" | "succeeded" | "failed";
  requested_at: string;
  finished_at: string | null;
  risks: number;
}

interface Rollup {
  id: string;
  bu_id: string;
  state: RollupRow["state"];
  requested_at: string;
  finished_at: string | null;
  failure: string | null;
  summary: null | { ale: { mean: number | null; percentiles: Record<string, number | null>; p_positive?: number | null }; curve?: unknown };
  risks: { risk_id: string; bu_id: string; title: string | null; mean: number | null; p90: number | null; share: number | null }[];
  covers: number;
  left_out: Record<string, number>;
  left_out_total: number;
  excluded_bus: number;
  aggregate_only: null | { bus: number; mean_total: number; label: string };
  mean_with_aggregate_only?: number;
  stale: boolean;
  independence: string;
}

const STATE: Record<RollupRow["state"], { label: string; tone: Tone }> = {
  queued: { label: "Computing", tone: "info" },
  succeeded: { label: "Computed", tone: "ok" },
  failed: { label: "Failed", tone: "bad" },
};

const LEFT_OUT: Record<string, string> = {
  stale: "stale exposure",
  unquantified: "no scenarios",
  computing: "exposure still computing",
  not_visible: "a result you cannot see",
  other_iterations: "pinned at another iteration count",
  outside: "a result outside the business unit",
};

function useCurrency(): string | null {
  return useApi<{ currency: string | null }>("/api/v1/risk/settings").data?.currency ?? null;
}

export function RollupsPage() {
  const list = useApi<{ rollups: RollupRow[] }>("/api/v1/register/rollups");
  const bus = useApi<{ bus: BU[] }>("/api/v1/register/bus?permission=register.view");
  const [bu, setBu] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    document.title = "Roll-ups · Risk register · FAIR Risk Platform";
  }, []);
  useEffect(() => {
    if (!bu && bus.data?.bus[0]) setBu(bus.data.bus[0].id);
  }, [bu, bus.data]);
  const buName = (id: string) => bus.data?.bus.find((b) => b.id === id)?.name ?? id;
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/register">Risk register</a>
      </nav>
      <h1>Roll-ups</h1>
      <p className="lede">The combined exposure of a business unit and everything below it, simulated, not summed.</p>
      <Section id="request" title="Request a roll-up" intro="It includes the open risks whose exposure is current and whose results you can see; it says what it leaves out and why. It is yours: others request their own.">
        <form
          className="filters"
          onSubmit={async (e) => {
            e.preventDefault();
            setError(undefined);
            setBusy(true);
            try {
              const r = await send<{ id: string }>("POST", "/api/v1/register/rollups", { bu_id: bu });
              window.location.assign(`/register/rollups/${r.id}`);
            } catch (err) {
              setError(describe(err));
            } finally {
              setBusy(false);
            }
          }}
        >
          <div className="field">
            <label htmlFor="rollup-bu">Business unit</label>
            <select id="rollup-bu" value={bu} onChange={(e) => setBu(e.target.value)}>
              {(bus.data?.bus ?? []).map((b) => (
                <option key={b.id} value={b.id}>
                  {b.name}
                </option>
              ))}
            </select>
          </div>
          <div className="actions">
            <button className="react-aria-Button primary" type="submit" disabled={busy || !bu}>
              Roll up
            </button>
          </div>
        </form>
        {error ? (
          <p role="alert" className="error-text">
            {error}
          </p>
        ) : null}
      </Section>
      <Section id="yours" title="Your roll-ups">
        <Status loaded={list}>
          {(d) =>
            d.rollups.length === 0 ? (
              <p>You have not requested a roll-up yet.</p>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <caption className="sr-only">Your roll-ups, newest first</caption>
                  <thead>
                    <tr>
                      <th scope="col">Business unit</th>
                      <th scope="col">Requested</th>
                      <th scope="col">Risks</th>
                      <th scope="col">State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.rollups.map((r) => (
                      <tr key={r.id}>
                        <td>
                          <a href={`/register/rollups/${r.id}`}>{buName(r.bu_id)}</a>
                        </td>
                        <td>{date(r.requested_at)}</td>
                        <td>{r.risks}</td>
                        <td>
                          <Badge tone={STATE[r.state].tone}>{STATE[r.state].label}</Badge>
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

export function RollupPage({ id }: { id: string }) {
  const [sort, setSort] = useState<"mean" | "p90">("mean");
  const r = useApi<Rollup>(`/api/v1/register/rollups/${id}?sort=${sort}`);
  const bus = useApi<{ bus: BU[] }>("/api/v1/register/bus?permission=register.view");
  const currency = useCurrency();
  usePolling(r.data?.state === "queued", r.reload);
  const name = r.data ? (bus.data?.bus.find((b) => b.id === r.data!.bu_id)?.name ?? "a business unit") : "";
  useEffect(() => {
    if (name) document.title = `Roll-up of ${name} · Risk register · FAIR Risk Platform`;
  }, [name]);
  return (
    <Status loaded={r}>
      {(x) => {
        const s = x.summary;
        const series: CurveSeries[] = s ? [{ label: `Roll-up of ${name}`, curve: s.curve as StoredCurve | undefined, percentiles: s.ale.percentiles, anyLoss: s.ale.p_positive ?? undefined }] : [];
        const bars = x.risks.filter((k) => k.mean !== null).map((k) => ({ label: k.title ?? k.risk_id, value: k.mean as number, share: k.share }));
        const left = Object.entries(x.left_out).filter(([, n]) => n > 0);
        return (
          <>
            <nav aria-label="Breadcrumb" className="crumbs">
              <a href="/register">Risk register</a> / <a href="/register/rollups">Roll-ups</a>
            </nav>
            <h1>Roll-up of {name}</h1>
            <p className="lede">
              Requested {date(x.requested_at)} · <Badge tone={STATE[x.state].tone}>{STATE[x.state].label}</Badge>
              {x.stale ? (
                <>
                  {" "}
                  · <Badge tone="warn">Stale</Badge>
                </>
              ) : null}
            </p>
            {x.stale ? (
              <div className="banner warn" role="status">
                <p>A roll-up now would include something else: a pin changed, or a risk was closed, added or became stale. Request a new one to see it.</p>
              </div>
            ) : null}
            {x.state === "failed" ? (
              <p role="alert" className="error-text">
                {FAILURE_LABELS[x.failure ?? ""] ?? x.failure}
              </p>
            ) : null}
            {x.state === "queued" ? <p role="status">The roll-up is being computed.</p> : null}
            <Section id="covers" title="What it covers" intro={x.independence.charAt(0).toUpperCase() + x.independence.slice(1) + "."}>
              <dl className="summary">
                <div>
                  <dt>Risks included</dt>
                  <dd>{x.covers}</dd>
                </div>
                <div>
                  <dt>Risks left out</dt>
                  <dd>
                    {x.left_out_total}
                    {left.length > 0 ? ` (${left.map(([k, n]) => `${n} with ${LEFT_OUT[k] ?? k}`).join("; ")})` : ""}
                  </dd>
                </div>
                <div>
                  <dt>Business units excluded by their roll-up mode</dt>
                  <dd>{x.excluded_bus}</dd>
                </div>
                {x.aggregate_only ? (
                  <div>
                    <dt>
                      {x.aggregate_only.label.charAt(0).toUpperCase() + x.aggregate_only.label.slice(1)} ({x.aggregate_only.bus})
                    </dt>
                    <dd>{money(x.aggregate_only.mean_total, currency)} mean annual loss, added to the mean, not to the distribution</dd>
                  </div>
                ) : null}
              </dl>
            </Section>
            {s ? (
              <Section id="result" title="Combined annual loss">
                <dl className="summary">
                  <div>
                    <dt>Mean annual loss</dt>
                    <dd>{money(s.ale.mean, currency)}</dd>
                  </div>
                  {x.mean_with_aggregate_only !== undefined ? (
                    <div>
                      <dt>Mean with restricted business units</dt>
                      <dd>{money(x.mean_with_aggregate_only, currency)}</dd>
                    </div>
                  ) : null}
                  <div>
                    <dt>1 year in 10 (90th percentile)</dt>
                    <dd>{money(s.ale.percentiles.p90, currency)}</dd>
                  </div>
                  <div>
                    <dt>1 year in 20 (95th percentile)</dt>
                    <dd>{money(s.ale.percentiles.p95, currency)}</dd>
                  </div>
                </dl>
                {s.curve ? (
                  <ChartFigure title={`Loss exceedance, roll-up of ${name}`} description={describeExceedance(series, currency)} table={exceedanceTable(series, currency)}>
                    {(ids) => <ExceedanceChart series={series} currency={currency} scale="log" {...ids} />}
                  </ChartFigure>
                ) : null}
              </Section>
            ) : null}
            <Section id="risks" title="Risks, by exposure" intro="Each risk's share is its mean annual loss over the sum of the included risks' (means add).">
              <div className="field">
                <label htmlFor="rollup-sort">Order by</label>
                <select id="rollup-sort" value={sort} onChange={(e) => setSort(e.target.value as "mean" | "p90")}>
                  <option value="mean">Mean annual loss</option>
                  <option value="p90">90th percentile</option>
                </select>
              </div>
              {x.risks.length === 0 ? (
                <p>No risk is included.</p>
              ) : (
                <>
                  <div className="table-wrap">
                    <table className="data">
                      <caption className="sr-only">Included risks, largest first</caption>
                      <thead>
                        <tr>
                          <th scope="col">Risk</th>
                          <th scope="col">Mean annual loss</th>
                          <th scope="col">90th percentile</th>
                          <th scope="col">Share of the mean</th>
                        </tr>
                      </thead>
                      <tbody>
                        {x.risks.map((k) => (
                          <tr key={k.risk_id}>
                            <td>
                              <a href={`/register/risks/${k.risk_id}`}>{k.title ?? k.risk_id}</a>
                            </td>
                            <td>{money(k.mean, currency)}</td>
                            <td>{money(k.p90, currency)}</td>
                            <td>{k.share === null ? "—" : `${(k.share * 100).toFixed(1)}%`}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <ChartFigure title="What each risk contributes" description={describeBars("Mean annual loss of each risk, with its share of the mean", bars, currency)} table={barsTable("Each risk's mean annual loss and share of the mean", bars, currency)}>
                    {(ids) => <Bars bars={bars} currency={currency} {...ids} />}
                  </ChartFigure>
                </>
              )}
            </Section>
            <p>
              <a href={auditHref(`register_rollup:${x.id}`)}>Audit history of this roll-up</a>
            </p>
          </>
        );
      }}
    </Status>
  );
}
