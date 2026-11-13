import { useEffect, useMemo, useState } from "react";
import { ApiError, describe, send } from "../api";
import { Section, useApi } from "../components";
import { ChartFigure } from "../charts/ChartFigure.tsx";
import { describeExceedance, exceedanceTable, signed, type CurveSeries } from "../charts/describe.ts";
import { ExceedanceChart } from "../charts/ExceedanceChart.tsx";
import { formatAmountFull, formatShare, type ScaleKind } from "../charts/scale.ts";
import { addToBasket, clearBasket, compareHref, MAX_ITEMS, useBasket, type Item } from "./basket";
import type { Distribution } from "./types";

// F-006 T-06 (F-006-AC-10 to AC-13, AC-16; design §3.2, §4): comparing two
// to six results. The page is its address: the items in order, the first
// the base. The service answers all of them or nothing (404 whichever item
// is hidden), and names the inputs that differ.

interface Difference {
  amount: number;
  share: number | null;
}

interface ComparisonItem {
  kind: "run" | "aggregate";
  id: string;
  bu_id: string;
  label: string;
  control_set?: string;
  scenario_id?: string;
  scenario_version?: number;
  aggregate_name?: string;
  seed: string;
  iterations: number;
  engine: { version: string | null; architecture: string | null };
  result_digest: string;
  ale: Distribution;
  curve?: CurveSeries["curve"];
  differences: null | { mean: Difference | null; percentiles: Record<string, Difference | null> };
}

interface Comparison {
  items: ComparisonItem[];
  unlike: string[];
  sampling_noise: boolean;
  statement: string | null;
}

const UNLIKE: Record<string, string> = {
  scenario: "scenarios",
  scenario_version: "scenario versions",
  iterations: "iteration counts",
  seed: "seeds",
  engine_version: "engine versions",
  architecture: "CPU architectures",
};

const STATS = [
  ["mean", "Mean annual loss"],
  ["p50", "Median year"],
  ["p90", "1 year in 10"],
  ["p95", "1 year in 20"],
  ["p99", "1 year in 100"],
] as const;

function useCurrency(): string | null {
  return useApi<{ currency: string | null }>("/api/v1/risk/settings").data?.currency ?? null;
}

/** "Add to comparison" for a result, and the basket's comparison link. */
export function AddToComparison({ item, label }: { item: Item; label: string }) {
  const basket = useBasket();
  const inBasket = basket.includes(item);
  return (
    <span className="add-compare">
      <button type="button" className="btn" disabled={inBasket} onClick={() => addToBasket(item)}>
        {inBasket ? `${label} is in the comparison` : `Add ${label} to the comparison`}
      </button>
    </span>
  );
}

/** The basket: what it holds and the link that opens it. */
export function BasketLink() {
  const basket = useBasket();
  if (basket.length === 0) return null;
  return (
    <p className="basket" role="status">
      {basket.length === 1 ? "One result to compare: add another." : `${basket.length} results to compare. `}
      {basket.length >= 2 ? <a href={compareHref(basket)}>Open the comparison</a> : null}{" "}
      <button type="button" className="btn" onClick={clearBasket}>
        Empty the comparison
      </button>
    </p>
  );
}

export function ComparePage() {
  const items = useMemo(() => new URLSearchParams(window.location.search).getAll("item"), []);
  const query = useMemo(() => new URLSearchParams(items.map((i) => ["item", i])).toString(), [items]);
  const cmp = useApi<Comparison>(`/api/v1/analyses/compare?${query}`);
  const currency = useCurrency();
  const [scale, setScale] = useState<ScaleKind>("log");
  useEffect(() => {
    document.title = "Comparison · FAIR Risk Platform";
  }, []);

  if (cmp.loading && !cmp.data) return <p role="status">Loading…</p>;
  if (cmp.error !== undefined) {
    const e = cmp.error;
    return (
      <>
        <h1>Comparison</h1>
        <p role="alert" className="error-text">
          {e instanceof ApiError && e.status === 404
            ? "This comparison is not available to you."
            : e instanceof ApiError && e.status === 409
              ? "One of these results has not finished, so they cannot be compared yet."
              : describe(e)}
        </p>
      </>
    );
  }
  const c = cmp.data;
  if (!c) return null;
  const series: CurveSeries[] = c.items.map((it) => ({ label: it.label, curve: it.curve, percentiles: it.ale.percentiles, anyLoss: it.ale.p_positive ?? undefined }));
  const base = c.items[0];
  return (
    <>
      <h1>Comparison of {c.items.length} results</h1>
      {c.unlike.length > 0 || c.statement ? (
        <div className="callout warn" role="note" aria-label="How these results differ">
          {c.unlike.length > 0 ? <p>These results differ in their {c.unlike.map((u) => UNLIKE[u] ?? u).join(", ")}.</p> : null}
          {c.statement ? <p>{c.statement}</p> : null}
        </div>
      ) : null}
      <Section id="compare-curves" title="Loss exceedance" intro={`The first result, ${base?.label ?? ""}, is the solid line and the base of every difference.`}>
        <fieldset className="inline-choice">
          <legend>Amount scale</legend>
          {(["log", "linear"] as const).map((s) => (
            <label key={s}>
              <input type="radio" name="compare-scale" value={s} checked={scale === s} onChange={() => setScale(s)} /> {s === "log" ? "Logarithmic" : "Linear"}
            </label>
          ))}
        </fieldset>
        <ChartFigure
          title="Loss exceedance curves compared"
          description={describeExceedance(series, currency)}
          table={exceedanceTable(series, currency)}
          downloads={{
            record: async (format) =>
              (await send<{ download_id: string }>("POST", "/api/v1/analyses/downloads", { subject: "comparison", items, view: "curve", format })).download_id,
            footer: (downloadId) => [
              `Loss exceedance curves compared: ${c.items.map((i) => i.label).join("; ")}`,
              `Currency: ${currency ?? "not set"}.${c.unlike.length ? ` Differ in: ${c.unlike.map((u) => UNLIKE[u] ?? u).join(", ")}.` : ""}`,
              ...c.items.map((i, n) => `${n + 1}. ${i.kind} ${i.id}${i.control_set ? ` (${i.control_set})` : ""}: results ${i.result_digest}`),
              ...(c.statement ? [c.statement] : []),
              `Download ${downloadId}`,
            ],
            file: { subject: "comparison", id: base?.id ?? "", view: "curve" },
            csvHref: `/api/v1/analyses/compare.csv?view=curve&${query}`,
          }}
        >
          {(ids) => <ExceedanceChart series={series} currency={currency} scale={scale} {...ids} />}
        </ChartFigure>
      </Section>
      <Section id="compare-summary" title="Side by side" intro="Each result's annual loss, and its difference from the first.">
        <div className="table-wrap">
          <table className="data">
            <caption>Annual loss of each result, with its difference from {base?.label}</caption>
            <thead>
              <tr>
                <th scope="col">Result</th>
                <th scope="col">Inputs</th>
                {STATS.map(([, l]) => (
                  <th key={l} scope="col">
                    {l}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {c.items.map((it, n) => (
                <tr key={`${it.id}-${it.control_set ?? ""}`}>
                  <th scope="row">
                    <a href={it.kind === "run" ? `/analyses/runs/${it.id}` : `/analyses/aggregates/${it.id}`}>{it.label}</a>
                  </th>
                  <td>
                    {it.iterations.toLocaleString("en-US")} iterations, seed {it.seed}, engine {it.engine.version ?? "—"}
                  </td>
                  {STATS.map(([k]) => {
                    const v = k === "mean" ? it.ale.mean : it.ale.percentiles[k];
                    const d = k === "mean" ? it.differences?.mean : it.differences?.percentiles[k];
                    return (
                      <td key={k}>
                        {v === null || v === undefined ? "—" : formatAmountFull(v, currency)}
                        {n > 0 && d ? (
                          <span className="muted">
                            {" "}
                            ({signed(d.amount, currency)}
                            {d.share === null ? "" : `, ${formatShare(Math.abs(d.share))} ${d.amount < 0 ? "lower" : d.amount > 0 ? "higher" : ""}`})
                          </span>
                        ) : null}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p>
          <a href={`/api/v1/analyses/compare.csv?view=summary&${query}`} download>
            Download the table as CSV
          </a>
        </p>
      </Section>
      <Section id="compare-share" title="Share this comparison">
        <p>This page's address opens the same comparison for anyone who can see every result in it.</p>
        {c.items.length < MAX_ITEMS ? (
          <p>
            <button type="button" className="btn" onClick={() => items.forEach((i) => addToBasket(i))}>
              Put these results in my comparison
            </button>{" "}
            then add more from the pages of runs and aggregates.
          </p>
        ) : null}
      </Section>
    </>
  );
}
