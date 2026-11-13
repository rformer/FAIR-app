// F-006 T-04 (F-006-AC-14; design §4): the text alternatives and data
// tables of the charts. Pure: unit-tested by `node --test`.

import { amountAt, mergedPoints, probabilityAt, type CurvePoint, type StoredCurve } from "./curve.ts";
import { formatAmount, formatAmountFull, formatProbability, formatShare } from "./scale.ts";
import { seriesStyle } from "./palette.ts";

export interface DataTable {
  caption: string;
  columns: string[];
  rows: string[][];
}

export interface CurveSeries {
  label: string;
  curve?: StoredCurve;
  /** The ALE summary's percentiles (amounts), for the exact points. */
  percentiles?: Record<string, number | null>;
  /** P(ALE > 0). */
  anyLoss?: number;
}

export function seriesPoints(s: CurveSeries): CurvePoint[] {
  return mergedPoints(s.curve, s.percentiles);
}

/**
 * The exceedance chart in sentences: the amount the first series exceeds
 * one year in ten, and each series' chance of exceeding it.
 */
export function describeExceedance(series: CurveSeries[], currency: string | null): string {
  const base = series[0];
  if (!base) return "No results to show.";
  const pts = seriesPoints(base);
  const p90 = base.percentiles?.["p90"];
  const at = typeof p90 === "number" && p90 > 0 ? p90 : amountAt(pts, 0.1, base.anyLoss);
  const amount = typeof at === "number" ? at : at.kind === "exact" || at.kind === "interpolated" ? at.value : null;
  if (amount === null || amount <= 0) {
    return `Loss exceedance curves of ${series.map((s) => s.label).join(", ")}: no amount is exceeded one year in ten.`;
  }
  const parts = series.map((s, i) => {
    const r = probabilityAt(seriesPoints(s), amount, s.anyLoss);
    const look = seriesStyle(i).look;
    const p =
      r.kind === "exact" || r.kind === "interpolated"
        ? formatProbability(r.value)
        : r.kind === "between"
          ? `between ${formatProbability(r.low)} and ${formatProbability(r.high)}`
          : r.kind === "none_exceeded"
            ? "no simulated year"
            : "unknown";
    return `${s.label} (${look}): ${p}`;
  });
  return `Chance of losing more than ${formatAmount(amount, currency)} in a year. ${parts.join("; ")}.`;
}

/** The exceedance chart's data: one row per amount of each series. */
export function exceedanceTable(series: CurveSeries[], currency: string | null): DataTable {
  const rows: string[][] = [];
  for (const s of series) {
    for (const p of seriesPoints(s)) {
      rows.push([s.label, formatAmountFull(p.amount, currency), formatProbability(p.probability), p.percentile ?? ""]);
    }
  }
  return { caption: "Loss exceedance curve points", columns: ["Series", "Annual loss", "Chance of exceeding it", "Exact at percentile"], rows };
}

export interface HistogramData {
  edges: number[];
  counts: number[];
  n: number;
  zero: number;
  zero_share: number;
  both_none?: number;
  scale: string;
}

/** The histogram in sentences: years apart, the fullest bin. */
export function describeHistogram(h: HistogramData, currency: string | null, difference: boolean): string {
  const apart = difference
    ? `${formatShare(h.zero_share)} of years show no difference`
    : `${formatShare(h.zero_share)} of years have no loss`;
  let top = -1;
  h.counts.forEach((c, i) => {
    if (top < 0 || c > (h.counts[top] ?? 0)) top = i;
  });
  if (top < 0 || h.n === 0) return `${apart}.`;
  const lo = h.edges[top] ?? 0;
  const hi = h.edges[top + 1] ?? lo;
  const what = difference ? "differences" : "annual losses";
  return `${apart}. The most frequent ${what}, ${formatShare((h.counts[top] ?? 0) / h.n)} of years, are between ${formatAmount(lo, currency)} and ${formatAmount(hi, currency)}.`;
}

/** The histogram's data: its bins, then the years apart. */
export function histogramTable(h: HistogramData, currency: string | null, difference: boolean): DataTable {
  const rows = h.counts.map((c, i) => [
    `${formatAmountFull(h.edges[i] ?? 0, currency)} to ${formatAmountFull(h.edges[i + 1] ?? 0, currency)}`,
    String(c),
    formatShare(h.n ? c / h.n : 0),
  ]);
  rows.push([difference ? "No difference" : "No loss", String(h.zero), formatShare(h.zero_share)]);
  if (difference && h.both_none !== undefined) rows.push(["Neither lost anything", String(h.both_none), formatShare(h.n ? h.both_none / h.n : 0)]);
  return { caption: difference ? "Per-year difference, years by bin" : "Annual loss, years by bin", columns: ["Range", "Years", "Share of years"], rows };
}

export interface BarDatum {
  label: string;
  value: number;
  share?: number | null;
}

/** Bars in sentences, from the largest. */
export function describeBars(title: string, bars: BarDatum[], currency: string | null): string {
  if (bars.length === 0) return `${title}: nothing to show.`;
  const sorted = [...bars].sort((a, b) => b.value - a.value);
  return `${title}: ${sorted
    .map((b) => `${b.label} ${formatAmount(b.value, currency)}${typeof b.share === "number" ? ` (${formatShare(b.share)})` : ""}`)
    .join("; ")}.`;
}

export function barsTable(caption: string, bars: BarDatum[], currency: string | null, valueColumn = "Mean annual loss"): DataTable {
  return {
    caption,
    columns: ["Name", valueColumn, "Share"],
    rows: bars.map((b) => [b.label, formatAmountFull(b.value, currency), typeof b.share === "number" ? formatShare(b.share) : ""]),
  };
}

export interface TornadoDatum {
  label: string;
  pointer?: string;
  low: number;
  high: number;
  spearman: number | null;
}

/** The tornado in sentences: the strongest inputs first. */
export function describeTornado(inputs: TornadoDatum[], currency: string | null): string {
  if (inputs.length === 0) return "No input drives the annual loss in this control set.";
  const top = inputs.slice(0, 3).map((d) => `${d.label} (from ${signed(d.low, currency)} to ${signed(d.high, currency)})`);
  return `The inputs that move the mean annual loss most, from its low to its high end: ${top.join("; ")}.`;
}

export function tornadoTable(inputs: TornadoDatum[], currency: string | null): DataTable {
  return {
    caption: "Inputs by their effect on the mean annual loss",
    columns: ["Input", "Place in the scenario", "Change at its low end", "Change at its high end", "Rank correlation"],
    rows: inputs.map((d) => [d.label, d.pointer ?? "", signed(d.low, currency), signed(d.high, currency), d.spearman === null ? "—" : d.spearman.toFixed(2)]),
  };
}

/** A signed amount: "+€1.2K", "−€300". */
export function signed(v: number, currency: string | null): string {
  if (!Number.isFinite(v)) return "—";
  if (v === 0) return formatAmount(0, currency);
  return `${v > 0 ? "+" : "−"}${formatAmount(Math.abs(v), currency)}`;
}
