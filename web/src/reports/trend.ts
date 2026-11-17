// F-010 T-17 (F-010-AC-05, AC-07; design §3.2): the dashboard's trends from
// the snapshots the caller may see: exposure (the roll-up's mean and 90th
// percentile where its row is visible; the sum of the open risks' means
// otherwise labelled as such) and coverage, with their text alternatives
// and data tables. Pure: unit-tested by `node --test`.

import type { DataTable } from "../charts/describe.ts";
import type { LineSeries } from "../charts/Lines.tsx";
import { formatAmount, formatAmountFull } from "../charts/scale.ts";

export interface TrendPoint {
  snapshot_id: number;
  taken_at: string;
  counts: {
    open: number;
    current: number;
    stale: number;
    unquantified: number;
    mean_sum: number;
    open_actions: number;
    overdue_actions: number;
    acceptances?: Record<string, number>;
  };
  rollup: null | { finished_at: string; mean: number | null; p10: number | null; p50: number | null; p90: number | null; p99: number | null };
}

const day = (s: string) => s.slice(0, 10);

/** The exposure series: the roll-up's mean and p90 (where visible), and the sum of means. */
export function exposureSeries(points: TrendPoint[]): LineSeries[] {
  const at = (p: TrendPoint) => new Date(p.taken_at).getTime();
  const out: LineSeries[] = [];
  const mean = points.filter((p) => typeof p.rollup?.mean === "number").map((p) => ({ t: at(p), v: p.rollup!.mean as number }));
  const p90 = points.filter((p) => typeof p.rollup?.p90 === "number").map((p) => ({ t: at(p), v: p.rollup!.p90 as number }));
  if (mean.length) out.push({ label: "Roll-up mean", points: mean });
  if (p90.length) out.push({ label: "Roll-up 90th percentile", points: p90 });
  out.push({ label: "Sum of the open risks' means", points: points.map((p) => ({ t: at(p), v: p.counts.mean_sum })) });
  return out;
}

export function coverageSeries(points: TrendPoint[]): LineSeries[] {
  const at = (p: TrendPoint) => new Date(p.taken_at).getTime();
  return [
    { label: "Current", points: points.map((p) => ({ t: at(p), v: p.counts.current })) },
    { label: "Stale", points: points.map((p) => ({ t: at(p), v: p.counts.stale })) },
    { label: "Unquantified", points: points.map((p) => ({ t: at(p), v: p.counts.unquantified })) },
  ];
}

/** The exposure trend in sentences: first and last snapshot. */
export function describeExposureTrend(points: TrendPoint[], currency: string | null): string {
  const first = points[0];
  const last = points[points.length - 1];
  if (!first || !last) return "No snapshot in this period.";
  const what = (p: TrendPoint) =>
    typeof p.rollup?.mean === "number"
      ? `a roll-up mean of ${formatAmount(p.rollup.mean, currency)}${typeof p.rollup.p90 === "number" ? ` (90th percentile ${formatAmount(p.rollup.p90, currency)})` : ""}`
      : `no roll-up you can see; the open risks' means sum to ${formatAmount(p.counts.mean_sum, currency)}`;
  if (points.length === 1) return `One snapshot, on ${day(first.taken_at)}: ${what(first)}.`;
  return `${points.length} snapshots from ${day(first.taken_at)} to ${day(last.taken_at)}. The first shows ${what(first)}; the last, ${what(last)}.`;
}

export function describeCoverageTrend(points: TrendPoint[]): string {
  const first = points[0];
  const last = points[points.length - 1];
  if (!first || !last) return "No snapshot in this period.";
  const what = (p: TrendPoint) => `${p.counts.current} of ${p.counts.open} open risks current, ${p.counts.stale} stale, ${p.counts.unquantified} unquantified`;
  if (points.length === 1) return `One snapshot, on ${day(first.taken_at)}: ${what(first)}.`;
  return `From ${day(first.taken_at)} to ${day(last.taken_at)}: ${what(first)} at first; ${what(last)} at the last.`;
}

const amount = (v: number | null | undefined, currency: string | null) => (typeof v === "number" ? formatAmountFull(v, currency) : "—");

export function trendTable(points: TrendPoint[], currency: string | null): DataTable {
  return {
    caption: "Snapshots, oldest first",
    columns: [
      "Snapshot",
      "Roll-up of",
      "Roll-up mean",
      "Roll-up 10th percentile",
      "Roll-up 90th percentile",
      "Sum of the open risks' means",
      "Open risks",
      "Current",
      "Stale",
      "Unquantified",
      "Open actions",
      "Overdue actions",
    ],
    rows: points.map((p) => [
      day(p.taken_at),
      p.rollup ? day(p.rollup.finished_at) : "No roll-up you can see",
      amount(p.rollup?.mean, currency),
      amount(p.rollup?.p10, currency),
      amount(p.rollup?.p90, currency),
      formatAmountFull(p.counts.mean_sum, currency),
      String(p.counts.open),
      String(p.counts.current),
      String(p.counts.stale),
      String(p.counts.unquantified),
      String(p.counts.open_actions),
      String(p.counts.overdue_actions),
    ]),
  };
}
