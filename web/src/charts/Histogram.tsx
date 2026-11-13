// F-006 T-04 (F-006-AC-02, AC-07, AC-09; design §3.1, §4): a histogram of
// annual loss (or of the per-year difference between control sets), with
// the mean and percentile markers; years with no loss (no difference) are
// stated beside it, not drawn as a bin.

import { HEIGHT, PLOT, WIDTH, XAxis, YAxis } from "./frame.tsx";
import type { HistogramData } from "./describe.ts";
import { formatAmount, formatShare, linearScale, logScale } from "./scale.ts";

export interface HistogramProps {
  data: HistogramData;
  currency: string | null;
  /** A per-year difference (linear, may be negative). */
  difference?: boolean;
  markers?: { mean?: number | null; percentiles?: Record<string, number | null> } | null;
  labelledBy?: string;
  describedBy?: string;
}

const MARKED = ["p50", "p90", "p99"] as const;

export function Histogram({ data, currency, difference = false, markers, labelledBy, describedBy }: HistogramProps) {
  const { edges, counts } = data;
  const lo = edges[0] ?? 0;
  const hi = edges[edges.length - 1] ?? 1;
  const log = data.scale === "log" && lo > 0;
  const x = log ? logScale([lo, hi], [PLOT.x0, PLOT.x1]) : linearScale([lo, hi], [PLOT.x0, PLOT.x1]);
  const maxCount = Math.max(1, ...counts);
  const y = linearScale([0, data.n ? maxCount / data.n : 1], [PLOT.y0, PLOT.y1]);
  const marks: { key: string; label: string; v: number }[] = [];
  if (typeof markers?.mean === "number") marks.push({ key: "mean", label: "mean", v: markers.mean });
  for (const p of MARKED) {
    const v = markers?.percentiles?.[p];
    if (typeof v === "number") marks.push({ key: p, label: p.toUpperCase(), v });
  }
  const inRange = marks.filter((m) => m.v >= Math.min(lo, hi) && m.v <= Math.max(lo, hi) && (!log || m.v > 0));
  const apart = difference ? "No difference" : "No loss";

  return (
    <div className="chart">
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="chart-svg" role="img" aria-labelledby={labelledBy} aria-describedby={describedBy}>
        <XAxis
          scale={x}
          format={(v) => formatAmount(v, currency)}
          title={`${difference ? "Difference in annual loss" : "Annual loss"}${currency ? ` (${currency})` : ""}${log ? ", logarithmic scale" : ""}`}
        />
        <YAxis scale={y} format={(v) => formatShare(v)} title="Share of years" />
        <g className="chart-bars series-1">
          {counts.map((c, i) => {
            const a = x.map(edges[i] ?? lo);
            const b = x.map(edges[i + 1] ?? hi);
            const top = y.map(data.n ? c / data.n : 0);
            return c > 0 ? <rect key={i} x={Math.min(a, b)} width={Math.max(1, Math.abs(b - a) - 0.5)} y={top} height={PLOT.y0 - top} fill="currentColor" /> : null;
          })}
        </g>
        {inRange.map((m, i) => (
          <g key={m.key} className="chart-marker">
            <line x1={x.map(m.v)} x2={x.map(m.v)} y1={PLOT.y0} y2={PLOT.y1 + 14 + (i % 2) * 12} strokeDasharray={m.key === "mean" ? "6 3" : "2 3"} className="chart-marker-line" />
            <text x={x.map(m.v) + 3} y={PLOT.y1 + 12 + (i % 2) * 12} className="chart-text">
              {m.label}
            </text>
          </g>
        ))}
        <text x={PLOT.x0 + 4} y={PLOT.y1 + 4} className="chart-text chart-note">
          {`${apart} in ${formatShare(data.zero_share)} of years (not drawn)`}
          {difference && data.both_none !== undefined ? `; neither lost anything in ${formatShare(data.n ? data.both_none / data.n : 0)}` : ""}
        </text>
      </svg>
    </div>
  );
}
