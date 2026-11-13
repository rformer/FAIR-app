// F-006 T-04 (F-006-AC-03, AC-04, AC-07; design §4): horizontal bars (the
// breakdown of loss, aggregate contributions) and the sensitivity tornado.
// Values are written at each bar's end, so no reading depends on colour.

import type { BarDatum, TornadoDatum } from "./describe.ts";
import { signed } from "./describe.ts";
import { clip, PLOT, WIDTH } from "./frame.tsx";
import { formatAmount, formatShare, linearScale } from "./scale.ts";

const ROW = 26;
const LABEL = 200;

function height(n: number): number {
  return Math.max(1, n) * ROW + 40;
}

export function Bars({ bars, currency, labelledBy, describedBy }: { bars: BarDatum[]; currency: string | null; labelledBy?: string; describedBy?: string }) {
  const h = height(bars.length);
  const max = Math.max(0, ...bars.map((b) => b.value));
  const x = linearScale([0, max || 1], [LABEL, PLOT.x1 - 110]);
  return (
    <div className="chart">
      <svg viewBox={`0 0 ${WIDTH} ${h}`} className="chart-svg" role="img" aria-labelledby={labelledBy} aria-describedby={describedBy}>
        {bars.map((b, i) => {
          const top = 12 + i * ROW;
          const end = x.map(Math.max(0, b.value));
          return (
            <g key={i}>
              <text x={LABEL - 8} y={top + 15} textAnchor="end" className="chart-text">
                {clip(b.label)}
              </text>
              <rect x={LABEL} y={top + 3} width={Math.max(0, end - LABEL)} height={ROW - 8} className="series-1" fill="currentColor" />
              <text x={end + 6} y={top + 15} className="chart-text">
                {formatAmount(b.value, currency)}
                {typeof b.share === "number" ? ` (${formatShare(b.share)})` : ""}
              </text>
            </g>
          );
        })}
        <line x1={LABEL} x2={LABEL} y1={8} y2={h - 24} className="chart-axis-line" />
      </svg>
    </div>
  );
}

export function Tornado({ inputs, currency, labelledBy, describedBy }: { inputs: TornadoDatum[]; currency: string | null; labelledBy?: string; describedBy?: string }) {
  const h = height(inputs.length) + 16;
  const vals = inputs.flatMap((d) => [d.low, d.high]);
  const lo = Math.min(0, ...vals);
  const hi = Math.max(0, ...vals);
  const x = linearScale([lo, hi === lo ? lo + 1 : hi], [LABEL + 60, PLOT.x1 - 60]);
  const zero = x.map(0);
  return (
    <div className="chart">
      <svg viewBox={`0 0 ${WIDTH} ${h}`} className="chart-svg" role="img" aria-labelledby={labelledBy} aria-describedby={describedBy}>
        <text x={zero} y={12} textAnchor="middle" className="chart-text chart-note">
          Change in mean annual loss: input at its low end (dashed outline, light fill) and at its high end (solid)
        </text>
        {inputs.map((d, i) => {
          const top = 24 + i * ROW;
          const bar = (v: number, cls: string, dash?: string) => {
            const a = x.map(v);
            return <rect x={Math.min(a, zero)} y={top + 3} width={Math.max(1, Math.abs(a - zero))} height={ROW - 8} className={cls} fill="currentColor" fillOpacity={dash ? 0.35 : 1} stroke="currentColor" strokeWidth={1.5} strokeDasharray={dash} />;
          };
          return (
            <g key={i}>
              <text x={LABEL - 8} y={top + 15} textAnchor="end" className="chart-text">
                {clip(d.label)}
              </text>
              {bar(d.low, "series-2", "4 2")}
              {bar(d.high, "series-1")}
              <text x={Math.min(x.map(d.low), x.map(d.high), zero) - 4} y={top + 15} textAnchor="end" className="chart-text">
                {signed(Math.min(d.low, d.high), currency)}
              </text>
              <text x={Math.max(x.map(d.low), x.map(d.high), zero) + 4} y={top + 15} className="chart-text">
                {signed(Math.max(d.low, d.high), currency)}
              </text>
            </g>
          );
        })}
        <line x1={zero} x2={zero} y1={20} y2={h - 8} className="chart-axis-line" />
      </svg>
    </div>
  );
}
