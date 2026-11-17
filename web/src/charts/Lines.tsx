// F-010 T-17 (F-010-AC-05, AC-07; ADR-014): values over time, for the
// dashboard's trends. Up to six series, each with its own dash pattern and
// markers (no reading depends on colour); the text alternative and the data
// table come from the caller (reports/trend.ts).

import { HEIGHT, PLOT, WIDTH, XAxis, YAxis } from "./frame.tsx";
import { markerPath, seriesStyle } from "./palette.ts";
import { linearScale } from "./scale.ts";

export interface LinePoint {
  /** Milliseconds since the epoch. */
  t: number;
  v: number;
}

export interface LineSeries {
  label: string;
  points: LinePoint[];
}

export function dateLabel(t: number): string {
  return new Date(t).toISOString().slice(0, 10);
}

export function Lines({
  series,
  format,
  yTitle,
  labelledBy,
  describedBy,
}: {
  series: LineSeries[];
  format: (v: number) => string;
  yTitle: string;
  labelledBy?: string;
  describedBy?: string;
}) {
  const all = series.flatMap((s) => s.points);
  const t0 = Math.min(...all.map((p) => p.t));
  const t1 = Math.max(...all.map((p) => p.t));
  const span = t1 > t0 ? [t0, t1] : [t0 - 86_400_000, t0 + 86_400_000];
  const x = linearScale([span[0] ?? 0, span[1] ?? 1], [PLOT.x0, PLOT.x1]);
  const max = Math.max(0, ...all.map((p) => p.v));
  const y = linearScale([0, max > 0 ? max * 1.05 : 1], [PLOT.y0, PLOT.y1]);
  return (
    <div className="chart">
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="chart-svg" role="img" aria-labelledby={labelledBy} aria-describedby={describedBy}>
        <YAxis scale={y} format={format} title={yTitle} />
        <XAxis scale={x} format={dateLabel} title="Snapshot date" ticks={4} />
        {series.map((s, i) => {
          const st = seriesStyle(i);
          const d = s.points.map((p, j) => `${j === 0 ? "M" : "L"}${x.map(p.t).toFixed(1)},${y.map(p.v).toFixed(1)}`).join(" ");
          return (
            <g key={s.label} className={st.className}>
              <path d={d} fill="none" stroke="currentColor" strokeWidth={2} strokeDasharray={st.dash || undefined} />
              {s.points.map((p, j) => (
                <path key={j} d={markerPath(st.marker, x.map(p.t), y.map(p.v))} fill="currentColor" stroke="currentColor" />
              ))}
            </g>
          );
        })}
      </svg>
      {series.length > 1 ? (
        <ul className="line-legend">
          {series.map((s, i) => (
            <li key={s.label}>
              <svg width="28" height="12" aria-hidden="true" className={seriesStyle(i).className}>
                <line x1="0" x2="28" y1="6" y2="6" stroke="currentColor" strokeWidth={2} strokeDasharray={seriesStyle(i).dash || undefined} />
                <path d={markerPath(seriesStyle(i).marker, 14, 6)} fill="currentColor" />
              </svg>{" "}
              {s.label} ({seriesStyle(i).look})
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
