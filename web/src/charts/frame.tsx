// F-006 T-04 (ADR-014): the shared frame of F-006's charts: size, margins
// and axes. Colours come from CSS classes (styles.css), never from inline
// styles (the UI's CSP; the export inlines computed values).

import type { Scale } from "./scale.ts";

export const WIDTH = 640;
export const HEIGHT = 320;
export const MARGIN = { top: 16, right: 16, bottom: 48, left: 76 } as const;
export const PLOT = {
  x0: MARGIN.left,
  x1: WIDTH - MARGIN.right,
  y0: HEIGHT - MARGIN.bottom,
  y1: MARGIN.top,
} as const;

/** The horizontal axis along the bottom of the plot, with a title. */
export function XAxis({ scale, format, title, ticks = 6 }: { scale: Scale; format: (v: number) => string; title: string; ticks?: number }) {
  return (
    <g className="chart-axis">
      <line x1={PLOT.x0} x2={PLOT.x1} y1={PLOT.y0} y2={PLOT.y0} className="chart-axis-line" />
      {scale.ticks(ticks).map((t) => (
        <g key={t}>
          <line x1={scale.map(t)} x2={scale.map(t)} y1={PLOT.y0} y2={PLOT.y0 + 5} className="chart-axis-line" />
          <text x={scale.map(t)} y={PLOT.y0 + 18} textAnchor="middle" className="chart-text">
            {format(t)}
          </text>
        </g>
      ))}
      <text x={(PLOT.x0 + PLOT.x1) / 2} y={HEIGHT - 8} textAnchor="middle" className="chart-text chart-title">
        {title}
      </text>
    </g>
  );
}

/** The vertical axis along the left of the plot, with light grid lines. */
export function YAxis({ scale, format, title, ticks = 5 }: { scale: Scale; format: (v: number) => string; title: string; ticks?: number }) {
  const mid = (PLOT.y0 + PLOT.y1) / 2;
  return (
    <g className="chart-axis">
      <line x1={PLOT.x0} x2={PLOT.x0} y1={PLOT.y0} y2={PLOT.y1} className="chart-axis-line" />
      {scale.ticks(ticks).map((t) => (
        <g key={t}>
          <line x1={PLOT.x0} x2={PLOT.x1} y1={scale.map(t)} y2={scale.map(t)} className="chart-grid" />
          <text x={PLOT.x0 - 8} y={scale.map(t) + 4} textAnchor="end" className="chart-text">
            {format(t)}
          </text>
        </g>
      ))}
      <text x={14} y={mid} textAnchor="middle" transform={`rotate(-90 14 ${mid})`} className="chart-text chart-title">
        {title}
      </text>
    </g>
  );
}

/** A label shortened to n characters (the full text is in the data table). */
export function clip(s: string, n = 28): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}
