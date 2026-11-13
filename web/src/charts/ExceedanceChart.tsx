// F-006 T-04 (F-006-AC-01, AC-05, AC-15, AC-16; design §3.4, §4): loss
// exceedance curves of up to six series, the first drawn solid, each with
// its own dash pattern, markers and legend entry. A cursor moves along the
// first series' amounts by pointer or keyboard (Left/Right, Page Up/Down,
// Home/End); it is a slider whose value text reads the amount and every
// series' chance of exceeding it.

import { useId, useMemo, useState, type KeyboardEvent, type PointerEvent } from "react";
import { probabilityAt, type CurvePoint } from "./curve.ts";
import { seriesPoints, type CurveSeries } from "./describe.ts";
import { clip, HEIGHT, PLOT, WIDTH, XAxis, YAxis } from "./frame.tsx";
import { markerPath, seriesStyle } from "./palette.ts";
import { formatAmount, formatProbability, linearScale, logScale, type ScaleKind } from "./scale.ts";

export interface ExceedanceProps {
  series: CurveSeries[];
  currency: string | null;
  scale: ScaleKind;
  /** The accessible name of the chart (its caption's id). */
  labelledBy?: string;
  describedBy?: string;
}

/** What the cursor reads at amount x for each series. */
export function cursorText(series: CurveSeries[], x: number, currency: string | null): string {
  const parts = series.map((s) => {
    const r = probabilityAt(seriesPoints(s), x, s.anyLoss);
    const p =
      r.kind === "exact" || r.kind === "interpolated"
        ? formatProbability(r.value)
        : r.kind === "between"
          ? `${formatProbability(r.low)} to ${formatProbability(r.high)}`
          : r.kind === "none_exceeded"
            ? "none"
            : "—";
    return `${s.label} ${p}`;
  });
  return `Annual loss ${formatAmount(x, currency)}: ${parts.join(", ")}`;
}

export function ExceedanceChart({ series, currency, scale, labelledBy, describedBy }: ExceedanceProps) {
  const pts = useMemo(() => series.map(seriesPoints), [series]);
  const all = pts.flat();
  const maxX = Math.max(0, ...all.map((p) => p.amount));
  const minX = Math.min(...all.map((p) => p.amount).filter((a) => a > 0), maxX || 1);
  const maxP = Math.max(0.01, ...all.map((p) => p.probability), ...series.map((s) => s.anyLoss ?? 0));
  const x = scale === "log" && maxX > 0 ? logScale([minX, maxX], [PLOT.x0, PLOT.x1]) : linearScale([0, maxX || 1], [PLOT.x0, PLOT.x1]);
  const y = linearScale([0, Math.min(1, maxP * 1.05)], [PLOT.y0, PLOT.y1]);
  const grid = useMemo(() => {
    const g = [...new Set((pts[0] ?? []).map((p) => p.amount))];
    return g.length ? g : [0];
  }, [pts]);
  const [cursor, setCursor] = useState<number | null>(null);
  const id = useId();

  const at = cursor === null ? null : (grid[Math.min(cursor, grid.length - 1)] ?? null);
  const move = (i: number) => setCursor(Math.max(0, Math.min(grid.length - 1, i)));
  const onKey = (e: KeyboardEvent) => {
    const i = cursor ?? 0;
    const step: Record<string, number> = { ArrowRight: 1, ArrowUp: 1, ArrowLeft: -1, ArrowDown: -1, PageUp: 10, PageDown: -10 };
    if (e.key in step) move(i + (step[e.key] ?? 0));
    else if (e.key === "Home") move(0);
    else if (e.key === "End") move(grid.length - 1);
    else return;
    e.preventDefault();
  };
  const onPointer = (e: PointerEvent<SVGRectElement>) => {
    const box = e.currentTarget.ownerSVGElement?.getBoundingClientRect();
    if (!box) return;
    const px = ((e.clientX - box.left) / box.width) * WIDTH;
    const v = x.invert(px);
    let best = 0;
    grid.forEach((g, i) => {
      if (Math.abs(x.map(g) - x.map(v)) < Math.abs(x.map(grid[best] ?? 0) - x.map(v))) best = i;
    });
    setCursor(best);
  };
  const path = (p: CurvePoint[]) => p.map((q, i) => `${i ? "L" : "M"}${x.map(q.amount).toFixed(1)},${y.map(q.probability).toFixed(1)}`).join("");
  const valueText = at === null ? "Move with the arrow keys" : cursorText(series, at, currency);

  return (
    <div className="chart">
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="chart-svg" role="group" aria-labelledby={labelledBy} aria-describedby={describedBy}>
        <XAxis scale={x} format={(v) => formatAmount(v, currency)} title={`Annual loss${currency ? ` (${currency})` : ""}, ${scale === "log" ? "logarithmic" : "linear"} scale`} />
        <YAxis scale={y} format={(v) => formatProbability(v)} title="Chance of exceeding" />
        {pts.map((p, i) => {
          const st = seriesStyle(i);
          const every = Math.max(1, Math.floor(p.length / 8));
          return (
            <g key={i} className={`chart-series ${st.className}`}>
              <path d={path(p)} fill="none" stroke="currentColor" strokeWidth={i === 0 ? 2.5 : 2} strokeDasharray={st.dash || undefined} />
              {p
                .filter((_, j) => j % every === 0)
                .map((q, j) => (
                  <path key={j} d={markerPath(st.marker, x.map(q.amount), y.map(q.probability))} fill="currentColor" stroke="currentColor" />
                ))}
            </g>
          );
        })}
        <g className="chart-legend">
          {series.map((s, i) => {
            const st = seriesStyle(i);
            const ly = PLOT.y1 + 6 + i * 16;
            return (
              <g key={i} className={st.className}>
                <line x1={PLOT.x1 - 190} x2={PLOT.x1 - 166} y1={ly} y2={ly} stroke="currentColor" strokeWidth={2} strokeDasharray={st.dash || undefined} />
                <path d={markerPath(st.marker, PLOT.x1 - 178, ly, 3.5)} fill="currentColor" stroke="currentColor" />
                <text x={PLOT.x1 - 160} y={ly + 4} className="chart-text">
                  {clip(s.label, 26)}
                </text>
              </g>
            );
          })}
        </g>
        {at !== null ? (
          <g className="chart-cursor">
            <line x1={x.map(at)} x2={x.map(at)} y1={PLOT.y0} y2={PLOT.y1} className="chart-cursor-line" />
          </g>
        ) : null}
        <rect
          x={PLOT.x0}
          y={PLOT.y1}
          width={PLOT.x1 - PLOT.x0}
          height={PLOT.y0 - PLOT.y1}
          className="chart-hit"
          tabIndex={0}
          role="slider"
          aria-label="Cursor on the loss exceedance curves"
          aria-orientation="horizontal"
          aria-valuemin={0}
          aria-valuemax={grid.length - 1}
          aria-valuenow={cursor ?? 0}
          aria-valuetext={valueText}
          aria-controls={`${id}-readout`}
          onKeyDown={onKey}
          onPointerMove={onPointer}
          onPointerDown={onPointer}
        />
      </svg>
      <p id={`${id}-readout`} className="chart-readout">
        {at === null ? "Point at the chart, or focus it and use the arrow keys, to read the curves." : `${valueText} (read from the curve).`}
      </p>
    </div>
  );
}
