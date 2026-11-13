// F-006 T-04 (F-006-AC-15; ADR-014): series styles. Each series pairs a
// colour (CSS token `--series-N`, light and dark values in styles.css,
// at least 3:1 against the backgrounds: palette.test.ts) with a dash
// pattern and a marker shape, so series are told apart without colour.

export type Marker = "circle" | "square" | "triangle" | "diamond" | "cross" | "bar";

export interface SeriesStyle {
  /** The CSS class giving the colour (`.series-N` in styles.css). */
  className: string;
  /** The colour token (`--series-N`). */
  token: string;
  /** SVG stroke-dasharray; "" is solid. */
  dash: string;
  marker: Marker;
  /** The words a screen reader or legend uses for the line's look. */
  look: string;
}

export const SERIES: readonly SeriesStyle[] = [
  { className: "series-1", token: "--series-1", dash: "", marker: "circle", look: "solid line, circles" },
  { className: "series-2", token: "--series-2", dash: "8 4", marker: "square", look: "dashed line, squares" },
  { className: "series-3", token: "--series-3", dash: "2 4", marker: "triangle", look: "dotted line, triangles" },
  { className: "series-4", token: "--series-4", dash: "10 3 2 3", marker: "diamond", look: "dash-dot line, diamonds" },
  { className: "series-5", token: "--series-5", dash: "4 2", marker: "cross", look: "short dashes, crosses" },
  { className: "series-6", token: "--series-6", dash: "1 3 6 3", marker: "bar", look: "dot-dash line, bars" },
];

/** The style of series i (0-based; six at most, design §3.2). */
export function seriesStyle(i: number): SeriesStyle {
  return SERIES[((i % SERIES.length) + SERIES.length) % SERIES.length]!;
}

/** The relative luminance of a #rrggbb colour (WCAG 2.1). */
export function luminance(hex: string): number {
  const m = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex.trim());
  if (!m) throw new Error(`not a #rrggbb colour: ${hex}`);
  const [r, g, b] = [m[1]!, m[2]!, m[3]!].map((h) => {
    const c = parseInt(h, 16) / 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  }) as [number, number, number];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** The WCAG contrast ratio of two #rrggbb colours. */
export function contrast(a: string, b: string): number {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p) as [number, number];
  return (x + 0.05) / (y + 0.05);
}

/** The SVG path of a marker centred on (x, y), of size s. */
export function markerPath(m: Marker, x: number, y: number, s = 4): string {
  switch (m) {
    case "circle":
      return `M${x - s},${y}a${s},${s} 0 1,0 ${2 * s},0a${s},${s} 0 1,0 ${-2 * s},0Z`;
    case "square":
      return `M${x - s},${y - s}h${2 * s}v${2 * s}h${-2 * s}Z`;
    case "triangle":
      return `M${x},${y - s}L${x + s},${y + s}L${x - s},${y + s}Z`;
    case "diamond":
      return `M${x},${y - s}L${x + s},${y}L${x},${y + s}L${x - s},${y}Z`;
    case "cross":
      return `M${x - s},${y - s}L${x + s},${y + s}M${x + s},${y - s}L${x - s},${y + s}`;
    case "bar":
      return `M${x},${y - s}V${y + s}`;
  }
}
