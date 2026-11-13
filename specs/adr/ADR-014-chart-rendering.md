# ADR-014 Chart rendering: the platform's own SVG components
Status: Accepted (Robert Former, 2026-11-13; F-006 design)
Date: 2026-11-13

## Context
F-006 draws a small, fixed set of charts:
- loss exceedance curves, overlaid for up to six results, on a linear or logarithmic amount axis;
- histograms of annual loss, and of the per-year difference between control sets;
- horizontal bars: the breakdown of loss, aggregate contributions, and the sensitivity tornado.

The charts must:
- meet WCAG 2.1 AA (Q3): a text alternative and a data table for every chart, keyboard use of every interaction (a cursor that moves along the curve), and series told apart by more than colour (F-006-AC-14 to AC-16);
- work under the UI's content security policy (`server.UICSP`: own scripts only, no inline script, a single hashed inline stylesheet), and the UI's E2E test fails on any violation;
- export as SVG and PNG with their labels drawn in (AC-17), with names escaped so a downloaded SVG cannot carry script;
- show the same in SaaS, self-hosted and air-gapped installations, with no external fonts or scripts (A7).

The web UI so far depends only on React and React Aria Components (ADR-003).

Three approaches were weighed:
- **A charting library built on SVG** (for example Recharts or visx). This would bring a dependency tree to vet, pin and keep current, with its own styling and DOM conventions. The keyboard cursor, the data tables, the text alternatives and the export would still be ours to write.
- **A canvas library** (for example Chart.js). The exported PNG comes easily. But a canvas has no document structure for assistive technology, so everything accessible is a parallel rendering, and an SVG export is not native.
- **Our own SVG components.** These are linear and logarithmic scales with readable ticks, axes, a line series, bars and a histogram, about a thousand lines of TypeScript. The platform has done the same where the need was narrow: its own PDF writer (F-001 T-38) and SCIM server (F-001 T-21).

## Decision
Draw F-006's charts with our own React SVG components in `web/src/charts/`:
- `scale.ts`: linear and logarithmic scales, tick choice, currency and percentage formatting through `Intl.NumberFormat` in the installation currency.
- `ExceedanceChart`, `Histogram`, `Bars` (breakdown, contributions), `Tornado`.
- `ChartFigure`: a `figure` with a caption, a text alternative, a data-table view and the download menu.
- `export.ts`: serializes the rendered SVG with colours resolved from the theme tokens and presentation attributes only (no `style` attributes or elements, no scripts, no external references). PNG output draws that SVG on a canvas through a `data:` image, which `img-src 'self' data:` already allows.

Series styles come from theme tokens `--series-1` to `--series-6`. Each pairs a colour (at least 3:1 against the background in the light and dark themes) with a dash pattern and a marker shape.

## Consequences
- No new runtime dependency, and no change to the content security policy.
- We maintain the scales and tick logic, and their unit tests (`web/src/charts/*.test.ts`, run by the UI typecheck and E2E job).
- Charts beyond F-006's (F-010 reports, F-007 roll-ups) reuse these components. A need they cannot meet reopens this decision.
- Text from users (scenario, control set and aggregate names) reaches the SVG only as React text children, and so is escaped. The export test downloads a chart whose scenario name holds markup and checks it stays text.
