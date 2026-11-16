# ADR-015 Charts in PDF reports: Go vector charts
Status: Proposed (F-010 design, 2026-11-16)
Date: 2026-11-16

## Context
F-010's PDF reports (portfolio and risk reports) carry the charts F-006 draws in the browser: loss exceedance curves, histograms of annual loss and horizontal bars (breakdown, contributions, drivers). ADR-014 draws them as React SVG components; reports are rendered in the risk service, in Go, without a browser.

The PDFs must:
- meet PDF/UA-1 and Section 508 (Q3): each chart a tagged Figure with alternative text, followed by its data table;
- print sharply and keep chart labels as real text;
- be produced with no network access in every deployment mode (A7), deterministically for a given document;
- look like the charts in the app, so a committee pack and the screen agree.

Three approaches were weighed:
- **Headless Chromium** rendering the web pages to PDF: the charts would match exactly, but it adds a large runtime to vet, patch and run under FIPS constraints, and its PDFs are poorly tagged.
- **Raster images** drawn in Go and embedded as PNG: simple, but blurry when printed, with labels as pixels.
- **Go vector charts** drawing PDF paths and text directly.

## Decision
Add `internal/report/chart`, a small Go module that draws loss exceedance curves (overlaid, up to six series, linear or logarithmic amount axis), histograms and horizontal bars as PDF vector content:
- Scales and tick choice port `web/src/charts/scale.ts` (linear, logarithmic, readable ticks, currency and percentage formats). Shared test vectors (`testdata/scales.json`, read by both the Go and the `node --test` suites) hold the two equal.
- Series styles follow ADR-014's tokens for the light theme: colour, dash pattern and marker shape, so series differ by more than colour.
- Axis labels, ticks and legends are text in the embedded fonts (marked as artifacts inside the Figure); the Figure carries the chart's alternative text, and the report places the chart's data table right after it.

## Consequences
- No new runtime dependency.
- Two implementations of the scales (TypeScript and Go), held equal by shared vectors; a change to one needs the vectors and both suites.
- New chart kinds in reports need this module; a need it cannot meet reopens this decision.
