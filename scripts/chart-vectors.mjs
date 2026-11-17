// F-010 T-08 (ADR-015): generates internal/report/chart/testdata/scales.json
// from the web scales, the reference; the Go chart module and
// web/src/charts/scale.vectors.test.ts both check against it.
//
//   node scripts/chart-vectors.mjs   (Node 22.18 or later)
import { writeFileSync } from "node:fs";
import { linearScale, linearTicks, logScale, logTicks, niceStep } from "../web/src/charts/scale.ts";

const spans = [[100, 5], [1, 4], [7300, 5], [0, 5], [0.003, 5], [2.5e9, 6], [17, 3], [999, 10]];
const lin = [[0, 100, 5], [-10, 6, 4], [0.1, 0.5, 4], [0, 1, 5], [0, 2_500_000, 5], [12_000, 97_500, 6], [0.0001, 0.0013, 4], [-3.2, 7.9, 5]];
const logs = [[1, 1000, 5], [1, 1e12, 4], [3, 40, 5], [3, 4, 5], [1000, 25_000_000, 5], [0.5, 2, 5], [12_345, 9_876_543_210, 6]];
const maps = [[0, 10, 100, 200, 5], [0, 10, 100, 200, 20], [0, 1, 300, 0, 0.25], [-5, 5, 0, 640, 1.25], [3, 3, 0, 10, 3]];
const logMaps = [[1, 1000, 0, 300, 10], [1, 1000, 0, 300, 0.001], [1000, 1e7, 50, 650, 31_622.7766], [5, 5, 0, 1, 5], [2, 2e6, 400, 0, 2e4]];

const out = {
  source: "web/src/charts/scale.ts (ADR-015); regenerate with node scripts/chart-vectors.mjs, never by hand",
  nice_step: spans.map(([s, c]) => [s, c, niceStep(s, c)]),
  linear_ticks: lin.map(([a, b, c]) => [a, b, c, linearTicks(a, b, c)]),
  log_ticks: logs.map(([a, b, c]) => [a, b, c, logTicks(a, b, c)]),
  linear_map: maps.map(([d0, d1, r0, r1, v]) => [d0, d1, r0, r1, v, linearScale([d0, d1], [r0, r1]).map(v)]),
  log_map: logMaps.map(([d0, d1, r0, r1, v]) => [d0, d1, r0, r1, v, logScale([d0, d1], [r0, r1]).map(v)]),
};
const lines = Object.entries(out).map(([k, v]) =>
  typeof v === "string" ? `  ${JSON.stringify(k)}: ${JSON.stringify(v)}` : `  ${JSON.stringify(k)}: [\n${v.map((r) => "    " + JSON.stringify(r)).join(",\n")}\n  ]`);
writeFileSync(new URL("../internal/report/chart/testdata/scales.json", import.meta.url), "{\n" + lines.join(",\n") + "\n}\n");
console.log("ok");
