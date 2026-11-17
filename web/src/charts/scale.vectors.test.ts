// F-010 T-08 (ADR-015): the scales hold to the vectors the Go chart module
// (internal/report/chart) is checked against, so PDF charts and the app's
// charts choose the same ticks and positions. Regenerate the vectors with
// node scripts/chart-vectors.mjs after a deliberate change here.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { linearScale, linearTicks, logScale, logTicks, niceStep } from "./scale.ts";

interface Vectors {
  nice_step: [number, number, number][];
  linear_ticks: [number, number, number, number[]][];
  log_ticks: [number, number, number, number[]][];
  linear_map: [number, number, number, number, number, number][];
  log_map: [number, number, number, number, number, number][];
}

const v = JSON.parse(readFileSync(new URL("../../../internal/report/chart/testdata/scales.json", import.meta.url), "utf8")) as Vectors;

const close = (a: number, b: number) => Math.abs(a - b) <= 1e-9 * Math.max(1, Math.abs(b));

test("the scales match the shared vectors", () => {
  for (const [span, count, want] of v.nice_step) assert.equal(niceStep(span, count), want);
  for (const [a, b, c, want] of v.linear_ticks) assert.deepEqual(linearTicks(a, b, c), want);
  for (const [a, b, c, want] of v.log_ticks) assert.deepEqual(logTicks(a, b, c), want);
  for (const [d0, d1, r0, r1, x, want] of v.linear_map) assert.ok(close(linearScale([d0, d1], [r0, r1]).map(x), want));
  for (const [d0, d1, r0, r1, x, want] of v.log_map) assert.ok(close(logScale([d0, d1], [r0, r1]).map(x), want));
});
