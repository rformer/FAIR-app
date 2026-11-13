// F-006 T-04 (F-006-AC-05; design §3.4): reading the curve.
import assert from "node:assert/strict";
import { test } from "node:test";
import { amountAt, mergedPoints, probabilityAt } from "./curve.ts";

const curve = {
  points: [
    [10, 0.5],
    [100, 0.2],
    [1000, 0],
  ],
  at_percentiles: { p90: 0.1, p50: 0.5, p1: 0.9 },
};
const percentiles = { p90: 400, p50: 10, p1: 0 };
const pts = mergedPoints(curve, percentiles);

test("points merge with the percentiles, sorted, positive amounts only", () => {
  assert.deepEqual(
    pts.map((p) => [p.amount, p.probability, p.percentile ?? ""]),
    [
      [10, 0.5, ""],
      [10, 0.5, "p50"],
      [100, 0.2, ""],
      [400, 0.1, "p90"],
      [1000, 0, ""],
    ],
  );
  assert.deepEqual(mergedPoints(undefined), []);
});

test("the probability interpolates linearly in log amount", () => {
  const r = probabilityAt(pts, Math.sqrt(10 * 100), 0.6);
  assert.equal(r.kind, "interpolated");
  assert.ok(r.kind === "interpolated" && Math.abs(r.value - 0.35) < 1e-12);
});

test("exact at a point, and at a reported percentile", () => {
  assert.deepEqual(probabilityAt(pts, 100), { kind: "exact", value: 0.2 });
  assert.deepEqual(probabilityAt(pts, 400), { kind: "exact", value: 0.1, percentile: "p90" });
  assert.deepEqual(probabilityAt(pts, 0, 0.6), { kind: "exact", value: 0.6 });
});

test("below the first point, between it and any loss; above the largest, none", () => {
  assert.deepEqual(probabilityAt(pts, 5, 0.6), { kind: "between", low: 0.5, high: 0.6 });
  assert.deepEqual(probabilityAt(pts, 5), { kind: "between", low: 0.5, high: 0.5 });
  assert.deepEqual(probabilityAt(pts, 2000), { kind: "none_exceeded" });
  assert.deepEqual(probabilityAt(pts, -1), { kind: "invalid" });
  assert.deepEqual(probabilityAt([], 5), { kind: "none_exceeded" });
});

test("the amount at a probability is the inverse, the smallest amount reaching it", () => {
  const r = amountAt(pts, 0.35, 0.6);
  assert.ok(r.kind === "interpolated" && Math.abs(r.value - Math.sqrt(1000)) < 1e-9);
  assert.deepEqual(amountAt(pts, 0.1), { kind: "exact", value: 400, percentile: "p90" });
  assert.deepEqual(amountAt(pts, 0.6, 0.6), { kind: "exact", value: 0 });
  assert.deepEqual(amountAt(pts, 0.55, 0.6), { kind: "between", low: 0, high: 10 });
  assert.deepEqual(amountAt(pts, 0), { kind: "exact", value: 1000 });
  assert.deepEqual(amountAt(pts, 1.5), { kind: "invalid" });
});

test("the two readings agree", () => {
  for (const q of [0.45, 0.3, 0.15, 0.05]) {
    const a = amountAt(pts, q, 0.6);
    assert.ok(a.kind === "interpolated" || a.kind === "exact");
    const p = probabilityAt(pts, a.value, 0.6);
    assert.ok((p.kind === "interpolated" || p.kind === "exact") && Math.abs(p.value - q) < 1e-9, `${q}: ${JSON.stringify(p)}`);
  }
});
