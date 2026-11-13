// F-006 T-04 (ADR-014): scales and ticks.
import assert from "node:assert/strict";
import { test } from "node:test";
import { formatAmount, formatProbability, linearScale, linearTicks, logScale, logTicks, niceStep } from "./scale.ts";

test("nice steps are 1, 2 or 5 times a power of ten", () => {
  assert.equal(niceStep(100, 5), 20);
  assert.equal(niceStep(1, 4), 0.5);
  assert.equal(niceStep(7300, 5), 2000);
  assert.equal(niceStep(0, 5), 1);
});

test("linear ticks are multiples of the step within the domain", () => {
  assert.deepEqual(linearTicks(0, 100, 5), [0, 20, 40, 60, 80, 100]);
  assert.deepEqual(linearTicks(-10, 6, 4), [-10, -5, 0, 5]);
  assert.deepEqual(linearTicks(0.1, 0.5, 4), [0.1, 0.2, 0.3, 0.4, 0.5]);
});

test("log ticks are powers of ten, thinned when many, filled with 2 and 5 when few", () => {
  assert.deepEqual(logTicks(1, 1000), [1, 10, 100, 1000]);
  assert.deepEqual(logTicks(1, 1e12, 4), [1, 1e3, 1e6, 1e9, 1e12]);
  assert.deepEqual(logTicks(3, 40), [5, 10, 20]);
  assert.deepEqual(logTicks(3, 4), [3, 4]);
});

test("linear scales map, clamp and invert", () => {
  const s = linearScale([0, 10], [100, 200]);
  assert.equal(s.map(5), 150);
  assert.equal(s.map(20), 200);
  assert.equal(s.invert(150), 5);
  assert.deepEqual(linearScale([3, 3], [0, 10]).domain, [2, 4]);
  const down = linearScale([0, 1], [300, 0]);
  assert.equal(down.map(0.25), 225);
});

test("log scales map ratios to equal distances", () => {
  const s = logScale([1, 1000], [0, 300]);
  assert.ok(Math.abs(s.map(10) - 100) < 1e-9);
  assert.ok(Math.abs(s.map(100) - 200) < 1e-9);
  assert.ok(Math.abs(s.invert(100) - 10) < 1e-9);
  assert.equal(s.map(0.001), 0);
  assert.throws(() => logScale([0, 10], [0, 1]));
  assert.deepEqual(logScale([5, 5], [0, 1]).domain, [0.5, 50]);
});

test("amounts and probabilities read as people write them", () => {
  assert.equal(formatAmount(2_100_000, "USD", "en-US"), "$2.1M");
  assert.equal(formatAmount(950, "EUR", "en-US"), "€950");
  assert.equal(formatAmount(1500, null, "en-US"), "1.5K");
  assert.match(formatAmount(12, "ZZZ", "en-US"), /^ZZZ\s12$/u);
  assert.equal(formatProbability(0.1, "en-US"), "10%");
  assert.equal(formatProbability(0.0123, "en-US"), "1.2%");
  assert.equal(formatProbability(0.00001, "en-US"), "<0.01%");
  assert.equal(formatAmount(Number.NaN, "USD"), "—");
});
