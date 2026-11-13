// F-006 T-04 (F-006-AC-14): the charts' text alternatives and tables.
import assert from "node:assert/strict";
import { test } from "node:test";
import { describeBars, describeExceedance, describeHistogram, describeTornado, exceedanceTable, histogramTable, signed, tornadoTable } from "./describe.ts";

const current = {
  label: "Current",
  curve: { points: [[1000, 0.5], [2_000_000, 0.1], [9_000_000, 0]], at_percentiles: { p90: 0.1 } },
  percentiles: { p90: 2_000_000 },
  anyLoss: 0.6,
};
const mfa = { label: "MFA rollout", curve: { points: [[1000, 0.3], [2_000_000, 0.04], [5_000_000, 0]] }, anyLoss: 0.35 };

test("the exceedance chart reads as each set's chance of exceeding the base's one-in-ten loss", () => {
  assert.equal(
    describeExceedance([current, mfa], "USD"),
    "Chance of losing more than $2M in a year. Current (solid line, circles): 10%; MFA rollout (dashed line, squares): 4%.",
  );
  assert.equal(describeExceedance([], "USD"), "No results to show.");
});

test("the exceedance table lists every point", () => {
  const t = exceedanceTable([current, mfa], "USD");
  assert.equal(t.rows.length, 7);
  assert.deepEqual(t.rows[2], ["Current", "$2,000,000", "10%", "p90"]);
});

const h = { edges: [0, 10, 20], counts: [30, 60], n: 100, zero: 10, zero_share: 0.1, scale: "linear" };

test("the histogram reads as years apart and the fullest bin", () => {
  assert.equal(describeHistogram(h, "EUR", false), "10% of years have no loss. The most frequent annual losses, 60% of years, are between €10 and €20.");
  assert.match(describeHistogram({ ...h, both_none: 4 }, "EUR", true), /^10% of years show no difference/);
  const t = histogramTable({ ...h, both_none: 4 }, "EUR", true);
  assert.deepEqual(t.rows.at(-1), ["Neither lost anything", "4", "4%"]);
  assert.deepEqual(t.rows[0], ["€0.00 to €10.00", "30", "30%"]);
});

test("bars and the tornado read from the largest", () => {
  assert.equal(
    describeBars("Loss by form", [{ label: "Response", value: 10, share: 0.25 }, { label: "Fines", value: 30, share: 0.75 }], null),
    "Loss by form: Fines 30 (75%); Response 10 (25%).",
  );
  const inputs = [{ label: "Contact frequency", pointer: "/lef/tef/contact_frequency", low: -2500, high: 2500, spearman: 0.5 }];
  assert.equal(describeTornado(inputs, "USD"), "The inputs that move the mean annual loss most, from its low to its high end: Contact frequency (from −$2.5K to +$2.5K).");
  assert.deepEqual(tornadoTable([{ ...inputs[0]!, spearman: null }], "USD").rows[0], ["Contact frequency", "/lef/tef/contact_frequency", "−$2.5K", "+$2.5K", "—"]);
  assert.equal(signed(0, "USD"), "$0");
});
