// F-010 T-17 (F-010-AC-05, AC-07): the trends' series, text alternatives
// and tables.
import assert from "node:assert/strict";
import { test } from "node:test";
import { coverageSeries, describeCoverageTrend, describeExposureTrend, exposureSeries, trendTable, type TrendPoint } from "./trend.ts";

const counts = (open: number, current: number, mean_sum: number) => ({ open, current, stale: open - current, unquantified: 0, mean_sum, open_actions: 2, overdue_actions: 1 });
const a: TrendPoint = { snapshot_id: 1, taken_at: "2026-10-01T00:00:00Z", counts: counts(4, 3, 900_000), rollup: null };
const b: TrendPoint = {
  snapshot_id: 2,
  taken_at: "2026-10-08T00:00:00Z",
  counts: counts(5, 5, 1_200_000),
  rollup: { finished_at: "2026-10-07T12:00:00Z", mean: 1_000_000, p10: 100_000, p50: 600_000, p90: 2_500_000, p99: 9_000_000 },
};

test("exposure: the roll-up only where its row is visible, the sum of means always", () => {
  const s = exposureSeries([a, b]);
  assert.deepEqual(
    s.map((x) => [x.label, x.points.length]),
    [
      ["Roll-up mean", 1],
      ["Roll-up 90th percentile", 1],
      ["Sum of the open risks' means", 2],
    ],
  );
  assert.deepEqual(exposureSeries([a]).map((x) => x.label), ["Sum of the open risks' means"]);
  assert.equal(coverageSeries([a, b])[0]?.points[1]?.v, 5);
});

test("the text alternatives read the first and last snapshots", () => {
  assert.equal(describeExposureTrend([], "USD"), "No snapshot in this period.");
  const e = describeExposureTrend([a, b], "USD");
  assert.match(e, /^2 snapshots from 2026-10-01 to 2026-10-08\./);
  assert.match(e, /no roll-up you can see/);
  assert.match(e, /roll-up mean of \$1(\.0)?M/);
  assert.equal(describeCoverageTrend([b]), "One snapshot, on 2026-10-08: 5 of 5 open risks current, 0 stale, 0 unquantified.");
});

test("the table has a row per snapshot, without a roll-up said so", () => {
  const t = trendTable([a, b], "USD");
  assert.equal(t.rows.length, 2);
  assert.equal(t.rows[0]?.[1], "No roll-up you can see");
  assert.equal(t.rows[1]?.[1], "2026-10-07");
  assert.equal(t.rows[0]?.length, t.columns.length);
});
