// F-006 T-04 (F-006-AC-05; design §3.4): reading the loss exceedance curve.
// The stored points (F-005 design §3.4: 200 log-spaced amounts with
// P(ALE > x)) are merged with the exceedance at each reported percentile
// (`curve.at_percentiles`, at the amount `ale.percentiles`). Between two
// points the probability is interpolated linearly in ln(amount). Nothing
// is stored: these are read from the curve, and labelled so.

export interface StoredCurve {
  points?: [number, number][] | number[][];
  at_percentiles?: Record<string, number | null>;
}

export interface CurvePoint {
  amount: number;
  probability: number;
  /** The reported percentile this point is exact at ("p90"), if any. */
  percentile?: string;
}

/** The curve's points, merged and sorted by amount (positive amounts only). */
export function mergedPoints(curve: StoredCurve | undefined, percentiles?: Record<string, number | null>): CurvePoint[] {
  const out: CurvePoint[] = [];
  for (const p of curve?.points ?? []) {
    const [a, b] = p;
    if (typeof a === "number" && typeof b === "number" && a > 0) out.push({ amount: a, probability: b });
  }
  for (const [k, prob] of Object.entries(curve?.at_percentiles ?? {})) {
    const amount = percentiles?.[k];
    if (typeof amount === "number" && amount > 0 && typeof prob === "number") out.push({ amount, probability: prob, percentile: k });
  }
  out.sort((x, y) => x.amount - y.amount || y.probability - x.probability);
  return out;
}

export type Reading =
  | { kind: "exact"; value: number; percentile?: string }
  | { kind: "interpolated"; value: number }
  | { kind: "between"; low: number; high: number }
  | { kind: "none_exceeded" }
  | { kind: "invalid" };

/**
 * P(ALE > x) read from the curve. `anyLoss` is P(ALE > 0) (the ALE
 * summary's `p_positive`; without it, the first point's probability).
 */
export function probabilityAt(points: CurvePoint[], x: number, anyLoss?: number): Reading {
  if (!Number.isFinite(x) || x < 0) return { kind: "invalid" };
  const first = points[0];
  const last = points[points.length - 1];
  if (!first || !last) return { kind: "none_exceeded" };
  const pAny = anyLoss ?? first.probability;
  if (x === 0) return { kind: "exact", value: pAny };
  if (x > last.amount) return { kind: "none_exceeded" };
  if (x < first.amount) return { kind: "between", low: first.probability, high: pAny };
  for (let j = 0; j < points.length; j++) {
    const pj = points[j]!;
    if (pj.amount === x) return pj.percentile ? { kind: "exact", value: pj.probability, percentile: pj.percentile } : { kind: "exact", value: pj.probability };
    if (pj.amount > x) {
      const pi = points[j - 1]!;
      const t = (Math.log(x) - Math.log(pi.amount)) / (Math.log(pj.amount) - Math.log(pi.amount));
      return { kind: "interpolated", value: pi.probability + t * (pj.probability - pi.probability) };
    }
  }
  return { kind: "none_exceeded" };
}

/**
 * The amount whose probability of being exceeded is q: the smallest
 * amount where the curve reaches q. At or above P(ALE > 0) it is 0.
 */
export function amountAt(points: CurvePoint[], q: number, anyLoss?: number): Reading {
  if (!Number.isFinite(q) || q < 0 || q > 1) return { kind: "invalid" };
  const first = points[0];
  if (!first) return { kind: "exact", value: 0 };
  const pAny = anyLoss ?? first.probability;
  if (q >= pAny) return { kind: "exact", value: 0 };
  for (let j = 0; j < points.length; j++) {
    const pj = points[j]!;
    if (pj.probability <= q) {
      if (pj.probability === q) return pj.percentile ? { kind: "exact", value: pj.amount, percentile: pj.percentile } : { kind: "exact", value: pj.amount };
      if (j === 0) return { kind: "between", low: 0, high: pj.amount };
      const pi = points[j - 1]!;
      const t = (pi.probability - q) / (pi.probability - pj.probability);
      return { kind: "interpolated", value: Math.exp(Math.log(pi.amount) + t * (Math.log(pj.amount) - Math.log(pi.amount))) };
    }
  }
  // Every point is above q: beyond the largest simulated loss.
  return { kind: "none_exceeded" };
}
