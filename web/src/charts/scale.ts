// F-006 T-04 (ADR-014; design §4): scales, ticks and the number formats of
// F-006's charts. Pure functions: unit-tested by `node --test`.

export type ScaleKind = "linear" | "log";

export interface Scale {
  kind: ScaleKind;
  domain: [number, number];
  range: [number, number];
  /** The position of a value (clamped to the domain). */
  map(v: number): number;
  /** The value at a position. */
  invert(px: number): number;
  /** Tick values within the domain, about `count` of them. */
  ticks(count?: number): number[];
}

/** A linear scale; a domain of one value is widened by one unit either side. */
export function linearScale(domain: [number, number], range: [number, number]): Scale {
  let [d0, d1] = domain;
  if (d0 === d1) {
    d0 -= 1;
    d1 += 1;
  }
  const [r0, r1] = range;
  const k = (r1 - r0) / (d1 - d0);
  return {
    kind: "linear",
    domain: [d0, d1],
    range,
    map: (v) => r0 + (Math.min(Math.max(v, Math.min(d0, d1)), Math.max(d0, d1)) - d0) * k,
    invert: (px) => d0 + (px - r0) / k,
    ticks: (count = 5) => linearTicks(d0, d1, count),
  };
}

/** A logarithmic scale over positive values; a domain of one value is widened by a factor of ten either side. */
export function logScale(domain: [number, number], range: [number, number]): Scale {
  let [d0, d1] = domain;
  if (!(d0 > 0) || !(d1 > 0)) throw new RangeError("a log scale needs a positive domain");
  if (d0 === d1) {
    d0 /= 10;
    d1 *= 10;
  }
  const [r0, r1] = range;
  const l0 = Math.log(d0);
  const k = (r1 - r0) / (Math.log(d1) - l0);
  return {
    kind: "log",
    domain: [d0, d1],
    range,
    map: (v) => r0 + (Math.log(Math.min(Math.max(v, d0), d1)) - l0) * k,
    invert: (px) => Math.exp(l0 + (px - r0) / k),
    ticks: (count = 5) => logTicks(d0, d1, count),
  };
}

/** The "nice" step (1, 2 or 5 times a power of ten) giving about count ticks. */
export function niceStep(span: number, count: number): number {
  const raw = Math.abs(span) / Math.max(count, 1);
  if (!(raw > 0) || !Number.isFinite(raw)) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(raw)));
  const m = raw / p;
  return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p;
}

/** Multiples of the nice step within [d0, d1]. */
export function linearTicks(d0: number, d1: number, count = 5): number[] {
  const lo = Math.min(d0, d1);
  const hi = Math.max(d0, d1);
  const step = niceStep(hi - lo, count);
  const out: number[] = [];
  for (let i = Math.ceil(lo / step); i * step <= hi + step * 1e-9; i++) {
    out.push(round(i * step, step));
    if (out.length > 100) break;
  }
  return out;
}

/** Powers of ten within [d0, d1] (every other one when there are many); 2 and 5 times them when there are fewer than two. */
export function logTicks(d0: number, d1: number, count = 5): number[] {
  const e0 = Math.ceil(Math.log10(d0) - 1e-12);
  const e1 = Math.floor(Math.log10(d1) + 1e-12);
  const decades: number[] = [];
  for (let e = e0; e <= e1; e++) decades.push(e);
  if (decades.length >= 2) {
    const every = Math.max(1, Math.ceil((decades.length - 1) / Math.max(count, 1)));
    return decades.filter((e) => (e - e0) % every === 0).map((e) => Math.pow(10, e));
  }
  const out: number[] = [];
  for (let e = Math.floor(Math.log10(d0)); e <= Math.ceil(Math.log10(d1)); e++) {
    for (const m of [1, 2, 5]) {
      const v = m * Math.pow(10, e);
      if (v >= d0 * (1 - 1e-12) && v <= d1 * (1 + 1e-12)) out.push(v);
    }
  }
  return out.length >= 2 ? out : [d0, d1];
}

function round(v: number, step: number): number {
  const digits = Math.max(0, -Math.floor(Math.log10(step)) + 1);
  return Number(v.toFixed(Math.min(digits, 20)));
}

/** An amount in the installation currency, compact ("€2.1M"); without a currency, a compact number. */
export function formatAmount(v: number, currency: string | null, locale?: string): string {
  if (!Number.isFinite(v)) return "—";
  const opts: Intl.NumberFormatOptions = { notation: "compact", maximumSignificantDigits: 3 };
  if (currency) {
    try {
      return new Intl.NumberFormat(locale, { ...opts, style: "currency", currency }).format(v);
    } catch {
      // An unknown code: the number, then the code.
      return `${new Intl.NumberFormat(locale, opts).format(v)} ${currency}`;
    }
  }
  return new Intl.NumberFormat(locale, opts).format(v);
}

/** An amount in full, for tables ("€2,104,553"). */
export function formatAmountFull(v: number, currency: string | null, locale?: string): string {
  if (!Number.isFinite(v)) return "—";
  const opts: Intl.NumberFormatOptions = { maximumFractionDigits: Math.abs(v) < 100 ? 2 : 0 };
  if (currency) {
    try {
      return new Intl.NumberFormat(locale, { ...opts, style: "currency", currency }).format(v);
    } catch {
      return `${new Intl.NumberFormat(locale, opts).format(v)} ${currency}`;
    }
  }
  return new Intl.NumberFormat(locale, opts).format(v);
}

/** A probability as a percentage with two significant digits; tiny ones as "<0.01%". */
export function formatProbability(p: number, locale?: string): string {
  if (!Number.isFinite(p)) return "—";
  if (p > 0 && p < 0.0001) return `<${new Intl.NumberFormat(locale, { style: "percent", maximumFractionDigits: 2 }).format(0.0001)}`;
  return new Intl.NumberFormat(locale, { style: "percent", maximumSignificantDigits: 2 }).format(p);
}

/** A share as a whole or one-decimal percentage. */
export function formatShare(s: number, locale?: string): string {
  if (!Number.isFinite(s)) return "—";
  return new Intl.NumberFormat(locale, { style: "percent", maximumFractionDigits: Math.abs(s) < 0.1 ? 1 : 0 }).format(s);
}
