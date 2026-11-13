// F-005 T-13: the analysis API's shapes (api/openapi/analysis.yaml).

export type RunState = "queued" | "running" | "succeeded" | "failed" | "cancelled";

export interface RunWarning {
  code: string;
  pointer?: string;
  control_set?: string;
  detail?: string;
}

export interface Distribution {
  n: number;
  mean: number | null;
  sd: number | null;
  min: number | null;
  max: number | null;
  percentiles: Record<string, number | null>;
  p_positive?: number | null;
}

export interface SensitivityInput {
  input: string;
  pointer: string;
  kind: "estimate" | "control_effect";
  control: string | null;
  factor: string | null;
  low: { value: number; mean: number; change: number };
  high: { value: number; mean: number; change: number };
  swing: number;
  spearman: number | null;
}

export interface SetSummary {
  independence: string;
  iterations: number;
  ale: Distribution;
  lef: Distribution;
  loss_per_event: Distribution;
  breakdown: { primary: number | null; secondary: number | null; forms: Record<string, number | null>; stakeholders: Record<string, number | null> };
  comparison: null | { against: string; mean: number; percentiles: Record<string, number>; difference?: Distribution };
  /** The loss exceedance curve (F-005 design §3.4): points [amount, P(ALE > amount)] and the exceedance at each percentile. */
  curve?: { points: [number, number][]; at_percentiles?: Record<string, number | null> };
  convergence: { se: number; rse: number | null; threshold_bp: number; converged: boolean; intervals: Record<string, [number, number]> };
  sensitivity?: { iterations: number; inputs: SensitivityInput[] };
}

export interface Run {
  id: string;
  bu_id: string;
  scenario_id: string;
  scenario_version: number;
  bundle_digest: string;
  seed: string;
  iterations: number;
  control_sets: string[];
  requested_by: string;
  requested_at: string;
  state: RunState;
  progress: number;
  started_at: string | null;
  finished_at: string | null;
  cancel_reason: string | null;
  failure: string | null;
  failure_detail: string | null;
  engine: null | { version: string; architecture: string | null; image_digest: string | null };
  warnings: RunWarning[];
  result_digest: string | null;
  reproduces: string | null;
  reproduction: null | "match" | "mismatch" | "other_version" | "other_architecture";
  seq: number;
  results?: { control_set: string; summary: SetSummary }[];
}

export interface AggregateMember {
  position: number;
  run_id: string;
  control_set: string;
  engine_version: string | null;
  scenario_id: string;
  scenario_version: number;
  scenario_name: string;
}

export interface Aggregate {
  id: string;
  bu_id: string;
  name: string;
  seed: string;
  iterations: number;
  requested_at: string;
  state: "queued" | "running" | "succeeded" | "failed";
  failure: string | null;
  failure_detail: string | null;
  engine: null | { version: string; architecture: string | null };
  result_digest: string | null;
  members?: AggregateMember[];
  member_engine_versions?: string[];
  mixed_engine_versions?: boolean;
  summary?: null | {
    independence: string;
    iterations: number;
    members: number;
    ale: Distribution;
    p95_year: { loss: number };
    contributions: { position: number; label: string; mean: number; share_of_p95_year: number | null }[];
  };
}

export const STATE_LABELS: Record<RunState, string> = {
  queued: "Queued",
  running: "Running",
  succeeded: "Succeeded",
  failed: "Failed",
  cancelled: "Cancelled",
};

export const REPRODUCTION_LABELS: Record<NonNullable<Run["reproduction"]>, string> = {
  match: "Reproduced exactly",
  mismatch: "Results differ",
  other_version: "Other engine version",
  other_architecture: "Other CPU architecture",
};

export const FAILURE_LABELS: Record<string, string> = {
  invalid_bundle: "The scenario could not be simulated",
  engine_not_validated: "The engine has not passed its validation",
  engine_unavailable: "The engine was unavailable",
  invalid_results: "The engine returned malformed results",
  engine_internal: "The engine failed",
};

/** Money in the installation currency, whole units. */
export function money(v: number | null | undefined, currency: string | null): string {
  if (v === null || v === undefined) return "—";
  if (!currency) return Math.round(v).toLocaleString("en-US");
  return new Intl.NumberFormat("en-US", { style: "currency", currency, maximumFractionDigits: 0 }).format(v);
}

export function percent(v: number | null | undefined, digits = 1): string {
  if (v === null || v === undefined) return "—";
  return `${(v * 100).toFixed(digits)}%`;
}

export function active(state: string): boolean {
  return state === "queued" || state === "running";
}
