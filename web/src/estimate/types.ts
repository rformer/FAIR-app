import type { Estimate, Unit } from "../risk/types";

// F-004: the estimate API's shapes the pages use (api/openapi/estimate.yaml).

export interface InboxItem {
  id: string;
  title: string;
  status: "open" | "complete" | "closed" | "cancelled";
  due_at: string;
  confidence: string;
  scenario_name: string | null;
  factors: number;
  answered: number;
  finished_at: string | null;
  created_at: string;
}

export interface RequestFactor {
  pointer: string;
  factor: string;
  unit: Unit;
  definition: string;
}

export interface OwnAnswer {
  pointer: string;
  revision: number;
  state: "draft" | "submitted";
  estimate: Estimate | null;
  declined: string | null;
  created_at: string;
}

export interface Reference {
  id: string;
  version: number;
  digest: string;
  document: {
    name: string;
    description?: string;
    period: { start: string; end: string };
    data:
      | {
          kind: "counts";
          series: { start: string; end: string; count: number }[];
        }
      | { kind: "losses"; unit: "currency"; amounts: string[] };
    sources: { type: string; ref: string }[];
  };
}

export interface EstimatorView {
  request: {
    id: string;
    bu_id: string;
    title: string;
    instructions: string;
    confidence: string;
    due_at: string;
    status: InboxItem["status"];
    finished_at: string | null;
  };
  context: {
    name?: string;
    description?: string;
    scope?: { in: string; out?: string };
    analysis_period?: { start: string; end: string };
    asset?: {
      kind: string;
      name?: string;
      asset_type?: string;
      description?: string;
      members?: number;
    };
    threat_community?: { name?: string; description?: string };
    threat_effects?: string[];
    loss_event?: string;
  };
  factors: RequestFactor[];
  references: Reference[];
  answers: OwnAnswer[];
}

export const STATUS_LABELS: Record<InboxItem["status"], string> = {
  open: "Open",
  complete: "Every estimator has answered",
  closed: "Closed",
  cancelled: "Cancelled",
};

// F-004 T-13: the analyst's views.

export interface RequestItem {
  id: string;
  bu_id: string;
  scenario_id: string;
  scenario_version: number;
  title: string;
  instructions: string;
  confidence: string;
  due_at: string;
  status: InboxItem["status"];
  affected: "moved" | "archived" | "factor_changed" | null;
  cancel_reason?: string;
  created_by: string;
  created_at: string;
  ended_at: string | null;
  factors: number;
  estimators: number;
}

export interface RequestDetail {
  request: RequestItem;
  context: EstimatorView["context"];
  factors: {
    pointer: string;
    factor: string;
    unit: Unit;
    definition: string;
    accepted_version: number | null;
    accepted_at: string | null;
  }[];
  estimators: {
    user_id: string;
    added_by: string;
    added_at: string;
    removed_at: string | null;
    finished_at: string | null;
  }[];
  references: { id: string; version: number; digest: string; name: string }[];
}

export interface CalibrationSnapshot {
  class: "calibrated" | "overconfident" | "underconfident" | "not_measured";
  range_rate?: string;
  as_of: string;
}

export interface Pooled {
  Min: string;
  ML: string;
  Max: string;
  Confidence: string;
  Weights: string[];
}

export interface ReviewAnswer {
  estimator: string;
  pointer: string;
  revision: number;
  estimate: Estimate | null;
  declined: string | null;
  calibration: CalibrationSnapshot | null;
  created_at: string;
}

export interface AnswersView {
  request: RequestItem;
  estimators: {
    user_id: string;
    name: string;
    finished_at: string | null;
    removed_at: string | null;
  }[];
  factors: (RequestFactor & {
    name: string;
    answers: ReviewAnswer[];
    previews: { equal?: Pooled; calibration?: Pooled };
  })[];
}

export interface Person {
  user_id: string;
  name: string;
}

export const CLASS_LABELS: Record<CalibrationSnapshot["class"], string> = {
  calibrated: "Calibrated",
  overconfident: "Overconfident",
  underconfident: "Underconfident",
  not_measured: "Not measured",
};

export const METHOD_LABELS: Record<
  "single" | "equal" | "calibration" | "own",
  string
> = {
  single: "One answer",
  equal: "Equal-weight pool",
  calibration: "Calibration-weighted pool",
  own: "My own estimate",
};

export const AFFECTED_LABELS: Record<
  NonNullable<RequestItem["affected"]>,
  string
> = {
  moved:
    "The scenario moved to another business unit after this request was sent.",
  archived: "The scenario was archived after this request was sent.",
  factor_changed:
    "A newer version of the scenario changed what a requested factor means.",
};

/** A calibration snapshot as a short phrase. */
export function showCalibration(
  c: CalibrationSnapshot | null | undefined,
): string {
  if (!c) return "Not measured";
  const rate = c.range_rate
    ? `, ${Math.round(Number(c.range_rate) * 100)}% of ranges held the truth`
    : "";
  return `${CLASS_LABELS[c.class] ?? c.class}${rate}`;
}
