// F-007 T-08: the register API's shapes (api/openapi/register.yaml) and the
// risk document (internal/register, schema_version 1).

import type { AcceptanceSummary } from "../acceptance/types";
import type { Tone } from "../components";

export interface Pin {
  run_id: string;
  control_set: string;
  reason?: string;
}

export interface Link {
  scenario_id: string;
  pin?: Pin | null;
}

export interface RiskDocument {
  schema_version: 1;
  title: string;
  description?: string;
  owner: string;
  category?: string | null;
  state: "open" | "closed";
  close_reason?: string;
  scenarios: Link[];
}

export type StatusName = "current" | "stale" | "unquantified" | "computing";
export type Reason = "no_pin" | "newer_version" | "too_old" | "archived" | "exposure_unavailable";

export interface ExposureStatus {
  status: StatusName;
  reasons: { reason: Reason; scenario_id?: string }[];
}

export interface RiskHead {
  id: string;
  bu_id: string;
  state: "open" | "closed";
  title: string | null;
  owner: string | null;
  owner_name: string | null;
  category: { id: string; name: string } | null;
  current_version: number;
  created_at: string;
  created_by: string;
  seq: number;
  scenarios: number;
  exposure_aggregate_id: string | null;
  status: ExposureStatus | null;
  treatment: null | { version: number; decision: string | null; next_due: string | null; overdue: boolean };
  /** F-008: the open acceptance as the user sees it. */
  acceptance?: AcceptanceSummary | null;
}

export interface LinkView {
  scenario_id: string;
  scenario_name: string | null;
  open: boolean;
  scenario_version: number | null;
  scenario_archived: boolean;
  pin: null | {
    run_id: string;
    control_set: string;
    reason?: string;
    pinned_version: number;
    pinned_by: string | null;
    pinned_at: string | null;
    run_scenario_version: number | null;
    run_finished_at: string | null;
  };
  newer_runs: { run_id: string; scenario_version: number; finished_at: string; control_sets: string[] }[];
}

export interface Exposure {
  kind: "none" | "run" | "aggregate";
  run_id?: string;
  control_set?: string;
  aggregate_id?: string | null;
  state?: string;
  visible?: boolean;
  summary?: {
    independence?: string;
    ale: { mean: number | null; percentiles: Record<string, number | null>; p_positive?: number | null };
    curve?: { points: [number, number][] };
  };
  assumption?: string;
}

export interface RiskView {
  risk: RiskHead;
  version: { version: number; document: RiskDocument; digest: string; change_note: string; author: string; created_at: string };
  links: LinkView[];
  exposure: Exposure;
}

export interface Category {
  id: string;
  name: string;
  archived_at: string | null;
}

export interface Owner {
  user_id: string;
  name: string;
}

export interface Coverage {
  open: number;
  current: number;
  stale: number;
  unquantified: number;
  computing: number;
  current_share: number | null;
}

export const STATUS_LABEL: Record<StatusName, { label: string; tone: Tone }> = {
  current: { label: "Current", tone: "ok" },
  stale: { label: "Stale", tone: "warn" },
  unquantified: { label: "Unquantified", tone: "muted" },
  computing: { label: "Computing", tone: "info" },
};

export const REASON_LABEL: Record<Reason, string> = {
  no_pin: "a linked scenario has no pinned analysis",
  newer_version: "a pinned analysis is of an older scenario version",
  too_old: "a pinned analysis is older than the register allows",
  archived: "a linked scenario is archived",
  exposure_unavailable: "the combined exposure could not be computed; save or adopt to try again",
};

export const DECISION_LABEL: Record<string, string> = {
  mitigate: "Mitigate",
  transfer: "Transfer",
  avoid: "Avoid",
  accept: "Accept",
};
