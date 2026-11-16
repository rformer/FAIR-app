// F-008 T-07: the acceptance API's shapes (api/openapi/acceptance.yaml).

import type { Tone } from "../components";

export type State = "pending" | "active" | "suspended" | "expired" | "ended";
export type ReviewReason = "stale" | "treatment" | "moved";
export type EndReason = "rejected" | "withdrawn" | "revoked" | "replaced" | "risk_closed";

export interface Acceptance {
  id: string;
  bu_id: string;
  risk_id: string;
  risk_title: string | null;
  renews: string | null;
  state: State;
  stored_state: string;
  end_reason: EndReason | null;
  tier: number;
  tier_bu_id: string;
  approvals_needed: number;
  approvals: number;
  mean: number;
  expires_on: string;
  approved_bu_id: string | null;
  requested_by: string;
  requested_by_name?: string | null;
  requested_at: string;
  activated_at: string | null;
  ended_at: string | null;
  seq: number;
  needs_review: ReviewReason[] | null;
}

export interface Step {
  n: number;
  kind: string;
  actor: string | null;
  at: string;
  reason: string | null;
  data: Record<string, unknown>;
}

export interface Evidence {
  justification?: string;
  conditions?: string;
  exposure?: { status?: string; mean?: number | null; p90?: number | null };
  pins?: { scenario_id: string; run_id: string; control_set: string }[];
  tier?: { n: number; approvals: number; levels_up: number | null; bu_id?: string };
}

export interface AcceptanceView extends Acceptance {
  steps: Step[];
  evidence?: Evidence;
  names: Record<string, string>;
  may_decide: boolean;
  may_withdraw: boolean;
  may_revoke: boolean;
  may_renew: boolean;
}

export interface Tier {
  tier: number;
  max_mean: number | null;
  levels_up: number | null;
  root: boolean;
  approvals: number;
}

/** A risk's open acceptance as the register shows it. */
export interface AcceptanceSummary {
  id: string;
  state: Exclude<State, "ended">;
  expires_on: string;
  tier: number;
  renewal_pending: boolean;
  needs_review: ReviewReason[];
}

export const STATE_LABEL: Record<State, { label: string; tone: Tone }> = {
  pending: { label: "Pending approval", tone: "info" },
  active: { label: "Accepted", tone: "ok" },
  suspended: { label: "Suspended", tone: "warn" },
  expired: { label: "Expired", tone: "bad" },
  ended: { label: "Ended", tone: "muted" },
};

export const REVIEW_LABEL: Record<ReviewReason, string> = {
  stale: "the risk's exposure is no longer current",
  treatment: "the risk's treatment decision is no longer accept",
  moved: "the risk moved to another business unit since it was approved",
};

export const END_LABEL: Record<EndReason, string> = {
  rejected: "Rejected",
  withdrawn: "Withdrawn",
  revoked: "Revoked",
  replaced: "Replaced by its renewal",
  risk_closed: "The risk was closed",
};

export const STEP_LABEL: Record<string, string> = {
  requested: "Requested",
  approved: "Approved",
  rejected: "Rejected",
  withdrawn: "Withdrawn",
  activated: "Accepted",
  suspended: "Suspended",
  review_requested: "Review opened",
  reactivated: "Reactivated",
  revoked: "Revoked",
  expired: "Expired",
  replaced: "Replaced",
  ended: "Ended",
};

/** Why the API refused, in words (its error codes). */
export const REFUSAL: Record<string, string> = {
  not_your_tier: "You do not hold acceptance approval at this acceptance's tier.",
  separation_of_duties: "The requester and the risk's owner cannot decide their own acceptance.",
  already_decided: "You have already decided this acceptance in this round.",
  not_pending: "This acceptance is no longer waiting for a decision.",
  not_active: "This acceptance is not in force.",
  exposure_not_current: "The risk's exposure is not current: update its analyses first.",
  not_accept: "The risk's treatment decision is not accept.",
  pending_exists: "A request for this risk is already pending.",
  already_accepted: "This risk is already accepted; renew the acceptance instead.",
  not_renewable: "Only an acceptance in force can be renewed, once at a time.",
  risk_closed: "The risk is closed.",
};

export function tierLabel(n: number): string {
  return `Tier ${n}`;
}
