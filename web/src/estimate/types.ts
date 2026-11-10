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
    data: { kind: "counts"; series: { start: string; end: string; count: number }[] } | { kind: "losses"; unit: "currency"; amounts: string[] };
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
    asset?: { kind: string; name?: string; asset_type?: string; description?: string; members?: number };
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
