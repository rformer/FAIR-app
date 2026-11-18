// F-011 T-18: the shapes of the integrations API (api/openapi/integrate.yaml)
// and the imports API (api/openapi/import.yaml) the pages read.

export type InputKind = "assets" | "loss_events" | "risks" | "control_status";
export type Delivery = "push" | "file" | "connector";

export interface Connector {
  type: "http_json" | "servicenow_cmdb";
  source: string;
  schedule_minutes: number;
  settings?: Record<string, unknown>;
}

export interface Integration {
  id: string;
  bu_id: string;
  bu_name?: string;
  name: string;
  kind: InputKind;
  delivery: Delivery;
  mapping: Record<string, unknown>;
  connector: Connector | null;
  service_account_id: string | null;
  service_account_name: string | null;
  auto_accept: boolean;
  state: "active" | "paused" | "deleted";
  version: number;
  created_at: string;
  changed_at: string | null;
  deleted_at: string | null;
  next_run_at: string | null;
  last_run_at: string | null;
  run_requested_at: string | null;
  failures: number;
  last_failure?: string | null;
  credentials: { purpose: "source" | "client"; set_at: string }[];
}

export interface Counts {
  received?: number;
  valid?: number;
  refused?: number;
  new?: number;
  changed?: number;
  unchanged?: number;
  proposed?: number;
  applied?: number;
}

export interface Refusal {
  n: number;
  external_id?: string;
  column?: string;
  pointer: string;
  message: string;
}

export interface Run {
  id: string;
  integration_id: string;
  integration_name?: string;
  bu_id?: string;
  trigger: "push" | "upload" | "schedule" | "manual";
  actor: string | null;
  actor_name: string | null;
  complete: boolean;
  state: "running" | "succeeded" | "failed";
  counts: Counts | null;
  refusals?: Refusal[];
  failure: string | null;
  started_at: string;
  finished_at: string | null;
}

export type TargetType = "asset" | "asset_group" | "control" | "risk" | "reference_class";

export interface Proposal {
  id: string;
  integration_id: string | null;
  integration_name?: string;
  run_id: string | null;
  run_started_at?: string;
  derivation_id?: string | null;
  bu_id: string;
  bu_name?: string;
  target_type: TargetType;
  target_id: string | null;
  external_id: string | null;
  action: "create" | "update" | "archive";
  record: Record<string, unknown> | null;
  descriptive_only: boolean;
  state: "pending" | "accepted" | "rejected" | "superseded";
  decided_by_name: string | null;
  decided_at: string | null;
  reason: string | null;
  created_at: string;
}

export interface ProposalView extends Proposal {
  current: { version: number; document: Record<string, unknown>; archived: boolean } | null;
  proposed: Record<string, unknown> | null;
  diff: { changes: { pointer: string; op: "added" | "removed" | "changed"; from?: unknown; to?: unknown }[] } | null;
  problems: { pointer: string; message: string }[];
}

export const KIND_LABEL: Record<InputKind, string> = {
  assets: "Assets and asset groups",
  loss_events: "Loss events",
  risks: "Risks",
  control_status: "Control status",
};

export const DELIVERY_LABEL: Record<Delivery, string> = {
  push: "Pushed to the API",
  file: "Uploaded as files",
  connector: "Pulled by a connector",
};

export const TARGET_LABEL: Record<TargetType, string> = {
  asset: "Asset",
  asset_group: "Asset group",
  control: "Control",
  risk: "Risk",
  reference_class: "Reference class",
};

export const ACTION_LABEL: Record<Proposal["action"], string> = { create: "Create", update: "Update", archive: "Archive" };

export const TRIGGER_LABEL: Record<Run["trigger"], string> = {
  push: "Pushed",
  upload: "Uploaded",
  schedule: "Scheduled",
  manual: "Run on request",
};

/** Where a proposal's record lives once accepted (its page). */
export function targetHref(p: Pick<Proposal, "target_type" | "target_id">): string | null {
  if (!p.target_id) return null;
  switch (p.target_type) {
    case "control":
      return `/controls/${p.target_id}`;
    case "risk":
      return `/register/risks/${p.target_id}`;
    default:
      return `/library/${p.target_id}`;
  }
}

export function dateTime(s: string | null | undefined): string {
  if (!s) return "—";
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? s : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
