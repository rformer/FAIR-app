// The Audit API's shapes (F-002 T-12, T-13; api/openapi/audit.yaml).

export const AUDIT_API = "/api/v1/audit";

export type Integrity = "verified" | "pending" | "failed";

export interface AuditRecord {
  seq: number;
  event_id: string;
  time: string;
  received_at: string;
  producer: string;
  type: string;
  category: string;
  severity: "info" | "low" | "high" | "critical";
  actor: string;
  target: string | null;
  bu_id: string;
  request_id: string | null;
  source_ip: string | null;
  approval_id: string | null;
  skew: boolean;
  segment: number;
  integrity: Integrity;
  /** Current display names of the users the record names, by id (AC-18). */
  names: Record<string, string>;
  /** The record's body as recorded. */
  event: { reason?: string; attributes?: Record<string, string>; before?: unknown; after?: unknown; [k: string]: unknown };
}

export interface RecordPage {
  records: AuditRecord[];
  filter?: Record<string, string>;
  next_before?: number | null;
  next_after?: number | null;
}

export interface Proof {
  segment: number;
  leaf_index: number;
  tree_size: number;
  leaf_hash: string;
  path: string[];
  statement: string;
  signature: string;
}

export interface Party {
  id: string;
  name?: string;
}

export interface ApprovalEvidence {
  approval_id: string;
  kind: string | null;
  target_ref: string | null;
  status: string | null;
  requested_by: Party | null;
  decided_by: Party | null;
  request: AuditRecord | null;
  decision: AuditRecord | null;
  applied: AuditRecord | null;
  changes: AuditRecord[];
  next_after: number | null;
}

/** An evidence export (F-002 T-15, AC-32 to AC-34). */
export interface Export {
  export_id: string;
  requested_by: string;
  filter: Record<string, string>;
  format: "jsonl" | "csv";
  reason: string;
  bu_scope: string[];
  status: "pending" | "ready" | "failed";
  record_count: number | null;
  digest: string | null;
  checkpoint_segment: number | null;
  failure: string | null;
  created_at: string;
  completed_at: string | null;
}

/** The search filters (AC-15), in the order the form shows them. */
export const FILTERS = ["from", "to", "type", "category", "severity", "actor", "target", "bu", "request_id", "source_ip"] as const;
export type FilterKey = (typeof FILTERS)[number];

export const CATEGORIES = [
  "authentication",
  "session",
  "role_permission",
  "bu_restriction",
  "breakglass",
  "token",
  "scim",
  "configuration",
  "access",
  "approval",
  "service_account",
  "system",
];
export const SEVERITIES = ["info", "low", "high", "critical"];
