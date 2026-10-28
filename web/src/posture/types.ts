// Response shapes of the Posture API (api/openapi/posture.yaml).

export const API = "/api/v1/posture";

export type Json = unknown;

export interface RegistryEntry {
  key: string;
  type: string;
  direction: string;
  bu_scopable: boolean;
  owner_feature: string;
  params: string[];
  controls: string[];
  value: Json;
  source: string;
  profile_default: Json;
  bound: Json;
  deviation: "in_bounds" | "exception" | "out_of_bounds" | "below_floor" | "unbound";
  exception_id?: string;
  exception_expires?: string;
}

export interface Profile {
  id: string;
  version: string;
  name: string;
  family: string;
  kind: string;
  status: string;
  label_deviates: boolean;
  active: boolean;
  base_profile_id?: string;
  base_version?: string;
}

export interface ExceptionRow {
  exception_id: string;
  key: string;
  bu_id?: string;
  overlay: boolean;
  value: Json;
  bound_at_creation: Json;
  justification: string;
  owner_id: string;
  approved_by: string;
  created_at: string;
  expires_at: string;
  renewed_from?: string;
  state: string;
}

export interface Conflict {
  conflict_id: string;
  key: string;
  bu_id?: string;
  current: Json;
  new_bound: Json;
  below_floor: boolean;
  resolution: string;
}

export interface PendingSwitch {
  switch_id: string;
  from: string;
  target: string;
  loosening: boolean;
  approval_id: string;
  unresolved: number;
  conflicts: Conflict[];
}

export interface Finding {
  finding_id: string;
  kind: string;
  check_id: string;
  severity: string;
  controls: string[];
  subject: string;
  detail: Json;
  remediation: string;
  status: string;
  first_seen: string;
  last_seen: string;
  acknowledged_by?: string;
  acknowledged_at?: string;
  acknowledge_reason?: string;
  resolved_at?: string;
}

export interface CheckAssessment {
  check_id: string;
  title: string;
  controls: string[];
  assessed: boolean;
  reason?: string;
}

export interface K8sAccess {
  state: string;
  permissions_digest: string | null;
  current_permissions_digest: string;
  decided_by: string | null;
  decided_at: string | null;
  reason: string | null;
  deployment_mode: string;
  last_report: string | null;
  warning: string;
  checks: CheckAssessment[];
}
