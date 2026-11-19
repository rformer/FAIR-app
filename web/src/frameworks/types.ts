// F-013 (control frameworks): the shapes the framework API answers
// (api/openapi/framework.yaml).

export interface BaselineRef {
  id: string;
  key: string;
  title: string;
  state: "active" | "retired";
  requirements: number;
}

export interface Version {
  id: string;
  family: string;
  family_title: string;
  publisher: string | null;
  label: string;
  title: string;
  published: string | null;
  source: "shipped" | "upload";
  format: string;
  sha256: string;
  state: "active" | "retired";
  imported_at: string;
  imported_by_name: string | null;
  retired_at: string | null;
  requirements: number;
  withdrawn: number;
  baselines?: BaselineRef[];
  changes: { added: number; changed: number; withdrawn: number; since: string | null } | null;
}

export interface Family {
  key: string;
  title: string;
  publisher: string | null;
  versions: Version[];
}

export interface Requirement {
  id: string;
  version_id: string;
  identifier: string;
  label: string | null;
  title: string;
  statement?: string | null;
  parent: string | null;
  withdrawn: boolean;
  incorporated_into: string[];
  ord: number;
}

export interface RequirementView extends Requirement {
  version: Version;
  children: { id: string; identifier: string; label: string | null; title: string; withdrawn: boolean }[];
  baselines: { id: string; key: string; title: string }[];
}

export interface Baseline {
  id: string;
  version_id: string;
  family: string;
  version_label: string;
  key: string;
  title: string;
  source: "shipped" | "upload";
  sha256: string;
  state: "active" | "retired";
  requirements: number;
  notes: string[];
  imported_at: string;
  retired_at: string | null;
  selected?: string[];
}

export type Relationship = "equal" | "subset_of" | "superset_of" | "intersects";

export interface Crosswalk {
  id: string;
  title: string;
  publisher: string | null;
  label: string;
  source: "shipped" | "upload";
  sha256: string;
  state: "active" | "retired";
  imported_at: string;
  retired_at: string | null;
  source_version: { id: string; family: string; label: string };
  target_version: { id: string; family: string; label: string };
  relationships: number;
  by_relationship: Partial<Record<Relationship, number>>;
  relationship_list?: {
    source: string;
    source_id: string;
    source_title: string;
    target: string;
    target_id: string;
    target_title: string;
    relationship: Relationship;
  }[];
  more?: boolean;
}

export interface VersionDiff {
  since: string | null;
  added: string[];
  changed: string[];
  withdrawn: string[];
  renumbered: Record<string, string>;
}

export interface Problem {
  pointer: string;
  message: string;
}

export interface Import {
  id: string;
  kind: "catalog" | "profile" | "simple" | "crosswalk";
  dry_run: boolean;
  sha256: string;
  state: "queued" | "running" | "succeeded" | "refused" | "failed";
  problems: Problem[] | null;
  result: { summary?: Record<string, unknown>; diff?: VersionDiff; version_id?: string; baseline_id?: string; crosswalk_id?: string } | null;
  requested_at: string;
  finished_at: string | null;
  requested_by_name: string | null;
}

export type CoverageState = "in_place" | "not_in_place" | "partial" | "not_covered";

export interface CoveredBy {
  control_id: string;
  version: number;
  name: string;
  bu_id: string;
  strength: "full" | "partial" | "supports";
  implementation: "in_place" | "partial" | "planned" | "not_in_place" | null;
  via?: string;
  crosswalk?: string;
  relationship?: Relationship;
  reach?: "equivalent" | "partial";
}

export type Counts = Record<CoverageState, number>;

export interface Coverage {
  version: { id: string; family: string; family_title: string; label: string; title: string; state: string };
  baseline: { id: string; key: string; title: string } | null;
  bu_id: string;
  as_of: string | null;
  requirements: {
    id: string;
    identifier: string;
    label: string | null;
    title: string;
    parent: string | null;
    state: CoverageState;
    direct: CoveredBy[];
    derived: CoveredBy[];
  }[];
  counts: Counts;
  restricted: { units: number; label: string; counts: Counts } | null;
  left_out: number;
}

export interface Mapping {
  framework: string;
  version: string;
  requirement: string;
  strength: "full" | "partial" | "supports";
  rationale?: string;
}

export interface Suggestion {
  reference: number;
  framework: string;
  version: string;
  requirement: string;
  requirement_id: string;
  label: string | null;
  title: string;
}

export interface MappingUpdate {
  mapping: number;
  from: Mapping;
  to_version: string;
  to: { requirement: string; label: string | null; title: string }[];
}

export interface RequirementScenarios {
  requirement: RequirementView;
  controls: {
    id: string;
    version: number;
    bu_id: string;
    name: string;
    strength: "full" | "partial" | "supports";
    implementation: string | null;
    effects: { factor: string }[];
  }[];
  uses: { id: string; name: string; bu_id: string; version: number; sets: string[]; controls: string[] }[];
  uses_more: boolean;
  could_use: { id: string; name: string; bu_id: string; version: number }[];
  could_use_more: boolean;
}

export interface Addressed {
  version: { id: string; family: string; family_title: string; label: string };
  requirements: { id: string; identifier: string; label: string | null; title: string; controls: { id: string; name: string; strength: string }[] }[];
}

export const STATE_LABELS: Record<CoverageState, string> = {
  in_place: "Covered, every mapped control in place",
  not_in_place: "Covered, a control not in place",
  partial: "Covered partially or through a crosswalk",
  not_covered: "Not covered",
};

export const STRENGTH_LABELS: Record<string, string> = { full: "Full", partial: "Partial", supports: "Supports" };

export const RELATIONSHIP_LABELS: Record<Relationship, string> = {
  equal: "equal to",
  subset_of: "a subset of",
  superset_of: "a superset of",
  intersects: "intersecting",
};

export const IMPLEMENTATION_LABELS: Record<string, string> = {
  in_place: "In place",
  partial: "Partly in place",
  planned: "Planned",
  not_in_place: "Not in place",
};

/** The display name of a requirement: its label (e.g. "AC-2") or identifier. */
export function reqName(r: { identifier: string; label?: string | null }): string {
  return r.label || r.identifier;
}
