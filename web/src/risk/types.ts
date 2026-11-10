// F-003 T-12: the risk API's shapes (api/openapi/risk.yaml) and the scenario
// document (internal/risk/model; JSON Schema urn:fair:risk:scenario:1).

export const FORMS = ["productivity", "response", "replacement", "fines_judgments", "competitive_advantage", "reputation"] as const;
export type Form = (typeof FORMS)[number];

export const FORM_LABELS: Record<Form, string> = {
  productivity: "Productivity",
  response: "Response",
  replacement: "Replacement",
  fines_judgments: "Fines and judgments",
  competitive_advantage: "Competitive advantage",
  reputation: "Reputation",
};

export const EFFECTS = ["confidentiality", "integrity", "availability"] as const;

export type Unit = "events_per_year" | "probability" | "currency" | "percentile" | "fraction";

export const UNIT_LABELS: Record<Unit, string> = {
  events_per_year: "events per year",
  probability: "probability (0 to 1)",
  currency: "amount",
  percentile: "percentile (0 to 100)",
  fraction: "fraction (0 to 1)",
};

export interface Source {
  type: "person" | "document" | "dataset" | "integration";
  ref: string;
  note?: string;
}

export interface Estimate {
  min: string;
  ml: string;
  max: string;
  unit: Unit;
  confidence: string;
  rationale: string;
  sources: Source[];
}

export interface Pin {
  id: string;
  version: number;
}

export interface ControlUse extends Pin {
  status: "in_place" | "proposed";
}

export interface ScenarioDoc {
  kind: "scenario";
  schema_version: 1;
  name: string;
  description?: string;
  scope: { in: string; out?: string };
  analysis_period: { start: string; end: string };
  owner: string;
  asset: Pin & { kind: "asset" | "asset_group" };
  threat_community: Pin;
  threat_effects: string[];
  loss_event: string;
  lef: {
    level: "lef" | "tef_vuln";
    estimate?: Estimate;
    tef?: { level: "tef" | "cf_poa"; estimate?: Estimate; contact_frequency?: Estimate; probability_of_action?: Estimate };
    vulnerability?: {
      level: "direct" | "derived";
      estimate?: Estimate;
      threat_capability?: { source: "threat_community" | "scenario"; estimate?: Estimate };
      resistance_strength?: Estimate;
    };
  };
  primary_loss: Partial<Record<Form, Estimate>>;
  secondary_risk?: { stakeholder: string; slef: Estimate; loss: Partial<Record<Form, Estimate>> }[];
  control_sets: { name: string; current: boolean; controls: ControlUse[] }[];
}

export interface Head {
  id: string;
  bu_id: string;
  kind: string;
  name: string | null;
  owner?: string | null;
  current_version: number;
  archived_at: string | null;
  created_at: string;
  created_by: string;
  inherited: boolean;
}

export interface Version {
  version: number;
  digest: string;
  author: string;
  created_at: string;
  change_note: string;
  document?: ScenarioDoc;
}

export interface PinItem {
  pointer: string;
  kind: string;
  id: string;
  version: number;
  digest: string;
  current_version: number | null;
  newer: boolean;
  member_of?: string;
  reachable?: boolean;
}

export interface TaxonomyNode {
  factor: string;
  parent?: string;
  status: "entered" | "derived" | "library" | "not_used";
  pointer?: string;
}

export interface ScenarioView {
  scenario: Head;
  version: Version;
  pins: PinItem[];
  taxonomy: TaxonomyNode[];
  currency: string | null;
}

export interface Change {
  pointer: string;
  op: "added" | "removed" | "changed";
  from?: unknown;
  to?: unknown;
}

export interface DiffView {
  id: string;
  from: number;
  to: number;
  changes: Change[];
  pins: { pointer: string; kind: string; from_id?: string; from_version?: number; to_id?: string; to_version?: number }[];
}

export interface BU {
  id: string;
  code: string;
  name: string;
}

export interface Problem {
  pointer: string;
  message: string;
}

/** Factor names as people read them. */
export function factorLabel(factor: string): string {
  const base: Record<string, string> = {
    risk: "Risk",
    loss_event_frequency: "Loss event frequency",
    threat_event_frequency: "Threat event frequency",
    contact_frequency: "Contact frequency",
    probability_of_action: "Probability of action",
    vulnerability: "Vulnerability",
    threat_capability: "Threat capability",
    resistance_strength: "Resistance strength",
    loss_magnitude: "Loss magnitude",
    primary_loss: "Primary loss",
    secondary_risk: "Secondary risk",
  };
  if (base[factor]) return base[factor];
  const m = /^primary_loss\.(\w+)$/.exec(factor);
  if (m) return FORM_LABELS[m[1] as Form] ?? m[1];
  const s = /^secondary_risk\.(\d+)(?:\.(slef|loss\.(\w+)))?$/.exec(factor);
  if (s) {
    if (!s[2]) return `Stakeholder group ${Number(s[1]) + 1}`;
    if (s[2] === "slef") return "Secondary loss event frequency";
    return FORM_LABELS[s[3] as Form] ?? s[3];
  }
  return factor;
}

/** An estimate as one line: "2 – 6 – 12 events per year (90%)". */
export function showEstimate(e: Estimate | undefined, currency: string | null): string {
  if (!e) return "—";
  const unit = e.unit === "currency" ? (currency ?? "amount") : UNIT_LABELS[e.unit];
  const conf = Math.round(Number(e.confidence) * 100);
  return `${e.min} – ${e.ml} – ${e.max} ${unit} (${conf}% confidence)`;
}

/** The value at a JSON pointer, or undefined. */
export function at(doc: unknown, pointer: string): unknown {
  let cur: unknown = doc;
  for (const part of pointer.split("/").slice(1)) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[part.replace(/~1/g, "/").replace(/~0/g, "~")];
  }
  return cur;
}

// F-003 T-13: library entries and controls.

export const LIBRARY_KINDS = ["asset", "asset_group", "threat_community", "loss_profile", "reference_class"] as const;
export type LibraryKind = (typeof LIBRARY_KINDS)[number];

export const KIND_LABELS: Record<LibraryKind | "control", string> = {
  asset: "Asset",
  asset_group: "Asset group",
  threat_community: "Threat community",
  loss_profile: "Loss profile",
  control: "Control",
  reference_class: "Reference class",
};

export interface AssetDoc {
  kind: "asset";
  schema_version: 1;
  name: string;
  asset_type: string;
  description?: string;
  value?: Estimate;
  value_basis?: string;
}

export interface AssetGroupDoc {
  kind: "asset_group";
  schema_version: 1;
  name: string;
  description?: string;
  members: Pin[];
  valuation: "whole" | "members";
  value?: Estimate;
}

export interface ThreatCommunityDoc {
  kind: "threat_community";
  schema_version: 1;
  name: string;
  description?: string;
  threat_capability: Estimate;
}

export interface LossProfileDoc {
  kind: "loss_profile";
  schema_version: 1;
  name: string;
  description?: string;
  magnitudes: Partial<Record<Form, Estimate>>;
}

export const FACTORS = [
  "contact_frequency",
  "probability_of_action",
  "threat_capability",
  "resistance_strength",
  ...FORMS.map((f) => `loss.${f}`),
] as const;

export interface Effect {
  factor: string;
  estimate: Estimate;
}

export interface ControlDoc {
  kind: "control";
  schema_version: 1;
  name: string;
  description?: string;
  references?: { framework: string; identifier: string }[];
  effects: Effect[];
}

// F-004 T-03, T-13: reference classes, the customer's own data (AC-13).
export interface ReferenceClassDoc {
  kind: "reference_class";
  schema_version: 1;
  name: string;
  description?: string;
  period: { start: string; end: string };
  data: { kind: "counts"; series: { start: string; end: string; count: number }[] } | { kind: "losses"; unit: "currency"; amounts: string[] };
  sources: { type: string; ref: string; note?: string }[];
}

export type EntryDoc = AssetDoc | AssetGroupDoc | ThreatCommunityDoc | LossProfileDoc | ControlDoc | ReferenceClassDoc;

export interface EntryView {
  entry?: Head;
  control?: Head;
  version: Omit<Version, "document"> & { document?: EntryDoc };
  pins?: PinItem[];
  currency: string | null;
}

export interface StarterEntry {
  key: string;
  release: string;
  kind: Exclude<LibraryKind, "reference_class">;
  name: string;
  illustrative: boolean;
  guidance: string;
  digest: string;
  document: EntryDoc;
}

/** The unit a control's effect on a factor is estimated in. */
export function effectUnit(factor: string): Unit {
  return factor === "resistance_strength" ? "percentile" : "fraction";
}

export function factorName(factor: string): string {
  if (factor.startsWith("loss.")) return `${FORM_LABELS[factor.slice(5) as Form] ?? factor.slice(5)} loss`;
  return factorLabel(factor);
}
