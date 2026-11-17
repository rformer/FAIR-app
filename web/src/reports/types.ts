// F-010 T-17: the reports API's shapes (api/openapi/report.yaml) and the
// kinds' parameters (design §3.4).

import type { Tone } from "../components";

export type Format = "pdf" | "csv" | "json";
export type KindName = "register" | "portfolio" | "acceptances" | "treatment" | "risk";
export type RunState = "queued" | "running" | "succeeded" | "failed";

export interface ReportFile {
  format: Format;
  size: number;
  sha256: string;
  created_at?: string;
  purged: boolean;
}

export interface Report {
  id: string;
  kind: KindName;
  bu_id: string;
  bu_name: string | null;
  params: Record<string, unknown>;
  formats: Format[];
  reason: string | null;
  schedule_id: string | null;
  state: RunState;
  progress: number;
  attempts?: number;
  data_as_of: string | null;
  risk_count: number | null;
  left_out: Record<string, number> | null;
  failure: string | null;
  requested_at: string;
  started_at: string | null;
  finished_at: string | null;
  files: ReportFile[];
}

export interface Schedule {
  id: string;
  kind: KindName;
  bu_id: string;
  bu_name: string | null;
  params: Record<string, unknown>;
  formats: Format[];
  cadence: "daily" | "weekly" | "monthly";
  weekday: number | null;
  monthday: number | null;
  hour: number;
  reason: string | null;
  next_at: string;
  state: "active" | "suspended";
  suspended_reason: "inactive" | "no_permission" | null;
  version: number;
  created_at?: string;
  last_run: null | { id: string; state: RunState; requested_at: string };
}

export interface KindInfo {
  kind: KindName;
  title: string;
  formats: Format[];
}

export interface Kinds {
  kinds: KindInfo[];
  limits: { risks: number; running: number; file_bytes: number };
}

export const KIND_LABEL: Record<KindName, string> = {
  register: "Risk register",
  portfolio: "Portfolio",
  acceptances: "Acceptances",
  treatment: "Treatment",
  risk: "Risk",
};

export const KIND_INTRO: Record<KindName, string> = {
  register: "Each open risk with its owner, category, exposure and its status, treatment decision, and acceptance state and expiry, with totals.",
  portfolio: "The dashboard as a document: the roll-up's distribution and curve, the largest risks, the business units below, coverage, acceptances, treatment, and the trend over a period.",
  acceptances: "Acceptances by state, those expiring soon, and the decisions in a period with their tier, approvers and reasons.",
  treatment: "Treatment actions by due date and owner, overdue ones first, with each risk's decision.",
  risk: "One risk: its description, each linked scenario's pinned results with curve, distribution and drivers, the estimates' provenance, its treatment and its acceptance history.",
};

export const FORMAT_LABEL: Record<Format, string> = {
  pdf: "PDF (tagged, for reading and filing)",
  csv: "CSV (a ZIP of tables)",
  json: "JSON (fair.report.v1)",
};

export const FILE_NAME: Record<Format, string> = { pdf: "report.pdf", csv: "report-csv.zip", json: "report.json" };

export const STATE: Record<RunState, { label: string; tone: Tone }> = {
  queued: { label: "Queued", tone: "info" },
  running: { label: "Generating", tone: "info" },
  succeeded: { label: "Ready", tone: "ok" },
  failed: { label: "Failed", tone: "bad" },
};

export const FAILURE: Record<string, string> = {
  no_permission: "You no longer held report.export at the business unit when it was generated.",
  limit_exceeded: "The report exceeded a limit.",
  unknown_kind: "This installation does not generate this kind of report.",
  invalid_document: "The report could not be built.",
  generation_failed: "Generating the report failed; request it again.",
};

/** A failure's text: the code's sentence, then the detail the service gave. */
export function failureText(f: string | null): string {
  if (!f) return "";
  const [code, ...rest] = f.split(":");
  const detail = rest.join(":").trim();
  const base = FAILURE[code ?? ""] ?? code ?? "";
  return detail && code !== "generation_failed" ? `${base} ${detail.charAt(0).toUpperCase()}${detail.slice(1)}.` : base;
}

const LEFT_OUT: Record<string, string> = {
  not_visible: "risks not visible to the requester",
  restricted: "risks in restricted business units, by their roll-up mode",
  unquantified: "risks without a quantified analysis",
  stale: "risks with a stale analysis",
  units_not_visible: "business units not visible (or restricted and excluded from roll-ups), whose records are left out",
  units_aggregate_only: "restricted business units shown as totals only, whose records are left out",
};

/** What a dashboard or report leaves out, and why (AC-04, AC-11), in words. */
export function leftOutText(m: Record<string, number> | null | undefined): string[] {
  return Object.entries(m ?? {})
    .filter(([, n]) => n > 0)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, n]) => `${n} ${LEFT_OUT[k] ?? k.replace(/_/g, " ")}`);
}

export const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

/** When a schedule runs, in words (UTC). */
export function cadenceText(s: Pick<Schedule, "cadence" | "weekday" | "monthday" | "hour">): string {
  const at = `${String(s.hour).padStart(2, "0")}:00 UTC`;
  if (s.cadence === "weekly") return `Every ${WEEKDAYS[s.weekday ?? 0]} at ${at}`;
  if (s.cadence === "monthly") return `On day ${s.monthday ?? 1} of every month at ${at}`;
  return `Every day at ${at}`;
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(1)} MiB`;
}

export function dateTime(s: string | null | undefined): string {
  if (!s) return "—";
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? s : `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/** The filters a report was made with, in words. */
export function paramsText(kind: KindName, p: Record<string, unknown>, names: { owner?: (id: string) => string } = {}): string {
  const parts: string[] = [];
  const v = (k: string) => (p[k] === undefined || p[k] === null || p[k] === "" ? undefined : String(p[k]));
  if (kind === "register") {
    if (v("status")) parts.push(`exposure ${v("status")}`);
    if (v("decision")) parts.push(`decision ${v("decision")}`);
    if (v("acceptance")) parts.push(`acceptance ${String(v("acceptance")).replace("_", " ")}`);
    if (v("owner")) parts.push(`owner ${names.owner ? names.owner(v("owner") ?? "") : v("owner")}`);
    if (v("category")) parts.push("one category");
  } else if (kind === "portfolio") {
    parts.push(`trend over ${v("period_days") ?? "365"} days`);
  } else if (kind === "acceptances") {
    if (v("expiring_within")) parts.push(`expiring within ${v("expiring_within")} days`);
    if (v("decided_from") || v("decided_to")) parts.push(`decisions ${v("decided_from") ?? "…"} to ${v("decided_to") ?? "today"}`);
  } else if (kind === "treatment") {
    if (v("owner")) parts.push("one action owner");
  } else if (kind === "risk") {
    parts.push("one risk");
  }
  return parts.length ? parts.join("; ") : "no filters";
}
