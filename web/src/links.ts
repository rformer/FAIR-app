// AC-44: every item links to its audit history and to its remediation or
// approval action. The audit trail's page is F-002's and approvals are
// F-001's; these are the routes those pages own (the platform shell serves
// them under the same origin).

/** The audit history of an audit target, e.g. "setting:session.idle_timeout". */
export function auditHref(target: string): string {
  return `/audit?target=${encodeURIComponent(target)}`;
}

/** An approval request in the F-001 approvals inbox. */
export function approvalHref(id: string): string {
  return `/approvals/${encodeURIComponent(id)}`;
}

/** Durations and values as the API returns them, for display. */
export function show(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return v;
  return JSON.stringify(v);
}

export function date(s: string | null | undefined): string {
  if (!s) return "—";
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? s : d.toISOString().slice(0, 10);
}

export function daysUntil(s: string, now: Date = new Date()): number {
  return Math.ceil((new Date(s).getTime() - now.getTime()) / 86_400_000);
}
