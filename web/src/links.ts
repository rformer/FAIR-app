// AC-44: every item links to its audit history and to its remediation or
// approval action. The audit trail's page is F-002's and approvals are
// F-001's; these are the routes those pages own (the platform shell serves
// them under the same origin).

/** The audit history of an audit target, e.g. "setting:session.idle_timeout". */
export function auditHref(target: string): string {
  return `/audit?target=${encodeURIComponent(target)}`;
}

/** The audit history of an actor (F-002 AC-16). */
export function actorHref(actor: string): string {
  return `/audit?actor=${encodeURIComponent(actor)}`;
}

/** Every visible record of one request (F-002 AC-17). */
export function requestHref(id: string): string {
  return `/audit?request=${encodeURIComponent(id)}`;
}

/** One approval's evidence in the audit trail (F-002 AC-35). */
export function evidenceHref(id: string): string {
  return `/audit?approval=${encodeURIComponent(id)}`;
}

/** One record with its proof (F-002 T-12). */
export function recordHref(seq: number): string {
  return `/audit?record=${seq}`;
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
