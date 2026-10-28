import type { Tone } from "../components";
import type { CheckAssessment, Finding, RegistryEntry } from "./types";

export interface ControlRow {
  control: string;
  status: string;
  tone: Tone;
  settings: string[];
  checks: string[];
  findings: number;
}

/** "AC-2(3)" sorts after "AC-2" and before "AC-11". */
function controlKey(c: string): [string, number, number] {
  const m = /^([A-Z]{2})-(\d+)(?:\((\d+)\))?/.exec(c);
  return m ? [m[1] ?? "", Number(m[2]), m[3] ? Number(m[3]) : 0] : [c, 0, 0];
}

/**
 * Per-control status (AC-43) from the settings that implement a control,
 * the deployment checks that assess it and the open findings against it.
 * Worst first: a setting below the floor or out of bounds, or an open
 * finding, then an exception, then not assessed, then OK.
 */
export function controlStatuses(settings: RegistryEntry[], findings: Finding[], checks: CheckAssessment[]): ControlRow[] {
  const rows = new Map<string, ControlRow & { rank: number }>();
  const row = (c: string) => {
    let r = rows.get(c);
    if (!r) {
      r = { control: c, status: "OK", tone: "ok", settings: [], checks: [], findings: 0, rank: 0 };
      rows.set(c, r);
    }
    return r;
  };
  const raise = (r: ControlRow & { rank: number }, rank: number, status: string, tone: Tone) => {
    if (rank > r.rank) Object.assign(r, { rank, status, tone });
  };
  for (const s of settings) {
    for (const c of s.controls ?? []) {
      const r = row(c);
      r.settings.push(s.key);
      if (s.deviation === "below_floor" || s.deviation === "out_of_bounds") raise(r, 4, "Deviation", "bad");
      else if (s.deviation === "exception") raise(r, 2, "Exception", "warn");
    }
  }
  for (const ch of checks) {
    for (const c of ch.controls ?? []) {
      const r = row(c);
      r.checks.push(ch.title);
      if (!ch.assessed) raise(r, 1, "Not assessed", "muted");
    }
  }
  for (const f of findings) {
    if (f.status === "resolved") continue;
    for (const c of f.controls ?? []) {
      const r = row(c);
      r.findings++;
      raise(r, 3, "Open finding", "bad");
    }
  }
  return [...rows.values()]
    .map(({ rank: _rank, ...r }) => r)
    .sort((a, b) => {
      const [x, y] = [controlKey(a.control), controlKey(b.control)];
      return x[0].localeCompare(y[0]) || x[1] - y[1] || x[2] - y[2];
    });
}
