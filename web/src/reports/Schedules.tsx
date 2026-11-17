import { useEffect, useState } from "react";
import { describe, send } from "../api";
import { Badge, ReasonAction, Section, Status, useApi } from "../components";
import { auditHref } from "../links";
import { withReason } from "../reason";
import { useReportBUs } from "./Dashboard";
import { FormatChoice, paramsOf, ParamsFields, StateBadge, type ParamValues } from "./Reports";
import { cadenceText, dateTime, KIND_INTRO, KIND_LABEL, paramsText, WEEKDAYS, type Format, type KindName, type Kinds, type Schedule } from "./types";

// F-010 T-17 (F-010-AC-19 to AC-21; design §3.7): a person's scheduled
// reports. Each runs as its owner sees the data when it falls due, and
// notifies the owner alone (a report.ready notice linking to the report;
// the file is never mailed). A schedule is suspended when its owner no
// longer holds report.export at its business unit, and resumed by them.

const SUSPENDED: Record<string, string> = {
  inactive: "its owner's account was inactive when it fell due",
  no_permission: "its owner no longer held report.export at its business unit when it fell due",
};

interface Draft {
  params: ParamValues;
  formats: Format[];
  cadence: Schedule["cadence"];
  weekday: string;
  monthday: string;
  hour: string;
  reason: string;
}

function draftOf(s?: Schedule): Draft {
  if (!s) return { params: {}, formats: ["pdf"], cadence: "weekly", weekday: "1", monthday: "1", hour: "6", reason: "" };
  return {
    params: Object.fromEntries(Object.entries(s.params ?? {}).map(([k, v]) => [k, String(v)])),
    formats: s.formats,
    cadence: s.cadence,
    weekday: String(s.weekday ?? 1),
    monthday: String(s.monthday ?? 1),
    hour: String(s.hour),
    reason: s.reason ?? "",
  };
}

function bodyOf(kind: KindName, d: Draft, asked?: string) {
  return {
    params: paramsOf(kind, d.params),
    formats: d.formats,
    cadence: d.cadence,
    weekday: d.cadence === "weekly" ? Number(d.weekday) : null,
    monthday: d.cadence === "monthly" ? Number(d.monthday) : null,
    hour: Number(d.hour),
    reason: asked ?? d.reason.trim(),
  };
}

/** When and how a schedule runs: cadence, day, hour (UTC), formats and reason. */
function WhenFields({ d, set }: { d: Draft; set: (d: Draft) => void }) {
  return (
    <>
      <div className="field">
        <label htmlFor="s-cadence">Every</label>
        <select id="s-cadence" value={d.cadence} onChange={(e) => set({ ...d, cadence: e.target.value as Draft["cadence"] })}>
          <option value="daily">Day</option>
          <option value="weekly">Week</option>
          <option value="monthly">Month</option>
        </select>
      </div>
      {d.cadence === "weekly" ? (
        <div className="field">
          <label htmlFor="s-weekday">On</label>
          <select id="s-weekday" value={d.weekday} onChange={(e) => set({ ...d, weekday: e.target.value })}>
            {WEEKDAYS.map((w, i) => (
              <option key={w} value={String(i)}>
                {w}
              </option>
            ))}
          </select>
        </div>
      ) : null}
      {d.cadence === "monthly" ? (
        <div className="field">
          <label htmlFor="s-monthday">On day</label>
          <select id="s-monthday" value={d.monthday} onChange={(e) => set({ ...d, monthday: e.target.value })}>
            {Array.from({ length: 28 }, (_, i) => String(i + 1)).map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </div>
      ) : null}
      <div className="field">
        <label htmlFor="s-hour">At (UTC)</label>
        <select id="s-hour" value={d.hour} onChange={(e) => set({ ...d, hour: e.target.value })}>
          {Array.from({ length: 24 }, (_, i) => String(i)).map((h) => (
            <option key={h} value={h}>
              {h.padStart(2, "0")}:00
            </option>
          ))}
        </select>
      </div>
      <FormatChoice value={d.formats} onChange={(formats) => set({ ...d, formats })} />
      <div className="field wide">
        <label htmlFor="s-reason">Reason</label>
        <textarea id="s-reason" rows={2} maxLength={500} value={d.reason} onChange={(e) => set({ ...d, reason: e.target.value })} aria-describedby="s-reason-hint" />
        <p id="s-reason-hint" className="muted">
          Required where the data's business units ask every export for a reason; each scheduled report carries it.
        </p>
      </div>
    </>
  );
}

export function SchedulesPage() {
  const list = useApi<{ schedules: Schedule[] }>("/api/v1/reports/schedules");
  useEffect(() => {
    document.title = "Scheduled reports · Reports · FAIR Risk Platform";
  }, []);
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/reports">Portfolio dashboard</a> / <a href="/reports/mine">My reports</a>
      </nav>
      <h1>Scheduled reports</h1>
      <p className="lede">Reports generated for you on a schedule, as you can see the data each time. When one is ready you get a notice that links to it; files are never mailed.</p>
      <p className="actions">
        <a className="react-aria-Button primary" href="/reports/schedules/new">
          Schedule a report
        </a>
      </p>
      <Section id="schedules" title="Your schedules">
        <Status loaded={list}>
          {(d) =>
            d.schedules.length === 0 ? (
              <p>You have no scheduled reports.</p>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <caption className="sr-only">Your scheduled reports</caption>
                  <thead>
                    <tr>
                      <th scope="col">Report</th>
                      <th scope="col">Business unit</th>
                      <th scope="col">When</th>
                      <th scope="col">Next</th>
                      <th scope="col">State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.schedules.map((s) => (
                      <tr key={s.id}>
                        <td>
                          <a href={`/reports/schedules/${s.id}`}>{KIND_LABEL[s.kind]}</a>
                        </td>
                        <td>{s.bu_name ?? "—"}</td>
                        <td>{cadenceText(s)}</td>
                        <td>{s.state === "active" ? dateTime(s.next_at) : "—"}</td>
                        <td>{s.state === "active" ? <Badge tone="ok">Active</Badge> : <Badge tone="warn">Suspended</Badge>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          }
        </Status>
      </Section>
    </>
  );
}

export function NewSchedulePage({ search = window.location.search }: { search?: string }) {
  const q = new URLSearchParams(search);
  const kinds = useApi<Kinds>("/api/v1/reports/kinds");
  const bus = useReportBUs("report.export");
  const [kind, setKind] = useState<KindName>((q.get("kind") as KindName | null) ?? "register");
  const [bu, setBu] = useState(q.get("bu") ?? "");
  const [d, setD] = useState<Draft>(() => draftOf());
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    document.title = "Schedule a report · Reports · FAIR Risk Platform";
  }, []);
  useEffect(() => {
    if (bus.data && !bus.data.bus.some((b) => b.id === bu) && bus.data.bus[0]) setBu(bus.data.bus[0].id);
  }, [bu, bus.data]);
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/reports">Portfolio dashboard</a> / <a href="/reports/schedules">Scheduled reports</a>
      </nav>
      <h1>Schedule a report</h1>
      <p className="lede">For you alone: others schedule their own, so no one receives data they cannot see.</p>
      <Status loaded={bus}>
        {(b) =>
          b.bus.length === 0 ? (
            <p>Scheduling reports needs report.export, which you do not hold at any business unit.</p>
          ) : (
            <Section id="schedule" title="The schedule">
              <form
                className="filters"
                aria-label="The report to schedule"
                onSubmit={async (e) => {
                  e.preventDefault();
                  setError(undefined);
                  if (d.formats.length === 0) {
                    setError("Choose at least one format.");
                    return;
                  }
                  setBusy(true);
                  try {
                    const s = await withReason((asked) => send<Schedule>("POST", "/api/v1/reports/schedules", { kind, bu_id: bu, ...bodyOf(kind, d, asked) }));
                    window.location.assign(`/reports/schedules/${s.id}`);
                  } catch (err) {
                    setError(describe(err));
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                <div className="field">
                  <label htmlFor="s-kind">Report</label>
                  <select
                    id="s-kind"
                    value={kind}
                    onChange={(e) => {
                      setKind(e.target.value as KindName);
                      setD({ ...d, params: {} });
                    }}
                  >
                    {(kinds.data?.kinds ?? []).map((k) => (
                      <option key={k.kind} value={k.kind}>
                        {KIND_LABEL[k.kind] ?? k.title}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="field">
                  <label htmlFor="s-bu">Business unit (with everything below it)</label>
                  <select id="s-bu" value={bu} onChange={(e) => setBu(e.target.value)}>
                    {b.bus.map((x) => (
                      <option key={x.id} value={x.id}>
                        {x.name}
                      </option>
                    ))}
                  </select>
                </div>
                <p className="muted wide">{KIND_INTRO[kind]}</p>
                <ParamsFields kind={kind} bu={bu} value={d.params} onChange={(params) => setD({ ...d, params })} idPrefix="s" />
                <WhenFields d={d} set={setD} />
                {error ? (
                  <p role="alert" className="error-text">
                    {error}
                  </p>
                ) : null}
                <div className="actions">
                  <button className="react-aria-Button primary" type="submit" disabled={busy || !bu}>
                    Schedule
                  </button>
                </div>
              </form>
            </Section>
          )
        }
      </Status>
    </>
  );
}

export function SchedulePage({ id }: { id: string }) {
  const s = useApi<Schedule>(`/api/v1/reports/schedules/${id}`);
  const [editing, setEditing] = useState(false);
  const [d, setD] = useState<Draft>(() => draftOf());
  const [error, setError] = useState<string>();
  const [done, setDone] = useState<string>();
  useEffect(() => {
    if (s.data) document.title = `${KIND_LABEL[s.data.kind]} schedule · Reports · FAIR Risk Platform`;
  }, [s.data]);
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/reports">Portfolio dashboard</a> / <a href="/reports/schedules">Scheduled reports</a>
      </nav>
      <Status loaded={s}>
        {(x) => (
          <>
            <h1>
              {KIND_LABEL[x.kind]} report{x.bu_name ? ` of ${x.bu_name}` : ""}, scheduled
            </h1>
            <p className="lede">
              {cadenceText(x)} · {x.state === "active" ? <Badge tone="ok">Active</Badge> : <Badge tone="warn">Suspended</Badge>}
            </p>
            {x.state === "suspended" ? (
              <div className="banner warn" role="status">
                <p>Suspended: {SUSPENDED[x.suspended_reason ?? ""] ?? "it could not run"}. It makes no reports until you resume it.</p>
              </div>
            ) : null}
            <div aria-live="polite">{done ? <p role="status">{done}</p> : null}</div>
            {error ? (
              <p role="alert" className="error-text">
                {error}
              </p>
            ) : null}
            <Section id="about" title="The schedule">
              <dl className="summary">
                <div>
                  <dt>Filters</dt>
                  <dd>{paramsText(x.kind, x.params ?? {})}</dd>
                </div>
                <div>
                  <dt>Formats</dt>
                  <dd>{x.formats.map((f) => f.toUpperCase()).join(", ")}</dd>
                </div>
                <div>
                  <dt>Next report</dt>
                  <dd>{x.state === "active" ? dateTime(x.next_at) : "None while suspended"}</dd>
                </div>
                {x.reason ? (
                  <div>
                    <dt>Reason</dt>
                    <dd>{x.reason}</dd>
                  </div>
                ) : null}
                <div>
                  <dt>Latest report</dt>
                  <dd>
                    {x.last_run ? (
                      <>
                        <a href={`/reports/${x.last_run.id}`}>{dateTime(x.last_run.requested_at)}</a> <StateBadge r={{ state: x.last_run.state, progress: 0 }} />
                      </>
                    ) : (
                      "None yet"
                    )}
                  </dd>
                </div>
              </dl>
              <div className="actions">
                {!editing ? (
                  <button
                    type="button"
                    className="btn"
                    onClick={() => {
                      setD(draftOf(x));
                      setEditing(true);
                    }}
                  >
                    Change
                  </button>
                ) : null}
                {x.state === "suspended" ? (
                  <button
                    type="button"
                    className="btn"
                    onClick={async () => {
                      setError(undefined);
                      try {
                        await send("POST", `/api/v1/reports/schedules/${x.id}/resume`, {});
                        setDone("Resumed.");
                        s.reload();
                      } catch (err) {
                        setError(describe(err));
                      }
                    }}
                  >
                    Resume
                  </button>
                ) : null}
                <ReasonAction
                  label="Delete"
                  title="Delete this schedule"
                  fieldLabel="Reason for deleting it"
                  description="It makes no more reports. The reports it made stay in your list until their retention ends."
                  submitLabel="Delete the schedule"
                  onSubmit={async (reason) => {
                    await send("DELETE", `/api/v1/reports/schedules/${x.id}`, { reason });
                    window.location.assign("/reports/schedules");
                  }}
                />
              </div>
            </Section>
            {editing ? (
              <Section id="change" title="Change the schedule" intro="Its report and business unit stay as they are; to change those, delete it and schedule another.">
                <form
                  className="filters"
                  aria-label="Change the schedule"
                  onSubmit={async (e) => {
                    e.preventDefault();
                    setError(undefined);
                    try {
                      await withReason((asked) => send<Schedule>("PUT", `/api/v1/reports/schedules/${x.id}`, { ...bodyOf(x.kind, d, asked), expected_version: x.version }));
                      setEditing(false);
                      setDone("Saved.");
                      s.reload();
                    } catch (err) {
                      setError(describe(err));
                    }
                  }}
                >
                  <ParamsFields kind={x.kind} bu={x.bu_id} value={d.params} onChange={(params) => setD({ ...d, params })} idPrefix="s" />
                  <WhenFields d={d} set={setD} />
                  <div className="actions">
                    <button className="react-aria-Button primary" type="submit">
                      Save
                    </button>
                    <button type="button" className="btn" onClick={() => setEditing(false)}>
                      Cancel
                    </button>
                  </div>
                </form>
              </Section>
            ) : null}
            <p>
              <a href={auditHref(`report_schedule:${x.id}`)}>Audit history of this schedule</a>
            </p>
          </>
        )}
      </Status>
    </>
  );
}
