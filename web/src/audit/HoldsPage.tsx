import { useEffect, useState, type FormEvent } from "react";
import { ApiError, describe, send } from "../api";
import { Badge, ReasonAction, Section, Status, useApi } from "../components";
import { filterLabel, Person, toLocalInput, utc } from "./AuditPage";
import { AUDIT_API, CATEGORIES, FILTERS, SEVERITIES, type FilterKey, type Hold } from "./types";

// F-002 T-19 (AC-29): legal holds, for holders of audit.hold at the root
// (Platform Admin). A hold's filter covers the whole trail, later records
// included, until it is released; held records are not destroyed. The
// search page links here with its applied filters.

function inWords(filter: Record<string, string>): string {
  const parts = Object.entries(filter).map(([k, v]) => `${filterLabel[k as FilterKey] ?? k}: ${v}`);
  return parts.length === 0 ? "Every record" : parts.join("; ");
}

export function HoldsPage({ search = window.location.search }: { search?: string }) {
  useEffect(() => {
    document.title = "Legal holds · FAIR Risk Platform";
  }, []);
  const holds = useApi<{ holds: Hold[] }>(`${AUDIT_API}/holds`);
  if (holds.error instanceof ApiError && (holds.error.status === 404 || holds.error.status === 403)) {
    return (
      <>
        <h1>Legal holds</h1>
        <p role="alert">You do not have access to legal holds (it needs the audit.hold permission at the top business unit).</p>
      </>
    );
  }
  const initial: Partial<Record<FilterKey, string>> = {};
  const p = new URLSearchParams(search);
  for (const k of FILTERS) {
    const v = p.get(k);
    if (v) initial[k] = v;
  }
  return (
    <>
      <h1>Legal holds</h1>
      <p className="lede">
        A legal hold keeps the audit records matching its filter, in every business unit and including records recorded later, from being
        destroyed until it is released. Placing and releasing holds is recorded at high severity.
      </p>
      <Section id="place" title="Place a legal hold">
        <PlaceHold initial={initial} onPlaced={holds.reload} />
      </Section>
      <Section id="holds" title="Holds">
        <Status loaded={holds}>
          {(d) =>
            d.holds.length === 0 ? (
              <p>No legal holds.</p>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <caption className="sr-only">Legal holds, newest first</caption>
                  <thead>
                    <tr>
                      <th scope="col">Records held</th>
                      <th scope="col">Reason</th>
                      <th scope="col">Placed</th>
                      <th scope="col">Segments</th>
                      <th scope="col">Status</th>
                      <th scope="col">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.holds.map((h) => (
                      <tr key={h.hold_id}>
                        <th scope="row" className="wrap">
                          {inWords(h.filter)}
                        </th>
                        <td className="wrap">{h.reason}</td>
                        <td>
                          {utc(h.placed_at)}, <Person id={h.placed_by} names={h.names} />
                        </td>
                        <td>
                          {h.segments}
                          {h.status === "active" && !h.archives_checked_at ? <div className="muted">Archived records being checked</div> : null}
                        </td>
                        <td>
                          {h.status === "active" ? (
                            <Badge tone="warn">Active</Badge>
                          ) : (
                            <>
                              <Badge tone="muted">Released</Badge>{" "}
                              <span className="muted">
                                {h.released_at ? utc(h.released_at) : ""}, {h.released_by ? <Person id={h.released_by} names={h.names} /> : null}:{" "}
                                {h.release_reason}
                              </span>
                            </>
                          )}
                        </td>
                        <td>
                          {h.status === "active" ? (
                            <ReasonAction
                              label="Release"
                              title={`Release the hold on ${inWords(h.filter).toLowerCase()}`}
                              fieldLabel="Reason for release"
                              description="Records no other hold covers then follow normal retention again."
                              submitLabel="Release hold"
                              onSubmit={async (reason) => {
                                await send("POST", `${AUDIT_API}/holds/${h.hold_id}/release`, { reason });
                                holds.reload();
                              }}
                            />
                          ) : null}
                        </td>
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

function PlaceHold({ initial, onPlaced }: { initial: Partial<Record<FilterKey, string>>; onPlaced: () => void }) {
  const [error, setError] = useState<string>();
  const [placed, setPlaced] = useState<Hold>();
  const [busy, setBusy] = useState(false);
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const data = new FormData(e.currentTarget);
    const filter: Record<string, string> = {};
    for (const k of FILTERS) {
      let v = String(data.get(k) ?? "").trim();
      if (!v) continue;
      if (k === "from" || k === "to") {
        const d = new Date(v);
        if (Number.isNaN(d.getTime())) {
          setError(`${filterLabel[k]} is not a valid time.`);
          return;
        }
        v = d.toISOString();
      }
      filter[k] = v;
    }
    const reason = String(data.get("reason") ?? "").trim();
    if (!reason) {
      setError("Give a reason for the hold.");
      return;
    }
    setError(undefined);
    setPlaced(undefined);
    setBusy(true);
    send<Hold>("POST", `${AUDIT_API}/holds`, { filter, reason })
      .then((h) => {
        setPlaced(h);
        onPlaced();
      })
      .catch((err: unknown) => setError(describe(err)))
      .finally(() => setBusy(false));
  };
  const text = (k: FilterKey) => (
    <div className="field" key={k}>
      <label htmlFor={`h-${k}`}>{filterLabel[k]}</label>
      <input id={`h-${k}`} name={k} type="text" defaultValue={initial[k] ?? ""} spellCheck={false} autoComplete="off" />
    </div>
  );
  return (
    <form className="filters" onSubmit={submit} aria-label="Place a legal hold" noValidate>
      <div className="field">
        <label htmlFor="h-from">{filterLabel.from}</label>
        <input id="h-from" name="from" type="datetime-local" defaultValue={toLocalInput(initial.from)} />
      </div>
      <div className="field">
        <label htmlFor="h-to">{filterLabel.to}</label>
        <input id="h-to" name="to" type="datetime-local" defaultValue={toLocalInput(initial.to)} />
      </div>
      {text("type")}
      <div className="field">
        <label htmlFor="h-category">{filterLabel.category}</label>
        <select id="h-category" name="category" defaultValue={initial.category ?? ""}>
          <option value="">Any</option>
          {CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      </div>
      <div className="field">
        <label htmlFor="h-severity">{filterLabel.severity}</label>
        <select id="h-severity" name="severity" defaultValue={initial.severity ?? ""}>
          <option value="">Any</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>
      {text("actor")}
      {text("target")}
      {text("bu")}
      {text("request_id")}
      {text("source_ip")}
      <div className="field wide">
        <label htmlFor="h-reason">Reason</label>
        <textarea id="h-reason" name="reason" rows={2} maxLength={1000} required aria-describedby="h-reason-hint" />
        <p id="h-reason-hint" className="muted">
          Recorded with the hold, for example the matter or case reference.
        </p>
      </div>
      {error ? (
        <p role="alert" className="error-text">
          {error}
        </p>
      ) : null}
      <div className="actions">
        <button type="submit" className="btn primary" disabled={busy}>
          Place hold
        </button>
      </div>
      <div role="status" className="wide">
        {placed ? (
          <p>
            Hold placed on {inWords(placed.filter).toLowerCase()}. It covers {placed.segments} {placed.segments === 1 ? "segment" : "segments"} of
            online records so far; archived records are checked within the hour, and nothing is destroyed until they have been.
          </p>
        ) : null}
      </div>
    </form>
  );
}
