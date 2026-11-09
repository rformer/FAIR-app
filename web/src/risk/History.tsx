import { useState } from "react";
import { describe, getJSON } from "../api";
import { Section, Status, useApi } from "../components";
import { date, show } from "../links";
import type { DiffView, Version } from "./types";

// F-003 T-12, T-13 (AC-15, AC-17): a scenario's, library entry's or
// control's versions, and what changed between two (base is its API path).

/** AC-15, AC-17: every version, and what changed between two. */
export function History({ base, current }: { base: string; current: number }) {
  const versions = useApi<{ versions: Version[] }>(`${base}/versions`);
  const [from, setFrom] = useState(Math.max(1, current - 1));
  const [to, setTo] = useState(current);
  const [diff, setDiff] = useState<{ data?: DiffView; error?: string }>({});
  return (
    <Section id="history" title="Versions">
      <Status loaded={versions}>
        {(data) => (
          <>
            <div className="table-wrap">
              <table className="data">
                <caption className="sr-only">Versions, newest first</caption>
                <thead>
                  <tr>
                    <th scope="col">Version</th>
                    <th scope="col">Saved</th>
                    <th scope="col">Change note</th>
                  </tr>
                </thead>
                <tbody>
                  {data.versions.map((x) => (
                    <tr key={x.version}>
                      <td>{x.version}</td>
                      <td>{date(x.created_at)}</td>
                      <td>{x.change_note}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {current > 1 ? (
              <form
                className="filters"
                aria-label="Compare versions"
                onSubmit={(e) => {
                  e.preventDefault();
                  getJSON<DiffView>(`${base}/diff?from=${from}&to=${to}`).then(
                    (d) => setDiff({ data: d }),
                    (err: unknown) => setDiff({ error: describe(err) }),
                  );
                }}
              >
                <div className="field">
                  <label htmlFor="diff-from">From version</label>
                  <select id="diff-from" value={from} onChange={(e) => setFrom(Number(e.target.value))}>
                    {data.versions.map((x) => (
                      <option key={x.version} value={x.version}>
                        {x.version}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="field">
                  <label htmlFor="diff-to">To version</label>
                  <select id="diff-to" value={to} onChange={(e) => setTo(Number(e.target.value))}>
                    {data.versions.map((x) => (
                      <option key={x.version} value={x.version}>
                        {x.version}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="actions">
                  <button className="btn" type="submit">
                    Compare
                  </button>
                </div>
              </form>
            ) : null}
            {diff.error ? (
              <p role="alert" className="error-text">
                {diff.error}
              </p>
            ) : null}
            {diff.data ? <DiffTable d={diff.data} /> : null}
          </>
        )}
      </Status>
    </Section>
  );
}

function DiffTable({ d }: { d: DiffView }) {
  const label = { added: "Added", removed: "Removed", changed: "Changed" };
  return (
    <div role="region" aria-label={`Changes from version ${d.from} to ${d.to}`} aria-live="polite">
      <h3>
        Changes from version {d.from} to {d.to}
      </h3>
      {d.changes.length === 0 ? (
        <p>No differences.</p>
      ) : (
        <div className="table-wrap">
          <table className="data">
            <caption className="sr-only">Changes</caption>
            <thead>
              <tr>
                <th scope="col">Where</th>
                <th scope="col">Change</th>
                <th scope="col">Before</th>
                <th scope="col">After</th>
              </tr>
            </thead>
            <tbody>
              {d.changes.map((c) => (
                <tr key={c.pointer}>
                  <td className="mono">{c.pointer}</td>
                  <td>{label[c.op]}</td>
                  <td className="mono">{c.from === undefined ? "—" : show(c.from)}</td>
                  <td className="mono">{c.to === undefined ? "—" : show(c.to)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
