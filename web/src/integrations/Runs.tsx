import { useEffect } from "react";
import { Badge, Section, Status, useApi } from "../components";
import { dateTime, TRIGGER_LABEL, type Counts as CountsT, type Integration, type Run } from "./types";

// F-011 T-18 (F-011-AC-06, AC-08): a run, its counts and its refused
// records by position and reason.

const COUNT_LABEL: [keyof CountsT, string][] = [
  ["received", "received"],
  ["valid", "valid"],
  ["refused", "refused"],
  ["new", "new"],
  ["changed", "changed"],
  ["unchanged", "unchanged"],
  ["proposed", "proposed"],
  ["applied", "applied at once"],
];

export function Counts({ c, inline }: { c: CountsT; inline?: boolean }) {
  const shown = COUNT_LABEL.filter(([k]) => c[k] !== undefined);
  if (inline) return <>{shown.map(([k, l]) => `${c[k] ?? 0} ${l}`).join(", ")}</>;
  return (
    <dl className="facts">
      {shown.map(([k, l]) => (
        <div key={k}>
          <dt>{l.charAt(0).toUpperCase() + l.slice(1)}</dt>
          <dd>{c[k] ?? 0}</dd>
        </div>
      ))}
    </dl>
  );
}

export function RunPage({ integration, id }: { integration: string; id: string }) {
  const it = useApi<Integration>(`/api/v1/integrations/${integration}`);
  const run = useApi<Run>(`/api/v1/integrations/${integration}/runs/${id}`);
  useEffect(() => {
    document.title = `Run · ${it.data?.name ?? "Integration"} · FAIR Risk Platform`;
  }, [it.data]);
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/integrations">Integrations</a> / <a href={`/integrations/${integration}`}>{it.data?.name ?? "Integration"}</a>
      </nav>
      <Status loaded={run}>
        {(r) => (
          <>
            <h1>Run of {dateTime(r.started_at)}</h1>
            <p className="lede">
              {r.state === "succeeded" ? <Badge tone="ok">Received</Badge> : r.state === "failed" ? <Badge tone="bad">Failed</Badge> : <Badge tone="info">Running</Badge>}{" "}
              {TRIGGER_LABEL[r.trigger]}
              {r.actor_name ? ` by ${r.actor_name}` : ""}
              {r.complete ? ", a complete snapshot of the source" : ""}.
            </p>
            {r.failure ? (
              <p role="alert" className="error-text">
                {r.failure}
              </p>
            ) : null}
            {r.counts && Object.keys(r.counts).length > 0 ? (
              <Section id="counts" title="Counts">
                <Counts c={r.counts} />
                {(r.counts.proposed ?? 0) > 0 ? (
                  <p>
                    <a href={`/integrations/proposals?integration=${integration}&run=${r.id}`}>Review the changes this run proposed</a>
                  </p>
                ) : null}
              </Section>
            ) : null}
            <Section id="refused" title="Refused records" intro="Each refused record with its position and why; the valid ones were taken.">
              {!r.refusals || r.refusals.length === 0 ? (
                <p>None.</p>
              ) : (
                <div className="table-wrap">
                  <table className="data">
                    <caption className="sr-only">Refused records</caption>
                    <thead>
                      <tr>
                        <th scope="col">Record</th>
                        <th scope="col">External ID</th>
                        <th scope="col">Field</th>
                        <th scope="col">Reason</th>
                      </tr>
                    </thead>
                    <tbody>
                      {r.refusals.map((f, i) => (
                        <tr key={`${f.n}-${f.pointer}-${i}`}>
                          <td>{f.n}</td>
                          <td className="mono">{f.external_id ?? "—"}</td>
                          <td className="mono">{f.column ? `${f.column} (${f.pointer})` : f.pointer || "/"}</td>
                          <td>{f.message}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Section>
          </>
        )}
      </Status>
    </>
  );
}
