import { useEffect, useState } from "react";
import { Badge, Section, Status, useApi, type Tone } from "../components";
import { DownloadButton } from "../reason";
import {
  IMPLEMENTATION_LABELS,
  RELATIONSHIP_LABELS,
  STATE_LABELS,
  STRENGTH_LABELS,
  reqName,
  type Coverage,
  type CoverageState,
  type CoveredBy,
  type Version,
} from "./types";

// F-013 T-10 (F-013-AC-12 to AC-15, AC-20): a framework version's coverage,
// or one of its baselines', for a business unit and its subtree: each
// requirement's state with the controls that cover it, directly or through
// a crosswalk (apart), counts by state and never a score; restricted units
// as their roll-up mode allows; as of a past date; exported as CSV or JSON
// (a reason where the export rule asks for one).

const TONES: Record<CoverageState, Tone> = { in_place: "ok", not_in_place: "bad", partial: "warn", not_covered: "muted" };
const STATES: CoverageState[] = ["in_place", "not_in_place", "partial", "not_covered"];

function Controls({ list }: { list: CoveredBy[] }) {
  if (list.length === 0) return <>—</>;
  return (
    <ul className="plain">
      {list.map((c) => (
        <li key={`${c.control_id}-${c.via ?? ""}`}>
          <a href={`/controls/${c.control_id}`}>{c.name}</a> ({STRENGTH_LABELS[c.strength]}, {c.implementation ? IMPLEMENTATION_LABELS[c.implementation] : "implementation not stated"})
          {c.via ? (
            <span className="muted">
              {" "}
              via {c.via}, {RELATIONSHIP_LABELS[c.relationship!]} this requirement ({c.crosswalk})
            </span>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

function CountList({ counts, label }: { counts: Record<CoverageState, number>; label: string }) {
  return (
    <dl className="facts" aria-label={label}>
      {STATES.map((s) => (
        <div key={s}>
          <dt>{STATE_LABELS[s]}</dt>
          <dd>{counts[s]}</dd>
        </div>
      ))}
    </dl>
  );
}

export function CoveragePage({ id, search = window.location.search }: { id: string; search?: string }) {
  const q0 = new URLSearchParams(search);
  const v = useApi<Version>(`/api/v1/frameworks/versions/${id}`);
  const bus = useApi<{ bus: { id: string; code: string; name: string }[] }>("/api/v1/risk/bus?permission=control.view");
  const [bu, setBU] = useState(q0.get("bu") ?? "");
  const [baseline, setBaseline] = useState(q0.get("baseline") ?? "");
  const [asOf, setAsOf] = useState(q0.get("as_of") ?? "");
  const [only, setOnly] = useState<CoverageState | "">("");
  useEffect(() => {
    const first = bus.data?.bus[0];
    if (!bu && first) setBU(first.id);
  }, [bus.data, bu]);
  const params = new URLSearchParams();
  if (bu) params.set("bu", bu);
  if (baseline) params.set("baseline", baseline);
  if (asOf) params.set("as_of", asOf);
  const cov = useApi<Coverage>(bu ? `/api/v1/frameworks/versions/${id}/coverage?${params.toString()}` : null);
  useEffect(() => {
    if (v.data) document.title = `Coverage · ${v.data.family_title} ${v.data.label} · FAIR Risk Platform`;
    if (bu) window.history.replaceState(null, "", `/frameworks/versions/${id}/coverage?${params.toString()}`);
  }, [v.data, bu, baseline, asOf, id]);
  return (
    <Status loaded={v}>
      {(ver) => (
        <>
          <nav aria-label="Breadcrumb" className="crumbs">
            <a href="/frameworks">Frameworks</a> › <a href={`/frameworks/versions/${id}`}>{`${ver.family_title} ${ver.label}`}</a>
          </nav>
          <h1>Coverage of {`${ver.family_title} ${ver.label}`}</h1>
          <p className="lede">
            Which requirements the controls you may see address, and whether those controls are in place. Coverage through a crosswalk
            is shown apart and never counts as in place. There is no score: read the requirements.
          </p>
          <form className="filters" aria-label="Coverage for" onSubmit={(e) => e.preventDefault()}>
            <div className="field">
              <label htmlFor="cov-bu">Business unit (and the units below it)</label>
              <select id="cov-bu" value={bu} onChange={(e) => setBU(e.target.value)}>
                {(bus.data?.bus ?? []).map((b) => (
                  <option key={b.id} value={b.id}>
                    {b.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="cov-baseline">Baseline</label>
              <select id="cov-baseline" value={baseline} onChange={(e) => setBaseline(e.target.value)}>
                <option value="">The whole version</option>
                {(ver.baselines ?? [])
                  .filter((b) => b.state === "active" || b.id === baseline)
                  .map((b) => (
                    <option key={b.id} value={b.id}>
                      {b.title}
                    </option>
                  ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="cov-asof">As of (optional)</label>
              <input id="cov-asof" type="date" value={asOf} max={new Date().toISOString().slice(0, 10)} onChange={(e) => setAsOf(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="cov-only">Show</label>
              <select id="cov-only" value={only} onChange={(e) => setOnly(e.target.value as CoverageState | "")}>
                <option value="">Every requirement</option>
                {STATES.map((s) => (
                  <option key={s} value={s}>
                    {STATE_LABELS[s]}
                  </option>
                ))}
              </select>
            </div>
          </form>
          {bu ? (
            <Status loaded={cov}>
              {(c) => {
                const rows = only ? c.requirements.filter((r) => r.state === only) : c.requirements;
                return (
                  <>
                    <Section id="counts" title="Requirements by state">
                      <CountList counts={c.counts} label="Requirements by state" />
                      {c.restricted ? (
                        <>
                          <h3>{c.restricted.units === 1 ? "A restricted business unit" : `${c.restricted.units} restricted business units`} (totals only)</h3>
                          <CountList counts={c.restricted.counts} label="Restricted units, by state" />
                        </>
                      ) : null}
                      {c.left_out > 0 ? (
                        <p className="muted">
                          {c.left_out === 1 ? "One business unit below is" : `${c.left_out} business units below are`} left out: you may not see
                          their controls, even as totals.
                        </p>
                      ) : null}
                      <div className="actions">
                        <DownloadButton href={`/api/v1/frameworks/versions/${id}/coverage.csv?${params.toString()}`} fallbackName="coverage.csv">
                          Download as CSV
                        </DownloadButton>
                        <DownloadButton href={`/api/v1/frameworks/versions/${id}/coverage.json?${params.toString()}`} fallbackName="coverage.json">
                          Download as JSON
                        </DownloadButton>
                      </div>
                    </Section>
                    <Section id="coverage" title="Requirements">
                      <div className="table-wrap">
                        <table className="data">
                          <caption className="sr-only">
                            Coverage of each requirement{c.as_of ? ` as of ${asOf}` : ""}
                          </caption>
                          <thead>
                            <tr>
                              <th scope="col">Requirement</th>
                              <th scope="col">State</th>
                              <th scope="col">Mapped controls</th>
                              <th scope="col">Through a crosswalk</th>
                            </tr>
                          </thead>
                          <tbody>
                            {rows.map((r) => (
                              <tr key={r.id}>
                                <th scope="row">
                                  <a href={`/frameworks/requirements/${r.id}`}>{reqName(r)}</a> {r.title}
                                </th>
                                <td>
                                  <Badge tone={TONES[r.state]}>{STATE_LABELS[r.state]}</Badge>
                                </td>
                                <td>
                                  <Controls list={r.direct} />
                                </td>
                                <td>
                                  <Controls list={r.derived} />
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </Section>
                  </>
                );
              }}
            </Status>
          ) : null}
        </>
      )}
    </Status>
  );
}
