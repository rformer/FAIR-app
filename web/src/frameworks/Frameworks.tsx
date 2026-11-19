import { useEffect, useState } from "react";
import { send } from "../api";
import { Badge, ReasonAction, Section, Status, useApi } from "../components";
import { auditHref, date } from "../links";
import {
  IMPLEMENTATION_LABELS,
  RELATIONSHIP_LABELS,
  STRENGTH_LABELS,
  reqName,
  type Baseline,
  type Crosswalk,
  type Family,
  type Requirement,
  type RequirementScenarios,
  type Version,
  type VersionDiff,
} from "./types";

// F-013 T-10 (F-013-AC-01 to AC-06, AC-10, AC-16, AC-17): frameworks, their
// versions with what changed, requirements, baselines and crosswalks, as
// reference data every reader of controls may see; retiring for holders of
// framework.manage. A requirement's page leads to the scenarios that use
// its controls, and to a proposed scenario version for one that does not
// (opened in the scenario editor, saved and run by the analyst).

type Listing = { frameworks: Family[]; may_manage?: boolean };

/** Whether the person may import and retire (framework.manage at the root). */
export function useMayManage(): boolean {
  const l = useApi<Listing>("/api/v1/frameworks");
  return l.data?.may_manage === true;
}

function Retired({ state }: { state: string }) {
  return state === "retired" ? (
    <>
      {" "}
      <Badge tone="muted">Retired</Badge>
    </>
  ) : null;
}

function Crumbs({ version }: { version?: { id: string; family_title?: string; label: string } }) {
  return (
    <nav aria-label="Breadcrumb" className="crumbs">
      <a href="/frameworks">Frameworks</a>
      {version ? (
        <>
          {" "}
          › <a href={`/frameworks/versions/${version.id}`}>{`${version.family_title ?? ""} ${version.label}`.trim()}</a>
        </>
      ) : null}
    </nav>
  );
}

export function FrameworksPage() {
  const [retired, setRetired] = useState(false);
  const list = useApi<Listing>(`/api/v1/frameworks${retired ? "?retired=true" : ""}`);
  const crosswalks = useApi<{ crosswalks: Crosswalk[] }>(`/api/v1/frameworks/crosswalks${retired ? "?retired=true" : ""}`);
  useEffect(() => {
    document.title = "Frameworks · FAIR Risk Platform";
  }, []);
  return (
    <>
      <h1>Frameworks</h1>
      <p className="lede">
        Control frameworks and their versions, as reference for mapping controls. Coverage shows which requirements your controls
        address; it is never a score.
      </p>
      <div className="actions">
        <label>
          <input type="checkbox" checked={retired} onChange={(e) => setRetired(e.target.checked)} /> Include retired versions
        </label>
        {list.data?.may_manage ? (
          <a className="react-aria-Button" href="/frameworks/imports">
            Import a framework, baseline or crosswalk
          </a>
        ) : null}
      </div>
      <Status loaded={list}>
        {(d) =>
          d.frameworks.length === 0 ? (
            <p>No frameworks are imported.</p>
          ) : (
            <>
              {d.frameworks.map((f) => (
                <Section key={f.key} id={`fw-${f.key}`} title={f.title} intro={f.publisher ?? undefined}>
                  <div className="table-wrap">
                    <table className="data">
                      <caption className="sr-only">Versions of {f.title}</caption>
                      <thead>
                        <tr>
                          <th scope="col">Version</th>
                          <th scope="col">Published</th>
                          <th scope="col" className="num">
                            Requirements
                          </th>
                          <th scope="col" className="num">
                            Baselines
                          </th>
                          <th scope="col">Source</th>
                        </tr>
                      </thead>
                      <tbody>
                        {f.versions.map((v) => (
                          <tr key={v.id}>
                            <td>
                              <a href={`/frameworks/versions/${v.id}`}>{v.label}</a>
                              <Retired state={v.state} />
                            </td>
                            <td>{date(v.published)}</td>
                            <td className="num">{v.requirements - v.withdrawn}</td>
                            <td className="num">{v.baselines?.length ?? 0}</td>
                            <td>{v.source === "shipped" ? "Shipped with the platform" : `Imported ${date(v.imported_at)}`}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Section>
              ))}
            </>
          )
        }
      </Status>
      <Section id="crosswalks" title="Crosswalks" intro="Relationships between requirements of two framework versions. Coverage reached through them is shown apart and never as in place.">
        <Status loaded={crosswalks}>
          {(d) =>
            d.crosswalks.length === 0 ? (
              <p>No crosswalks.</p>
            ) : (
              <ul>
                {d.crosswalks.map((x) => (
                  <li key={x.id}>
                    <a href={`/frameworks/crosswalks/${x.id}`}>{x.title}</a> ({x.source_version.family} {x.source_version.label} to {x.target_version.family}{" "}
                    {x.target_version.label}, {x.relationships} relationships)
                    <Retired state={x.state} />
                  </li>
                ))}
              </ul>
            )
          }
        </Status>
      </Section>
    </>
  );
}

export function VersionPage({ id }: { id: string }) {
  const v = useApi<Version>(`/api/v1/frameworks/versions/${id}`);
  const diff = useApi<VersionDiff>(`/api/v1/frameworks/versions/${id}/diff`);
  const crosswalks = useApi<{ crosswalks: Crosswalk[] }>(`/api/v1/frameworks/crosswalks?version=${id}&retired=true`);
  const manage = useMayManage();
  const [q, setQ] = useState("");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const params = new URLSearchParams({ limit: "100", offset: String(offset) });
  if (search) params.set("q", search);
  else params.set("parent", "");
  const reqs = useApi<{ requirements: Requirement[]; more: boolean }>(`/api/v1/frameworks/versions/${id}/requirements?${params.toString()}`);
  useEffect(() => {
    if (v.data) document.title = `${v.data.family_title} ${v.data.label} · Frameworks · FAIR Risk Platform`;
  }, [v.data]);
  return (
    <Status loaded={v}>
      {(ver) => (
        <>
          <Crumbs />
          <h1>
            {ver.family_title} {ver.label}
          </h1>
          <p className="lede">
            {ver.title}
            <Retired state={ver.state} />
          </p>
          <p className="actions">
            <a className="react-aria-Button primary" href={`/frameworks/versions/${id}/coverage`}>
              Coverage
            </a>
            {manage && ver.state === "active" ? (
              <ReasonAction
                label="Retire this version"
                title={`Retire ${ver.family_title} ${ver.label}`}
                fieldLabel="Why it is retired"
                description="A retired version stays readable, and controls mapped to it keep their mappings; it is hidden from new choices."
                submitLabel="Retire"
                onSubmit={async (reason) => {
                  await send("POST", `/api/v1/frameworks/versions/${id}/retire`, { reason });
                  v.reload();
                }}
              />
            ) : null}
            <a href={auditHref(`framework_version:${id}`)}>Audit history of this version</a>
          </p>
          <Section id="version" title="Version">
            <dl className="facts">
              <dt>Published</dt>
              <dd>{date(ver.published)}</dd>
              <dt>Requirements</dt>
              <dd>
                {ver.requirements - ver.withdrawn} ({ver.withdrawn} withdrawn)
              </dd>
              <dt>Source</dt>
              <dd>{ver.source === "shipped" ? "Shipped with the platform" : `Imported ${date(ver.imported_at)}${ver.imported_by_name ? ` by ${ver.imported_by_name}` : ""}`}</dd>
              <dt>File digest (SHA-256)</dt>
              <dd className="mono">{ver.sha256}</dd>
            </dl>
          </Section>
          <Section id="changes" title="What changed">
            <Status loaded={diff}>
              {(d) =>
                d.since === null ? (
                  <p>This is the first version of the framework here.</p>
                ) : (
                  <>
                    <p>
                      Since {d.since}: {d.added.length} added, {d.changed.length} changed, {d.withdrawn.length} withdrawn.
                    </p>
                    {(["added", "changed", "withdrawn"] as const).map((k) =>
                      d[k].length > 0 ? (
                        <details key={k}>
                          <summary>
                            {k[0]?.toUpperCase()}
                            {k.slice(1)} ({d[k].length})
                          </summary>
                          <p className="mono">
                            {d[k].map((x) => (k === "withdrawn" && d.renumbered[x] ? `${x} → ${d.renumbered[x]}` : x)).join(", ")}
                          </p>
                        </details>
                      ) : null,
                    )}
                  </>
                )
              }
            </Status>
          </Section>
          <Section id="baselines" title="Baselines">
            {(ver.baselines ?? []).length === 0 ? (
              <p>No baselines select from this version.</p>
            ) : (
              <ul>
                {(ver.baselines ?? []).map((b) => (
                  <li key={b.id}>
                    <a href={`/frameworks/baselines/${b.id}`}>{b.title}</a> ({b.requirements} requirements)
                    <Retired state={b.state} />
                  </li>
                ))}
              </ul>
            )}
          </Section>
          <Section id="version-crosswalks" title="Crosswalks">
            <Status loaded={crosswalks}>
              {(d) =>
                d.crosswalks.length === 0 ? (
                  <p>No crosswalks relate this version.</p>
                ) : (
                  <ul>
                    {d.crosswalks.map((x) => (
                      <li key={x.id}>
                        <a href={`/frameworks/crosswalks/${x.id}`}>{x.title}</a>
                        <Retired state={x.state} />
                      </li>
                    ))}
                  </ul>
                )
              }
            </Status>
          </Section>
          <Section id="requirements" title="Requirements">
            <form
              className="filters"
              aria-label="Search requirements"
              onSubmit={(e) => {
                e.preventDefault();
                setOffset(0);
                setSearch(q.trim());
              }}
            >
              <div className="field">
                <label htmlFor="req-q">Identifier, title or text</label>
                <input id="req-q" type="search" value={q} maxLength={200} onChange={(e) => setQ(e.target.value)} />
              </div>
              <button className="react-aria-Button" type="submit">
                Search
              </button>
            </form>
            <Status loaded={reqs}>
              {(d) => (
                <>
                  {d.requirements.length === 0 ? (
                    <p>No requirements match.</p>
                  ) : (
                    <div className="table-wrap">
                      <table className="data">
                        <caption className="sr-only">{search ? `Requirements matching ${search}` : "Top-level requirements"}</caption>
                        <thead>
                          <tr>
                            <th scope="col">Requirement</th>
                            <th scope="col">Title</th>
                          </tr>
                        </thead>
                        <tbody>
                          {d.requirements.map((r) => (
                            <tr key={r.id}>
                              <td>
                                <a href={`/frameworks/requirements/${r.id}`}>{reqName(r)}</a>
                              </td>
                              <td>
                                {r.title}
                                {r.withdrawn ? <span className="muted"> (withdrawn)</span> : null}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                  <div className="actions">
                    {offset > 0 ? (
                      <button className="react-aria-Button" type="button" onClick={() => setOffset(Math.max(0, offset - 100))}>
                        Previous page
                      </button>
                    ) : null}
                    {d.more ? (
                      <button className="react-aria-Button" type="button" onClick={() => setOffset(offset + 100)}>
                        Next page
                      </button>
                    ) : null}
                  </div>
                </>
              )}
            </Status>
          </Section>
        </>
      )}
    </Status>
  );
}

export function RequirementPage({ id }: { id: string }) {
  const a = useApi<RequirementScenarios>(`/api/v1/frameworks/requirements/${id}/scenarios`);
  useEffect(() => {
    const r = a.data?.requirement;
    if (r) document.title = `${reqName(r)} · ${r.version.family_title} ${r.version.label} · FAIR Risk Platform`;
  }, [a.data]);
  return (
    <Status loaded={a}>
      {(d) => {
        const r = d.requirement;
        return (
          <>
            <Crumbs version={r.version} />
            <h1>
              {reqName(r)} {r.title}
            </h1>
            {r.withdrawn ? (
              <p className="banner" role="note">
                Withdrawn{r.incorporated_into.length > 0 ? `; incorporated into ${r.incorporated_into.join(", ")}` : ""}.
              </p>
            ) : null}
            <Section id="statement" title="Requirement">
              {r.statement ? <p className="statement">{r.statement}</p> : <p className="muted">No statement.</p>}
              {r.children.length > 0 ? (
                <>
                  <h3>Parts and enhancements</h3>
                  <ul>
                    {r.children.map((c) => (
                      <li key={c.id}>
                        <a href={`/frameworks/requirements/${c.id}`}>{reqName(c)}</a> {c.title}
                        {c.withdrawn ? <span className="muted"> (withdrawn)</span> : null}
                      </li>
                    ))}
                  </ul>
                </>
              ) : null}
              {r.baselines.length > 0 ? <p>In baselines: {r.baselines.map((b) => b.title).join(", ")}.</p> : null}
            </Section>
            <Section id="req-controls" title="Controls mapped to it" intro="The controls you may see, at their latest versions.">
              {d.controls.length === 0 ? (
                <p>No control you can see maps to this requirement.</p>
              ) : (
                <div className="table-wrap">
                  <table className="data">
                    <caption className="sr-only">Controls mapped to {reqName(r)}</caption>
                    <thead>
                      <tr>
                        <th scope="col">Control</th>
                        <th scope="col">Strength</th>
                        <th scope="col">Implementation</th>
                        <th scope="col">FAIR effects</th>
                      </tr>
                    </thead>
                    <tbody>
                      {d.controls.map((c) => (
                        <tr key={c.id}>
                          <td>
                            <a href={`/controls/${c.id}`}>{c.name}</a>
                          </td>
                          <td>{STRENGTH_LABELS[c.strength]}</td>
                          <td>{c.implementation ? IMPLEMENTATION_LABELS[c.implementation] : "Not stated"}</td>
                          <td>{c.effects.map((e) => e.factor.replace(/^loss\./, "loss: ").replace(/_/g, " ")).join(", ") || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Section>
            <Section id="uses" title="Scenarios that use them" intro="Scenarios whose latest version has one of these controls in a current control set.">
              {d.uses.length === 0 ? (
                <p>None you can see.</p>
              ) : (
                <ul>
                  {d.uses.map((s) => (
                    <li key={s.id}>
                      <a href={`/scenarios/${s.id}`}>{s.name}</a> (in {s.sets.join(", ")})
                    </li>
                  ))}
                </ul>
              )}
              {d.uses_more ? <p className="muted">More scenarios use them than are listed.</p> : null}
            </Section>
            <Section
              id="could-use"
              title="Scenarios that could use them"
              intro="Scenarios in the controls' business units that do not use them. A proposal opens in the scenario editor as a new control set: nothing is saved or run until you do it."
            >
              {d.could_use.length === 0 || d.controls.length === 0 ? (
                <p>None you can see.</p>
              ) : (
                <div className="table-wrap">
                  <table className="data">
                    <caption className="sr-only">Scenarios that could use the controls</caption>
                    <thead>
                      <tr>
                        <th scope="col">Scenario</th>
                        <th scope="col">Propose a control set with</th>
                      </tr>
                    </thead>
                    <tbody>
                      {d.could_use.map((s) => (
                        <tr key={s.id}>
                          <td>
                            <a href={`/scenarios/${s.id}`}>{s.name}</a>
                          </td>
                          <td>
                            {d.controls.map((c, i) => (
                                <span key={c.id}>
                                  {i > 0 ? ", " : null}
                                  <a href={`/scenarios/${s.id}/edit?add_control=${c.id}`} aria-label={`Propose ${c.name} for ${s.name}`}>
                                    {c.name}
                                  </a>
                                </span>
                              ))}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {d.could_use_more ? <p className="muted">More scenarios could use them than are listed.</p> : null}
            </Section>
          </>
        );
      }}
    </Status>
  );
}

export function BaselinePage({ id }: { id: string }) {
  const b = useApi<Baseline>(`/api/v1/frameworks/baselines/${id}`);
  const manage = useMayManage();
  useEffect(() => {
    if (b.data) document.title = `${b.data.title} · Frameworks · FAIR Risk Platform`;
  }, [b.data]);
  return (
    <Status loaded={b}>
      {(x) => (
        <>
          <Crumbs version={{ id: x.version_id, label: `${x.family} ${x.version_label}` }} />
          <h1>{x.title}</h1>
          <p className="lede">
            A baseline of {x.family} {x.version_label}: {x.requirements} requirements.
            <Retired state={x.state} />
          </p>
          <p className="actions">
            <a className="react-aria-Button primary" href={`/frameworks/versions/${x.version_id}/coverage?baseline=${x.id}`}>
              Coverage of this baseline
            </a>
            {manage && x.state === "active" ? (
              <ReasonAction
                label="Retire this baseline"
                title={`Retire ${x.title}`}
                fieldLabel="Why it is retired"
                description="A retired baseline stays readable; it is hidden from coverage choices."
                submitLabel="Retire"
                onSubmit={async (reason) => {
                  await send("POST", `/api/v1/frameworks/baselines/${id}/retire`, { reason });
                  b.reload();
                }}
              />
            ) : null}
          </p>
          {x.notes.length > 0 ? (
            <Section id="notes" title="Notes from resolving the profile">
              <ul>
                {x.notes.map((n, i) => (
                  <li key={i}>{n}</li>
                ))}
              </ul>
            </Section>
          ) : null}
          <Section id="selected" title="Requirements it selects">
            <p className="mono">{(x.selected ?? []).join(", ")}</p>
          </Section>
        </>
      )}
    </Status>
  );
}

export function CrosswalkPage({ id }: { id: string }) {
  const [offset, setOffset] = useState(0);
  const x = useApi<Crosswalk>(`/api/v1/frameworks/crosswalks/${id}?limit=500&offset=${offset}`);
  const manage = useMayManage();
  useEffect(() => {
    if (x.data) document.title = `${x.data.title} · Crosswalks · FAIR Risk Platform`;
  }, [x.data]);
  return (
    <Status loaded={x}>
      {(c) => (
        <>
          <Crumbs />
          <h1>{c.title}</h1>
          <p className="lede">
            From {c.source_version.family} {c.source_version.label} to {c.target_version.family} {c.target_version.label}, version {c.label}
            {c.publisher ? `, by ${c.publisher}` : ""}.
            <Retired state={c.state} />
          </p>
          {manage && c.state === "active" ? (
            <p className="actions">
              <ReasonAction
                label="Retire this crosswalk"
                title={`Retire ${c.title}`}
                fieldLabel="Why it is retired"
                description="A retired crosswalk stays readable and no longer shows coverage through it."
                submitLabel="Retire"
                onSubmit={async (reason) => {
                  await send("POST", `/api/v1/frameworks/crosswalks/${id}/retire`, { reason });
                  x.reload();
                }}
              />
            </p>
          ) : null}
          <Section id="relationships" title="Relationships" intro="Each reads: the source requirement is equal to, a subset of, a superset of, or intersecting the target.">
            <div className="table-wrap">
              <table className="data">
                <caption className="sr-only">Relationships of {c.title}</caption>
                <thead>
                  <tr>
                    <th scope="col">Source</th>
                    <th scope="col">Relationship</th>
                    <th scope="col">Target</th>
                  </tr>
                </thead>
                <tbody>
                  {(c.relationship_list ?? []).map((l) => (
                    <tr key={`${l.source_id}-${l.target_id}`}>
                      <td>
                        <a href={`/frameworks/requirements/${l.source_id}`}>{l.source}</a> {l.source_title}
                      </td>
                      <td>{RELATIONSHIP_LABELS[l.relationship]}</td>
                      <td>
                        <a href={`/frameworks/requirements/${l.target_id}`}>{l.target}</a> {l.target_title}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="actions">
              {offset > 0 ? (
                <button className="react-aria-Button" type="button" onClick={() => setOffset(Math.max(0, offset - 500))}>
                  Previous page
                </button>
              ) : null}
              {c.more ? (
                <button className="react-aria-Button" type="button" onClick={() => setOffset(offset + 500)}>
                  Next page
                </button>
              ) : null}
            </div>
          </Section>
        </>
      )}
    </Status>
  );
}
