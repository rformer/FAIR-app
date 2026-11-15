import { useEffect, useState } from "react";
import { ApiError, describe, getJSON, send } from "../api";
import type { Run } from "../analysis/types";
import { Section, Status, useApi } from "../components";
import type { BU, Head } from "../risk/types";
import type { Category, Link, Owner, RiskDocument, RiskView } from "./types";

// F-007 T-08 (F-007-AC-01, AC-02, AC-06): a new risk, or a change to one:
// its title, description, owner, category, the scenarios it covers and the
// analysis pinned for each. The database checks everything (the owner sees
// the risk's business unit; each scenario is visible, in its subtree, linked
// to no other open risk; each pin is a succeeded run of the register's
// iteration count); its problems are shown by field.

interface Problem {
  pointer: string;
  message: string;
}

export function RiskEditor({ id }: { id?: string }) {
  const existing = useApi<RiskView>(id ? `/api/v1/register/risks/${id}` : "/api/v1/register/categories");
  useEffect(() => {
    document.title = `${id ? "Edit risk" : "New risk"} · Risk register · FAIR Risk Platform`;
  }, [id]);
  if (!id) return <Form />;
  return <Status loaded={existing}>{(v) => <Form view={v as RiskView} />}</Status>;
}

function Form({ view }: { view?: RiskView }) {
  const doc = view?.version.document;
  const editable = useApi<{ bus: BU[] }>("/api/v1/register/bus?permission=register.edit");
  const categories = useApi<{ categories: Category[] }>("/api/v1/register/categories");
  const scenarios = useApi<{ scenarios: Head[] }>("/api/v1/scenarios?archived=false&limit=200");
  const [bu, setBu] = useState(view?.risk.bu_id ?? "");
  useEffect(() => {
    if (!bu && editable.data?.bus[0]) setBu(editable.data.bus[0].id);
  }, [bu, editable.data]);
  const owners = useApi<{ owners: Owner[] }>(bu ? `/api/v1/register/owners?bu=${encodeURIComponent(bu)}` : "/api/v1/register/categories");
  const [title, setTitle] = useState(doc?.title ?? "");
  const [description, setDescription] = useState(doc?.description ?? "");
  const [owner, setOwner] = useState(doc?.owner ?? "");
  const [category, setCategory] = useState(doc?.category ?? "");
  const [links, setLinks] = useState<Link[]>(doc?.scenarios ?? []);
  const [adding, setAdding] = useState("");
  const [note, setNote] = useState("");
  const [problems, setProblems] = useState<Problem[]>([]);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const ownerList = bu ? ((owners.data as { owners?: Owner[] } | undefined)?.owners ?? []) : [];
  useEffect(() => {
    if (!owner && ownerList[0]) setOwner(ownerList[0].user_id);
  }, [owner, ownerList]);
  const name = (sid: string) => scenarios.data?.scenarios.find((s) => s.id === sid)?.name ?? sid;
  const problemsAt = (prefix: string) => problems.filter((p) => p.pointer === prefix || p.pointer.startsWith(`${prefix}/`));

  const save = async () => {
    setProblems([]);
    setError(undefined);
    if (!note.trim()) {
      setError("A change note is required.");
      return;
    }
    const document: RiskDocument = {
      schema_version: 1,
      title,
      owner,
      state: "open",
      scenarios: links.map((l) => (l.pin ? { scenario_id: l.scenario_id, pin: { ...l.pin, reason: l.pin.reason || undefined } } : { scenario_id: l.scenario_id })),
    };
    if (description.trim()) document.description = description;
    document.category = category || null;
    setBusy(true);
    try {
      if (view) {
        await send("PUT", `/api/v1/register/risks/${view.risk.id}`, { document, expected_version: view.risk.current_version, change_note: note });
        window.location.assign(`/register/risks/${view.risk.id}`);
      } else {
        const r = await send<{ id: string }>("POST", "/api/v1/register/risks", { bu_id: bu, document, change_note: note });
        window.location.assign(`/register/risks/${r.id}`);
      }
    } catch (err) {
      const body = err instanceof ApiError ? (err.body as { problems?: Problem[] } | undefined) : undefined;
      if (body?.problems) setProblems(body.problems);
      setError(describe(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/register">Risk register</a>
        {view ? (
          <>
            {" / "}
            <a href={`/register/risks/${view.risk.id}`}>{doc?.title}</a>
          </>
        ) : null}
      </nav>
      <h1>{view ? `Edit ${doc?.title ?? "risk"}` : "New risk"}</h1>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        <Section id="risk" title="Risk">
          {!view ? (
            <div className="field">
              <label htmlFor="bu">Business unit</label>
              <select id="bu" value={bu} onChange={(e) => (setBu(e.target.value), setOwner(""))}>
                {(editable.data?.bus ?? []).map((b) => (
                  <option key={b.id} value={b.id}>
                    {b.name}
                  </option>
                ))}
              </select>
            </div>
          ) : null}
          <div className="field">
            <label htmlFor="title">Title</label>
            <input id="title" value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} aria-describedby={problemsAt("/title").length ? "title-err" : undefined} />
            <Problems id="title-err" list={problemsAt("/title")} />
          </div>
          <div className="field">
            <label htmlFor="description">Description</label>
            <textarea id="description" rows={4} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={5000} />
          </div>
          <div className="field">
            <label htmlFor="owner">Owner</label>
            <select id="owner" value={owner} onChange={(e) => setOwner(e.target.value)} aria-describedby={problemsAt("/owner").length ? "owner-err" : undefined}>
              {doc && !ownerList.some((o) => o.user_id === doc.owner) ? <option value={doc.owner}>{view?.risk.owner_name ?? doc.owner}</option> : null}
              {ownerList.map((o) => (
                <option key={o.user_id} value={o.user_id}>
                  {o.name}
                </option>
              ))}
            </select>
            <Problems id="owner-err" list={problemsAt("/owner")} />
          </div>
          <div className="field">
            <label htmlFor="category">Category</label>
            <select id="category" value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="">None</option>
              {(categories.data?.categories ?? [])
                .filter((c) => !c.archived_at || c.id === doc?.category)
                .map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
            </select>
          </div>
        </Section>
        <Section id="links" title="Scenarios" intro="The scenarios this risk covers, and for each the analysis that stands for it: a succeeded run at the register's iteration count, and one of its control sets.">
          {links.length === 0 ? <p>No scenarios linked yet.</p> : null}
          {links.map((l, i) => (
            <LinkEditor
              key={l.scenario_id}
              index={i}
              link={l}
              name={name(l.scenario_id)}
              problems={problemsAt(`/scenarios/${i}`)}
              onChange={(next) => setLinks(links.map((x, j) => (j === i ? next : x)))}
              onRemove={() => setLinks(links.filter((_, j) => j !== i))}
            />
          ))}
          <div className="filters">
            <div className="field">
              <label htmlFor="add-scenario">Link a scenario</label>
              <select id="add-scenario" value={adding} onChange={(e) => setAdding(e.target.value)}>
                <option value="">Choose a scenario</option>
                {(scenarios.data?.scenarios ?? [])
                  .filter((s) => !links.some((l) => l.scenario_id === s.id))
                  .map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name ?? s.id}
                    </option>
                  ))}
              </select>
            </div>
            <div className="actions">
              <button
                className="btn"
                type="button"
                disabled={!adding}
                onClick={() => {
                  setLinks([...links, { scenario_id: adding }]);
                  setAdding("");
                }}
              >
                Link
              </button>
            </div>
          </div>
        </Section>
        <Section id="save" title="Save">
          <div className="field">
            <label htmlFor="note">Change note</label>
            <textarea id="note" rows={2} value={note} onChange={(e) => setNote(e.target.value)} maxLength={1000} />
          </div>
          {error ? (
            <div role="alert" className="error-text">
              <p>{error}</p>
              {problems.length > 0 ? (
                <ul>
                  {problems.map((p, i) => (
                    <li key={i}>
                      <span className="mono">{p.pointer}</span>: {p.message}
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}
          <div className="actions">
            <button className="react-aria-Button primary" type="submit" disabled={busy}>
              {view ? "Save" : "Create risk"}
            </button>
            <a href={view ? `/register/risks/${view.risk.id}` : "/register"}>Cancel</a>
          </div>
        </Section>
      </form>
    </>
  );
}

function Problems({ id, list }: { id: string; list: Problem[] }) {
  if (list.length === 0) return null;
  return (
    <p id={id} className="error-text">
      {list.map((p) => p.message).join("; ")}
    </p>
  );
}

/** One linked scenario and its pin: a run and a control set (another than the run's current one with a reason). */
function LinkEditor({
  index,
  link,
  name,
  problems,
  onChange,
  onRemove,
}: {
  index: number;
  link: Link;
  name: string;
  problems: Problem[];
  onChange: (l: Link) => void;
  onRemove: () => void;
}) {
  const [runs, setRuns] = useState<Run[]>();
  const [loadError, setLoadError] = useState<string>();
  useEffect(() => {
    getJSON<{ runs: Run[] }>(`/api/v1/analyses/runs?scenario=${encodeURIComponent(link.scenario_id)}&limit=50`).then(
      (d) => setRuns(d.runs.filter((r) => r.state === "succeeded")),
      (err: unknown) => setLoadError(describe(err)),
    );
  }, [link.scenario_id]);
  const run = runs?.find((r) => r.id === link.pin?.run_id);
  const sets = run?.control_sets ?? (link.pin ? [link.pin.control_set] : []);
  const current = sets[0];
  const base = `link-${index}`;
  return (
    <fieldset className="card nested" aria-describedby={problems.length ? `${base}-err` : undefined}>
      <legend>{name}</legend>
      <div className="filters">
        <div className="field">
          <label htmlFor={`${base}-run`}>Pinned analysis</label>
          <select
            id={`${base}-run`}
            value={link.pin?.run_id ?? ""}
            onChange={(e) => {
              const r = runs?.find((x) => x.id === e.target.value);
              onChange(r ? { scenario_id: link.scenario_id, pin: { run_id: r.id, control_set: r.control_sets[0] ?? "" } } : { scenario_id: link.scenario_id });
            }}
          >
            <option value="">None yet</option>
            {link.pin && !run ? <option value={link.pin.run_id}>The pinned run</option> : null}
            {(runs ?? []).map((r) => (
              <option key={r.id} value={r.id}>
                Version {r.scenario_version}, {r.iterations.toLocaleString("en-US")} iterations, {r.finished_at?.slice(0, 10) ?? ""}
              </option>
            ))}
          </select>
        </div>
        {link.pin ? (
          <div className="field">
            <label htmlFor={`${base}-set`}>Control set</label>
            <select id={`${base}-set`} value={link.pin.control_set} onChange={(e) => onChange({ ...link, pin: { ...link.pin!, control_set: e.target.value } })}>
              {sets.map((s, j) => (
                <option key={s} value={s}>
                  {s}
                  {j === 0 ? " (current)" : ""}
                </option>
              ))}
            </select>
          </div>
        ) : null}
        {link.pin && link.pin.control_set !== current ? (
          <div className="field">
            <label htmlFor={`${base}-reason`}>Why this control set</label>
            <input id={`${base}-reason`} value={link.pin.reason ?? ""} onChange={(e) => onChange({ ...link, pin: { ...link.pin!, reason: e.target.value } })} maxLength={1000} />
          </div>
        ) : null}
        <div className="actions">
          <button className="btn" type="button" onClick={onRemove}>
            Unlink
          </button>
        </div>
      </div>
      {loadError ? <p className="error-text">{loadError}</p> : null}
      <Problems id={`${base}-err`} list={problems} />
    </fieldset>
  );
}
