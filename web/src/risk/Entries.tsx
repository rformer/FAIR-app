import { useEffect, useState, type ReactNode } from "react";
import { Button, Dialog, DialogTrigger, Heading, Modal } from "react-aria-components";
import { ApiError, describe, send } from "../api";
import { Badge, Section, Status, useApi } from "../components";
import { auditHref, date } from "../links";
import { ArchiveAction } from "./Actions";
import { EstimateFields, fieldId, newEstimate } from "./EstimateFields";
import { History } from "./History";
import {
  FACTORS,
  FORMS,
  FORM_LABELS,
  KIND_LABELS,
  LIBRARY_KINDS,
  effectUnit,
  factorName,
  showEstimate,
  type AssetDoc,
  type AssetGroupDoc,
  type BU,
  type ControlDoc,
  type EntryDoc,
  type EntryView,
  type Form,
  type Head,
  type LibraryKind,
  type LossProfileDoc,
  type Problem,
  type StarterEntry,
  type ThreatCommunityDoc,
} from "./types";

// F-003 T-13 (AC-08, AC-11, AC-12, AC-14, AC-22, AC-27): the library
// (assets, asset groups, threat communities, loss profiles) and controls:
// lists with inherited entries marked, an entry's page with its versions,
// the editors, and the starter library with its copy action.

export type EntrySection = "library" | "controls";

const perm = (s: EntrySection) => (s === "library" ? "library" : "control");
const api = (s: EntrySection) => `/api/v1/${s}`;
const title = (s: EntrySection) => (s === "library" ? "Library" : "Controls");

function useBUs(s: EntrySection) {
  const view = useApi<{ bus: BU[] }>(`/api/v1/risk/bus?permission=${perm(s)}.view`);
  const edit = useApi<{ bus: BU[] }>(`/api/v1/risk/bus?permission=${perm(s)}.edit`);
  return { view: view.data?.bus ?? [], edit: edit.data?.bus ?? [] };
}

export function EntryList({ section, search = window.location.search }: { section: EntrySection; search?: string }) {
  const q = new URLSearchParams(search);
  const archived = q.get("archived") ?? "false";
  const kind = section === "library" ? (q.get("kind") ?? "") : "";
  useEffect(() => {
    document.title = `${title(section)} · FAIR Risk Platform`;
  }, [section]);
  const list = useApi<{ entries?: Head[]; controls?: Head[]; next_cursor?: string }>(
    `${api(section)}?archived=${encodeURIComponent(archived)}${kind ? `&kind=${encodeURIComponent(kind)}` : ""}`,
  );
  const bus = useBUs(section);
  const buName = (h: Head) => bus.view.find((b) => b.id === h.bu_id)?.name ?? (h.inherited ? "A higher business unit" : h.bu_id);
  return (
    <>
      <h1>{title(section)}</h1>
      <p className="lede">
        {section === "library"
          ? "Assets, asset groups, threat communities and loss profiles, shared down the business unit tree."
          : "Safeguards and their effect on FAIR factors, shared down the business unit tree."}
      </p>
      {bus.edit.length > 0 ? (
        <p className="actions">
          {section === "library" ? (
            LIBRARY_KINDS.map((k) => (
              <a key={k} className="react-aria-Button" href={`/library/new?kind=${k}`}>
                New {KIND_LABELS[k].toLowerCase()}
              </a>
            ))
          ) : (
            <a className="react-aria-Button primary" href="/controls/new">
              New control
            </a>
          )}
        </p>
      ) : null}
      <Section id="entries" title={section === "library" ? "Entries" : "Controls"}>
        <form
          className="filters"
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            const p = new URLSearchParams({ archived: String(f.get("archived") ?? "false") });
            if (f.get("kind")) p.set("kind", String(f.get("kind")));
            window.location.assign(`/${section}?${p.toString()}`);
          }}
        >
          {section === "library" ? (
            <div className="field">
              <label htmlFor="kind">Kind</label>
              <select id="kind" name="kind" defaultValue={kind}>
                <option value="">All kinds</option>
                {LIBRARY_KINDS.map((k) => (
                  <option key={k} value={k}>
                    {KIND_LABELS[k]}
                  </option>
                ))}
              </select>
            </div>
          ) : null}
          <div className="field">
            <label htmlFor="archived">Show</label>
            <select id="archived" name="archived" defaultValue={archived}>
              <option value="false">Active</option>
              <option value="true">Archived</option>
              <option value="all">All</option>
            </select>
          </div>
          <div className="actions">
            <button className="btn" type="submit">
              Apply
            </button>
          </div>
        </form>
        <Status loaded={list}>
          {(data) => {
            const rows = data.entries ?? data.controls ?? [];
            return rows.length === 0 ? (
              <p>Nothing to show.</p>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <caption className="sr-only">{title(section)}, newest first</caption>
                  <thead>
                    <tr>
                      <th scope="col">Name</th>
                      <th scope="col">Kind</th>
                      <th scope="col">Business unit</th>
                      <th scope="col">Version</th>
                      <th scope="col">State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((h) => (
                      <tr key={h.id}>
                        <td>
                          <a href={`/${section}/${h.id}`}>{h.name ?? h.id}</a>
                        </td>
                        <td>{KIND_LABELS[h.kind as LibraryKind] ?? h.kind}</td>
                        <td>
                          {buName(h)} {h.inherited ? <Badge tone="info">Inherited</Badge> : null}
                        </td>
                        <td>{h.current_version}</td>
                        <td>{h.archived_at ? <Badge tone="muted">Archived</Badge> : <Badge tone="ok">Active</Badge>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );
          }}
        </Status>
      </Section>
      {section === "library" ? <Starter bus={bus.edit} /> : null}
    </>
  );
}

/** AC-11: the release's starter library, copied into a BU to adapt. */
function Starter({ bus }: { bus: BU[] }) {
  const starter = useApi<{ entries: StarterEntry[] }>("/api/v1/library/starter");
  return (
    <Section
      id="starter"
      title="Starter library"
      intro="Generic threat communities and guidance for each form of loss, written from Open FAIR concepts. Every number in it is illustrative, not industry data: copy an entry into a business unit and replace them with your own."
    >
      <Status loaded={starter}>
        {(data) => (
          <div className="table-wrap">
            <table className="data">
              <caption className="sr-only">Starter library entries</caption>
              <thead>
                <tr>
                  <th scope="col">Entry</th>
                  <th scope="col">Kind</th>
                  <th scope="col">Guidance</th>
                  <th scope="col">Action</th>
                </tr>
              </thead>
              <tbody>
                {data.entries.map((e) => (
                  <tr key={e.key}>
                    <td>
                      {e.name} {e.illustrative ? <Badge tone="warn">Illustrative values</Badge> : null}
                    </td>
                    <td>{KIND_LABELS[e.kind]}</td>
                    <td>{e.guidance}</td>
                    <td>{bus.length > 0 ? <CopyAction entry={e} bus={bus} /> : <span className="muted">—</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Status>
    </Section>
  );
}

function CopyAction({ entry, bus }: { entry: StarterEntry; bus: BU[] }) {
  const [to, setTo] = useState(bus[0]?.id ?? "");
  const [error, setError] = useState<string>();
  return (
    <DialogTrigger onOpenChange={() => setError(undefined)}>
      <Button aria-label={`Copy ${entry.name}`}>Copy</Button>
      <Modal isDismissable>
        <Dialog>
          {({ close }) => (
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                try {
                  const made = await send<{ id: string }>("POST", `/api/v1/library/starter/${entry.key}/copy`, { bu_id: to });
                  close();
                  window.location.assign(`/library/${made.id}`);
                } catch (err) {
                  setError(err instanceof ApiError && err.code === "currency_not_set" ? "Its amounts need the installation currency, which is not set yet." : describe(err));
                }
              }}
            >
              <Heading slot="title">Copy {entry.name}</Heading>
              <p>The copy is an ordinary library entry, yours to edit; the starter entry does not change.</p>
              <div className="field">
                <label htmlFor="copy-to">Into</label>
                <select id="copy-to" value={to} onChange={(e) => setTo(e.target.value)}>
                  {bus.map((b) => (
                    <option key={b.id} value={b.id}>
                      {b.name}
                    </option>
                  ))}
                </select>
              </div>
              {error ? (
                <p role="alert" className="error-text">
                  {error}
                </p>
              ) : null}
              <div className="actions">
                <Button type="submit" className="react-aria-Button primary">
                  Copy
                </Button>
                <Button slot="close">Cancel</Button>
              </div>
            </form>
          )}
        </Dialog>
      </Modal>
    </DialogTrigger>
  );
}

export function EntryPage({ section, id }: { section: EntrySection; id: string }) {
  const view = useApi<EntryView>(`${api(section)}/${id}`);
  const bus = useBUs(section);
  const doc = view.data?.version.document;
  useEffect(() => {
    document.title = `${doc?.name ?? title(section)} · FAIR Risk Platform`;
  }, [doc?.name, section]);
  return (
    <Status loaded={view}>
      {(v) => {
        const h = (v.entry ?? v.control)!;
        const d = v.version.document!;
        const mayEdit = bus.edit.some((b) => b.id === h.bu_id);
        const where = bus.view.find((b) => b.id === h.bu_id)?.name ?? (h.inherited ? "a higher business unit" : h.bu_id);
        return (
          <>
            <nav aria-label="Breadcrumb" className="crumbs">
              <a href={`/${section}`}>{title(section)}</a>
            </nav>
            <h1>{d.name}</h1>
            <p className="lede">
              {KIND_LABELS[d.kind]} · {where} · version {h.current_version}
              {h.inherited ? (
                <>
                  {" "}
                  · <Badge tone="info">Inherited: read only here</Badge>
                </>
              ) : null}
              {h.archived_at ? (
                <>
                  {" "}
                  · <Badge tone="muted">Archived</Badge>
                </>
              ) : null}
            </p>
            <p className="actions">
              {mayEdit && !h.archived_at && d.kind !== "reference_class" ? (
                <a className="react-aria-Button" href={`/${section}/${id}/edit`}>
                  Edit
                </a>
              ) : null}
              {mayEdit ? <ArchiveAction base={`${api(section)}/${id}`} archived={h.archived_at !== null} what={KIND_LABELS[d.kind].toLowerCase()} onDone={view.reload} /> : null}
              <a href={auditHref(`${section === "library" ? "library" : "control"}:${id}`)}>Audit history of this entry</a>
            </p>
            <Section id="entry" title={KIND_LABELS[d.kind]}>
              <EntrySummary doc={d} currency={v.currency} />
              <p className="muted">
                Last change: {v.version.change_note} ({date(v.version.created_at)})
              </p>
            </Section>
            <History key={h.current_version} base={`${api(section)}/${id}`} current={h.current_version} />
          </>
        );
      }}
    </Status>
  );
}

function EntrySummary({ doc, currency }: { doc: EntryDoc; currency: string | null }) {
  const rows: [string, ReactNode][] = [];
  if (doc.description) rows.push(["Description", doc.description]);
  switch (doc.kind) {
    case "asset":
      rows.push(["Type", doc.asset_type]);
      rows.push(doc.value ? ["Value", showEstimate(doc.value, currency)] : ["Value basis", doc.value_basis]);
      break;
    case "asset_group":
      rows.push(["Members", `${doc.members.length} asset${doc.members.length === 1 ? "" : "s"}`]);
      rows.push(["Valued", doc.valuation === "whole" ? `As a whole: ${showEstimate(doc.value, currency)}` : "By its members"]);
      break;
    case "threat_community":
      rows.push(["Threat capability", showEstimate(doc.threat_capability, currency)]);
      break;
    case "loss_profile":
      for (const f of FORMS) if (doc.magnitudes[f]) rows.push([FORM_LABELS[f], showEstimate(doc.magnitudes[f], currency)]);
      break;
    case "control":
      for (const e of doc.effects) rows.push([`Effect on ${factorName(e.factor)}`, showEstimate(e.estimate, currency)]);
      for (const r of doc.references ?? []) rows.push([r.framework, r.identifier]);
      break;
    case "reference_class":
      rows.push(["Period", `${doc.period.start} to ${doc.period.end}`]);
      if (doc.data.kind === "counts") {
        const total = doc.data.series.reduce((n, s) => n + s.count, 0);
        rows.push(["Events", `${total} in ${doc.data.series.length} period${doc.data.series.length === 1 ? "" : "s"}`]);
      } else {
        rows.push(["Observed losses", `${doc.data.amounts.length} amount${doc.data.amounts.length === 1 ? "" : "s"}${currency ? ` (${currency})` : ""}`]);
      }
      for (const s of doc.sources) rows.push(["Source", s.ref]);
      break;
  }
  return (
    <dl className="summary">
      {rows.map(([k, v], i) => (
        <div key={i}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

function blankDoc(kind: LibraryKind | "control"): EntryDoc {
  const base = { schema_version: 1 as const, name: "" };
  switch (kind) {
    case "asset":
      return { ...base, kind, asset_type: "", value_basis: "" };
    case "asset_group":
      return { ...base, kind, members: [], valuation: "members" };
    case "threat_community":
      return { ...base, kind, threat_capability: newEstimate("percentile") };
    case "loss_profile":
      return { ...base, kind, magnitudes: {} };
    case "control":
      return { ...base, kind, effects: [{ factor: "resistance_strength", estimate: newEstimate("percentile") }] };
  }
}

export function EntryEditor({ section, id, kind }: { section: EntrySection; id?: string; kind?: string }) {
  const view = useApi<EntryView>(id ? `${api(section)}/${id}` : "/api/v1/risk/settings");
  useEffect(() => {
    document.title = `${id ? "Edit" : "New"} ${section === "library" ? "library entry" : "control"} · FAIR Risk Platform`;
  }, [id, section]);
  if (!id) {
    const k = section === "controls" ? "control" : LIBRARY_KINDS.includes(kind as LibraryKind) ? (kind as LibraryKind) : "asset";
    return <EditorForm section={section} initial={blankDoc(k)} />;
  }
  return <Status loaded={view}>{(v) => <EditorForm section={section} initial={v.version.document!} view={v} />}</Status>;
}

function EditorForm({ section, initial, view }: { section: EntrySection; initial: EntryDoc; view?: EntryView }) {
  const [doc, setDoc] = useState<EntryDoc>(initial);
  const [note, setNote] = useState("");
  const [problems, setProblems] = useState<Problem[]>([]);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const bus = useBUs(section);
  const [bu, setBU] = useState("");
  const settings = useApi<{ currency: string | null }>("/api/v1/risk/settings");
  const assets = useApi<{ entries: Head[] }>("/api/v1/library?kind=asset");
  const currency = settings.data?.currency ?? null;
  const h = view?.entry ?? view?.control;
  const set = (patch: Partial<EntryDoc>) => setDoc((d) => ({ ...d, ...patch }) as EntryDoc);
  useEffect(() => {
    const first = bus.edit[0];
    if (!bu && first) setBU(first.id);
  }, [bus.edit, bu]);

  const submit = async () => {
    setProblems([]);
    setError(undefined);
    setBusy(true);
    try {
      const saved = h
        ? await send<{ id: string }>("PUT", `${api(section)}/${h.id}`, { document: doc, expected_version: h.current_version, change_note: note })
        : await send<{ id: string }>("POST", api(section), section === "library" ? { bu_id: bu, kind: doc.kind, document: doc, change_note: note } : { bu_id: bu, document: doc, change_note: note });
      window.location.assign(`/${section}/${saved.id}`);
    } catch (err) {
      const listed = err instanceof ApiError && err.status === 422 ? (err.body as { problems?: Problem[] } | undefined)?.problems : undefined;
      if (listed && listed.length > 0) setProblems(listed);
      else setError(describe(err));
    } finally {
      setBusy(false);
    }
  };

  const text = (label: string, pointer: string, value: string | undefined, onChange: (v: string) => void, multiline = false) => (
    <div className="field">
      <label htmlFor={fieldId(pointer)}>{label}</label>
      {multiline ? (
        <textarea id={fieldId(pointer)} rows={2} value={value ?? ""} onChange={(e) => onChange(e.target.value)} />
      ) : (
        <input id={fieldId(pointer)} value={value ?? ""} onChange={(e) => onChange(e.target.value)} />
      )}
    </div>
  );

  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href={`/${section}`}>{title(section)}</a>
      </nav>
      <h1>{h ? `Edit ${initial.name}` : `New ${KIND_LABELS[doc.kind].toLowerCase()}`}</h1>
      <div tabIndex={-1} aria-live="assertive">
        {error ? (
          <p role="alert" className="error-text">
            {error}
          </p>
        ) : null}
        {problems.length > 0 ? (
          <div role="alert" className="banner">
            <h2>Not saved</h2>
            <ul>
              {problems.map((p, i) => (
                <li key={i}>
                  <a href={`#${fieldId(p.pointer)}`}>{p.pointer || "The entry"}</a>: {p.message}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
      <form
        className="editor"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Section id="entry-fields" title={KIND_LABELS[doc.kind]}>
          {h ? null : (
            <div className="field">
              <label htmlFor="bu">Business unit</label>
              <select id="bu" value={bu} onChange={(e) => setBU(e.target.value)}>
                {bus.edit.map((b) => (
                  <option key={b.id} value={b.id}>
                    {b.name}
                  </option>
                ))}
              </select>
            </div>
          )}
          {text("Name", "/name", doc.name, (name) => set({ name }))}
          {text("Description (optional)", "/description", doc.description, (v) => set({ description: v || undefined }), true)}
          {doc.kind === "asset" ? (
            <AssetFields doc={doc} currency={currency} set={set} text={text} />
          ) : doc.kind === "asset_group" ? (
            <GroupFields doc={doc} currency={currency} assets={assets.data?.entries ?? []} set={set} />
          ) : doc.kind === "threat_community" ? (
            <EstimateFields legend="Threat capability" pointer="/threat_capability" value={doc.threat_capability} currency={currency} onChange={(e) => set({ threat_capability: e } as Partial<ThreatCommunityDoc>)} />
          ) : doc.kind === "loss_profile" ? (
            <LossFields doc={doc} currency={currency} set={set} />
          ) : doc.kind === "control" ? (
            <ControlFields doc={doc} currency={currency} set={set} />
          ) : (
            <p>Reference classes are edited through the API for now.</p>
          )}
        </Section>
        <Section id="save" title="Save">
          <div className="field">
            <label htmlFor="change-note">Change note</label>
            <textarea id="change-note" rows={2} value={note} onChange={(e) => setNote(e.target.value)} />
          </div>
          <div className="actions">
            <button type="submit" className="btn primary" disabled={busy}>
              {h ? "Save a new version" : `Create the ${KIND_LABELS[doc.kind].toLowerCase()}`}
            </button>
            <a href={h ? `/${section}/${h.id}` : `/${section}`}>Cancel</a>
          </div>
        </Section>
      </form>
    </>
  );
}

type TextField = (label: string, pointer: string, value: string | undefined, onChange: (v: string) => void, multiline?: boolean) => ReactNode;

function AssetFields({ doc, currency, set, text }: { doc: AssetDoc; currency: string | null; set: (p: Partial<EntryDoc>) => void; text: TextField }) {
  const valued = doc.value !== undefined;
  return (
    <>
      {text("Asset type", "/asset_type", doc.asset_type, (asset_type) => set({ asset_type } as Partial<AssetDoc>))}
      <fieldset className="checks">
        <legend>Value</legend>
        <label>
          <input type="radio" name="valued" checked={!valued} onChange={() => set({ value: undefined, value_basis: "" } as Partial<AssetDoc>)} /> Described in words
        </label>
        <label>
          <input type="radio" name="valued" checked={valued} onChange={() => set({ value: newEstimate("currency"), value_basis: undefined } as Partial<AssetDoc>)} /> Estimated
        </label>
      </fieldset>
      {valued ? (
        <EstimateFields legend="Value" pointer="/value" value={doc.value!} currency={currency} onChange={(value) => set({ value } as Partial<AssetDoc>)} />
      ) : (
        text("Value basis", "/value_basis", doc.value_basis, (value_basis) => set({ value_basis } as Partial<AssetDoc>), true)
      )}
    </>
  );
}

function GroupFields({ doc, currency, assets, set }: { doc: AssetGroupDoc; currency: string | null; assets: Head[]; set: (p: Partial<EntryDoc>) => void }) {
  return (
    <>
      <fieldset className="checks" id={fieldId("/members")}>
        <legend>Member assets</legend>
        {assets.length === 0 ? <p className="muted">No assets to choose from.</p> : null}
        {assets.map((a) => (
          <label key={a.id}>
            <input
              type="checkbox"
              checked={doc.members.some((m) => m.id === a.id)}
              onChange={(e) =>
                set({ members: e.target.checked ? [...doc.members, { id: a.id, version: a.current_version }] : doc.members.filter((m) => m.id !== a.id) } as Partial<AssetGroupDoc>)
              }
            />{" "}
            {a.name ?? a.id}
          </label>
        ))}
      </fieldset>
      <fieldset className="checks">
        <legend>Valued</legend>
        <label>
          <input type="radio" name="valuation" checked={doc.valuation === "members"} onChange={() => set({ valuation: "members", value: undefined } as Partial<AssetGroupDoc>)} /> By its members
        </label>
        <label>
          <input type="radio" name="valuation" checked={doc.valuation === "whole"} onChange={() => set({ valuation: "whole", value: newEstimate("currency") } as Partial<AssetGroupDoc>)} /> As a whole
        </label>
      </fieldset>
      {doc.valuation === "whole" && doc.value ? <EstimateFields legend="Value" pointer="/value" value={doc.value} currency={currency} onChange={(value) => set({ value } as Partial<AssetGroupDoc>)} /> : null}
    </>
  );
}

function LossFields({ doc, currency, set }: { doc: LossProfileDoc; currency: string | null; set: (p: Partial<EntryDoc>) => void }) {
  const m = doc.magnitudes;
  return (
    <>
      <fieldset className="checks" id={fieldId("/magnitudes")}>
        <legend>Forms of loss</legend>
        {FORMS.map((f) => (
          <label key={f}>
            <input
              type="checkbox"
              checked={m[f] !== undefined}
              onChange={(e) => {
                const next = { ...m };
                if (e.target.checked) next[f] = newEstimate("currency");
                else delete next[f];
                set({ magnitudes: next } as Partial<LossProfileDoc>);
              }}
            />{" "}
            {FORM_LABELS[f]}
          </label>
        ))}
      </fieldset>
      {FORMS.filter((f) => m[f]).map((f: Form) => (
        <EstimateFields key={f} legend={FORM_LABELS[f]} pointer={`/magnitudes/${f}`} value={m[f]!} currency={currency} onChange={(e) => set({ magnitudes: { ...m, [f]: e } } as Partial<LossProfileDoc>)} />
      ))}
    </>
  );
}

function ControlFields({ doc, currency, set }: { doc: ControlDoc; currency: string | null; set: (p: Partial<EntryDoc>) => void }) {
  const effects = doc.effects;
  const refs = doc.references ?? [];
  return (
    <>
      <h3>Effects</h3>
      {effects.map((e, i) => (
        <fieldset key={i} className="group">
          <legend>Effect {i + 1}</legend>
          <div className="field">
            <label htmlFor={fieldId(`/effects/${i}/factor`)}>Factor affected</label>
            <select
              id={fieldId(`/effects/${i}/factor`)}
              value={e.factor}
              onChange={(ev) => set({ effects: effects.map((x, j) => (j === i ? { factor: ev.target.value, estimate: newEstimate(effectUnit(ev.target.value)) } : x)) } as Partial<ControlDoc>)}
            >
              {FACTORS.map((f) => (
                <option key={f} value={f}>
                  {factorName(f)}
                  {f === "resistance_strength" ? " (provided)" : " (reduced)"}
                </option>
              ))}
            </select>
          </div>
          <EstimateFields
            legend={e.factor === "resistance_strength" ? "Resistance strength provided" : `Reduction of ${factorName(e.factor).toLowerCase()}`}
            pointer={`/effects/${i}/estimate`}
            value={e.estimate}
            currency={currency}
            onChange={(est) => set({ effects: effects.map((x, j) => (j === i ? { ...x, estimate: est } : x)) } as Partial<ControlDoc>)}
          />
          {effects.length > 1 ? (
            <button type="button" className="btn" onClick={() => set({ effects: effects.filter((_, j) => j !== i) } as Partial<ControlDoc>)}>
              Remove effect {i + 1}
            </button>
          ) : null}
        </fieldset>
      ))}
      <button type="button" className="btn" onClick={() => set({ effects: [...effects, { factor: "contact_frequency", estimate: newEstimate("fraction") }] } as Partial<ControlDoc>)}>
        Add an effect
      </button>
      <h3>Framework references</h3>
      {refs.map((r, i) => (
        <div className="grid" key={i}>
          <div className="field">
            <label htmlFor={fieldId(`/references/${i}/framework`)}>Framework {i + 1}</label>
            <input
              id={fieldId(`/references/${i}/framework`)}
              value={r.framework}
              onChange={(e) => set({ references: refs.map((x, j) => (j === i ? { ...x, framework: e.target.value } : x)) } as Partial<ControlDoc>)}
            />
          </div>
          <div className="field">
            <label htmlFor={fieldId(`/references/${i}/identifier`)}>Identifier {i + 1}</label>
            <input
              id={fieldId(`/references/${i}/identifier`)}
              value={r.identifier}
              onChange={(e) => set({ references: refs.map((x, j) => (j === i ? { ...x, identifier: e.target.value } : x)) } as Partial<ControlDoc>)}
            />
          </div>
          <div className="field">
            <button type="button" className="btn" onClick={() => set({ references: refs.filter((_, j) => j !== i) } as Partial<ControlDoc>)}>
              Remove reference {i + 1}
            </button>
          </div>
        </div>
      ))}
      <button type="button" className="btn" onClick={() => set({ references: [...refs, { framework: "", identifier: "" }] } as Partial<ControlDoc>)}>
        Add a framework reference
      </button>
    </>
  );
}
