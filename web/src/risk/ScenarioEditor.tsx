import { useEffect, useRef, useState, type ReactNode } from "react";
import { ApiError, describe, send } from "../api";
import { Section, Status, useApi } from "../components";
import { EstimateFields, fieldId, newEstimate } from "./EstimateFields";
import {
  EFFECTS,
  FORMS,
  FORM_LABELS,
  type BU,
  type Estimate,
  type Form,
  type Head,
  type Problem,
  type ScenarioDoc,
  type ScenarioView,
} from "./types";

// F-003 T-12 (AC-01 to AC-06, AC-12, AC-13, AC-27, AC-29): creating a
// scenario and saving new versions. The analyst picks, per branch, the
// level the scenario is estimated at; the form then asks for exactly the
// estimates that level needs. A refused save lists every problem, each
// linked to its field.

type Entries = { entries: Head[] };
type Controls = { controls: Head[] };

function blank(owner: string): ScenarioDoc {
  const y = new Date().getUTCFullYear();
  return {
    kind: "scenario",
    schema_version: 1,
    name: "",
    scope: { in: "" },
    analysis_period: { start: `${y}-01-01`, end: `${y}-12-31` },
    owner,
    asset: { kind: "asset", id: "", version: 1 },
    threat_community: { id: "", version: 1 },
    threat_effects: [],
    loss_event: "",
    lef: { level: "lef", estimate: newEstimate("events_per_year") },
    primary_loss: {},
    control_sets: [{ name: "Current", current: true, controls: [] }],
  };
}

export function ScenarioEditor({ id }: { id?: string }) {
  const existing = useApi<ScenarioView>(id ? `/api/v1/scenarios/${id}` : "/api/v1/me");
  const me = useApi<{ user_id: string }>("/api/v1/me");
  useEffect(() => {
    document.title = `${id ? "Edit scenario" : "New scenario"} · FAIR Risk Platform`;
  }, [id]);
  if (!id) {
    return <Status loaded={me}>{(m) => <Form initial={blank(m.user_id)} />}</Status>;
  }
  return <Status loaded={existing}>{(v) => <Form initial={(v as ScenarioView).version.document!} view={v as ScenarioView} />}</Status>;
}

function Form({ initial, view }: { initial: ScenarioDoc; view?: ScenarioView }) {
  const [doc, setDoc] = useState<ScenarioDoc>(initial);
  const [bu, setBU] = useState("");
  const [note, setNote] = useState("");
  const [problems, setProblems] = useState<Problem[]>([]);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const summary = useRef<HTMLDivElement>(null);
  const bus = useApi<{ bus: BU[] }>("/api/v1/risk/bus?permission=scenario.edit");
  const assets = useApi<Entries>("/api/v1/library?kind=asset");
  const groups = useApi<Entries>("/api/v1/library?kind=asset_group");
  const communities = useApi<Entries>("/api/v1/library?kind=threat_community");
  const controls = useApi<Controls>("/api/v1/controls");
  const settings = useApi<{ currency: string | null }>("/api/v1/risk/settings");
  const currency = settings.data?.currency ?? null;
  const set = (patch: Partial<ScenarioDoc>) => setDoc((d) => ({ ...d, ...patch }));
  const lef = doc.lef;
  const setLEF = (patch: Partial<ScenarioDoc["lef"]>) => set({ lef: { ...lef, ...patch } });

  useEffect(() => {
    const first = bus.data?.bus[0];
    if (!bu && first) setBU(first.id);
  }, [bus.data, bu]);
  useEffect(() => {
    if (problems.length > 0 || error) summary.current?.focus();
  }, [problems, error]);

  const entryOptions = (list: Head[] | undefined) =>
    (list ?? []).map((e) => (
      <option key={e.id} value={e.id}>
        {e.name ?? e.id}
        {e.inherited ? " (inherited)" : ""}
      </option>
    ));
  const versionOf = (list: Head[] | undefined, entry: string) => list?.find((e) => e.id === entry)?.current_version ?? 1;

  const submit = async () => {
    setProblems([]);
    setError(undefined);
    setBusy(true);
    try {
      const body = view
        ? { document: doc, expected_version: view.scenario.current_version, change_note: note }
        : { bu_id: bu, document: doc, change_note: note };
      const saved = view
        ? await send<{ id: string }>("PUT", `/api/v1/scenarios/${view.scenario.id}`, body)
        : await send<{ id: string }>("POST", "/api/v1/scenarios", body);
      window.location.assign(`/scenarios/${saved.id}`);
    } catch (err) {
      const listed = err instanceof ApiError && err.status === 422 ? (err.body as { problems?: Problem[] } | undefined)?.problems : undefined;
      if (listed && listed.length > 0) {
        setProblems(listed);
      } else if (err instanceof ApiError && err.code === "currency_not_set") {
        setError("Amounts cannot be saved until an administrator sets the installation currency.");
      } else {
        setError(describe(err));
      }
    } finally {
      setBusy(false);
    }
  };

  const lossPicker = (value: Partial<Record<Form, Estimate>>, pointer: string, onChange: (v: Partial<Record<Form, Estimate>>) => void) => (
    <>
      <fieldset className="checks">
        <legend>Forms of loss</legend>
        {FORMS.map((f) => (
          <label key={f}>
            <input
              type="checkbox"
              checked={value[f] !== undefined}
              onChange={(e) => {
                const next = { ...value };
                if (e.target.checked) next[f] = newEstimate("currency");
                else delete next[f];
                onChange(next);
              }}
            />{" "}
            {FORM_LABELS[f]}
          </label>
        ))}
      </fieldset>
      {FORMS.filter((f) => value[f]).map((f) => (
        <EstimateFields key={f} legend={FORM_LABELS[f]} pointer={`${pointer}/${f}`} value={value[f]!} currency={currency} onChange={(e) => onChange({ ...value, [f]: e })} />
      ))}
    </>
  );

  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/scenarios">Scenarios</a>
        {view ? (
          <>
            {" / "}
            <a href={`/scenarios/${view.scenario.id}`}>{initial.name}</a>
          </>
        ) : null}
      </nav>
      <h1>{view ? `Edit ${initial.name}` : "New scenario"}</h1>
      <div ref={summary} tabIndex={-1} aria-live="assertive">
        {error ? (
          <p role="alert" className="error-text">
            {error}
          </p>
        ) : null}
        {problems.length > 0 ? (
          <div role="alert" className="banner">
            <h2>The scenario was not saved</h2>
            <ul>
              {problems.map((p, i) => (
                <li key={i}>
                  <a href={`#${fieldId(p.pointer)}`}>{p.pointer || "The scenario"}</a>: {p.message}
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
        <Section id="what" title="The scenario">
          {view ? null : (
            <Field label="Business unit" id="bu">
              <select id="bu" value={bu} onChange={(e) => setBU(e.target.value)}>
                {(bus.data?.bus ?? []).map((b) => (
                  <option key={b.id} value={b.id}>
                    {b.name}
                  </option>
                ))}
              </select>
            </Field>
          )}
          <Field label="Name" id={fieldId("/name")}>
            <input id={fieldId("/name")} value={doc.name} required onChange={(e) => set({ name: e.target.value })} />
          </Field>
          <Field label="Description (optional)" id={fieldId("/description")}>
            <textarea id={fieldId("/description")} rows={2} value={doc.description ?? ""} onChange={(e) => set({ description: e.target.value || undefined })} />
          </Field>
          <Field label="Loss event" id={fieldId("/loss_event")}>
            <textarea id={fieldId("/loss_event")} rows={2} value={doc.loss_event} required onChange={(e) => set({ loss_event: e.target.value })} />
          </Field>
          <Field label="In scope" id={fieldId("/scope/in")}>
            <textarea id={fieldId("/scope/in")} rows={2} value={doc.scope.in} required onChange={(e) => set({ scope: { ...doc.scope, in: e.target.value } })} />
          </Field>
          <Field label="Out of scope (optional)" id={fieldId("/scope/out")}>
            <textarea id={fieldId("/scope/out")} rows={2} value={doc.scope.out ?? ""} onChange={(e) => set({ scope: { ...doc.scope, out: e.target.value || undefined } })} />
          </Field>
          <div className="grid">
            <Field label="Analysis period starts" id={fieldId("/analysis_period/start")}>
              <input id={fieldId("/analysis_period/start")} type="date" value={doc.analysis_period.start} onChange={(e) => set({ analysis_period: { ...doc.analysis_period, start: e.target.value } })} />
            </Field>
            <Field label="Analysis period ends" id={fieldId("/analysis_period/end")}>
              <input id={fieldId("/analysis_period/end")} type="date" value={doc.analysis_period.end} onChange={(e) => set({ analysis_period: { ...doc.analysis_period, end: e.target.value } })} />
            </Field>
          </div>
          <fieldset className="checks" id={fieldId("/threat_effects")}>
            <legend>Threat effects</legend>
            {EFFECTS.map((t) => (
              <label key={t}>
                <input
                  type="checkbox"
                  checked={doc.threat_effects.includes(t)}
                  onChange={(e) => set({ threat_effects: e.target.checked ? [...doc.threat_effects, t] : doc.threat_effects.filter((x) => x !== t) })}
                />{" "}
                {t.charAt(0).toUpperCase() + t.slice(1)}
              </label>
            ))}
          </fieldset>
          <div className="grid">
            <Field label="Asset kind" id="asset-kind">
              <select id="asset-kind" value={doc.asset.kind} onChange={(e) => set({ asset: { kind: e.target.value as "asset" | "asset_group", id: "", version: 1 } })}>
                <option value="asset">An asset</option>
                <option value="asset_group">An asset group</option>
              </select>
            </Field>
            <Field label={doc.asset.kind === "asset" ? "Asset" : "Asset group"} id={fieldId("/asset/id")}>
              <select
                id={fieldId("/asset/id")}
                value={doc.asset.id}
                onChange={(e) => {
                  const list = doc.asset.kind === "asset" ? assets.data?.entries : groups.data?.entries;
                  set({ asset: { ...doc.asset, id: e.target.value, version: versionOf(list, e.target.value) } });
                }}
              >
                <option value="">Choose…</option>
                {entryOptions(doc.asset.kind === "asset" ? assets.data?.entries : groups.data?.entries)}
              </select>
            </Field>
            <Field label="Threat community" id={fieldId("/threat_community/id")}>
              <select
                id={fieldId("/threat_community/id")}
                value={doc.threat_community.id}
                onChange={(e) => set({ threat_community: { id: e.target.value, version: versionOf(communities.data?.entries, e.target.value) } })}
              >
                <option value="">Choose…</option>
                {entryOptions(communities.data?.entries)}
              </select>
            </Field>
          </div>
        </Section>

        <Section id="frequency" title="Loss event frequency" intro="Estimate it directly, or from threat event frequency and Vulnerability.">
          <Radios
            name="lef-level"
            legend="Estimate loss event frequency"
            value={lef.level}
            options={[
              ["lef", "Directly"],
              ["tef_vuln", "From threat event frequency and Vulnerability"],
            ]}
            onChange={(level) =>
              setLEF(
                level === "lef"
                  ? { level: "lef", estimate: newEstimate("events_per_year"), tef: undefined, vulnerability: undefined }
                  : {
                      level: "tef_vuln",
                      estimate: undefined,
                      tef: { level: "tef", estimate: newEstimate("events_per_year") },
                      vulnerability: { level: "direct", estimate: newEstimate("probability") },
                    },
              )
            }
          />
          {lef.level === "lef" && lef.estimate ? (
            <EstimateFields legend="Loss event frequency" pointer="/lef/estimate" value={lef.estimate} currency={currency} onChange={(e) => setLEF({ estimate: e })} />
          ) : null}
          {lef.level === "tef_vuln" && lef.tef && lef.vulnerability ? (
            <>
              <h3>Threat event frequency</h3>
              <Radios
                name="tef-level"
                legend="Estimate threat event frequency"
                value={lef.tef.level}
                options={[
                  ["tef", "Directly"],
                  ["cf_poa", "From contact frequency and probability of action"],
                ]}
                onChange={(level) =>
                  setLEF({
                    tef:
                      level === "tef"
                        ? { level: "tef", estimate: newEstimate("events_per_year") }
                        : { level: "cf_poa", contact_frequency: newEstimate("events_per_year"), probability_of_action: newEstimate("probability") },
                  })
                }
              />
              {lef.tef.level === "tef" && lef.tef.estimate ? (
                <EstimateFields legend="Threat event frequency" pointer="/lef/tef/estimate" value={lef.tef.estimate} currency={currency} onChange={(e) => setLEF({ tef: { ...lef.tef!, estimate: e } })} />
              ) : null}
              {lef.tef.level === "cf_poa" && lef.tef.contact_frequency && lef.tef.probability_of_action ? (
                <>
                  <EstimateFields legend="Contact frequency" pointer="/lef/tef/contact_frequency" value={lef.tef.contact_frequency} currency={currency} onChange={(e) => setLEF({ tef: { ...lef.tef!, contact_frequency: e } })} />
                  <EstimateFields legend="Probability of action" pointer="/lef/tef/probability_of_action" value={lef.tef.probability_of_action} currency={currency} onChange={(e) => setLEF({ tef: { ...lef.tef!, probability_of_action: e } })} />
                </>
              ) : null}
              <h3>Vulnerability</h3>
              <Radios
                name="vuln-level"
                legend="Estimate Vulnerability"
                value={lef.vulnerability.level}
                options={[
                  ["direct", "Directly, as a probability"],
                  ["derived", "From threat capability against resistance strength"],
                ]}
                onChange={(level) =>
                  setLEF({
                    vulnerability:
                      level === "direct"
                        ? { level: "direct", estimate: newEstimate("probability") }
                        : { level: "derived", threat_capability: { source: "threat_community" }, resistance_strength: newEstimate("percentile") },
                  })
                }
              />
              {lef.vulnerability.level === "direct" && lef.vulnerability.estimate ? (
                <EstimateFields legend="Vulnerability" pointer="/lef/vulnerability/estimate" value={lef.vulnerability.estimate} currency={currency} onChange={(e) => setLEF({ vulnerability: { ...lef.vulnerability!, estimate: e } })} />
              ) : null}
              {lef.vulnerability.level === "derived" && lef.vulnerability.threat_capability && lef.vulnerability.resistance_strength ? (
                <>
                  <Radios
                    name="tcap-source"
                    legend="Threat capability"
                    value={lef.vulnerability.threat_capability.source}
                    options={[
                      ["threat_community", "The threat community's estimate"],
                      ["scenario", "Estimated for this scenario"],
                    ]}
                    onChange={(source) =>
                      setLEF({
                        vulnerability: {
                          ...lef.vulnerability!,
                          threat_capability: source === "scenario" ? { source: "scenario", estimate: newEstimate("percentile") } : { source: "threat_community" },
                        },
                      })
                    }
                  />
                  {lef.vulnerability.threat_capability.estimate ? (
                    <EstimateFields
                      legend="Threat capability"
                      pointer="/lef/vulnerability/threat_capability/estimate"
                      value={lef.vulnerability.threat_capability.estimate}
                      currency={currency}
                      onChange={(e) => setLEF({ vulnerability: { ...lef.vulnerability!, threat_capability: { source: "scenario", estimate: e } } })}
                    />
                  ) : null}
                  <EstimateFields legend="Resistance strength" pointer="/lef/vulnerability/resistance_strength" value={lef.vulnerability.resistance_strength} currency={currency} onChange={(e) => setLEF({ vulnerability: { ...lef.vulnerability!, resistance_strength: e } })} />
                </>
              ) : null}
            </>
          ) : null}
        </Section>

        <Section id="magnitude" title="Primary loss" intro={`Per form of loss, in ${currency ?? "the installation currency (not set yet)"}.`}>
          {lossPicker(doc.primary_loss, "/primary_loss", (v) => set({ primary_loss: v }))}
        </Section>

        <Section id="secondary" title="Secondary risk" intro="Losses from secondary stakeholders' reactions (regulators, customers, partners), per stakeholder group.">
          {(doc.secondary_risk ?? []).map((g, i) => (
            <fieldset key={i} className="group">
              <legend>Stakeholder group {i + 1}</legend>
              <Field label="Stakeholders" id={fieldId(`/secondary_risk/${i}/stakeholder`)}>
                <input
                  id={fieldId(`/secondary_risk/${i}/stakeholder`)}
                  value={g.stakeholder}
                  onChange={(e) => set({ secondary_risk: doc.secondary_risk!.map((x, j) => (j === i ? { ...x, stakeholder: e.target.value } : x)) })}
                />
              </Field>
              <EstimateFields
                legend="Secondary loss event frequency (probability per loss event)"
                pointer={`/secondary_risk/${i}/slef`}
                value={g.slef}
                currency={currency}
                onChange={(e) => set({ secondary_risk: doc.secondary_risk!.map((x, j) => (j === i ? { ...x, slef: e } : x)) })}
              />
              {lossPicker(g.loss, `/secondary_risk/${i}/loss`, (v) => set({ secondary_risk: doc.secondary_risk!.map((x, j) => (j === i ? { ...x, loss: v } : x)) }))}
              <button type="button" className="btn" onClick={() => set({ secondary_risk: doc.secondary_risk!.filter((_, j) => j !== i) })}>
                Remove stakeholder group {i + 1}
              </button>
            </fieldset>
          ))}
          <button
            type="button"
            className="btn"
            onClick={() => set({ secondary_risk: [...(doc.secondary_risk ?? []), { stakeholder: "", slef: newEstimate("probability"), loss: {} }] })}
          >
            Add a stakeholder group
          </button>
        </Section>

        <Section id="controls" title="Controls" intro="The controls in place now, and alternative sets to compare (AC-13).">
          {doc.control_sets.map((cs, i) => (
            <fieldset key={i} className="group">
              <legend>{cs.current ? "Current controls" : `Alternative: ${cs.name || `set ${i + 1}`}`}</legend>
              {cs.current ? null : (
                <Field label="Name of this set" id={fieldId(`/control_sets/${i}/name`)}>
                  <input
                    id={fieldId(`/control_sets/${i}/name`)}
                    value={cs.name}
                    onChange={(e) => set({ control_sets: doc.control_sets.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)) })}
                  />
                </Field>
              )}
              {(controls.data?.controls ?? []).length === 0 ? <p className="muted">No controls to choose from.</p> : null}
              {(controls.data?.controls ?? []).map((c) => {
                const use = cs.controls.find((u) => u.id === c.id);
                const update = (next: typeof cs.controls) => set({ control_sets: doc.control_sets.map((x, j) => (j === i ? { ...x, controls: next } : x)) });
                return (
                  <div className="grid" key={c.id}>
                    <label>
                      <input
                        type="checkbox"
                        checked={use !== undefined}
                        onChange={(e) => update(e.target.checked ? [...cs.controls, { id: c.id, version: c.current_version, status: "in_place" }] : cs.controls.filter((u) => u.id !== c.id))}
                      />{" "}
                      {c.name ?? c.id}
                    </label>
                    {use ? (
                      <div className="field">
                        <label htmlFor={`cs-${i}-${c.id}`}>Status of {c.name ?? c.id}</label>
                        <select id={`cs-${i}-${c.id}`} value={use.status} onChange={(e) => update(cs.controls.map((u) => (u.id === c.id ? { ...u, status: e.target.value as "in_place" | "proposed" } : u)))}>
                          <option value="in_place">In place</option>
                          <option value="proposed">Proposed</option>
                        </select>
                      </div>
                    ) : null}
                  </div>
                );
              })}
              {cs.current ? null : (
                <button type="button" className="btn" onClick={() => set({ control_sets: doc.control_sets.filter((_, j) => j !== i) })}>
                  Remove this alternative
                </button>
              )}
            </fieldset>
          ))}
          <button
            type="button"
            className="btn"
            onClick={() => set({ control_sets: [...doc.control_sets, { name: `Alternative ${doc.control_sets.length}`, current: false, controls: [] }] })}
          >
            Add an alternative control set
          </button>
        </Section>

        <Section id="save" title="Save">
          <Field label="Change note" id="change-note">
            <textarea id="change-note" rows={2} value={note} required onChange={(e) => setNote(e.target.value)} />
          </Field>
          <div className="actions">
            <button type="submit" className="btn primary" disabled={busy}>
              {view ? "Save a new version" : "Create the scenario"}
            </button>
            <a href={view ? `/scenarios/${view.scenario.id}` : "/scenarios"}>Cancel</a>
          </div>
        </Section>
      </form>
    </>
  );
}

function Field({ label, id, children }: { label: string; id: string; children: ReactNode }) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {children}
    </div>
  );
}

function Radios({
  name,
  legend,
  value,
  options,
  onChange,
}: {
  name: string;
  legend: string;
  value: string;
  options: [string, string][];
  onChange: (v: string) => void;
}) {
  return (
    <fieldset className="checks">
      <legend>{legend}</legend>
      {options.map(([v, label]) => (
        <label key={v}>
          <input type="radio" name={name} value={v} checked={value === v} onChange={() => onChange(v)} /> {label}
        </label>
      ))}
    </fieldset>
  );
}

