import { useState } from "react";
import { Section, useApi } from "../components";
import { fieldId } from "../risk/EstimateFields";
import { STRENGTH_LABELS, reqName, type Addressed, type Family, type Mapping, type MappingUpdate, type Suggestion } from "./types";

// F-013 T-10 (F-013-AC-07 to AC-09, AC-18): a control's framework mappings
// in its editor (saved with the control's version), with suggestions from
// its plain references and moves to newer framework versions; the mappings
// on the control's page; the requirements a register risk's scenarios
// address.

type Listing = { frameworks: Family[] };

/** The mapping fields of the control editor. id is the control's (absent for a new one). */
export function MappingFields({ id, mappings, onChange }: { id?: string; mappings: Mapping[]; onChange: (m: Mapping[]) => void }) {
  const fw = useApi<Listing>("/api/v1/frameworks");
  const suggestions = useApi<{ suggestions: Suggestion[] }>(id ? `/api/v1/controls/${id}/suggested-mappings` : null);
  const updates = useApi<{ updates: MappingUpdate[] }>(id ? `/api/v1/controls/${id}/mapping-updates` : null);
  const families = fw.data?.frameworks ?? [];
  const versionsOf = (key: string) => families.find((f) => f.key === key)?.versions ?? [];
  const put = (i: number, patch: Partial<Mapping>) => onChange(mappings.map((m, j) => (j === i ? { ...m, ...patch } : m)));
  const has = (m: { framework: string; version: string; requirement: string }) =>
    mappings.some((x) => x.framework === m.framework && x.version === m.version && x.requirement === m.requirement);
  const pending = (suggestions.data?.suggestions ?? []).filter((s) => !has(s));
  return (
    <>
      <h3>Framework mappings</h3>
      <p className="muted">
        The requirements this control addresses, saved with the control's version. Strength says how much of a requirement it meets; only
        full mappings to controls in place count as in place in coverage.
      </p>
      {mappings.map((m, i) => (
        <fieldset key={i} className="group">
          <legend>Mapping {i + 1}</legend>
          <div className="grid">
            <div className="field">
              <label htmlFor={fieldId(`/mappings/${i}/framework`)}>Framework</label>
              <select
                id={fieldId(`/mappings/${i}/framework`)}
                value={m.framework}
                onChange={(e) => put(i, { framework: e.target.value, version: versionsOf(e.target.value)[0]?.label ?? "" })}
              >
                {m.framework && !families.some((f) => f.key === m.framework) ? <option value={m.framework}>{m.framework}</option> : null}
                {families.map((f) => (
                  <option key={f.key} value={f.key}>
                    {f.title}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor={fieldId(`/mappings/${i}/version`)}>Version</label>
              <select id={fieldId(`/mappings/${i}/version`)} value={m.version} onChange={(e) => put(i, { version: e.target.value })}>
                {m.version && !versionsOf(m.framework).some((v) => v.label === m.version) ? <option value={m.version}>{m.version}</option> : null}
                {versionsOf(m.framework).map((v) => (
                  <option key={v.id} value={v.label}>
                    {v.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor={fieldId(`/mappings/${i}/requirement`)}>Requirement identifier</label>
              <input id={fieldId(`/mappings/${i}/requirement`)} value={m.requirement} onChange={(e) => put(i, { requirement: e.target.value.trim() })} />
            </div>
            <div className="field">
              <label htmlFor={fieldId(`/mappings/${i}/strength`)}>Strength</label>
              <select id={fieldId(`/mappings/${i}/strength`)} value={m.strength} onChange={(e) => put(i, { strength: e.target.value as Mapping["strength"] })}>
                {(["full", "partial", "supports"] as const).map((s) => (
                  <option key={s} value={s}>
                    {STRENGTH_LABELS[s]}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="field">
            <label htmlFor={fieldId(`/mappings/${i}/rationale`)}>Rationale (optional)</label>
            <textarea id={fieldId(`/mappings/${i}/rationale`)} rows={2} value={m.rationale ?? ""} onChange={(e) => put(i, { rationale: e.target.value || undefined })} />
          </div>
          <button type="button" className="btn" onClick={() => onChange(mappings.filter((_, j) => j !== i))}>
            Remove mapping {i + 1}
          </button>
        </fieldset>
      ))}
      <button
        type="button"
        className="btn"
        onClick={() => {
          const f = families[0];
          onChange([...mappings, { framework: f?.key ?? "", version: f?.versions[0]?.label ?? "", requirement: "", strength: "full" }]);
        }}
      >
        Add a mapping
      </button>
      {pending.length > 0 ? (
        <div className="card" role="region" aria-label="Suggested mappings">
          <h4>Suggested from the control's references</h4>
          <ul>
            {pending.map((s) => (
              <li key={`${s.framework}-${s.version}-${s.requirement}`}>
                {s.framework} {s.version} {reqName({ identifier: s.requirement, label: s.label })} {s.title}{" "}
                <button
                  type="button"
                  className="btn"
                  onClick={() => onChange([...mappings, { framework: s.framework, version: s.version, requirement: s.requirement, strength: "full" }])}
                >
                  Add {reqName({ identifier: s.requirement, label: s.label })}
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {(updates.data?.updates ?? []).length > 0 ? (
        <div className="card" role="region" aria-label="Newer framework versions">
          <h4>Newer framework versions</h4>
          <ul>
            {(updates.data?.updates ?? []).map((u) => (
              <li key={u.mapping}>
                {u.from.framework} {u.from.version} {u.from.requirement} in {u.to_version}:{" "}
                {u.to.length === 0
                  ? "no equivalent requirement"
                  : u.to.map((t) => (
                      <button
                        key={t.requirement}
                        type="button"
                        className="btn"
                        disabled={has({ framework: u.from.framework, version: u.to_version, requirement: t.requirement })}
                        onClick={() =>
                          onChange(mappings.map((m) => (m.framework === u.from.framework && m.version === u.from.version && m.requirement === u.from.requirement
                            ? { ...m, version: u.to_version, requirement: t.requirement }
                            : m)))
                        }
                      >
                        Move to {reqName({ identifier: t.requirement, label: t.label })}
                      </button>
                    ))}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </>
  );
}

/** A control's mappings on its page. */
export function MappingsSummary({ mappings }: { mappings: Mapping[] }) {
  return (
    <Section id="mappings" title="Framework mappings">
      {mappings.length === 0 ? (
        <p>This control is not mapped to a framework requirement.</p>
      ) : (
        <ul>
          {mappings.map((m) => (
            <li key={`${m.framework}-${m.version}-${m.requirement}`}>
              {m.framework} {m.version} {m.requirement}: {STRENGTH_LABELS[m.strength]}
              {m.rationale ? <span className="muted"> ({m.rationale})</span> : null}
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

/** AC-18: on a register risk, the requirements its scenarios' current controls address. */
export function RiskRequirements({ requirements }: { requirements: Addressed[] | undefined }) {
  const [open, setOpen] = useState(false);
  const list = requirements ?? [];
  const n = list.reduce((s, g) => s + g.requirements.length, 0);
  return (
    <Section id="requirements" title="Framework requirements addressed" intro="By the controls in the current control sets of its scenarios, as you may see them.">
      {n === 0 ? (
        <p>None: no control in its scenarios' current sets is mapped, or none you can see.</p>
      ) : (
        <>
          <p>
            {n} {n === 1 ? "requirement" : "requirements"} in {list.length} {list.length === 1 ? "framework version" : "framework versions"}.{" "}
            <button type="button" className="btn" aria-expanded={open} onClick={() => setOpen(!open)}>
              {open ? "Hide them" : "Show them"}
            </button>
          </p>
          {open
            ? list.map((g) => (
                <div key={g.version.id}>
                  <h3>
                    {g.version.family_title} {g.version.label}
                  </h3>
                  <ul>
                    {g.requirements.map((r) => (
                      <li key={r.id}>
                        <a href={`/frameworks/requirements/${r.id}`}>{reqName(r)}</a> {r.title}{" "}
                        <span className="muted">({r.controls.map((c) => c.name).join(", ")})</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))
            : null}
        </>
      )}
    </Section>
  );
}

