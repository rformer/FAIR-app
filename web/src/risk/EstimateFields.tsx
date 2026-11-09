import type { Estimate, Source, Unit } from "./types";
import { UNIT_LABELS } from "./types";

// An estimate's fields (AC-05, AC-06): a range (min, most likely, max) in
// the factor's unit, a confidence, a rationale and one or more sources.
// Field ids follow the document's JSON pointers, so a refused save's
// problems link to the field they are about.

export function fieldId(pointer: string): string {
  return "f" + pointer.replace(/[^A-Za-z0-9_]+/g, "-");
}

export function newEstimate(unit: Unit): Estimate {
  return { min: "", ml: "", max: "", unit, confidence: "0.9", rationale: "", sources: [{ type: "person", ref: "" }] };
}

export function EstimateFields({
  legend,
  pointer,
  value,
  currency,
  onChange,
}: {
  legend: string;
  pointer: string;
  value: Estimate;
  currency: string | null;
  onChange: (e: Estimate) => void;
}) {
  const set = (patch: Partial<Estimate>) => onChange({ ...value, ...patch });
  const setSource = (i: number, patch: Partial<Source>) =>
    set({ sources: value.sources.map((s, j) => (j === i ? { ...s, ...patch } : s)) });
  const unit = value.unit === "currency" ? (currency ?? "amount") : UNIT_LABELS[value.unit];
  const num = (k: "min" | "ml" | "max" | "confidence", label: string) => (
    <div className="field">
      <label htmlFor={fieldId(`${pointer}/${k}`)}>{label}</label>
      <input
        id={fieldId(`${pointer}/${k}`)}
        inputMode="decimal"
        value={value[k]}
        required
        onChange={(e) => set({ [k]: e.target.value } as Partial<Estimate>)}
      />
    </div>
  );
  return (
    <fieldset className="estimate" id={fieldId(pointer)}>
      <legend>
        {legend} <span className="muted">({unit})</span>
      </legend>
      <div className="grid">
        {num("min", "Minimum")}
        {num("ml", "Most likely")}
        {num("max", "Maximum")}
        {num("confidence", "Confidence (0 to 1)")}
      </div>
      <div className="field">
        <label htmlFor={fieldId(`${pointer}/rationale`)}>Rationale</label>
        <textarea id={fieldId(`${pointer}/rationale`)} rows={2} value={value.rationale} required onChange={(e) => set({ rationale: e.target.value })} />
      </div>
      {value.sources.map((s, i) => (
        <div className="grid" key={i}>
          <div className="field">
            <label htmlFor={fieldId(`${pointer}/sources/${i}/type`)}>Source {i + 1} type</label>
            <select id={fieldId(`${pointer}/sources/${i}/type`)} value={s.type} onChange={(e) => setSource(i, { type: e.target.value as Source["type"] })}>
              <option value="person">Person</option>
              <option value="document">Document</option>
              <option value="dataset">Dataset</option>
              <option value="integration">Integration</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor={fieldId(`${pointer}/sources/${i}/ref`)}>Source {i + 1}</label>
            <input id={fieldId(`${pointer}/sources/${i}/ref`)} value={s.ref} required onChange={(e) => setSource(i, { ref: e.target.value })} />
          </div>
          {value.sources.length > 1 ? (
            <div className="field">
              <button type="button" className="btn" onClick={() => set({ sources: value.sources.filter((_, j) => j !== i) })}>
                Remove source {i + 1}
              </button>
            </div>
          ) : null}
        </div>
      ))}
      <button type="button" className="btn" onClick={() => set({ sources: [...value.sources, { type: "document", ref: "" }] })}>
        Add a source
      </button>
    </fieldset>
  );
}
