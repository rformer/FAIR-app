import { useEffect, useState } from "react";
import { describe, getJSON, upload } from "../api";
import { Section } from "../components";
import type { Import } from "./types";

// F-013 T-10 (F-013-AC-01 to AC-03, AC-05, AC-10): importing an OSCAL
// catalog or profile, a simple framework (JSON or CSV) or a crosswalk. The
// file is checked by a job, whole or not at all; a dry run shows what would
// be imported, and what changed since the family's last version, without
// applying it. Nothing a file links to is fetched.

type Kind = "catalog" | "profile" | "simple" | "crosswalk";

const KINDS: { value: Kind; label: string }[] = [
  { value: "catalog", label: "An OSCAL catalog (a framework version)" },
  { value: "profile", label: "An OSCAL profile (a baseline)" },
  { value: "simple", label: "A framework in the simple format (JSON or CSV)" },
  { value: "crosswalk", label: "A crosswalk (JSON, CSV or an OSCAL mapping collection)" },
];

const FIELDS: Record<Kind, { name: string; label: string; csvOnly?: boolean; optional?: boolean }[]> = {
  catalog: [
    { name: "family", label: "Framework key (lower-case letters, digits and hyphens)" },
    { name: "family_title", label: "Framework name" },
    { name: "publisher", label: "Publisher", optional: true },
  ],
  profile: [
    { name: "catalog_family", label: "Framework key of the catalog it selects from" },
    { name: "catalog_version", label: "Version of that catalog" },
    { name: "key", label: "Baseline key (lower-case letters, digits and hyphens)" },
  ],
  simple: [
    { name: "family", label: "Framework key", csvOnly: true },
    { name: "family_title", label: "Framework name", csvOnly: true },
    { name: "label", label: "Version", csvOnly: true },
    { name: "title", label: "Version title", csvOnly: true },
    { name: "published", label: "Published (YYYY-MM-DD)", csvOnly: true, optional: true },
  ],
  crosswalk: [
    { name: "source_family", label: "Source framework key (CSV and OSCAL)", optional: true },
    { name: "source_version", label: "Source version (CSV and OSCAL)", optional: true },
    { name: "target_family", label: "Target framework key (CSV and OSCAL)", optional: true },
    { name: "target_version", label: "Target version (CSV and OSCAL)", optional: true },
    { name: "title", label: "Title (CSV)", optional: true },
    { name: "label", label: "Crosswalk version (CSV)", optional: true },
  ],
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function ImportsPage() {
  const [kind, setKind] = useState<Kind>("simple");
  const [file, setFile] = useState<File>();
  const [values, setValues] = useState<Record<string, string>>({});
  const [result, setResult] = useState<Import>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    document.title = "Import · Frameworks · FAIR Risk Platform";
  }, []);
  const csv = file ? /\.csv$/i.test(file.name) || file.type === "text/csv" : false;
  const run = async (dryRun: boolean) => {
    if (!file) {
      setError("Choose a file.");
      return;
    }
    setBusy(true);
    setError(undefined);
    setResult(undefined);
    try {
      const q = new URLSearchParams({ kind });
      if (dryRun) q.set("dry_run", "true");
      for (const f of FIELDS[kind]) {
        const v = (values[f.name] ?? "").trim();
        if (v && (!f.csvOnly || csv)) q.set(f.name, v);
      }
      let imp = await upload<Import>(`/api/v1/frameworks/imports?${q.toString()}`, file, csv ? "text/csv" : "application/json");
      for (let i = 0; i < 300 && (imp.state === "queued" || imp.state === "running"); i++) {
        await sleep(1000);
        imp = await getJSON<Import>(`/api/v1/frameworks/imports/${imp.id}`);
      }
      setResult(imp);
    } catch (err) {
      setError(describe(err));
    } finally {
      setBusy(false);
    }
  };
  const summary = result?.result?.summary ?? {};
  const done = result && !result.dry_run && result.state === "succeeded";
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/frameworks">Frameworks</a>
      </nav>
      <h1>Import</h1>
      <p className="lede">
        A file is checked as a whole: any problem refuses all of it, each named by where it is. Try a dry run first to see what would be
        imported. Nothing the file links to is fetched.
      </p>
      <Section id="file" title="The file">
        <form
          className="form"
          aria-label="Import a file"
          onSubmit={(e) => {
            e.preventDefault();
            void run(true);
          }}
        >
          <div className="field">
            <label htmlFor="imp-kind">What it is</label>
            <select id="imp-kind" value={kind} onChange={(e) => setKind(e.target.value as Kind)}>
              {KINDS.map((k) => (
                <option key={k.value} value={k.value}>
                  {k.label}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="imp-file">File (JSON or CSV, up to 50 MiB)</label>
            <input id="imp-file" type="file" accept=".json,.csv,application/json,text/csv" onChange={(e) => setFile(e.target.files?.[0])} />
          </div>
          {FIELDS[kind]
            .filter((f) => !f.csvOnly || csv)
            .map((f) => (
              <div className="field" key={f.name}>
                <label htmlFor={`imp-${f.name}`}>
                  {f.label}
                  {f.optional ? " (optional)" : ""}
                </label>
                <input id={`imp-${f.name}`} value={values[f.name] ?? ""} onChange={(e) => setValues({ ...values, [f.name]: e.target.value })} />
              </div>
            ))}
          <div className="actions">
            <button className="react-aria-Button primary" type="submit" disabled={busy}>
              Dry run
            </button>
            <button className="react-aria-Button" type="button" disabled={busy || !(result?.dry_run && result.state === "succeeded")} onClick={() => void run(false)}>
              Import
            </button>
          </div>
        </form>
      </Section>
      <div aria-live="polite">
        {busy ? <p role="status">Checking the file…</p> : null}
        {error ? (
          <p role="alert" className="error-text">
            {error}
          </p>
        ) : null}
      </div>
      {result ? (
        <Section id="outcome" title={result.state === "succeeded" ? (result.dry_run ? "Dry run: it would be imported" : "Imported") : "Refused"}>
          {result.state === "succeeded" ? (
            <>
              <dl className="facts">
                {Object.entries(summary)
                  .filter(([, v]) => typeof v !== "object" || v === null)
                  .map(([k, v]) => (
                    <div key={k}>
                      <dt>{k.replace(/_/g, " ")}</dt>
                      <dd>{String(v)}</dd>
                    </div>
                  ))}
              </dl>
              {done ? (
                <p>
                  {result.result?.version_id ? <a href={`/frameworks/versions/${result.result.version_id}`}>Open the version</a> : null}
                  {result.result?.baseline_id ? <a href={`/frameworks/baselines/${result.result.baseline_id}`}>Open the baseline</a> : null}
                  {result.result?.crosswalk_id ? <a href={`/frameworks/crosswalks/${result.result.crosswalk_id}`}>Open the crosswalk</a> : null}
                </p>
              ) : (
                <p>Nothing was applied. Import it to apply it.</p>
              )}
            </>
          ) : (
            <>
              <p>Nothing was imported. Fix these and try again:</p>
              <ul role="alert">
                {(result.problems ?? []).map((p, i) => (
                  <li key={i}>
                    <code>{p.pointer || "the file"}</code>: {p.message}
                  </li>
                ))}
              </ul>
            </>
          )}
        </Section>
      ) : null}
    </>
  );
}
