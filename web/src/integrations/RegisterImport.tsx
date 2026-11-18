import { useEffect, useState } from "react";
import { ApiError, describe, send } from "../api";
import { Section, Status, useApi } from "../components";
import type { Counts as CountsT } from "./types";
import { Counts } from "./Runs";

// F-011 T-18 (F-011-AC-20 to AC-22; design §3.6): importing a risk register
// from a CSV file into a business unit. Every column is mapped first; ratings
// and scores are never imported as exposure (P1): a rating column is
// refused, a text column is kept in the description. The import runs only
// after a dry run, with its fingerprint, all or nothing; the risks arrive
// unquantified, and a file imported again proposes its changes for review.

type Role = "external_id" | "title" | "description" | "owner" | "category" | "text" | "rating" | "";

const ROLES: { value: Role; label: string }[] = [
  { value: "", label: "Choose…" },
  { value: "external_id", label: "The source's ID" },
  { value: "title", label: "Title" },
  { value: "description", label: "Description" },
  { value: "owner", label: "Owner (email)" },
  { value: "category", label: "Category" },
  { value: "text", label: "Keep as text in the description" },
  { value: "rating", label: "A rating or score: refuse it" },
];

interface DryRun {
  dry_run: boolean;
  fingerprint: string;
  counts: CountsT;
  refused_columns: string[];
  matches?: { external_id: string; match: string }[];
  run?: { id: string };
  integration_id?: string;
}

/** The header row of a CSV file (quoted fields allowed). */
export function csvHeader(text: string): string[] {
  const line = text.replace(/^﻿/, "").split(/\r?\n/, 1)[0] ?? "";
  const out: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (ch === '"') quoted = false;
      else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      out.push(cur.trim());
      cur = "";
    } else cur += ch;
  }
  out.push(cur.trim());
  return out.filter((h, i, a) => h !== "" || i < a.length - 1);
}

export function RegisterImportPage() {
  const bus = useApi<{ bus: { id: string; code: string; name: string }[] }>("/api/v1/register/bus?permission=register.edit");
  const [bu, setBu] = useState("");
  const [label, setLabel] = useState("");
  const [csv, setCsv] = useState("");
  const [fileName, setFileName] = useState("");
  const [roles, setRoles] = useState<Record<string, Role>>({});
  const [dry, setDry] = useState<DryRun>();
  const [problems, setProblems] = useState<{ pointer: string; message: string }[]>([]);
  const [msg, setMsg] = useState<{ ok?: string; error?: string }>({});
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    document.title = "Import a register · Risk register · FAIR Risk Platform";
  }, []);
  useEffect(() => {
    if (bus.data && !bu && bus.data.bus[0]) setBu(bus.data.bus[0].id);
  }, [bus.data, bu]);
  const header = csv ? csvHeader(csv) : [];
  const mapped = header.length > 0 && header.every((h) => roles[h]);
  const body = () => ({ bu_id: bu, label: label.trim(), csv, columns: roles });
  const reset = () => {
    setDry(undefined);
    setProblems([]);
    setMsg({});
  };
  const run = async (dryRun: boolean) => {
    setBusy(true);
    setMsg({});
    setProblems([]);
    try {
      const r = await send<DryRun>("POST", `/api/v1/register/imports${dryRun ? "?dry_run=true" : ""}`, dryRun ? body() : { ...body(), fingerprint: dry?.fingerprint });
      if (dryRun) setDry(r);
      else {
        setDry(undefined);
        const created = r.counts.applied ?? 0; // new IDs are created in the import; known ones wait for review
        const waiting = Math.max(0, (r.counts.proposed ?? 0) - created);
        setMsg({ ok: `Imported: ${created} ${created === 1 ? "risk" : "risks"} created, ${waiting} ${waiting === 1 ? "change" : "changes"} proposed for review.` });
      }
    } catch (err) {
      if (err instanceof ApiError && err.code === "invalid_import") {
        const b = err.body as { problems?: { pointer: string; message: string }[] } | undefined;
        setProblems(b?.problems ?? []);
      }
      setMsg({ error: describe(err) });
      if (!dryRun) setDry(undefined);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/register">Risk register</a>
      </nav>
      <h1>Import a register</h1>
      <p className="lede">
        Risks from a spreadsheet, created unquantified so the register lists them until they are analysed. Ratings and heat-map
        scores are never imported as exposure: refuse their columns or keep them as text.
      </p>
      <Status loaded={bus}>
        {(b) =>
          b.bus.length === 0 ? (
            <p>Importing a register needs register.edit, which you do not hold at any business unit.</p>
          ) : (
            <Section id="import" title="The file">
              <form className="form" aria-label="Register file" onSubmit={(e) => e.preventDefault()}>
                <div className="field">
                  <label htmlFor="ri-bu">Business unit</label>
                  <select
                    id="ri-bu"
                    value={bu}
                    onChange={(e) => {
                      setBu(e.target.value);
                      reset();
                    }}
                  >
                    {b.bus.map((x) => (
                      <option key={x.id} value={x.id}>
                        {x.name} ({x.code})
                      </option>
                    ))}
                  </select>
                </div>
                <div className="field">
                  <label htmlFor="ri-label">Source name</label>
                  <input
                    id="ri-label"
                    required
                    maxLength={100}
                    value={label}
                    aria-describedby="ri-label-hint"
                    onChange={(e) => {
                      setLabel(e.target.value);
                      reset();
                    }}
                  />
                  <p id="ri-label-hint" className="muted">
                    The register's name, such as "2026 ERM register". Importing the same source again matches its IDs.
                  </p>
                </div>
                <div className="field">
                  <label htmlFor="ri-file">CSV file</label>
                  <input
                    id="ri-file"
                    type="file"
                    accept=".csv,text/csv"
                    onChange={async (e) => {
                      const f = e.target.files?.[0];
                      reset();
                      if (!f) return;
                      setFileName(f.name);
                      setCsv(await f.text());
                      setRoles({});
                    }}
                  />
                  {fileName ? <p className="muted">{fileName}</p> : null}
                </div>
              </form>
              {header.length > 0 ? (
                <fieldset className="wide">
                  <legend>What each column holds</legend>
                  {header.map((h, i) => (
                    <div className="field" key={`${h}-${i}`}>
                      <label htmlFor={`ri-col-${i}`}>{h || `Column ${i + 1}`}</label>
                      <select
                        id={`ri-col-${i}`}
                        value={roles[h] ?? ""}
                        onChange={(e) => {
                          setRoles({ ...roles, [h]: e.target.value as Role });
                          reset();
                        }}
                      >
                        {ROLES.map((r) => (
                          <option key={r.value} value={r.value}>
                            {r.label}
                          </option>
                        ))}
                      </select>
                    </div>
                  ))}
                </fieldset>
              ) : null}
              <div className="actions">
                <button className="react-aria-Button primary" type="button" disabled={!mapped || !label.trim() || busy} onClick={() => void run(true)}>
                  Check the file (dry run)
                </button>
                {dry ? (
                  <button className="react-aria-Button primary" type="button" disabled={busy} onClick={() => void run(false)}>
                    Import
                  </button>
                ) : null}
              </div>
              <div aria-live="polite">
                {msg.ok ? <p className="ok-text">{msg.ok}</p> : null}
                {msg.error ? (
                  <p role="alert" className="error-text">
                    {msg.error}
                  </p>
                ) : null}
              </div>
            </Section>
          )
        }
      </Status>
      {problems.length > 0 ? (
        <Section id="problems" title="Problems: nothing was imported">
          <ul>
            {problems.map((p, i) => (
              <li key={`${p.pointer}-${i}`}>
                <span className="mono">{p.pointer}</span> {p.message}
              </li>
            ))}
          </ul>
        </Section>
      ) : null}
      {dry ? (
        <Section id="dry-run" title="What importing would do">
          <Counts c={dry.counts} />
          {dry.refused_columns.length > 0 ? <p>Refused columns, not imported: {dry.refused_columns.join(", ")}.</p> : null}
          <p className="muted">Nothing has been imported yet. Import now to create the risks exactly as checked.</p>
        </Section>
      ) : null}
    </>
  );
}
