import { useEffect, useState } from "react";
import { ApiError, describe, send } from "../api";
import { Section, useApi } from "../components";
import type { BU } from "./types";

// F-003 T-13 (AC-24, AC-25): exporting risk data as a fair.risk.v1 file and
// importing one, with a dry run first.

interface Created {
  section: string;
  kind: string;
  source_id: string;
  id: string;
  versions: number;
  reused?: boolean;
}
interface ImportProblem {
  item: string;
  pointer: string;
  message: string;
}
interface ImportResult {
  dry_run: boolean;
  created: Created[];
  problems: ImportProblem[];
}

export function TransferPage() {
  useEffect(() => {
    document.title = "Export and import · FAIR Risk Platform";
  }, []);
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/scenarios">Scenarios</a>
      </nav>
      <h1>Export and import</h1>
      <p className="lede">Move scenarios, the library and controls between installations as fair.risk.v1 files.</p>
      <Export />
      <Import />
    </>
  );
}

function Export() {
  const bus = useApi<{ bus: BU[] }>("/api/v1/risk/bus?permission=scenario.view");
  const [bu, setBU] = useState("");
  const [archived, setArchived] = useState(false);
  const [done, setDone] = useState<{ digest?: string; error?: string }>({});
  useEffect(() => {
    const first = bus.data?.bus[0];
    if (!bu && first) setBU(first.id);
  }, [bus.data, bu]);
  return (
    <Section id="export" title="Export" intro="Everything you can see in a business unit and below it, with every version, and the versions it uses from elsewhere.">
      <form
        className="export"
        onSubmit={async (e) => {
          e.preventDefault();
          setDone({});
          try {
            const resp = await fetch(`/api/v1/risk/export?bu=${encodeURIComponent(bu)}${archived ? "&archived=true" : ""}`, { credentials: "same-origin" });
            if (!resp.ok) throw new ApiError(resp.status, "", "");
            const blob = await resp.blob();
            const a = document.createElement("a");
            a.href = URL.createObjectURL(blob);
            a.download = /filename="([^"]+)"/.exec(resp.headers.get("Content-Disposition") ?? "")?.[1] ?? "fair-risk.json";
            document.body.appendChild(a);
            a.click();
            a.remove();
            setDone({ digest: resp.headers.get("X-Fair-Digest")?.replace(/^sha256=/, "") ?? "" });
          } catch (err) {
            setDone({ error: describe(err) });
          }
        }}
      >
        <div className="field">
          <label htmlFor="export-bu">Business unit</label>
          <select id="export-bu" value={bu} onChange={(e) => setBU(e.target.value)}>
            {(bus.data?.bus ?? []).map((b) => (
              <option key={b.id} value={b.id}>
                {b.name}
              </option>
            ))}
          </select>
        </div>
        <label>
          <input type="checkbox" checked={archived} onChange={(e) => setArchived(e.target.checked)} /> Include archived items
        </label>
        <div className="actions">
          <button className="btn primary" type="submit" disabled={!bu}>
            Download the export
          </button>
        </div>
        <div aria-live="polite">
          {done.digest ? (
            <p role="status">
              Exported. SHA-256 of the file: <span className="mono">{done.digest}</span>
            </p>
          ) : null}
          {done.error ? (
            <p role="alert" className="error-text">
              {done.error}
            </p>
          ) : null}
        </div>
      </form>
    </Section>
  );
}

function Import() {
  const bus = useApi<{ bus: BU[] }>("/api/v1/risk/bus?permission=scenario.edit");
  const [bu, setBU] = useState("");
  const [file, setFile] = useState<unknown>();
  const [result, setResult] = useState<{ data?: ImportResult; error?: string }>({});
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const first = bus.data?.bus[0];
    if (!bu && first) setBU(first.id);
  }, [bus.data, bu]);
  const run = async (dry: boolean) => {
    setBusy(true);
    setResult({});
    try {
      const data = await send<ImportResult>("POST", `/api/v1/risk/imports${dry ? "?dry_run=true" : ""}`, { bu_id: bu, file });
      setResult({ data });
    } catch (err) {
      const body = err instanceof ApiError ? (err.body as Partial<ImportResult> | undefined) : undefined;
      if (body?.problems?.length) setResult({ data: { dry_run: dry, created: [], problems: body.problems } });
      else setResult({ error: describe(err) });
    } finally {
      setBusy(false);
    }
  };
  const clean = result.data && result.data.dry_run && result.data.problems.length === 0;
  return (
    <Section id="import" title="Import" intro="Each item becomes a new entry in the business unit, with its versions; check the file first with a dry run, which changes nothing.">
      <form className="export" onSubmit={(e) => e.preventDefault()}>
        <div className="field">
          <label htmlFor="import-bu">Into business unit</label>
          <select id="import-bu" value={bu} onChange={(e) => setBU(e.target.value)}>
            {(bus.data?.bus ?? []).map((b) => (
              <option key={b.id} value={b.id}>
                {b.name}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="import-file">fair.risk.v1 file</label>
          <input
            id="import-file"
            type="file"
            accept="application/json,.json"
            onChange={async (e) => {
              setResult({});
              const f = e.target.files?.[0];
              if (!f) return setFile(undefined);
              try {
                setFile(JSON.parse(await f.text()));
              } catch {
                setFile(undefined);
                setResult({ error: "The file is not JSON." });
              }
            }}
          />
        </div>
        <div className="actions">
          <button className="btn" type="button" disabled={!file || !bu || busy} onClick={() => void run(true)}>
            Check the file (dry run)
          </button>
          <button className="btn primary" type="button" disabled={!clean || busy} onClick={() => void run(false)}>
            Import
          </button>
        </div>
      </form>
      <div aria-live="polite">
        {result.error ? (
          <p role="alert" className="error-text">
            {result.error}
          </p>
        ) : null}
        {result.data && result.data.problems.length > 0 ? (
          <div role="alert" className="banner">
            <h3>The file cannot be imported</h3>
            <ul>
              {result.data.problems.map((p, i) => (
                <li key={i}>
                  <span className="mono">
                    {p.item}
                    {p.pointer}
                  </span>
                  : {p.message}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {result.data && result.data.problems.length === 0 ? (
          <div role="status">
            <h3>{result.data.dry_run ? "The file can be imported: nothing has been written yet" : "Imported"}</h3>
            <div className="table-wrap">
              <table className="data">
                <caption className="sr-only">{result.data.dry_run ? "What the import would create" : "What was created"}</caption>
                <thead>
                  <tr>
                    <th scope="col">Section</th>
                    <th scope="col">Kind</th>
                    <th scope="col">Versions</th>
                    <th scope="col">Result</th>
                  </tr>
                </thead>
                <tbody>
                  {result.data.created.map((c) => (
                    <tr key={`${c.section}/${c.source_id}`}>
                      <td>{c.section}</td>
                      <td>{c.kind}</td>
                      <td>{c.versions}</td>
                      <td>{c.reused ? "Already here: reused" : result.data!.dry_run ? "Would be created" : <a href={`/${c.kind === "scenario" ? "scenarios" : c.kind === "control" ? "controls" : "library"}/${c.id}`}>Created</a>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : null}
      </div>
    </Section>
  );
}
