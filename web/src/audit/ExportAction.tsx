import { useEffect, useState, type FormEvent } from "react";
import { describe, getJSON, send } from "../api";
import { AUDIT_API, type Export, type FilterKey } from "./types";

// F-002 T-15 (AC-32 to AC-34): export the records matching the applied
// search as a bundle that fair-audit-verify checks offline. The audit
// service builds it in the background; the page follows its status and
// then offers the download. Users without audit.export are told so by the
// API's refusal.

const POLL_MS = 1000;

/** The applied filters in words, for the user to confirm what is exported. */
function inWords(filter: Partial<Record<FilterKey, string>>): string {
  const parts = Object.entries(filter).map(([k, v]) => `${k.replace("_", " ")} ${v}`);
  return parts.length === 0 ? "every record you may export" : `the records matching ${parts.join(", ")}`;
}

export function ExportAction({ filter }: { filter: Partial<Record<FilterKey, string>> }) {
  const [exp, setExp] = useState<Export>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  // Follow a pending export until it is ready or has failed.
  useEffect(() => {
    if (!exp || exp.status !== "pending") return;
    const ctl = new AbortController();
    const t = window.setTimeout(() => {
      getJSON<Export>(`${AUDIT_API}/exports/${exp.export_id}`, ctl.signal)
        .then(setExp)
        .catch((err: unknown) => {
          if (!ctl.signal.aborted) setError(describe(err));
        });
    }, POLL_MS);
    return () => {
      window.clearTimeout(t);
      ctl.abort();
    };
  }, [exp]);

  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const data = new FormData(e.currentTarget);
    const reason = String(data.get("reason") ?? "").trim();
    const format = String(data.get("format") ?? "jsonl");
    if (!reason) {
      setError("Give a reason for the export.");
      return;
    }
    setError(undefined);
    setExp(undefined);
    setBusy(true);
    send<Export>("POST", `${AUDIT_API}/exports`, { filter, format, reason })
      .then(setExp)
      .catch((err: unknown) => setError(describe(err)))
      .finally(() => setBusy(false));
  };

  return (
    <>
      <p>
        Exports {inWords(filter)} (the filters applied above, not unsaved changes) in the business units where you may export, with
        each record's proof, the signed checkpoints and keys, and a signed manifest stating the filter.
      </p>
      <form className="export" onSubmit={submit} aria-label="Export the matching records" noValidate>
        <fieldset>
          <legend>Format</legend>
          <div className="choice">
            <input type="radio" id="x-jsonl" name="format" value="jsonl" defaultChecked />
            <label htmlFor="x-jsonl">JSON lines (the records exactly as recorded)</label>
          </div>
          <div className="choice">
            <input type="radio" id="x-csv" name="format" value="csv" />
            <label htmlFor="x-csv">CSV (a table, with the records as recorded alongside)</label>
          </div>
        </fieldset>
        <div className="field">
          <label htmlFor="x-reason">Reason</label>
          <textarea id="x-reason" name="reason" rows={2} maxLength={1000} required aria-describedby="x-reason-hint" />
          <p id="x-reason-hint" className="muted">
            Recorded with the export and in its manifest.
          </p>
        </div>
        {error ? (
          <p role="alert" className="error-text">
            {error}
          </p>
        ) : null}
        <div className="actions">
          <button type="submit" className="btn primary" disabled={busy}>
            Export these records
          </button>
        </div>
      </form>
      <div role="status" className="export-status">
        {exp?.status === "pending" ? <p>Preparing the export. This page shows the download when it is ready.</p> : null}
        {exp?.status === "ready" ? (
          <>
            <p>
              The export is ready: {exp.record_count} {exp.record_count === 1 ? "record" : "records"}, up to checkpoint{" "}
              {exp.checkpoint_segment}.
            </p>
            <p>
              <a className="btn" href={`${AUDIT_API}/exports/${exp.export_id}/bundle`} download>
                Download the export (ZIP)
              </a>
            </p>
            <p className="muted wrap">
              SHA-256 <span className="mono">{exp.digest}</span>. Check it offline with{" "}
              <code>fair-audit-verify verify-export -keys trusted-keys.pem bundle.zip</code>.
            </p>
          </>
        ) : null}
      </div>
      {exp?.status === "failed" ? (
        <p role="alert" className="error-text">
          The export failed: {exp.failure}
        </p>
      ) : null}
    </>
  );
}
