// F-006 T-04 (F-006-AC-14, AC-17; design §4, §6.3; ADR-014): a chart's
// figure: a visible caption, a text alternative in sentences, a data table
// on request, and downloads. An image download is recorded first
// (`record`, POST /api/v1/analyses/downloads) and drawn only once that
// succeeds, with the download's id in its footer; the CSV is a link to the
// service, which records it.

import { useId, useRef, useState, type ReactNode } from "react";
import { Button } from "react-aria-components";
import type { DataTable } from "./describe.ts";
import { attachmentName, describe, getFile } from "../api";
import { withReason } from "../reason";
import { fileName, pngOf, save, serializeChart } from "./export.ts";

export interface ChartDownloads {
  /**
   * Records an image download, with a reason where the service asks for
   * one (F-010 T-17); resolves to the download's id.
   */
  record(format: "svg" | "png", reason?: string): Promise<string>;
  /** The footer lines drawn into an image, given its download id. */
  footer(downloadId: string): string[];
  file: { subject: string; id: string; view: string };
  /** The view's CSV on the service (recorded there). */
  csvHref?: string;
}

export interface ChartFigureProps {
  title: string;
  /** The text alternative: what the chart shows and its main values. */
  description: string;
  table: DataTable;
  downloads?: ChartDownloads;
  /** The chart, given the ids of its caption and description. */
  children: (ids: { labelledBy: string; describedBy: string }) => ReactNode;
}

export function ChartFigure({ title, description, table, downloads, children }: ChartFigureProps) {
  const id = useId();
  const box = useRef<HTMLDivElement>(null);
  const [showTable, setShowTable] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const download = async (format: "svg" | "png") => {
    const svg = box.current?.querySelector("svg");
    if (!svg || !downloads) return;
    setBusy(true);
    setError(null);
    try {
      const downloadId = await withReason((reason) => downloads.record(format, reason));
      const markup = serializeChart(svg, { lines: downloads.footer(downloadId) });
      const blob = format === "svg" ? new Blob([markup], { type: "image/svg+xml" }) : await pngOf(markup);
      save(blob, fileName(downloads.file.subject, downloads.file.id, downloads.file.view, format));
    } catch (e) {
      setError(describe(e));
    } finally {
      setBusy(false);
    }
  };

  // The CSV comes from the service, which records it (and may ask for a
  // reason first): fetched, then saved.
  const downloadCSV = async (href: string) => {
    if (!downloads) return;
    setBusy(true);
    setError(null);
    try {
      const resp = await withReason((reason) => getFile(href, reason));
      save(await resp.blob(), attachmentName(resp, fileName(downloads.file.subject, downloads.file.id, downloads.file.view, "csv")));
    } catch (e) {
      setError(describe(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <figure className="chart-figure" aria-labelledby={`${id}-cap`}>
      <figcaption id={`${id}-cap`} className="chart-caption">
        {title}
      </figcaption>
      <p id={`${id}-desc`} className="chart-description">
        {description}
      </p>
      <div ref={box}>{children({ labelledBy: `${id}-cap`, describedBy: `${id}-desc` })}</div>
      <div className="actions chart-actions">
        <Button onPress={() => setShowTable((s) => !s)} aria-expanded={showTable} aria-controls={`${id}-table`}>
          {showTable ? "Hide data table" : "Show data table"}
        </Button>
        {downloads ? (
          <>
            <Button onPress={() => void download("svg")} isDisabled={busy}>
              Download SVG
            </Button>
            <Button onPress={() => void download("png")} isDisabled={busy}>
              Download PNG
            </Button>
            {downloads.csvHref ? (
              <Button onPress={() => void downloadCSV(downloads.csvHref ?? "")} isDisabled={busy}>
                Download CSV
              </Button>
            ) : null}
          </>
        ) : null}
      </div>
      {error ? (
        <p role="alert" className="error-text">
          {error}
        </p>
      ) : null}
      <div id={`${id}-table`} className="table-wrap" hidden={!showTable}>
        {showTable ? (
          <table className="data">
            <caption className="sr-only">{table.caption}</caption>
            <thead>
              <tr>
                {table.columns.map((c) => (
                  <th key={c} scope="col">
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {table.rows.map((r, i) => (
                <tr key={i}>
                  {r.map((c, j) => (j === 0 ? <th key={j} scope="row">{c}</th> : <td key={j}>{c}</td>))}
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </div>
    </figure>
  );
}
