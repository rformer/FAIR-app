import { useEffect, useState } from "react";
import { Badge, Section, Status, useApi } from "../components";
import { date } from "../links";
import type { BU, Head } from "./types";

// F-003 T-12 (AC-26, AC-27): the scenarios the user can see, newest first.

interface Page {
  scenarios: Head[];
  next_cursor?: string;
}

export function ScenarioList({ search = window.location.search }: { search?: string }) {
  const q = new URLSearchParams(search);
  const archived = q.get("archived") ?? "false";
  const cursor = q.get("cursor") ?? "";
  useEffect(() => {
    document.title = "Scenarios · FAIR Risk Platform";
  }, []);
  const page = useApi<Page>(`/api/v1/scenarios?archived=${encodeURIComponent(archived)}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
  const bus = useApi<{ bus: BU[] }>("/api/v1/risk/bus?permission=scenario.view");
  const editable = useApi<{ bus: BU[] }>("/api/v1/risk/bus?permission=scenario.edit");
  const buName = (id: string) => bus.data?.bus.find((b) => b.id === id)?.name ?? id;
  const [filter, setFilter] = useState(archived);

  return (
    <>
      <h1>Scenarios</h1>
      <p className="lede">Loss scenarios in Open FAIR terms, in the business units you can see.</p>
      <p className="actions">
        {editable.data && editable.data.bus.length > 0 ? (
          <a className="react-aria-Button primary" href="/scenarios/new">
            New scenario
          </a>
        ) : null}
        <a href="/risk/transfer">Export or import</a>
      </p>
      <Section id="scenarios" title="Scenarios">
        <form
          className="filters"
          onSubmit={(e) => {
            e.preventDefault();
            window.location.assign(`/scenarios?archived=${encodeURIComponent(filter)}`);
          }}
        >
          <div className="field">
            <label htmlFor="archived">Show</label>
            <select id="archived" value={filter} onChange={(e) => setFilter(e.target.value)}>
              <option value="false">Active scenarios</option>
              <option value="true">Archived scenarios</option>
              <option value="all">All scenarios</option>
            </select>
          </div>
          <div className="actions">
            <button className="btn" type="submit">
              Apply
            </button>
          </div>
        </form>
        <Status loaded={page}>
          {(data) =>
            data.scenarios.length === 0 ? (
              <p>No scenarios to show.</p>
            ) : (
              <>
                <div className="table-wrap">
                  <table className="data">
                    <caption className="sr-only">Scenarios, newest first</caption>
                    <thead>
                      <tr>
                        <th scope="col">Name</th>
                        <th scope="col">Business unit</th>
                        <th scope="col">Version</th>
                        <th scope="col">Created</th>
                        <th scope="col">State</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.scenarios.map((s) => (
                        <tr key={s.id}>
                          <td>
                            <a href={`/scenarios/${s.id}`}>{s.name ?? "(unnamed)"}</a>
                          </td>
                          <td>{buName(s.bu_id)}</td>
                          <td>{s.current_version}</td>
                          <td>{date(s.created_at)}</td>
                          <td>{s.archived_at ? <Badge tone="muted">Archived</Badge> : <Badge tone="ok">Active</Badge>}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {data.next_cursor ? (
                  <p>
                    <a href={`/scenarios?archived=${encodeURIComponent(archived)}&cursor=${encodeURIComponent(data.next_cursor)}`}>Older scenarios</a>
                  </p>
                ) : null}
              </>
            )
          }
        </Status>
      </Section>
    </>
  );
}
