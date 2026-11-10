import { useEffect } from "react";
import { ApiError } from "../api";
import { Badge, Section, useApi } from "../components";
import { date } from "../links";
import { STATUS_LABELS, type InboxItem } from "./types";

// F-004 T-12 (AC-05, AC-07): the estimate requests addressed to the
// signed-in person, soonest due first.

export function Inbox() {
  useEffect(() => {
    document.title = "Estimate requests · FAIR Risk Platform";
  }, []);
  const inbox = useApi<{ requests: InboxItem[] }>("/api/v1/estimates/inbox");
  // Without estimate.submit anywhere the inbox does not exist (404).
  const none = inbox.error instanceof ApiError && inbox.error.status === 404;
  return (
    <>
      <h1>Estimate requests</h1>
      <p className="lede">
        Requests for your estimates of factors of risk scenarios. Answer each on
        its own; nobody else's answers are shown to you.
      </p>
      <Section id="inbox" title="Your requests">
        {inbox.loading && !inbox.data ? (
          <p role="status">Loading…</p>
        ) : none || (inbox.data && inbox.data.requests.length === 0) ? (
          <p>No estimate requests are addressed to you.</p>
        ) : inbox.error ? (
          <p role="alert" className="error-text">
            The requests could not be loaded.
          </p>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <caption className="sr-only">
                Estimate requests addressed to you, soonest due first
              </caption>
              <thead>
                <tr>
                  <th scope="col">Request</th>
                  <th scope="col">Scenario</th>
                  <th scope="col">Due</th>
                  <th scope="col">Answered</th>
                  <th scope="col">State</th>
                </tr>
              </thead>
              <tbody>
                {inbox.data!.requests.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <a href={`/estimates/${r.id}`}>{r.title}</a>
                    </td>
                    <td>{r.scenario_name ?? "—"}</td>
                    <td>{date(r.due_at)}</td>
                    <td>
                      {r.answered} of {r.factors}
                    </td>
                    <td>
                      {r.finished_at ? (
                        <Badge tone="ok">You have answered every factor</Badge>
                      ) : (
                        <Badge tone={r.status === "open" ? "info" : "muted"}>
                          {STATUS_LABELS[r.status]}
                        </Badge>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </>
  );
}
