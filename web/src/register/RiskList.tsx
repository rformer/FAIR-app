import { useEffect, useState } from "react";
import { getMe } from "../api";
import { Badge, Section, Status, useApi } from "../components";
import type { BU } from "../risk/types";
import { STATE_LABEL as ACCEPTANCE_LABEL } from "../acceptance/types";
import { DECISION_LABEL, STATUS_LABEL, type Category, type Coverage, type RiskHead } from "./types";

// F-007 T-08 (F-007-AC-09, AC-14, AC-19): the risks the user can see, with
// filters, sorting by exposure, and how many of the open ones are current.

const PAGE = 50;
const FILTERS = ["bu", "owner", "category", "state", "status", "decision", "overdue", "acceptance", "sort"] as const;

export function RiskList({ search = window.location.search }: { search?: string }) {
  const q = new URLSearchParams(search);
  const offset = Number(q.get("offset") ?? "0") || 0;
  const [form, setForm] = useState<Record<string, string>>(() => Object.fromEntries(FILTERS.map((k) => [k, q.get(k) ?? (k === "state" ? "open" : "")])));
  const [me, setMe] = useState<string>();
  useEffect(() => {
    document.title = "Risk register · FAIR Risk Platform";
    void getMe().then((m) => setMe(m.user_id));
  }, []);
  const params = new URLSearchParams();
  for (const k of FILTERS) {
    const v = form[k] ?? "";
    if (v && v !== "all" && k !== "owner") params.set(k, v);
  }
  if (form.owner === "me" && me) params.set("owner", me);
  params.set("limit", String(PAGE));
  params.set("offset", String(offset));
  const list = useApi<{ risks: RiskHead[]; more: boolean }>(`/api/v1/register/risks?${params.toString()}`);
  const bus = useApi<{ bus: BU[] }>("/api/v1/register/bus?permission=register.view");
  const editable = useApi<{ bus: BU[] }>("/api/v1/register/bus?permission=register.edit");
  const categories = useApi<{ categories: Category[] }>("/api/v1/register/categories");
  const coverage = useApi<Coverage>(`/api/v1/register/coverage${form.bu ? `?bu=${encodeURIComponent(form.bu)}` : ""}`);
  const buName = (id: string) => bus.data?.bus.find((b) => b.id === id)?.name ?? id;
  const go = (next: Record<string, string>, at = 0) => {
    const u = new URLSearchParams();
    for (const k of FILTERS) if (next[k]) u.set(k, next[k] ?? "");
    if (at > 0) u.set("offset", String(at));
    window.location.assign(`/register?${u.toString()}`);
  };
  const select = (id: string, label: string, options: [string, string][]) => (
    <div className="field">
      <label htmlFor={`f-${id}`}>{label}</label>
      <select id={`f-${id}`} value={form[id] ?? ""} onChange={(e) => setForm({ ...form, [id]: e.target.value })}>
        {options.map(([v, l]) => (
          <option key={v} value={v}>
            {l}
          </option>
        ))}
      </select>
    </div>
  );

  return (
    <>
      <h1>Risk register</h1>
      <p className="lede">Risks in business terms, each quantified by the analyses its owner pinned.</p>
      <p className="actions">
        {editable.data && editable.data.bus.length > 0 ? (
          <a className="react-aria-Button primary" href="/register/new">
            New risk
          </a>
        ) : null}
        <a href="/register/rollups">Roll-ups</a>
      </p>
      <Section id="coverage" title="Coverage" intro="Open risks whose exposure is current, against those stale, unquantified or still computing.">
        <Status loaded={coverage}>
          {(c) => (
            <dl className="summary">
              <div>
                <dt>Current</dt>
                <dd>
                  {c.current} of {c.open} open risks{c.current_share === null ? "" : ` (${Math.round(c.current_share * 100)}%)`}
                </dd>
              </div>
              {(["stale", "unquantified", "computing"] as const).map((s) => (
                <div key={s}>
                  <dt>{STATUS_LABEL[s].label}</dt>
                  <dd>{c[s] > 0 ? <a href={`/register?state=open&status=${s}${form.bu ? `&bu=${form.bu}` : ""}`}>{c[s]}</a> : c[s]}</dd>
                </div>
              ))}
            </dl>
          )}
        </Status>
      </Section>
      <Section id="risks" title="Risks">
        <form
          className="filters"
          aria-label="Filter risks"
          onSubmit={(e) => {
            e.preventDefault();
            go(form);
          }}
        >
          {select("bu", "Business unit (with its subtree)", [["", "All you can see"], ...(bus.data?.bus ?? []).map((b): [string, string] => [b.id, b.name])])}
          {select("owner", "Owner", [
            ["", "Anyone"],
            ["me", "Me"],
          ])}
          {select("category", "Category", [["", "Any"], ...(categories.data?.categories ?? []).map((c): [string, string] => [c.id, c.name])])}
          {select("state", "State", [
            ["all", "Open and closed"],
            ["open", "Open"],
            ["closed", "Closed"],
          ])}
          {select("status", "Exposure", [["", "Any"], ...Object.entries(STATUS_LABEL).map(([k, v]): [string, string] => [k, v.label])])}
          {select("decision", "Treatment", [["", "Any"], ...Object.entries(DECISION_LABEL), ["none", "No decision"]])}
          {select("overdue", "Actions", [
            ["", "Any"],
            ["true", "With overdue actions"],
          ])}
          {select("acceptance", "Acceptance", [
            ["", "Any"],
            ["active", "Accepted"],
            ["pending", "Pending approval"],
            ["suspended", "Suspended"],
            ["expired", "Expired"],
            ["needs_review", "Accepted, needs review"],
            ["expiring", "Accepted, expiring within 30 days"],
            ["none", "Not accepted"],
          ])}
          {select("sort", "Sort by", [
            ["", "Newest"],
            ["title", "Title"],
            ["mean", "Mean annual loss"],
            ["p90", "90th percentile"],
          ])}
          <div className="actions">
            <button className="btn" type="submit">
              Apply
            </button>
          </div>
        </form>
        <Status loaded={list}>
          {(data) =>
            data.risks.length === 0 ? (
              <p>No risks to show.</p>
            ) : (
              <>
                <div className="table-wrap">
                  <table className="data">
                    <caption className="sr-only">Risks</caption>
                    <thead>
                      <tr>
                        <th scope="col">Risk</th>
                        <th scope="col">Business unit</th>
                        <th scope="col">Owner</th>
                        <th scope="col">Category</th>
                        <th scope="col">Exposure</th>
                        <th scope="col">Treatment</th>
                        <th scope="col">Acceptance</th>
                        <th scope="col">State</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.risks.map((r) => (
                        <tr key={r.id}>
                          <td>
                            <a href={`/register/risks/${r.id}`}>{r.title ?? "(untitled)"}</a>
                          </td>
                          <td>{buName(r.bu_id)}</td>
                          <td>{r.owner_name ?? "—"}</td>
                          <td>{r.category?.name ?? "—"}</td>
                          <td>{r.status ? <Badge tone={STATUS_LABEL[r.status.status].tone}>{STATUS_LABEL[r.status.status].label}</Badge> : "—"}</td>
                          <td>
                            {r.treatment?.decision ? DECISION_LABEL[r.treatment.decision] : "—"}
                            {r.treatment?.overdue ? (
                              <>
                                {" "}
                                <Badge tone="bad">Overdue actions</Badge>
                              </>
                            ) : null}
                          </td>
                          <td>
                            {r.acceptance ? (
                              <a href={`/acceptances/${r.acceptance.id}`}>
                                <Badge tone={ACCEPTANCE_LABEL[r.acceptance.state].tone}>{ACCEPTANCE_LABEL[r.acceptance.state].label}</Badge>
                                {r.acceptance.needs_review.length > 0 ? (
                                  <>
                                    {" "}
                                    <Badge tone="warn">Needs review</Badge>
                                  </>
                                ) : null}
                              </a>
                            ) : (
                              "—"
                            )}
                          </td>
                          <td>{r.state === "open" ? <Badge tone="ok">Open</Badge> : <Badge tone="muted">Closed</Badge>}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="actions">
                  {offset > 0 ? (
                    <a href="#" onClick={(e) => (e.preventDefault(), go(form, Math.max(0, offset - PAGE)))}>
                      Previous risks
                    </a>
                  ) : null}
                  {data.more ? (
                    <a href="#" onClick={(e) => (e.preventDefault(), go(form, offset + PAGE))}>
                      More risks
                    </a>
                  ) : null}
                </p>
              </>
            )
          }
        </Status>
      </Section>
    </>
  );
}
