import { useEffect, useState } from "react";
import { money } from "../analysis/types";
import { Badge, Section, Status, useApi } from "../components";
import { date, daysUntil } from "../links";
import type { BU } from "../risk/types";
import { STATE_LABEL, tierLabel, type Acceptance } from "./types";

// F-008 T-07 (F-008-AC-08, AC-14, AC-19): the acceptances the user can see,
// with filters, and the approver's inbox of those waiting for their decision.

const PAGE = 50;
const FILTERS = ["state", "bu", "expiring_within"] as const;

export function useCurrency(): string | null {
  return useApi<{ currency: string | null }>("/api/v1/risk/settings").data?.currency ?? null;
}

export function useBUNames(): (id: string) => string {
  const bus = useApi<{ bus: BU[] }>("/api/v1/register/bus?permission=register.view");
  return (id: string) => bus.data?.bus.find((b) => b.id === id)?.name ?? "a business unit above yours";
}

export function StateBadge({ a }: { a: Pick<Acceptance, "state" | "needs_review"> }) {
  const s = STATE_LABEL[a.state];
  return (
    <>
      <Badge tone={s.tone}>{s.label}</Badge>
      {a.needs_review && a.needs_review.length > 0 ? (
        <>
          {" "}
          <Badge tone="warn">Needs review</Badge>
        </>
      ) : null}
    </>
  );
}

function Expiry({ a }: { a: Acceptance }) {
  if (a.state !== "active" && a.state !== "suspended") return <>{date(a.expires_on)}</>;
  const n = daysUntil(a.expires_on);
  return (
    <>
      {date(a.expires_on)}
      {n <= 30 ? (
        <>
          {" "}
          <Badge tone="warn">{n <= 1 ? "Expires tomorrow" : `In ${n} days`}</Badge>
        </>
      ) : null}
    </>
  );
}

function Table({ rows, caption, buName, currency }: { rows: Acceptance[]; caption: string; buName: (id: string) => string; currency: string | null }) {
  return (
    <div className="table-wrap">
      <table className="data">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">Risk</th>
            <th scope="col">Business unit</th>
            <th scope="col">State</th>
            <th scope="col">Tier</th>
            <th scope="col">Mean annual loss</th>
            <th scope="col">Requested by</th>
            <th scope="col">Expires</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((a) => (
            <tr key={a.id}>
              <td>
                <a href={`/acceptances/${a.id}`}>{a.risk_title ?? "(a risk you cannot see)"}</a>
                {a.renews ? <span className="muted"> (renewal)</span> : null}
              </td>
              <td>{buName(a.bu_id)}</td>
              <td>
                <StateBadge a={a} />
              </td>
              <td>
                {tierLabel(a.tier)}
                {a.state === "pending" || a.state === "suspended" ? (
                  <span className="muted">
                    {" "}
                    ({a.approvals} of {a.approvals_needed} approvals)
                  </span>
                ) : null}
              </td>
              <td>{money(a.mean, currency)}</td>
              <td>{a.requested_by_name ?? "—"}</td>
              <td>
                <Expiry a={a} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function AcceptanceList({ search = window.location.search }: { search?: string }) {
  const q = new URLSearchParams(search);
  const offset = Number(q.get("offset") ?? "0") || 0;
  const [form, setForm] = useState<Record<string, string>>(() => Object.fromEntries(FILTERS.map((k) => [k, q.get(k) ?? ""])));
  useEffect(() => {
    document.title = "Risk acceptances · FAIR Risk Platform";
  }, []);
  const params = new URLSearchParams();
  for (const k of FILTERS) if (form[k]) params.set(k, form[k] ?? "");
  params.set("limit", String(PAGE));
  params.set("offset", String(offset));
  const list = useApi<{ acceptances: Acceptance[]; more: boolean }>(`/api/v1/acceptances?${params.toString()}`);
  const bus = useApi<{ bus: BU[] }>("/api/v1/register/bus?permission=register.view");
  const buName = useBUNames();
  const currency = useCurrency();
  const go = (next: Record<string, string>, at = 0) => {
    const u = new URLSearchParams();
    for (const k of FILTERS) if (next[k]) u.set(k, next[k] ?? "");
    if (at > 0) u.set("offset", String(at));
    window.location.assign(`/acceptances?${u.toString()}`);
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
      <h1>Risk acceptances</h1>
      <p className="lede">Risks accepted as they stand, each approved at its exposure tier and in force until its expiry date.</p>
      <p className="actions">
        <a href="/acceptances/inbox">Waiting for your decision</a>
      </p>
      <Section id="acceptances" title="Acceptances">
        <form
          className="filters"
          aria-label="Filter acceptances"
          onSubmit={(e) => {
            e.preventDefault();
            go(form);
          }}
        >
          {select("state", "State", [
            ["", "Any"],
            ...Object.entries(STATE_LABEL).map(([k, v]): [string, string] => [k, v.label]),
            ["needs_review", "Needs review"],
          ])}
          {select("bu", "Business unit (with its subtree)", [["", "All you can see"], ...(bus.data?.bus ?? []).map((b): [string, string] => [b.id, b.name])])}
          {select("expiring_within", "Expiry", [
            ["", "Any"],
            ["30", "In force, expiring within 30 days"],
            ["90", "In force, expiring within 90 days"],
          ])}
          <div className="actions">
            <button className="btn" type="submit">
              Apply
            </button>
          </div>
        </form>
        <Status loaded={list}>
          {(data) =>
            data.acceptances.length === 0 ? (
              <p>No acceptances to show.</p>
            ) : (
              <>
                <Table rows={data.acceptances} caption="Acceptances" buName={buName} currency={currency} />
                <p className="actions">
                  {offset > 0 ? (
                    <a href="#" onClick={(e) => (e.preventDefault(), go(form, Math.max(0, offset - PAGE)))}>
                      Previous acceptances
                    </a>
                  ) : null}
                  {data.more ? (
                    <a href="#" onClick={(e) => (e.preventDefault(), go(form, offset + PAGE))}>
                      More acceptances
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

export function AcceptanceInbox() {
  useEffect(() => {
    document.title = "Waiting for your decision · Risk acceptances · FAIR Risk Platform";
  }, []);
  const list = useApi<{ acceptances: Acceptance[] }>("/api/v1/acceptances/inbox");
  const buName = useBUNames();
  const currency = useCurrency();
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/acceptances">Risk acceptances</a>
      </nav>
      <h1>Waiting for your decision</h1>
      <p className="lede">Requests and reviews at a tier where you approve, that you neither requested nor own, oldest first.</p>
      <Section id="inbox" title="Requests">
        <Status loaded={list}>
          {(data) =>
            data.acceptances.length === 0 ? (
              <p>Nothing is waiting for your decision.</p>
            ) : (
              <Table rows={data.acceptances} caption="Waiting for your decision" buName={buName} currency={currency} />
            )
          }
        </Status>
      </Section>
    </>
  );
}
