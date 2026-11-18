import { useEffect, useState } from "react";
import { describe, getJSON, send } from "../api";
import { Badge, ReasonAction, Section, Status, useApi } from "../components";
import { show } from "../links";
import { ACTION_LABEL, dateTime, TARGET_LABEL, targetHref, type Integration, type Proposal, type ProposalView, type TargetType } from "./types";

// F-011 T-18 (F-011-AC-10 to AC-14, AC-25; design §3.4): the review queue.
// Proposals are the reviewer's to merge: each opens with the record's
// current version, the document accepting would write, and the diff, all
// as the reviewer reads the record. Accepting writes through the record's
// own save code under the reviewer's permissions; scenarios pinned to older
// versions see a newer one and are not changed.

const STATES: Proposal["state"][] = ["pending", "accepted", "rejected", "superseded"];
const STATE_LABEL: Record<Proposal["state"], string> = { pending: "Pending", accepted: "Accepted", rejected: "Rejected", superseded: "Superseded" };

function originText(p: Proposal): string {
  if (p.derivation_id) return "Derived from loss events";
  return p.integration_name ?? "An integration";
}

export function ProposalsPage({ search = window.location.search }: { search?: string }) {
  const q = new URLSearchParams(search);
  const [state, setState] = useState<Proposal["state"]>((q.get("state") as Proposal["state"] | null) ?? "pending");
  const [kind, setKind] = useState<string>(q.get("kind") ?? "");
  const integration = q.get("integration") ?? "";
  const run = q.get("run") ?? "";
  const params = new URLSearchParams({ state, limit: "200" });
  if (kind) params.set("kind", kind);
  if (integration) params.set("integration", integration);
  const list = useApi<{ proposals: Proposal[]; more: boolean }>(`/api/v1/proposals?${params.toString()}`);
  const it = useApi<Integration>(integration ? `/api/v1/integrations/${integration}` : null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [msg, setMsg] = useState<{ ok?: string; error?: string }>({});
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    document.title = "Proposed changes · Integrations · FAIR Risk Platform";
  }, []);
  useEffect(() => setSelected(new Set()), [state, kind]);
  const shown = (list.data?.proposals ?? []).filter((p) => !run || p.run_id === run);
  const toggle = (id: string) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/integrations">Integrations</a>
        {it.data ? (
          <>
            {" "}
            / <a href={`/integrations/${it.data.id}`}>{it.data.name}</a>
          </>
        ) : null}
      </nav>
      <h1>Proposed changes</h1>
      <p className="lede">
        Changes integrations propose to assets, controls, risks and reference classes you may review. Open one to see what
        accepting would write.
        {run ? " Showing one run's proposals." : ""}
      </p>
      <form className="filters" aria-label="Filter proposals" onSubmit={(e) => e.preventDefault()}>
        <div className="field">
          <label htmlFor="p-state">State</label>
          <select id="p-state" value={state} onChange={(e) => setState(e.target.value as Proposal["state"])}>
            {STATES.map((s) => (
              <option key={s} value={s}>
                {STATE_LABEL[s]}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="p-kind">Record</label>
          <select id="p-kind" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="">Any</option>
            {(Object.keys(TARGET_LABEL) as TargetType[]).map((k) => (
              <option key={k} value={k}>
                {TARGET_LABEL[k]}
              </option>
            ))}
          </select>
        </div>
      </form>
      <div aria-live="polite">
        {msg.ok ? <p className="ok-text">{msg.ok}</p> : null}
        {msg.error ? (
          <p role="alert" className="error-text">
            {msg.error}
          </p>
        ) : null}
      </div>
      <Section id="proposals" title={`${STATE_LABEL[state]} proposals`}>
        <Status loaded={list}>
          {() =>
            shown.length === 0 ? (
              <p>No {state} proposals you may review.</p>
            ) : (
              <>
                {state === "pending" ? (
                  <div className="actions">
                    <button
                      className="react-aria-Button primary"
                      type="button"
                      disabled={selected.size === 0 || busy}
                      onClick={async () => {
                        setBusy(true);
                        setMsg({});
                        try {
                          const chosen = shown.filter((p) => selected.has(p.id));
                          // Updates are accepted against the version reviewed: read each now.
                          const items = await Promise.all(
                            chosen.map(async (p) => {
                              if (p.action !== "update") return { id: p.id };
                              const v = await getJSON<ProposalView>(`/api/v1/proposals/${p.id}`);
                              return { id: p.id, expected_version: v.current?.version };
                            }),
                          );
                          await send("POST", "/api/v1/proposals/accept", { proposals: items });
                          setMsg({ ok: `Accepted ${items.length} ${items.length === 1 ? "change" : "changes"}.` });
                          setSelected(new Set());
                          list.reload();
                        } catch (err) {
                          setMsg({ error: `Nothing was accepted: ${describe(err)}` });
                        } finally {
                          setBusy(false);
                        }
                      }}
                    >
                      Accept selected ({selected.size})
                    </button>
                    <button
                      className="react-aria-Button"
                      type="button"
                      onClick={() => setSelected(selected.size === shown.length ? new Set() : new Set(shown.map((p) => p.id)))}
                    >
                      {selected.size === shown.length ? "Select none" : "Select all"}
                    </button>
                  </div>
                ) : null}
                <div className="table-wrap">
                  <table className="data">
                    <caption className="sr-only">Proposals, newest first</caption>
                    <thead>
                      <tr>
                        {state === "pending" ? (
                          <th scope="col">
                            <span className="sr-only">Select</span>
                          </th>
                        ) : null}
                        <th scope="col">Change</th>
                        <th scope="col">Record</th>
                        <th scope="col">Business unit</th>
                        <th scope="col">From</th>
                        <th scope="col">Proposed</th>
                      </tr>
                    </thead>
                    <tbody>
                      {shown.map((p) => {
                        const name = String((p.record?.name ?? p.record?.title ?? p.external_id ?? p.id) as string);
                        return (
                          <tr key={p.id}>
                            {state === "pending" ? (
                              <td>
                                <input type="checkbox" checked={selected.has(p.id)} onChange={() => toggle(p.id)} aria-label={`Select ${name}`} />
                              </td>
                            ) : null}
                            <td>
                              <a href={`/integrations/proposals/${p.id}`}>
                                {ACTION_LABEL[p.action]} {TARGET_LABEL[p.target_type].toLowerCase()}
                              </a>
                              {p.descriptive_only ? (
                                <>
                                  {" "}
                                  <Badge tone="info">Names and descriptions only</Badge>
                                </>
                              ) : null}
                            </td>
                            <td>{name}</td>
                            <td>{p.bu_name ?? "—"}</td>
                            <td>{originText(p)}</td>
                            <td>{dateTime(p.created_at)}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                {list.data?.more ? <p className="muted">More proposals are waiting; accept or reject these to see them.</p> : null}
              </>
            )
          }
        </Status>
      </Section>
    </>
  );
}

export function ProposalPage({ id }: { id: string }) {
  const view = useApi<ProposalView>(`/api/v1/proposals/${id}`);
  const [msg, setMsg] = useState<{ ok?: string; error?: string }>({});
  useEffect(() => {
    document.title = "Proposed change · Integrations · FAIR Risk Platform";
  }, []);
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/integrations">Integrations</a> / <a href="/integrations/proposals">Proposed changes</a>
      </nav>
      <Status loaded={view}>
        {(p) => {
          const href = targetHref(p);
          return (
            <>
              <h1>
                {ACTION_LABEL[p.action]} {TARGET_LABEL[p.target_type].toLowerCase()}
                {p.external_id ? <span className="muted"> {p.external_id}</span> : null}
              </h1>
              <p className="lede">
                <Badge tone={p.state === "pending" ? "info" : p.state === "accepted" ? "ok" : "muted"}>{STATE_LABEL[p.state]}</Badge> From{" "}
                {p.integration_id ? <a href={`/integrations/${p.integration_id}`}>{originText(p)}</a> : originText(p)}, at {p.bu_name ?? "its business unit"},{" "}
                {dateTime(p.created_at)}.
                {href ? (
                  <>
                    {" "}
                    <a href={href}>Open the record</a>.
                  </>
                ) : null}
              </p>
              {p.state !== "pending" ? (
                <p>
                  {STATE_LABEL[p.state]}
                  {p.decided_by_name ? ` by ${p.decided_by_name}` : ""} {p.decided_at ? dateTime(p.decided_at) : ""}
                  {p.reason ? `: ${p.reason}` : "."}
                </p>
              ) : null}
              <div aria-live="polite">
                {msg.ok ? <p className="ok-text">{msg.ok}</p> : null}
                {msg.error ? (
                  <p role="alert" className="error-text">
                    {msg.error}
                  </p>
                ) : null}
              </div>
              {p.problems.length > 0 ? (
                <Section id="problems" title="It cannot be accepted as it is">
                  <ul>
                    {p.problems.map((x) => (
                      <li key={x.pointer + x.message}>
                        {x.pointer ? <span className="mono">{x.pointer}</span> : null} {x.message}
                      </li>
                    ))}
                  </ul>
                </Section>
              ) : null}
              {p.state === "pending" ? (
                <div className="actions">
                  <button
                    className="react-aria-Button primary"
                    type="button"
                    disabled={p.problems.length > 0}
                    onClick={async () => {
                      try {
                        await send("POST", `/api/v1/proposals/${p.id}/accept`, p.action === "update" ? { expected_version: p.current?.version } : {});
                        setMsg({ ok: "Accepted: the record has a new version." });
                        view.reload();
                      } catch (err) {
                        setMsg({ error: describe(err) });
                      }
                    }}
                  >
                    Accept
                  </button>
                  <ReasonAction
                    label="Reject"
                    title="Reject this change"
                    fieldLabel="Why it is rejected"
                    description="The same values from the source are not proposed again."
                    submitLabel="Reject"
                    onSubmit={async (reason) => {
                      await send("POST", `/api/v1/proposals/${p.id}/reject`, { reason });
                      setMsg({ ok: "Rejected." });
                      view.reload();
                    }}
                  />
                </div>
              ) : null}
              {p.diff ? (
                <Section id="diff" title={`What changes from version ${p.current?.version ?? ""}`}>
                  {p.diff.changes.length === 0 ? (
                    <p>No differences.</p>
                  ) : (
                    <div className="table-wrap">
                      <table className="data">
                        <caption className="sr-only">Changes accepting would make</caption>
                        <thead>
                          <tr>
                            <th scope="col">Where</th>
                            <th scope="col">Now</th>
                            <th scope="col">Proposed</th>
                          </tr>
                        </thead>
                        <tbody>
                          {p.diff.changes.map((c) => (
                            <tr key={c.pointer}>
                              <td className="mono">{c.pointer}</td>
                              <td className="mono">{c.from === undefined ? "—" : show(c.from)}</td>
                              <td className="mono">{c.to === undefined ? "—" : show(c.to)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </Section>
              ) : null}
              {p.action === "archive" && p.state === "pending" ? (
                <Section id="archive" title="Archiving">
                  <p>The source no longer holds this record. Accepting archives it; scenarios and risks that use it keep their pinned versions.</p>
                </Section>
              ) : null}
              {p.proposed && !p.diff ? (
                <Section id="proposed" title="The record accepting would write">
                  <pre className="mono wrap">{JSON.stringify(p.proposed, null, 2)}</pre>
                </Section>
              ) : null}
              {p.record ? (
                <Section id="record" title="What the source sent">
                  <pre className="mono wrap">{JSON.stringify(p.record, null, 2)}</pre>
                </Section>
              ) : null}
            </>
          );
        }}
      </Status>
    </>
  );
}
