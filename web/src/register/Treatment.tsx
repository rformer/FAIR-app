import { useEffect, useState } from "react";
import { ApiError, describe, send } from "../api";
import { money } from "../analysis/types";
import { compareHref } from "../analysis/basket";
import { Badge, Section, Status, useApi } from "../components";
import { date } from "../links";
import type { BU, ScenarioView } from "../risk/types";
import { DECISION_LABEL, type Owner, type RiskView } from "./types";

// F-007 T-09 (F-007-AC-15 to AC-18): a risk's treatment plan: the decision
// and its rationale, the control set each scenario is expected to reach
// (mitigate), the actions with their owners and due dates (overdue ones
// flagged), the expected exposure after treatment beside the current one,
// and whether an acceptance is needed (decided in F-008).

export interface Action {
  id: string;
  title: string;
  owner: string;
  due: string;
  state: "planned" | "in_progress" | "done" | "cancelled";
  cancel_reason?: string;
}

export interface TreatmentDoc {
  schema_version: 1;
  decision: "mitigate" | "transfer" | "avoid" | "accept" | null;
  rationale?: string;
  targets?: { scenario_id: string; control_set: string }[];
  actions?: Action[];
}

interface Expected {
  available: boolean;
  reason?: "no_targets" | "incomplete";
  scenarios?: {
    scenario_id: string;
    run_id: string | null;
    current_set: string | null;
    target_set: string | null;
    status: "ok" | "no_pin" | "not_visible" | "target_not_in_pinned_run";
    current_mean?: number;
    target_mean?: number;
    reduction?: number;
  }[];
  current_mean_total?: number;
  target_mean_total?: number;
  reduction?: number;
  compare_items?: string[];
  assumption?: string;
}

export interface TreatmentView {
  risk_id: string;
  version: number;
  document: TreatmentDoc;
  actions: (Action & { overdue: boolean })[];
  overdue_actions: number;
  acceptance: { needed: boolean; state: string | null };
  expected: Expected;
}

const STATE_LABEL: Record<Action["state"], string> = { planned: "Planned", in_progress: "In progress", done: "Done", cancelled: "Cancelled" };
const EXPECTED_STATUS: Record<string, string> = {
  ok: "Compared",
  no_pin: "No pinned analysis",
  not_visible: "Not visible to you",
  target_not_in_pinned_run: "The pinned run does not have the target set",
};

function useCurrency(): string | null {
  return useApi<{ currency: string | null }>("/api/v1/risk/settings").data?.currency ?? null;
}

/** The plan on a risk's page; nothing for those without treatment.view. */
export function TreatmentSection({ v }: { v: RiskView }) {
  const t = useApi<TreatmentView>(`/api/v1/register/risks/${v.risk.id}/treatment`);
  const editable = useApi<{ bus: BU[] }>("/api/v1/register/bus?permission=treatment.edit");
  const owners = useApi<{ owners: Owner[] }>(`/api/v1/register/owners?bu=${encodeURIComponent(v.risk.bu_id)}`);
  const currency = useCurrency();
  if (t.error instanceof ApiError && (t.error.status === 403 || t.error.status === 404)) return null;
  const mayEdit = v.risk.state === "open" && (editable.data?.bus.some((b) => b.id === v.risk.bu_id) ?? false);
  const who = (id: string) => owners.data?.owners.find((o) => o.user_id === id)?.name ?? id;
  const scenario = (id: string) => v.links.find((l) => l.scenario_id === id)?.scenario_name ?? id;
  return (
    <Section id="treatment" title="Treatment">
      <Status loaded={t}>
        {(tv) => (
          <>
            {tv.version === 0 ? (
              <p>No treatment plan yet.</p>
            ) : (
              <dl className="summary">
                <div>
                  <dt>Decision</dt>
                  <dd>{tv.document.decision ? DECISION_LABEL[tv.document.decision] : "Not decided"}</dd>
                </div>
                {tv.document.rationale ? (
                  <div>
                    <dt>Rationale</dt>
                    <dd>{tv.document.rationale}</dd>
                  </div>
                ) : null}
              </dl>
            )}
            {tv.acceptance.needed ? (
              <div className="callout warn" role="note" aria-label="Acceptance">
                <p>Accepting this risk needs an acceptance, approved in the acceptance workflow. The register records the decision; it does not approve it.</p>
              </div>
            ) : null}
            {mayEdit ? (
              <p className="actions">
                <a className="react-aria-Button" href={`/register/risks/${v.risk.id}/treatment`}>
                  {tv.version === 0 ? "Plan treatment" : "Change the plan"}
                </a>
              </p>
            ) : null}
            {tv.actions.length > 0 ? (
              <div className="table-wrap">
                <table className="data">
                  <caption>Actions{tv.overdue_actions > 0 ? `, ${tv.overdue_actions} overdue` : ""}</caption>
                  <thead>
                    <tr>
                      <th scope="col">Action</th>
                      <th scope="col">Owner</th>
                      <th scope="col">Due</th>
                      <th scope="col">State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tv.actions.map((a) => (
                      <tr key={a.id}>
                        <td>{a.title}</td>
                        <td>{who(a.owner)}</td>
                        <td>
                          {a.due} {a.overdue ? <Badge tone="bad">Overdue</Badge> : null}
                        </td>
                        <td>
                          {STATE_LABEL[a.state]}
                          {a.cancel_reason ? <span className="muted"> ({a.cancel_reason})</span> : null}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}
            {tv.document.decision === "mitigate" ? <ExpectedExposure e={tv.expected} scenario={scenario} currency={currency} /> : null}
          </>
        )}
      </Status>
    </Section>
  );
}

/** AC-16: the expected exposure after treatment beside the current one. */
function ExpectedExposure({ e, scenario, currency }: { e: Expected; scenario: (id: string) => string; currency: string | null }) {
  return (
    <div role="region" aria-label="Expected exposure after treatment">
      <h3>Expected exposure after treatment</h3>
      {e.reason === "no_targets" ? <p>The plan names no target control sets.</p> : null}
      {e.scenarios && e.scenarios.length > 0 ? (
        <div className="table-wrap">
          <table className="data">
            <caption className="sr-only">Each scenario's mean annual loss now and at its target control set, from the same pinned run</caption>
            <thead>
              <tr>
                <th scope="col">Scenario</th>
                <th scope="col">Now (control set)</th>
                <th scope="col">Target (control set)</th>
                <th scope="col">Mean annual loss now</th>
                <th scope="col">Expected after treatment</th>
                <th scope="col">Reduction</th>
              </tr>
            </thead>
            <tbody>
              {e.scenarios.map((x) => (
                <tr key={x.scenario_id}>
                  <td>{scenario(x.scenario_id)}</td>
                  <td>{x.current_set ?? "—"}</td>
                  <td>{x.target_set ?? "—"}</td>
                  {x.status === "ok" ? (
                    <>
                      <td>{money(x.current_mean, currency)}</td>
                      <td>{money(x.target_mean, currency)}</td>
                      <td>{money(x.reduction, currency)}</td>
                    </>
                  ) : (
                    <td colSpan={3}>{EXPECTED_STATUS[x.status]}</td>
                  )}
                </tr>
              ))}
            </tbody>
            {e.available ? (
              <tfoot>
                <tr>
                  <th scope="row" colSpan={3}>
                    All scenarios
                  </th>
                  <td>{money(e.current_mean_total, currency)}</td>
                  <td>{money(e.target_mean_total, currency)}</td>
                  <td>{money(e.reduction, currency)}</td>
                </tr>
              </tfoot>
            ) : null}
          </table>
        </div>
      ) : null}
      {e.assumption ? <p className="muted">{e.assumption.charAt(0).toUpperCase() + e.assumption.slice(1)}.</p> : null}
      {e.compare_items ? (
        <p>
          <a href={compareHref(e.compare_items)}>Compare the distributions now and after treatment</a>
        </p>
      ) : null}
    </div>
  );
}

/** The plan's editor (AC-15, AC-17), for holders of treatment.edit. */
export function TreatmentEditor({ id }: { id: string }) {
  const risk = useApi<RiskView>(`/api/v1/register/risks/${id}`);
  const t = useApi<TreatmentView>(`/api/v1/register/risks/${id}/treatment`);
  useEffect(() => {
    document.title = "Treatment plan · Risk register · FAIR Risk Platform";
  }, []);
  return (
    <Status loaded={risk}>
      {(v) => <Status loaded={t}>{(tv) => <PlanForm v={v} tv={tv} />}</Status>}
    </Status>
  );
}

function PlanForm({ v, tv }: { v: RiskView; tv: TreatmentView }) {
  const owners = useApi<{ owners: Owner[] }>(`/api/v1/register/owners?bu=${encodeURIComponent(v.risk.bu_id)}`);
  const [decision, setDecision] = useState<TreatmentDoc["decision"]>(tv.document.decision);
  const [rationale, setRationale] = useState(tv.document.rationale ?? "");
  const [targets, setTargets] = useState<Record<string, string>>(Object.fromEntries((tv.document.targets ?? []).map((x) => [x.scenario_id, x.control_set])));
  const [actions, setActions] = useState<Action[]>(tv.document.actions ?? []);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string>();
  const [problems, setProblems] = useState<{ pointer: string; message: string }[]>([]);
  const [busy, setBusy] = useState(false);
  const ownerList = owners.data?.owners ?? [];
  const today = new Date().toISOString().slice(0, 10);
  const setAction = (i: number, a: Partial<Action>) => setActions(actions.map((x, j) => (j === i ? { ...x, ...a } : x)));

  const save = async () => {
    setError(undefined);
    setProblems([]);
    if (!note.trim()) {
      setError("A change note is required.");
      return;
    }
    const document: TreatmentDoc = { schema_version: 1, decision };
    if (rationale.trim()) document.rationale = rationale;
    if (decision === "mitigate") {
      document.targets = Object.entries(targets)
        .filter(([, s]) => s)
        .map(([scenario_id, control_set]) => ({ scenario_id, control_set }));
    }
    document.actions = actions.map((a) => (a.state === "cancelled" ? a : { id: a.id, title: a.title, owner: a.owner, due: a.due, state: a.state }));
    setBusy(true);
    try {
      await send("PUT", `/api/v1/register/risks/${v.risk.id}/treatment`, { document, expected_version: tv.version, change_note: note });
      window.location.assign(`/register/risks/${v.risk.id}`);
    } catch (err) {
      const body = err instanceof ApiError ? (err.body as { problems?: { pointer: string; message: string }[] } | undefined) : undefined;
      if (body?.problems) setProblems(body.problems);
      setError(describe(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/register">Risk register</a> / <a href={`/register/risks/${v.risk.id}`}>{v.risk.title}</a>
      </nav>
      <h1>Treatment plan</h1>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void save();
        }}
      >
        <Section id="decision" title="Decision">
          <fieldset className="inline-choice">
            <legend>How the risk will be treated</legend>
            {(["mitigate", "transfer", "avoid", "accept"] as const).map((d) => (
              <label key={d}>
                <input type="radio" name="decision" value={d} checked={decision === d} onChange={() => setDecision(d)} /> {DECISION_LABEL[d]}
              </label>
            ))}
            <label>
              <input type="radio" name="decision" value="" checked={decision === null} onChange={() => setDecision(null)} /> Not decided
            </label>
          </fieldset>
          <div className="field">
            <label htmlFor="rationale">Rationale</label>
            <textarea id="rationale" rows={3} value={rationale} onChange={(e) => setRationale(e.target.value)} maxLength={5000} />
          </div>
          {decision === "accept" ? (
            <p className="muted">An acceptance is then needed, approved in the acceptance workflow.</p>
          ) : null}
        </Section>
        {decision === "mitigate" ? (
          <Section id="targets" title="Target control sets" intro="For each scenario, the control set the treatment is expected to reach, from the scenario's latest version.">
            {v.links.map((l) => (
              <TargetField key={l.scenario_id} scenarioId={l.scenario_id} name={l.scenario_name ?? l.scenario_id} value={targets[l.scenario_id] ?? ""} onChange={(s) => setTargets({ ...targets, [l.scenario_id]: s })} />
            ))}
          </Section>
        ) : null}
        <Section id="actions" title="Actions">
          {actions.map((a, i) => (
            <fieldset key={a.id} className="card nested">
              <legend>Action {i + 1}</legend>
              <div className="filters">
                <div className="field">
                  <label htmlFor={`a${i}-title`}>Title</label>
                  <input id={`a${i}-title`} value={a.title} onChange={(e) => setAction(i, { title: e.target.value })} maxLength={200} />
                </div>
                <div className="field">
                  <label htmlFor={`a${i}-owner`}>Owner</label>
                  <select id={`a${i}-owner`} value={a.owner} onChange={(e) => setAction(i, { owner: e.target.value })}>
                    {!ownerList.some((o) => o.user_id === a.owner) ? <option value={a.owner}>{a.owner}</option> : null}
                    {ownerList.map((o) => (
                      <option key={o.user_id} value={o.user_id}>
                        {o.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="field">
                  <label htmlFor={`a${i}-due`}>Due</label>
                  <input id={`a${i}-due`} type="date" value={a.due} onChange={(e) => setAction(i, { due: e.target.value })} />
                </div>
                <div className="field">
                  <label htmlFor={`a${i}-state`}>State</label>
                  <select id={`a${i}-state`} value={a.state} onChange={(e) => setAction(i, { state: e.target.value as Action["state"] })}>
                    {Object.entries(STATE_LABEL).map(([k, l]) => (
                      <option key={k} value={k}>
                        {l}
                      </option>
                    ))}
                  </select>
                </div>
                {a.state === "cancelled" ? (
                  <div className="field">
                    <label htmlFor={`a${i}-reason`}>Why cancelled</label>
                    <input id={`a${i}-reason`} value={a.cancel_reason ?? ""} onChange={(e) => setAction(i, { cancel_reason: e.target.value })} maxLength={1000} />
                  </div>
                ) : null}
                <div className="actions">
                  <button className="btn" type="button" onClick={() => setActions(actions.filter((_, j) => j !== i))}>
                    Remove action {i + 1}
                  </button>
                </div>
              </div>
            </fieldset>
          ))}
          <p className="actions">
            <button
              className="btn"
              type="button"
              onClick={() => setActions([...actions, { id: crypto.randomUUID(), title: "", owner: ownerList[0]?.user_id ?? v.risk.owner ?? "", due: today, state: "planned" }])}
            >
              Add an action
            </button>
          </p>
        </Section>
        <Section id="save" title="Save">
          <div className="field">
            <label htmlFor="note">Change note</label>
            <textarea id="note" rows={2} value={note} onChange={(e) => setNote(e.target.value)} maxLength={1000} />
          </div>
          {error ? (
            <div role="alert" className="error-text">
              <p>{error}</p>
              {problems.length > 0 ? (
                <ul>
                  {problems.map((p, i) => (
                    <li key={i}>
                      <span className="mono">{p.pointer}</span>: {p.message}
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}
          <div className="actions">
            <button className="react-aria-Button primary" type="submit" disabled={busy}>
              Save the plan
            </button>
            <a href={`/register/risks/${v.risk.id}`}>Cancel</a>
          </div>
        </Section>
      </form>
      <p className="muted">Last saved {tv.version === 0 ? "never" : `as version ${tv.version}`}; today is {date(today)}.</p>
    </>
  );
}

function TargetField({ scenarioId, name, value, onChange }: { scenarioId: string; name: string; value: string; onChange: (s: string) => void }) {
  const s = useApi<ScenarioView>(`/api/v1/scenarios/${scenarioId}`);
  const sets = s.data?.version.document?.control_sets.map((c) => c.name) ?? [];
  const id = `target-${scenarioId}`;
  return (
    <div className="field">
      <label htmlFor={id}>{name}</label>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">No target</option>
        {sets.map((x) => (
          <option key={x} value={x}>
            {x}
          </option>
        ))}
      </select>
    </div>
  );
}
