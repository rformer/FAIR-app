import { useEffect, useState } from "react";
import { ApiError, describe, send } from "../api";
import { Badge, ReasonAction, Section, Status, useApi } from "../components";
import { auditHref, date } from "../links";
import { EstimateFields, fieldId, newEstimate } from "../risk/EstimateFields";
import {
  at,
  factorLabel,
  showEstimate,
  type Estimate,
  type Head,
  type Problem,
  type ScenarioView,
} from "../risk/types";
import {
  AFFECTED_LABELS,
  METHOD_LABELS,
  STATUS_LABELS,
  showCalibration,
  type AnswersView,
  type Person,
  type Pooled,
  type RequestDetail,
  type RequestItem,
} from "./types";

// F-004 T-13 (AC-01 to AC-06, AC-15 to AC-19): the analyst's side of
// estimate requests: sending one from a scenario, its status and changes,
// the answers side by side with the estimators' calibration and the pools'
// previews, and accepting factors into a new scenario version.

const CONTEXT: [string, string][] = [
  ["name", "Scenario name"],
  ["description", "Description"],
  ["scope", "Scope"],
  ["analysis_period", "Analysis period"],
  ["asset", "Asset"],
  ["threat_community", "Threat community"],
  ["threat_effects", "Threat effects"],
  ["loss_event", "Loss event"],
];

/** The local date and time a datetime-local input shows for an instant. */
function localInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

function problemsOf(err: unknown): Problem[] | undefined {
  return err instanceof ApiError && err.status === 422
    ? (err.body as { problems?: Problem[] } | undefined)?.problems
    : undefined;
}

function Problems({
  error,
  problems,
  title,
}: {
  error?: string;
  problems: Problem[];
  title: string;
}) {
  return (
    <div aria-live="assertive">
      {error ? (
        <p role="alert" className="error-text">
          {error}
        </p>
      ) : null}
      {problems.length > 0 ? (
        <div role="alert" className="banner">
          <h2>{title}</h2>
          <ul>
            {problems.map((p, i) => (
              <li key={i}>
                <a href={`#${fieldId(p.pointer)}`}>
                  {p.pointer || "The request"}
                </a>
                : {p.message}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function StatusBadge({ r }: { r: RequestItem }) {
  const tone =
    r.status === "open" ? "info" : r.status === "complete" ? "ok" : "muted";
  return <Badge tone={tone}>{STATUS_LABELS[r.status]}</Badge>;
}

// --- On the scenario page ----------------------------------------------------

/** AC-04, AC-06: a scenario's requests, newest first, with the affected ones marked. */
export function ScenarioRequests({
  id,
  canRequest,
}: {
  id: string;
  canRequest: boolean;
}) {
  const list = useApi<{ requests: RequestItem[] }>(
    `/api/v1/estimates/requests?scenario=${id}`,
  );
  if (list.error instanceof ApiError && list.error.status === 404) return null;
  return (
    <Section
      id="requests"
      title="Estimate requests"
      intro="Requests to subject-matter experts for estimates of this scenario's factors."
    >
      {canRequest ? (
        <p className="actions">
          <a
            className="react-aria-Button"
            href={`/estimates/requests/new?scenario=${id}`}
          >
            Request estimates
          </a>
        </p>
      ) : null}
      <Status loaded={list}>
        {(d) =>
          d.requests.length === 0 ? (
            <p>No requests yet.</p>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <caption className="sr-only">
                  Estimate requests for this scenario, newest first
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Request</th>
                    <th scope="col">Due</th>
                    <th scope="col">Factors</th>
                    <th scope="col">Estimators</th>
                    <th scope="col">State</th>
                  </tr>
                </thead>
                <tbody>
                  {d.requests.map((r) => (
                    <tr key={r.id}>
                      <td>
                        <a href={`/estimates/requests/${r.id}`}>{r.title}</a>
                      </td>
                      <td>{date(r.due_at)}</td>
                      <td>{r.factors}</td>
                      <td>{r.estimators}</td>
                      <td>
                        <StatusBadge r={r} />{" "}
                        {r.affected ? (
                          <Badge tone="warn">Affected</Badge>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        }
      </Status>
    </Section>
  );
}

type Elicitation = {
  request: string;
  method: keyof typeof METHOD_LABELS;
  confidence: string;
  imported?: boolean;
  answers: {
    estimator: string;
    name: string;
    revision: number;
    weight: string;
    min: string;
    ml: string;
    max: string;
    confidence: string;
    calibration: Parameters<typeof showCalibration>[0];
  }[];
};

/** AC-18, AC-31: where the scenario's accepted estimates came from. */
export function Provenance({ v }: { v: ScenarioView }) {
  const rows = v.taxonomy
    .filter((n) => n.pointer)
    .map((n) => ({
      n,
      e: at(v.version.document, n.pointer!) as
        (Estimate & { elicitation?: Elicitation }) | undefined,
    }))
    .filter((x) => x.e?.elicitation);
  if (rows.length === 0) return null;
  return (
    <Section
      id="provenance"
      title="Estimates from experts"
      intro="Estimates accepted from estimate requests: the method, the answers used, and each estimator's calibration when they answered."
    >
      {rows.map(({ n, e }) => {
        const el = e!.elicitation!;
        return (
          <div key={n.pointer} className="group">
            <h3>{factorLabel(n.factor)}</h3>
            <p>
              {METHOD_LABELS[el.method] ?? el.method}:{" "}
              {showEstimate(e, v.currency)}.{" "}
              {el.imported ? (
                <Badge tone="muted">Imported: not verified here</Badge>
              ) : (
                <>
                  From{" "}
                  <a href={`/estimates/requests/${el.request}`}>
                    estimate request
                  </a>
                  .
                </>
              )}
            </p>
            {el.answers.length > 0 ? (
              <div className="table-wrap">
                <table className="data">
                  <caption className="sr-only">
                    Answers used for {factorLabel(n.factor).toLowerCase()}
                  </caption>
                  <thead>
                    <tr>
                      <th scope="col">Estimator</th>
                      <th scope="col">Answer</th>
                      <th scope="col">Weight</th>
                      <th scope="col">Calibration then</th>
                    </tr>
                  </thead>
                  <tbody>
                    {el.answers.map((a) => (
                      <tr key={a.estimator}>
                        <td>{a.name}</td>
                        <td>
                          {a.min} – {a.ml} – {a.max} (
                          {Math.round(Number(a.confidence) * 100)}%), revision{" "}
                          {a.revision}
                        </td>
                        <td>{a.weight}</td>
                        <td>{showCalibration(a.calibration)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}
          </div>
        );
      })}
    </Section>
  );
}

// --- Sending a request (AC-01, AC-02, AC-14) ---------------------------------

export function RequestForm({
  search = window.location.search,
}: {
  search?: string;
}) {
  const sid = new URLSearchParams(search).get("scenario") ?? "";
  const view = useApi<ScenarioView>(`/api/v1/scenarios/${sid}`);
  useEffect(() => {
    document.title = "Request estimates · FAIR Risk Platform";
  }, []);
  return <Status loaded={view}>{(v) => <NewRequest v={v} />}</Status>;
}

function NewRequest({ v }: { v: ScenarioView }) {
  const doc = v.version.document!;
  const people = useApi<{ estimators: Person[] }>(
    `/api/v1/estimates/estimators?bu=${v.scenario.bu_id}`,
  );
  const refs = useApi<{ entries: Head[] }>(
    "/api/v1/library?kind=reference_class",
  );
  const factors = v.taxonomy.filter((n) => n.status === "entered" && n.pointer);
  const [title, setTitle] = useState(`Estimates for ${doc.name}`);
  const [instructions, setInstructions] = useState("");
  const [confidence, setConfidence] = useState("0.9");
  const [due, setDue] = useState(() =>
    localInput(new Date(Date.now() + 7 * 864e5)),
  );
  const [chosen, setChosen] = useState<string[]>([]);
  const [context, setContext] = useState<string[]>(CONTEXT.map(([k]) => k));
  const [estimators, setEstimators] = useState<string[]>([]);
  const [references, setReferences] = useState<string[]>([]);
  const [problems, setProblems] = useState<Problem[]>([]);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const toggle = (
    list: string[],
    set: (l: string[]) => void,
    k: string,
    on: boolean,
  ) => set(on ? [...list, k] : list.filter((x) => x !== k));

  const submit = async () => {
    setProblems([]);
    setError(undefined);
    if (chosen.length === 0 || estimators.length === 0) {
      setError("Choose at least one factor and one estimator.");
      return;
    }
    setBusy(true);
    try {
      const entries = refs.data?.entries ?? [];
      const made = await send<{ id: string }>(
        "POST",
        "/api/v1/estimates/requests",
        {
          scenario_id: v.scenario.id,
          title,
          instructions: instructions || undefined,
          confidence,
          due_at: new Date(due).toISOString(),
          factors: chosen,
          context,
          estimators,
          references: references.map((id) => ({
            id,
            version: entries.find((e) => e.id === id)!.current_version,
          })),
        },
      );
      window.location.assign(`/estimates/requests/${made.id}`);
    } catch (err) {
      const listed = problemsOf(err);
      if (listed?.length) setProblems(listed);
      else setError(describe(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/scenarios">Scenarios</a> ›{" "}
        <a href={`/scenarios/${v.scenario.id}`}>{doc.name}</a>
      </nav>
      <h1>Request estimates</h1>
      <p className="lede">
        From version {v.scenario.current_version} of {doc.name}. Each estimator
        answers on their own and sees only what you share here.
      </p>
      <Problems error={error} problems={problems} title="Not sent" />
      <form
        className="editor"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Section id="request" title="Request">
          <div className="field">
            <label htmlFor={fieldId("/title")}>Title</label>
            <input
              id={fieldId("/title")}
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor={fieldId("/instructions")}>
              Instructions (optional)
            </label>
            <textarea
              id={fieldId("/instructions")}
              rows={3}
              value={instructions}
              onChange={(e) => setInstructions(e.target.value)}
            />
          </div>
          <div className="grid">
            <div className="field">
              <label htmlFor={fieldId("/due_at")}>Due</label>
              <input
                id={fieldId("/due_at")}
                type="datetime-local"
                value={due}
                onChange={(e) => setDue(e.target.value)}
              />
            </div>
            <div className="field">
              <label htmlFor={fieldId("/confidence")}>
                Confidence to answer at (0 to 1)
              </label>
              <input
                id={fieldId("/confidence")}
                inputMode="decimal"
                value={confidence}
                onChange={(e) => setConfidence(e.target.value)}
              />
            </div>
          </div>
        </Section>
        <Section id="factors" title="Factors">
          <fieldset className="checks" id={fieldId("/factors")}>
            <legend>Factors to estimate</legend>
            {factors.map((n) => (
              <label key={n.pointer}>
                <input
                  type="checkbox"
                  checked={chosen.includes(n.pointer!)}
                  onChange={(e) =>
                    toggle(chosen, setChosen, n.pointer!, e.target.checked)
                  }
                />{" "}
                {factorLabel(n.factor)}
              </label>
            ))}
          </fieldset>
        </Section>
        <Section
          id="estimators"
          title="Estimators"
          intro="People who hold the Estimator permission at this scenario's business unit."
        >
          <Status loaded={people}>
            {(d) =>
              d.estimators.length === 0 ? (
                <p>
                  Nobody can be asked here yet: estimators need the Estimator
                  role at this business unit.
                </p>
              ) : (
                <fieldset className="checks" id={fieldId("/estimators")}>
                  <legend>Estimators to ask</legend>
                  {d.estimators.map((p) => (
                    <label key={p.user_id}>
                      <input
                        type="checkbox"
                        checked={estimators.includes(p.user_id)}
                        onChange={(e) =>
                          toggle(
                            estimators,
                            setEstimators,
                            p.user_id,
                            e.target.checked,
                          )
                        }
                      />{" "}
                      {p.name}
                    </label>
                  ))}
                </fieldset>
              )
            }
          </Status>
        </Section>
        <Section id="shared" title="What estimators see">
          <fieldset className="checks" id={fieldId("/context")}>
            <legend>Scenario context to share</legend>
            {CONTEXT.map(([k, label]) => (
              <label key={k}>
                <input
                  type="checkbox"
                  checked={context.includes(k)}
                  onChange={(e) =>
                    toggle(context, setContext, k, e.target.checked)
                  }
                />{" "}
                {label}
              </label>
            ))}
          </fieldset>
          <fieldset className="checks" id={fieldId("/references")}>
            <legend>Reference classes to attach</legend>
            {(refs.data?.entries ?? []).length === 0 ? (
              <p className="muted">No reference classes in the library.</p>
            ) : null}
            {(refs.data?.entries ?? []).map((r) => (
              <label key={r.id}>
                <input
                  type="checkbox"
                  checked={references.includes(r.id)}
                  onChange={(e) =>
                    toggle(references, setReferences, r.id, e.target.checked)
                  }
                />{" "}
                {r.name ?? r.id} (version {r.current_version})
              </label>
            ))}
          </fieldset>
        </Section>
        <div className="actions">
          <button type="submit" className="btn primary" disabled={busy}>
            Send the request
          </button>
          <a href={`/scenarios/${v.scenario.id}`}>Cancel</a>
        </div>
      </form>
    </>
  );
}

// --- One request (AC-03 to AC-06, AC-15 to AC-19) -----------------------------

export function RequestPage({ id }: { id: string }) {
  const detail = useApi<RequestDetail>(`/api/v1/estimates/requests/${id}`);
  const answers = useApi<AnswersView>(
    `/api/v1/estimates/requests/${id}/answers`,
  );
  const editable = useApi<{ bus: { id: string }[] }>(
    "/api/v1/risk/bus?permission=scenario.edit",
  );
  const settings = useApi<{ currency: string | null }>("/api/v1/risk/settings");
  useEffect(() => {
    if (detail.data)
      document.title = `${detail.data.request.title} · Estimate requests · FAIR Risk Platform`;
  }, [detail.data]);
  const reload = () => {
    detail.reload();
    answers.reload();
  };
  return (
    <Status loaded={detail}>
      {(d) => {
        const r = d.request;
        const mayEdit =
          editable.data?.bus.some((b) => b.id === r.bu_id) ?? false;
        const names = new Map(
          (answers.data?.estimators ?? []).map((e) => [e.user_id, e.name]),
        );
        const name = (u: string) => names.get(u) ?? u;
        return (
          <>
            <nav aria-label="Breadcrumb" className="crumbs">
              <a href="/scenarios">Scenarios</a> ›{" "}
              <a href={`/scenarios/${r.scenario_id}`}>
                {d.context.name ?? "Scenario"}
              </a>
            </nav>
            <h1>{r.title}</h1>
            <p className="lede">
              From version {r.scenario_version} · due {date(r.due_at)} · at{" "}
              {Math.round(Number(r.confidence) * 100)}% confidence ·{" "}
              <StatusBadge r={r} />
            </p>
            {r.affected ? (
              <div className="banner warn" role="status">
                <p>
                  {AFFECTED_LABELS[r.affected]} Its answers stay as they were
                  given; check them before accepting.
                </p>
              </div>
            ) : null}
            {r.status === "cancelled" && r.cancel_reason ? (
              <p>Cancelled: {r.cancel_reason}</p>
            ) : null}
            <p className="actions">
              {mayEdit && r.status === "open" ? (
                <ReasonAction
                  label="Cancel the request"
                  title="Cancel the request"
                  fieldLabel="Reason"
                  description={
                    <p>
                      Its estimators are told it is closed; answers already
                      given are kept.
                    </p>
                  }
                  submitLabel="Cancel the request"
                  onSubmit={async (reason) => {
                    await send(
                      "POST",
                      `/api/v1/estimates/requests/${id}/cancel`,
                      { reason },
                    );
                    reload();
                  }}
                />
              ) : null}
              <a href={auditHref(`estimate_request:${id}`)}>
                Audit history of this request
              </a>
            </p>
            <Section id="status" title="Factors and estimators">
              <div className="table-wrap">
                <table className="data">
                  <caption className="sr-only">Requested factors</caption>
                  <thead>
                    <tr>
                      <th scope="col">Factor</th>
                      <th scope="col">Accepted</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.factors.map((f) => (
                      <tr key={f.pointer}>
                        <td>{factorLabel(f.factor)}</td>
                        <td>
                          {f.accepted_version ? (
                            `Into version ${f.accepted_version} (${date(f.accepted_at!)})`
                          ) : (
                            <span className="muted">Not yet</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <ul className="plain" aria-label="Estimators">
                {d.estimators.map((e) => (
                  <li key={e.user_id}>
                    {name(e.user_id)}{" "}
                    {e.removed_at ? (
                      <Badge tone="muted">Removed</Badge>
                    ) : e.finished_at ? (
                      <Badge tone="ok">Answered every factor</Badge>
                    ) : (
                      <Badge tone="info">Waiting</Badge>
                    )}
                  </li>
                ))}
              </ul>
              {d.references.length > 0 ? (
                <p>
                  Reference classes attached:{" "}
                  {d.references
                    .map((x) => `${x.name} (version ${x.version})`)
                    .join("; ")}
                  .
                </p>
              ) : null}
            </Section>
            {mayEdit && r.status === "open" ? (
              <ChangeRequest d={d} name={name} onDone={reload} />
            ) : null}
            <Status loaded={answers}>
              {(a) => (
                <Review a={a} currency={settings.data?.currency ?? null} />
              )}
            </Status>
            {mayEdit && answers.data && r.status !== "cancelled" ? (
              <Accept d={d} a={answers.data} onDone={reload} />
            ) : null}
          </>
        );
      }}
    </Status>
  );
}

/** AC-03: extend the due date, add or remove estimators. */
function ChangeRequest({
  d,
  name,
  onDone,
}: {
  d: RequestDetail;
  name: (u: string) => string;
  onDone: () => void;
}) {
  const r = d.request;
  const people = useApi<{ estimators: Person[] }>(
    `/api/v1/estimates/estimators?bu=${r.bu_id}`,
  );
  const current = d.estimators
    .filter((e) => !e.removed_at)
    .map((e) => e.user_id);
  const [due, setDue] = useState(localInput(new Date(r.due_at)));
  const [add, setAdd] = useState<string[]>([]);
  const [remove, setRemove] = useState<string[]>([]);
  const [reason, setReason] = useState("");
  const [result, setResult] = useState<{ ok?: string; error?: string }>({});
  const addable = (people.data?.estimators ?? []).filter(
    (p) => !d.estimators.some((e) => e.user_id === p.user_id && !e.removed_at),
  );
  return (
    <Section id="change" title="Change the request">
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setResult({});
          const body: Record<string, unknown> = {};
          if (localInput(new Date(r.due_at)) !== due)
            body.due_at = new Date(due).toISOString();
          if (add.length) body.add_estimators = add;
          if (remove.length) body.remove_estimators = remove;
          if (reason) body.reason = reason;
          if (!body.due_at && !add.length && !remove.length) {
            setResult({
              error: "Change the due date or the estimators first.",
            });
            return;
          }
          try {
            await send("PATCH", `/api/v1/estimates/requests/${r.id}`, body);
            setAdd([]);
            setRemove([]);
            setReason("");
            setResult({ ok: "The request was changed." });
            onDone();
          } catch (err) {
            setResult({ error: describe(err) });
          }
        }}
      >
        <div className="field">
          <label htmlFor="change-due">Due</label>
          <input
            id="change-due"
            type="datetime-local"
            value={due}
            onChange={(e) => setDue(e.target.value)}
          />
        </div>
        {addable.length > 0 ? (
          <fieldset className="checks">
            <legend>Add estimators</legend>
            {addable.map((p) => (
              <label key={p.user_id}>
                <input
                  type="checkbox"
                  checked={add.includes(p.user_id)}
                  onChange={(e) =>
                    setAdd(
                      e.target.checked
                        ? [...add, p.user_id]
                        : add.filter((x) => x !== p.user_id),
                    )
                  }
                />{" "}
                {p.name}
              </label>
            ))}
          </fieldset>
        ) : null}
        <fieldset className="checks">
          <legend>Remove estimators (their answers are kept)</legend>
          {current.map((u) => (
            <label key={u}>
              <input
                type="checkbox"
                checked={remove.includes(u)}
                onChange={(e) =>
                  setRemove(
                    e.target.checked
                      ? [...remove, u]
                      : remove.filter((x) => x !== u),
                  )
                }
              />{" "}
              {name(u)}
            </label>
          ))}
        </fieldset>
        <div className="field">
          <label htmlFor="change-reason">Reason (optional)</label>
          <input
            id="change-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        </div>
        <div aria-live="polite">
          {result.ok ? <p role="status">{result.ok}</p> : null}
          {result.error ? (
            <p role="alert" className="error-text">
              {result.error}
            </p>
          ) : null}
        </div>
        <div className="actions">
          <button type="submit" className="btn">
            Save the changes
          </button>
        </div>
      </form>
    </Section>
  );
}

function showPool(p: Pooled | undefined): string {
  return p
    ? `${p.Min} – ${p.ML} – ${p.Max} (${Math.round(Number(p.Confidence) * 100)}%)`
    : "Not available";
}

/** AC-15: every submitted answer per factor, side by side. */
function Review({ a, currency }: { a: AnswersView; currency: string | null }) {
  const name = (u: string) =>
    a.estimators.find((e) => e.user_id === u)?.name ?? u;
  return (
    <Section
      id="answers"
      title="Answers"
      intro="Submitted answers only, never drafts. Calibration is each estimator's as it was when they answered."
    >
      {a.factors.map((f) => (
        <div
          key={f.pointer}
          className="group"
          role="group"
          aria-labelledby={`${fieldId(f.pointer)}-review`}
        >
          <h3 id={`${fieldId(f.pointer)}-review`}>{factorLabel(f.factor)}</h3>
          {f.answers.length === 0 ? (
            <p className="muted">No answers yet.</p>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <caption className="sr-only">
                  Answers for {factorLabel(f.factor).toLowerCase()}
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Estimator</th>
                    <th scope="col">Answer</th>
                    <th scope="col">Rationale</th>
                    <th scope="col">Calibration then</th>
                    <th scope="col">Submitted</th>
                  </tr>
                </thead>
                <tbody>
                  {f.answers.map((x) => (
                    <tr key={`${x.estimator}-${x.revision}`}>
                      <td>
                        {name(x.estimator)}{" "}
                        <span className="muted">(revision {x.revision})</span>
                      </td>
                      <td>
                        {x.declined !== null ? (
                          <>Declined: {x.declined}</>
                        ) : (
                          showEstimate(x.estimate ?? undefined, currency)
                        )}
                      </td>
                      <td>{x.estimate?.rationale ?? "—"}</td>
                      <td>{showCalibration(x.calibration)}</td>
                      <td>{date(x.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <dl className="summary">
            <div>
              <dt>{METHOD_LABELS.equal}</dt>
              <dd>{showPool(f.previews.equal)}</dd>
            </div>
            <div>
              <dt>{METHOD_LABELS.calibration}</dt>
              <dd>{showPool(f.previews.calibration)}</dd>
            </div>
          </dl>
        </div>
      ))}
    </Section>
  );
}

type Choice = {
  on: boolean;
  method: keyof typeof METHOD_LABELS;
  single: string;
  pool: string[];
  own: Estimate;
};

/** AC-16 to AC-19: accept factors into one new version of the scenario. */
function Accept({
  d,
  a,
  onDone,
}: {
  d: RequestDetail;
  a: AnswersView;
  onDone: () => void;
}) {
  const r = d.request;
  const scenario = useApi<ScenarioView>(`/api/v1/scenarios/${r.scenario_id}`);
  const answered = (pointer: string) => {
    const latest = new Map<
      string,
      AnswersView["factors"][number]["answers"][number]
    >();
    for (const x of a.factors.find((f) => f.pointer === pointer)?.answers ?? [])
      latest.set(x.estimator, x);
    return [...latest.values()]
      .filter((x) => x.declined === null)
      .map((x) => x.estimator);
  };
  const [choices, setChoices] = useState<Record<string, Choice>>(() =>
    Object.fromEntries(
      a.factors.map((f) => {
        const who = answered(f.pointer);
        return [
          f.pointer,
          {
            on: false,
            method: who.length > 1 ? "equal" : "single",
            single: who[0] ?? "",
            pool: who,
            own: { ...newEstimate(f.unit), confidence: r.confidence },
          },
        ];
      }),
    ),
  );
  const [note, setNote] = useState("");
  const [problems, setProblems] = useState<Problem[]>([]);
  const [error, setError] = useState<string>();
  const [saved, setSaved] = useState<number>();
  const set = (p: string, patch: Partial<Choice>) =>
    setChoices((c) => ({ ...c, [p]: { ...c[p]!, ...patch } }));
  const name = (u: string) =>
    a.estimators.find((e) => e.user_id === u)?.name ?? u;
  const toggle = (list: string[], u: string, on: boolean) =>
    on ? [...list, u] : list.filter((x) => x !== u);

  const submit = async () => {
    setProblems([]);
    setError(undefined);
    setSaved(undefined);
    const factors = a.factors
      .filter((f) => choices[f.pointer]!.on)
      .map((f) => {
        const c = choices[f.pointer]!;
        if (c.method === "single")
          return {
            pointer: f.pointer,
            method: "single",
            estimators: [c.single],
          };
        if (c.method === "own")
          return {
            pointer: f.pointer,
            method: "own",
            estimators: c.pool,
            estimate: c.own,
          };
        return { pointer: f.pointer, method: c.method, estimators: c.pool };
      });
    if (factors.length === 0) {
      setError("Choose a factor to accept.");
      return;
    }
    try {
      const out = await send<{ version: number }>(
        "POST",
        `/api/v1/estimates/requests/${r.id}/accept`,
        {
          expected_version: scenario.data!.scenario.current_version,
          change_note: note,
          factors,
        },
      );
      setSaved(out.version);
      scenario.reload();
      onDone();
    } catch (err) {
      const listed = problemsOf(err);
      if (listed?.length) setProblems(listed);
      else if (err instanceof ApiError && err.code === "stale_version")
        setError(
          "The scenario has a newer version than this page knew: reload and try again.",
        );
      else setError(describe(err));
    }
  };

  return (
    <Section
      id="accept"
      title="Accept into the scenario"
      intro="The accepted factors are saved together as one new version of the scenario, each with where it came from."
    >
      <form
        className="editor"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        {a.factors.map((f) => {
          const c = choices[f.pointer]!;
          const who = answered(f.pointer);
          const label = factorLabel(f.factor);
          const fid = fieldId(f.pointer);
          return (
            <fieldset key={f.pointer} className="group" id={fid}>
              <legend>{label}</legend>
              <label>
                <input
                  type="checkbox"
                  checked={c.on}
                  onChange={(e) => set(f.pointer, { on: e.target.checked })}
                />{" "}
                Accept {label.toLowerCase()}
              </label>
              {c.on ? (
                <>
                  <div className="field">
                    <label htmlFor={`${fid}-method`}>
                      Method for {label.toLowerCase()}
                    </label>
                    <select
                      id={`${fid}-method`}
                      value={c.method}
                      onChange={(e) =>
                        set(f.pointer, {
                          method: e.target.value as Choice["method"],
                        })
                      }
                    >
                      {(Object.keys(METHOD_LABELS) as Choice["method"][]).map(
                        (m) => (
                          <option key={m} value={m}>
                            {METHOD_LABELS[m]}
                          </option>
                        ),
                      )}
                    </select>
                  </div>
                  {c.method === "single" ? (
                    <div className="field">
                      <label htmlFor={`${fid}-single`}>Whose answer</label>
                      <select
                        id={`${fid}-single`}
                        value={c.single}
                        onChange={(e) =>
                          set(f.pointer, { single: e.target.value })
                        }
                      >
                        {who.map((u) => (
                          <option key={u} value={u}>
                            {name(u)}
                          </option>
                        ))}
                      </select>
                    </div>
                  ) : (
                    <fieldset className="checks">
                      <legend>
                        {c.method === "own"
                          ? "Answers your estimate refers to"
                          : "Answers to pool"}
                      </legend>
                      {who.map((u) => (
                        <label key={u}>
                          <input
                            type="checkbox"
                            checked={c.pool.includes(u)}
                            onChange={(e) =>
                              set(f.pointer, {
                                pool: toggle(c.pool, u, e.target.checked),
                              })
                            }
                          />{" "}
                          {name(u)}
                        </label>
                      ))}
                    </fieldset>
                  )}
                  {c.method === "own" ? (
                    <EstimateFields
                      legend={`Your estimate of ${label.toLowerCase()}`}
                      pointer={f.pointer}
                      value={c.own}
                      currency={scenario.data?.currency ?? null}
                      requested={r.confidence}
                      onChange={(own) => set(f.pointer, { own })}
                    />
                  ) : null}
                </>
              ) : null}
            </fieldset>
          );
        })}
        <div className="field">
          <label htmlFor="accept-note">Change note</label>
          <textarea
            id="accept-note"
            rows={2}
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
        </div>
        <Problems error={error} problems={problems} title="Not accepted" />
        <div aria-live="polite">
          {saved ? (
            <p role="status">
              Saved as version {saved} of the scenario.{" "}
              <a href={`/scenarios/${r.scenario_id}`}>Open the scenario</a>
            </p>
          ) : null}
        </div>
        <div className="actions">
          <button
            type="submit"
            className="btn primary"
            disabled={!scenario.data}
          >
            Accept into a new version
          </button>
        </div>
      </form>
    </Section>
  );
}
