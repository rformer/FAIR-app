import { useEffect, useState } from "react";
import { ApiError, describe, send } from "../api";
import { Badge, Section, Status, useApi } from "../components";
import { date } from "../links";
import { EstimateFields, fieldId, newEstimate } from "../risk/EstimateFields";
import { factorLabel, type Estimate } from "../risk/types";
import {
  STATUS_LABELS,
  type EstimatorView,
  type Reference,
  type RequestFactor,
} from "./types";

// F-004 T-12 (AC-07 to AC-12, AC-14): one request as its estimator sees it:
// the request, the context the analyst shared, the reference classes, and
// an answer per factor (an estimate with the estimating aids, or a decline
// with a reason), saved as drafts or submitted.

type Draft = {
  mode: "answer" | "decline";
  estimate: Estimate;
  declined: string;
};

const answerPointer = (p: string) => `/answers${p}`;

export function AnswerPage({ id }: { id: string }) {
  const view = useApi<EstimatorView>(`/api/v1/estimates/inbox/${id}`);
  useEffect(() => {
    if (view.data)
      document.title = `${view.data.request.title} · Estimate requests · FAIR Risk Platform`;
  }, [view.data]);
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/estimates">Estimate requests</a>
      </nav>
      <Status loaded={view}>
        {(v) => <Answer key={v.request.id} v={v} reload={view.reload} />}
      </Status>
    </>
  );
}

function Answer({ v, reload }: { v: EstimatorView; reload: () => void }) {
  const r = v.request;
  const open =
    (r.status === "open" || r.status === "complete") &&
    new Date(r.due_at) > new Date();
  const latest = (p: string) => v.answers.filter((a) => a.pointer === p).at(-1);
  const [drafts, setDrafts] = useState<Record<string, Draft>>(() =>
    Object.fromEntries(
      v.factors.map((f) => {
        const a = latest(f.pointer);
        return [
          f.pointer,
          {
            mode: a?.declined ? "decline" : "answer",
            estimate: a?.estimate ?? {
              ...newEstimate(f.unit),
              confidence: r.confidence,
            },
            declined: a?.declined ?? "",
          },
        ];
      }),
    ),
  );
  const [result, setResult] = useState<{
    ok?: string;
    error?: string;
    problems?: { pointer: string; message: string }[];
  }>({});
  const set = (p: string, patch: Partial<Draft>) =>
    setDrafts((d) => ({ ...d, [p]: { ...d[p]!, ...patch } }));
  const filled = (d: Draft) =>
    d.mode === "decline"
      ? d.declined.trim() !== ""
      : d.estimate.min !== "" &&
        d.estimate.ml !== "" &&
        d.estimate.max !== "" &&
        d.estimate.rationale.trim() !== "";

  const save = async (submit: boolean) => {
    setResult({});
    const answers = v.factors
      .filter((f) => filled(drafts[f.pointer]!))
      .map((f) => {
        const d = drafts[f.pointer]!;
        return d.mode === "decline"
          ? { pointer: f.pointer, declined: d.declined }
          : { pointer: f.pointer, estimate: d.estimate };
      });
    if (answers.length === 0) {
      setResult({ error: "Answer or decline a factor first." });
      return;
    }
    try {
      await send("PUT", `/api/v1/estimates/inbox/${r.id}/answers`, {
        submit,
        answers,
      });
      setResult({
        ok: submit
          ? `Submitted ${answers.length} answer${answers.length === 1 ? "" : "s"}.`
          : "Drafts saved: only you can see them.",
      });
      reload();
    } catch (err) {
      const body =
        err instanceof ApiError
          ? (err.body as
              { problems?: { pointer: string; message: string }[] } | undefined)
          : undefined;
      setResult({ error: describe(err), problems: body?.problems });
    }
  };

  return (
    <>
      <h1>{r.title}</h1>
      <p className="lede">
        Due {date(r.due_at)} · answer at{" "}
        {Math.round(Number(r.confidence) * 100)}% confidence ·{" "}
        {r.finished_at ? (
          <Badge tone="ok">You have answered every factor</Badge>
        ) : (
          <Badge tone={r.status === "open" ? "info" : "muted"}>
            {STATUS_LABELS[r.status]}
          </Badge>
        )}
      </p>
      {r.instructions ? (
        <Section id="instructions" title="Instructions">
          <p className="prewrap">{r.instructions}</p>
        </Section>
      ) : null}
      <ContextSection v={v} />
      {v.references.length > 0 ? <References refs={v.references} /> : null}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void save(true);
        }}
      >
        {v.factors.map((f) => (
          <FactorAnswer
            key={f.pointer}
            f={f}
            draft={drafts[f.pointer]!}
            set={(p) => set(f.pointer, p)}
            disabled={!open}
            requested={r.confidence}
            history={v.answers.filter((a) => a.pointer === f.pointer)}
          />
        ))}
        <div aria-live="polite">
          {result.ok ? <p role="status">{result.ok}</p> : null}
          {result.error ? (
            <div role="alert" className="banner">
              <p>{result.error}</p>
              {result.problems?.length ? (
                <ul>
                  {result.problems.map((p, i) => (
                    <li key={i}>
                      <a href={`#${fieldId(answerPointer(p.pointer))}`}>
                        {p.pointer}
                      </a>
                      : {p.message}
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}
        </div>
        {open ? (
          <div className="actions">
            <button
              type="button"
              className="btn"
              onClick={() => void save(false)}
            >
              Save drafts
            </button>
            <button type="submit" className="btn primary">
              Submit answers
            </button>
          </div>
        ) : (
          <p className="muted">This request no longer takes answers.</p>
        )}
      </form>
    </>
  );
}

function ContextSection({ v }: { v: EstimatorView }) {
  const c = v.context;
  const rows: [string, string][] = [];
  if (c.name) rows.push(["Scenario", c.name]);
  if (c.description) rows.push(["Description", c.description]);
  if (c.scope)
    rows.push(
      ["In scope", c.scope.in],
      ...(c.scope.out
        ? ([["Out of scope", c.scope.out]] as [string, string][])
        : []),
    );
  if (c.analysis_period)
    rows.push([
      "Analysis period",
      `${c.analysis_period.start} to ${c.analysis_period.end}`,
    ]);
  if (c.asset)
    rows.push([
      "Asset",
      [c.asset.name, c.asset.asset_type, c.asset.description]
        .filter(Boolean)
        .join(" · "),
    ]);
  if (c.threat_community)
    rows.push([
      "Threat community",
      [c.threat_community.name, c.threat_community.description]
        .filter(Boolean)
        .join(" · "),
    ]);
  if (c.threat_effects?.length)
    rows.push(["Threat effects", c.threat_effects.join(", ")]);
  if (c.loss_event) rows.push(["Loss event", c.loss_event]);
  if (rows.length === 0) return null;
  return (
    <Section id="context" title="What the estimates are about">
      <dl className="summary">
        {rows.map(([k, val]) => (
          <div key={k}>
            <dt>{k}</dt>
            <dd>{val}</dd>
          </div>
        ))}
      </dl>
    </Section>
  );
}

function summary(r: Reference): string {
  const d = r.document.data;
  if (d.kind === "counts") {
    const total = d.series.reduce((n, s) => n + s.count, 0);
    const years = d.series.reduce(
      (y, s) =>
        y + (Date.parse(s.end) - Date.parse(s.start)) / (365.25 * 864e5),
      0,
    );
    return `${total} event${total === 1 ? "" : "s"} in ${d.series.length} period${d.series.length === 1 ? "" : "s"}${years > 0 ? `, about ${(total / years).toFixed(1)} a year` : ""}`;
  }
  const xs = d.amounts.map(Number).sort((a, b) => a - b);
  const median =
    xs.length % 2
      ? xs[(xs.length - 1) / 2]!
      : (xs[xs.length / 2 - 1]! + xs[xs.length / 2]!) / 2;
  return `${xs.length} observed loss${xs.length === 1 ? "" : "es"}: lowest ${xs[0]}, median ${median}, highest ${xs[xs.length - 1]}`;
}

function References({ refs }: { refs: Reference[] }) {
  return (
    <Section
      id="references"
      title="Reference data"
      intro="Your organization's own data, attached by the analyst. It is not industry data."
    >
      <ul className="plain">
        {refs.map((r) => (
          <li key={r.id}>
            <strong>{r.document.name}</strong> ({r.document.period.start} to{" "}
            {r.document.period.end}): {summary(r)}.
            {r.document.description ? <> {r.document.description}</> : null}
            <span className="muted">
              {" "}
              Source: {r.document.sources.map((s) => s.ref).join("; ")}.
            </span>
          </li>
        ))}
      </ul>
    </Section>
  );
}

function FactorAnswer({
  f,
  draft,
  set,
  disabled,
  requested,
  history,
}: {
  f: RequestFactor;
  draft: Draft;
  set: (p: Partial<Draft>) => void;
  disabled: boolean;
  requested: string;
  history: EstimatorView["answers"];
}) {
  const name = factorLabel(f.factor);
  const id = fieldId(answerPointer(f.pointer));
  const last = history.at(-1);
  return (
    <Section id={`${id}-section`} title={name}>
      <p>{f.definition}</p>
      {last ? (
        <p className="muted">
          Your last answer: revision {last.revision},{" "}
          {last.state === "draft" ? "a draft only you can see" : "submitted"}.
        </p>
      ) : null}
      <fieldset disabled={disabled} className="choice">
        <legend className="sr-only">{name}: answer or decline</legend>
        <label>
          <input
            type="radio"
            name={`${id}-mode`}
            checked={draft.mode === "answer"}
            onChange={() => set({ mode: "answer" })}
          />{" "}
          Give an estimate
        </label>
        <label>
          <input
            type="radio"
            name={`${id}-mode`}
            checked={draft.mode === "decline"}
            onChange={() => set({ mode: "decline" })}
          />{" "}
          Decline this factor
        </label>
      </fieldset>
      {draft.mode === "answer" ? (
        <fieldset disabled={disabled} className="plain">
          <EstimateFields
            legend={`Your estimate of ${name.toLowerCase()}`}
            pointer={answerPointer(f.pointer)}
            value={draft.estimate}
            currency={null}
            requested={requested}
            onChange={(e) => set({ estimate: e })}
          />
        </fieldset>
      ) : (
        <div className="field">
          <label htmlFor={`${id}-declined`}>Why you decline</label>
          <textarea
            id={`${id}-declined`}
            rows={2}
            value={draft.declined}
            disabled={disabled}
            onChange={(e) => set({ declined: e.target.value })}
          />
        </div>
      )}
    </Section>
  );
}
