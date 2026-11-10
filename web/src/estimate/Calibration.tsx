import { useEffect, useState } from "react";
import { ApiError, describe, send } from "../api";
import { Badge, Section, Status, useApi, type Tone } from "../components";
import { date } from "../links";
import { CLASS_LABELS, type CalibrationSnapshot } from "./types";

// F-004 T-14 (AC-20 to AC-27): calibration exercises (keyboard only, no
// time limits), the feedback after submitting, the person's own record and
// history, and question set administration for calibration.manage.

type Klass = CalibrationSnapshot["class"];
const TONE: Record<Klass, Tone> = {
  calibrated: "ok",
  overconfident: "warn",
  underconfident: "warn",
  not_measured: "muted",
};

function ClassBadge({ c }: { c: Klass | undefined }) {
  const k = c ?? "not_measured";
  return <Badge tone={TONE[k] ?? "muted"}>{CLASS_LABELS[k] ?? k}</Badge>;
}

interface Score {
  class: Klass;
  ranges?: {
    n: number;
    hits: number;
    rate?: string;
    band: [number, number];
    class: Klass;
  };
  binary?: {
    n: number;
    correct: number;
    expected?: string;
    z?: string;
    brier?: string;
    class: Klass;
  };
  computed_at?: string;
}

interface Question {
  id: string;
  version: number;
  kind: "range" | "binary";
  text: string;
  unit: string | null;
  answer?: string;
  source?: string;
  low?: string | null;
  high?: string | null;
  choice?: boolean | null;
  confidence?: string | null;
  correct?: boolean | null;
}

interface Exercise {
  id: string;
  started_at: string;
  submitted_at: string | null;
  questions: Question[];
  score?: Score;
}

const pct = (s: string | undefined) =>
  s === undefined ? "" : `${Math.round(Number(s) * 1000) / 10}%`;

// --- Own record (AC-23, AC-27) -------------------------------------------------

export function CalibrationPage() {
  useEffect(() => {
    document.title = "Calibration · FAIR Risk Platform";
  }, []);
  const me = useApi<{
    score: Score | null;
    history: { computed_at: string; class: Klass; rate: string | null }[];
    exercises: {
      id: string;
      started_at: string;
      submitted_at: string | null;
      questions: number;
      correct: number;
    }[];
  }>("/api/v1/calibration/me");
  const sets = useApi<{ sets: unknown[] }>("/api/v1/calibration/question-sets");
  const [error, setError] = useState<string>();
  const none = me.error instanceof ApiError && me.error.status === 404;
  const start = async () => {
    setError(undefined);
    try {
      const ex = await send<Exercise>(
        "POST",
        "/api/v1/calibration/exercises",
        {},
      );
      window.location.assign(`/calibration/exercises/${ex.id}`);
    } catch (err) {
      setError(describe(err));
    }
  };
  return (
    <>
      <h1>Calibration</h1>
      <p className="lede">
        Practise giving ranges you are 90% sure of, and true-or-false answers
        with an honest confidence. Take as long as you like: nothing is timed.
        Your record is yours: others see at most your class and hit rate.
      </p>
      <p className="muted">
        Your score covers your recent exercises. Ranges: calibrated when the
        share of your 90% ranges holding the truth is within what a calibrated
        person would score by chance; overconfident when fewer hold it,
        underconfident when more do. True or false: your share correct against
        the confidence you stated. Until you have answered enough questions you
        are not yet measured.
      </p>
      {none ? (
        <p>Calibration exercises are not available to you.</p>
      ) : (
        <>
          <p className="actions">
            <button
              type="button"
              className="btn primary"
              onClick={() => void start()}
            >
              {me.data?.exercises.some((e) => !e.submitted_at)
                ? "Resume your exercise"
                : "Start an exercise"}
            </button>
            {sets.data ? (
              <a href="/calibration/question-sets">Question sets</a>
            ) : null}
          </p>
          {error ? (
            <p role="alert" className="error-text">
              {error}
            </p>
          ) : null}
          <Status loaded={me}>
            {(m) => (
              <>
                <Section id="score" title="Your score">
                  <ScoreView s={m.score} />
                </Section>
                <Section id="history" title="Score history">
                  {m.history.length === 0 ? (
                    <p>No scores yet.</p>
                  ) : (
                    <div className="table-wrap">
                      <table className="data">
                        <caption className="sr-only">
                          Your scores, oldest first
                        </caption>
                        <thead>
                          <tr>
                            <th scope="col">Computed</th>
                            <th scope="col">Class</th>
                            <th scope="col">Ranges holding the truth</th>
                          </tr>
                        </thead>
                        <tbody>
                          {m.history.map((h, i) => (
                            <tr key={i}>
                              <td>{date(h.computed_at)}</td>
                              <td>
                                <ClassBadge c={h.class} />
                              </td>
                              <td>{h.rate ? pct(h.rate) : "—"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </Section>
                <Section id="exercises" title="Your exercises">
                  {m.exercises.length === 0 ? (
                    <p>No exercises yet.</p>
                  ) : (
                    <div className="table-wrap">
                      <table className="data">
                        <caption className="sr-only">
                          Your exercises, newest first
                        </caption>
                        <thead>
                          <tr>
                            <th scope="col">Started</th>
                            <th scope="col">State</th>
                            <th scope="col">Correct</th>
                          </tr>
                        </thead>
                        <tbody>
                          {m.exercises.map((e) => (
                            <tr key={e.id}>
                              <td>
                                <a href={`/calibration/exercises/${e.id}`}>
                                  {date(e.started_at)}
                                </a>
                              </td>
                              <td>
                                {e.submitted_at ? (
                                  `Submitted ${date(e.submitted_at)}`
                                ) : (
                                  <Badge tone="info">Not submitted</Badge>
                                )}
                              </td>
                              <td>
                                {e.submitted_at
                                  ? `${e.correct} of ${e.questions}`
                                  : "—"}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </Section>
              </>
            )}
          </Status>
        </>
      )}
    </>
  );
}

function ScoreView({ s }: { s: Score | null | undefined }) {
  if (!s) return <p>Not measured yet: take an exercise.</p>;
  return (
    <dl className="summary">
      <div>
        <dt>Class</dt>
        <dd>
          <ClassBadge c={s.class} />
        </dd>
      </div>
      {s.ranges && s.ranges.n > 0 ? (
        <div>
          <dt>Ranges</dt>
          <dd>
            {s.ranges.hits} of {s.ranges.n} held the truth
            {s.ranges.rate ? ` (${pct(s.ranges.rate)})` : ""}; a calibrated
            person&apos;s 90% ranges would hold it {s.ranges.band[0]} to{" "}
            {s.ranges.band[1]} times.
          </dd>
        </div>
      ) : null}
      {s.binary && s.binary.n > 0 ? (
        <div>
          <dt>True or false</dt>
          <dd>
            {s.binary.correct} of {s.binary.n} correct
            {s.binary.expected
              ? `; your confidence expected ${s.binary.expected}`
              : ""}
            .
          </dd>
        </div>
      ) : null}
      {s.computed_at ? (
        <div>
          <dt>As of</dt>
          <dd>{date(s.computed_at)}</dd>
        </div>
      ) : null}
    </dl>
  );
}

// --- An exercise (AC-20 to AC-22) ----------------------------------------------

type Answer = {
  low: string;
  high: string;
  choice: "" | "true" | "false";
  confidence: string;
};

export function ExercisePage({ id }: { id: string }) {
  const ex = useApi<Exercise>(`/api/v1/calibration/exercises/${id}`);
  const [done, setDone] = useState<Exercise>();
  useEffect(() => {
    document.title = "Calibration exercise · FAIR Risk Platform";
  }, []);
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/calibration">Calibration</a>
      </nav>
      <Status loaded={ex}>
        {(e) =>
          (done ?? e).submitted_at ? (
            <Feedback e={done ?? e} />
          ) : (
            <Take e={e} onDone={setDone} />
          )
        }
      </Status>
    </>
  );
}

function Take({ e, onDone }: { e: Exercise; onDone: (x: Exercise) => void }) {
  const [answers, setAnswers] = useState<Record<string, Answer>>(() =>
    Object.fromEntries(
      e.questions.map((q) => [
        q.id,
        { low: "", high: "", choice: "", confidence: "" },
      ]),
    ),
  );
  const [error, setError] = useState<string>();
  const set = (id: string, p: Partial<Answer>) =>
    setAnswers((a) => ({ ...a, [id]: { ...a[id]!, ...p } }));
  const missing = e.questions.filter((q) => {
    const a = answers[q.id]!;
    return q.kind === "range"
      ? a.low.trim() === "" || a.high.trim() === ""
      : a.choice === "" || a.confidence === "";
  }).length;
  return (
    <>
      <h1>Calibration exercise</h1>
      <p className="lede">
        {e.questions.length} questions. For each range, give a low and a high
        you are 90% sure the true value lies between. For each statement, say
        whether it is true and how sure you are. There is no time limit, and you
        may leave and come back.
      </p>
      <form
        noValidate
        onSubmit={async (ev) => {
          ev.preventDefault();
          setError(undefined);
          if (missing > 0) {
            setError(`Answer every question first: ${missing} still open.`);
            return;
          }
          try {
            const out = await send<Exercise>(
              "POST",
              `/api/v1/calibration/exercises/${e.id}/submit`,
              {
                answers: e.questions.map((q) => {
                  const a = answers[q.id]!;
                  return q.kind === "range"
                    ? {
                        id: q.id,
                        low: a.low.trim().replace(/,/g, ""),
                        high: a.high.trim().replace(/,/g, ""),
                      }
                    : {
                        id: q.id,
                        choice: a.choice === "true",
                        confidence: a.confidence,
                      };
                }),
              },
            );
            onDone(out);
            window.scrollTo(0, 0);
          } catch (err) {
            setError(describe(err));
          }
        }}
      >
        <ol className="questions">
          {e.questions.map((q, i) => {
            const a = answers[q.id]!;
            const qid = `q${i + 1}`;
            return (
              <li key={q.id}>
                <fieldset className="group">
                  <legend>
                    Question {i + 1}: {q.text}
                    {q.kind === "range" && q.unit ? (
                      <span className="muted"> ({q.unit})</span>
                    ) : null}
                  </legend>
                  {q.kind === "range" ? (
                    <div className="grid">
                      <div className="field">
                        <label htmlFor={`${qid}-low`}>
                          Question {i + 1} low
                        </label>
                        <input
                          id={`${qid}-low`}
                          inputMode="decimal"
                          value={a.low}
                          onChange={(ev) => set(q.id, { low: ev.target.value })}
                        />
                      </div>
                      <div className="field">
                        <label htmlFor={`${qid}-high`}>
                          Question {i + 1} high
                        </label>
                        <input
                          id={`${qid}-high`}
                          inputMode="decimal"
                          value={a.high}
                          onChange={(ev) =>
                            set(q.id, { high: ev.target.value })
                          }
                        />
                      </div>
                    </div>
                  ) : (
                    <div className="grid">
                      <fieldset className="checks">
                        <legend className="sr-only">
                          Question {i + 1}: true or false
                        </legend>
                        <label>
                          <input
                            type="radio"
                            name={`${qid}-choice`}
                            checked={a.choice === "true"}
                            onChange={() => set(q.id, { choice: "true" })}
                          />{" "}
                          True
                        </label>
                        <label>
                          <input
                            type="radio"
                            name={`${qid}-choice`}
                            checked={a.choice === "false"}
                            onChange={() => set(q.id, { choice: "false" })}
                          />{" "}
                          False
                        </label>
                      </fieldset>
                      <div className="field">
                        <label htmlFor={`${qid}-confidence`}>
                          Question {i + 1} confidence
                        </label>
                        <select
                          id={`${qid}-confidence`}
                          value={a.confidence}
                          onChange={(ev) =>
                            set(q.id, { confidence: ev.target.value })
                          }
                        >
                          <option value="">Choose…</option>
                          {["0.5", "0.6", "0.7", "0.8", "0.9", "1"].map((c) => (
                            <option key={c} value={c}>
                              {Math.round(Number(c) * 100)}%
                              {c === "0.5"
                                ? " (a guess)"
                                : c === "1"
                                  ? " (certain)"
                                  : ""}
                            </option>
                          ))}
                        </select>
                      </div>
                    </div>
                  )}
                </fieldset>
              </li>
            );
          })}
        </ol>
        <div aria-live="assertive">
          {error ? (
            <p role="alert" className="error-text">
              {error}
            </p>
          ) : null}
        </div>
        <div className="actions">
          <button type="submit" className="btn primary">
            Submit the exercise
          </button>
          <a href="/calibration">Leave and come back later</a>
        </div>
      </form>
    </>
  );
}

/** AC-22: each answer against the truth with its source, hits against 90%, accuracy against confidence, the bet. */
function Feedback({ e }: { e: Exercise }) {
  const ranges = e.questions.filter((q) => q.kind === "range");
  const binary = e.questions.filter((q) => q.kind === "binary");
  const hits = ranges.filter((q) => q.correct).length;
  const correct = binary.filter((q) => q.correct).length;
  const expected = binary.reduce((s, q) => s + Number(q.confidence ?? 0), 0);
  return (
    <>
      <h1>Your results</h1>
      <Section id="summary" title="This exercise">
        <dl className="summary">
          {ranges.length > 0 ? (
            <div>
              <dt>Ranges</dt>
              <dd>
                {hits} of {ranges.length} held the truth; at 90% you would
                expect about {Math.round(ranges.length * 0.9 * 10) / 10}.
                {hits < ranges.length * 0.9 - 1
                  ? " Your ranges may be too narrow."
                  : ""}
              </dd>
            </div>
          ) : null}
          {binary.length > 0 ? (
            <div>
              <dt>True or false</dt>
              <dd>
                {correct} of {binary.length} correct; your stated confidence
                expected about {Math.round(expected * 10) / 10}.
              </dd>
            </div>
          ) : null}
        </dl>
        <p className="bet">
          Before your next range, ask yourself: would you rather win a prize if
          the true value is in your range, or by spinning a wheel that wins 90%
          of the time? If you would rather spin the wheel, widen the range; if
          you would rather bet on your range, it may be too wide.
        </p>
      </Section>
      {e.score ? (
        <Section id="score" title="Your score now">
          <ScoreView s={e.score} />
        </Section>
      ) : null}
      <Section id="answers" title="Answers">
        <ol className="questions">
          {e.questions.map((q, i) => (
            <li key={q.id}>
              <p>
                <strong>
                  Question {i + 1}: {q.text}
                </strong>{" "}
                {q.correct ? (
                  <Badge tone="ok">
                    {q.kind === "range" ? "In your range" : "Correct"}
                  </Badge>
                ) : (
                  <Badge tone="warn">
                    {q.kind === "range" ? "Outside your range" : "Incorrect"}
                  </Badge>
                )}
              </p>
              <p>
                {q.kind === "range" ? (
                  <>
                    Your range: {q.low} to {q.high}
                    {q.unit ? ` ${q.unit}` : ""}. The answer: {q.answer}
                    {q.unit ? ` ${q.unit}` : ""}.
                  </>
                ) : (
                  <>
                    You said {q.choice ? "true" : "false"} at{" "}
                    {pct(q.confidence ?? undefined)}. The answer: {q.answer}.
                  </>
                )}
              </p>
              <p className="muted">Source: {q.source}</p>
            </li>
          ))}
        </ol>
        <p>
          <a href="/calibration">Back to your record</a>
        </p>
      </Section>
    </>
  );
}

// --- Question sets (AC-24 to AC-26) --------------------------------------------

interface QuestionSet {
  id: string;
  origin: "shipped" | "custom";
  name: string;
  description: string;
  status: "draft" | "active" | "retired";
  release: string | null;
  created_at?: string;
  questions: number | (Question & { retired: boolean })[];
}

const SET_TONE: Record<QuestionSet["status"], Tone> = {
  draft: "info",
  active: "ok",
  retired: "muted",
};

export function QuestionSets() {
  useEffect(() => {
    document.title = "Question sets · Calibration · FAIR Risk Platform";
  }, []);
  const list = useApi<{ sets: QuestionSet[] }>(
    "/api/v1/calibration/question-sets",
  );
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string>();
  const none = list.error instanceof ApiError && list.error.status === 404;
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/calibration">Calibration</a>
      </nav>
      <h1>Question sets</h1>
      <p className="lede">
        The questions exercises draw from: the shipped set, read-only and
        updated with releases, and your installation&apos;s own sets.
      </p>
      {none ? (
        <p>Question sets are managed by holders of calibration.manage.</p>
      ) : (
        <>
          <Status loaded={list}>
            {(d) => (
              <Section id="sets" title="Sets">
                <div className="table-wrap">
                  <table className="data">
                    <caption className="sr-only">Question sets</caption>
                    <thead>
                      <tr>
                        <th scope="col">Set</th>
                        <th scope="col">Origin</th>
                        <th scope="col">Questions</th>
                        <th scope="col">State</th>
                      </tr>
                    </thead>
                    <tbody>
                      {d.sets.map((s) => (
                        <tr key={s.id}>
                          <td>
                            <a href={`/calibration/question-sets/${s.id}`}>
                              {s.name}
                            </a>
                          </td>
                          <td>
                            {s.origin === "shipped"
                              ? `Shipped (release ${s.release})`
                              : "Custom"}
                          </td>
                          <td>{String(s.questions)}</td>
                          <td>
                            <Badge tone={SET_TONE[s.status]}>
                              {s.status[0]!.toUpperCase() + s.status.slice(1)}
                            </Badge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Section>
            )}
          </Status>
          <Section id="new-set" title="New question set">
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                setError(undefined);
                try {
                  const made = await send<{ id: string }>(
                    "POST",
                    "/api/v1/calibration/question-sets",
                    { name, description: description || undefined },
                  );
                  window.location.assign(
                    `/calibration/question-sets/${made.id}`,
                  );
                } catch (err) {
                  setError(describe(err));
                }
              }}
            >
              <div className="field">
                <label htmlFor="set-name">Name</label>
                <input
                  id="set-name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div className="field">
                <label htmlFor="set-description">Description (optional)</label>
                <textarea
                  id="set-description"
                  rows={2}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </div>
              {error ? (
                <p role="alert" className="error-text">
                  {error}
                </p>
              ) : null}
              <div className="actions">
                <button type="submit" className="btn primary">
                  Create the set
                </button>
              </div>
            </form>
          </Section>
        </>
      )}
    </>
  );
}

type QDraft = {
  kind: "range" | "binary";
  text: string;
  unit: string;
  answer: string;
  source: string;
};
const blankQ: QDraft = {
  kind: "range",
  text: "",
  unit: "",
  answer: "",
  source: "",
};

export function QuestionSetPage({ id }: { id: string }) {
  const set = useApi<QuestionSet>(`/api/v1/calibration/question-sets/${id}`);
  useEffect(() => {
    if (set.data)
      document.title = `${set.data.name} · Question sets · FAIR Risk Platform`;
  }, [set.data]);
  const [msg, setMsg] = useState<{ ok?: string; error?: string }>({});
  const act = async (
    what: string,
    path: string,
    body: unknown,
    method: "POST" | "PUT" = "POST",
  ) => {
    setMsg({});
    try {
      await send(method, path, body);
      setMsg({ ok: what });
      set.reload();
      return true;
    } catch (err) {
      setMsg({ error: describe(err) });
      return false;
    }
  };
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/calibration">Calibration</a> ›{" "}
        <a href="/calibration/question-sets">Question sets</a>
      </nav>
      <Status loaded={set}>
        {(s) => {
          const qs = Array.isArray(s.questions) ? s.questions : [];
          const custom = s.origin === "custom";
          const editable = custom && s.status !== "retired";
          return (
            <>
              <h1>{s.name}</h1>
              <p className="lede">
                {custom
                  ? "Custom set"
                  : `Shipped set, release ${s.release}: read-only`}{" "}
                ·{" "}
                <Badge tone={SET_TONE[s.status]}>
                  {s.status[0]!.toUpperCase() + s.status.slice(1)}
                </Badge>
              </p>
              {s.description ? <p>{s.description}</p> : null}
              <p className="actions">
                {custom && s.status === "draft" ? (
                  <button
                    type="button"
                    className="btn primary"
                    onClick={() =>
                      void act(
                        "The set is active: new exercises draw from it.",
                        `/api/v1/calibration/question-sets/${id}/activate`,
                        {},
                      )
                    }
                  >
                    Activate the set
                  </button>
                ) : null}
                {custom && s.status !== "retired" ? (
                  <button
                    type="button"
                    className="btn"
                    onClick={() =>
                      void act(
                        "The set is retired: no new exercise draws from it.",
                        `/api/v1/calibration/question-sets/${id}/retire`,
                        {},
                      )
                    }
                  >
                    Retire the set
                  </button>
                ) : null}
              </p>
              <div aria-live="polite">
                {msg.ok ? <p role="status">{msg.ok}</p> : null}
                {msg.error ? (
                  <p role="alert" className="error-text">
                    {msg.error}
                  </p>
                ) : null}
              </div>
              <Section
                id="questions"
                title="Questions"
                intro="Answers are shown here to managers only; people taking an exercise see them after they submit it."
              >
                {qs.length === 0 ? (
                  <p>No questions yet.</p>
                ) : (
                  <ol className="questions">
                    {qs.map((q) => (
                      <li key={q.id}>
                        <QuestionRow q={q} editable={editable} act={act} />
                      </li>
                    ))}
                  </ol>
                )}
              </Section>
              {editable ? (
                <Section id="add" title="Add a question">
                  <QuestionForm
                    key={qs.length}
                    initial={blankQ}
                    kindFixed={false}
                    submitLabel="Add the question"
                    onSubmit={(d) =>
                      act(
                        "The question was added.",
                        `/api/v1/calibration/question-sets/${id}/questions`,
                        body(d),
                      )
                    }
                  />
                </Section>
              ) : null}
            </>
          );
        }}
      </Status>
    </>
  );
}

function body(d: QDraft) {
  return {
    kind: d.kind,
    text: d.text,
    unit: d.kind === "range" ? d.unit || null : null,
    answer: d.answer.trim(),
    source: d.source,
  };
}

function QuestionRow({
  q,
  editable,
  act,
}: {
  q: Question & { retired: boolean };
  editable: boolean;
  act: (
    what: string,
    path: string,
    body: unknown,
    method?: "POST" | "PUT",
  ) => Promise<boolean>;
}) {
  const [editing, setEditing] = useState(false);
  return (
    <>
      <p>
        <strong>{q.text}</strong>{" "}
        <span className="muted">
          (
          {q.kind === "range"
            ? `range${q.unit ? `, ${q.unit}` : ""}`
            : "true or false"}
          , version {q.version})
        </span>{" "}
        {q.retired ? <Badge tone="muted">Retired</Badge> : null}
      </p>
      <p>
        Answer: {q.answer}. <span className="muted">Source: {q.source}</span>
      </p>
      {editable && !q.retired ? (
        editing ? (
          <QuestionForm
            initial={{
              kind: q.kind,
              text: q.text,
              unit: q.unit ?? "",
              answer: q.answer ?? "",
              source: q.source ?? "",
            }}
            kindFixed
            submitLabel="Save a new version"
            onSubmit={async (d) => {
              const { kind: _kind, ...rest } = body(d);
              const ok = await act(
                "The question was saved as a new version.",
                `/api/v1/calibration/questions/${q.id}`,
                rest,
                "PUT",
              );
              if (ok) setEditing(false);
              return ok;
            }}
          />
        ) : (
          <p className="actions">
            <button
              type="button"
              className="btn"
              aria-label={`Edit: ${q.text}`}
              onClick={() => setEditing(true)}
            >
              Edit
            </button>
            <button
              type="button"
              className="btn"
              aria-label={`Retire: ${q.text}`}
              onClick={() =>
                void act(
                  "The question was retired.",
                  `/api/v1/calibration/questions/${q.id}/retire`,
                  {},
                )
              }
            >
              Retire
            </button>
          </p>
        )
      ) : null}
    </>
  );
}

function QuestionForm({
  initial,
  kindFixed,
  submitLabel,
  onSubmit,
}: {
  initial: QDraft;
  kindFixed: boolean;
  submitLabel: string;
  onSubmit: (d: QDraft) => Promise<boolean>;
}) {
  const [d, setD] = useState<QDraft>(initial);
  const set = (p: Partial<QDraft>) => setD((x) => ({ ...x, ...p }));
  const [uid] = useState(() => `qf-${Math.random().toString(36).slice(2, 8)}`);
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        void onSubmit(d);
      }}
    >
      {kindFixed ? null : (
        <fieldset className="checks">
          <legend>Kind</legend>
          <label>
            <input
              type="radio"
              name={`${uid}-kind`}
              checked={d.kind === "range"}
              onChange={() => set({ kind: "range", answer: "" })}
            />{" "}
            A range question (a number)
          </label>
          <label>
            <input
              type="radio"
              name={`${uid}-kind`}
              checked={d.kind === "binary"}
              onChange={() => set({ kind: "binary", answer: "true", unit: "" })}
            />{" "}
            A true-or-false statement
          </label>
        </fieldset>
      )}
      <div className="field">
        <label htmlFor={`${uid}-text`}>
          {d.kind === "range" ? "Question" : "Statement"}
        </label>
        <textarea
          id={`${uid}-text`}
          rows={2}
          value={d.text}
          onChange={(e) => set({ text: e.target.value })}
        />
      </div>
      {d.kind === "range" ? (
        <div className="grid">
          <div className="field">
            <label htmlFor={`${uid}-answer`}>Answer (a number)</label>
            <input
              id={`${uid}-answer`}
              inputMode="decimal"
              value={d.answer}
              onChange={(e) => set({ answer: e.target.value })}
            />
          </div>
          <div className="field">
            <label htmlFor={`${uid}-unit`}>Unit (optional)</label>
            <input
              id={`${uid}-unit`}
              value={d.unit}
              onChange={(e) => set({ unit: e.target.value })}
            />
          </div>
        </div>
      ) : (
        <div className="field">
          <label htmlFor={`${uid}-answer`}>Answer</label>
          <select
            id={`${uid}-answer`}
            value={d.answer}
            onChange={(e) => set({ answer: e.target.value })}
          >
            <option value="true">True</option>
            <option value="false">False</option>
          </select>
        </div>
      )}
      <div className="field">
        <label htmlFor={`${uid}-source`}>Source</label>
        <input
          id={`${uid}-source`}
          value={d.source}
          onChange={(e) => set({ source: e.target.value })}
        />
      </div>
      <div className="actions">
        <button type="submit" className="btn primary">
          {submitLabel}
        </button>
      </div>
    </form>
  );
}
