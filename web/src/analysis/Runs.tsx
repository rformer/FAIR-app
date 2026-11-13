import { useEffect, useState, type FormEvent } from "react";
import { ApiError, describe, send } from "../api";
import { Badge, ConfirmAction, ReasonAction, Section, Status, useApi, type Tone } from "../components";
import { auditHref, date } from "../links";
import type { BU } from "../risk/types";
import {
  active,
  FAILURE_LABELS,
  money,
  percent,
  REPRODUCTION_LABELS,
  STATE_LABELS,
  type Run,
  type RunState,
  type SetSummary,
} from "./types";

// F-005 T-13 (AC-01 to AC-05, AC-13, AC-16): a scenario's simulation runs:
// request one, follow its progress, read its results, cancel or reproduce
// it. Results are the engine's; charts are F-006's.

const STATE_TONE: Record<RunState, Tone> = { queued: "muted", running: "info", succeeded: "ok", failed: "bad", cancelled: "muted" };

export function RunStateBadge({ run }: { run: Pick<Run, "state" | "progress"> }) {
  return (
    <>
      <Badge tone={STATE_TONE[run.state]}>{STATE_LABELS[run.state]}</Badge>
      {run.state === "running" ? (
        <>
          {" "}
          <progress max={1} value={run.progress} aria-label="Progress">
            {percent(run.progress, 0)}
          </progress>{" "}
          <span className="muted">{percent(run.progress, 0)}</span>
        </>
      ) : null}
    </>
  );
}

/** Reloads every two seconds while busy says so. */
export function usePolling(busy: boolean, reload: () => void) {
  useEffect(() => {
    if (!busy) return;
    const t = window.setInterval(reload, 2000);
    return () => window.clearInterval(t);
  }, [busy, reload]);
}

export function ScenarioRuns({
  id,
  buId,
  version,
  controlSets,
  currency,
  archived,
}: {
  id: string;
  buId: string;
  version: number;
  controlSets: { name: string; current: boolean }[];
  currency: string | null;
  archived: boolean;
}) {
  const list = useApi<{ runs: Run[] }>(`/api/v1/analyses/runs?scenario=${id}`);
  const runBUs = useApi<{ bus: BU[] }>("/api/v1/risk/bus?permission=analysis.run");
  const [open, setOpen] = useState<string>();
  const busy = list.data?.runs.some((r) => active(r.state)) ?? false;
  usePolling(busy, list.reload);
  if (list.error instanceof ApiError && list.error.status === 404) return null;
  const canRun = runBUs.data?.bus.some((b) => b.id === buId) ?? false;
  return (
    <Section
      id="runs"
      title="Simulations"
      intro="Monte Carlo runs of this scenario: the annualized loss each control set gives. Every input is sampled independently."
    >
      {canRun && !archived ? <RunForm id={id} version={version} controlSets={controlSets} onRequested={list.reload} /> : null}
      <Status loaded={list}>
        {(d) =>
          d.runs.length === 0 ? (
            <p>No runs yet.</p>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <caption className="sr-only">Simulation runs of this scenario, newest first</caption>
                <thead>
                  <tr>
                    <th scope="col">Requested</th>
                    <th scope="col">Version</th>
                    <th scope="col">Control sets</th>
                    <th scope="col">Iterations</th>
                    <th scope="col">State</th>
                    <th scope="col">Mean annual loss</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {d.runs.map((r) => (
                    <RunRow
                      key={r.id}
                      run={r}
                      currency={currency}
                      canRun={canRun}
                      open={open === r.id}
                      onToggle={() => setOpen(open === r.id ? undefined : r.id)}
                      onChanged={list.reload}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )
        }
      </Status>
      {open ? <RunDetails id={open} currency={currency} onChanged={list.reload} /> : null}
    </Section>
  );
}

function RunRow({
  run,
  currency,
  canRun,
  open,
  onToggle,
  onChanged,
}: {
  run: Run;
  currency: string | null;
  canRun: boolean;
  open: boolean;
  onToggle: () => void;
  onChanged: () => void;
}) {
  // The list carries no results; the current set's mean comes with details.
  return (
    <tr>
      <td>{date(run.requested_at)}</td>
      <td>{run.scenario_version}</td>
      <td>{run.control_sets.join(", ")}</td>
      <td>{run.iterations.toLocaleString("en-US")}</td>
      <td>
        <RunStateBadge run={run} />
        {run.reproduction ? (
          <>
            {" "}
            <Badge tone={run.reproduction === "match" ? "ok" : "warn"}>{REPRODUCTION_LABELS[run.reproduction]}</Badge>
          </>
        ) : null}
        {run.failure ? <div className="muted">{FAILURE_LABELS[run.failure] ?? run.failure}</div> : null}
        {run.warnings.length > 0 && run.state === "succeeded" ? (
          <div className="muted">
            {run.warnings.length} {run.warnings.length === 1 ? "warning" : "warnings"}
          </div>
        ) : null}
      </td>
      <td>{run.state === "succeeded" ? <MeanOf id={run.id} currency={currency} /> : "—"}</td>
      <td className="actions">
        <button type="button" className="btn" aria-expanded={open} onClick={onToggle}>
          {open ? "Hide details" : "Details"}
          <span className="sr-only"> of the run requested {date(run.requested_at)}</span>
        </button>
        {canRun && active(run.state) ? (
          <ReasonAction
            label="Cancel"
            title="Cancel the run"
            fieldLabel="Reason"
            description={<p>The engine stops; no partial results are kept.</p>}
            submitLabel="Cancel the run"
            onSubmit={async (reason) => {
              await send("POST", `/api/v1/analyses/runs/${run.id}/cancel`, { reason });
              onChanged();
            }}
          />
        ) : null}
        {canRun && run.state === "succeeded" ? (
          <ConfirmAction
            label="Reproduce"
            title="Reproduce the run"
            description={
              <p>
                A new run with the same scenario version, seed, iterations and control sets. On the same engine version and CPU architecture
                its results must be identical, bit for bit.
              </p>
            }
            confirmLabel="Reproduce"
            onConfirm={async () => {
              await send("POST", `/api/v1/analyses/runs/${run.id}/reproduce`, {});
              onChanged();
            }}
          />
        ) : null}
      </td>
    </tr>
  );
}

function MeanOf({ id, currency }: { id: string; currency: string | null }) {
  const run = useApi<Run>(`/api/v1/analyses/runs/${id}`);
  const first = run.data?.results?.[0];
  return <>{first ? money(first.summary.ale.mean, currency) : "…"}</>;
}

function RunForm({
  id,
  version,
  controlSets,
  onRequested,
}: {
  id: string;
  version: number;
  controlSets: { name: string; current: boolean }[];
  onRequested: () => void;
}) {
  const current = controlSets.find((c) => c.current)?.name ?? "";
  const others = controlSets.filter((c) => !c.current).map((c) => c.name);
  const [chosen, setChosen] = useState<string[]>(others);
  const [iterations, setIterations] = useState("");
  const [seed, setSeed] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string>();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(undefined);
    setDone(undefined);
    const body: Record<string, unknown> = { scenario_id: id, version, control_sets: [current, ...others.filter((o) => chosen.includes(o))] };
    if (iterations.trim()) {
      const n = Number(iterations.replace(/,/g, ""));
      if (!Number.isInteger(n) || n < 1) {
        setError("Iterations must be a whole number.");
        return;
      }
      body.iterations = n;
    }
    if (seed.trim()) {
      if (!/^[0-9]{1,20}$/.test(seed.trim())) {
        setError("The seed is a whole number from 0 to 18446744073709551615.");
        return;
      }
      body.seed = seed.trim();
    }
    setBusy(true);
    try {
      await send("POST", "/api/v1/analyses/runs", body);
      setDone("The run is queued.");
      onRequested();
    } catch (err) {
      setError(describe(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="run-form" onSubmit={submit} aria-labelledby="run-form-h">
      <h3 id="run-form-h">Run a simulation of the current version</h3>
      <fieldset className="checks">
        <legend>Control sets</legend>
        <label>
          <input type="checkbox" checked disabled /> {current} (current: always simulated)
        </label>
        {others.map((o) => (
          <label key={o}>
            <input
              type="checkbox"
              checked={chosen.includes(o)}
              onChange={(e) => setChosen(e.target.checked ? [...chosen, o] : chosen.filter((x) => x !== o))}
            />{" "}
            {o}
          </label>
        ))}
      </fieldset>
      <div className="fields">
        <div className="field">
          <label htmlFor="run-iterations">Iterations</label>
          <input
            id="run-iterations"
            inputMode="numeric"
            placeholder="The installation's default"
            value={iterations}
            onChange={(e) => setIterations(e.target.value)}
            aria-describedby="run-iterations-help"
          />
          <p id="run-iterations-help" className="muted">
            Simulated years. More iterations give steadier results and take longer.
          </p>
        </div>
        <div className="field">
          <label htmlFor="run-seed">Seed</label>
          <input id="run-seed" inputMode="numeric" placeholder="Random" value={seed} onChange={(e) => setSeed(e.target.value)} aria-describedby="run-seed-help" />
          <p id="run-seed-help" className="muted">
            The same seed gives the same results on the same engine.
          </p>
        </div>
      </div>
      {error ? (
        <p role="alert" className="error-text">
          {error}
        </p>
      ) : null}
      {done ? <p role="status">{done}</p> : null}
      <div className="actions">
        <button type="submit" className="btn primary" disabled={busy}>
          Run the simulation
        </button>
      </div>
    </form>
  );
}

/** One run in full: its record, and per control set its results. */
export function RunDetails({ id, currency, onChanged }: { id: string; currency: string | null; onChanged?: () => void }) {
  const run = useApi<Run>(`/api/v1/analyses/runs/${id}`);
  const busy = run.data ? active(run.data.state) : false;
  usePolling(busy, run.reload);
  useEffect(() => {
    if (run.data && !active(run.data.state)) onChanged?.();
    // Once: when the run finishes, the list catches up.
  }, [run.data?.state]);
  return (
    <section className="card run-details" aria-labelledby={`run-${id}-h`}>
      <Status loaded={run}>
        {(r) => (
          <>
            <h3 id={`run-${id}-h`}>Run of {date(r.requested_at)}</h3>
            <dl className="summary">
              <div>
                <dt>State</dt>
                <dd>
                  <RunStateBadge run={r} />
                  {r.cancel_reason ? <span className="muted"> ({r.cancel_reason})</span> : null}
                </dd>
              </div>
              <div>
                <dt>Inputs</dt>
                <dd>
                  Version {r.scenario_version}, {r.iterations.toLocaleString("en-US")} iterations, seed {r.seed}
                </dd>
              </div>
              {r.engine ? (
                <div>
                  <dt>Engine</dt>
                  <dd>
                    {r.engine.version} on {r.engine.architecture}
                  </dd>
                </div>
              ) : null}
              {r.result_digest ? (
                <div>
                  <dt>Results digest</dt>
                  <dd className="mono">{r.result_digest}</dd>
                </div>
              ) : null}
              {r.reproduces ? (
                <div>
                  <dt>Reproduces</dt>
                  <dd>
                    the run {r.reproduces.slice(0, 8)}
                    {r.reproduction ? (
                      <>
                        {": "}
                        <Badge tone={r.reproduction === "match" ? "ok" : "warn"}>{REPRODUCTION_LABELS[r.reproduction]}</Badge>
                      </>
                    ) : null}
                  </dd>
                </div>
              ) : null}
              {r.failure ? (
                <div>
                  <dt>Failure</dt>
                  <dd>
                    {FAILURE_LABELS[r.failure] ?? r.failure}
                    {r.failure_detail ? <span className="muted"> ({r.failure_detail})</span> : null}
                  </dd>
                </div>
              ) : null}
              <div>
                <dt>Audit</dt>
                <dd>
                  <a href={auditHref(`analysis_run:${r.id}`)}>Audit history of this run</a>
                </dd>
              </div>
            </dl>
            {(r.results ?? []).map((x) => (
              <SetResults key={x.control_set} set={x.control_set} s={x.summary} currency={currency} />
            ))}
            {r.warnings.length > 0 ? (
              <>
                <h4>Warnings</h4>
                <ul>
                  {r.warnings.map((w, i) => (
                    <li key={i}>
                      <span className="mono">{w.code}</span>
                      {w.control_set ? ` (${w.control_set})` : ""}
                      {w.pointer ? (
                        <>
                          {" "}
                          at <span className="mono">{w.pointer}</span>
                        </>
                      ) : null}
                      {w.detail ? `: ${w.detail}` : ""}
                    </li>
                  ))}
                </ul>
              </>
            ) : null}
          </>
        )}
      </Status>
    </section>
  );
}

function SetResults({ set, s, currency }: { set: string; s: SetSummary; currency: string | null }) {
  const p = s.ale.percentiles;
  const c = s.convergence;
  const top = (s.sensitivity?.inputs ?? []).slice(0, 5);
  return (
    <section aria-label={`Results: ${set}`} className="set-results">
      <h4>{set}</h4>
      <dl className="summary">
        <div>
          <dt>Mean annual loss</dt>
          <dd>{money(s.ale.mean, currency)}</dd>
        </div>
        <div>
          <dt>Median year</dt>
          <dd>{money(p.p50, currency)}</dd>
        </div>
        <div>
          <dt>1 year in 10 (90th percentile)</dt>
          <dd>{money(p.p90, currency)}</dd>
        </div>
        <div>
          <dt>1 year in 20 (95th percentile)</dt>
          <dd>{money(p.p95, currency)}</dd>
        </div>
        <div>
          <dt>1 year in 100 (99th percentile)</dt>
          <dd>{money(p.p99, currency)}</dd>
        </div>
        <div>
          <dt>Chance of any loss in a year</dt>
          <dd>{percent(s.ale.p_positive ?? null)}</dd>
        </div>
        <div>
          <dt>Loss events per year (mean)</dt>
          <dd>{s.lef.mean === null ? "—" : s.lef.mean.toFixed(2)}</dd>
        </div>
        {s.comparison ? (
          <div>
            <dt>Mean against {s.comparison.against}</dt>
            <dd>
              {s.comparison.mean <= 0 ? "−" : "+"}
              {money(Math.abs(s.comparison.mean), currency)}
            </dd>
          </div>
        ) : null}
        <div>
          <dt>Convergence</dt>
          <dd>
            {c.converged ? <Badge tone="ok">Converged</Badge> : <Badge tone="warn">Not converged</Badge>}{" "}
            <span className="muted">
              relative standard error {c.rse === null ? "—" : percent(Math.abs(c.rse), 2)} (threshold {(c.threshold_bp / 100).toFixed(2)}%)
            </span>
          </dd>
        </div>
      </dl>
      {top.length > 0 ? (
        <div className="table-wrap">
          <table className="data">
            <caption>Most influential inputs ({set}): mean annual loss with each held at its 5th and 95th percentile</caption>
            <thead>
              <tr>
                <th scope="col">Input</th>
                <th scope="col">At the 5th</th>
                <th scope="col">At the 95th</th>
                <th scope="col">Rank correlation</th>
              </tr>
            </thead>
            <tbody>
              {top.map((x) => (
                <tr key={x.input}>
                  <td className="mono">{x.input}</td>
                  <td>{money(x.low.mean, currency)}</td>
                  <td>{money(x.high.mean, currency)}</td>
                  <td>{x.spearman === null ? "—" : x.spearman.toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
