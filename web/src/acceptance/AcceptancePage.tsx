import { useEffect, useState, type ReactNode } from "react";
import { ApiError, describe, send } from "../api";
import { money } from "../analysis/types";
import { ReasonAction, Section, Status, useApi } from "../components";
import { auditHref, date } from "../links";
import { StateBadge, useBUNames, useCurrency } from "./Acceptances";
import { END_LABEL, REFUSAL, REVIEW_LABEL, STEP_LABEL, tierLabel, type AcceptanceView } from "./types";

// F-008 T-07 (F-008-AC-03, AC-05 to AC-07, AC-13 to AC-16): one acceptance:
// its state and why it needs review, the evidence it was requested on, its
// history, and what the user may do: decide, withdraw, revoke or renew.

export function refusal(err: unknown): string {
  if (err instanceof ApiError && REFUSAL[err.code]) return REFUSAL[err.code] ?? "";
  return describe(err);
}

export function AcceptancePage({ id }: { id: string }) {
  const view = useApi<AcceptanceView>(`/api/v1/acceptances/${id}`);
  const buName = useBUNames();
  const currency = useCurrency();
  const title = view.data?.risk_title ?? "Acceptance";
  useEffect(() => {
    document.title = `Acceptance of ${title} · FAIR Risk Platform`;
  }, [title]);
  return (
    <Status loaded={view}>
      {(a) => {
        const who = (u: string | null) => (u === null ? "The system" : (a.names[u] ?? "Someone you cannot see"));
        const row = (label: string, value: ReactNode) => (
          <div>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        );
        const ev = a.evidence ?? {};
        const review = a.needs_review ?? [];
        return (
          <>
            <nav aria-label="Breadcrumb" className="crumbs">
              <a href="/acceptances">Risk acceptances</a>
            </nav>
            <h1>Acceptance of {a.risk_title ?? "a risk you cannot see"}</h1>
            <p className="lede">
              {buName(a.bu_id)} · {tierLabel(a.tier)} · <StateBadge a={a} />
              {a.end_reason ? ` · ${END_LABEL[a.end_reason]}` : null}
            </p>
            <p className="actions">
              {a.risk_title !== null ? <a href={`/register/risks/${a.risk_id}`}>The risk</a> : null}
              {a.renews ? <a href={`/acceptances/${a.renews}`}>The acceptance it renews</a> : null}
              {a.may_renew ? (
                <a className="react-aria-Button" href={`/acceptances/new?risk=${a.risk_id}&renews=${a.id}`}>
                  Renew
                </a>
              ) : null}
              {a.may_withdraw ? (
                <ReasonAction
                  label="Withdraw"
                  title="Withdraw this request"
                  fieldLabel="Reason"
                  description={<p>The request ends without a decision. A new one can be made later.</p>}
                  submitLabel="Withdraw"
                  onSubmit={async (reason) => {
                    try {
                      await send("POST", `/api/v1/acceptances/${id}/withdraw`, { reason });
                    } catch (err) {
                      throw new Error(refusal(err));
                    }
                    view.reload();
                  }}
                />
              ) : null}
              {a.may_revoke ? (
                <ReasonAction
                  label="Revoke"
                  title="Revoke this acceptance"
                  fieldLabel="Reason"
                  description={<p>The risk is no longer accepted from now on. Its owner can request acceptance again.</p>}
                  submitLabel="Revoke"
                  onSubmit={async (reason) => {
                    try {
                      await send("POST", `/api/v1/acceptances/${id}/revoke`, { reason });
                    } catch (err) {
                      throw new Error(refusal(err));
                    }
                    view.reload();
                  }}
                />
              ) : null}
              <a href={auditHref(`acceptance:${id}`)}>Audit history of this acceptance</a>
            </p>
            {a.state === "suspended" ? (
              <div className="banner warn" role="status">
                <p>
                  Suspended: the risk's exposure is now in {tierLabel(a.tier).toLowerCase()}. The risk is not accepted until approvers at that tier
                  approve it again.
                </p>
              </div>
            ) : null}
            {a.state === "expired" ? (
              <div className="banner warn" role="status">
                <p>Expired on {date(a.expires_on)}: the risk is no longer accepted.</p>
              </div>
            ) : null}
            {review.length > 0 ? (
              <div className="banner warn" role="status">
                <p>In force, but needs review:</p>
                <ul>
                  {review.map((r) => (
                    <li key={r}>{REVIEW_LABEL[r]}</li>
                  ))}
                </ul>
                {a.may_renew ? <p>Renewing it records a new approval on the risk as it stands.</p> : null}
              </div>
            ) : null}
            <Section id="terms" title="Terms">
              <dl className="summary">
                {row("Requested by", `${who(a.requested_by)} on ${date(a.requested_at)}`)}
                {row("Justification", ev.justification ?? "—")}
                {ev.conditions ? row("Conditions", ev.conditions) : null}
                {row("Expires", date(a.expires_on))}
                {row("Mean annual loss at request", money(a.mean, currency))}
                {row(
                  "Approvals",
                  a.state === "pending" || a.state === "suspended"
                    ? `${a.approvals} of ${a.approvals_needed}, at ${buName(a.tier_bu_id)}`
                    : `${a.approvals_needed} needed, at ${buName(a.tier_bu_id)}`,
                )}
                {a.activated_at ? row("In force since", date(a.activated_at)) : null}
                {a.ended_at ? row("Ended", date(a.ended_at)) : null}
              </dl>
            </Section>
            {a.may_decide ? <DecisionForm a={a} onDone={view.reload} /> : null}
            <Section id="evidence" title="Evidence" intro="The risk's exposure and analyses when acceptance was requested, kept as they were.">
              <dl className="summary">
                {row("Exposure", ev.exposure?.status === "current" ? "Current" : (ev.exposure?.status ?? "—"))}
                {row("Mean annual loss", money(ev.exposure?.mean ?? null, currency))}
                {row("90th percentile", money(ev.exposure?.p90 ?? null, currency))}
                {row("Pinned analyses", ev.pins?.length ?? 0)}
              </dl>
              {ev.pins && ev.pins.length > 0 ? (
                <ul>
                  {ev.pins.map((p) => (
                    <li key={p.run_id + p.control_set}>
                      <a href={`/analyses/runs/${p.run_id}`}>Analysis run</a>, control set {p.control_set}
                    </li>
                  ))}
                </ul>
              ) : null}
            </Section>
            <Section id="history" title="History">
              <div className="table-wrap">
                <table className="data">
                  <caption className="sr-only">History</caption>
                  <thead>
                    <tr>
                      <th scope="col">Step</th>
                      <th scope="col">By</th>
                      <th scope="col">When</th>
                      <th scope="col">Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {a.steps.map((s) => (
                      <tr key={s.n}>
                        <td>{STEP_LABEL[s.kind] ?? s.kind}</td>
                        <td>{who(s.actor)}</td>
                        <td>{new Date(s.at).toISOString().slice(0, 16).replace("T", " ")}</td>
                        <td>{s.kind === "requested" ? "—" : (s.reason ?? "—")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>
          </>
        );
      }}
    </Status>
  );
}

function DecisionForm({ a, onDone }: { a: AcceptanceView; onDone: () => void }) {
  const [decision, setDecision] = useState<"approve" | "reject">("approve");
  const [rationale, setRationale] = useState("");
  const [shorter, setShorter] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const tomorrow = new Date(Date.now() + 86_400_000).toISOString().slice(0, 10);
  const submit = async () => {
    setError(undefined);
    if (!rationale.trim()) {
      setError("A rationale is required.");
      return;
    }
    setBusy(true);
    try {
      await send("POST", `/api/v1/acceptances/${a.id}/decisions`, {
        decision,
        rationale,
        expires_on: decision === "approve" && shorter ? shorter : null,
      });
      onDone();
    } catch (err) {
      setError(refusal(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Section
      id="decide"
      title="Your decision"
      intro={
        a.approvals_needed > 1
          ? `This tier needs ${a.approvals_needed} approvals from different approvers; ${a.approvals} given so far. One rejection ends the request.`
          : "One approval puts it in force; a rejection ends the request."
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <fieldset className="inline-choice">
          <legend>Decision</legend>
          <label>
            <input type="radio" name="decision" value="approve" checked={decision === "approve"} onChange={() => setDecision("approve")} /> Approve
          </label>
          <label>
            <input type="radio" name="decision" value="reject" checked={decision === "reject"} onChange={() => setDecision("reject")} /> Reject
          </label>
        </fieldset>
        <div className="field">
          <label htmlFor="rationale">Rationale</label>
          <textarea id="rationale" rows={3} value={rationale} onChange={(e) => setRationale(e.target.value)} maxLength={5000} />
        </div>
        {decision === "approve" ? (
          <div className="field">
            <label htmlFor="shorter">A shorter expiry (optional)</label>
            <input id="shorter" type="date" min={tomorrow} max={a.expires_on} value={shorter} onChange={(e) => setShorter(e.target.value)} aria-describedby="shorter-help" />
            <p id="shorter-help" className="muted">
              Requested until {date(a.expires_on)}; an approval may shorten it, never lengthen it.
            </p>
          </div>
        ) : null}
        {error ? (
          <p role="alert" className="error-text">
            {error}
          </p>
        ) : null}
        <div className="actions">
          <button className="react-aria-Button primary" type="submit" disabled={busy}>
            Record the decision
          </button>
        </div>
      </form>
    </Section>
  );
}
