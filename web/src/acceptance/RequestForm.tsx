import { useEffect, useState } from "react";
import { ApiError, send } from "../api";
import { money } from "../analysis/types";
import { Section, Status, useApi } from "../components";
import { date } from "../links";
import type { RiskView } from "../register/types";
import { refusal } from "./AcceptancePage";
import { useCurrency } from "./Acceptances";
import { tierLabel, type Acceptance, type Tier } from "./types";

// F-008 T-07 (F-008-AC-01, AC-02, AC-04, AC-11, AC-12): requesting
// acceptance of a register risk, or renewing an acceptance in force: the
// justification, any conditions, and an expiry within the longest the
// settings allow; the tier its exposure places it in, and who approves.

export function placeTier(tiers: Tier[], mean: number | null | undefined): Tier | undefined {
  if (mean === null || mean === undefined) return undefined;
  return tiers.find((t) => t.max_mean === null || mean <= t.max_mean) ?? tiers[tiers.length - 1];
}

function addDays(n: number): string {
  return new Date(Date.now() + n * 86_400_000).toISOString().slice(0, 10);
}

export function RequestForm({ search = window.location.search }: { search?: string }) {
  const q = new URLSearchParams(search);
  const risk = q.get("risk") ?? "";
  const renews = q.get("renews");
  const view = useApi<RiskView>(`/api/v1/register/risks/${risk}`);
  const tiers = useApi<{ tiers: Tier[]; max_duration_days: number }>("/api/v1/acceptances/tiers");
  const renewed = useApi<Acceptance>(renews ? `/api/v1/acceptances/${renews}` : "/api/v1/acceptances/tiers");
  const currency = useCurrency();
  const [justification, setJustification] = useState("");
  const [conditions, setConditions] = useState("");
  const [expires, setExpires] = useState("");
  const [error, setError] = useState<string>();
  const [problems, setProblems] = useState<{ pointer: string; message: string }[]>([]);
  const [busy, setBusy] = useState(false);
  const heading = renews ? "Renew the acceptance" : "Request acceptance";
  useEffect(() => {
    document.title = `${heading} · FAIR Risk Platform`;
  }, [heading]);
  useEffect(() => {
    // A renewal starts from the terms in force.
    const r = renewed.data as (Acceptance & { evidence?: { justification?: string; conditions?: string } }) | undefined;
    if (renews && r?.evidence) {
      setJustification((j) => j || (r.evidence?.justification ?? ""));
      setConditions((c) => c || (r.evidence?.conditions ?? ""));
    }
  }, [renews, renewed.data]);

  return (
    <Status loaded={view}>
      {(v) => {
        const max = tiers.data?.max_duration_days ?? 365;
        const mean = v.exposure.summary?.ale.mean;
        const tier = placeTier(tiers.data?.tiers ?? [], mean);
        const submit = async () => {
          setError(undefined);
          setProblems([]);
          if (!justification.trim()) {
            setError("A justification is required.");
            return;
          }
          if (!expires) {
            setError("An expiry date is required.");
            return;
          }
          setBusy(true);
          try {
            const a = await send<Acceptance>("POST", "/api/v1/acceptances", {
              risk_id: risk,
              justification,
              conditions,
              expires_on: expires,
              renews: renews ?? null,
            });
            window.location.assign(`/acceptances/${a.id}`);
          } catch (err) {
            const body = err instanceof ApiError ? (err.body as { problems?: { pointer: string; message: string }[] } | undefined) : undefined;
            if (body?.problems) setProblems(body.problems);
            setError(refusal(err));
          } finally {
            setBusy(false);
          }
        };
        return (
          <>
            <nav aria-label="Breadcrumb" className="crumbs">
              <a href="/register">Risk register</a> / <a href={`/register/risks/${risk}`}>{v.risk.title}</a>
            </nav>
            <h1>{heading}</h1>
            <p className="lede">
              {v.risk.title}: accepting it as it stands, until the expiry date
              {renews ? "; the acceptance in force stays until this one is approved, with no gap" : ""}.
            </p>
            <Section id="tier" title="Approval" intro="The tier is placed on the risk's mean annual loss when you submit; the settings in force decide who approves.">
              <dl className="summary">
                <div>
                  <dt>Mean annual loss</dt>
                  <dd>{money(mean ?? null, currency)}</dd>
                </div>
                <div>
                  <dt>Tier</dt>
                  <dd>
                    {tier
                      ? `${tierLabel(tier.tier)}: ${tier.approvals} approval${tier.approvals > 1 ? "s" : ""}, ${
                          tier.root ? "at the top business unit" : tier.levels_up === 0 ? "at the risk's business unit" : `${tier.levels_up} level${tier.levels_up === 1 ? "" : "s"} above it`
                        }`
                      : "Not placed: the risk has no current exposure"}
                  </dd>
                </div>
              </dl>
            </Section>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void submit();
              }}
            >
              <Section id="terms" title="Terms">
                <div className="field">
                  <label htmlFor="justification">Justification</label>
                  <textarea id="justification" rows={4} value={justification} onChange={(e) => setJustification(e.target.value)} maxLength={5000} />
                </div>
                <div className="field">
                  <label htmlFor="conditions">Conditions (optional)</label>
                  <textarea id="conditions" rows={3} value={conditions} onChange={(e) => setConditions(e.target.value)} maxLength={5000} />
                </div>
                <div className="field">
                  <label htmlFor="expires">Expires on</label>
                  <input
                    id="expires"
                    type="date"
                    min={addDays(1)}
                    max={addDays(max)}
                    value={expires}
                    onChange={(e) => setExpires(e.target.value)}
                    aria-describedby="expires-help"
                  />
                  <p id="expires-help" className="muted">
                    At most {max} days from today ({date(addDays(max))}).
                  </p>
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
                    {renews ? "Request the renewal" : "Request acceptance"}
                  </button>
                  <a href={`/register/risks/${risk}`}>Cancel</a>
                </div>
              </Section>
            </form>
          </>
        );
      }}
    </Status>
  );
}
