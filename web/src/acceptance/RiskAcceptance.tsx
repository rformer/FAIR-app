import { ApiError } from "../api";
import { Section, Status, useApi } from "../components";
import { date } from "../links";
import type { RiskView } from "../register/types";
import { StateBadge } from "./Acceptances";
import { REVIEW_LABEL, tierLabel, type Acceptance } from "./types";

// F-008 T-07 (F-008-AC-01, AC-14, AC-16): a risk's acceptances on its page:
// the one open now (in force, suspended, expired or pending) with why it
// needs review, earlier ones, and requesting when the user may. Nothing for
// those without an acceptance permission.

export function AcceptanceSection({ v }: { v: RiskView }) {
  const r = v.risk;
  const list = useApi<{ acceptances: Acceptance[] }>(`/api/v1/acceptances?risk=${r.id}&limit=20`);
  const perms = useApi<Record<string, boolean>>(`/api/v1/acceptances/permissions?bu=${encodeURIComponent(r.bu_id)}`);
  if (list.error instanceof ApiError && list.error.status === 404) return null;
  const open = r.acceptance ?? null;
  const mayRequest =
    (perms.data?.["acceptance.request"] ?? false) &&
    r.state === "open" &&
    r.treatment?.decision === "accept" &&
    r.status?.status === "current" &&
    (open === null || open.state === "expired");
  return (
    <Section id="acceptance" title="Acceptance">
      {open ? (
        <dl className="summary">
          <div>
            <dt>State</dt>
            <dd>
              <a href={`/acceptances/${open.id}`}>
                <StateBadge a={open} />
              </a>{" "}
              {tierLabel(open.tier)}
            </dd>
          </div>
          <div>
            <dt>Expires</dt>
            <dd>{date(open.expires_on)}</dd>
          </div>
          {open.renewal_pending ? (
            <div>
              <dt>Renewal</dt>
              <dd>Requested, waiting for approval</dd>
            </div>
          ) : null}
        </dl>
      ) : (
        <p>{r.treatment?.decision === "accept" ? "Not accepted yet: the treatment decision is accept, which needs an approved acceptance." : "Not accepted."}</p>
      )}
      {open && open.needs_review.length > 0 ? (
        <div className="callout warn" role="note" aria-label="Needs review">
          <p>The acceptance is in force, but needs review:</p>
          <ul>
            {open.needs_review.map((x) => (
              <li key={x}>{REVIEW_LABEL[x]}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {mayRequest ? (
        <p className="actions">
          <a className="react-aria-Button" href={`/acceptances/new?risk=${r.id}`}>
            Request acceptance
          </a>
        </p>
      ) : null}
      {r.treatment?.decision === "accept" && r.status?.status !== "current" && !open ? (
        <p className="muted">Acceptance can be requested once the exposure is current.</p>
      ) : null}
      <Status loaded={list}>
        {(data) => {
          const earlier = data.acceptances.filter((a) => a.id !== open?.id);
          return earlier.length === 0 ? null : (
            <details>
              <summary>Other acceptances of this risk ({earlier.length})</summary>
              <ul>
                {earlier.map((a) => (
                  <li key={a.id}>
                    <a href={`/acceptances/${a.id}`}>Requested {date(a.requested_at)}</a> <StateBadge a={a} />
                  </li>
                ))}
              </ul>
            </details>
          );
        }}
      </Status>
    </Section>
  );
}
