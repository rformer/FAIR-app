import { date } from "../links";

// F-011 T-18 (F-011-AC-24, AC-25; design §3.7, §3.8): where a version came
// from, on version histories, and the warning that a control a scenario
// relies on as in place no longer is.

export interface ProvenanceT {
  version: number;
  integration_id: string | null;
  integration_name: string | null;
  run_id: string | null;
  derivation_id?: string;
  external_id: string | null;
  received_at: string | null;
  accepted_at: string | null;
  accepted_by_name: string | null;
}

/** A version's origin: the integration and source record, who accepted it when. */
export function ProvenanceText({ p }: { p?: ProvenanceT | null }) {
  if (!p) return <>Saved directly</>;
  const by = p.accepted_by_name ? `, accepted by ${p.accepted_by_name}` : "";
  const when = p.accepted_at ? ` ${date(p.accepted_at)}` : "";
  if (p.derivation_id) return <>Derived from loss events{by}{when}</>;
  return (
    <>
      From {p.integration_id ? <a href={`/integrations/${p.integration_id}`}>{p.integration_name ?? "an integration"}</a> : "an integration"}
      {p.external_id ? (
        <>
          {" "}
          (<span className="mono">{p.external_id}</span>)
        </>
      ) : null}
      {p.run_id && p.integration_id ? (
        <>
          , <a href={`/integrations/${p.integration_id}/runs/${p.run_id}`}>its run</a>
        </>
      ) : null}
      {by}
      {when}
    </>
  );
}

export interface Lapse {
  scenario_id: string;
  control_id: string;
  status: string;
  assessed_on: string | null;
}

const STATUS_LABEL: Record<string, string> = {
  partial: "partly in place",
  planned: "planned",
  not_in_place: "not in place",
};

/**
 * AC-24: controls the scenario's current control sets count as in place
 * whose latest version says otherwise; names maps scenario ids to names
 * (on a risk, several scenarios).
 */
export function LapsedBanner({ lapses, names }: { lapses?: Lapse[] | null; names?: Record<string, string> }) {
  if (!lapses || lapses.length === 0) return null;
  return (
    <div className="banner warn" role="status">
      <p>
        {lapses.length === 1 ? "A control" : "Controls"} {names ? "its scenarios rely" : "this scenario relies"} on as in place{" "}
        {lapses.length === 1 ? "is" : "are"} no longer in place:
      </p>
      <ul>
        {lapses.map((l) => (
          <li key={`${l.scenario_id}-${l.control_id}`}>
            <a href={`/controls/${l.control_id}`}>The control</a> is now {STATUS_LABEL[l.status] ?? l.status}
            {l.assessed_on ? ` (assessed ${date(l.assessed_on)})` : ""}
            {names ? (
              <>
                {" "}
                for <a href={`/scenarios/${l.scenario_id}`}>{names[l.scenario_id] ?? "a scenario"}</a>
              </>
            ) : null}
          </li>
        ))}
      </ul>
      <p>Adopt the control's new version and run the analysis again to make the exposure current.</p>
    </div>
  );
}
