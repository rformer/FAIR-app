import { useEffect, type ReactNode } from "react";
import { send } from "../api";
import { Badge, ReasonAction, Section, Status, useApi, type Tone } from "../components";
import { auditHref, date } from "../links";
import { Provenance, ScenarioRequests } from "../estimate/Requests";
import { ArchiveAction, MoveAction } from "./Actions";
import { History } from "./History";
import { at, factorLabel, showEstimate, type BU, type Estimate, type ScenarioView, type TaxonomyNode } from "./types";

// F-003 T-12 (AC-10, AC-15, AC-17, AC-27, AC-28): one scenario: what it
// says, its FAIR taxonomy as estimated, the library versions it pins (with
// newer ones to adopt), and its history with comparisons.

const STATUS: Record<TaxonomyNode["status"], { label: string; tone: Tone }> = {
  entered: { label: "Entered", tone: "info" },
  derived: { label: "Derived", tone: "ok" },
  library: { label: "From the library", tone: "info" },
  not_used: { label: "Not used", tone: "muted" },
};

export function ScenarioPage({ id }: { id: string }) {
  const view = useApi<ScenarioView>(`/api/v1/scenarios/${id}`);
  const bus = useApi<{ bus: BU[] }>("/api/v1/risk/bus?permission=scenario.view");
  const editable = useApi<{ bus: BU[] }>("/api/v1/risk/bus?permission=scenario.edit");
  const name = view.data?.version.document?.name ?? "Scenario";
  useEffect(() => {
    document.title = `${name} · FAIR Risk Platform`;
  }, [name]);

  return (
    <Status loaded={view}>
      {(v) => {
        const doc = v.version.document!;
        const bu = bus.data?.bus.find((b) => b.id === v.scenario.bu_id)?.name ?? v.scenario.bu_id;
        // Changes need scenario.edit at the scenario's BU; the API decides,
        // the page only offers what it would allow.
        const mayEdit = editable.data?.bus.some((b) => b.id === v.scenario.bu_id) ?? false;
        const canEdit = !v.scenario.archived_at && mayEdit;
        return (
          <>
            <nav aria-label="Breadcrumb" className="crumbs">
              <a href="/scenarios">Scenarios</a>
            </nav>
            <h1>{doc.name}</h1>
            <p className="lede">
              {bu} · version {v.scenario.current_version}
              {v.scenario.archived_at ? (
                <>
                  {" "}
                  · <Badge tone="muted">Archived</Badge>
                </>
              ) : null}
            </p>
            <p className="actions">
              {canEdit ? (
                <a className="react-aria-Button" href={`/scenarios/${id}/edit`}>
                  Edit
                </a>
              ) : null}
              {canEdit ? <MoveAction id={id} from={v.scenario.bu_id} bus={editable.data?.bus ?? []} onDone={view.reload} /> : null}
              {mayEdit ? <ArchiveAction base={`/api/v1/scenarios/${id}`} archived={v.scenario.archived_at !== null} what="scenario" onDone={view.reload} /> : null}
              <a href={auditHref(`scenario:${id}`)}>Audit history of this scenario</a>
            </p>
            <Summary v={v} />
            <Taxonomy v={v} />
            <Pins v={v} id={id} canEdit={canEdit} onAdopted={view.reload} />
            {/* F-004 T-13: estimate requests and where accepted estimates came from. */}
            <Provenance v={v} />
            <ScenarioRequests id={id} canRequest={canEdit} />
            {/* Remounted on a new version: its list and comparison follow. */}
            <History key={v.scenario.current_version} base={`/api/v1/scenarios/${id}`} current={v.scenario.current_version} />
          </>
        );
      }}
    </Status>
  );
}

function Summary({ v }: { v: ScenarioView }) {
  const doc = v.version.document!;
  const row = (label: string, value: ReactNode) => (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
  return (
    <Section id="summary" title="Scenario">
      <dl className="summary">
        {row("Loss event", doc.loss_event)}
        {doc.description ? row("Description", doc.description) : null}
        {row("In scope", doc.scope.in)}
        {doc.scope.out ? row("Out of scope", doc.scope.out) : null}
        {row("Analysis period", `${doc.analysis_period.start} to ${doc.analysis_period.end}`)}
        {row("Threat effects", doc.threat_effects.join(", "))}
        {row("Currency", v.currency ?? "not set")}
        {row("Last change", `${v.version.change_note} (${date(v.version.created_at)})`)}
      </dl>
    </Section>
  );
}

/** AC-28: the taxonomy as estimated: entered, derived, or not used. */
function Taxonomy({ v }: { v: ScenarioView }) {
  const children = (parent: string | undefined) => v.taxonomy.filter((n) => n.parent === parent);
  const tree = (parent: string | undefined): ReactNode => {
    const nodes = children(parent);
    if (nodes.length === 0) return null;
    return (
      <ul className={parent === undefined ? "tree" : undefined}>
        {nodes.map((n) => (
          <li key={n.factor}>
            <span className="node">
              {factorLabel(n.factor)} <Badge tone={STATUS[n.status].tone}>{STATUS[n.status].label}</Badge>
              {n.pointer ? <span className="muted"> {showEstimate(at(v.version.document, n.pointer) as Estimate, v.currency)}</span> : null}
            </span>
            {tree(n.factor)}
          </li>
        ))}
      </ul>
    );
  };
  return (
    <Section id="taxonomy" title="FAIR taxonomy" intro="Which factors this scenario estimates, and which the simulation will derive from them.">
      {tree(undefined)}
    </Section>
  );
}

/** AC-10: the library and control versions in use, and newer ones. */
function Pins({ v, id, canEdit, onAdopted }: { v: ScenarioView; id: string; canEdit: boolean; onAdopted: () => void }) {
  const newer = v.pins.filter((p) => p.newer && !p.member_of);
  return (
    <Section id="pins" title="Library and controls used" intro="Each is pinned to the version the scenario was saved with; a newer version changes nothing until you adopt it.">
      {newer.length > 0 && canEdit ? (
        <div className="banner warn" role="status">
          <p>
            {newer.length === 1 ? "A newer version is available" : `${newer.length} newer versions are available`} for what this scenario uses.
          </p>
          <ReasonAction
            label="Adopt newer versions"
            title="Adopt newer versions"
            fieldLabel="Change note"
            description={<p>Saves a new version of the scenario using the newest version of each, with nothing else changed.</p>}
            submitLabel="Adopt"
            onSubmit={async (note) => {
              await send("POST", `/api/v1/scenarios/${id}/adopt`, { expected_version: v.scenario.current_version, change_note: note });
              onAdopted();
            }}
          />
        </div>
      ) : null}
      <div className="table-wrap">
        <table className="data">
          <caption className="sr-only">Pinned library entries and controls</caption>
          <thead>
            <tr>
              <th scope="col">Used as</th>
              <th scope="col">Kind</th>
              <th scope="col">Pinned version</th>
              <th scope="col">Current version</th>
            </tr>
          </thead>
          <tbody>
            {v.pins.map((p) => (
              <tr key={p.pointer}>
                <td className="mono">{p.pointer}</td>
                <td>{p.kind.replace("_", " ")}</td>
                <td>{p.version}</td>
                <td>
                  {p.current_version === null ? (
                    <span className="muted">Not visible to you</span>
                  ) : (
                    <>
                      {p.current_version} {p.newer ? <Badge tone="warn">Newer available</Badge> : null}
                    </>
                  )}
                  {p.reachable === false ? (
                    <>
                      {" "}
                      <Badge tone="warn">Outside this business unit</Badge>
                    </>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  );
}
