import { useState } from "react";
import { ApiError, send } from "../api";
import { Badge, ConfirmAction, ReasonAction, Section, Status, useApi, type Loaded, type Tone } from "../components";
import { approvalHref, auditHref, date, daysUntil, show } from "../links";
import { controlStatuses } from "./controls";
import {
  API,
  type ExceptionRow,
  type Finding,
  type K8sAccess,
  type PendingSwitch,
  type Profile,
  type RegistryEntry,
} from "./types";

// F-015 T-32 (AC-43, AC-44): the Posture page, for posture.view holders.
// Every item links to its audit history and to its remediation or approval
// action.

const deviationLabel: Record<RegistryEntry["deviation"], [string, Tone]> = {
  in_bounds: ["Within bounds", "ok"],
  exception: ["Exception", "warn"],
  out_of_bounds: ["Out of bounds", "bad"],
  below_floor: ["Below hard floor", "bad"],
  unbound: ["Not in profile", "muted"],
};

const severityTone: Record<string, Tone> = { critical: "bad", high: "bad", medium: "warn", low: "info" };

export function PosturePage() {
  const registry = useApi<{ settings: RegistryEntry[] }>(`${API}/registry`);
  const profiles = useApi<{ profiles: Profile[] }>(`${API}/profiles`);
  const exceptions = useApi<{ exceptions: ExceptionRow[] }>(`${API}/exceptions`);
  const switches = useApi<{ pending: PendingSwitch | null }>(`${API}/switches`);
  // Fixed for the page's lifetime: a new cutoff on every render would change
  // the URL and refetch forever.
  const [since] = useState(() => new Date(Date.now() - 30 * 86_400_000).toISOString());
  const drift = useApi<{ findings: Finding[] }>(`${API}/drift?resolved_since=${encodeURIComponent(since)}`);
  const k8s = useApi<K8sAccess>(`${API}/k8s-access`);

  if (registry.error instanceof ApiError && registry.error.status === 404) {
    return (
      <>
        <h1>Security posture</h1>
        <p role="alert">You do not have access to the security posture (it needs the posture.view permission).</p>
      </>
    );
  }

  return (
    <>
      <h1>Security posture</h1>
      <p className="lede">The active security profile, how the platform conforms to it, and what needs attention.</p>
      <nav className="toc" aria-label="Posture sections">
        <ul>
          <li><a href="#profile">Profile and conformance</a></li>
          <li><a href="#deviations">Deviations and exceptions</a></li>
          <li><a href="#expiries">Expiries and reverts</a></li>
          <li><a href="#switch">Profile switch</a></li>
          <li><a href="#drift">Drift findings</a></li>
          <li><a href="#k8s">Kubernetes access</a></li>
          <li><a href="#controls">Controls</a></li>
        </ul>
      </nav>
      <K8sBanner loaded={k8s} />
      <ProfileSection profiles={profiles} registry={registry} />
      <DeviationsSection registry={registry} exceptions={exceptions} />
      <ExpiriesSection exceptions={exceptions} />
      <SwitchSection switches={switches} />
      <DriftSection drift={drift} />
      <K8sSection k8s={k8s} />
      <ControlsSection registry={registry} drift={drift} k8s={k8s} />
    </>
  );
}

/** AC-40: the persistent warning while deployment drift detection is off. */
function K8sBanner({ loaded }: { loaded: Loaded<K8sAccess> }) {
  const w = loaded.data?.warning;
  if (!w) return null;
  return (
    <div className="banner" role="region" aria-label="Deployment drift detection warning">
      <strong>Deployment drift detection: </strong>
      {w} <a href="#k8s">Kubernetes access details</a>
    </div>
  );
}

function ProfileSection({ profiles, registry }: { profiles: Loaded<{ profiles: Profile[] }>; registry: Loaded<{ settings: RegistryEntry[] }> }) {
  return (
    <Section id="profile" title="Profile and conformance">
      <Status loaded={profiles}>
        {({ profiles: ps }) => {
          const active = ps.find((p) => p.active);
          if (!active) return <p>No profile is active yet: the install has not been seeded.</p>;
          return (
            <p>
              Active profile: <strong>{active.name}</strong> <span className="mono">{active.id}@{active.version}</span>{" "}
              <Badge tone="info">{active.kind === "custom" ? "Custom" : "Built-in"}</Badge>{" "}
              {active.label_deviates ? <Badge tone="warn">Deviates from {active.base_profile_id}</Badge> : null}{" "}
              <a href={auditHref(`profile:${active.id}@${active.version}`)}>Audit history</a>
            </p>
          );
        }}
      </Status>
      <Status loaded={registry}>
        {({ settings }) => {
          const n = (d: RegistryEntry["deviation"]) => settings.filter((s) => s.deviation === d).length;
          const bound = settings.length - n("unbound");
          return (
            <>
              <p>
                <strong>{n("in_bounds")}</strong> of {bound} settings are within the profile's bounds.
              </p>
              <ul className="stats" aria-label="Conformance">
                <li><span className="n">{n("in_bounds")}</span>within bounds</li>
                <li><span className="n">{n("exception")}</span>under an approved exception</li>
                <li><span className="n">{n("out_of_bounds")}</span>out of bounds</li>
                <li><span className="n">{n("below_floor")}</span>below the hard floor</li>
              </ul>
            </>
          );
        }}
      </Status>
    </Section>
  );
}

function DeviationsSection({ registry, exceptions }: { registry: Loaded<{ settings: RegistryEntry[] }>; exceptions: Loaded<{ exceptions: ExceptionRow[] }> }) {
  return (
    <Section id="deviations" title="Deviations and exceptions">
      <Status loaded={registry}>
        {({ settings }) => {
          const devs = settings.filter((s) => s.deviation !== "in_bounds" && s.deviation !== "unbound");
          if (devs.length === 0) return <p>Every setting is within the active profile's bounds.</p>;
          return (
            <div className="table-wrap">
              <table className="data">
                <caption className="sr-only">Settings that deviate from the active profile</caption>
                <thead>
                  <tr>
                    <th scope="col">Setting</th><th scope="col">Value</th><th scope="col">Profile bound</th>
                    <th scope="col">Status</th><th scope="col">Controls</th><th scope="col">Links</th>
                  </tr>
                </thead>
                <tbody>
                  {devs.map((s) => {
                    const [label, tone] = deviationLabel[s.deviation];
                    return (
                      <tr key={s.key}>
                        <th scope="row" className="mono">{s.key}</th>
                        <td className="mono">{show(s.value)}</td>
                        <td className="mono">{show(s.bound)}</td>
                        <td>
                          <Badge tone={tone}>{label}</Badge>
                          {s.exception_expires ? <> until {date(s.exception_expires)}</> : null}
                        </td>
                        <td>{(s.controls ?? []).join(", ") || "—"}</td>
                        <td><a href={auditHref(`setting:${s.key}`)}>Audit history<span className="sr-only"> of {s.key}</span></a></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          );
        }}
      </Status>
      <h3>Active exceptions</h3>
      <Status loaded={exceptions}>
        {({ exceptions: xs }) => {
          const active = xs.filter((x) => x.state === "active" || x.state === "revert_failed");
          if (active.length === 0) return <p>No active exceptions.</p>;
          return (
            <div className="table-wrap">
              <table className="data">
                <caption className="sr-only">Active exceptions with their owners and expiry</caption>
                <thead>
                  <tr>
                    <th scope="col">Setting</th><th scope="col">Value</th><th scope="col">Owner</th><th scope="col">Approved by</th>
                    <th scope="col">Expires</th><th scope="col">Justification</th><th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {active.map((x) => (
                    <tr key={x.exception_id}>
                      <th scope="row" className="mono">
                        {x.overlay ? "overlay: " : ""}{x.key}{x.bu_id ? ` @ ${x.bu_id}` : ""}
                      </th>
                      <td className="mono">{show(x.value)}</td>
                      <td className="mono">{x.owner_id}</td>
                      <td className="mono">{x.approved_by}</td>
                      <td>
                        {date(x.expires_at)} {x.state === "revert_failed" ? <Badge tone="bad">Revert failing</Badge> : null}
                      </td>
                      <td>{x.justification}</td>
                      <td className="actions">
                        <ReasonAction
                          label="Renew"
                          title={`Renew the exception for ${x.key}`}
                          fieldLabel="New justification"
                          description="A renewal needs a new justification and a second approver; the exception keeps its value until it expires."
                          submitLabel="Request renewal"
                          onSubmit={async (reason) => {
                            await send("POST", `${API}/exceptions/${x.exception_id}/renew`, { justification: reason });
                            exceptions.reload();
                          }}
                        />
                        <a href={auditHref(`exception:${x.exception_id}`)}>Audit history<span className="sr-only"> of this exception</span></a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          );
        }}
      </Status>
    </Section>
  );
}

function ExpiriesSection({ exceptions }: { exceptions: Loaded<{ exceptions: ExceptionRow[] }> }) {
  return (
    <Section id="expiries" title="Upcoming expiries and recent reverts">
      <Status loaded={exceptions}>
        {({ exceptions: xs }) => {
          const upcoming = xs.filter((x) => x.state === "active" && daysUntil(x.expires_at) <= 30);
          const reverted = xs.filter((x) => x.state === "reverted" && daysUntil(x.expires_at) >= -30);
          return (
            <>
              <h3>Expiring within 30 days</h3>
              {upcoming.length === 0 ? (
                <p>None.</p>
              ) : (
                <ul>
                  {upcoming.map((x) => (
                    <li key={x.exception_id}>
                      <span className="mono">{x.key}</span> expires {date(x.expires_at)} ({daysUntil(x.expires_at)} days) and then reverts automatically.{" "}
                      <a href={auditHref(`exception:${x.exception_id}`)}>Audit history</a>
                    </li>
                  ))}
                </ul>
              )}
              <h3>Reverted in the last 30 days</h3>
              {reverted.length === 0 ? (
                <p>None.</p>
              ) : (
                <ul>
                  {reverted.map((x) => (
                    <li key={x.exception_id}>
                      <span className="mono">{x.key}</span> reverted to the profile value after its exception expired on {date(x.expires_at)}.{" "}
                      <a href={auditHref(`exception:${x.exception_id}`)}>Audit history</a>
                    </li>
                  ))}
                </ul>
              )}
            </>
          );
        }}
      </Status>
    </Section>
  );
}

function SwitchSection({ switches }: { switches: Loaded<{ pending: PendingSwitch | null }> }) {
  return (
    <Section id="switch" title="Pending profile switch">
      <Status loaded={switches}>
        {({ pending }) => {
          if (!pending) return <p>No profile switch is pending.</p>;
          return (
            <>
              <p>
                From <span className="mono">{pending.from}</span> to <span className="mono">{pending.target}</span>{" "}
                {pending.loosening ? <Badge tone="warn">Loosening: needs approval</Badge> : null}{" "}
                <Badge tone={pending.unresolved > 0 ? "warn" : "ok"}>{pending.unresolved} unresolved conflicts</Badge>{" "}
                {pending.approval_id ? <a href={approvalHref(pending.approval_id)}>Approval request</a> : null}{" "}
                <a href={auditHref(`switch:${pending.switch_id}`)}>Audit history</a>
              </p>
              {pending.conflicts.length > 0 ? (
                <div className="table-wrap">
                  <table className="data">
                    <caption className="sr-only">Conflicts of the pending switch</caption>
                    <thead>
                      <tr>
                        <th scope="col">Setting</th><th scope="col">Scope</th><th scope="col">Current value</th>
                        <th scope="col">Target bound</th><th scope="col">Resolution</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pending.conflicts.map((c) => (
                        <tr key={c.conflict_id}>
                          <th scope="row" className="mono">{c.key}</th>
                          <td>{c.bu_id ? <span className="mono">{c.bu_id}</span> : "Instance"}</td>
                          <td className="mono">{show(c.current)}</td>
                          <td className="mono">{show(c.new_bound)}</td>
                          <td>
                            <Badge tone={c.resolution === "unresolved" ? "warn" : "ok"}>{c.resolution}</Badge>
                            {c.below_floor ? <> (below the target's hard floor: must conform)</> : null}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}
            </>
          );
        }}
      </Status>
    </Section>
  );
}

function DriftSection({ drift }: { drift: Loaded<{ findings: Finding[] }> }) {
  return (
    <Section id="drift" title="Drift findings" intro="Findings stay open until the check that raised them no longer sees the problem; acknowledging records that it is being handled.">
      <Status loaded={drift}>
        {({ findings }) => {
          if (findings.length === 0) return <p>No drift findings.</p>;
          return (
            <div className="table-wrap">
              <table className="data">
                <caption className="sr-only">Drift findings, most severe first</caption>
                <thead>
                  <tr>
                    <th scope="col">Severity</th><th scope="col">Finding</th><th scope="col">Controls</th>
                    <th scope="col">Status</th><th scope="col">Remediation</th><th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f) => (
                    <tr key={f.finding_id}>
                      <td><Badge tone={severityTone[f.severity] ?? "muted"}>{f.severity}</Badge></td>
                      <th scope="row">
                        <span className="mono">{f.check_id}</span>
                        <br />
                        <span className="mono muted">{f.subject}</span>
                        {f.kind === "deployment" ? <> <Badge tone="muted">Deployment</Badge></> : null}
                      </th>
                      <td>{(f.controls ?? []).join(", ")}</td>
                      <td>
                        <Badge tone={f.status === "resolved" ? "ok" : f.status === "acknowledged" ? "info" : "warn"}>{f.status}</Badge>
                        {f.acknowledge_reason ? <div className="muted">“{f.acknowledge_reason}”</div> : null}
                      </td>
                      <td>{f.remediation}</td>
                      <td className="actions">
                        {f.status === "open" ? (
                          <ReasonAction
                            label="Acknowledge"
                            title={`Acknowledge ${f.check_id}`}
                            fieldLabel="Reason"
                            description="Acknowledging records that the finding is being handled. It stays open until its check no longer sees the problem."
                            submitLabel="Acknowledge finding"
                            onSubmit={async (reason) => {
                              await send("POST", `${API}/drift/${f.finding_id}/acknowledge`, { reason });
                              drift.reload();
                            }}
                          />
                        ) : null}
                        <a href={auditHref(f.subject)}>Audit history<span className="sr-only"> of {f.subject}</span></a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          );
        }}
      </Status>
    </Section>
  );
}

function K8sSection({ k8s }: { k8s: Loaded<K8sAccess> }) {
  return (
    <Section id="k8s" title="Kubernetes access">
      <Status loaded={k8s}>
        {(s) => (
          <>
            <p>
              State: <Badge tone={s.state === "granted" ? "ok" : "bad"}>{s.state}</Badge>
              {s.decided_at ? <> since {date(s.decided_at)}</> : null}
              {s.reason ? <> — “{s.reason}”</> : null}. Deployment mode: {s.deployment_mode}. Last scanner report:{" "}
              {s.last_report ? date(s.last_report) : "none"}. <a href={auditHref("posture:k8s-access")}>Audit history</a>
            </p>
            {s.state === "requested" ? (
              <ConfirmAction
                label="Acknowledge the scanner's access"
                title="Acknowledge Kubernetes access"
                description={
                  <p>
                    This grants the deployment scanner the read-only permissions listed in the release's permission manifest (digest{" "}
                    <span className="mono">{s.permissions_digest?.slice(0, 12)}</span>…).
                  </p>
                }
                confirmLabel="Grant access"
                onConfirm={async () => {
                  await send("POST", `${API}/k8s-access/acknowledge-grant`, { permissions_digest: s.permissions_digest });
                  k8s.reload();
                }}
              />
            ) : null}
            <div className="table-wrap">
              <table className="data">
                <caption className="sr-only">Deployment checks and whether they are assessed</caption>
                <thead>
                  <tr><th scope="col">Deployment check</th><th scope="col">Controls</th><th scope="col">Assessment</th></tr>
                </thead>
                <tbody>
                  {s.checks.map((c) => (
                    <tr key={c.check_id}>
                      <th scope="row">{c.title}</th>
                      <td>{(c.controls ?? []).join(", ")}</td>
                      <td>
                        {c.assessed ? <Badge tone="ok">Assessed</Badge> : <><Badge tone="muted">Not assessed</Badge> {c.reason}</>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Status>
    </Section>
  );
}

function ControlsSection({ registry, drift, k8s }: { registry: Loaded<{ settings: RegistryEntry[] }>; drift: Loaded<{ findings: Finding[] }>; k8s: Loaded<K8sAccess> }) {
  return (
    <Section id="controls" title="Per-control status" intro="Each 800-53 control the platform's settings and deployment checks support, with what affects it.">
      <Status loaded={registry}>
        {({ settings }) => {
          const rows = controlStatuses(settings, drift.data?.findings ?? [], k8s.data?.checks ?? []);
          return (
            <div className="table-wrap">
              <table className="data">
                <caption className="sr-only">Status per control</caption>
                <thead>
                  <tr><th scope="col">Control</th><th scope="col">Status</th><th scope="col">Settings</th><th scope="col">Deployment checks</th><th scope="col">Open findings</th></tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.control}>
                      <th scope="row">{r.control}</th>
                      <td><Badge tone={r.tone}>{r.status}</Badge></td>
                      <td>
                        {r.settings.length === 0 ? "—" : r.settings.map((s, i) => (
                          <span key={s}>{i > 0 ? ", " : ""}<a className="mono" href={auditHref(`setting:${s}`)}>{s}</a></span>
                        ))}
                      </td>
                      <td>{r.checks.join(", ") || "—"}</td>
                      <td>{r.findings || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          );
        }}
      </Status>
    </Section>
  );
}
