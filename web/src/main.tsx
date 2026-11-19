import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { describe, getMe, send, type Me } from "./api";
import { AcceptanceInbox, AcceptanceList } from "./acceptance/Acceptances";
import { AcceptancePage } from "./acceptance/AcceptancePage";
import { ChannelsPage, DeliveriesPage } from "./notify/Channels";
import { IntegrationForm, IntegrationPage, IntegrationsPage } from "./integrations/Integrations";
import { LossEventsPage } from "./integrations/LossEvents";
import { CoveragePage } from "./frameworks/Coverage";
import { BaselinePage, CrosswalkPage, FrameworksPage, RequirementPage, VersionPage } from "./frameworks/Frameworks";
import { ImportsPage as FrameworkImportsPage } from "./frameworks/Imports";
import { RegisterImportPage } from "./integrations/RegisterImport";
import { ProposalPage, ProposalsPage } from "./integrations/Review";
import { RunPage as IntegrationRunPage } from "./integrations/Runs";
import { NotificationsLink, NotificationsPage, PreferencesPage } from "./notify/Notifications";
import { RequestForm as AcceptanceRequestForm } from "./acceptance/RequestForm";
import { AggregateForm, AggregatePage, AggregatesPage } from "./analysis/Aggregates";
import { ComparePage } from "./analysis/Compare";
import { RunPage } from "./analysis/RunPage";
import { AuditPage } from "./audit/AuditPage";
import { BannerPage } from "./banner";
import { AnswerPage } from "./estimate/AnswerPage";
import { CalibrationPage, ExercisePage, QuestionSetPage, QuestionSets } from "./estimate/Calibration";
import { Inbox } from "./estimate/Inbox";
import { RequestForm, RequestPage } from "./estimate/Requests";
import { PosturePage } from "./posture/PosturePage";
import {
  EntryEditor,
  EntryList,
  EntryPage,
  type EntrySection,
} from "./risk/Entries";
import { ScenarioEditor } from "./risk/ScenarioEditor";
import { ScenarioList } from "./risk/ScenarioList";
import { ScenarioPage } from "./risk/ScenarioPage";
import { TransferPage } from "./risk/Transfer";
import { RiskEditor } from "./register/RiskEditor";
import { RiskList } from "./register/RiskList";
import { RiskPage } from "./register/RiskPage";
import { RollupPage, RollupsPage } from "./register/Rollups";
import { TreatmentEditor } from "./register/Treatment";
import { ReasonPrompt } from "./reason";
import { DashboardPage } from "./reports/Dashboard";
import { MyReportsPage, NewReportPage, ReportPage } from "./reports/Reports";
import { NewSchedulePage, SchedulePage, SchedulesPage } from "./reports/Schedules";
import "./styles.css";

type SessionState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; me: Me };

function App() {
  // The session first: until the system-use banner is acknowledged (F-001
  // T-19, AC-34) the gateway serves nothing else, so the banner is all the
  // app shows.
  const [session, setSession] = useState<SessionState>({ kind: "loading" });
  const load = () =>
    getMe().then(
      (me) => setSession({ kind: "ready", me }),
      (err: unknown) => setSession({ kind: "error", message: describe(err) }),
    );
  useEffect(() => {
    void load();
  }, []);

  if (session.kind === "loading") {
    return <p className="muted">Loading…</p>;
  }
  if (session.kind === "error") {
    return (
      <main id="main">
        <p role="alert">{session.message}</p>
      </main>
    );
  }
  const { banner } = session.me;
  if (banner.required) {
    return (
      <BannerPage
        text={banner.text ?? ""}
        onAcknowledge={async () => {
          await send("POST", "/api/v1/auth/banner/ack", {
            version: banner.version,
          });
          await load();
        }}
      />
    );
  }
  // The platform shell's routing arrives with later features: the path
  // chooses the page (the gateway serves the app for every route).
  const path = window.location.pathname;
  const section = path.startsWith("/notifications")
    ? "notifications"
    : path.startsWith("/frameworks")
    ? "frameworks"
    : path.startsWith("/integrations")
    ? "integrations"
    : path.startsWith("/reports")
    ? "reports"
    : path.startsWith("/register")
    ? "register"
    : path.startsWith("/acceptances")
    ? "acceptances"
    : path.startsWith("/analyses")
    ? "analyses"
    : path.startsWith("/estimates")
    ? "estimates"
    : path.startsWith("/calibration")
    ? "calibration"
    : path.startsWith("/audit")
      ? "audit"
      : path.startsWith("/scenarios") || path.startsWith("/risk/")
        ? "scenarios"
        : path.startsWith("/library")
          ? "library"
          : path.startsWith("/controls")
            ? "controls"
            : "posture";
  const current = (s: string) => (section === s ? "page" : undefined);
  return (
    <>
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <header className="app">
        <span className="brand">FAIR Risk Platform</span>
        <nav aria-label="Primary">
          <ul>
            <li>
              <a href="/register" aria-current={current("register")}>
                Risk register
              </a>
            </li>
            <li>
              <a href="/acceptances" aria-current={current("acceptances")}>
                Acceptances
              </a>
            </li>
            <li>
              <a href="/reports" aria-current={current("reports")}>
                Reports
              </a>
            </li>
            <li>
              <a href="/scenarios" aria-current={current("scenarios")}>
                Scenarios
              </a>
            </li>
            <li>
              <a href="/analyses/aggregates" aria-current={current("analyses")}>
                Aggregates
              </a>
            </li>
            <li>
              <a href="/estimates" aria-current={current("estimates")}>
                Estimate requests
              </a>
            </li>
            <li>
              <a href="/calibration" aria-current={current("calibration")}>
                Calibration
              </a>
            </li>
            <li>
              <a href="/library" aria-current={current("library")}>
                Library
              </a>
            </li>
            <li>
              <a href="/controls" aria-current={current("controls")}>
                Controls
              </a>
            </li>
            <li>
              <a href="/frameworks" aria-current={current("frameworks")}>
                Frameworks
              </a>
            </li>
            <li>
              <a href="/integrations" aria-current={current("integrations")}>
                Integrations
              </a>
            </li>
            <li>
              <a href="/posture" aria-current={current("posture")}>
                Security posture
              </a>
            </li>
            <li>
              <a href="/audit" aria-current={current("audit")}>
                Audit trail
              </a>
            </li>
            <li>
              <NotificationsLink current={section === "notifications"} />
            </li>
          </ul>
        </nav>
      </header>
      <main id="main" tabIndex={-1}>
        {section === "notifications" ? (
          <NotificationRoutes path={path} />
        ) : section === "frameworks" ? (
          <FrameworkRoutes path={path} />
        ) : section === "integrations" ? (
          <IntegrationRoutes path={path} />
        ) : section === "reports" ? (
          <ReportRoutes path={path} />
        ) : section === "register" ? (
          <RegisterRoutes path={path} />
        ) : section === "acceptances" ? (
          <AcceptanceRoutes path={path} />
        ) : section === "analyses" ? (
          <AnalysisRoutes path={path} />
        ) : section === "estimates" ? (
          <EstimateRoutes path={path} />
        ) : section === "calibration" ? (
          <CalibrationRoutes path={path} />
        ) : section === "audit" ? (
          <AuditPage />
        ) : section === "scenarios" ? (
          <ScenarioRoutes path={path} />
        ) : section === "library" || section === "controls" ? (
          <EntryRoutes section={section} path={path} />
        ) : (
          <PosturePage />
        )}
      </main>
      <ReasonPrompt />
    </>
  );
}

// F-010 T-17: /reports (the dashboard), /reports/new, /reports/mine,
// /reports/{id}, /reports/schedules, /reports/schedules/new,
// /reports/schedules/{id} (F-009 notices link to the last two kinds).
function ReportRoutes({ path }: { path: string }) {
  if (path === "/reports" || path === "/reports/") return <DashboardPage />;
  if (path === "/reports/new") return <NewReportPage />;
  if (path === "/reports/mine") return <MyReportsPage />;
  if (path === "/reports/schedules") return <SchedulesPage />;
  if (path === "/reports/schedules/new") return <NewSchedulePage />;
  const s = /^\/reports\/schedules\/([0-9a-f-]{36})$/.exec(path);
  if (s?.[1]) return <SchedulePage id={s[1]} />;
  const m = /^\/reports\/([0-9a-f-]{36})$/.exec(path);
  return m?.[1] ? <ReportPage id={m[1]} /> : <p role="alert">Not found.</p>;
}

// F-013 T-10: /frameworks, /frameworks/imports, /frameworks/versions/{id}
// [/coverage], /frameworks/requirements/{id}, /frameworks/baselines/{id},
// /frameworks/crosswalks/{id}.
function FrameworkRoutes({ path }: { path: string }) {
  if (path === "/frameworks" || path === "/frameworks/") return <FrameworksPage />;
  if (path === "/frameworks/imports") return <FrameworkImportsPage />;
  const v = /^\/frameworks\/versions\/([0-9a-f-]{36})(\/coverage)?$/.exec(path);
  if (v) return v[2] ? <CoveragePage id={v[1] ?? ""} /> : <VersionPage id={v[1] ?? ""} />;
  const m = /^\/frameworks\/(requirements|baselines|crosswalks)\/([0-9a-f-]{36})$/.exec(path);
  if (!m) return <p role="alert">Not found.</p>;
  const id = m[2] ?? "";
  return m[1] === "requirements" ? <RequirementPage id={id} /> : m[1] === "baselines" ? <BaselinePage id={id} /> : <CrosswalkPage id={id} />;
}

// F-011 T-18: /integrations, /integrations/new, /integrations/{id}[/edit],
// /integrations/{id}/runs/{run}, /integrations/proposals[/{id}] (F-009
// notices link to ?run=), /integrations/loss-events.
function IntegrationRoutes({ path }: { path: string }) {
  if (path === "/integrations" || path === "/integrations/") return <IntegrationsPage />;
  if (path === "/integrations/new") return <IntegrationForm />;
  if (path === "/integrations/proposals") return <ProposalsPage />;
  if (path === "/integrations/loss-events") return <LossEventsPage />;
  const p = /^\/integrations\/proposals\/([0-9a-f-]{36})$/.exec(path);
  if (p?.[1]) return <ProposalPage id={p[1]} />;
  const r = /^\/integrations\/([0-9a-f-]{36})\/runs\/([0-9a-f-]{36})$/.exec(path);
  if (r?.[1] && r[2]) return <IntegrationRunPage integration={r[1]} id={r[2]} />;
  const m = /^\/integrations\/([0-9a-f-]{36})(\/edit)?$/.exec(path);
  if (!m?.[1]) return <p role="alert">Not found.</p>;
  return m[2] ? <IntegrationForm id={m[1]} /> : <IntegrationPage id={m[1]} />;
}

// F-009 T-13: /notifications, /notifications/preferences, /notifications/channels,
// /notifications/deliveries.
function NotificationRoutes({ path }: { path: string }) {
  if (path === "/notifications" || path === "/notifications/") return <NotificationsPage />;
  if (path === "/notifications/preferences") return <PreferencesPage />;
  if (path === "/notifications/channels") return <ChannelsPage />;
  if (path === "/notifications/deliveries") return <DeliveriesPage />;
  return <p role="alert">Not found.</p>;
}

// F-007 T-08: /register, /register/new, /register/risks/{id}, /register/risks/{id}/edit;
// T-09: /register/risks/{id}/treatment, /register/rollups, /register/rollups/{id}.
function RegisterRoutes({ path }: { path: string }) {
  if (path === "/register" || path === "/register/") return <RiskList />;
  if (path === "/register/new") return <RiskEditor />;
  if (path === "/register/import") return <RegisterImportPage />; // F-011 T-18
  if (path === "/register/rollups") return <RollupsPage />;
  const ru = /^\/register\/rollups\/([0-9a-f-]{36})$/.exec(path);
  if (ru?.[1]) return <RollupPage id={ru[1]} />;
  const tr = /^\/register\/risks\/([0-9a-f-]{36})\/treatment$/.exec(path);
  if (tr?.[1]) return <TreatmentEditor id={tr[1]} />;
  const m = /^\/register\/risks\/([0-9a-f-]{36})(\/edit)?$/.exec(path);
  if (!m) return <p role="alert">Not found.</p>;
  const id = m[1] ?? "";
  return m[2] ? <RiskEditor id={id} /> : <RiskPage id={id} />;
}

// F-008 T-07: /acceptances, /acceptances/inbox, /acceptances/new?risk=[&renews=],
// /acceptances/{id}.
function AcceptanceRoutes({ path }: { path: string }) {
  if (path === "/acceptances" || path === "/acceptances/") return <AcceptanceList />;
  if (path === "/acceptances/inbox") return <AcceptanceInbox />;
  if (path === "/acceptances/new") return <AcceptanceRequestForm />;
  const m = /^\/acceptances\/([0-9a-f-]{36})$/.exec(path);
  return m?.[1] ? <AcceptancePage id={m[1]} /> : <p role="alert">Not found.</p>;
}

// F-005 T-13: /analyses/aggregates, /analyses/aggregates/new, /analyses/aggregates/{id};
// F-006 T-05: /analyses/runs/{id}; T-06: /analyses/compare?item=….
function AnalysisRoutes({ path }: { path: string }) {
  if (path === "/analyses/compare") return <ComparePage />;
  const run = /^\/analyses\/runs\/([0-9a-f-]{36})$/.exec(path);
  if (run?.[1]) return <RunPage id={run[1]} />;
  if (path === "/analyses/aggregates/new") return <AggregateForm />;
  const m = /^\/analyses\/aggregates\/([0-9a-f-]{36})$/.exec(path);
  if (m?.[1]) return <AggregatePage id={m[1]} />;
  return <AggregatesPage />;
}

// F-003 T-12: /scenarios, /scenarios/new, /scenarios/{id}, /scenarios/{id}/edit.
function ScenarioRoutes({ path }: { path: string }) {
  if (path === "/risk/transfer") return <TransferPage />;
  if (path === "/scenarios" || path === "/scenarios/") return <ScenarioList />;
  if (path === "/scenarios/new") return <ScenarioEditor />;
  const m = /^\/scenarios\/([0-9a-f-]{36})(\/edit)?$/.exec(path);
  if (!m) return <p role="alert">Not found.</p>;
  const id = m[1] ?? "";
  return m[2] ? <ScenarioEditor id={id} /> : <ScenarioPage id={id} />;
}

// F-004 T-12: /estimates (the estimator's inbox), /estimates/{id}.
function EstimateRoutes({ path }: { path: string }) {
  if (path === "/estimates" || path === "/estimates/") return <Inbox />;
  // F-004 T-13: the analyst's side.
  if (path === "/estimates/requests/new") return <RequestForm />;
  const r = /^\/estimates\/requests\/([0-9a-f-]{36})$/.exec(path);
  if (r) return <RequestPage id={r[1] ?? ""} />;
  const m = /^\/estimates\/([0-9a-f-]{36})$/.exec(path);
  return m ? <AnswerPage id={m[1] ?? ""} /> : <p role="alert">Not found.</p>;
}

// F-004 T-14: /calibration, /calibration/exercises/{id},
// /calibration/question-sets[/{id}].
function CalibrationRoutes({ path }: { path: string }) {
  if (path === "/calibration" || path === "/calibration/") return <CalibrationPage />;
  if (path === "/calibration/question-sets") return <QuestionSets />;
  const e = /^\/calibration\/exercises\/([0-9a-f-]{36})$/.exec(path);
  if (e) return <ExercisePage id={e[1] ?? ""} />;
  const s = /^\/calibration\/question-sets\/([0-9a-f-]{36})$/.exec(path);
  return s ? <QuestionSetPage id={s[1] ?? ""} /> : <p role="alert">Not found.</p>;
}

// F-003 T-13: /library and /controls, /new, /{id}, /{id}/edit.
function EntryRoutes({
  section,
  path,
}: {
  section: EntrySection;
  path: string;
}) {
  if (path === `/${section}` || path === `/${section}/`)
    return <EntryList section={section} />;
  if (path === `/${section}/new`)
    return (
      <EntryEditor
        section={section}
        kind={
          new URLSearchParams(window.location.search).get("kind") ?? undefined
        }
      />
    );
  const m = new RegExp(`^/${section}/([0-9a-f-]{36})(/edit)?$`).exec(path);
  if (!m) return <p role="alert">Not found.</p>;
  const id = m[1] ?? "";
  return m[2] ? (
    <EntryEditor section={section} id={id} />
  ) : (
    <EntryPage section={section} id={id} />
  );
}

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
