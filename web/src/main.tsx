import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { describe, getMe, send, type Me } from "./api";
import { AggregateForm, AggregatePage, AggregatesPage } from "./analysis/Aggregates";
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
  const section = path.startsWith("/analyses")
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
              <a href="/posture" aria-current={current("posture")}>
                Security posture
              </a>
            </li>
            <li>
              <a href="/audit" aria-current={current("audit")}>
                Audit trail
              </a>
            </li>
          </ul>
        </nav>
      </header>
      <main id="main" tabIndex={-1}>
        {section === "analyses" ? (
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
    </>
  );
}

// F-005 T-13: /analyses/aggregates, /analyses/aggregates/new, /analyses/aggregates/{id};
// F-006 T-05: /analyses/runs/{id}.
function AnalysisRoutes({ path }: { path: string }) {
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
