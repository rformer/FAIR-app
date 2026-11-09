import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { describe, getMe, send, type Me } from "./api";
import { AuditPage } from "./audit/AuditPage";
import { BannerPage } from "./banner";
import { PosturePage } from "./posture/PosturePage";
import { ScenarioEditor } from "./risk/ScenarioEditor";
import { ScenarioList } from "./risk/ScenarioList";
import { ScenarioPage } from "./risk/ScenarioPage";
import "./styles.css";

type SessionState = { kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; me: Me };

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
          await send("POST", "/api/v1/auth/banner/ack", { version: banner.version });
          await load();
        }}
      />
    );
  }
  // The platform shell's routing arrives with later features: the path
  // chooses the page (the gateway serves the app for every route).
  const path = window.location.pathname;
  const section = path.startsWith("/audit") ? "audit" : path.startsWith("/scenarios") ? "scenarios" : "posture";
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
        {section === "audit" ? <AuditPage /> : section === "scenarios" ? <ScenarioRoutes path={path} /> : <PosturePage />}
      </main>
    </>
  );
}

// F-003 T-12: /scenarios, /scenarios/new, /scenarios/{id}, /scenarios/{id}/edit.
function ScenarioRoutes({ path }: { path: string }) {
  if (path === "/scenarios" || path === "/scenarios/") return <ScenarioList />;
  if (path === "/scenarios/new") return <ScenarioEditor />;
  const m = /^\/scenarios\/([0-9a-f-]{36})(\/edit)?$/.exec(path);
  if (!m) return <p role="alert">Not found.</p>;
  const id = m[1] ?? "";
  return m[2] ? <ScenarioEditor id={id} /> : <ScenarioPage id={id} />;
}

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
