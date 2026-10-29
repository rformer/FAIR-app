import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { describe, getMe, send, type Me } from "./api";
import { BannerPage } from "./banner";
import { PosturePage } from "./posture/PosturePage";
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
  // The platform shell's routing arrives with later features; T-32 serves
  // the Posture page.
  return (
    <>
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <header className="app">
        <span className="brand">FAIR Risk Platform</span>
        <nav aria-label="Primary">
          <a href="/posture" aria-current="page">
            Security posture
          </a>
        </nav>
      </header>
      <main id="main" tabIndex={-1}>
        <PosturePage />
      </main>
    </>
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
