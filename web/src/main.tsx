import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { PosturePage } from "./posture/PosturePage";
import "./styles.css";

function App() {
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
