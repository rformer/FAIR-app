import { useEffect, useRef, useState } from "react";
import { describe, send } from "./api";

// The system-use notification (F-001 T-19, AC-34): shown after sign-in and
// before anything else, until the user acknowledges it. Signing out is the
// other way on.
export function BannerPage({ text, onAcknowledge }: { text: string; onAcknowledge: () => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => heading.current?.focus(), []);

  return (
    <main id="main" className="banner-page">
      <h1 ref={heading} tabIndex={-1}>
        System use notification
      </h1>
      <div className="banner-text">{text}</div>
      {error && <p role="alert">{error}</p>}
      <div className="actions">
        <button
          type="button"
          className="btn primary"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            setError("");
            try {
              await onAcknowledge();
            } catch (err) {
              setError(describe(err));
              setBusy(false);
            }
          }}
        >
          Acknowledge and continue
        </button>
        <button
          type="button"
          className="btn"
          disabled={busy}
          onClick={async () => {
            await send("POST", "/api/v1/auth/logout", {}).catch(() => undefined);
            window.location.assign("/");
          }}
        >
          Sign out
        </button>
      </div>
    </main>
  );
}
