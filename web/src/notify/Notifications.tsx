import { useEffect, useState } from "react";
import { ApiError, describe, send } from "../api";
import { Badge, Section, Status, useApi } from "../components";

// F-009 T-13 (F-009-AC-02, AC-18, AC-19): each user's notifications in the
// app, their unread count in the header, and which optional notices they
// receive by email or in a daily digest.

export interface Envelope {
  id: string;
  kind: string;
  at: string;
  bu: { id: string; name: string };
  item: { type: string; id: string | null; link: string };
  title?: string;
}

export interface Notification {
  id: number;
  created_at: string;
  read_at: string | null;
  kind: string;
  label: string;
  mandatory: boolean;
  envelope: Envelope;
}

interface Preferences {
  kinds: { kind: string; label: string; mandatory: boolean; security: boolean; email_muted: boolean }[];
  digest: boolean;
  digest_hour: number;
}

function when(s: string): string {
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? s : d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

/** Links only into the platform: a notice's link is a path. */
function safeLink(link: string): string {
  return link.startsWith("/") && !link.startsWith("//") ? link : "/notifications";
}

/** The header's link, with the unread count. */
export function NotificationsLink({ current }: { current: boolean }) {
  const count = useApi<{ unread: number }>("/api/v1/notifications/count");
  const n = count.data?.unread ?? 0;
  return (
    <a href="/notifications" aria-current={current ? "page" : undefined}>
      Notifications
      {n > 0 ? (
        <>
          {" "}
          <span className="badge info">
            {n}
            <span className="sr-only"> unread</span>
          </span>
        </>
      ) : null}
    </a>
  );
}

export function NotificationsPage({ search = window.location.search }: { search?: string }) {
  const q = new URLSearchParams(search);
  const unread = q.get("unread") === "true";
  const before = q.get("before");
  useEffect(() => {
    document.title = "Notifications · FAIR Risk Platform";
  }, []);
  const path = `/api/v1/notifications?limit=50${unread ? "&unread=true" : ""}${before ? `&before=${encodeURIComponent(before)}` : ""}`;
  const list = useApi<{ notifications: Notification[]; more: boolean }>(path);
  const [error, setError] = useState<string>();
  const markAll = async () => {
    setError(undefined);
    try {
      await send("POST", "/api/v1/notifications/read", { all: true });
      list.reload();
    } catch (err) {
      setError(describe(err));
    }
  };
  const open = async (n: Notification) => {
    if (!n.read_at) {
      try {
        await send("POST", "/api/v1/notifications/read", { ids: [n.id] });
      } catch {
        // Opening still works; it stays unread.
      }
    }
    window.location.assign(safeLink(n.envelope.item.link));
  };
  return (
    <>
      <h1>Notifications</h1>
      <p className="lede">What needs your attention, newest first. Each opens the item, where your access decides what you see.</p>
      <p className="actions">
        <a href={unread ? "/notifications" : "/notifications?unread=true"}>{unread ? "Show all" : "Show unread only"}</a>
        <button className="btn" type="button" onClick={() => void markAll()}>
          Mark all as read
        </button>
        <a href="/notifications/preferences">Preferences</a>
      </p>
      {error ? (
        <p role="alert" className="error-text">
          {error}
        </p>
      ) : null}
      <Section id="notifications" title={unread ? "Unread notifications" : "All notifications"}>
        <Status loaded={list}>
          {(data) =>
            data.notifications.length === 0 ? (
              <p>No notifications.</p>
            ) : (
              <>
                <ul className="notice-list">
                  {data.notifications.map((n) => (
                    <li key={n.id} className={n.read_at ? "read" : "unread"}>
                      <a
                        href={safeLink(n.envelope.item.link)}
                        onClick={(e) => {
                          e.preventDefault();
                          void open(n);
                        }}
                      >
                        {n.label}
                        {n.envelope.title ? `: ${n.envelope.title}` : ""}
                      </a>{" "}
                      {n.read_at ? null : <Badge tone="info">Unread</Badge>}
                      {n.mandatory ? null : <Badge tone="muted">Optional</Badge>}
                      <br />
                      <span className="muted">
                        {n.envelope.bu.name} · {when(n.created_at)}
                      </span>
                    </li>
                  ))}
                </ul>
                {data.more ? (
                  <p className="actions">
                    <a href={`/notifications?${unread ? "unread=true&" : ""}before=${data.notifications[data.notifications.length - 1]?.id}`}>Older notifications</a>
                  </p>
                ) : null}
              </>
            )
          }
        </Status>
      </Section>
    </>
  );
}

export function PreferencesPage() {
  useEffect(() => {
    document.title = "Notification preferences · FAIR Risk Platform";
  }, []);
  const prefs = useApi<Preferences>("/api/v1/notifications/preferences");
  const [muted, setMuted] = useState<Record<string, boolean>>({});
  const [digest, setDigest] = useState(false);
  const [hour, setHour] = useState(7);
  const [status, setStatus] = useState<{ tone: "ok" | "bad"; text: string }>();
  useEffect(() => {
    if (prefs.data) {
      setMuted(Object.fromEntries(prefs.data.kinds.map((k) => [k.kind, k.email_muted])));
      setDigest(prefs.data.digest);
      setHour(prefs.data.digest_hour);
    }
  }, [prefs.data]);
  const save = async () => {
    setStatus(undefined);
    try {
      const mutes = Object.fromEntries((prefs.data?.kinds ?? []).filter((k) => !k.mandatory).map((k) => [k.kind, muted[k.kind] ?? false]));
      await send("PUT", "/api/v1/notifications/preferences", { mutes, digest, digest_hour: hour });
      setStatus({ tone: "ok", text: "Saved." });
      prefs.reload();
    } catch (err) {
      const mandatory = err instanceof ApiError && err.code === "mandatory";
      setStatus({ tone: "bad", text: mandatory ? "Security notices and requests to act cannot be muted." : describe(err) });
    }
  };
  return (
    <>
      <nav aria-label="Breadcrumb" className="crumbs">
        <a href="/notifications">Notifications</a>
      </nav>
      <h1>Notification preferences</h1>
      <p className="lede">Every notice stays in your notifications here. These choices are about email only.</p>
      <Status loaded={prefs}>
        {(p) => (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void save();
            }}
          >
            <Section id="email" title="Email" intro="Security notices and requests that ask you to act are always sent.">
              <div className="table-wrap">
                <table className="data">
                  <caption className="sr-only">Notices by email</caption>
                  <thead>
                    <tr>
                      <th scope="col">Notice</th>
                      <th scope="col">By email</th>
                    </tr>
                  </thead>
                  <tbody>
                    {p.kinds.map((k) => (
                      <tr key={k.kind}>
                        <td>{k.label}</td>
                        <td>
                          {k.mandatory ? (
                            <span className="muted">Always sent</span>
                          ) : (
                            <label>
                              <input
                                type="checkbox"
                                checked={!(muted[k.kind] ?? false)}
                                onChange={(e) => setMuted({ ...muted, [k.kind]: !e.target.checked })}
                              />{" "}
                              Send<span className="sr-only">: {k.label}</span>
                            </label>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>
            <Section id="digest" title="Daily digest" intro="Gather the optional notices you receive by email into one email a day.">
              <label>
                <input type="checkbox" checked={digest} onChange={(e) => setDigest(e.target.checked)} /> Send optional notices as one daily digest
              </label>
              <div className="field">
                <label htmlFor="digest-hour">Digest time (UTC)</label>
                <select id="digest-hour" value={hour} onChange={(e) => setHour(Number(e.target.value))} disabled={!digest}>
                  {Array.from({ length: 24 }, (_, h) => (
                    <option key={h} value={h}>
                      {String(h).padStart(2, "0")}:00
                    </option>
                  ))}
                </select>
              </div>
            </Section>
            {status ? (
              <p role={status.tone === "bad" ? "alert" : "status"} className={status.tone === "bad" ? "error-text" : undefined}>
                {status.text}
              </p>
            ) : null}
            <div className="actions">
              <button className="react-aria-Button primary" type="submit">
                Save preferences
              </button>
            </div>
          </form>
        )}
      </Status>
    </>
  );
}
