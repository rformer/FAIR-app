// The API client. Requests go to the same origin: the gateway (F-001 T-13)
// authenticates the session and forwards them to the services. Every
// mutation carries the session's CSRF token (from /api/v1/me) and a fresh
// Idempotency-Key (F-015 T-31), so a retried request never applies twice.

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly detail: string,
  ) {
    super(detail || code || `HTTP ${status}`);
  }
}

async function handle<T>(resp: Response): Promise<T> {
  const text = await resp.text();
  let body: unknown = undefined;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    body = undefined;
  }
  if (!resp.ok) {
    const b = (body ?? {}) as { error?: string; detail?: string };
    throw new ApiError(resp.status, b.error ?? "", b.detail ?? "");
  }
  return body as T;
}

export async function getJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
  const resp = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" }, signal });
  return handle<T>(resp);
}

/** The session as the gateway describes it (F-001 T-13, T-19). */
export interface Me {
  user_id: string;
  auth_method: string;
  csrf_token: string;
  banner: { required: boolean; version?: number; text?: string; acknowledged_at?: string | null };
}

let csrfToken: string | undefined;

/** The session; remembers its CSRF token for later mutations. */
export async function getMe(): Promise<Me> {
  const me = await getJSON<Me>("/api/v1/me");
  csrfToken = me.csrf_token;
  return me;
}

export async function send<T>(method: "POST" | "PATCH", path: string, body: unknown): Promise<T> {
  if (csrfToken === undefined) {
    await getMe();
  }
  const resp = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "Idempotency-Key": crypto.randomUUID(),
      "X-CSRF-Token": csrfToken ?? "",
    },
    body: JSON.stringify(body),
  });
  return handle<T>(resp);
}

/** A human message for an error, without leaking anything the server did not say. */
export function describe(err: unknown): string {
  if (err instanceof ApiError) {
    switch (err.status) {
      case 401:
        return "Your session has expired. Sign in again.";
      case 403:
        return "You do not hold the permission this action needs.";
      case 404:
        return "Not found, or not visible to you.";
      default:
        return err.detail || `The request failed (${err.status}${err.code ? `: ${err.code}` : ""}).`;
    }
  }
  return "The request failed. Check your connection and try again.";
}
