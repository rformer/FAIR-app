// The API client. Requests go to the same origin: the gateway (F-001 T-13)
// authenticates the session and forwards them to the services. Every
// mutation carries the session's CSRF token (from /api/v1/me) and a fresh
// Idempotency-Key (F-015 T-31), so a retried request never applies twice.

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly detail: string,
    /** The error's body as the API sent it (e.g. a 422's problems). */
    readonly body: unknown = undefined,
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
    const b = (body ?? {}) as { error?: string; detail?: string; login_url?: string };
    // Sign in again at the IdP, coming back to this page: the session ended
    // because its network changed (F-001 T-20), or a restricted business
    // unit needs a recent sign-in (step-up, F-015 T-24b; the URL then
    // already asks the IdP to re-authenticate).
    if (resp.status === 401 && b.login_url?.startsWith("/api/v1/auth/")) {
      const login = new URL(b.login_url, window.location.origin);
      login.searchParams.set("return", window.location.pathname + window.location.search);
      window.location.assign(login.pathname + login.search);
    }
    throw new ApiError(resp.status, b.error ?? "", b.detail ?? "", body);
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

export async function send<T>(method: "POST" | "PATCH" | "PUT" | "DELETE", path: string, body: unknown, headers: Record<string, string> = {}): Promise<T> {
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
      ...headers,
    },
    body: JSON.stringify(body),
  });
  return handle<T>(resp);
}

/**
 * The header carrying an export's or a download's reason (F-010 T-12,
 * design §3.6): percent-encoded UTF-8, as browsers send only Latin-1 in
 * headers. Empty without a reason.
 */
export function reasonHeader(reason?: string): Record<string, string> {
  return reason ? { "X-Fair-Reason": encodeURIComponent(reason) } : {};
}

/** A file from the API (a download), with an optional reason; errors as ApiError. */
export async function getFile(path: string, reason?: string): Promise<Response> {
  const resp = await fetch(path, { credentials: "same-origin", headers: { Accept: "*/*", ...reasonHeader(reason) } });
  if (!resp.ok) await handle<never>(resp);
  return resp;
}

/** The file name a download's Content-Disposition gives, or fallback. */
export function attachmentName(resp: Response, fallback: string): string {
  return /filename="([^"]+)"/.exec(resp.headers.get("Content-Disposition") ?? "")?.[1] ?? fallback;
}

/** The person closed the reason prompt: nothing was exported. */
export class ReasonCancelled extends Error {
  constructor() {
    super("No reason was given, so nothing was exported.");
    this.name = "ReasonCancelled";
  }
}

/** A human message for an error, without leaking anything the server did not say. */
export function describe(err: unknown): string {
  if (err instanceof ReasonCancelled) return err.message;
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
