/**
 * The one place this portal talks to the API. Every request in the application goes through
 * {@link request}, so the rules below are properties of the whole client rather than habits
 * at forty call sites.
 *
 * 1. **Same-origin, credentialed.** Paths are relative (`/v1/...`), so the browser attaches
 *    the `HttpOnly` session cookie and the request is same-origin: no CORS preflight, no
 *    allow-list to keep in step, and no way for this client to be pointed at another host by
 *    configuration. {@link assertSameOriginPath} refuses anything that is not a `/v1` path,
 *    which is what stops a caller-supplied identifier from turning a path into a URL.
 *
 * 2. **Every mutation carries the CSRF secret, read fresh.** {@link readCsrfToken} reads the
 *    cookie at the moment of the request. Never cached: another tab that signed in, or a
 *    password change that replaced the session, rewrites that cookie, and a cached copy is
 *    exactly the stale value that produces a baffling refusal. A mutation with no token
 *    available is **refused here** rather than sent -- the server would refuse it anyway, and
 *    failing locally keeps a pointless credentialed request off the wire.
 *
 * 3. **Bodies are bounded before they are sent.** The API refuses a body over 16 KiB with
 *    `413`, and this refuses one over the same limit without sending it. Not a security
 *    control -- the server's is -- but it means an oversized value is reported against the
 *    form the customer is looking at.
 *
 * 4. **Refusals become {@link ApiError} and nothing else.** No response text reaches a
 *    message; the code is looked up in a closed table. A response that is not JSON, a network
 *    failure and an unparseable body all become an `ApiError` too, so no caller has to
 *    distinguish "the API refused" from "fetch threw".
 *
 * 5. **Nothing is logged.** There is no `console` call in this file or anywhere else in the
 *    portal (Biome's `noConsole` is an error), because the one thing a log of a request would
 *    eventually contain is a request that carried a secret.
 */

import { readCsrfToken } from "../lib/csrf.ts";
import { ApiError } from "./errors.ts";

/** The API's own bound, mirrored so an oversized body is reported against the form. */
export const MAX_BODY_BYTES = 16 * 1024;

/** The header the API reads the CSRF secret from. */
export const CSRF_HEADER = "X-CSRF-Token";

/** The header a retry-safe mutation carries. */
export const IDEMPOTENCY_HEADER = "Idempotency-Key";

type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

/**
 * The mutations that are **not** cookie-authenticated, and therefore carry no CSRF secret.
 *
 * CSRF protection defends a request that the browser authenticates *for* the caller -- the
 * session cookie rides along whether or not the page meant it to, which is the whole problem.
 * These six routes authenticate with what is in the body (a password, a one-time token) or
 * with nothing at all, so there is no ambient authority to abuse and no session secret in
 * existence yet to prove knowledge of. The API requires no `X-CSRF-Token` on any of them; it
 * requires an allow-listed `Origin` on login, which the browser sends by itself.
 *
 * A **closed list, checked here**, rather than a flag each call site passes. A flag can be
 * forgotten at a new call site, and the failure mode of forgetting it is a cookie-
 * authenticated mutation that silently stops proving where it came from. This way, adding a
 * route to the exemption is an edit to this list -- visible in a diff, and a thing somebody
 * has to justify.
 */
const UNAUTHENTICATED_MUTATIONS: ReadonlySet<string> = new Set([
  "/v1/account/signup",
  "/v1/account/verification/request",
  "/v1/account/verification/complete",
  "/v1/account/recovery/request",
  "/v1/account/recovery/complete",
  "/v1/account/login",
]);

/** Whether a mutation to this path must carry the session's CSRF secret. Reads never do. */
export function requiresCsrf(method: string, path: string): boolean {
  if (method === "GET") return false;
  return !UNAUTHENTICATED_MUTATIONS.has(path);
}

interface RequestOptions {
  method?: Method;
  body?: unknown;
  /** Supplied for the mutations the API requires one on; ignored on reads. */
  idempotencyKey?: string;
  signal?: AbortSignal;
  /**
   * Bypass every HTTP cache for this request. The API already answers everything with
   * `Cache-Control: no-store`; a read whose answer *decides* something -- whether a session
   * is still live -- says so from this side as well, so that no intermediary's idea of a
   * cached `200` can stand in for the server's verdict.
   */
  fresh?: boolean;
  /**
   * The workspace the page or action making this request began under, carried as
   * {@link WORKSPACE_HEADER}. Every workspace mutation sends it; the database compares it
   * with the workspace the session is bound to, under the workspace lock, and refuses a
   * mismatch before anything is written, so a page loaded for one workspace can never apply
   * its action to another that a different tab has since selected.
   */
  workspace?: string;
}

/** The header every workspace mutation carries: the workspace its page or action began under. */
export const WORKSPACE_HEADER = "X-Workspace-Id";

/**
 * Refuse anything that is not an absolute path under `/v1`.
 *
 * Two holes this closes. A caller that interpolated an identifier into a path could produce
 * `//evil.example/v1/...`, which `fetch` treats as protocol-relative and sends **to another
 * origin, with cookies**. And an absolute URL would do the same thing more obviously. The
 * client has no legitimate reason to address anything but this origin's `/v1`, so the rule
 * is stated once here rather than trusted at every call site.
 */
export function assertSameOriginPath(path: string): void {
  const acceptable =
    typeof path === "string" &&
    path.startsWith("/v1/") &&
    !path.startsWith("//") &&
    !path.includes("\\") &&
    // biome-ignore lint/suspicious/noControlCharactersInRegex: refusing them is the point.
    !/[\u0000-\u0020\u007f]/.test(path);
  if (!acceptable) {
    throw new ApiError(0, "invalid_request", "client");
  }
}

function encodeBody(body: unknown): string {
  const serialised = JSON.stringify(body ?? {});
  if (new TextEncoder().encode(serialised).length > MAX_BODY_BYTES) {
    throw new ApiError(413, "request_too_large", "client");
  }
  return serialised;
}

async function readError(response: Response): Promise<never> {
  let code = "internal_error";
  try {
    const parsed: unknown = await response.json();
    if (parsed && typeof parsed === "object" && "error" in parsed) {
      const value = (parsed as { error: unknown }).error;
      if (typeof value === "string") code = value;
    }
  } catch {
    // A refusal whose body is not JSON is still a refusal. The status is what matters, and
    // the body is deliberately not read as text -- doing so is how server output reaches a
    // page.
  }
  throw new ApiError(response.status, code);
}

/** The headers a mutation carries, and its encoded body. */
function prepareMutation(
  method: Method,
  path: string,
  headers: Headers,
  options: RequestOptions,
): string {
  if (requiresCsrf(method, path)) {
    const csrf = readCsrfToken();
    if (csrf === null) {
      // A cookie-authenticated mutation with no session cookie behind it. Refused here
      // rather than sent: the server would refuse it, and this way the caller gets the
      // honest reason instead of a round trip. Marked as the client's own refusal,
      // because it is one: no server has said anything about this session.
      throw new ApiError(401, "authentication_required", "client");
    }
    headers.set(CSRF_HEADER, csrf);
  }
  headers.set("Content-Type", "application/json");
  if (options.idempotencyKey !== undefined) {
    headers.set(IDEMPOTENCY_HEADER, options.idempotencyKey);
  }
  return encodeBody(options.body);
}

/**
 * One request. Resolves with the parsed body, or `null` for `204`; throws {@link ApiError}.
 */
export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  assertSameOriginPath(path);
  const method = options.method ?? "GET";
  const mutation = method !== "GET";
  const headers = new Headers();
  const init: RequestInit = {
    method,
    // The session cookie must ride along. Same-origin, so this is not a CORS decision.
    credentials: "same-origin",
    headers,
    // No `Accept` header is sent: the API answers JSON on every route, and a refusal whose
    // body is not JSON is handled below, so there is nothing to negotiate. What a caller may
    // add is a deadline or its operation's abort, through `signal`, and `no-store` for a
    // read that must reach the server rather than a cache.
    ...(options.signal ? { signal: options.signal } : {}),
    ...(options.fresh ? { cache: "no-store" as const } : {}),
  };

  if (mutation) init.body = prepareMutation(method, path, headers, options);
  if (options.workspace !== undefined) {
    headers.set(WORKSPACE_HEADER, options.workspace);
  }

  let response: Response;
  try {
    response = await fetch(path, init);
  } catch {
    // A dropped connection, a refused socket, a timed-out or aborted request. Never the
    // exception's own text, which on some engines names the URL. The server's state is
    // unknown -- the request may or may not have arrived -- and `isTransient` says so.
    throw new ApiError(0, "network_error", "client");
  }

  if (!response.ok) await readError(response);
  if (response.status === 204) return null as T;
  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError(response.status, "internal_error", "client");
  }
}

/** The reason a request was abandoned because its deadline passed. */
export function timeoutReason(): DOMException {
  return new DOMException("The request did not answer before its deadline.", "TimeoutError");
}

/**
 * Run one request under a deadline, inside an outer operation's signal when there is one.
 *
 * A request that never answers would leave the customer looking at a "Working…" button
 * with no way to know where they stand. The deadline turns silence into a transport failure
 * the page can report. Two ways to abort, one signal: the timer fires, or the `upstream`
 * signal -- the operation this request belongs to -- is aborted because the operation is
 * obsolete. Either way `fetch` rejects promptly and {@link request} maps it to a transient
 * `ApiError`, so the caller sees one failure shape and decides from its own state, not from
 * the abort's reason.
 *
 * Everything armed here is released in `finally`, whichever way the request settles: the
 * timer is cleared so it cannot fire into a later operation, and the upstream listener is
 * removed so a long-lived signal does not accumulate one closure per request.
 */
export async function withDeadline<T>(
  milliseconds: number,
  upstream: AbortSignal | undefined,
  run: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  const follow = () => controller.abort(upstream?.reason);
  if (upstream?.aborted) {
    follow();
  } else {
    upstream?.addEventListener("abort", follow, { once: true });
  }
  const timer = setTimeout(() => controller.abort(timeoutReason()), milliseconds);
  try {
    return await run(controller.signal);
  } finally {
    clearTimeout(timer);
    upstream?.removeEventListener("abort", follow);
  }
}

/**
 * A retry key for one mutation, from the platform's CSPRNG.
 *
 * The API requires one on workspace creation, rename, invitation and credential issuance and
 * rotation, and refuses reuse for a *different* request. Generated per attempt so a retry the
 * customer initiates is a new request rather than a replay of a different one -- the portal
 * does not silently re-send anything, so a key is never reused across two distinct bodies.
 */
export function retryKey(prefix: string): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${prefix}-${hex}`;
}
