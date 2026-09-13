/**
 * Turning the API's refusals into something a customer can act on -- and nothing more.
 *
 * The boundary answers every failure with `{"error": <code>}` and no other field: no value,
 * no database text, no identifier the caller did not send. That is deliberate, and this
 * module is the other half of it. A code is looked up in a **closed table** of sentences
 * written for a person; a code that is not in the table becomes a generic sentence, and is
 * never rendered raw. Echoing an unknown code would turn the one field the server does
 * return into an output channel for whatever string a future version put there.
 */

/** The refusal codes this portal understands, mapped to what a person should read. */
const MESSAGES: Readonly<Record<string, string>> = {
  authentication_required: "Your session has ended. Sign in again to continue.",
  invalid_credentials: "That email address and password do not match an account.",
  email_verification_required:
    "Confirm your email address before signing in. Check your inbox for the link.",
  invalid_token: "That link is no longer valid. Links expire, and each one works once.",
  workspace_required: "Choose a workspace before opening that page.",
  workspace_mismatch:
    "This page was loaded for a different workspace than the one this session now has selected. Nothing was saved. Reload to continue with the current workspace.",
  session_context_required: "Your session needs to be re-established. Sign in again.",
  origin_not_allowed: "This page was not served from an address the API accepts.",
  csrf_token_required: "This page could not prove the request came from you. Reload and retry.",
  forbidden: "Your role in this workspace does not allow that.",
  not_found: "That is not here, or is not yours to see.",
  conflict: "That conflicts with the current state. Reload to see where things stand.",
  idempotency_key_reuse: "That request was already made with different details. Start again.",
  idempotency_key_required: "This request needs a retry key. Reload and try once more.",
  invalid_request: "Some of what was sent is not acceptable. Check the fields and retry.",
  invalid_json: "The request body was malformed.",
  unsupported_media_type: "The request body was not JSON.",
  request_too_large: "That request is larger than this service accepts.",
  service_unavailable: "The service is briefly at capacity. Try again in a moment.",
  internal_error: "Something went wrong at our end. Nothing was changed.",
  network_error: "The service could not be reached. Check your connection and retry.",
};

const GENERIC = "That did not work. Nothing was changed.";

/**
 * Where a refusal came from. The **server** answered, and its status is the server's
 * verdict; or the **client** refused before anything was sent -- no CSRF cookie to prove
 * the request with, a path that is not this origin's, a body over the limit, a connection
 * that dropped -- and the status is the nearest description, not a verdict about the
 * session. Recorded so a caller can tell the two apart; a sign-out, in particular, decides
 * nothing from either -- it asks the server, once (ADR 0010, decision 9).
 */
export type ErrorOrigin = "server" | "client";

/** One refusal from the API, carrying its status and its code and never its internals. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly origin: ErrorOrigin;

  constructor(status: number, code: string, origin: ErrorOrigin = "server") {
    super(messageForCode(code));
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.origin = origin;
  }

  /** The session is gone, refused, or expired: the caller must sign in again. */
  get isUnauthenticated(): boolean {
    return this.status === 401;
  }

  /** The session is fine but has selected no workspace, and this route needs one. */
  get needsWorkspace(): boolean {
    return this.status === 412;
  }

  /** Authenticated, and not allowed. A demotion that happened while the page was open. */
  get isForbidden(): boolean {
    return this.status === 403;
  }

  /**
   * The workspace this page was loaded for is not the one the session is bound to now:
   * another tab switched it. Nothing was saved; the page reloads for the current one.
   */
  get isWorkspaceMismatch(): boolean {
    return this.status === 409 && this.code === "workspace_mismatch";
  }

  /**
   * The request never reached a verdict: a dropped connection, a timeout, a `5xx`. The
   * state on the server is unknown, so the caller must not assume the action happened --
   * and must not assume it did not.
   */
  get isTransient(): boolean {
    return this.status === 0 || this.status >= 500;
  }
}

/**
 * The sentence for one code. Unknown codes get the generic sentence.
 *
 * A code is server-supplied text. It is looked up, never interpolated, so a value outside
 * the table cannot reach the page -- which is what stops the error path from becoming a way
 * to render arbitrary content.
 */
export function messageForCode(code: string): string {
  return Object.hasOwn(MESSAGES, code) ? (MESSAGES[code] as string) : GENERIC;
}

/** Whether the portal has a written sentence for this code, for tests and for triage. */
export function isKnownErrorCode(code: string): boolean {
  return Object.hasOwn(MESSAGES, code);
}
