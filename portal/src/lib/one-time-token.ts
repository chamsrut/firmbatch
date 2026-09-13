/**
 * One-time tokens from emailed links: captured once, taken out of the URL, held in memory.
 *
 * Verification, recovery and invitation links carry a secret in the query string, which is
 * the one place this design cannot avoid putting one -- an emailed link has nowhere else to
 * carry it. What happens next has to satisfy four rules at once, and a React effect that
 * read the URL and scrubbed it in the same tick satisfied none of them under StrictMode,
 * which replays every effect on mount: the second run found an already-scrubbed URL and
 * forgot the token.
 *
 * 1. **Captured once.** The first thing the application does on a token route is move the
 *    token from the URL into this module. A second capture -- StrictMode's replayed
 *    initializer, a second render, a later effect -- finds nothing in the URL and leaves the
 *    held value alone.
 * 2. **Scrubbed promptly.** The history entry carrying the secret is *replaced* by the same
 *    path without it, so the token is not in the address bar, in the back-button history, or
 *    in a `Referer` header on the next navigation. Other query parameters survive.
 * 3. **Submitted at most once at a time.** {@link submitOnce} joins a submission already in
 *    flight rather than starting a second, so a replayed effect cannot spend a one-time token
 *    twice. After a failure the token is still held, so an explicit retry can submit again.
 * 4. **Held only in memory, only for the mounted application.** Never `localStorage`, never
 *    `sessionStorage`, never a cookie, never logged, never put in another URL. A page reload
 *    loses it, by design -- the page then says so and tells the customer to open the link
 *    again -- and {@link releaseToken} forgets it the moment it has been used.
 */

export type TokenFlow = "verification" | "recovery" | "invitation";

/** The routes an emailed link lands on, and the flow each token belongs to. */
const TOKEN_ROUTES: Readonly<Record<string, TokenFlow>> = {
  "/verify-email": "verification",
  "/reset-password": "recovery",
  "/accept-invitation": "invitation",
};

const held = new Map<TokenFlow, string>();
const inFlight = new Map<TokenFlow, Promise<unknown>>();

/**
 * Move a token from the current URL into memory, and scrub the URL. Idempotent: a URL with
 * no token changes nothing, so calling this twice on mount is harmless.
 */
export function captureTokenFromLocation(): void {
  const flow = TOKEN_ROUTES[window.location.pathname];
  if (flow === undefined) return;
  const url = new URL(window.location.href);
  const token = url.searchParams.get("token");
  if (token === null) return;
  held.set(flow, token);
  inFlight.delete(flow);
  url.searchParams.delete("token");
  // replaceState, not pushState: the entry carrying the secret is *replaced*, so the back
  // button cannot return to it.
  window.history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
}

/** The token held for a flow, or `null` when none was captured or it has been used. */
export function heldToken(flow: TokenFlow): string | null {
  return held.get(flow) ?? null;
}

/** Forget a token: it has been used, or the flow it belonged to is over. */
export function releaseToken(flow: TokenFlow): void {
  held.delete(flow);
  inFlight.delete(flow);
}

/**
 * Submit the held token, at most once at a time.
 *
 * Returns `null` when no token is held. Otherwise, if a submission for this flow is already
 * in flight, that same promise is returned -- the caller joins it rather than sending the
 * token again -- and if not, `submit` is called with the token. The in-flight record is
 * cleared when the submission settles, so a **failed** submission can be retried on an
 * explicit action while the token stays held; a **successful** one should be followed by
 * {@link releaseToken}.
 */
export function submitOnce<T>(
  flow: TokenFlow,
  submit: (token: string) => Promise<T>,
): Promise<T> | null {
  const token = held.get(flow);
  if (token === undefined) return null;
  const pending = inFlight.get(flow);
  if (pending !== undefined) return pending as Promise<T>;
  const promise = submit(token).finally(() => {
    if (inFlight.get(flow) === promise) inFlight.delete(flow);
  });
  inFlight.set(flow, promise);
  return promise;
}

/**
 * Forget every held token. For the test harness, which mounts one application per test in
 * one module instance; a real page holds nothing between one document and the next.
 */
export function forgetHeldTokens(): void {
  held.clear();
  inFlight.clear();
}
