/**
 * Reading the CSRF secret the API set, and the reason it lives in a cookie at all.
 *
 * `open_browser_session` mints the CSRF secret once and stores only its SHA-256 fingerprint,
 * so the plaintext exists in exactly one place: the login response. A portal that kept it in
 * a variable would lose it on every reload -- and nothing can re-issue it, because a
 * fingerprint is one-way -- leaving a signed-in customer able to read every page and change
 * nothing until they signed in again. Milestone 3.2 closes that by having the API set the
 * same secret as a readable, host-only, `SameSite=Strict` cookie with the session's own
 * lifetime.
 *
 * **This cookie is not a credential.** The session cookie beside it is `HttpOnly` and is the
 * only thing that authenticates. Holding the CSRF secret alone authenticates nobody, and the
 * API never compares the cookie against the header: the header is checked *inside
 * PostgreSQL* against the session's stored fingerprint, so a caller must produce the
 * session's actual secret rather than echo a value it set on both sides itself.
 *
 * Read fresh on every mutation, never cached in a module variable. Another tab that signed
 * in, a password change that replaced the session, or a logout, all rewrite this cookie, and
 * a cached copy would be exactly the stale value that produces a confusing refusal.
 */

/** The unprefixed name, used when the cookie is not `Secure` (development over plain http). */
export const CSRF_COOKIE_NAME = "fb_csrf";

/**
 * The `__Host-` prefixed name, used wherever the cookie is `Secure`.
 *
 * The prefix is a promise the *browser* enforces: set over HTTPS, `Path=/`, and no `Domain`
 * attribute, so no sibling host can set or shadow it. The API chooses which name to send
 * from whether the cookie is `Secure`; the portal reads whichever is present, preferring the
 * prefixed one, because it cannot know the deployment's scheme and should not have a setting
 * that could disagree with the server.
 */
export const CSRF_COOKIE_HOST_NAME = `__Host-${CSRF_COOKIE_NAME}`;

/** Every cookie on this document, as name/value pairs. Values stay percent-encoded here. */
function cookiePairs(source: string): Array<[string, string]> {
  const pairs: Array<[string, string]> = [];
  for (const entry of source.split(";")) {
    const separator = entry.indexOf("=");
    if (separator < 1) continue;
    const name = entry.slice(0, separator).trim();
    const value = entry.slice(separator + 1).trim();
    if (name) pairs.push([name, value]);
  }
  return pairs;
}

/**
 * The CSRF secret this document holds, or `null`.
 *
 * The prefixed name wins when both are present. That is not arbitrary: a `__Host-` cookie
 * can only have been set by this exact host over HTTPS, while an unprefixed one of the same
 * name could have been set by a sibling subdomain, so preferring the prefixed value means a
 * cookie-tossing attempt cannot displace the real secret -- it can only add a value that is
 * ignored. A tossed value could not be used to forge anything in any case, because the
 * database compares the header against the session's own fingerprint, but the wrong value
 * would produce a refusal that looked like an expired session, and this avoids it.
 */
export function readCsrfToken(source: string = document.cookie): string | null {
  const pairs = cookiePairs(source);
  const prefixed = pairs.find(([name]) => name === CSRF_COOKIE_HOST_NAME);
  const plain = pairs.find(([name]) => name === CSRF_COOKIE_NAME);
  const raw = (prefixed ?? plain)?.[1];
  if (raw === undefined || raw === "") return null;
  try {
    return decodeURIComponent(raw);
  } catch {
    // A malformed percent-encoding is not a token. Treat it as absent rather than passing
    // the raw bytes to the server, which would produce a refusal that is harder to read.
    return null;
  }
}
