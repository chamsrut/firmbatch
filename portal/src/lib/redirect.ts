/**
 * Where a "come back here after signing in" link is allowed to go.
 *
 * The portal remembers the page a signed-out visitor was trying to reach and returns them to
 * it after login, which means a URL carries a destination -- and a destination that came
 * from a URL is the classic open-redirect hole: `?next=https://evil.example` on a genuine
 * Firmbatch login page is a phishing page with a real address bar.
 *
 * The rule here is a **whitelist of shapes, not a blacklist of tricks**. A value is accepted
 * only when it is a path this application actually serves; everything else becomes the
 * default. There is no attempt to "clean" a hostile value, because sanitising a redirect is
 * a game of finding the encoding somebody has not thought of -- `//evil`, `/\evil`,
 * `https:/\evil`, `%2f%2fevil`, a backslash Windows treats as a separator, a `\t` that
 * `new URL` strips -- and one miss is the whole hole.
 */

/** Where a visitor goes when no safe destination was named. */
export const DEFAULT_DESTINATION = "/";

/** A throwaway origin to resolve against. A destination is local if it stays here. */
const BASE = "https://portal.invalid";

/**
 * The syntactic half of the rule: is this string shaped like one of this application's
 * paths? Applied to the caller's string before parsing, and again to the rebuilt string
 * after it, because the parser can produce a shape the caller's string did not have.
 */
function hasLocalShape(value: string): boolean {
  // Control characters and the space, including the tab, newline and carriage return
  // that URL parsers strip *before* parsing -- which is what makes "/\u0009evil" and
  // "/\u000a/evil" dangerous: the checks below would see a leading "/" and the parser
  // would then see something else entirely.
  // biome-ignore lint/suspicious/noControlCharactersInRegex: refusing them is the point.
  if (/[\u0000-\u0020\u007f]/.test(value)) return false;
  if (value.includes("\\")) return false;
  if (!value.startsWith("/")) return false;
  if (value.startsWith("//")) return false;
  return true;
}

/**
 * A safe in-application destination, or the default.
 *
 * Accepted only if, after rejecting every control character:
 *   - it begins with exactly one `/` (so `//host` and `///host` are out -- both are
 *     protocol-relative URLs a browser sends to another origin);
 *   - the second character is not `/` or `\` (a backslash is a separator to some parsers,
 *     which is how `/\evil.example` becomes an off-site redirect);
 *   - it contains no `\`, no `:` before the first `/`... which is to say it contains no
 *     scheme, because a leading `/` already forbids one;
 *   - it resolves, against a throwaway base, to a URL whose origin is that base;
 *   - and the destination **rebuilt from the parsed parts** passes the same checks again
 *     and resolves to the same place.
 *
 * The parser check is the belt to the syntactic checks' braces: it hands the string to the
 * same parser the browser uses and asks whether the result is still local. The last check
 * is what makes the belt hold. The parser normalises dot segments, and `/..//evil.example`,
 * `/.//evil.example` and `/a/..//evil.example` -- one leading slash, so paths by the first
 * rule, and local by the parser's own account -- each normalise to a pathname of
 * `//evil.example`, which is protocol-relative and which a browser handed it would send
 * off-site. What is returned is therefore never the caller's string and never an unchecked
 * pathname: it is the rebuilt destination, in the form it will be navigated to, and only if
 * that form passes every check as well.
 */
export function safeDestination(
  candidate: string | null | undefined,
  fallback: string = DEFAULT_DESTINATION,
): string {
  if (typeof candidate !== "string" || candidate === "") return fallback;
  if (!hasLocalShape(candidate)) return fallback;

  let resolved: URL;
  try {
    resolved = new URL(candidate, BASE);
  } catch {
    return fallback;
  }
  if (resolved.origin !== BASE) return fallback;

  // Rebuild from the parsed parts rather than returning the caller's string, so what is
  // navigated to is exactly what was checked -- and check *that*, because normalisation
  // can turn a path into a protocol-relative URL the checks above never saw.
  const rebuilt = `${resolved.pathname}${resolved.search}${resolved.hash}`;
  if (!hasLocalShape(rebuilt)) return fallback;
  let reparsed: URL;
  try {
    reparsed = new URL(rebuilt, BASE);
  } catch {
    return fallback;
  }
  const stable =
    reparsed.origin === BASE &&
    reparsed.pathname === resolved.pathname &&
    reparsed.search === resolved.search &&
    reparsed.hash === resolved.hash;
  return stable ? rebuilt : fallback;
}

/**
 * The destination carried by a location's `next` parameter, checked.
 *
 * Kept separate from {@link safeDestination} so that the place a destination is *read from*
 * and the rule for what is acceptable are not the same function -- a caller that reads the
 * parameter some other way still goes through the same check.
 */
export function destinationFromSearch(search: string, fallback = DEFAULT_DESTINATION): string {
  let params: URLSearchParams;
  try {
    params = new URLSearchParams(search);
  } catch {
    return fallback;
  }
  return safeDestination(params.get("next"), fallback);
}

/** A `next=` query string for one destination, or an empty string when it is the default. */
export function destinationQuery(destination: string): string {
  const safe = safeDestination(destination);
  if (safe === DEFAULT_DESTINATION) return "";
  return `?next=${encodeURIComponent(safe)}`;
}
