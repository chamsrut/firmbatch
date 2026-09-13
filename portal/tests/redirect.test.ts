/**
 * Open-redirect refusals.
 *
 * The `next` parameter is the one place a URL decides where a signed-in customer lands, so
 * this is the table of everything that must **not** be honoured. Each case is a real
 * technique rather than a variation for its own sake: protocol-relative URLs, backslash
 * separators some parsers treat as slashes, the whitespace characters URL parsers strip
 * before parsing, schemes, encoded forms of all of them, and dot segments whose
 * normalisation turns a path into a protocol-relative URL.
 */

import { describe, expect, it } from "vitest";
import {
  DEFAULT_DESTINATION,
  destinationFromSearch,
  destinationQuery,
  safeDestination,
} from "../src/lib/redirect.ts";

const HOSTILE: ReadonlyArray<[string, string]> = [
  ["//evil.example", "protocol-relative: a browser sends this off-site"],
  ["///evil.example", "three slashes, same thing"],
  ["////evil.example/path", "four slashes"],
  ["https://evil.example", "an absolute URL"],
  ["http://evil.example", "an absolute URL, plain"],
  ["//evil.example/settings/team", "protocol-relative with a plausible path"],
  ["/\\evil.example", "backslash after the slash"],
  ["\\\\evil.example", "two backslashes, a UNC-looking path"],
  ["/\\/evil.example", "mixed separators"],
  ["javascript:alert(1)", "a scheme that is not navigation at all"],
  ["JavaScript:alert(1)", "the same, cased to defeat a lower-case check"],
  ["data:text/html,<script>", "a data URL"],
  ["\tjavascript:alert(1)", "a tab the URL parser strips before parsing"],
  ["\n/\n/evil.example", "newlines the URL parser strips"],
  ["\r//evil.example", "a carriage return"],
  [" //evil.example", "a leading space"],
  ["/\u0000/evil", "a null byte"],
  ["evil.example", "a bare host, no leading slash"],
  ["settings/team", "a relative path"],
  ["", "empty"],
  ["https:/\\evil.example", "scheme with mixed separators"],
  ["//user:pass@evil.example", "credentials in the authority"],
  // Dot-segment normalisation. Each of these begins with exactly one "/", and the URL parser
  // resolves it against the portal's own origin -- and then reports a pathname of
  // "//evil.example", which is protocol-relative, and which a browser handed it sends
  // off-site. The syntactic checks see the caller's string; the parser rebuilds another.
  ["/..//evil.example", "a dot-segment climb that normalises to a protocol-relative URL"],
  ["/.//evil.example", "a single-dot segment that normalises to a protocol-relative URL"],
  ["/a/..//evil.example", "a climb out of a real-looking segment, the same"],
  ["/%2e%2e//evil.example", "the climb percent-encoded, which the parser still resolves"],
  ["/.%2E//evil.example", "the climb half-encoded"],
  ["/a/../..//evil.example", "two climbs, past the root"],
  ["/..//evil.example?next=1#top", "the climb with a query and a fragment"],
];

/** The three cases the final review named, kept separately so each is asserted by name. */
const NORMALISES_OFF_SITE: ReadonlyArray<string> = [
  "/..//evil.example",
  "/.//evil.example",
  "/a/..//evil.example",
];

const SAFE: ReadonlyArray<string> = [
  "/",
  "/settings/team",
  "/settings/credentials",
  "/account/security",
  "/workspaces/new",
  "/jobs?filter=open",
  "/results#section",
  "/settings/team?tab=invitations#top",
];

describe("safeDestination", () => {
  it.each(HOSTILE)("refuses %j (%s)", (candidate) => {
    expect(safeDestination(candidate)).toBe(DEFAULT_DESTINATION);
  });

  it.each(SAFE)("accepts the in-application path %j", (candidate) => {
    expect(safeDestination(candidate)).toBe(candidate);
  });

  it("refuses a non-string", () => {
    expect(safeDestination(null)).toBe(DEFAULT_DESTINATION);
    expect(safeDestination(undefined)).toBe(DEFAULT_DESTINATION);
  });

  it("honours a caller-supplied fallback", () => {
    expect(safeDestination("//evil.example", "/workspaces")).toBe("/workspaces");
  });

  it("returns the reparsed path, not the caller's string", () => {
    // What is navigated to must be what was checked. A value that normalises differently
    // when parsed must come back in its parsed form, or the check applied to one string and
    // the navigation used another.
    expect(safeDestination("/settings/../account")).toBe("/account");
    expect(safeDestination("/a/../../b")).toBe("/b");
  });
});

describe("the rebuilt destination is checked again", () => {
  it.each(NORMALISES_OFF_SITE)("%j normalises to //evil.example and is refused", (candidate) => {
    // The premise, stated so the test is about the parser this code relies on: the WHATWG
    // parser resolves the candidate against the portal's origin and calls it local, and the
    // pathname it rebuilds is protocol-relative -- resolved on its own, it names evil.example.
    const parsed = new URL(candidate, "https://portal.invalid");
    expect(parsed.origin).toBe("https://portal.invalid");
    expect(parsed.pathname).toBe("//evil.example");
    expect(new URL(parsed.pathname, "https://portal.invalid").origin).toBe("https://evil.example");
    // The rule: the rebuilt form is checked as the caller's string was, and it fails.
    expect(safeDestination(candidate)).toBe(DEFAULT_DESTINATION);
    expect(safeDestination(candidate, "/workspaces")).toBe("/workspaces");
  });

  it.each(HOSTILE)("never returns a protocol-relative or off-origin string for %j", (candidate) => {
    const result = safeDestination(candidate);
    expect(result.startsWith("/")).toBe(true);
    expect(result.startsWith("//")).toBe(false);
    expect(new URL(result, "https://portal.invalid").origin).toBe("https://portal.invalid");
  });

  it.each(SAFE)("returns %j in a form that passes the same check again", (candidate) => {
    const result = safeDestination(candidate);
    expect(safeDestination(result)).toBe(result);
    expect(new URL(result, "https://portal.invalid").origin).toBe("https://portal.invalid");
  });
});

describe("destinationFromSearch", () => {
  it("reads a safe next parameter", () => {
    expect(destinationFromSearch("?next=%2Fsettings%2Fteam")).toBe("/settings/team");
  });

  it.each(HOSTILE)("refuses next=%j", (candidate) => {
    const search = `?next=${encodeURIComponent(candidate)}`;
    expect(destinationFromSearch(search)).toBe(DEFAULT_DESTINATION);
  });

  it("refuses a doubly encoded protocol-relative URL", () => {
    // %252F decodes to %2F, which decodes to /. A single decode leaves "%2F%2Fevil.example",
    // which is not a path and is refused; the point is that neither depth is honoured.
    expect(destinationFromSearch("?next=%252F%252Fevil.example")).toBe(DEFAULT_DESTINATION);
  });

  it("falls back when there is no parameter at all", () => {
    expect(destinationFromSearch("")).toBe(DEFAULT_DESTINATION);
    expect(destinationFromSearch("?other=1")).toBe(DEFAULT_DESTINATION);
  });
});

describe("destinationQuery", () => {
  it("is empty for the default destination, so a clean sign-in URL stays clean", () => {
    expect(destinationQuery("/")).toBe("");
  });

  it("encodes a safe destination", () => {
    expect(destinationQuery("/settings/team")).toBe("?next=%2Fsettings%2Fteam");
  });

  it("drops a hostile destination rather than encoding it", () => {
    expect(destinationQuery("//evil.example")).toBe("");
  });

  it.each(NORMALISES_OFF_SITE)(
    "drops %j, which normalises off-site, rather than encoding it",
    (candidate) => {
      expect(destinationQuery(candidate)).toBe("");
    },
  );

  it("round-trips a safe climb in its rebuilt form", () => {
    expect(destinationQuery("/settings/../account")).toBe("?next=%2Faccount");
    expect(destinationFromSearch(destinationQuery("/settings/../account"))).toBe("/account");
  });
});
