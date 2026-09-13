import "@testing-library/jest-dom/vitest";
import { configure } from "@testing-library/dom";
import { afterEach, expect } from "vitest";
import { forgetHeldTokens } from "./src/lib/one-time-token.ts";
import { reads } from "./src/lib/requests.ts";

/**
 * How long an async query waits, and why the default is not enough here.
 *
 * Testing Library's `findBy*` gives up after 1000 ms. That is generous for one file and
 * tight for ten, each of which builds its own jsdom: on a loaded machine -- a CI runner, or a
 * developer running the whole verification script -- creating those environments takes tens
 * of seconds of wall clock, and a `findByRole` that would resolve in 20 ms on an idle box can
 * miss a 1 s window. Reproduced by running the suite alongside six busy processes: one test
 * failed with "Unable to find role=heading", and the same test passes every time on an idle
 * machine.
 *
 * **This changes how long a test waits, not what it asserts.** A genuinely missing element
 * still fails, five seconds later. The alternative -- sprinkling explicit timeouts at the
 * call sites that happened to fail -- would leave the next slowest query to be discovered by
 * a flaky gate, and a flaky gate is worse than no gate.
 */
configure({ asyncUtilTimeout: 5000 });

/**
 * One global guard, applied to every test in the suite: **the portal must not touch
 * `localStorage` or `sessionStorage`.**
 *
 * The rule is not "must not store a secret there" but "must not use them at all", because
 * the weaker rule needs a human to decide, per call site, whether the value being stored is
 * sensitive -- and a session id, an account id, an email address or a workspace id all leak
 * something. A blanket refusal is checkable by a machine, and this is the machine.
 *
 * Both accessors throw here rather than record, so a test that provokes an access fails at
 * the access with a stack trace pointing at the offending line, instead of at an assertion
 * in an unrelated place. `tests/storage.test.ts` additionally scans the source for the
 * identifiers, which catches a call on a path no test happens to walk.
 */
function forbidWebStorage(name: "localStorage" | "sessionStorage"): void {
  Object.defineProperty(window, name, {
    configurable: true,
    get() {
      throw new Error(
        `the portal read or wrote ${name}. Browser storage is not used by this ` +
          "application at all: the session cookie is HttpOnly and the CSRF cookie carries " +
          "the session's own lifetime, so nothing needs to be persisted by script.",
      );
    },
  });
}

forbidWebStorage("localStorage");
forbidWebStorage("sessionStorage");

afterEach(() => {
  // jsdom keeps one document per file, so cookies set by one test would otherwise be
  // visible to the next and a "no cookie" case would silently test the wrong thing.
  for (const entry of document.cookie.split(";")) {
    const name = entry.split("=")[0]?.trim();
    if (name) document.cookie = `${name}=; Max-Age=0; path=/`;
  }
  // The same for a one-time token held in memory, and for the page reads in flight: one
  // module instance serves every test in a file, and a real page holds nothing between one
  // document and the next.
  forgetHeldTokens();
  reads.clear();
});

expect.extend({});
