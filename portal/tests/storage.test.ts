/**
 * Secrets must not reach browser storage, a URL, or a log.
 *
 * Two complementary checks, because neither is sufficient alone.
 *
 * A **source scan** catches a call on a path no test happens to walk, which is the realistic
 * way a `localStorage.setItem` gets added later. It is a blunt instrument and it is meant to
 * be: the rule is "the portal does not use browser storage at all", not "does not store
 * anything sensitive there", because the weaker rule needs a human to judge every call site
 * and a session id, an account id or an email address all leak something.
 *
 * A **runtime guard** (in `vitest.setup.ts`) makes any access throw, so a call that somehow
 * evaded the scan fails the test that provokes it, at the line that made it.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

// Vitest runs from the portal root. `import.meta.url` is rewritten by the jsdom transform and
// does not resolve to a real path here, which is why this is anchored to the working
// directory instead.
const SRC = resolve(process.cwd(), "src");

function sourceFiles(directory: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) {
      found.push(...sourceFiles(path));
    } else if (/\.(ts|tsx)$/.test(entry)) {
      found.push(path);
    }
  }
  return found;
}

/** Every source file, with comments stripped, so a rule is not tripped by prose about it. */
function sourcesWithoutComments(): Array<[string, string]> {
  return sourceFiles(SRC).map((path) => {
    const text = readFileSync(path, "utf8");
    const stripped = text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
    return [path.slice(SRC.length + 1), stripped];
  });
}

describe("browser storage is not used at all", () => {
  it.each(["localStorage", "sessionStorage", "indexedDB"])(
    "no source file references %s",
    (api) => {
      const offenders = sourcesWithoutComments()
        .filter(([, text]) => text.includes(api))
        .map(([name]) => name);
      expect(offenders).toEqual([]);
    },
  );

  it("the runtime guard is armed, so an access would fail loudly", () => {
    expect(() => window.localStorage).toThrow(/localStorage/);
    expect(() => window.sessionStorage).toThrow(/sessionStorage/);
  });
});

describe("nothing is logged", () => {
  it.each(["console.log", "console.error", "console.warn", "console.debug", "console.info"])(
    "no source file calls %s",
    (call) => {
      const offenders = sourcesWithoutComments()
        .filter(([, text]) => text.includes(call))
        .map(([name]) => name);
      expect(offenders).toEqual([]);
    },
  );
});

describe("no HTML is ever injected", () => {
  it.each([
    "dangerouslySetInnerHTML",
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
  ])("no source file uses %s", (api) => {
    const offenders = sourcesWithoutComments()
      .filter(([, text]) => text.includes(api))
      .map(([name]) => name);
    expect(offenders).toEqual([]);
  });

  it("no source file evaluates a string", () => {
    const offenders = sourcesWithoutComments()
      .filter(([, text]) => /\beval\s*\(|new Function\s*\(/.test(text))
      .map(([name]) => name);
    expect(offenders).toEqual([]);
  });
});

describe("the customer boundary", () => {
  /**
   * Roadmap "Internal and supplier surfaces" and target §17 invariant 11: a customer account
   * never reaches supplier capacity, pool identities, bridge budgets, operator settlement,
   * internal routing or certification administration -- and the operator capacity agent is
   * separate operator-side software that is never a customer-portal feature.
   *
   * The strongest version of this test is not a word search; it is that the API this portal
   * calls exposes no such route, and the scope catalogue contains no such scope. But a word
   * search over the source is what catches somebody adding a link to one, so both exist:
   * `control_plane/tests/test_portal_http.py` asserts the API side
   * (`test_the_route_inventory_is_customer_only`).
   */
  it.each([
    "supplier",
    "operator",
    "capacity_agent",
    "capacity-agent",
    "pool_identity",
    "bridge_budget",
    "bridge-budget",
    "settlement",
    "window_offer",
    "window-offer",
    "certification",
    "qualification",
    "provider_reconciliation",
  ])("no route, path or identifier in the portal mentions %s", (term) => {
    const offenders = sourcesWithoutComments()
      .filter(([, text]) => text.toLowerCase().includes(term))
      .map(([name]) => name);
    expect(offenders).toEqual([]);
  });
});
