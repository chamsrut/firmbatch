/**
 * The authentication journeys, driven through the real components.
 *
 * What these assert beyond "the form works": that the portal does not undo the API's
 * neutrality (the same confirmation for a known and an unknown address), that a one-time
 * token is taken out of the URL the moment it is read, that an unsafe `next` is not honoured
 * after a successful sign-in, and that a session which ends mid-page produces a sign-in
 * prompt rather than a broken screen.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { StrictMode, useEffect } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App.tsx";
import { LOGOUT_TIMEOUT_MS, SESSION_CHECK_TIMEOUT_MS } from "../src/api/endpoints.ts";
import { ApiError } from "../src/api/errors.ts";
import { type SessionApi, SessionProvider, useSession } from "../src/auth/session.tsx";
import { Link, RouterProvider, useRouter } from "../src/lib/router.tsx";
import {
  ACCOUNT_ID,
  CSRF_COOKIE,
  CSRF_VALUE,
  type Deferred,
  deferred,
  FakeApi,
  jar,
  json,
  MEMBERSHIP_ID,
  membershipList,
  noContent,
  OTHER_WORKSPACE_ID,
  profile,
  type RecordedRequest,
  refusal,
  renderPortal,
  renderWithProviders,
  SESSION_COOKIE,
  SESSION_ID,
  signedIn,
  signedOut,
  WORKSPACE_ID,
  workspaceDetail,
} from "./harness.tsx";

let api: FakeApi;

/** Hands the live session context to a test, for driving the provider directly. */
function Probe({ expose }: { expose: (session: SessionApi) => void }) {
  const session = useSession();
  useEffect(() => {
    expose(session);
  }, [session, expose]);
  return null;
}

// Vitest runs from the portal root; `import.meta.url` is rewritten by the jsdom transform.
const SRC = resolve(process.cwd(), "src");

function sourceFiles(directory: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) found.push(...sourceFiles(path));
    else if (/\.(ts|tsx)$/.test(entry)) found.push(path);
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

/** The names of the sources whose text offends. */
function namesWhere(sources: Array<[string, string]>, offends: (text: string) => boolean) {
  return sources.filter(([, text]) => offends(text)).map(([name]) => name);
}

/** A `reconcile(` call whose first argument is not the lease the request was made under. */
function reconcilesWithoutLease(text: string): boolean {
  return [...text.matchAll(/reconcile\(\s*([^,)]*)/g)].some(
    (m) => !/^(ticket\.)?lease$/.test(m[1]?.trim() ?? ""),
  );
}

beforeEach(() => {
  api = new FakeApi();
  window.history.replaceState(null, "", "/");
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("signing up", () => {
  it("confirms in the same words whether or not the address has an account", async () => {
    // The API answers 202 for both, so that the boundary is not an oracle for who has an
    // account. A portal that distinguished them would hand that oracle straight back.
    signedOut(api, "/signup");
    api.on("POST /v1/account/signup", () => json({ status: "accepted" }, 202));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /create an account/i });
    await userEvent.type(screen.getByLabelText(/email address/i), "new@example.com");
    await userEvent.type(screen.getByLabelText(/^password/i), "correct horse battery staple");
    await userEvent.type(
      screen.getByLabelText(/confirm password/i),
      "correct horse battery staple",
    );
    await userEvent.click(screen.getByRole("button", { name: /create account/i }));

    const confirmation = await screen.findByRole("heading", { name: /check your email/i });
    expect(confirmation).toBeInTheDocument();
    expect(screen.getByText(/new@example.com/)).toBeInTheDocument();
    // Nothing on the page says whether the address was already registered.
    expect(screen.queryByText(/already/i)).not.toBeInTheDocument();
  });

  it("refuses a mismatched confirmation before sending anything", async () => {
    signedOut(api, "/signup");
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /create an account/i });
    await userEvent.type(screen.getByLabelText(/email address/i), "new@example.com");
    await userEvent.type(screen.getByLabelText(/^password/i), "correct horse battery staple");
    await userEvent.type(screen.getByLabelText(/confirm password/i), "something else entirely");
    await userEvent.click(screen.getByRole("button", { name: /create account/i }));

    expect(await screen.findByText(/do not match/i)).toBeInTheDocument();
    expect(api.to("POST", "/v1/account/signup")).toHaveLength(0);
  });
});

describe("confirming an email address", () => {
  it("consumes the token and removes it from the URL", async () => {
    signedOut(api, "/verify-email?token=fbv_ONETIMETOKENnotarealsecret000000000000");
    api.on("POST /v1/account/verification/complete", () => json({ verified: true }));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /address confirmed/i });
    // The secret is out of the address bar, and out of the back-button history: the entry
    // was replaced, not pushed.
    expect(window.location.search).toBe("");
    expect(window.location.href).not.toContain("fbv_");
  });

  it("offers a new link when the token is spent, without saying whose it was", async () => {
    signedOut(api, "/verify-email?token=fbv_SPENTTOKENnotarealsecret0000000000000000");
    api.on("POST /v1/account/verification/complete", () => refusal(400, "invalid_token"));
    api.install();
    renderPortal();

    expect(await screen.findByText(/no longer valid/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /send a new link/i })).toBeInTheDocument();
    expect(window.location.search).toBe("");
  });
});

describe("signing in", () => {
  it("signs in and lands on the overview", async () => {
    signedOut(api, "/login");
    api.on("POST /v1/account/login", () => {
      jar.set(SESSION_COOKIE, "fbs_NEWSESSIONnotarealsecret0000000000000000");
      jar.set(CSRF_COOKIE, CSRF_VALUE);
      api
        .reply("GET /v1/account", profile())
        .reply("GET /v1/account/workspaces", membershipList())
        .reply("GET /v1/workspace", workspaceDetail());
      return json({
        account_id: "x",
        session_id: SESSION_ID,
        csrf_token: CSRF_VALUE,
        expires_at: null,
      });
    });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /^sign in$/i });
    await userEvent.type(screen.getByLabelText(/email address/i), "person@example.com");
    await userEvent.type(screen.getByLabelText(/password/i), "correct horse battery staple");
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    expect(await screen.findByRole("heading", { name: /overview/i })).toBeInTheDocument();
  });

  it("refuses a wrong password without naming which field was wrong", async () => {
    signedOut(api, "/login");
    api.on("POST /v1/account/login", () => refusal(401, "invalid_credentials"));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /^sign in$/i });
    await userEvent.type(screen.getByLabelText(/email address/i), "person@example.com");
    await userEvent.type(screen.getByLabelText(/password/i), "wrong");
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/do not match an account/i);
    // One sentence about the pair, never "no such account" or "wrong password".
    expect(alert.textContent).not.toMatch(/no such|unknown|does not exist/i);
  });

  it("points an unverified account at a new confirmation link", async () => {
    signedOut(api, "/login");
    api.on("POST /v1/account/login", () => refusal(403, "email_verification_required"));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /^sign in$/i });
    await userEvent.type(screen.getByLabelText(/email address/i), "person@example.com");
    await userEvent.type(screen.getByLabelText(/password/i), "correct horse battery staple");
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/confirm your email/i);
    expect(screen.getByRole("link", { name: /send a new confirmation link/i })).toBeInTheDocument();
  });

  it("does not follow an off-site next parameter after a successful sign-in", async () => {
    signedOut(api, "/login?next=https%3A%2F%2Fevil.example%2Fsteal");
    api.on("POST /v1/account/login", () => {
      jar.set(SESSION_COOKIE, "fbs_NEWSESSIONnotarealsecret0000000000000000");
      jar.set(CSRF_COOKIE, CSRF_VALUE);
      api
        .reply("GET /v1/account", profile())
        .reply("GET /v1/account/workspaces", membershipList())
        .reply("GET /v1/workspace", workspaceDetail());
      return json({
        account_id: "x",
        session_id: SESSION_ID,
        csrf_token: CSRF_VALUE,
        expires_at: null,
      });
    });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /^sign in$/i });
    await userEvent.type(screen.getByLabelText(/email address/i), "person@example.com");
    await userEvent.type(screen.getByLabelText(/password/i), "correct horse battery staple");
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    await screen.findByRole("heading", { name: /overview/i });
    expect(window.location.pathname).toBe("/");
    expect(window.location.href).not.toContain("evil.example");
  });

  it("does not follow a next parameter that normalises to a protocol-relative URL", async () => {
    // "/..//evil.example" begins with one "/" and the URL parser resolves it against this
    // origin; the pathname it rebuilds is "//evil.example", which a browser handed it would
    // send off-site. The destination is checked again in its rebuilt form.
    signedOut(api, "/login?next=%2F..%2F%2Fevil.example");
    api.on("POST /v1/account/login", () => {
      jar.set(SESSION_COOKIE, "fbs_NEWSESSIONnotarealsecret0000000000000000");
      jar.set(CSRF_COOKIE, CSRF_VALUE);
      api
        .reply("GET /v1/account", profile())
        .reply("GET /v1/account/workspaces", membershipList())
        .reply("GET /v1/workspace", workspaceDetail());
      return json({
        account_id: "x",
        session_id: SESSION_ID,
        csrf_token: CSRF_VALUE,
        expires_at: null,
      });
    });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /^sign in$/i });
    await userEvent.type(screen.getByLabelText(/email address/i), "person@example.com");
    await userEvent.type(screen.getByLabelText(/password/i), "correct horse battery staple");
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    await screen.findByRole("heading", { name: /overview/i });
    expect(window.location.pathname).toBe("/");
    expect(window.location.href).not.toContain("evil.example");
    expect(window.location.href.startsWith(window.location.origin)).toBe(true);
  });

  it("honours a safe next parameter", async () => {
    signedOut(api, "/login?next=%2Fsettings%2Fcredentials");
    api.on("POST /v1/account/login", () => {
      jar.set(SESSION_COOKIE, "fbs_NEWSESSIONnotarealsecret0000000000000000");
      jar.set(CSRF_COOKIE, CSRF_VALUE);
      api
        .reply("GET /v1/account", profile())
        .reply("GET /v1/account/workspaces", membershipList())
        .reply("GET /v1/workspace", workspaceDetail())
        .reply("GET /v1/workspace/credentials", { workspace_id: WORKSPACE_ID, credentials: [] });
      return json({
        account_id: "x",
        session_id: SESSION_ID,
        csrf_token: CSRF_VALUE,
        expires_at: null,
      });
    });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /^sign in$/i });
    await userEvent.type(screen.getByLabelText(/email address/i), "person@example.com");
    await userEvent.type(screen.getByLabelText(/password/i), "correct horse battery staple");
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    await waitFor(() => expect(window.location.pathname).toBe("/settings/credentials"));
  });
});

describe("a destination that normalises off-site, at the router", () => {
  /** The three cases the final review named: a path by every syntactic rule, `//evil.example` once parsed. */
  const NORMALISES_OFF_SITE = ["/..//evil.example", "/.//evil.example", "/a/..//evil.example"];

  /** Navigates once, on mount, the way a page's redirect does. */
  function Navigator({ to }: { to: string }) {
    const { navigate, pathname } = useRouter();
    useEffect(() => {
      navigate(to);
    }, [navigate, to]);
    return <p>at {pathname}</p>;
  }

  it.each(NORMALISES_OFF_SITE)("navigates to the default rather than to %j", async (to) => {
    window.history.replaceState(null, "", "/settings/team");
    render(
      <RouterProvider>
        <Navigator to={to} />
      </RouterProvider>,
    );

    await waitFor(() => expect(window.location.pathname).toBe("/"));
    expect(screen.getByText("at /")).toBeInTheDocument();
    expect(window.location.href).toBe(`${window.location.origin}/`);
  });

  it.each(NORMALISES_OFF_SITE)("renders a link to %j as a link to the default", async (to) => {
    window.history.replaceState(null, "", "/settings/team");
    render(
      <RouterProvider>
        <Link to={to}>elsewhere</Link>
      </RouterProvider>,
    );

    // The `href` is what a copied link, a new tab or assistive technology sees: never off-site.
    const link = screen.getByRole("link", { name: "elsewhere" });
    expect(link).toHaveAttribute("href", "/");
    await userEvent.click(link);
    expect(window.location.pathname).toBe("/");
    expect(window.location.href).toBe(`${window.location.origin}/`);
  });
});

describe("recovery", () => {
  it("confirms identically for a known and an unknown address", async () => {
    signedOut(api, "/recover");
    api.on("POST /v1/account/recovery/request", () => json({ status: "accepted" }, 202));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /reset your password/i });
    await userEvent.type(screen.getByLabelText(/email address/i), "unknown@example.com");
    await userEvent.click(screen.getByRole("button", { name: /send a reset link/i }));

    expect(await screen.findByRole("heading", { name: /check your email/i })).toBeInTheDocument();
    expect(screen.getByText(/if/i)).toBeInTheDocument();
  });

  it("shows the same confirmation even when the request itself failed", async () => {
    // A transport failure must not become a signal about the address. Showing an error for
    // one address and a confirmation for another is the oracle the 202 exists to avoid.
    signedOut(api, "/recover");
    api.on("POST /v1/account/recovery/request", () => refusal(503, "service_unavailable"));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /reset your password/i });
    await userEvent.type(screen.getByLabelText(/email address/i), "person@example.com");
    await userEvent.click(screen.getByRole("button", { name: /send a reset link/i }));

    expect(await screen.findByRole("heading", { name: /check your email/i })).toBeInTheDocument();
  });

  it("sets a new password and says every session has ended", async () => {
    signedOut(api, "/reset-password?token=fbr_RECOVERYTOKENnotarealsecret000000000");
    api.on("POST /v1/account/recovery/complete", () => json({ recovered: true }));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /set a new password/i });
    expect(window.location.search).toBe("");

    // The form appears only once the token has been read out of the URL, which is an effect.
    await userEvent.type(
      await screen.findByLabelText(/^new password/i),
      "a new correct horse staple",
    );
    await userEvent.type(
      screen.getByLabelText(/confirm new password/i),
      "a new correct horse staple",
    );
    await userEvent.click(screen.getByRole("button", { name: /set password/i }));

    expect(await screen.findByRole("heading", { name: /password set/i })).toBeInTheDocument();
    expect(
      screen.getByText(/every session that was open under the old one has been ended/i),
    ).toBeInTheDocument();
  });

  it("refuses to submit without the token from the email", async () => {
    signedOut(api, "/reset-password");
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /set a new password/i });
    expect(screen.getByText(/needs the link from your email/i)).toBeInTheDocument();
    expect(screen.queryByLabelText(/^new password/i)).not.toBeInTheDocument();
  });
});

// ------------------------------------------------------ the session and its replacement

const SESSION_B = "77777777-7777-4777-8777-777777777777";
const REPLACEMENT_CSRF = "fbc_REPLACEMENTCSRFnotarealsecret0000000000";
const CURRENT_PASSWORD = "the current password here";
const NEXT_PASSWORD = "a different password entirely";
const realSetTimeout = globalThis.setTimeout.bind(globalThis);

/** Let every promise the portal has in flight run to completion, inside `act`. */
const settle = () => act(() => new Promise<void>((resolve) => realSetTimeout(resolve, 50)));

function logoutThatSucceeds(): void {
  api.on("POST /v1/account/logout", () => {
    // The API clears both cookies on this response.
    jar.clear(SESSION_COOKIE);
    jar.clear(CSRF_COOKIE);
    return noContent();
  });
}

/** From now on the account read answers 401: the server says the session is gone. */
function accountReadsUnauthenticated(): void {
  api.on("GET /v1/account", () => refusal(401, "authentication_required"));
}

/** The replacement session a password change leaves behind: same account, new identity. */
function profileB() {
  return profile({ session: { ...profile().session, session_id: SESSION_B } });
}

/** The security page lists sessions, and renders its own sign-out control for this one. */
function withSessions(): void {
  api.reply("GET /v1/account/sessions", {
    sessions: [
      {
        session_id: SESSION_ID,
        created_at: "2026-09-09T09:00:00+00:00",
        last_seen_at: "2026-09-09T10:00:00+00:00",
        expires_at: "2026-09-09T22:00:00+00:00",
        workspace_id: null,
        current: true,
      },
    ],
  });
}

/**
 * A password change that replaces session A with session B, exactly as the API does: the
 * response carries the new session, both cookies are rewritten, and from then on the
 * account read describes B. Any answer still owed to an operation begun under A is now an
 * answer about a session that no longer exists.
 */
function passwordChangeAdoptsB(): void {
  api.on("POST /v1/account/password", () => {
    jar.set(CSRF_COOKIE, REPLACEMENT_CSRF);
    api.reply("GET /v1/account", profileB());
    return json({
      account_id: ACCOUNT_ID,
      session_id: SESSION_B,
      csrf_token: REPLACEMENT_CSRF,
      expires_at: null,
      other_sessions_revoked: true,
    });
  });
}

/** The direct API, or a `userEvent.setup()` instance wired to a fake clock. */
interface Driver {
  click: (element: Element) => Promise<void>;
  type: (element: Element, text: string) => Promise<void>;
}

async function changePassword(user: Driver = userEvent): Promise<void> {
  await user.type(screen.getByLabelText(/current password/i), CURRENT_PASSWORD);
  await user.type(screen.getByLabelText(/^new password/i), NEXT_PASSWORD);
  await user.type(screen.getByLabelText(/confirm new password/i), NEXT_PASSWORD);
  await user.click(screen.getByRole("button", { name: /change password/i }));
  await screen.findByText(/password changed/i);
}

/**
 * The validity read is the one account read that carries a signal: it is bounded by a
 * deadline and owned by the sign-out operation, and the page's own reads are neither.
 */
function isValidityRead(request: RecordedRequest): boolean {
  return request.signal !== undefined;
}

function validityReads(): RecordedRequest[] {
  return api.to("GET", "/v1/account").filter(isValidityRead);
}

function logouts(): RecordedRequest[] {
  return api.to("POST", "/v1/account/logout");
}

/** Both sign-out controls on the security page, and only those: not "every other session". */
function signOutControls(): HTMLElement[] {
  return screen.getAllByRole("button", { name: /^(sign out|working…)$/i });
}

async function clickSignOut(user: Driver = userEvent): Promise<void> {
  await screen.findByRole("heading", { name: /overview/i });
  await user.click(screen.getByRole("button", { name: /^sign out$/i }));
}

/** Still signed in: same page, same cookies, no sign-in screen, the control ready again. */
function expectStillSignedIn(): void {
  expect(window.location.pathname).toBe("/");
  expect(screen.getByRole("heading", { name: /overview/i })).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: /^sign in$/i })).not.toBeInTheDocument();
  expect(jar.get(CSRF_COOKIE)).toBe(CSRF_VALUE);
  expect(jar.get(SESSION_COOKIE)).not.toBeNull();
  expect(screen.getByRole("button", { name: /^sign out$/i })).toBeEnabled();
}

/** Session B is the one the portal holds: still on the page, its cookie, no sign-in. */
function expectSessionBRetained(): void {
  expect(window.location.pathname).toBe("/account/security");
  expect(screen.getByRole("heading", { level: 1, name: /^security$/i })).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: /^sign in$/i })).not.toBeInTheDocument();
  expect(jar.get(CSRF_COOKIE)).toBe(REPLACEMENT_CSRF);
  for (const control of signOutControls()) expect(control).toBeEnabled();
}

describe("signing out", () => {
  describe("outcomes", () => {
    it("clears local state and returns to sign in after a successful logout, with no validity read", async () => {
      signedIn(api, "/");
      logoutThatSucceeds();
      api.install();
      renderPortal();

      await clickSignOut();
      await waitFor(() => expect(window.location.pathname).toBe("/login"));
      expect(jar.get(CSRF_COOKIE)).toBeNull();
      expect(logouts()).toHaveLength(1);
      // The one account read is the page's own load; a successful logout needs no check.
      expect(api.to("GET", "/v1/account")).toHaveLength(1);
      expect(validityReads()).toHaveLength(0);
    });

    it("takes a 401 from logout as proof of nothing: an expired session is confirmed by one validity read", async () => {
      signedIn(api, "/");
      api.on("POST /v1/account/logout", () => {
        // The session expired underneath the page. The server refuses the logout and, from
        // now on, the account read; it is the read that settles it, not the logout's status.
        accountReadsUnauthenticated();
        return refusal(401, "authentication_required");
      });
      api.install();
      renderPortal();

      await clickSignOut();
      await waitFor(() => expect(window.location.pathname).toBe("/login"));
      expect(logouts()).toHaveLength(1);
      expect(validityReads()).toHaveLength(1);
    });

    it("keeps a live session the server refused to end: 401 from logout, 200 from the read", async () => {
      // The accepted reproduction: a valid session whose CSRF proof does not match gets the
      // neutral 401 from logout, the server deletes no cookie, and the account read still
      // succeeds. Clearing local state on that 401 put a signed-out screen over a live
      // session.
      signedIn(api, "/");
      api.on("POST /v1/account/logout", () => refusal(401, "authentication_required"));
      api.install();
      renderPortal();

      await clickSignOut();
      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent(/you are still signed in/i);
      expect(alert).toHaveTextContent(/refused/i);
      expect(alert.textContent).not.toMatch(/session has ended/i);
      expectStillSignedIn();
      expect(logouts()).toHaveLength(1);
      expect(validityReads()).toHaveLength(1);
    });

    it("signs out when the logout response was lost but the server had revoked the session", async () => {
      signedIn(api, "/");
      api.on("POST /v1/account/logout", () => {
        // The request arrived and the server revoked the session; then the response was lost.
        accountReadsUnauthenticated();
        throw new TypeError("Failed to fetch");
      });
      api.install();
      renderPortal();

      await clickSignOut();
      await waitFor(() => expect(window.location.pathname).toBe("/login"));
      expect(logouts()).toHaveLength(1);
      expect(validityReads()).toHaveLength(1);
    });

    it("keeps the session and says it could not be checked when the validity read fails in transport", async () => {
      signedIn(api, "/");
      api.on("POST /v1/account/logout", () => {
        api.on("GET /v1/account", () => {
          throw new TypeError("Failed to fetch");
        });
        return refusal(500, "internal_error");
      });
      api.install();
      renderPortal();

      await clickSignOut();
      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent(/could not be checked/i);
      expect(alert).toHaveTextContent(/treat yourself as signed in/i);
      expectStillSignedIn();
      expect(logouts()).toHaveLength(1);
      expect(validityReads()).toHaveLength(1);
    });

    it("keeps the session and says it could not be checked when the validity read is a 5xx", async () => {
      signedIn(api, "/");
      api.on("POST /v1/account/logout", () => {
        api.on("GET /v1/account", () => refusal(503, "service_unavailable"));
        return refusal(500, "internal_error");
      });
      api.install();
      renderPortal();

      await clickSignOut();
      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent(/could not be checked/i);
      expectStillSignedIn();
      expect(logouts()).toHaveLength(1);
      expect(validityReads()).toHaveLength(1);
    });

    it("asks the server, not a cache, and asks once: the validity read is bounded, fresh, and the same account route", async () => {
      signedIn(api, "/");
      api.on("POST /v1/account/logout", () => refusal(500, "internal_error"));
      api.install();
      renderPortal();

      await clickSignOut();
      await screen.findByRole("alert");
      const [pageLoad, check] = api.to("GET", "/v1/account");
      expect(pageLoad?.signal).toBeUndefined();
      expect(check?.signal).toBeInstanceOf(AbortSignal);
      expect(check?.cache).toBe("no-store");
      expect(validityReads()).toHaveLength(1);
    });
  });

  describe("one operation, every control", () => {
    it("retries only on request after a server 500 with a live read: one new logout, then signed out", async () => {
      signedIn(api, "/");
      let attempts = 0;
      api.on("POST /v1/account/logout", () => {
        attempts += 1;
        if (attempts === 1) return refusal(500, "internal_error");
        jar.clear(SESSION_COOKIE);
        jar.clear(CSRF_COOKIE);
        return noContent();
      });
      api.install();
      renderPortal();

      await clickSignOut();
      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent(/you are still signed in/i);
      expectStillSignedIn();
      expect(validityReads()).toHaveLength(1);
      // Nothing retries the logout on its own: the count stays at one until the customer acts.
      await settle();
      expect(attempts).toBe(1);

      await userEvent.click(screen.getByRole("button", { name: /^sign out$/i }));
      await waitFor(() => expect(window.location.pathname).toBe("/login"));
      // Exactly one new operation and one new request; a successful one needs no read.
      expect(attempts).toBe(2);
      expect(validityReads()).toHaveLength(1);
      expect(jar.get(CSRF_COOKIE)).toBeNull();
    });

    it("sends one logout and makes one validity read when the masthead and the security page are clicked before React re-renders, and both controls show the one operation", async () => {
      signedIn(api, "/account/security");
      withSessions();
      const logout = deferred<Response>();
      api.on("POST /v1/account/logout", () => logout.promise);
      api.install();
      renderPortal();

      await waitFor(() => expect(signOutControls()).toHaveLength(2));
      const [masthead, onPage] = signOutControls() as [HTMLElement, HTMLElement];
      // One `act` scope, so React renders nothing between the two clicks: both handlers
      // run against the same tree, and both reach the provider in the same tick.
      act(() => {
        masthead.click();
        onPage.click();
      });
      expect(logouts()).toHaveLength(1);
      await waitFor(() => {
        for (const control of signOutControls()) {
          expect(control).toHaveTextContent("Working…");
          expect(control).toBeDisabled();
        }
      });

      await act(async () => {
        logout.resolve(refusal(500, "internal_error"));
      });
      const alerts = await screen.findAllByRole("alert");
      expect(alerts).toHaveLength(2);
      expect(alerts[0]).toHaveTextContent(/you are still signed in/i);
      expect(alerts[1]?.textContent).toBe(alerts[0]?.textContent);
      expect(logouts()).toHaveLength(1);
      expect(validityReads()).toHaveLength(1);
      for (const control of signOutControls()) expect(control).toBeEnabled();
      expect(window.location.pathname).toBe("/account/security");
      expect(jar.get(CSRF_COOKIE)).toBe(CSRF_VALUE);
    });

    it("joins every direct call in the same tick to one operation: one promise, one logout, one outcome", async () => {
      signedIn(api, "/");
      logoutThatSucceeds();
      api.install();
      const probe: { session: SessionApi | null } = { session: null };
      renderWithProviders(
        <Probe
          expose={(session) => {
            probe.session = session;
          }}
        />,
      );
      await waitFor(() => expect(probe.session?.status).toBe("authenticated"));
      const session = probe.session as SessionApi;
      expect(session.signOutStatus).toEqual({ pending: false, failure: null });

      const first = session.signOut();
      const second = session.signOut();
      const third = session.signOut();
      expect(second).toBe(first);
      expect(third).toBe(first);
      // Registered and sent synchronously, before any of the three has been awaited.
      expect(logouts()).toHaveLength(1);
      await expect(Promise.all([first, second, third])).resolves.toEqual([
        "signed-out",
        "signed-out",
        "signed-out",
      ]);
      await waitFor(() => expect(probe.session?.status).toBe("anonymous"));
      expect(logouts()).toHaveLength(1);
      expect(probe.session?.signOutStatus).toEqual({ pending: false, failure: null });
    });

    it("starts exactly one new operation on an explicit retry after the previous one settled", async () => {
      signedIn(api, "/");
      api.on("POST /v1/account/logout", () => refusal(500, "internal_error"));
      api.install();
      const probe: { session: SessionApi | null } = { session: null };
      renderWithProviders(
        <Probe
          expose={(session) => {
            probe.session = session;
          }}
        />,
      );
      await waitFor(() => expect(probe.session?.status).toBe("authenticated"));

      const first = (probe.session as SessionApi).signOut();
      await expect(first).resolves.toBe("incomplete");
      // The context value the probe holds is a render old until React publishes the
      // settled state; the failure is what proves that publication has happened.
      await waitFor(() => expect(probe.session?.signOutStatus.failure?.validity).toBe("live"));
      expect(probe.session?.signOutStatus.pending).toBe(false);
      expect(probe.session?.status).toBe("authenticated");

      const second = (probe.session as SessionApi).signOut();
      expect(second).not.toBe(first);
      expect(logouts()).toHaveLength(2);
      await expect(second).resolves.toBe("incomplete");
      expect(logouts()).toHaveLength(2);
      expect(validityReads()).toHaveLength(2);
    });
  });

  describe("fenced to the session that started it", () => {
    /**
     * The late answers an obsolete validity read can deliver. Every one of them would, if
     * applied, do something to session B that only session A's sign-out was entitled to do:
     * a 401 would clear B and go to sign-in; a 200 would publish "still signed in" over B; a
     * 500 or a dropped connection would publish "could not be checked" over B.
     */
    const LATE_ANSWERS: Array<[string, (late: Deferred<Response>) => void]> = [
      ["401", (late) => late.resolve(refusal(401, "authentication_required"))],
      ["200", (late) => late.resolve(json(profile()))],
      ["500", (late) => late.resolve(refusal(500, "internal_error"))],
      ["a transport failure", (late) => late.reject(new TypeError("Failed to fetch"))],
    ];

    it.each(LATE_ANSWERS)(
      "ignores a validity read begun under session A that answers %s after session B is adopted: B stays signed in, nowhere is navigated to, nothing is shown",
      async (_, answer) => {
        signedIn(api, "/account/security");
        withSessions();
        api.on("POST /v1/account/logout", () => refusal(500, "internal_error"));
        const late = deferred<Response>();
        api.on("GET /v1/account", (request) =>
          isValidityRead(request) ? late.promise : json(profile()),
        );
        passwordChangeAdoptsB();
        // A wire that delivers the answer whatever the abort said: it is the fence on the
        // late answer, not the abort, that this test is about.
        api.install({ abortable: false });
        renderPortal();

        await waitFor(() => expect(signOutControls()).toHaveLength(2));
        await userEvent.click(signOutControls()[0] as HTMLElement);
        await waitFor(() => expect(validityReads()).toHaveLength(1));
        for (const control of signOutControls()) expect(control).toBeDisabled();

        await changePassword();
        // Adopting B disowned the operation: its pending state is gone from every control.
        expectSessionBRetained();
        expect(screen.queryByRole("alert")).not.toBeInTheDocument();

        await act(async () => {
          answer(late);
        });
        await settle();
        expectSessionBRetained();
        expect(screen.queryByRole("alert")).not.toBeInTheDocument();
        expect(logouts()).toHaveLength(1);
        expect(validityReads()).toHaveLength(1);
      },
    );

    it("ignores a logout that succeeds after session B is adopted: B is not cleared and no navigation happens", async () => {
      signedIn(api, "/account/security");
      withSessions();
      const late = deferred<Response>();
      api.on("POST /v1/account/logout", () => late.promise);
      passwordChangeAdoptsB();
      api.install({ abortable: false });
      renderPortal();

      await waitFor(() => expect(signOutControls()).toHaveLength(2));
      await userEvent.click(signOutControls()[0] as HTMLElement);
      await waitFor(() => expect(logouts()).toHaveLength(1));

      await changePassword();
      expectSessionBRetained();

      await act(async () => {
        late.resolve(noContent());
      });
      await settle();
      expectSessionBRetained();
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
      expect(logouts()).toHaveLength(1);
    });

    it("ignores a logout refused after session B is adopted: no validity read is made for a session that is gone", async () => {
      signedIn(api, "/account/security");
      withSessions();
      const late = deferred<Response>();
      api.on("POST /v1/account/logout", () => late.promise);
      passwordChangeAdoptsB();
      api.install({ abortable: false });
      renderPortal();

      await waitFor(() => expect(signOutControls()).toHaveLength(2));
      await userEvent.click(signOutControls()[0] as HTMLElement);
      await waitFor(() => expect(logouts()).toHaveLength(1));

      await changePassword();
      await act(async () => {
        late.resolve(refusal(401, "authentication_required"));
      });
      await settle();
      expectSessionBRetained();
      expect(validityReads()).toHaveLength(0);
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    });

    it("lets no stale answer clear the current session or overwrite a newer operation's state", async () => {
      signedIn(api, "/account/security");
      withSessions();
      api.on("POST /v1/account/logout", () => refusal(500, "internal_error"));
      const stale = deferred<Response>();
      api.on("GET /v1/account", (request) =>
        isValidityRead(request) ? stale.promise : json(profile()),
      );
      passwordChangeAdoptsB();
      api.install({ abortable: false });
      renderPortal();

      // Operation 1, under A: its validity read never answers in time.
      await waitFor(() => expect(signOutControls()).toHaveLength(2));
      await userEvent.click(signOutControls()[0] as HTMLElement);
      await waitFor(() => expect(validityReads()).toHaveLength(1));

      // B is adopted; operation 1 is disowned. Operation 2, under B: refused, and the read
      // finds B live, so B's controls show that B is still signed in.
      await changePassword();
      expectSessionBRetained();
      await userEvent.click(signOutControls()[0] as HTMLElement);
      const alerts = await screen.findAllByRole("alert");
      expect(alerts[0]).toHaveTextContent(/you are still signed in/i);
      expect(logouts()).toHaveLength(2);
      expect(validityReads()).toHaveLength(2);

      // Operation 1's read finally answers 401 -- about A. B is untouched, and so is what
      // operation 2 published.
      await act(async () => {
        stale.resolve(refusal(401, "authentication_required"));
      });
      await settle();
      expectSessionBRetained();
      const still = screen.getAllByRole("alert");
      expect(still).toHaveLength(2);
      expect(still[0]).toHaveTextContent(/you are still signed in/i);
      expect(still[0]?.textContent).not.toMatch(/could not be checked/i);
      expect(logouts()).toHaveLength(2);
    });
  });

  describe("deadlines and cleanup", () => {
    // Real deadlines, driven by a fake clock. Only `setTimeout` and `clearTimeout` are
    // faked, so React's scheduling and Testing Library's polling stay real; the clock also
    // advances with real time, so a zero-delay timer still fires on its own, and a deadline
    // seconds away is reached by jumping to it.
    beforeEach(() => {
      vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"], shouldAdvanceTime: true });
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    const user = () => userEvent.setup({ advanceTimers: (ms) => vi.advanceTimersByTime(ms) });

    /** A request that never answers, unless the wire is told to stop waiting for it. */
    function stalled(): Promise<Response> {
      return new Promise(() => undefined);
    }

    async function jump(milliseconds: number): Promise<void> {
      await act(async () => {
        vi.advanceTimersByTime(milliseconds);
      });
    }

    it("aborts a stalled validity read at its deadline, and not before: unknown, still signed in, controls restored, nothing left armed", async () => {
      signedIn(api, "/");
      api.on("POST /v1/account/logout", () => refusal(500, "internal_error"));
      api.on("GET /v1/account", (request) =>
        isValidityRead(request) ? stalled() : json(profile()),
      );
      api.install();
      renderPortal();

      await clickSignOut(user());
      await waitFor(() => expect(validityReads()).toHaveLength(1));
      const check = validityReads()[0] as RecordedRequest;
      const signal = check.signal as AbortSignal;

      await jump(SESSION_CHECK_TIMEOUT_MS - 1000);
      expect(signal.aborted).toBe(false);
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
      expect(screen.getByRole("button", { name: /^(sign out|working…)$/i })).toBeDisabled();

      await jump(1000);
      expect(signal.aborted).toBe(true);
      expect((signal.reason as DOMException).name).toBe("TimeoutError");
      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent(/could not be checked/i);
      expect(alert).toHaveTextContent(/treat yourself as signed in/i);
      expectStillSignedIn();
      expect(logouts()).toHaveLength(1);
      expect(validityReads()).toHaveLength(1);
      expect(vi.getTimerCount()).toBe(0);
    });

    it("aborts a stalled logout at its deadline, then makes the one validity read; an unknown answer changes nothing", async () => {
      signedIn(api, "/");
      api.on("POST /v1/account/logout", () => stalled());
      api.on("GET /v1/account", (request) => {
        if (!isValidityRead(request)) return json(profile());
        throw new TypeError("Failed to fetch");
      });
      api.install();
      renderPortal();

      await clickSignOut(user());
      await waitFor(() => expect(logouts()).toHaveLength(1));
      const signal = (logouts()[0] as RecordedRequest).signal as AbortSignal;

      await jump(LOGOUT_TIMEOUT_MS - 1000);
      expect(signal.aborted).toBe(false);
      expect(validityReads()).toHaveLength(0);

      await jump(1000);
      expect(signal.aborted).toBe(true);
      expect((signal.reason as DOMException).name).toBe("TimeoutError");
      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent(/could not be checked/i);
      // A minute later nothing has been sent again and nothing has changed.
      await jump(60_000);
      expectStillSignedIn();
      expect(logouts()).toHaveLength(1);
      expect(validityReads()).toHaveLength(1);
      expect(vi.getTimerCount()).toBe(0);
    });

    it("aborts the read of an operation made obsolete by session B, and publishes no unknown over B", async () => {
      signedIn(api, "/account/security");
      withSessions();
      api.on("POST /v1/account/logout", () => refusal(500, "internal_error"));
      api.on("GET /v1/account", (request) =>
        isValidityRead(request) ? stalled() : json(profile()),
      );
      passwordChangeAdoptsB();
      api.install();
      renderPortal();

      await waitFor(() => expect(signOutControls()).toHaveLength(2));
      await user().click(signOutControls()[0] as HTMLElement);
      await waitFor(() => expect(validityReads()).toHaveLength(1));
      const signal = (validityReads()[0] as RecordedRequest).signal as AbortSignal;
      expect(signal.aborted).toBe(false);

      await changePassword(user());
      // The wire honoured the abort: the read rejected with the operation's reason, which
      // the client reports as a transport failure, which an *owned* operation would have
      // published as "unknown". This one is not owned any more.
      expect(signal.aborted).toBe(true);
      expect((signal.reason as DOMException).name).toBe("AbortError");
      await settle();
      expectSessionBRetained();
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
      expect(logouts()).toHaveLength(1);
      expect(validityReads()).toHaveLength(1);
      expect(vi.getTimerCount()).toBe(0);
    });

    it("abandons a pending sign-out when the provider is torn down: request aborted, deadline cleared", async () => {
      signedIn(api, "/");
      api.on("POST /v1/account/logout", () => stalled());
      api.install();
      const { unmount } = renderPortal();

      await clickSignOut(user());
      await waitFor(() => expect(logouts()).toHaveLength(1));
      const signal = (logouts()[0] as RecordedRequest).signal as AbortSignal;
      expect(signal.aborted).toBe(false);
      expect(vi.getTimerCount()).toBeGreaterThanOrEqual(1);

      unmount();
      expect(signal.aborted).toBe(true);
      expect((signal.reason as DOMException).name).toBe("AbortError");
      await settle();
      expect(vi.getTimerCount()).toBe(0);
      expect(validityReads()).toHaveLength(0);
    });
  });
});

describe("a session lease fences every asynchronous response", () => {
  const OTHER_SESSION = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
  const SESSION_C = "88888888-8888-4888-8888-888888888888";

  function sessionRow(id: string, current: boolean) {
    return {
      session_id: id,
      created_at: "2026-09-09T09:00:00+00:00",
      last_seen_at: "2026-09-09T10:00:00+00:00",
      expires_at: "2026-09-09T22:00:00+00:00",
      workspace_id: null,
      current,
    };
  }

  /** The security page with two sessions listed: this browser's, and another's. */
  function withTwoSessions(): void {
    api.reply("GET /v1/account/sessions", {
      sessions: [sessionRow(SESSION_ID, true), sessionRow(OTHER_SESSION, false)],
    });
  }

  function otherSessionRow(): HTMLElement {
    return screen.getByText("Another browser").closest("tr") as HTMLElement;
  }

  /** Session B is the one the portal holds, while a request under A is still pending. */
  function expectSessionB(): void {
    expect(window.location.pathname).toBe("/account/security");
    expect(screen.getByRole("heading", { level: 1, name: /^security$/i })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /^sign in$/i })).not.toBeInTheDocument();
    expect(jar.get(CSRF_COOKIE)).toBe(REPLACEMENT_CSRF);
  }

  /** Nothing about the session was shown: not "ended", not "still open", no alert at all. */
  function expectNothingPublished(): void {
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByText(/session has ended/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/still open/i)).not.toBeInTheDocument();
  }

  async function mountProbe(): Promise<{ session: SessionApi | null }> {
    const probe: { session: SessionApi | null } = { session: null };
    renderWithProviders(
      <Probe
        expose={(session) => {
          probe.session = session;
        }}
      />,
    );
    await waitFor(() => expect(probe.session?.status).toBe("authenticated"));
    return probe;
  }

  describe("an answer about a session that has been replaced", () => {
    it("ignores a page read begun under session A that answers 401 after session B is adopted: B stays, no sign-in navigation", async () => {
      signedIn(api, "/account/security");
      const late = deferred<Response>();
      let reads = 0;
      api.on("GET /v1/account/sessions", () => {
        reads += 1;
        return reads === 1 ? late.promise : json({ sessions: [sessionRow(SESSION_ID, true)] });
      });
      passwordChangeAdoptsB();
      // A wire that delivers the answer whatever the abort said: the fence is under test.
      api.install({ abortable: false });
      renderPortal();

      await screen.findByRole("heading", { level: 1, name: /^security$/i });
      await changePassword();
      await waitFor(() => expect(signOutControls()).toHaveLength(2));
      expectSessionBRetained();

      await act(async () => {
        late.resolve(refusal(401, "authentication_required"));
      });
      await settle();
      expectSessionBRetained();
      expectNothingPublished();
      expect(validityReads()).toHaveLength(0);
    });

    it("ignores a mutation begun under session A that answers 401 after session B is adopted: B stays, nothing is checked", async () => {
      signedIn(api, "/account/security");
      withTwoSessions();
      const late = deferred<Response>();
      api.on("DELETE /v1/account/sessions/{id}", () => late.promise);
      passwordChangeAdoptsB();
      api.install({ abortable: false });
      renderPortal();

      await screen.findByText("Another browser");
      await userEvent.click(within(otherSessionRow()).getByRole("button", { name: /^sign out$/i }));
      await waitFor(() =>
        expect(api.to("DELETE", `/v1/account/sessions/${OTHER_SESSION}`)).toHaveLength(1),
      );

      await changePassword();
      expectSessionB();

      await act(async () => {
        late.resolve(refusal(401, "authentication_required"));
      });
      await settle();
      // The late answer settled the request, which restored its control; it changed nothing.
      expectSessionBRetained();
      expectNothingPublished();
      expect(validityReads()).toHaveLength(0);
    });

    it("lets none of several answers through when a password change adopts a replacement while they are pending", async () => {
      signedIn(api, "/account/security");
      withTwoSessions();
      const revoke = deferred<Response>();
      const revokeAll = deferred<Response>();
      api.on("DELETE /v1/account/sessions/{id}", () => revoke.promise);
      api.on("POST /v1/account/sessions/revoke-all", () => revokeAll.promise);
      passwordChangeAdoptsB();
      api.install({ abortable: false });
      renderPortal();

      await screen.findByText("Another browser");
      await userEvent.click(within(otherSessionRow()).getByRole("button", { name: /^sign out$/i }));
      await userEvent.click(
        screen.getByRole("button", { name: /sign out of every other session/i }),
      );
      await waitFor(() =>
        expect(api.to("POST", "/v1/account/sessions/revoke-all")).toHaveLength(1),
      );

      await changePassword();
      expectSessionB();

      // One late failure that would have cleared and one that would have been reported:
      // neither counts.
      await act(async () => {
        revoke.resolve(refusal(401, "authentication_required"));
        revokeAll.resolve(refusal(500, "internal_error"));
      });
      await settle();
      expectSessionBRetained();
      expectNothingPublished();
      expect(screen.queryByText(/signed out of/i)).not.toBeInTheDocument();
      expect(validityReads()).toHaveLength(0);
    });

    it("keeps the session a fresh sign-in adopted when a read begun before the sign-out answers 401 afterwards", async () => {
      signedIn(api, "/settings/credentials");
      const late = deferred<Response>();
      let reads = 0;
      api.on("GET /v1/workspace/credentials", () => {
        reads += 1;
        return reads === 1 ? late.promise : json({ workspace_id: WORKSPACE_ID, credentials: [] });
      });
      logoutThatSucceeds();
      api.on("POST /v1/account/login", () => {
        jar.set(SESSION_COOKIE, "fbs_NEWSESSIONnotarealsecret0000000000000000");
        jar.set(CSRF_COOKIE, REPLACEMENT_CSRF);
        api.reply("GET /v1/account", profileB());
        return json({
          account_id: ACCOUNT_ID,
          session_id: SESSION_B,
          csrf_token: REPLACEMENT_CSRF,
          expires_at: null,
        });
      });
      api.install({ abortable: false });
      renderPortal();

      // Out under A, while A's read is still pending; back in as B, at the overview.
      await userEvent.click(await screen.findByRole("button", { name: /^sign out$/i }));
      await screen.findByRole("heading", { name: /^sign in$/i });
      await userEvent.type(screen.getByLabelText(/email address/i), "person@example.com");
      await userEvent.type(screen.getByLabelText(/password/i), "correct horse battery staple");
      await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
      await screen.findByRole("heading", { name: /overview/i });
      expect(reads).toBe(1);

      await act(async () => {
        late.resolve(refusal(401, "authentication_required"));
      });
      await settle();
      expect(window.location.pathname).toBe("/");
      expect(screen.getByRole("heading", { name: /overview/i })).toBeInTheDocument();
      expect(screen.queryByRole("heading", { name: /^sign in$/i })).not.toBeInTheDocument();
      expect(jar.get(CSRF_COOKIE)).toBe(REPLACEMENT_CSRF);
      expectNothingPublished();
      expect(validityReads()).toHaveLength(0);
    });

    it("lets neither a late success nor a late failure from an older read overwrite the newer state", async () => {
      signedIn(api, "/");
      const lateA = deferred<Response>();
      const lateB = deferred<Response>();
      const profileC = profile({ session: { ...profile().session, session_id: SESSION_C } });
      // The account reads, in order: the first load (A), an old read of A that answers late,
      // the adoption of B, an old read of B that answers late, then C for good.
      const answers: Array<() => Response | Promise<Response>> = [
        () => json(profile()),
        () => lateA.promise,
        () => json(profileB()),
        () => lateB.promise,
      ];
      let reads = 0;
      api.on("GET /v1/account", () => {
        reads += 1;
        return (answers[reads - 1] ?? (() => json(profileC)))();
      });
      api.install({ abortable: false });
      const probe = await mountProbe();

      // A read of A is pending when B is adopted; then A's answer arrives, a success.
      const staleRead = (probe.session as SessionApi).refresh();
      await waitFor(() => expect(reads).toBe(2));
      await (probe.session as SessionApi).adoptReplacement(SESSION_B);
      await waitFor(() => expect(probe.session?.profile?.session.session_id).toBe(SESSION_B));
      await act(async () => {
        lateA.resolve(json(profile()));
      });
      await staleRead;
      await settle();
      expect(probe.session?.profile?.session.session_id).toBe(SESSION_B);
      expect(probe.session?.status).toBe("authenticated");

      // A read of B is pending when C is adopted; then B's answer arrives, a 401.
      const stalerRead = (probe.session as SessionApi).refresh();
      await waitFor(() => expect(reads).toBe(4));
      await (probe.session as SessionApi).adoptReplacement(SESSION_C);
      await waitFor(() => expect(probe.session?.profile?.session.session_id).toBe(SESSION_C));
      await act(async () => {
        lateB.resolve(refusal(401, "authentication_required"));
      });
      await stalerRead;
      await settle();
      expect(probe.session?.profile?.session.session_id).toBe(SESSION_C);
      expect(probe.session?.status).toBe("authenticated");
      expect(window.location.pathname).toBe("/");
    });

    it("abandons the bounded check of a refusal whose session is replaced, and publishes nothing for it", async () => {
      signedIn(api, "/");
      let reads = 0;
      api.on("GET /v1/account", (request) => {
        reads += 1;
        if (isValidityRead(request)) return new Promise<Response>(() => undefined);
        return json(reads >= 3 ? profileB() : profile());
      });
      api.install();
      const probe = await mountProbe();
      const session = probe.session as SessionApi;

      const lease = session.lease();
      const pending = session.reconcile(
        lease,
        new ApiError(401, "authentication_required"),
        "mutation",
      );
      await waitFor(() => expect(validityReads()).toHaveLength(1));
      const signal = (validityReads()[0] as RecordedRequest).signal as AbortSignal;
      expect(signal.aborted).toBe(false);

      await session.adoptReplacement(SESSION_B);
      expect(signal.aborted).toBe(true);
      expect((signal.reason as DOMException).name).toBe("AbortError");
      await expect(pending).resolves.toBe("obsolete");
      await waitFor(() => expect(probe.session?.profile?.session.session_id).toBe(SESSION_B));
      expect(probe.session?.status).toBe("authenticated");
    });
  });

  describe("what a refusal is allowed to mean", () => {
    it("clears the matching current session on a definitive 401 from a safe read, and remembers the page", async () => {
      signedIn(api, "/settings/credentials");
      api.on("GET /v1/workspace/credentials", () => refusal(401, "authentication_required"));
      api.install();
      renderPortal();

      await waitFor(() => expect(window.location.pathname).toBe("/login"));
      expect(window.location.search).toContain("next=%2Fsettings%2Fcredentials");
      // Definitive: no validity read was needed.
      expect(validityReads()).toHaveLength(0);
    });

    it("does not clear on a mutation 401 by itself: one bounded, fresh read finds the session live", async () => {
      signedIn(api, "/settings/credentials", "member");
      api.reply("GET /v1/workspace/credentials", { workspace_id: WORKSPACE_ID, credentials: [] });
      api.on("POST /v1/workspace/credentials", () => refusal(401, "authentication_required"));
      api.install();
      renderPortal();

      await screen.findByRole("heading", { name: /api credentials/i });
      await userEvent.click(screen.getByRole("button", { name: /create credential/i }));

      expect(await screen.findByRole("alert")).toHaveTextContent(/still open/i);
      expect(window.location.pathname).toBe("/settings/credentials");
      expect(screen.queryByText(/session has ended/i)).not.toBeInTheDocument();
      expect(validityReads()).toHaveLength(1);
      const check = validityReads()[0] as RecordedRequest;
      expect(check.cache).toBe("no-store");
      expect(check.signal).toBeInstanceOf(AbortSignal);
    });

    it("clears on a mutation 401 when the bounded read finds the session gone", async () => {
      signedIn(api, "/settings/credentials", "member");
      api.reply("GET /v1/workspace/credentials", { workspace_id: WORKSPACE_ID, credentials: [] });
      api.on("POST /v1/workspace/credentials", () => {
        accountReadsUnauthenticated();
        return refusal(401, "authentication_required");
      });
      api.install();
      renderPortal();

      await screen.findByRole("heading", { name: /api credentials/i });
      await userEvent.click(screen.getByRole("button", { name: /create credential/i }));

      await waitFor(() => expect(window.location.pathname).toBe("/login"));
      expect(validityReads()).toHaveLength(1);
    });

    it("retains on a mutation 401 when the bounded read cannot settle it", async () => {
      signedIn(api, "/settings/credentials", "member");
      api.reply("GET /v1/workspace/credentials", { workspace_id: WORKSPACE_ID, credentials: [] });
      api.on("POST /v1/workspace/credentials", () => {
        api.on("GET /v1/account", () => refusal(503, "service_unavailable"));
        return refusal(401, "authentication_required");
      });
      api.install();
      renderPortal();

      await screen.findByRole("heading", { name: /api credentials/i });
      await userEvent.click(screen.getByRole("button", { name: /create credential/i }));

      expect(await screen.findByRole("alert")).toHaveTextContent(/still open/i);
      expect(window.location.pathname).toBe("/settings/credentials");
      expect(validityReads()).toHaveLength(1);
    });

    it("leaves the session alone for a 401 that is a verdict on a password, not on the session", async () => {
      signedIn(api, "/account/security");
      withSessions();
      api.on("POST /v1/account/password", () => refusal(401, "invalid_credentials"));
      api.install();
      renderPortal();

      await screen.findByRole("heading", { level: 1, name: /^security$/i });
      await userEvent.type(screen.getByLabelText(/current password/i), "not the current one");
      await userEvent.type(screen.getByLabelText(/^new password/i), NEXT_PASSWORD);
      await userEvent.type(screen.getByLabelText(/confirm new password/i), NEXT_PASSWORD);
      await userEvent.click(screen.getByRole("button", { name: /change password/i }));

      expect(await screen.findByRole("alert")).toHaveTextContent(/current password is not right/i);
      expect(window.location.pathname).toBe("/account/security");
      expect(validityReads()).toHaveLength(0);
    });

    it("answers each refusal by policy, and an obsolete lease with nothing", async () => {
      signedIn(api, "/");
      api.install();
      const probe = await mountProbe();
      const session = probe.session as SessionApi;
      const lease = session.lease();
      const before = api.to("GET", "/v1/account").length;

      // A 403 re-reads authority; a wrong password is not about the session at all.
      await expect(
        session.reconcile(lease, new ApiError(403, "forbidden"), "mutation"),
      ).resolves.toBe("refreshed");
      expect(api.to("GET", "/v1/account")).toHaveLength(before + 1);
      await expect(
        session.reconcile(lease, new ApiError(401, "invalid_credentials"), "mutation"),
      ).resolves.toBe("unchanged");
      await expect(session.reconcile(lease, new Error("not an ApiError"), "read")).resolves.toBe(
        "unchanged",
      );
      expect(validityReads()).toHaveLength(0);

      // The client's own refusal of a mutation with no CSRF cookie is ambiguous too.
      await expect(
        session.reconcile(
          lease,
          new ApiError(401, "authentication_required", "client"),
          "mutation",
        ),
      ).resolves.toBe("retained");
      expect(validityReads()).toHaveLength(1);
      expect(probe.session?.status).toBe("authenticated");

      // A lease from a generation that has passed decides nothing, and asks nothing.
      const obsolete = { generation: lease.generation - 1, sessionId: lease.sessionId };
      await expect(
        session.reconcile(obsolete, new ApiError(401, "authentication_required"), "read"),
      ).resolves.toBe("obsolete");
      expect(session.holds(obsolete)).toBe(false);
      expect(validityReads()).toHaveLength(1);
      expect(probe.session?.status).toBe("authenticated");

      // The definitive case, last: a safe read's 401 under the current lease clears.
      await expect(
        session.reconcile(lease, new ApiError(401, "authentication_required"), "read"),
      ).resolves.toBe("cleared");
      await waitFor(() => expect(probe.session?.status).toBe("anonymous"));
      // And the same answer again is about a session that is gone.
      await expect(
        session.reconcile(lease, new ApiError(401, "authentication_required"), "read"),
      ).resolves.toBe("obsolete");
    });

    it("moves the generation only when the browser session is replaced, not when the workspace changes", async () => {
      signedIn(api, "/");
      api.on("PUT /v1/account/workspace", () =>
        json({ workspace_id: OTHER_WORKSPACE_ID, role: "owner", membership_id: MEMBERSHIP_ID }),
      );
      api.install();
      const probe = await mountProbe();
      const session = probe.session as SessionApi;
      const lease = session.lease();

      // Re-reads of the same session, and a workspace switch under it, keep the lease.
      await session.refresh();
      await session.selectWorkspace(OTHER_WORKSPACE_ID);
      await waitFor(() => expect(api.to("PUT", "/v1/account/workspace")).toHaveLength(1));
      expect(session.holds(lease)).toBe(true);

      // A replacement session does not.
      api.reply("GET /v1/account", profileB());
      await session.adoptReplacement(SESSION_B);
      expect(session.holds(lease)).toBe(false);
      expect(session.holds(session.lease())).toBe(true);
    });
  });

  describe("duplicate and unfenced invalidation", () => {
    it("clears once, not twice, when StrictMode replays a load and both halves of it answer 401", async () => {
      signedIn(api, "/settings/team");
      api.on("GET /v1/workspace/members", () => refusal(401, "authentication_required"));
      api.on("GET /v1/workspace/invitations", () => refusal(401, "authentication_required"));
      api.install();
      const seen = new Set<SessionApi>();
      render(
        <StrictMode>
          <RouterProvider>
            <SessionProvider>
              <App />
              <Probe
                expose={(session) => {
                  seen.add(session);
                }}
              />
            </SessionProvider>
          </RouterProvider>
        </StrictMode>,
      );

      await waitFor(() => expect(window.location.pathname).toBe("/login"));
      expect(window.location.search).toContain("next=%2Fsettings%2Fteam");
      await settle();
      // Every published value is a distinct object; one clearing publishes one anonymous one.
      const anonymous = [...seen].filter((session) => session.status === "anonymous");
      expect(anonymous).toHaveLength(1);
      expect(validityReads()).toHaveLength(0);
    });

    it("exposes no unfenced way to clear authentication, and every production caller carries a lease", async () => {
      signedIn(api, "/");
      api.install();
      const probe = await mountProbe();
      expect("forget" in (probe.session as SessionApi)).toBe(false);
      expect("forgetIfCurrent" in (probe.session as SessionApi)).toBe(false);

      const elsewhere = sourcesWithoutComments().filter(([name]) => name !== "auth/session.tsx");
      // Nothing outside the provider forgets; nothing re-reads without saying for which
      // session (the one retry of the current session goes through `retryLoad`); every
      // reconciliation carries the lease; and every module that calls the API under the
      // session takes its tickets from `usePageRequests`, which carry the lease and the
      // workspace. Supporting evidence for the behavioural tests above, not a substitute.
      expect(namesWhere(elsewhere, (text) => /\bforget(IfCurrent)?\(/.test(text))).toEqual([]);
      expect(namesWhere(elsewhere, (text) => /\.refresh\(\s*\)/.test(text))).toEqual([]);
      expect(namesWhere(elsewhere, reconcilesWithoutLease)).toEqual([]);
      const callers = elsewhere.filter(([, text]) => text.includes("api/endpoints.ts"));
      expect(callers.length).toBeGreaterThanOrEqual(6);
      expect(namesWhere(callers, (text) => !/usePageRequests\(|\.lease\(\)/.test(text))).toEqual(
        [],
      );
    });
  });
});

describe("the replacement barrier and the page lifecycle", () => {
  /** Every URL the router is handed from here on, so a detour through sign-in is visible. */
  function trackNavigation(): string[] {
    const visited: string[] = [];
    const push = window.history.pushState.bind(window.history);
    const replace = window.history.replaceState.bind(window.history);
    vi.spyOn(window.history, "pushState").mockImplementation((data, unused, url) => {
      visited.push(String(url));
      push(data, unused, url);
    });
    vi.spyOn(window.history, "replaceState").mockImplementation((data, unused, url) => {
      visited.push(String(url));
      replace(data, unused, url);
    });
    return visited;
  }

  function sessionRow(id: string, current: boolean) {
    return {
      session_id: id,
      created_at: "2026-09-09T09:00:00+00:00",
      last_seen_at: "2026-09-09T10:00:00+00:00",
      expires_at: "2026-09-09T22:00:00+00:00",
      workspace_id: null,
      current,
    };
  }

  function replacementFromPasswordChange(): void {
    api.on("POST /v1/account/password", () => {
      jar.set(CSRF_COOKIE, REPLACEMENT_CSRF);
      return json({
        account_id: ACCOUNT_ID,
        session_id: SESSION_B,
        csrf_token: REPLACEMENT_CSRF,
        expires_at: null,
        other_sessions_revoked: true,
      });
    });
  }

  async function submitPasswordChange(): Promise<void> {
    await userEvent.type(screen.getByLabelText(/current password/i), CURRENT_PASSWORD);
    await userEvent.type(screen.getByLabelText(/^new password/i), NEXT_PASSWORD);
    await userEvent.type(screen.getByLabelText(/confirm new password/i), NEXT_PASSWORD);
    await userEvent.click(screen.getByRole("button", { name: /change password/i }));
  }

  async function mountProbe(): Promise<{ session: SessionApi | null }> {
    const probe: { session: SessionApi | null } = { session: null };
    renderWithProviders(
      <Probe
        expose={(session) => {
          probe.session = session;
        }}
      />,
    );
    await waitFor(() => expect(probe.session?.status).toBe("authenticated"));
    return probe;
  }

  describe("a password change versus an old Security-page 401", () => {
    it("old 401 after the replacement response but before its read: B stands, no sign-in detour, the success is kept", async () => {
      signedIn(api, "/account/security");
      const staleSessions = deferred<Response>();
      let sessionReads = 0;
      api.on("GET /v1/account/sessions", () => {
        sessionReads += 1;
        return sessionReads === 1
          ? staleSessions.promise
          : json({ sessions: [sessionRow(SESSION_B, true)] });
      });
      const replacementRead = deferred<Response>();
      let accountReads = 0;
      api.on("GET /v1/account", () => {
        accountReads += 1;
        if (accountReads === 1) return json(profile());
        if (accountReads === 2) return replacementRead.promise;
        return json(profileB());
      });
      replacementFromPasswordChange();
      api.install({ abortable: false });
      const visited = trackNavigation();
      renderPortal();

      await screen.findByRole("heading", { level: 1, name: /^security$/i });
      await submitPasswordChange();
      // The replacement is adopted from the response and its read is in flight.
      await waitFor(() => expect(accountReads).toBe(2));
      expect(jar.get(CSRF_COOKIE)).toBe(REPLACEMENT_CSRF);

      // Now the Security page's own read, begun under A, answers 401.
      await act(async () => {
        staleSessions.resolve(refusal(401, "authentication_required"));
      });
      await settle();
      expect(window.location.pathname).toBe("/account/security");
      expect(screen.queryByText(/session has ended/i)).not.toBeInTheDocument();

      // And the replacement's read completes.
      await act(async () => {
        replacementRead.resolve(json(profileB()));
      });
      await screen.findByText(/password changed/i);
      expectSessionBRetained();
      expect(visited.filter((url) => url.startsWith("/login"))).toEqual([]);
      expect(validityReads()).toHaveLength(0);
    });

    it("old 401 before the replacement response: deferred, then B adopted, no sign-in detour, the success is kept", async () => {
      signedIn(api, "/account/security");
      const staleSessions = deferred<Response>();
      let sessionReads = 0;
      api.on("GET /v1/account/sessions", () => {
        sessionReads += 1;
        return sessionReads === 1
          ? staleSessions.promise
          : json({ sessions: [sessionRow(SESSION_B, true)] });
      });
      const change = deferred<Response>();
      api.on("POST /v1/account/password", () => change.promise);
      api.install({ abortable: false });
      const visited = trackNavigation();
      renderPortal();

      await screen.findByRole("heading", { level: 1, name: /^security$/i });
      await submitPasswordChange();
      await waitFor(() => expect(api.to("POST", "/v1/account/password")).toHaveLength(1));

      // A's read answers 401 while the change -- which will replace A -- is still pending.
      await act(async () => {
        staleSessions.resolve(refusal(401, "authentication_required"));
      });
      await settle();
      expect(window.location.pathname).toBe("/account/security");
      expect(screen.queryByText(/session has ended/i)).not.toBeInTheDocument();
      expect(validityReads()).toHaveLength(0);

      // The change answers with the replacement.
      jar.set(CSRF_COOKIE, REPLACEMENT_CSRF);
      api.reply("GET /v1/account", profileB());
      await act(async () => {
        change.resolve(
          json({
            account_id: ACCOUNT_ID,
            session_id: SESSION_B,
            csrf_token: REPLACEMENT_CSRF,
            expires_at: null,
            other_sessions_revoked: true,
          }),
        );
      });
      await screen.findByText(/password changed/i);
      expectSessionBRetained();
      expect(visited.filter((url) => url.startsWith("/login"))).toEqual([]);
    });

    it("a deferred 401 is settled by one bounded read when the change fails", async () => {
      signedIn(api, "/account/security");
      const staleSessions = deferred<Response>();
      let sessionReads = 0;
      api.on("GET /v1/account/sessions", () => {
        sessionReads += 1;
        return sessionReads === 1 ? staleSessions.promise : json({ sessions: [] });
      });
      const change = deferred<Response>();
      api.on("POST /v1/account/password", () => change.promise);
      api.install({ abortable: false });
      renderPortal();

      await screen.findByRole("heading", { level: 1, name: /^security$/i });
      await submitPasswordChange();
      await waitFor(() => expect(api.to("POST", "/v1/account/password")).toHaveLength(1));
      await act(async () => {
        staleSessions.resolve(refusal(401, "authentication_required"));
      });
      await settle();
      expect(validityReads()).toHaveLength(0);

      // The change fails on the current password: the session was not replaced, so the
      // deferred refusal is now the ambiguous kind, checked once -- and the check finds the
      // session gone.
      accountReadsUnauthenticated();
      await act(async () => {
        change.resolve(refusal(401, "invalid_credentials"));
      });
      await waitFor(() => expect(window.location.pathname).toBe("/login"));
      expect(validityReads()).toHaveLength(1);
    });

    it("a replacement whose read fails is a live session with a retry, never the old session and never signed out", async () => {
      signedIn(api, "/account/security");
      withSessions();
      let accountReads = 0;
      api.on("GET /v1/account", () => {
        accountReads += 1;
        if (accountReads === 1) return json(profile());
        if (accountReads === 2) return refusal(503, "service_unavailable");
        return json(profileB());
      });
      replacementFromPasswordChange();
      api.install();
      renderPortal();

      await screen.findByRole("heading", { level: 1, name: /^security$/i });
      await submitPasswordChange();
      const problem = await screen.findByText(/could not be loaded/i);
      expect(problem).toBeInTheDocument();
      // Still signed in, on the same page, with the replacement's cookie.
      expect(window.location.pathname).toBe("/account/security");
      expect(screen.queryByRole("heading", { name: /^sign in$/i })).not.toBeInTheDocument();
      expect(jar.get(CSRF_COOKIE)).toBe(REPLACEMENT_CSRF);
      expect(await screen.findByText(/password changed/i)).toBeInTheDocument();

      await userEvent.click(screen.getByRole("button", { name: /^retry$/i }));
      await waitFor(() =>
        expect(screen.queryByText(/could not be loaded/i)).not.toBeInTheDocument(),
      );
      expect(accountReads).toBe(3);
    });

    it("a sign-in whose read fails shows a signed-in retry, not the sign-in page", async () => {
      signedOut(api, "/login");
      let accountReads = 0;
      api.on("POST /v1/account/login", () => {
        jar.set(SESSION_COOKIE, "fbs_NEWSESSIONnotarealsecret0000000000000000");
        jar.set(CSRF_COOKIE, CSRF_VALUE);
        api
          .on("GET /v1/account", () => {
            accountReads += 1;
            return accountReads === 1 ? refusal(503, "service_unavailable") : json(profile());
          })
          .reply("GET /v1/account/workspaces", membershipList())
          .reply("GET /v1/workspace", workspaceDetail());
        return json({
          account_id: ACCOUNT_ID,
          session_id: SESSION_ID,
          csrf_token: CSRF_VALUE,
          expires_at: null,
        });
      });
      api.install();
      renderPortal();

      await screen.findByRole("heading", { name: /^sign in$/i });
      await userEvent.type(screen.getByLabelText(/email address/i), "person@example.com");
      await userEvent.type(screen.getByLabelText(/password/i), "correct horse battery staple");
      await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

      expect(await screen.findByText(/could not be loaded/i)).toBeInTheDocument();
      expect(screen.queryByRole("heading", { name: /^sign in$/i })).not.toBeInTheDocument();
      await userEvent.click(screen.getByRole("button", { name: /^retry$/i }));
      expect(await screen.findByRole("heading", { name: /overview/i })).toBeInTheDocument();
    });
  });

  describe("hygiene", () => {
    it("shares one validity read between concurrent askers", async () => {
      signedIn(api, "/");
      api.install();
      const probe = await mountProbe();
      const session = probe.session as SessionApi;
      const lease = session.lease();
      const refused = new ApiError(401, "authentication_required");
      const outcomes = await Promise.all([
        session.reconcile(lease, refused, "mutation"),
        session.reconcile(lease, refused, "mutation"),
        session.reconcile(lease, refused, "mutation"),
      ]);
      expect(outcomes).toEqual(["retained", "retained", "retained"]);
      expect(validityReads()).toHaveLength(1);
    });

    it("says a confirmation link is on its way only once the server accepted the request", async () => {
      signedIn(api, "/account");
      api.reply("GET /v1/account", profile({ email_verified: false }));
      let attempts = 0;
      api.on("POST /v1/account/verification/request", () => {
        attempts += 1;
        return attempts === 1
          ? refusal(503, "service_unavailable")
          : json({ status: "accepted" }, 202);
      });
      api.install();
      renderPortal();

      await screen.findByRole("heading", { name: /your account/i });
      await userEvent.click(screen.getByRole("button", { name: /send a new confirmation link/i }));
      expect(await screen.findByText(/could not be requested/i)).toBeInTheDocument();
      expect(screen.queryByText(/on its way/i)).not.toBeInTheDocument();

      await userEvent.click(screen.getByRole("button", { name: /send a new confirmation link/i }));
      expect(await screen.findByText(/on its way/i)).toBeInTheDocument();
      expect(attempts).toBe(2);
    });

    it("takes the invitation's ticket before the request, so a replacement adopted meanwhile navigates nowhere", async () => {
      const INVITATION = "fbi_INVITATIONTOKENnotarealsecret00000000000";
      signedIn(api, `/accept-invitation?token=${INVITATION}`);
      const acceptance = deferred<Response>();
      api.on("POST /v1/account/invitations/accept", () => acceptance.promise);
      api.install({ abortable: false });
      const probe: { session: SessionApi | null } = { session: null };
      renderWithProviders(
        <>
          <App />
          <Probe
            expose={(session) => {
              probe.session = session;
            }}
          />
        </>,
      );

      await userEvent.click(await screen.findByRole("button", { name: /accept invitation/i }));
      await waitFor(() => expect(api.to("POST", "/v1/account/invitations/accept")).toHaveLength(1));

      // Session B is adopted while the acceptance is pending; its answer belongs to A.
      api.reply("GET /v1/account", profileB());
      await act(async () => {
        await (probe.session as SessionApi).adoptReplacement(SESSION_B);
      });
      await act(async () => {
        acceptance.resolve(
          json({
            workspace_id: WORKSPACE_ID,
            membership_id: MEMBERSHIP_ID,
            role: "member",
            replayed: false,
          }),
        );
      });
      await settle();
      expect(window.location.pathname).toBe("/accept-invitation");
      expect(api.to("PUT", "/v1/account/workspace")).toHaveLength(0);
    });

    it("has no workspace-clearing call, in the provider or in the sources", async () => {
      signedIn(api, "/");
      api.install();
      const probe = await mountProbe();
      expect("clearWorkspace" in (probe.session as SessionApi)).toBe(false);
      expect(namesWhere(sourcesWithoutComments(), (text) => /clearWorkspace/.test(text))).toEqual(
        [],
      );
    });
  });
});

describe("one-time tokens under StrictMode", () => {
  const TOKEN = "fbv_ONETIMETOKENnotarealsecret000000000000";

  it("confirms an address exactly once, with the token out of the URL, when effects replay", async () => {
    // StrictMode mounts, unmounts and mounts every effect again. The first implementation
    // read the token from the URL inside an effect and scrubbed the URL in the same tick,
    // so the replayed effect found nothing and the token was lost; a submission inside an
    // effect would have run twice. Neither may happen.
    signedOut(api, `/verify-email?token=${TOKEN}`);
    api.on("POST /v1/account/verification/complete", () => json({ verified: true }));
    api.install();
    renderPortal({ strict: true });

    await screen.findByRole("heading", { name: /address confirmed/i });
    expect(api.to("POST", "/v1/account/verification/complete")).toHaveLength(1);
    expect(api.to("POST", "/v1/account/verification/complete")[0]?.body).toEqual({ token: TOKEN });
    expect(window.location.search).toBe("");
    expect(window.location.href).not.toContain(TOKEN);
  });

  it("keeps a token whose submission failed in transport, and submits it again on retry", async () => {
    signedOut(api, `/verify-email?token=${TOKEN}`);
    let attempts = 0;
    api.on("POST /v1/account/verification/complete", () => {
      attempts += 1;
      return attempts === 1 ? refusal(503, "service_unavailable") : json({ verified: true });
    });
    api.install();
    renderPortal({ strict: true });

    // A transport failure is not a spent link: the token is held, and the page offers a retry
    // rather than a new link.
    expect(await screen.findByText(/could not be confirmed just now/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /send a new link/i })).not.toBeInTheDocument();
    expect(attempts).toBe(1);

    await userEvent.click(screen.getByRole("button", { name: /try again/i }));
    await screen.findByRole("heading", { name: /address confirmed/i });
    expect(attempts).toBe(2);
    expect(api.to("POST", "/v1/account/verification/complete")[1]?.body).toEqual({ token: TOKEN });
    expect(window.location.href).not.toContain(TOKEN);
  });

  it("treats a 400 as a spent link and offers a new one, without retrying", async () => {
    signedOut(api, `/verify-email?token=${TOKEN}`);
    api.on("POST /v1/account/verification/complete", () => refusal(400, "invalid_token"));
    api.install();
    renderPortal({ strict: true });

    expect(await screen.findByText(/no longer valid/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /send a new link/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /try again/i })).not.toBeInTheDocument();
    expect(api.to("POST", "/v1/account/verification/complete")).toHaveLength(1);
  });

  it("shows the reset form under StrictMode and submits the recovery token exactly once", async () => {
    const recovery = "fbr_RECOVERYTOKENnotarealsecret000000000";
    signedOut(api, `/reset-password?token=${recovery}`);
    api.on("POST /v1/account/recovery/complete", () => json({ recovered: true }));
    api.install();
    renderPortal({ strict: true });

    await screen.findByRole("heading", { name: /set a new password/i });
    expect(window.location.search).toBe("");
    await userEvent.type(
      await screen.findByLabelText(/^new password/i),
      "a new correct horse staple",
    );
    await userEvent.type(
      screen.getByLabelText(/confirm new password/i),
      "a new correct horse staple",
    );
    await userEvent.click(screen.getByRole("button", { name: /set password/i }));

    await screen.findByRole("heading", { name: /password set/i });
    expect(api.to("POST", "/v1/account/recovery/complete")).toHaveLength(1);
    expect(api.to("POST", "/v1/account/recovery/complete")[0]?.body).toMatchObject({
      token: recovery,
    });
    expect(window.location.href).not.toContain(recovery);
  });

  it("keeps a recovery token whose submission failed, and submits it again on retry", async () => {
    const recovery = "fbr_RECOVERYTOKENnotarealsecret000000000";
    signedOut(api, `/reset-password?token=${recovery}`);
    let attempts = 0;
    api.on("POST /v1/account/recovery/complete", () => {
      attempts += 1;
      return attempts === 1 ? refusal(503, "service_unavailable") : json({ recovered: true });
    });
    api.install();
    renderPortal({ strict: true });

    await screen.findByRole("heading", { name: /set a new password/i });
    await userEvent.type(
      await screen.findByLabelText(/^new password/i),
      "a new correct horse staple",
    );
    await userEvent.type(
      screen.getByLabelText(/confirm new password/i),
      "a new correct horse staple",
    );
    await userEvent.click(screen.getByRole("button", { name: /set password/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/could not be reached|at capacity/i);
    // The form is still there, with the token still held behind it.
    await userEvent.click(screen.getByRole("button", { name: /set password/i }));
    await screen.findByRole("heading", { name: /password set/i });
    expect(attempts).toBe(2);
  });

  it("after a reload the token is gone, and the page says to open the link again", async () => {
    // A reload is a new document: the URL was scrubbed, memory is empty. The page must not
    // pretend otherwise, and must not have kept the token anywhere a reload could find it.
    signedOut(api, "/reset-password");
    api.install();
    renderPortal({ strict: true });

    await screen.findByRole("heading", { name: /set a new password/i });
    expect(screen.getByText(/open the link from the email again/i)).toBeInTheDocument();
    expect(screen.queryByLabelText(/^new password/i)).not.toBeInTheDocument();
  });

  it("puts the token in the one request that consumes it, and nowhere else", async () => {
    signedOut(api, `/verify-email?token=${TOKEN}`);
    api.on("POST /v1/account/verification/complete", () => json({ verified: true }));
    api.install();
    renderPortal({ strict: true });

    await screen.findByRole("heading", { name: /address confirmed/i });
    const carriers = api.requests.filter((request) => JSON.stringify(request).includes(TOKEN));
    expect(carriers.map((request) => request.path)).toEqual(["/v1/account/verification/complete"]);
    expect(jar.all()).not.toContain(TOKEN);
    expect(window.location.href).not.toContain(TOKEN);
    // Browser storage would have thrown (vitest.setup.ts); reaching here means it was never touched.
  });
});

describe("accepting an invitation", () => {
  const INVITATION = "fbi_INVITATIONTOKENnotarealsecret000000000";
  const INVITED_PROFILE = profile({
    session: { session_id: SESSION_ID, workspace_id: null, role: null, expires_at: null },
  });

  function loginThatSucceeds(): void {
    api.on("POST /v1/account/login", () => {
      jar.set(SESSION_COOKIE, "fbs_NEWSESSIONnotarealsecret0000000000000000");
      jar.set(CSRF_COOKIE, CSRF_VALUE);
      api
        .reply("GET /v1/account", INVITED_PROFILE)
        .reply("GET /v1/account/workspaces", { workspaces: [] });
      return json({
        account_id: "x",
        session_id: SESSION_ID,
        csrf_token: CSRF_VALUE,
        expires_at: null,
      });
    });
  }

  function acceptanceThatSucceeds(): void {
    api.on("POST /v1/account/invitations/accept", () =>
      json({
        workspace_id: "33333333-3333-4333-8333-333333333333",
        membership_id: "m",
        role: "member",
        replayed: false,
      }),
    );
    api.on("PUT /v1/account/workspace", () => {
      api
        .reply("GET /v1/account", profile())
        .reply("GET /v1/account/workspaces", membershipList("member"))
        .reply("GET /v1/workspace", workspaceDetail("member"));
      return json({
        workspace_id: "33333333-3333-4333-8333-333333333333",
        role: "member",
        membership_id: "m",
      });
    });
  }

  function tokenAppearsOnlyInTheAcceptance(): void {
    const carriers = api.requests.filter((request) => JSON.stringify(request).includes(INVITATION));
    expect(carriers.map((request) => request.path)).toEqual(["/v1/account/invitations/accept"]);
    expect(carriers[0]?.body).toEqual({ token: INVITATION });
    expect(jar.all()).not.toContain(INVITATION);
    expect(window.location.href).not.toContain(INVITATION);
  }

  it("signed out: keeps the token, sends the visitor to sign in with a route as the continuation, and accepts after sign-in", async () => {
    signedOut(api, `/accept-invitation?token=${INVITATION}`);
    loginThatSucceeds();
    acceptanceThatSucceeds();
    api.install();
    renderPortal({ strict: true });

    // Publicly reachable: the guard did not redirect it away, and the token left the URL.
    await screen.findByRole("heading", { name: /sign in to accept this invitation/i });
    expect(window.location.pathname).toBe("/accept-invitation");
    expect(window.location.href).not.toContain(INVITATION);

    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    await screen.findByRole("heading", { name: /^sign in$/i });
    // The continuation is a checked internal route. The token is not in it.
    expect(window.location.search).toBe("?next=%2Faccept-invitation");

    await userEvent.type(screen.getByLabelText(/email address/i), "person@example.com");
    await userEvent.type(screen.getByLabelText(/password/i), "correct horse battery staple");
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    // Back on the invitation page, in the same mounted application, with the token still held.
    await screen.findByRole("heading", { name: /accept this invitation/i });
    expect(window.location.pathname).toBe("/accept-invitation");
    await userEvent.click(screen.getByRole("button", { name: /accept invitation/i }));

    await screen.findByRole("heading", { name: /overview/i });
    expect(api.to("POST", "/v1/account/invitations/accept")).toHaveLength(1);
    expect(api.to("PUT", "/v1/account/workspace")).toHaveLength(1);
    tokenAppearsOnlyInTheAcceptance();
  });

  it("signed out: the sign-up path carries the same continuation and comes back to accept", async () => {
    signedOut(api, `/accept-invitation?token=${INVITATION}`);
    api.on("POST /v1/account/signup", () => json({ status: "accepted" }, 202));
    loginThatSucceeds();
    acceptanceThatSucceeds();
    api.install();
    renderPortal({ strict: true });

    await screen.findByRole("heading", { name: /sign in to accept this invitation/i });
    await userEvent.click(screen.getByRole("link", { name: /create one/i }));
    await screen.findByRole("heading", { name: /create an account/i });
    expect(window.location.search).toBe("?next=%2Faccept-invitation");

    await userEvent.type(screen.getByLabelText(/email address/i), "invited@example.com");
    await userEvent.type(screen.getByLabelText(/^password/i), "correct horse battery staple");
    await userEvent.type(
      screen.getByLabelText(/confirm password/i),
      "correct horse battery staple",
    );
    await userEvent.click(screen.getByRole("button", { name: /create account/i }));

    // Verification happens through the emailed link, in whatever tab it opens. This tab keeps
    // the continuation on its way back to sign in.
    await screen.findByRole("heading", { name: /check your email/i });
    const back = screen.getByRole("link", { name: /back to sign in/i });
    expect(back).toHaveAttribute("href", "/login?next=%2Faccept-invitation");
    await userEvent.click(back);

    await screen.findByRole("heading", { name: /^sign in$/i });
    await userEvent.type(screen.getByLabelText(/email address/i), "invited@example.com");
    await userEvent.type(screen.getByLabelText(/password/i), "correct horse battery staple");
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    await screen.findByRole("heading", { name: /accept this invitation/i });
    await userEvent.click(screen.getByRole("button", { name: /accept invitation/i }));
    await screen.findByRole("heading", { name: /overview/i });
    tokenAppearsOnlyInTheAcceptance();
  });

  it("already signed in: accepts directly", async () => {
    jar.set(SESSION_COOKIE, "fbs_TESTSESSIONSECRETnotarealsecret000000000");
    jar.set(CSRF_COOKIE, CSRF_VALUE);
    window.history.replaceState(null, "", `/accept-invitation?token=${INVITATION}`);
    api
      .reply("GET /v1/account", INVITED_PROFILE)
      .reply("GET /v1/account/workspaces", { workspaces: [] });
    acceptanceThatSucceeds();
    api.install();
    renderPortal({ strict: true });

    await screen.findByRole("heading", { name: /accept this invitation/i });
    expect(screen.getByText(/person@example.com/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /accept invitation/i }));
    await screen.findByRole("heading", { name: /overview/i });
    tokenAppearsOnlyInTheAcceptance();
  });

  it("reports a spent, revoked or mis-addressed invitation without naming which", async () => {
    jar.set(SESSION_COOKIE, "fbs_TESTSESSIONSECRETnotarealsecret000000000");
    jar.set(CSRF_COOKIE, CSRF_VALUE);
    window.history.replaceState(null, "", `/accept-invitation?token=${INVITATION}`);
    api
      .reply("GET /v1/account", INVITED_PROFILE)
      .reply("GET /v1/account/workspaces", { workspaces: [] });
    api.on("POST /v1/account/invitations/accept", () => refusal(404, "not_found"));
    api.install();
    renderPortal({ strict: true });

    await screen.findByRole("heading", { name: /accept this invitation/i });
    await userEvent.click(screen.getByRole("button", { name: /accept invitation/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/cannot be accepted by the account you are signed in as/i);
    expect(alert.textContent).not.toContain(INVITATION);
    expect(window.location.pathname).toBe("/accept-invitation");
  });

  it("after a reload the token is gone, and the page says to open the link again", async () => {
    jar.set(SESSION_COOKIE, "fbs_TESTSESSIONSECRETnotarealsecret000000000");
    jar.set(CSRF_COOKIE, CSRF_VALUE);
    window.history.replaceState(null, "", "/accept-invitation");
    api
      .reply("GET /v1/account", INVITED_PROFILE)
      .reply("GET /v1/account/workspaces", { workspaces: [] });
    api.install();
    renderPortal({ strict: true });

    await screen.findByRole("heading", { name: /accept this invitation/i });
    expect(screen.getByText(/open the link from the email again/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /accept invitation/i })).not.toBeInTheDocument();
  });

  it("follows no off-site continuation: the route after sign-in is the invitation page and nothing else", async () => {
    // The invitation page fixes its own continuation. A hostile next= on the sign-in page it
    // hands off to is refused by the same whitelist every destination goes through.
    signedOut(api, `/accept-invitation?token=${INVITATION}`);
    api.install();
    renderPortal({ strict: true });

    await screen.findByRole("heading", { name: /sign in to accept this invitation/i });
    expect(screen.getByRole("link", { name: /create one/i })).toHaveAttribute(
      "href",
      "/signup?next=%2Faccept-invitation",
    );
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    expect(window.location.pathname + window.location.search).toBe(
      "/login?next=%2Faccept-invitation",
    );
  });
});

describe("a session that ends while a page is open", () => {
  it("sends the customer to sign in and remembers where they were", async () => {
    signedOut(api, "/settings/team");
    api.install();
    renderPortal();

    await waitFor(() => expect(window.location.pathname).toBe("/login"));
    expect(window.location.search).toContain("next=%2Fsettings%2Fteam");
  });

  it("does not sign the customer out on a server error", async () => {
    // Only a 401 means "not signed in". A 500 must leave the session alone, or a transient
    // failure logs everybody out.
    window.history.replaceState(null, "", "/");
    jar.set(SESSION_COOKIE, "fbs_TESTSESSIONSECRETnotarealsecret000000000");
    jar.set(CSRF_COOKIE, CSRF_VALUE);
    api.on("GET /v1/account", () => refusal(500, "internal_error"));
    api.install();
    renderPortal();

    // The provider treats an unreachable API as "show the sign-in page" rather than spinning
    // forever, but it must not have decided the session was invalid.
    await waitFor(() => expect(window.location.pathname).toBe("/login"));
    expect(jar.get(CSRF_COOKIE)).toBe(CSRF_VALUE);
  });
});
