/**
 * The signed-in password change, session management, and rendering escapes.
 *
 * The password change is the flow Milestone 3.1 left to 3.2, and the properties under test
 * are the ones that make it safe rather than the ones that make it work: the current password
 * is required and is cleared on every failure, the drastic consequence is stated *before* it
 * happens, a concurrent change is reported as "nothing was changed here", and the replacement
 * session's cookies are what the page carries on with.
 */

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  CSRF_COOKIE,
  CSRF_VALUE,
  FakeApi,
  jar,
  json,
  noContent,
  profile,
  refusal,
  renderPortal,
  SESSION_ID,
  signedIn,
  WORKSPACE_ID,
} from "./harness.tsx";

let api: FakeApi;

/** The session a password change leaves behind: same account, new identity. */
const REPLACEMENT_SESSION = "77777777-7777-4777-8777-777777777777";

const CURRENT = "the current password here";
const REPLACEMENT = "a different password entirely";

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
      {
        session_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        created_at: "2026-09-08T09:00:00+00:00",
        last_seen_at: "2026-09-08T10:00:00+00:00",
        expires_at: "2026-09-09T21:00:00+00:00",
        workspace_id: null,
        current: false,
      },
    ],
  });
}

async function fillPasswordForm(current = CURRENT, next = REPLACEMENT): Promise<void> {
  await userEvent.type(screen.getByLabelText(/current password/i), current);
  await userEvent.type(screen.getByLabelText(/^new password/i), next);
  await userEvent.type(screen.getByLabelText(/confirm new password/i), next);
}

beforeEach(() => {
  api = new FakeApi();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("changing a password while signed in", () => {
  it("states the consequence before it is done", async () => {
    signedIn(api, "/account/security", "owner");
    withSessions();
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /^security$/i });
    // A customer must know that this ends every other session and revokes their API
    // credentials *before* they do it, not afterwards. The sentence is deliberately broken
    // across an emphasis element, so it is matched against the paragraph's text.
    const warning = screen
      .getAllByText(/changing your password/i)
      .map((node) => node.textContent ?? "")
      .join(" ");
    expect(warning).toMatch(/signs out every other session/i);
    expect(warning).toMatch(/revokes every api credential you have issued/i);
  });

  it("sends the current and the new password, and nothing else", async () => {
    signedIn(api, "/account/security", "owner");
    withSessions();
    api.on("POST /v1/account/password", () => {
      api.reply(
        "GET /v1/account",
        profile({ session: { ...profile().session, session_id: REPLACEMENT_SESSION } }),
      );
      // The API replaces the session and sets both cookies on this response.
      jar.set(CSRF_COOKIE, "fbc_REPLACEMENTCSRFnotarealsecret0000000000");
      return json({
        account_id: "a1",
        session_id: REPLACEMENT_SESSION,
        csrf_token: "fbc_REPLACEMENTCSRFnotarealsecret0000000000",
        expires_at: null,
        other_sessions_revoked: true,
      });
    });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /^security$/i });
    await fillPasswordForm();
    await userEvent.click(screen.getByRole("button", { name: /change password/i }));

    await waitFor(() => expect(api.to("POST", "/v1/account/password")).toHaveLength(1));
    const sent = api.to("POST", "/v1/account/password")[0];
    expect(sent?.body).toEqual({ current_password: CURRENT, new_password: REPLACEMENT });
    // Cookie-authenticated, so it carried the CSRF secret.
    expect(sent?.headers["x-csrf-token"]).toBe(CSRF_VALUE);
  });

  it("clears the fields and carries on with the replacement session", async () => {
    signedIn(api, "/account/security", "owner");
    withSessions();
    const replacement = "fbc_REPLACEMENTCSRFnotarealsecret0000000000";
    api.on("POST /v1/account/password", () => {
      api.reply(
        "GET /v1/account",
        profile({ session: { ...profile().session, session_id: REPLACEMENT_SESSION } }),
      );
      jar.set(CSRF_COOKIE, replacement);
      return json({
        account_id: "a1",
        session_id: REPLACEMENT_SESSION,
        csrf_token: replacement,
        expires_at: null,
        other_sessions_revoked: true,
      });
    });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /^security$/i });
    await fillPasswordForm();
    await userEvent.click(screen.getByRole("button", { name: /change password/i }));

    expect(await screen.findByText(/password changed/i)).toBeInTheDocument();
    // The plaintext passwords stop existing in the form at the earliest moment.
    expect(screen.getByLabelText(/current password/i)).toHaveValue("");
    expect(screen.getByLabelText(/^new password/i)).toHaveValue("");
    // The page is still signed in, on the replacement session's CSRF secret.
    expect(jar.get(CSRF_COOKIE)).toBe(replacement);
    expect(screen.queryByRole("heading", { name: /^sign in$/i })).not.toBeInTheDocument();
  });

  it("refuses a wrong current password and clears the field", async () => {
    signedIn(api, "/account/security", "owner");
    withSessions();
    api.on("POST /v1/account/password", () => refusal(401, "invalid_credentials"));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /^security$/i });
    await fillPasswordForm("the wrong password");
    await userEvent.click(screen.getByRole("button", { name: /change password/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/current password is not right/i);
    // A 401 here cannot mean "session gone": the same request already proved the cookie.
    expect(screen.queryByText(/session has ended/i)).not.toBeInTheDocument();
    expect(screen.getByLabelText(/current password/i)).toHaveValue("");
  });

  it("reports a concurrent change as 'nothing was changed here'", async () => {
    signedIn(api, "/account/security", "owner");
    withSessions();
    // The compare-and-swap lost: another session, or a recovery link, replaced the password
    // while this request was running Argon2.
    api.on("POST /v1/account/password", () => refusal(409, "conflict"));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /^security$/i });
    await fillPasswordForm();
    await userEvent.click(screen.getByRole("button", { name: /change password/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/changed somewhere else/i);
    // The alternative reading -- "did it half work?" -- is what makes somebody retry in a
    // panic, so the message says plainly that nothing happened.
    expect(alert).toHaveTextContent(/nothing was changed here/i);
  });

  it("refuses a mismatched confirmation before sending anything", async () => {
    signedIn(api, "/account/security", "owner");
    withSessions();
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /^security$/i });
    await userEvent.type(screen.getByLabelText(/current password/i), CURRENT);
    await userEvent.type(screen.getByLabelText(/^new password/i), REPLACEMENT);
    await userEvent.type(screen.getByLabelText(/confirm new password/i), "not the same");
    await userEvent.click(screen.getByRole("button", { name: /change password/i }));

    expect(await screen.findByText(/do not match/i)).toBeInTheDocument();
    expect(api.to("POST", "/v1/account/password")).toHaveLength(0);
  });

  it("refuses to set the new password to the current one", async () => {
    signedIn(api, "/account/security", "owner");
    withSessions();
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /^security$/i });
    await fillPasswordForm(CURRENT, CURRENT);
    await userEvent.click(screen.getByRole("button", { name: /change password/i }));

    expect(await screen.findByText(/must be different from the current one/i)).toBeInTheDocument();
    expect(api.to("POST", "/v1/account/password")).toHaveLength(0);
  });

  it("never puts a password in a URL, a cookie or a later request", async () => {
    signedIn(api, "/account/security", "owner");
    withSessions();
    api.on("POST /v1/account/password", () => {
      api.reply(
        "GET /v1/account",
        profile({ session: { ...profile().session, session_id: REPLACEMENT_SESSION } }),
      );
      jar.set(CSRF_COOKIE, "fbc_REPLACEMENTCSRFnotarealsecret0000000000");
      return json({ account_id: "a1", session_id: SESSION_ID, csrf_token: "x", expires_at: null });
    });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /^security$/i });
    await fillPasswordForm();
    await userEvent.click(screen.getByRole("button", { name: /change password/i }));
    await waitFor(() => expect(api.to("POST", "/v1/account/password")).toHaveLength(1));

    expect(window.location.href).not.toContain(CURRENT.replace(/ /g, ""));
    expect(window.location.search).toBe("");
    expect(jar.all()).not.toContain("password");
    // The body of the one request that legitimately carries it is the only place it appears.
    const carriers = api.requests.filter((request) =>
      JSON.stringify(request.body ?? null).includes(REPLACEMENT),
    );
    expect(carriers).toHaveLength(1);
    expect(carriers[0]?.path).toBe("/v1/account/password");
  });
});

describe("session management", () => {
  it("lists sessions and marks which one is this browser", async () => {
    signedIn(api, "/account/security", "owner");
    withSessions();
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /^security$/i });
    // Scoped to the table: the password-change warning above it also mentions this browser,
    // which is correct there and would otherwise make this query ambiguous.
    const table = within(await screen.findByRole("table"));
    expect(table.getByText(/this browser/i)).toBeInTheDocument();
    expect(table.getByText(/another browser/i)).toBeInTheDocument();
  });

  it("revokes one other session", async () => {
    signedIn(api, "/account/security", "owner");
    withSessions();
    api.on("DELETE /v1/account/sessions/{id}", () => noContent());
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /^security$/i });
    const row = (await screen.findByText(/another browser/i)).closest("tr") as HTMLElement;
    await userEvent.click(within(row).getByRole("button", { name: /sign out/i }));

    expect(await screen.findByText(/that session has been signed out/i)).toBeInTheDocument();
  });

  it("keeps this browser when signing out of every other session", async () => {
    signedIn(api, "/account/security", "owner");
    withSessions();
    api.on("POST /v1/account/sessions/revoke-all", () => json({ revoked: 3 }));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /^security$/i });
    // The control lives below the session table, which appears only once the list loads.
    await userEvent.click(
      await screen.findByRole("button", { name: /sign out of every other session/i }),
    );

    await waitFor(() => expect(api.to("POST", "/v1/account/sessions/revoke-all")).toHaveLength(1));
    expect(api.to("POST", "/v1/account/sessions/revoke-all")[0]?.body).toEqual({
      keep_current: true,
    });
    expect(await screen.findByText(/signed out of 3 other sessions/i)).toBeInTheDocument();
  });
});

describe("rendering server-supplied text", () => {
  it("escapes markup in a workspace name rather than interpreting it", async () => {
    const hostile = '<img src=x onerror="alert(1)">';
    signedIn(api, "/settings/workspace", "owner");
    api.reply("GET /v1/workspace", {
      workspace_id: WORKSPACE_ID,
      slug: "acme",
      name: hostile,
      role: "owner",
      membership_id: "m",
      created_at: null,
    });
    api.install();
    renderPortal();

    // Rendered as text, exactly as sent.
    expect(await screen.findByDisplayValue(hostile)).toBeInTheDocument();
    // And not as an element: no img was created, and no handler exists to fire.
    expect(document.querySelector("img")).toBeNull();
  });

  it("escapes markup in a member's address", async () => {
    const hostile = "<script>alert(1)</script>@example.com";
    signedIn(api, "/settings/team", "owner");
    api
      .reply("GET /v1/workspace/members", {
        workspace_id: WORKSPACE_ID,
        members: [
          {
            membership_id: "m1",
            account_id: "a1",
            email: hostile,
            role: "owner",
            joined_at: null,
          },
        ],
      })
      .reply("GET /v1/workspace/invitations", { workspace_id: WORKSPACE_ID, invitations: [] });
    api.install();
    renderPortal();

    expect(await screen.findByText(hostile)).toBeInTheDocument();
    expect(document.querySelector("script")).toBeNull();
  });

  it("escapes markup in a consent paragraph", async () => {
    const hostile = "<iframe src=evil></iframe>";
    signedIn(api, "/settings/preferences", "owner");
    api
      .reply("GET /v1/workspace/preferences", {
        workspace_id: WORKSPACE_ID,
        region_policy: [],
        excluded_provider_classes: [],
        model_profile_note: null,
        evaluation_intent: "undecided",
        consent_version: null,
        consent_acknowledged_at: null,
        consent_account_id: null,
        updated_at: null,
        unservable_exclusion: false,
        current_consent_version: "v1",
      })
      .reply("GET /v1/consent", {
        version: "v1",
        title: "Consent",
        authority: "Target D.1",
        sections: [{ heading: "A section", body: [hostile] }],
        current_version: "v1",
        versions: ["v1"],
      });
    api.install();
    renderPortal();

    expect(await screen.findByText(hostile)).toBeInTheDocument();
    expect(document.querySelector("iframe")).toBeNull();
  });
});

describe("the account page", () => {
  it("shows verification status and offers a new link when unconfirmed", async () => {
    signedIn(api, "/account", "owner");
    api.reply("GET /v1/account", profile({ email_verified: false }));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /your account/i });
    expect(screen.getByText(/not yet/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /send a new confirmation link/i }),
    ).toBeInTheDocument();
  });

  it("says changing an address is not available rather than offering a dead control", async () => {
    signedIn(api, "/account", "owner");
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /your account/i });
    expect(screen.getByText(/changing it is not available yet/i)).toBeInTheDocument();
  });
});
