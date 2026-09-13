/**
 * API credentials: issue, show once, rotate, revoke — and where the secret must never go.
 *
 * The leak tests are the point of this file. A freshly minted credential is the only
 * plaintext secret this portal receives besides the CSRF token, and it is shown once because
 * the database keeps a fingerprint and cannot produce it again. So each test that displays
 * one also asserts it did **not** reach the URL, browser storage, a cookie, a later request,
 * or the page after dismissal.
 */

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  CREDENTIAL_ID,
  FakeApi,
  jar,
  json,
  noContent,
  refusal,
  renderPortal,
  signedIn,
  WORKSPACE_ID,
} from "./harness.tsx";

let api: FakeApi;

const SECRET = "fbk_MINTEDCREDENTIALVALUEnotarealsecret000000";
const SECOND_SECRET = "fbk_ROTATEDCREDENTIALVALUEnotarealsecret00000";

function existing(overrides: Record<string, unknown> = {}) {
  return {
    workspace_id: WORKSPACE_ID,
    credentials: [
      {
        credential_id: CREDENTIAL_ID,
        label: "ci",
        scopes: ["workspace:read"],
        created_at: "2026-09-01T10:00:00+00:00",
        expires_at: null,
        revoked_at: null,
        last_used_at: null,
        rotated_from_id: null,
        membership_id: "m1",
        email: "person@example.com",
        active: true,
        ...overrides,
      },
    ],
  };
}

beforeEach(() => {
  api = new FakeApi();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("issuing", () => {
  it("shows the secret exactly once, and says why it cannot be shown again", async () => {
    signedIn(api, "/settings/credentials", "owner");
    api.reply("GET /v1/workspace/credentials", { workspace_id: WORKSPACE_ID, credentials: [] });
    api.on("POST /v1/workspace/credentials", () =>
      json(
        {
          credential_id: CREDENTIAL_ID,
          scopes: ["workspace:read", "mutation:execute"],
          expires_at: null,
          rotated_from_id: null,
          replayed: false,
          credential: SECRET,
        },
        201,
      ),
    );
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    await userEvent.click(screen.getByRole("button", { name: /create credential/i }));

    const panel = await screen.findByRole("alert", { name: /copy this key now/i });
    expect(within(panel).getByText(SECRET)).toBeInTheDocument();
    expect(panel).toHaveTextContent(/only time it is shown/i);
    expect(panel).toHaveTextContent(/fingerprint/i);
  });

  it("keeps the secret out of the URL, storage, cookies and every later request", async () => {
    signedIn(api, "/settings/credentials", "owner");
    api.reply("GET /v1/workspace/credentials", { workspace_id: WORKSPACE_ID, credentials: [] });
    api.on("POST /v1/workspace/credentials", () =>
      json(
        {
          credential_id: CREDENTIAL_ID,
          scopes: ["workspace:read"],
          expires_at: null,
          rotated_from_id: null,
          replayed: false,
          credential: SECRET,
        },
        201,
      ),
    );
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    await userEvent.click(screen.getByRole("button", { name: /create credential/i }));
    await screen.findByRole("alert", { name: /copy this key now/i });

    expect(window.location.href).not.toContain(SECRET);
    expect(window.location.search).toBe("");
    expect(jar.all()).not.toContain(SECRET);
    expect(document.cookie).not.toContain("fbk_");
    // The reload the page performs after issuing must not echo the secret back.
    expect(api.anyCarried(SECRET)).toBe(false);
    // And the storage guard in vitest.setup.ts proves nothing wrote it to localStorage,
    // because any access at all would have thrown.
  });

  it("removes the secret from the page when dismissed, and does not bring it back", async () => {
    signedIn(api, "/settings/credentials", "owner");
    api.reply("GET /v1/workspace/credentials", { workspace_id: WORKSPACE_ID, credentials: [] });
    api.on("POST /v1/workspace/credentials", () =>
      json(
        {
          credential_id: CREDENTIAL_ID,
          scopes: ["workspace:read"],
          expires_at: null,
          rotated_from_id: null,
          replayed: false,
          credential: SECRET,
        },
        201,
      ),
    );
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    await userEvent.click(screen.getByRole("button", { name: /create credential/i }));
    await screen.findByRole("alert", { name: /copy this key now/i });

    await userEvent.click(screen.getByRole("button", { name: /i have saved it/i }));

    await waitFor(() => expect(screen.queryByText(SECRET)).not.toBeInTheDocument());
    expect(document.body.textContent).not.toContain(SECRET);
  });

  it("treats a replay as already-issued rather than as an empty secret", async () => {
    signedIn(api, "/settings/credentials", "owner");
    api.reply("GET /v1/workspace/credentials", existing());
    api.on("POST /v1/workspace/credentials", () =>
      json({
        credential_id: CREDENTIAL_ID,
        scopes: ["workspace:read"],
        expires_at: null,
        rotated_from_id: null,
        replayed: true,
        // The database returns null on a replay: the secret was displayed when it was
        // minted and genuinely cannot be produced again.
        credential: null,
      }),
    );
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    await userEvent.click(screen.getByRole("button", { name: /create credential/i }));

    expect(await screen.findByText(/already issued/i)).toBeInTheDocument();
    expect(screen.queryByRole("alert", { name: /copy this key now/i })).not.toBeInTheDocument();
  });

  it("sends only the scopes that were ticked, and an idempotency key", async () => {
    signedIn(api, "/settings/credentials", "owner");
    api.reply("GET /v1/workspace/credentials", { workspace_id: WORKSPACE_ID, credentials: [] });
    api.on("POST /v1/workspace/credentials", () =>
      json(
        {
          credential_id: CREDENTIAL_ID,
          scopes: [],
          expires_at: null,
          rotated_from_id: null,
          replayed: false,
          credential: SECRET,
        },
        201,
      ),
    );
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    // The defaults are workspace:read and mutation:execute; add the audit scope.
    await userEvent.click(screen.getByLabelText(/read the audit trail/i));
    await userEvent.click(screen.getByRole("button", { name: /create credential/i }));

    await waitFor(() => expect(api.to("POST", "/v1/workspace/credentials")).toHaveLength(1));
    const sent = api.to("POST", "/v1/workspace/credentials")[0];
    expect(sent?.body).toMatchObject({
      scopes: expect.arrayContaining(["workspace:read", "mutation:execute", "audit:read"]),
    });
    expect(sent?.headers["idempotency-key"]).toMatch(/^issue-[0-9a-f]{32}$/);
  });

  it("offers no scope outside the customer catalogue", async () => {
    signedIn(api, "/settings/credentials", "owner");
    api.reply("GET /v1/workspace/credentials", { workspace_id: WORKSPACE_ID, credentials: [] });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    const boxes = screen.getAllByRole("checkbox");
    expect(boxes.length).toBeGreaterThan(0);
    // credential:manage would mint a credential tied to no membership, and is issuable by
    // nobody; there is no supplier, capacity or settlement scope in the catalogue at all.
    const page = document.body.textContent ?? "";
    expect(page).not.toContain("credential:manage");
    expect(page).not.toContain("tenant:provision");
  });
});

describe("rotating", () => {
  it("shows the successor once and says the old key stopped", async () => {
    signedIn(api, "/settings/credentials", "owner");
    api.reply("GET /v1/workspace/credentials", existing());
    api.on("POST /v1/workspace/credentials/{id}/rotate", () =>
      json(
        {
          credential_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          scopes: ["workspace:read"],
          expires_at: null,
          rotated_from_id: CREDENTIAL_ID,
          replayed: false,
          credential: SECOND_SECRET,
        },
        201,
      ),
    );
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    await userEvent.click(screen.getByRole("button", { name: /rotate/i }));

    const panel = await screen.findByRole("alert", { name: /copy this key now/i });
    expect(within(panel).getByText(SECOND_SECRET)).toBeInTheDocument();
    expect(
      await screen.findByText(/previous key stopped working immediately/i),
    ).toBeInTheDocument();
    expect(api.anyCarried(SECOND_SECRET)).toBe(false);
  });

  it("reports the API's refusal when the caller is not the issuing member", async () => {
    signedIn(api, "/settings/credentials", "admin");
    api.reply("GET /v1/workspace/credentials", existing({ email: "colleague@example.com" }));
    // Only the issuing member may rotate; a manager revokes instead.
    api.on("POST /v1/workspace/credentials/{id}/rotate", () => refusal(404, "not_found"));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    await userEvent.click(screen.getByRole("button", { name: /rotate/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/not yours to see|not here/i);
  });
});

describe("revoking", () => {
  it("revokes and says it takes effect immediately", async () => {
    signedIn(api, "/settings/credentials", "owner");
    api.reply("GET /v1/workspace/credentials", existing());
    api.on("DELETE /v1/workspace/credentials/{id}", () => noContent());
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    await userEvent.click(screen.getByRole("button", { name: /revoke/i }));

    expect(await screen.findByText(/stops working immediately/i)).toBeInTheDocument();
  });

  it("renders a revoked credential's state as a word, not only as a colour", async () => {
    signedIn(api, "/settings/credentials", "owner");
    api.reply(
      "GET /v1/workspace/credentials",
      existing({ revoked_at: "2026-09-02T10:00:00+00:00", active: false }),
    );
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    expect(screen.getByText("revoked")).toBeInTheDocument();
    // And its actions are unavailable, with a reason rather than silently.
    const row = screen.getByText("revoked").closest("tr") as HTMLElement;
    const revoke = within(row).getByRole("button", { name: /revoke/i });
    expect(revoke).toBeDisabled();
    expect(
      document.getElementById(revoke.getAttribute("aria-describedby") as string),
    ).toHaveTextContent(/no longer active/i);
  });
});

describe("history", () => {
  it("is offered to a role that can read the audit trail, and opens in a dialog", async () => {
    signedIn(api, "/settings/credentials", "admin");
    api.reply("GET /v1/workspace/credentials", existing());
    api.on("GET /v1/workspace/credentials/{id}/history", () =>
      json({
        credential_id: CREDENTIAL_ID,
        workspace_id: WORKSPACE_ID,
        history: [
          {
            audit_event_id: "e1",
            action: "credential.issued",
            outcome: "completed",
            actor_kind: "session",
            actor_account_id: "a1",
            occurred_at: "2026-09-01T10:00:00+00:00",
            details: {},
          },
        ],
      }),
    );
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    await userEvent.click(screen.getByRole("button", { name: /history/i }));

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("credential.issued")).toBeInTheDocument();
  });

  it("is not offered to a member, who does not hold audit:read", async () => {
    signedIn(api, "/settings/credentials", "member");
    api.reply("GET /v1/workspace/credentials", existing());
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    expect(screen.queryByRole("button", { name: /history/i })).not.toBeInTheDocument();
  });
});

describe("empty state", () => {
  it("says there are none rather than showing a placeholder row", async () => {
    signedIn(api, "/settings/credentials", "owner");
    api.reply("GET /v1/workspace/credentials", { workspace_id: WORKSPACE_ID, credentials: [] });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    expect(screen.getByText(/no credentials yet/i)).toBeInTheDocument();
    // No table at all, rather than a table of fabricated rows.
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });
});
