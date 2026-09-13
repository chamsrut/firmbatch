/**
 * Permission-aware controls, and the rule that makes them safe to have at all.
 *
 * **Hiding a control is not authorization.** These tests assert both halves: that a viewer is
 * shown a disabled control *with a reason* rather than a mystery, and that when the server
 * refuses an operation anyway -- because the role changed after the page was drawn -- the
 * portal believes the server, re-reads its authority, and re-renders. The interface follows
 * the server; it never substitutes for it.
 */

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { shows } from "../src/auth/session.tsx";
import {
  FakeApi,
  json,
  MEMBERSHIP_ID,
  membershipList,
  noContent,
  refusal,
  renderPortal,
  signedIn,
  WORKSPACE_ID,
  workspaceDetail,
} from "./harness.tsx";

let api: FakeApi;

const OTHER_MEMBERSHIP = "88888888-8888-4888-8888-888888888888";

function team(role: string): void {
  api
    .reply("GET /v1/workspace/members", {
      workspace_id: WORKSPACE_ID,
      members: [
        {
          membership_id: MEMBERSHIP_ID,
          account_id: "a1",
          email: "owner@example.com",
          role: "owner",
          joined_at: null,
        },
        {
          membership_id: OTHER_MEMBERSHIP,
          account_id: "a2",
          email: "colleague@example.com",
          role: role === "owner" ? "member" : "member",
          joined_at: null,
        },
      ],
    })
    .reply("GET /v1/workspace/invitations", { workspace_id: WORKSPACE_ID, invitations: [] });
}

beforeEach(() => {
  api = new FakeApi();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the rendering predicates", () => {
  it("describe what to show, and are named so they cannot be mistaken for authority", () => {
    expect(shows.teamManagement("owner")).toBe(true);
    expect(shows.teamManagement("admin")).toBe(true);
    expect(shows.teamManagement("member")).toBe(false);
    expect(shows.teamManagement("viewer")).toBe(false);
    expect(shows.teamManagement(null)).toBe(false);

    expect(shows.ownerActions("owner")).toBe(true);
    expect(shows.ownerActions("admin")).toBe(false);

    expect(shows.credentialIssuing("member")).toBe(true);
    expect(shows.credentialIssuing("viewer")).toBe(false);

    expect(shows.auditHistory("admin")).toBe(true);
    expect(shows.auditHistory("member")).toBe(false);
  });
});

describe("a viewer", () => {
  it("sees the team and is told why it cannot change it", async () => {
    signedIn(api, "/settings/team", "viewer");
    team("viewer");
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /^team$/i });
    expect(
      screen.getByText(/inviting, removing and changing roles needs an owner or an admin/i),
    ).toBeInTheDocument();

    const invite = screen.getByRole("button", { name: /send invitation/i });
    expect(invite).toBeDisabled();
    // A disabled control with no explanation is how an interface tells somebody they did
    // something wrong. The reason is present and is associated with the control.
    const describedBy = invite.getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    expect(document.getElementById(describedBy as string)).toHaveTextContent(
      /only an owner or an admin can invite people/i,
    );
  });

  it("cannot change this workspace's stated policy, and is told so", async () => {
    signedIn(api, "/settings/preferences", "viewer");
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
        current_consent_version: "provider-policy-v1-d.1",
      })
      .reply("GET /v1/consent", {
        version: "provider-policy-v1-d.1",
        title: "Consent",
        authority: "Target D.1",
        sections: [],
        current_version: "provider-policy-v1-d.1",
        versions: ["provider-policy-v1-d.1"],
      });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /policy and preferences/i });
    const save = screen.getByRole("button", { name: /^save$/i });
    expect(save).toBeDisabled();
    expect(
      document.getElementById(save.getAttribute("aria-describedby") as string),
    ).toHaveTextContent(/a viewer cannot change/i);
  });

  it("cannot create an API credential, and is told so", async () => {
    signedIn(api, "/settings/credentials", "viewer");
    api.reply("GET /v1/workspace/credentials", { workspace_id: WORKSPACE_ID, credentials: [] });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    const create = screen.getByRole("button", { name: /create credential/i });
    expect(create).toBeDisabled();
    expect(
      document.getElementById(create.getAttribute("aria-describedby") as string),
    ).toHaveTextContent(/a viewer cannot create api credentials/i);
  });
});

describe("owner-only rules, stated where they bite", () => {
  it("an admin cannot remove an owner, and the control says why", async () => {
    signedIn(api, "/settings/team", "admin");
    // Two owners, so the refusal under test is "only an owner may act on an owner" rather
    // than the last-owner rule, which would otherwise be the binding reason and would make
    // this test pass for the wrong cause.
    api
      .reply("GET /v1/workspace/members", {
        workspace_id: WORKSPACE_ID,
        members: [
          {
            membership_id: MEMBERSHIP_ID,
            account_id: "a1",
            email: "owner@example.com",
            role: "owner",
            joined_at: null,
          },
          {
            membership_id: "99999999-9999-4999-8999-999999999999",
            account_id: "a3",
            email: "second-owner@example.com",
            role: "owner",
            joined_at: null,
          },
          {
            membership_id: OTHER_MEMBERSHIP,
            account_id: "a2",
            email: "colleague@example.com",
            role: "member",
            joined_at: null,
          },
        ],
      })
      .reply("GET /v1/workspace/invitations", { workspace_id: WORKSPACE_ID, invitations: [] });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /^team$/i });
    const ownerRow = screen.getByText("owner@example.com").closest("tr") as HTMLElement;
    const remove = within(ownerRow).getByRole("button", { name: /remove/i });
    expect(remove).toBeDisabled();
    expect(
      document.getElementById(remove.getAttribute("aria-describedby") as string),
    ).toHaveTextContent(/only an owner can remove an owner/i);
  });

  it("the last owner cannot be removed, even by themselves", async () => {
    signedIn(api, "/settings/team", "owner");
    api
      .reply("GET /v1/workspace/members", {
        workspace_id: WORKSPACE_ID,
        members: [
          {
            membership_id: MEMBERSHIP_ID,
            account_id: "a1",
            email: "owner@example.com",
            role: "owner",
            joined_at: null,
          },
        ],
      })
      .reply("GET /v1/workspace/invitations", { workspace_id: WORKSPACE_ID, invitations: [] });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /^team$/i });
    const ownerRow = screen.getByText("owner@example.com").closest("tr") as HTMLElement;
    const remove = within(ownerRow).getByRole("button", { name: /remove/i });
    expect(remove).toBeDisabled();
    expect(
      document.getElementById(remove.getAttribute("aria-describedby") as string),
    ).toHaveTextContent(/must keep at least one owner/i);
  });

  it("an admin is not offered the owner role when inviting", async () => {
    signedIn(api, "/settings/team", "admin");
    team("admin");
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /^team$/i });
    const roleSelect = screen.getByLabelText(/^role$/i);
    const options = within(roleSelect)
      .getAllByRole("option")
      .map((o) => o.getAttribute("value"));
    expect(options).not.toContain("owner");
    expect(options).toContain("admin");
  });

  it("an owner is offered it", async () => {
    signedIn(api, "/settings/team", "owner");
    team("owner");
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /^team$/i });
    const roleSelect = screen.getByLabelText(/^role$/i);
    const options = within(roleSelect)
      .getAllByRole("option")
      .map((o) => o.getAttribute("value"));
    expect(options).toContain("owner");
  });
});

describe("an owner acting normally", () => {
  it("removes a member and says what the removal took with it", async () => {
    signedIn(api, "/settings/team", "owner");
    team("owner");
    api.on("DELETE /v1/workspace/members/{id}", () => noContent());
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /^team$/i });
    const row = screen.getByText("colleague@example.com").closest("tr") as HTMLElement;
    await userEvent.click(within(row).getByRole("button", { name: /remove/i }));

    // The membership trigger revokes every credential that membership issued. Saying so is
    // the difference between a customer understanding the consequence and being surprised.
    expect(
      await screen.findByText(/their credentials for this workspace are revoked/i),
    ).toBeInTheDocument();
  });

  it("invites with an idempotency key", async () => {
    signedIn(api, "/settings/team", "owner");
    team("owner");
    api.on("POST /v1/workspace/invitations", () =>
      json({ invitation_id: "i1", role: "member", expires_at: null, replayed: false }, 201),
    );
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /^team$/i });
    await userEvent.type(screen.getByLabelText(/email address/i), "new@example.com");
    await userEvent.click(screen.getByRole("button", { name: /send invitation/i }));

    await waitFor(() => expect(api.to("POST", "/v1/workspace/invitations")).toHaveLength(1));
    expect(api.to("POST", "/v1/workspace/invitations")[0]?.headers["idempotency-key"]).toMatch(
      /^invite-[0-9a-f]{32}$/,
    );
  });
});

describe("demotion while the page is open", () => {
  it("believes the server's 403, re-reads authority, and re-renders as the new role", async () => {
    signedIn(api, "/settings/team", "owner");
    team("owner");
    // The customer was demoted to viewer between the page loading and this click.
    api.on("DELETE /v1/workspace/members/{id}", () => refusal(403, "forbidden"));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /^team$/i });
    const row = screen.getByText("colleague@example.com").closest("tr") as HTMLElement;

    // From here on the server reports the new role.
    api
      .reply("GET /v1/workspace", workspaceDetail("viewer"))
      .reply("GET /v1/account/workspaces", membershipList("viewer"));

    await userEvent.click(within(row).getByRole("button", { name: /remove/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/does not allow that/i);
    // The interface has caught up: the controls are now a viewer's.
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /send invitation/i })).toBeDisabled(),
    );
  });

  it("does not take a 401 during an action as the session ending on its own: one safe read decides", async () => {
    // A mutation's 401 is ambiguous -- a wrong CSRF secret on a live session gets the same
    // neutral refusal -- so the session is asked about once, and here it answers that it is
    // live. The definitive cases, read 401 and checked-and-gone, are in auth-flows.test.tsx.
    signedIn(api, "/settings/credentials", "member");
    api.reply("GET /v1/workspace/credentials", { workspace_id: WORKSPACE_ID, credentials: [] });
    api.on("POST /v1/workspace/credentials", () => refusal(401, "authentication_required"));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    await userEvent.click(screen.getByRole("button", { name: /create credential/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/still open/i);
    expect(window.location.pathname).toBe("/settings/credentials");
    // The page's own load, and exactly one validity read after the refusal.
    expect(api.to("GET", "/v1/account")).toHaveLength(2);
  });
});
