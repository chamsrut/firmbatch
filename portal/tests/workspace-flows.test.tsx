/**
 * The first-workspace journey, switching workspaces, and what happens when a membership
 * disappears underneath an open page.
 *
 * The gate case behind most of this is `AUTH-MEMBERSHIP-BOUND-IDENTITY` case 1: a verified
 * account with no membership keeps its account-level session and can create its first
 * workspace, and cannot bind a workspace it is not a member of by any route the interface
 * offers. Case 2 -- revocation stops the identity acting -- is the concurrent-demotion group
 * at the end.
 */

import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useEffect } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App.tsx";
import { type SessionApi, useSession } from "../src/auth/session.tsx";
import {
  CREDENTIAL_ID,
  CSRF_COOKIE,
  CSRF_VALUE,
  deferred,
  FakeApi,
  jar,
  json,
  MEMBERSHIP_ID,
  membershipList,
  OTHER_WORKSPACE_ID,
  profile,
  refusal,
  renderPortal,
  renderWithProviders,
  SESSION_COOKIE,
  SESSION_ID,
  signedIn,
  WORKSPACE_ID,
  workspaceDetail,
} from "./harness.tsx";

let api: FakeApi;

function signedInWithNoWorkspace(path = "/"): void {
  jar.set(SESSION_COOKIE, "fbs_TESTSESSIONSECRETnotarealsecret000000000");
  jar.set(CSRF_COOKIE, CSRF_VALUE);
  window.history.replaceState(null, "", path);
  api
    .reply(
      "GET /v1/account",
      profile({
        session: { session_id: SESSION_ID, workspace_id: null, role: null, expires_at: null },
      }),
    )
    .reply("GET /v1/account/workspaces", { workspaces: [] });
}

beforeEach(() => {
  api = new FakeApi();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("a verified account with no workspace", () => {
  it("keeps its session and is offered the first-workspace page", async () => {
    signedInWithNoWorkspace("/");
    api.install();
    renderPortal();

    // Not signed out, not an error: a real account-level session with nothing bound to it.
    await waitFor(() => expect(window.location.pathname).toBe("/workspaces/new"));
    expect(
      await screen.findByRole("heading", { name: /create your first workspace/i }),
    ).toBeInTheDocument();
  });

  it("creates the first workspace and selects it as a separate, revalidated step", async () => {
    signedInWithNoWorkspace("/workspaces/new");
    api.on("POST /v1/account/workspaces", () =>
      json(
        {
          workspace_id: WORKSPACE_ID,
          membership_id: MEMBERSHIP_ID,
          role: "owner",
          replayed: false,
        },
        201,
      ),
    );
    api.on("PUT /v1/account/workspace", () => {
      // Creating does not bind. Binding is its own call, and the server derives the
      // membership for it.
      api
        .reply("GET /v1/account", profile())
        .reply("GET /v1/account/workspaces", membershipList())
        .reply("GET /v1/workspace", workspaceDetail());
      return json({ workspace_id: WORKSPACE_ID, role: "owner", membership_id: MEMBERSHIP_ID });
    });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /create your first workspace/i });
    await userEvent.type(screen.getByLabelText(/workspace name/i), "Acme Research");
    await userEvent.click(screen.getByRole("button", { name: /create workspace/i }));

    expect(await screen.findByRole("heading", { name: /overview/i })).toBeInTheDocument();
    expect(api.to("POST", "/v1/account/workspaces")).toHaveLength(1);
    expect(api.to("PUT", "/v1/account/workspace")).toHaveLength(1);
  });

  it("derives a slug from the name and lets it be overridden", async () => {
    signedInWithNoWorkspace("/workspaces/new");
    api.on("POST /v1/account/workspaces", () =>
      json(
        {
          workspace_id: WORKSPACE_ID,
          membership_id: MEMBERSHIP_ID,
          role: "owner",
          replayed: false,
        },
        201,
      ),
    );
    api.on("PUT /v1/account/workspace", () => refusal(404, "not_found"));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /create your first workspace/i });
    await userEvent.type(screen.getByLabelText(/workspace name/i), "Acme Research!! 2026");
    expect(screen.getByLabelText(/short name/i)).toHaveValue("acme-research-2026");

    await userEvent.clear(screen.getByLabelText(/short name/i));
    await userEvent.type(screen.getByLabelText(/short name/i), "acme");
    await userEvent.click(screen.getByRole("button", { name: /create workspace/i }));

    await waitFor(() => expect(api.to("POST", "/v1/account/workspaces")).toHaveLength(1));
    expect(api.to("POST", "/v1/account/workspaces")[0]?.body).toMatchObject({ slug: "acme" });
  });

  it("carries an idempotency key on creation, so a retry cannot make two workspaces", async () => {
    signedInWithNoWorkspace("/workspaces/new");
    api.on("POST /v1/account/workspaces", () =>
      json(
        {
          workspace_id: WORKSPACE_ID,
          membership_id: MEMBERSHIP_ID,
          role: "owner",
          replayed: false,
        },
        201,
      ),
    );
    api.on("PUT /v1/account/workspace", () => refusal(404, "not_found"));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /create your first workspace/i });
    await userEvent.type(screen.getByLabelText(/workspace name/i), "Acme");
    await userEvent.click(screen.getByRole("button", { name: /create workspace/i }));

    await waitFor(() => expect(api.to("POST", "/v1/account/workspaces")).toHaveLength(1));
    expect(api.to("POST", "/v1/account/workspaces")[0]?.headers["idempotency-key"]).toMatch(
      /^ws-[0-9a-f]{32}$/,
    );
  });

  it("reports a taken short name without claiming the workspace exists elsewhere", async () => {
    signedInWithNoWorkspace("/workspaces/new");
    api.on("POST /v1/account/workspaces", () => refusal(409, "conflict"));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /create your first workspace/i });
    await userEvent.type(screen.getByLabelText(/workspace name/i), "Acme");
    await userEvent.click(screen.getByRole("button", { name: /create workspace/i }));

    const alert = await screen.findByRole("alert");
    // Tenant-local uniqueness: the message speaks about "here", never about another tenant.
    expect(alert).toHaveTextContent(/already exists here/i);
  });
});

describe("switching workspaces", () => {
  it("asks the server to select, and re-reads the role from the binding", async () => {
    signedIn(api, "/");
    api.reply("GET /v1/account/workspaces", {
      workspaces: [
        ...membershipList("owner").workspaces,
        {
          workspace_id: OTHER_WORKSPACE_ID,
          slug: "beta",
          name: "Beta",
          role: "viewer",
          membership_id: "77777777-7777-4777-8777-777777777777",
          joined_at: null,
        },
      ],
    });
    api.on("PUT /v1/account/workspace", () => {
      api.reply("GET /v1/workspace", {
        ...workspaceDetail("viewer"),
        workspace_id: OTHER_WORKSPACE_ID,
        name: "Beta",
      });
      api.reply(
        "GET /v1/account",
        profile({
          session: {
            session_id: SESSION_ID,
            workspace_id: OTHER_WORKSPACE_ID,
            role: "viewer",
            expires_at: null,
          },
        }),
      );
      return json({ workspace_id: OTHER_WORKSPACE_ID, role: "viewer", membership_id: "x" });
    });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /overview/i });
    await userEvent.selectOptions(screen.getByLabelText(/^workspace$/i), OTHER_WORKSPACE_ID);

    await waitFor(() => expect(api.to("PUT", "/v1/account/workspace")).toHaveLength(1));
    // The role came from GET /v1/workspace after the bind, not from the list the switcher
    // was drawn from: the binding is what the next request is evaluated against.
    await waitFor(() => expect(api.to("GET", "/v1/workspace").length).toBeGreaterThan(1));
  });

  it("refuses a workspace the membership no longer covers, and refreshes the list", async () => {
    signedIn(api, "/");
    api.reply("GET /v1/account/workspaces", {
      workspaces: [
        ...membershipList("owner").workspaces,
        {
          workspace_id: OTHER_WORKSPACE_ID,
          slug: "beta",
          name: "Beta",
          role: "member",
          membership_id: "77777777-7777-4777-8777-777777777777",
          joined_at: null,
        },
      ],
    });
    // The membership was revoked between the list being drawn and this click.
    api.on("PUT /v1/account/workspace", () => refusal(404, "not_found"));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /overview/i });
    await userEvent.selectOptions(screen.getByLabelText(/^workspace$/i), OTHER_WORKSPACE_ID);

    expect(await screen.findByText(/no longer available to you/i)).toBeInTheDocument();
  });
});

describe("a membership revoked while the page is open", () => {
  it("sends the customer to the picker rather than showing a workspace they have lost", async () => {
    jar.set(SESSION_COOKIE, "fbs_TESTSESSIONSECRETnotarealsecret000000000");
    jar.set(CSRF_COOKIE, CSRF_VALUE);
    window.history.replaceState(null, "", "/settings/team");
    // The session row still points at a workspace; the membership behind it is gone, so the
    // server refuses to establish the workspace context.
    api
      .reply("GET /v1/account", profile())
      .reply("GET /v1/account/workspaces", { workspaces: [] })
      .on("GET /v1/workspace", () => refusal(412, "workspace_required"));
    api.install();
    renderPortal();

    await waitFor(() => expect(window.location.pathname).toBe("/workspaces/new"));
  });

  it("offers the picker when other memberships remain", async () => {
    jar.set(SESSION_COOKIE, "fbs_TESTSESSIONSECRETnotarealsecret000000000");
    jar.set(CSRF_COOKIE, CSRF_VALUE);
    window.history.replaceState(null, "", "/settings/team");
    api
      .reply("GET /v1/account", profile())
      .reply("GET /v1/account/workspaces", membershipList("member"))
      .on("GET /v1/workspace", () => refusal(412, "workspace_required"));
    api.install();
    renderPortal();

    await waitFor(() => expect(window.location.pathname).toBe("/workspaces"));
    expect(await screen.findByRole("heading", { name: /choose a workspace/i })).toBeInTheDocument();
  });
});

describe("the workspace picker", () => {
  it("lists only this account's own memberships, with no way to look up another", async () => {
    jar.set(SESSION_COOKIE, "fbs_TESTSESSIONSECRETnotarealsecret000000000");
    jar.set(CSRF_COOKIE, CSRF_VALUE);
    window.history.replaceState(null, "", "/workspaces");
    api
      .reply(
        "GET /v1/account",
        profile({
          session: { session_id: SESSION_ID, workspace_id: null, role: null, expires_at: null },
        }),
      )
      .reply("GET /v1/account/workspaces", membershipList("member"));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /choose a workspace/i });
    const list = screen.getByRole("list");
    expect(within(list).getAllByRole("button")).toHaveLength(1);
    // No search field, no "join by id", nothing that could answer whether a workspace exists.
    expect(screen.queryByRole("searchbox")).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/workspace id/i)).not.toBeInTheDocument();
  });
});

// ------------------------------------------- selection, refresh order and the page lifecycle

/** Hands the live session context to a test, for driving the provider directly. */
function Probe({ expose }: { expose: (session: SessionApi) => void }) {
  const session = useSession();
  useEffect(() => {
    expose(session);
  }, [session, expose]);
  return null;
}

const realSetTimeout = globalThis.setTimeout.bind(globalThis);

/** Let every promise the portal has in flight run to completion, inside `act`. */
const settle = () => act(() => new Promise<void>((resolve) => realSetTimeout(resolve, 50)));

const OTHER_MEMBERSHIP = "99999999-9999-4999-8999-999999999999";

function twoMemberships() {
  return {
    workspaces: [
      ...membershipList("owner").workspaces,
      {
        workspace_id: OTHER_WORKSPACE_ID,
        slug: "beta",
        name: "Beta",
        role: "member",
        membership_id: OTHER_MEMBERSHIP,
        joined_at: "2026-09-02T10:00:00+00:00",
      },
    ],
  };
}

function profileBoundTo(workspace: string, role: string) {
  return profile({
    session: { session_id: SESSION_ID, workspace_id: workspace, role, expires_at: null },
  });
}

function detailOf(workspace: string, role: string, name: string) {
  return {
    ...workspaceDetail(role),
    workspace_id: workspace,
    name,
    membership_id: OTHER_MEMBERSHIP,
  };
}

function memberRow(email: string) {
  return { membership_id: MEMBERSHIP_ID, account_id: "a1", email, role: "owner", joined_at: null };
}

function members(workspace: string, email: string) {
  return { workspace_id: workspace, members: [memberRow(email)] };
}

function noInvitations(workspace: string) {
  return { workspace_id: workspace, invitations: [] };
}

/** The portal with a probe beside it, so a test can drive the provider while pages render. */
function renderWithProbe(): { session: SessionApi | null } {
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
  return probe;
}

describe("selecting a workspace", () => {
  it("publishes the binding the server returned at once, leaves for the overview, and keeps it when the follow-up read fails", async () => {
    signedIn(api, "/settings/team");
    api
      .reply("GET /v1/account/workspaces", twoMemberships())
      .reply("GET /v1/workspace/members", members(WORKSPACE_ID, "owner@example.com"))
      .reply("GET /v1/workspace/invitations", noInvitations(WORKSPACE_ID));
    let accountReads = 0;
    api.on("GET /v1/account", () => {
      accountReads += 1;
      // The first read is the page's own; the read after the switch fails.
      if (accountReads === 2) return refusal(503, "service_unavailable");
      return json(accountReads === 1 ? profile() : profileBoundTo(OTHER_WORKSPACE_ID, "member"));
    });
    api.on("PUT /v1/account/workspace", () => {
      api.reply("GET /v1/workspace", detailOf(OTHER_WORKSPACE_ID, "member", "Beta"));
      return json({
        workspace_id: OTHER_WORKSPACE_ID,
        role: "member",
        membership_id: OTHER_MEMBERSHIP,
      });
    });
    api.install();
    const probe = renderWithProbe();

    await screen.findByRole("heading", { name: /^team$/i });
    await userEvent.selectOptions(screen.getByLabelText(/^workspace$/i), OTHER_WORKSPACE_ID);

    // Selected, and at the overview, with the follow-up read having failed.
    await waitFor(() => expect(window.location.pathname).toBe("/"));
    await waitFor(() => expect(probe.session?.workspaceId).toBe(OTHER_WORKSPACE_ID));
    expect(probe.session?.role).toBe("member");
    expect(screen.getByLabelText(/^workspace$/i)).toHaveValue(OTHER_WORKSPACE_ID);
    const problem = await screen.findByRole("alert");
    expect(problem).toHaveTextContent(/could not be loaded/i);
    expect(screen.queryByText(/no longer available/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/could not be opened/i)).not.toBeInTheDocument();

    // The retry completes the picture without touching the binding.
    await userEvent.click(screen.getByRole("button", { name: /^retry$/i }));
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
    expect(probe.session?.workspaceId).toBe(OTHER_WORKSPACE_ID);
    expect(probe.session?.profile?.session.workspace_id).toBe(OTHER_WORKSPACE_ID);
    expect(api.to("PUT", "/v1/account/workspace")).toHaveLength(1);
  });

  it("never publishes one workspace's binding with another's role: an incoherent read is read again", async () => {
    signedIn(api, "/");
    api.reply("GET /v1/account/workspaces", twoMemberships());
    let accountReads = 0;
    let detailReads = 0;
    api.on("GET /v1/account", () => {
      accountReads += 1;
      // The page's load sees A. The refresh's first pass sees A, its second pass sees B --
      // the session was switched between two of its reads.
      return json(accountReads <= 2 ? profile() : profileBoundTo(OTHER_WORKSPACE_ID, "member"));
    });
    api.on("GET /v1/workspace", () => {
      detailReads += 1;
      return json(
        detailReads === 1
          ? workspaceDetail("owner")
          : detailOf(OTHER_WORKSPACE_ID, "member", "Beta"),
      );
    });
    api.install();
    const published: Array<[string | null, string | null]> = [];
    const probe: { session: SessionApi | null } = { session: null };
    renderWithProviders(
      <Probe
        expose={(session) => {
          probe.session = session;
          published.push([session.workspaceId, session.role]);
        }}
      />,
    );
    await waitFor(() => expect(probe.session?.workspaceId).toBe(WORKSPACE_ID));

    await act(async () => {
      await (probe.session as SessionApi).refresh();
    });
    await waitFor(() => expect(probe.session?.workspaceId).toBe(OTHER_WORKSPACE_ID));
    expect(probe.session?.role).toBe("member");
    // Two passes, and the mixed pair -- A's binding with B's role -- was never published.
    expect(accountReads).toBe(3);
    expect(detailReads).toBe(3);
    expect(published).not.toContainEqual([WORKSPACE_ID, "member"]);
  });

  it("drops a read that is incoherent twice, and says the account could not be loaded", async () => {
    signedIn(api, "/");
    api.reply("GET /v1/account/workspaces", twoMemberships());
    let detailReads = 0;
    api.on("GET /v1/workspace", () => {
      detailReads += 1;
      // The page's load is coherent; every pass of the refresh answers for another workspace.
      return json(
        detailReads === 1
          ? workspaceDetail("owner")
          : detailOf(OTHER_WORKSPACE_ID, "member", "Beta"),
      );
    });
    api.install();
    const probe = renderWithProbe();
    await screen.findByRole("heading", { name: /overview/i });

    await act(async () => {
      await (probe.session as SessionApi).refresh();
    });
    expect(detailReads).toBe(3);
    expect(probe.session?.workspaceId).toBe(WORKSPACE_ID);
    expect(probe.session?.role).toBe("owner");
    expect(await screen.findByRole("alert")).toHaveTextContent(/could not be loaded/i);
  });

  it("a switch during a refresh makes the refresh a stranger: its late, coherent answer does not undo the switch", async () => {
    signedIn(api, "/");
    api.reply("GET /v1/account/workspaces", twoMemberships());
    const lateProfile = deferred<Response>();
    let switched = false;
    let accountReads = 0;
    let detailReads = 0;
    // The reads, in the order they are made: the page's load (1), the refresh's profile
    // (2, answered late), the switch's follow-up load (3). A refresh that went on reading
    // after its late profile would be answered with A's detail too -- a coherent set that
    // describes A, exactly what a refresh begun before the switch must never publish.
    api.on("GET /v1/account", () => {
      accountReads += 1;
      if (accountReads === 2) return lateProfile.promise;
      return json(switched ? profileBoundTo(OTHER_WORKSPACE_ID, "member") : profile());
    });
    api.on("GET /v1/workspace", () => {
      detailReads += 1;
      if (detailReads === 3) return json(workspaceDetail("owner"));
      return json(
        switched ? detailOf(OTHER_WORKSPACE_ID, "member", "Beta") : workspaceDetail("owner"),
      );
    });
    api.on("PUT /v1/account/workspace", () => {
      switched = true;
      return json({
        workspace_id: OTHER_WORKSPACE_ID,
        role: "member",
        membership_id: OTHER_MEMBERSHIP,
      });
    });
    api.install({ abortable: false });
    const probe = renderWithProbe();
    await screen.findByRole("heading", { name: /overview/i });

    const session = probe.session as SessionApi;
    const stale = session.refresh();
    await waitFor(() => expect(accountReads).toBe(2));
    await act(async () => {
      await session.selectWorkspace(OTHER_WORKSPACE_ID);
    });
    await waitFor(() => expect(probe.session?.workspaceId).toBe(OTHER_WORKSPACE_ID));
    await waitFor(() => expect(accountReads).toBe(3));

    // The refresh begun before the switch answers, with A: it is a stranger now, and it
    // neither reads on nor publishes.
    await act(async () => {
      lateProfile.resolve(json(profile()));
    });
    await stale;
    await settle();
    expect(probe.session?.workspaceId).toBe(OTHER_WORKSPACE_ID);
    expect(probe.session?.role).toBe("member");
    expect(probe.session?.profile?.session.workspace_id).toBe(OTHER_WORKSPACE_ID);
    expect(detailReads).toBe(2);
  });

  it("a refresh during a switch cannot overtake the binding the switch publishes", async () => {
    signedIn(api, "/");
    api.reply("GET /v1/account/workspaces", twoMemberships());
    const bind = deferred<Response>();
    const lateProfile = deferred<Response>();
    let accountReads = 0;
    api.on("GET /v1/account", () => {
      accountReads += 1;
      if (accountReads === 2) return lateProfile.promise;
      return json(accountReads === 1 ? profile() : profileBoundTo(OTHER_WORKSPACE_ID, "member"));
    });
    api.on("PUT /v1/account/workspace", () => {
      api.reply("GET /v1/workspace", detailOf(OTHER_WORKSPACE_ID, "member", "Beta"));
      return bind.promise;
    });
    api.install({ abortable: false });
    const probe = renderWithProbe();
    await screen.findByRole("heading", { name: /overview/i });

    const session = probe.session as SessionApi;
    const switching = session.selectWorkspace(OTHER_WORKSPACE_ID);
    const refreshing = session.refresh();
    await waitFor(() => expect(accountReads).toBe(2));
    await act(async () => {
      bind.resolve(
        json({ workspace_id: OTHER_WORKSPACE_ID, role: "member", membership_id: OTHER_MEMBERSHIP }),
      );
    });
    await switching;
    await waitFor(() => expect(probe.session?.workspaceId).toBe(OTHER_WORKSPACE_ID));
    await act(async () => {
      lateProfile.resolve(json(profile()));
    });
    await refreshing;
    await settle();
    expect(probe.session?.workspaceId).toBe(OTHER_WORKSPACE_ID);
  });
});

describe("the expected-workspace contract, from the page's side", () => {
  it("sends the workspace the page began under with every mutation it makes", async () => {
    signedIn(api, "/settings/team");
    api
      .reply("GET /v1/workspace/members", members(WORKSPACE_ID, "owner@example.com"))
      .reply("GET /v1/workspace/invitations", noInvitations(WORKSPACE_ID))
      .on("POST /v1/workspace/invitations", () =>
        json({ invitation_id: "i1", role: "member", expires_at: null, replayed: false }, 201),
      );
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /^team$/i });
    await userEvent.type(screen.getByLabelText(/email address/i), "new@example.com");
    await userEvent.click(screen.getByRole("button", { name: /send invitation/i }));
    await waitFor(() => expect(api.to("POST", "/v1/workspace/invitations")).toHaveLength(1));
    expect(api.to("POST", "/v1/workspace/invitations")[0]?.headers["x-workspace-id"]).toBe(
      WORKSPACE_ID,
    );
  });

  it("reports a stale action the server refused as a mismatch, and announces no success", async () => {
    signedIn(api, "/settings/workspace");
    api.reply("GET /v1/workspace", workspaceDetail("owner"));
    api.on("PATCH /v1/workspace", () => refusal(409, "workspace_mismatch"));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /^workspace$/i });
    await userEvent.clear(screen.getByLabelText(/workspace name/i));
    await userEvent.type(screen.getByLabelText(/workspace name/i), "Renamed");
    await userEvent.click(screen.getByRole("button", { name: /save name/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/different workspace/i);
    expect(screen.queryByText(/workspace renamed/i)).not.toBeInTheDocument();
    expect(api.to("PATCH", "/v1/workspace")[0]?.headers["x-workspace-id"]).toBe(WORKSPACE_ID);
  });

  it("never renders a late answer for A after the session moved to B, and reloads for B", async () => {
    signedIn(api, "/settings/team");
    api.reply("GET /v1/account/workspaces", twoMemberships());
    const lateMembers = deferred<Response>();
    let memberReads = 0;
    api.on("GET /v1/workspace/members", () => {
      memberReads += 1;
      return memberReads === 1
        ? lateMembers.promise
        : json(members(OTHER_WORKSPACE_ID, "beta-owner@example.com"));
    });
    api.on("GET /v1/workspace/invitations", () =>
      json(noInvitations(memberReads === 1 ? WORKSPACE_ID : OTHER_WORKSPACE_ID)),
    );
    api.install({ abortable: false });
    const probe = renderWithProbe();
    await waitFor(() => expect(memberReads).toBe(1));

    // Another tab switched the session to B; this provider learns it from a refresh.
    api
      .reply("GET /v1/account", profileBoundTo(OTHER_WORKSPACE_ID, "member"))
      .reply("GET /v1/workspace", detailOf(OTHER_WORKSPACE_ID, "member", "Beta"));
    await act(async () => {
      await (probe.session as SessionApi).refresh();
    });
    await waitFor(() => expect(probe.session?.workspaceId).toBe(OTHER_WORKSPACE_ID));
    expect(await screen.findByText("beta-owner@example.com")).toBeInTheDocument();

    // A's list finally answers. It is about A, and A is not what this page shows any more.
    await act(async () => {
      lateMembers.resolve(json(members(WORKSPACE_ID, "owner@example.com")));
    });
    await settle();
    expect(screen.getByText("beta-owner@example.com")).toBeInTheDocument();
    expect(screen.queryByText("owner@example.com")).not.toBeInTheDocument();
  });

  it("does not render a list that names another workspace than the page's, and re-reads the binding", async () => {
    signedIn(api, "/settings/team");
    api
      .reply("GET /v1/workspace/members", members(OTHER_WORKSPACE_ID, "beta-owner@example.com"))
      .reply("GET /v1/workspace/invitations", noInvitations(OTHER_WORKSPACE_ID));
    api.install();
    renderPortal();

    expect(await screen.findByRole("alert")).toHaveTextContent(/another workspace/i);
    expect(screen.queryByText("beta-owner@example.com")).not.toBeInTheDocument();
    await waitFor(() => expect(api.to("GET", "/v1/account").length).toBeGreaterThan(1));
  });
});

describe("the lifecycle of a page's requests", () => {
  function teamWith(invitation: boolean): void {
    api
      .reply("GET /v1/workspace/members", members(WORKSPACE_ID, "owner@example.com"))
      .reply("GET /v1/workspace/invitations", {
        workspace_id: WORKSPACE_ID,
        invitations: invitation
          ? [
              {
                invitation_id: "i1",
                email: "pending@example.com",
                role: "member",
                created_at: null,
                expires_at: null,
                status: "pending",
              },
            ]
          : [],
      });
  }

  /** The provider learns of a switch to the other workspace while this page stays open. */
  function switchesToOther(): void {
    api.reply("GET /v1/account/workspaces", twoMemberships());
    api.on("PUT /v1/account/workspace", () => {
      api
        .reply("GET /v1/account", profileBoundTo(OTHER_WORKSPACE_ID, "member"))
        .reply("GET /v1/workspace", detailOf(OTHER_WORKSPACE_ID, "member", "Beta"));
      return json({
        workspace_id: OTHER_WORKSPACE_ID,
        role: "member",
        membership_id: OTHER_MEMBERSHIP,
      });
    });
  }

  it("an older load's late answer neither publishes nor ends a newer load", async () => {
    signedIn(api, "/settings/team");
    switchesToOther();
    const slow = deferred<Response>();
    let memberReads = 0;
    api.on("GET /v1/workspace/members", () => {
      memberReads += 1;
      return memberReads === 1
        ? slow.promise
        : json(members(OTHER_WORKSPACE_ID, "beta-owner@example.com"));
    });
    api.on("GET /v1/workspace/invitations", () =>
      json(noInvitations(memberReads === 1 ? WORKSPACE_ID : OTHER_WORKSPACE_ID)),
    );
    api.install({ abortable: false });
    const probe = renderWithProbe();
    await waitFor(() => expect(memberReads).toBe(1));

    // Load 1 is in flight when the selected workspace changes; load 2 starts and completes.
    await act(async () => {
      await (probe.session as SessionApi).selectWorkspace(OTHER_WORKSPACE_ID);
    });
    expect(await screen.findByText("beta-owner@example.com")).toBeInTheDocument();
    expect(memberReads).toBe(2);

    // Load 1 answers late, with an older list: nothing changes, and the page is not put back
    // into, or taken out of, a loading state by a load that is not the newest.
    await act(async () => {
      slow.resolve(json({ workspace_id: WORKSPACE_ID, members: [memberRow("stale@example.com")] }));
    });
    await settle();
    expect(screen.queryByText("stale@example.com")).not.toBeInTheDocument();
    expect(screen.getByText("beta-owner@example.com")).toBeInTheDocument();
    expect(screen.queryByText(/loading your team/i)).not.toBeInTheDocument();
  });

  it("an older load that finishes first does not end the newer load's loading state", async () => {
    signedIn(api, "/settings/team");
    switchesToOther();
    const first = deferred<Response>();
    const second = deferred<Response>();
    let memberReads = 0;
    api.on("GET /v1/workspace/members", () => {
      memberReads += 1;
      return memberReads === 1 ? first.promise : second.promise;
    });
    api.on("GET /v1/workspace/invitations", () =>
      json(noInvitations(memberReads === 1 ? WORKSPACE_ID : OTHER_WORKSPACE_ID)),
    );
    api.install({ abortable: false });
    const probe = renderWithProbe();
    await waitFor(() => expect(memberReads).toBe(1));
    await act(async () => {
      await (probe.session as SessionApi).selectWorkspace(OTHER_WORKSPACE_ID);
    });
    await waitFor(() => expect(memberReads).toBe(2));

    // Load 1 finishes; load 2 is still in flight, and the page still says so.
    await act(async () => {
      first.resolve(json(members(WORKSPACE_ID, "owner@example.com")));
    });
    await settle();
    expect(screen.getByText(/loading your team/i)).toBeInTheDocument();
    expect(screen.queryByText("owner@example.com")).not.toBeInTheDocument();
    await act(async () => {
      second.resolve(json(members(OTHER_WORKSPACE_ID, "beta-owner@example.com")));
    });
    expect(await screen.findByText("beta-owner@example.com")).toBeInTheDocument();
    expect(screen.queryByText(/loading your team/i)).not.toBeInTheDocument();
  });

  it("a completion from a page the customer has left is inert: no message, no secret, no navigation", async () => {
    signedIn(api, "/settings/credentials");
    api.reply("GET /v1/workspace/credentials", { workspace_id: WORKSPACE_ID, credentials: [] });
    teamWith(false);
    const issued = deferred<Response>();
    api.on("POST /v1/workspace/credentials", () => issued.promise);
    api.install({ abortable: false });
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    await userEvent.click(screen.getByRole("button", { name: /create credential/i }));
    await waitFor(() => expect(api.to("POST", "/v1/workspace/credentials")).toHaveLength(1));
    // Leave for the team page while the issue is pending.
    await userEvent.click(screen.getByRole("link", { name: /^team$/i }));
    await screen.findByRole("heading", { name: /^team$/i });

    await act(async () => {
      issued.resolve(
        json(
          {
            credential_id: CREDENTIAL_ID,
            scopes: ["workspace:read"],
            expires_at: null,
            rotated_from_id: null,
            replayed: false,
            credential: "fbk_SHOULDNEVERAPPEARnotarealsecret0000000000",
          },
          201,
        ),
      );
    });
    await settle();
    expect(screen.queryByText(/fbk_SHOULDNEVERAPPEAR/)).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(window.location.pathname).toBe("/settings/team");
  });

  it("a late failure from a page the customer has left reconciles nothing", async () => {
    signedIn(api, "/settings/credentials");
    api.reply("GET /v1/workspace/credentials", { workspace_id: WORKSPACE_ID, credentials: [] });
    teamWith(false);
    const issued = deferred<Response>();
    api.on("POST /v1/workspace/credentials", () => issued.promise);
    api.install({ abortable: false });
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    await userEvent.click(screen.getByRole("button", { name: /create credential/i }));
    await userEvent.click(screen.getByRole("link", { name: /^team$/i }));
    await screen.findByRole("heading", { name: /^team$/i });
    const accountReads = api.to("GET", "/v1/account").length;

    await act(async () => {
      issued.resolve(refusal(401, "authentication_required"));
    });
    await settle();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(api.to("GET", "/v1/account")).toHaveLength(accountReads);
    expect(window.location.pathname).toBe("/settings/team");
  });

  it("a selection that answers after the customer has left the picker navigates nowhere", async () => {
    signedInWithNoWorkspace("/workspaces");
    api.reply("GET /v1/account/workspaces", membershipList("owner"));
    const bind = deferred<Response>();
    api.on("PUT /v1/account/workspace", () => bind.promise);
    api.install({ abortable: false });
    renderPortal();

    await userEvent.click(await screen.findByRole("button", { name: /acme/i }));
    await waitFor(() => expect(api.to("PUT", "/v1/account/workspace")).toHaveLength(1));
    // The customer leaves for their account page while the selection is pending.
    act(() => {
      window.history.pushState(null, "", "/account");
      window.dispatchEvent(new PopStateEvent("popstate"));
    });
    await screen.findByRole("heading", { name: /your account/i });

    await act(async () => {
      bind.resolve(
        json({ workspace_id: WORKSPACE_ID, role: "owner", membership_id: MEMBERSHIP_ID }),
      );
    });
    await settle();
    expect(window.location.pathname).toBe("/account");
  });
});

describe("mount-time requests under StrictMode", () => {
  it("issues each of a page's reads once, and once again when the customer comes back", async () => {
    signedIn(api, "/settings/team");
    api
      .reply("GET /v1/workspace/members", members(WORKSPACE_ID, "owner@example.com"))
      .reply("GET /v1/workspace/invitations", noInvitations(WORKSPACE_ID))
      .reply("GET /v1/workspace/credentials", { workspace_id: WORKSPACE_ID, credentials: [] });
    api.install();
    renderPortal({ strict: true });

    await screen.findByRole("heading", { name: /^team$/i });
    expect(api.to("GET", "/v1/workspace/members")).toHaveLength(1);
    expect(api.to("GET", "/v1/workspace/invitations")).toHaveLength(1);
    expect(api.to("GET", "/v1/account")).toHaveLength(1);
    expect(api.to("GET", "/v1/account/workspaces")).toHaveLength(1);
    expect(api.to("GET", "/v1/workspace")).toHaveLength(1);

    // Away, and back: a legitimate refresh, once more.
    await userEvent.click(screen.getByRole("link", { name: /api credentials/i }));
    await screen.findByRole("heading", { name: /api credentials/i });
    expect(api.to("GET", "/v1/workspace/credentials")).toHaveLength(1);
    await userEvent.click(screen.getByRole("link", { name: /^team$/i }));
    await screen.findByRole("heading", { name: /^team$/i });
    expect(api.to("GET", "/v1/workspace/members")).toHaveLength(2);
  });
});
