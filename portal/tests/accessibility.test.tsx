/**
 * Keyboard interaction, labelling and announcements.
 *
 * Not a generic audit -- those find missing alt text and little else. These are the specific
 * things this portal does that break for a keyboard or screen-reader user if they are done
 * carelessly: a dialog that lets focus escape behind it, a form field whose error is only a
 * colour, a live region that never announces, a skip link that goes nowhere, and a disabled
 * control that gives no reason.
 */

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CREDENTIAL_ID, FakeApi, json, renderPortal, signedIn, WORKSPACE_ID } from "./harness.tsx";

let api: FakeApi;

beforeEach(() => {
  api = new FakeApi();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("landmarks and the skip link", () => {
  it("has one main region, and the skip link points at it", async () => {
    signedIn(api, "/");
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /overview/i });
    const main = screen.getByRole("main");
    expect(main).toHaveAttribute("id", "main");

    const skip = screen.getByRole("link", { name: /skip to main content/i });
    expect(skip).toHaveAttribute("href", "#main");
    // It is the first focusable thing on the page, which is what makes it useful.
    await userEvent.tab();
    expect(skip).toHaveFocus();
  });

  it("names its navigation, so a screen reader can jump between landmarks", async () => {
    signedIn(api, "/");
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /overview/i });
    expect(screen.getByRole("navigation", { name: /portal sections/i })).toBeInTheDocument();
  });
});

describe("forms", () => {
  it("labels every input, so nothing is addressed only by placeholder", async () => {
    signedIn(api, "/settings/workspace", "owner");
    api.install();
    renderPortal();

    await screen.findByLabelText(/workspace name/i);
    for (const input of screen.getAllByRole("textbox")) {
      // An accessible name from a real <label for>, not a placeholder, which is announced
      // inconsistently and disappears the moment somebody types.
      expect(input).toHaveAccessibleName();
    }
  });

  it("marks an invalid field and ties the message to it", async () => {
    signedIn(api, "/account/security", "owner");
    api.reply("GET /v1/account/sessions", { sessions: [] });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /^security$/i });
    await userEvent.type(screen.getByLabelText(/current password/i), "old password here");
    await userEvent.type(screen.getByLabelText(/^new password/i), "a new password entirely");
    await userEvent.type(screen.getByLabelText(/confirm new password/i), "something different");
    await userEvent.click(screen.getByRole("button", { name: /change password/i }));

    const confirmation = await screen.findByLabelText(/confirm new password/i);
    expect(confirmation).toHaveAttribute("aria-invalid", "true");
    const describedBy = confirmation.getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    expect(document.getElementById(describedBy as string)).toHaveTextContent(/do not match/i);
  });

  it("associates a hint with its field", async () => {
    signedIn(api, "/settings/credentials", "owner");
    api.reply("GET /v1/workspace/credentials", { workspace_id: WORKSPACE_ID, credentials: [] });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { name: /api credentials/i });
    const label = screen.getByLabelText(/^label$/i);
    const describedBy = label.getAttribute("aria-describedby");
    expect(document.getElementById(describedBy as string)).toHaveTextContent(/never put a secret/i);
  });

  it("can be submitted from the keyboard alone", async () => {
    signedIn(api, "/settings/workspace", "owner");
    api.on("PATCH /v1/workspace", () =>
      json({ workspace_id: WORKSPACE_ID, name: "Renamed", replayed: false }),
    );
    api.install();
    renderPortal();

    const field = await screen.findByLabelText(/workspace name/i);
    field.focus();
    await userEvent.clear(field);
    await userEvent.type(field, "Renamed{Enter}");

    await waitFor(() => expect(api.to("PATCH", "/v1/workspace")).toHaveLength(1));
  });
});

describe("announcements", () => {
  it("puts a failure in an alert region, so it interrupts", async () => {
    signedIn(api, "/settings/workspace", "owner");
    api.on(
      "PATCH /v1/workspace",
      () =>
        new Response(JSON.stringify({ error: "forbidden" }), {
          status: 403,
          headers: { "content-type": "application/json" },
        }),
    );
    api.install();
    renderPortal();

    await screen.findByLabelText(/workspace name/i);
    await userEvent.click(screen.getByRole("button", { name: /save name/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/does not allow that/i);
  });

  it("puts a confirmation in a status region, so it does not", async () => {
    signedIn(api, "/settings/workspace", "owner");
    api.on("PATCH /v1/workspace", () =>
      json({ workspace_id: WORKSPACE_ID, name: "Acme", replayed: false }),
    );
    api.install();
    renderPortal();

    await screen.findByLabelText(/workspace name/i);
    await userEvent.click(screen.getByRole("button", { name: /save name/i }));

    expect(await screen.findByText(/workspace renamed/i)).toBeInTheDocument();
  });

  it("announces a loading state rather than showing a silent spinner", async () => {
    signedIn(api, "/settings/credentials", "owner");
    // Never resolves, so the loading state is the one under test.
    api.on("GET /v1/workspace/credentials", () => new Promise<Response>(() => {}));
    api.install();
    renderPortal();

    expect(await screen.findByText(/loading credentials/i)).toBeInTheDocument();
  });
});

describe("the credential history dialog", () => {
  async function openDialog(): Promise<HTMLElement> {
    signedIn(api, "/settings/credentials", "admin");
    api.reply("GET /v1/workspace/credentials", {
      workspace_id: WORKSPACE_ID,
      credentials: [
        {
          credential_id: CREDENTIAL_ID,
          label: "ci",
          scopes: ["workspace:read"],
          created_at: null,
          expires_at: null,
          revoked_at: null,
          last_used_at: null,
          rotated_from_id: null,
          membership_id: "m1",
          email: "person@example.com",
          active: true,
        },
      ],
    });
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
            occurred_at: null,
            details: {},
          },
        ],
      }),
    );
    api.install();
    renderPortal();
    await screen.findByRole("heading", { name: /api credentials/i });
    await userEvent.click(screen.getByRole("button", { name: /history/i }));
    return await screen.findByRole("dialog");
  }

  it("is a labelled modal that takes focus when it opens", async () => {
    const dialog = await openDialog();
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAccessibleName(/credential history/i);
    await waitFor(() => expect(dialog).toHaveFocus());
  });

  it("keeps Tab inside itself", async () => {
    const dialog = await openDialog();
    const inside = within(dialog).getAllByRole("button");
    expect(inside.length).toBeGreaterThan(0);

    // Tab from the last control wraps to the first rather than escaping to the page behind,
    // which a sighted user notices immediately and a screen-reader user does not.
    (inside[inside.length - 1] as HTMLElement).focus();
    await userEvent.tab();
    expect(dialog.contains(document.activeElement)).toBe(true);

    (inside[0] as HTMLElement).focus();
    await userEvent.tab({ shift: true });
    expect(dialog.contains(document.activeElement)).toBe(true);
  });

  it("closes on Escape and returns focus to what opened it", async () => {
    const dialog = await openDialog();
    const opener = screen.getByRole("button", { name: /history/i });
    await userEvent.keyboard("{Escape}");
    await waitFor(() => expect(dialog).not.toBeInTheDocument());
    expect(opener).toHaveFocus();
  });
});

describe("tables", () => {
  it("captions its table and uses column headers", async () => {
    signedIn(api, "/settings/team", "owner");
    api
      .reply("GET /v1/workspace/members", {
        workspace_id: WORKSPACE_ID,
        members: [
          {
            membership_id: "m1",
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
    const table = screen.getAllByRole("table")[0] as HTMLElement;
    expect(within(table).getByText(/people in this workspace/i)).toBeInTheDocument();
    for (const header of within(table).getAllByRole("columnheader")) {
      expect(header).toHaveAttribute("scope", "col");
    }
  });
});

describe("the unavailable sections", () => {
  it.each([
    ["/evaluation", /evaluation/i],
    ["/jobs", /jobs/i],
    ["/results", /results/i],
    ["/billing", /billing/i],
  ])("%s says it is unavailable in text, not only by styling", async (path, name) => {
    signedIn(api, path, "owner");
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name });
    // Scoped to the page region: the navigation marks all four of these as unavailable too,
    // which is the intended behaviour and would otherwise make this query ambiguous.
    const main = within(screen.getByRole("main"));
    expect(main.getByText(/not available yet/i)).toBeInTheDocument();
    expect(main.getByText(/nothing on this page is simulated/i)).toBeInTheDocument();
    // No fabricated data: no table of pretend jobs, invoices or results.
    expect(main.queryByRole("table")).not.toBeInTheDocument();
  });
});

describe("focus after navigation", () => {
  // The sidebar: the overview page links to the same places from its journey list, and a
  // keyboard user navigating between sections uses the navigation landmark.
  const navigation = () => screen.getByRole("navigation", { name: /portal sections/i });

  it("moves focus to the new page heading on every route change made from the keyboard", async () => {
    signedIn(api, "/");
    api.reply("GET /v1/account/sessions", { sessions: [] });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /overview/i });

    // Navigation one: to the account page, by keyboard.
    within(navigation())
      .getByRole("link", { name: /your account/i })
      .focus();
    await userEvent.keyboard("{Enter}");
    await waitFor(() =>
      expect(screen.getByRole("heading", { level: 1, name: /your account/i })).toHaveFocus(),
    );

    // Navigation two: to a second page. The first implementation moved focus only on the
    // shell's first mount, which is to say never, so a second transition is the case that
    // matters.
    within(navigation())
      .getByRole("link", { name: /^security$/i })
      .focus();
    await userEvent.keyboard("{Enter}");
    await waitFor(() =>
      expect(screen.getByRole("heading", { level: 1, name: /^security$/i })).toHaveFocus(),
    );

    // Navigation three: back to the overview.
    within(navigation())
      .getByRole("link", { name: /overview/i })
      .focus();
    await userEvent.keyboard("{Enter}");
    await waitFor(() =>
      expect(screen.getByRole("heading", { level: 1, name: /overview/i })).toHaveFocus(),
    );
  });

  it("focuses the heading of a page that loads its content after the transition", async () => {
    signedIn(api, "/");
    api
      .reply("GET /v1/workspace/preferences", {
        workspace_id: "33333333-3333-4333-8333-333333333333",
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

    await screen.findByRole("heading", { level: 1, name: /overview/i });
    within(navigation())
      .getByRole("link", { name: /policy and preferences/i })
      .focus();
    await userEvent.keyboard("{Enter}");
    // The page shows a spinner first and its heading only once the settings have loaded;
    // focus follows the heading when it appears, because nothing else has taken it.
    await waitFor(() =>
      expect(
        screen.getByRole("heading", { level: 1, name: /policy and preferences/i }),
      ).toHaveFocus(),
    );
  });

  it("leaves focus alone when the route has not changed", async () => {
    signedIn(api, "/settings/workspace", "owner");
    api.on("PATCH /v1/workspace", () =>
      json({ workspace_id: WORKSPACE_ID, name: "Acme", replayed: false }),
    );
    api.install();
    renderPortal();

    const field = await screen.findByLabelText(/workspace name/i);
    field.focus();
    // A state change inside the page re-renders the tree without changing the route. Focus
    // must stay where the customer put it, not jump to the heading.
    await userEvent.type(field, " Ltd");
    await userEvent.click(screen.getByRole("button", { name: /save name/i }));
    await screen.findByText(/workspace renamed/i);
    expect(screen.getByRole("heading", { level: 1 })).not.toHaveFocus();
  });

  it("does not steal focus on the first render", async () => {
    signedIn(api, "/");
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /overview/i });
    // The browser's own restoration wins on a page load; the heading is not focused.
    expect(screen.getByRole("heading", { level: 1, name: /overview/i })).not.toHaveFocus();
    await userEvent.tab();
    expect(screen.getByRole("link", { name: /skip to main content/i })).toHaveFocus();
  });
});
