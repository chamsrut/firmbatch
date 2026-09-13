/**
 * Stated policy, and the consent statement.
 *
 * The two properties that matter here are honesty properties rather than security ones.
 *
 * The page must say that what it captures is **intent** -- the roadmap's words are "for later
 * use without claiming a quote or an execution" -- and it must not imply a job, a quote or a
 * price anywhere.
 *
 * And the exclusion v1 cannot honour must be neither silently refused nor silently accepted.
 * `provider_policy` governs execution placement only; the payload plane is S3 for every
 * tenant; so a customer who excludes Amazon altogether cannot be served in v1, and D.1's
 * instruction is that the consent text says exactly that "rather than promising an exclusion
 * the design cannot honour".
 */

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  CONSENT_DOCUMENT,
  FakeApi,
  json,
  preferences,
  profile,
  refusal,
  renderPortal,
  SESSION_ID,
  signedIn,
  workspaceDetail,
} from "./harness.tsx";

let api: FakeApi;

function withPreferences(overrides: Record<string, unknown> = {}): void {
  api
    .reply("GET /v1/workspace/preferences", preferences(overrides))
    .reply("GET /v1/consent", CONSENT_DOCUMENT);
}

beforeEach(() => {
  api = new FakeApi();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("what the page claims", () => {
  it("says it records intent and prices or schedules nothing", async () => {
    signedIn(api, "/settings/preferences", "owner");
    withPreferences();
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /policy and preferences/i });
    const main = within(screen.getByRole("main"));
    expect(main.getByText(/recorded intent/i)).toBeInTheDocument();
    expect(
      main.getByText(/does not create a job, reserve capacity, produce a quote or schedule/i),
    ).toBeInTheDocument();
  });

  it("shows no price, no quote and no job anywhere", async () => {
    signedIn(api, "/settings/preferences", "owner");
    withPreferences();
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /policy and preferences/i });
    const text = screen.getByRole("main").textContent ?? "";
    // No currency figure of any kind: this page must not look like a pricing page.
    expect(text).not.toMatch(/[$£€]\s?\d/);
    expect(text).not.toMatch(/\bper hour\b|\bper token\b|\bper thousand\b/i);
    // "quote" and "invoice" may appear, but only in a sentence that denies one. An
    // affirmative mention would be the page claiming something this milestone cannot do.
    const sentences = text.split(/(?<=[.!?])\s+/);
    for (const sentence of sentences) {
      if (!/\b(quote|invoice|job)\b/i.test(sentence)) continue;
      expect(sentence).toMatch(/\b(no|not|never|nothing|does not|creates no)\b/i);
    }
  });

  it("says a region constraint costs something, rather than presenting it as free", async () => {
    signedIn(api, "/settings/preferences", "owner");
    withPreferences();
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /policy and preferences/i });
    expect(screen.getByText(/more expensive and slower to place/i)).toBeInTheDocument();
  });
});

describe("the exclusion v1 cannot honour", () => {
  it("labels Amazon with the reason before it is ticked", async () => {
    signedIn(api, "/settings/preferences", "owner");
    withPreferences();
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /policy and preferences/i });
    const amazon = screen.getByLabelText(/amazon web services/i);
    const describedBy = amazon.getAttribute("aria-describedby");
    expect(document.getElementById(describedBy as string)).toHaveTextContent(
      /cannot be honoured in v1/i,
    );
  });

  it("accepts and records it, and warns rather than refusing", async () => {
    signedIn(api, "/settings/preferences", "owner");
    withPreferences();
    api.on("PUT /v1/workspace/preferences", (request) =>
      json(
        preferences({
          excluded_provider_classes: (request.body as { excluded_provider_classes: string[] })
            .excluded_provider_classes,
          unservable_exclusion: true,
        }),
      ),
    );
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /policy and preferences/i });
    await userEvent.click(screen.getByLabelText(/amazon web services/i));
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    // Recorded, because a customer who requires it is a fact worth having.
    await waitFor(() => expect(api.to("PUT", "/v1/workspace/preferences")).toHaveLength(1));
    expect(api.to("PUT", "/v1/workspace/preferences")[0]?.body).toMatchObject({
      excluded_provider_classes: ["amazon"],
    });
    // And flagged, because accepting it silently would promise something v1 cannot do.
    const warning = await screen.findByText(/inputs and outputs are stored in amazon s3/i);
    expect(warning).toBeInTheDocument();
    expect(screen.getByText(/would refuse work under it/i)).toBeInTheDocument();
  });
});

describe("the consent statement", () => {
  it("is rendered from the API's response, not from a copy in the frontend", async () => {
    signedIn(api, "/settings/preferences", "owner");
    withPreferences();
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /policy and preferences/i });
    await waitFor(() => expect(api.to("GET", "/v1/consent")).toHaveLength(1));
    expect(screen.getByText(CONSENT_DOCUMENT.title)).toBeInTheDocument();
    expect(screen.getByText(CONSENT_DOCUMENT.sections[0]?.body[0] as string)).toBeInTheDocument();
  });

  it("acknowledges the version it displayed, and sends no actor or timestamp", async () => {
    signedIn(api, "/settings/preferences", "owner");
    withPreferences();
    api.on("POST /v1/workspace/preferences/consent", () =>
      json(
        preferences({
          consent_version: "provider-policy-v1-d.1",
          consent_acknowledged_at: "2026-09-09T12:00:00+00:00",
          consent_account_id: "a1",
        }),
      ),
    );
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /policy and preferences/i });
    await userEvent.click(screen.getByRole("button", { name: /acknowledge this statement/i }));

    await waitFor(() =>
      expect(api.to("POST", "/v1/workspace/preferences/consent")).toHaveLength(1),
    );
    const sent = api.to("POST", "/v1/workspace/preferences/consent")[0];
    // Who and when are the server's, derived inside the database function from the bound
    // session and the server's clock. There is no field for either, so there is nothing to
    // state wrongly; what travels is the displayed version and the workspace the form was
    // loaded for.
    expect(sent?.body).toEqual({
      workspace_id: "33333333-3333-4333-8333-333333333333",
      consent_version: "provider-policy-v1-d.1",
    });
    expect(await screen.findByText(/acknowledged/i)).toBeInTheDocument();
  });

  it("says an earlier version was acknowledged when the statement has moved on", async () => {
    signedIn(api, "/settings/preferences", "owner");
    api
      .reply(
        "GET /v1/workspace/preferences",
        preferences({
          consent_version: "provider-policy-v1-d.0",
          consent_acknowledged_at: "2026-08-01T12:00:00+00:00",
          consent_account_id: "a1",
        }),
      )
      .reply("GET /v1/consent", CONSENT_DOCUMENT);
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /policy and preferences/i });
    expect(screen.getByText(/acknowledged an earlier version/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /acknowledge this statement/i })).toBeInTheDocument();
  });

  it("states that acknowledging creates no commitment", async () => {
    signedIn(api, "/settings/preferences", "owner");
    withPreferences();
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /policy and preferences/i });
    expect(screen.getByText(/creates no job, quote, invoice or commitment/i)).toBeInTheDocument();
  });

  it("reports a failure to load the statement rather than showing a blank section", async () => {
    signedIn(api, "/settings/preferences", "owner");
    api
      .reply("GET /v1/workspace/preferences", preferences())
      .on("GET /v1/consent", () => refusal(500, "internal_error"));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /policy and preferences/i });
    // The two halves load independently, so a consent outage costs the consent section and
    // leaves the customer's own settings loaded and editable.
    expect(await screen.findByText(/consent statement could not be loaded/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/model and runtime profile/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^save$/i })).toBeEnabled();
  });
});

describe("a failed load", () => {
  it("refuses to save, rather than replacing real settings with blanks", async () => {
    signedIn(api, "/settings/preferences", "owner");
    api
      .on("GET /v1/workspace/preferences", () => refusal(500, "internal_error"))
      .reply("GET /v1/consent", CONSENT_DOCUMENT);
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /policy and preferences/i });
    const save = await screen.findByRole("button", { name: /^save$/i });
    expect(save).toBeDisabled();
    expect(
      document.getElementById(save.getAttribute("aria-describedby") as string),
    ).toHaveTextContent(/could not be read, so they must not be replaced/i);
  });
});

describe("saving", () => {
  it("sends the closed vocabularies and re-renders from what the server returned", async () => {
    signedIn(api, "/settings/preferences", "owner");
    withPreferences();
    api.on("PUT /v1/workspace/preferences", () =>
      json(
        preferences({
          region_policy: ["EU"],
          evaluation_intent: "planning_evaluation",
          // The server normalises; the form must show what came back, not what was typed.
          model_profile_note: "Qwen3-8B on vllm-fp8",
        }),
      ),
    );
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /policy and preferences/i });
    await userEvent.click(screen.getByLabelText(/european union/i));
    await userEvent.type(
      screen.getByLabelText(/model and runtime profile/i),
      "  Qwen3-8B on vllm-fp8  ",
    );
    await userEvent.selectOptions(screen.getByLabelText(/free evaluation/i), "planning_evaluation");
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => expect(api.to("PUT", "/v1/workspace/preferences")).toHaveLength(1));
    expect(api.to("PUT", "/v1/workspace/preferences")[0]?.body).toMatchObject({
      region_policy: ["EU"],
      evaluation_intent: "planning_evaluation",
      model_profile_note: "Qwen3-8B on vllm-fp8",
    });
    expect(await screen.findByText(/^saved\.$/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/model and runtime profile/i)).toHaveValue("Qwen3-8B on vllm-fp8");
  });

  it("does not touch the consent columns when only preferences change", async () => {
    signedIn(api, "/settings/preferences", "owner");
    withPreferences();
    api.on("PUT /v1/workspace/preferences", () => json(preferences()));
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /policy and preferences/i });
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => expect(api.to("PUT", "/v1/workspace/preferences")).toHaveLength(1));
    const sent = api.to("PUT", "/v1/workspace/preferences")[0]?.body as Record<string, unknown>;
    // An ordinary preference edit can never re-date or clear an acknowledgement, so it does
    // not send one.
    expect(Object.keys(sent)).not.toContain("consent_version");
    expect(Object.keys(sent)).not.toContain("consent_acknowledged_at");
  });
});

describe("the workspace the form was loaded for", () => {
  const OTHER = "44444444-4444-4444-8444-444444444444";
  const THIS_WORKSPACE = "33333333-3333-4333-8333-333333333333";

  it("names it with every save and every acknowledgement", async () => {
    signedIn(api, "/settings/preferences", "owner");
    withPreferences();
    api.on("PUT /v1/workspace/preferences", () => json(preferences({ region_policy: ["EU"] })));
    api.on("POST /v1/workspace/preferences/consent", () =>
      json(preferences({ consent_version: "provider-policy-v1-d.1" })),
    );
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /policy and preferences/i });
    await userEvent.click(screen.getByLabelText(/european union/i));
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(api.to("PUT", "/v1/workspace/preferences")).toHaveLength(1));
    // The identifier the form was loaded with, from the server's own response: never typed,
    // never taken from the URL, never the switcher's current value.
    expect(api.to("PUT", "/v1/workspace/preferences")[0]?.body).toMatchObject({
      workspace_id: THIS_WORKSPACE,
    });

    await userEvent.click(screen.getByRole("button", { name: /acknowledge this statement/i }));
    await waitFor(() =>
      expect(api.to("POST", "/v1/workspace/preferences/consent")).toHaveLength(1),
    );
    expect(api.to("POST", "/v1/workspace/preferences/consent")[0]?.body).toEqual({
      workspace_id: THIS_WORKSPACE,
      consent_version: "provider-policy-v1-d.1",
    });
  });

  it("a save refused because another tab switched workspaces saves nothing and reloads the page for the current one", async () => {
    signedIn(api, "/settings/preferences", "owner");
    withPreferences({ model_profile_note: "the note on the first workspace" });
    api.on("PUT /v1/workspace/preferences", () => {
      // The session moved to another workspace between the load and this save. The API
      // refuses, and from now on says the session is bound to the other workspace.
      api
        .reply(
          "GET /v1/account",
          profile({
            session: {
              session_id: SESSION_ID,
              workspace_id: OTHER,
              role: "owner",
              expires_at: null,
            },
          }),
        )
        .reply("GET /v1/workspace", {
          ...workspaceDetail("owner"),
          workspace_id: OTHER,
          name: "Beta",
        })
        .reply(
          "GET /v1/workspace/preferences",
          preferences({ workspace_id: OTHER, model_profile_note: "the note on the other one" }),
        );
      return refusal(409, "workspace_mismatch");
    });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /policy and preferences/i });
    const note = screen.getByLabelText(/model and runtime profile/i);
    expect(note).toHaveValue("the note on the first workspace");
    await userEvent.clear(note);
    await userEvent.type(note, "edited on the first workspace");
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    // Told plainly that nothing was saved, and why; and the form now shows the workspace
    // the session actually has selected, under its own values, never the first workspace's
    // edits under the other workspace's name.
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/different workspace/i);
    expect(alert).toHaveTextContent(/nothing was saved/i);
    await waitFor(() =>
      expect(screen.getByLabelText(/model and runtime profile/i)).toHaveValue(
        "the note on the other one",
      ),
    );
    expect(api.to("PUT", "/v1/workspace/preferences")).toHaveLength(1);
    expect(api.to("GET", "/v1/workspace/preferences")).toHaveLength(2);
    expect(api.to("GET", "/v1/account").length).toBeGreaterThan(1);
    expect(screen.queryByText(/^saved\.$/i)).not.toBeInTheDocument();
  });

  it("an acknowledgement refused the same way records nothing and reloads", async () => {
    signedIn(api, "/settings/preferences", "owner");
    withPreferences();
    api.on("POST /v1/workspace/preferences/consent", () => {
      // The session moved to another workspace between the load and this acknowledgement.
      // The API refuses, and from now on says the session is bound to the other workspace.
      api
        .reply(
          "GET /v1/account",
          profile({
            session: {
              session_id: SESSION_ID,
              workspace_id: OTHER,
              role: "owner",
              expires_at: null,
            },
          }),
        )
        .reply("GET /v1/workspace", {
          ...workspaceDetail("owner"),
          workspace_id: OTHER,
          name: "Beta",
        })
        .reply(
          "GET /v1/workspace/preferences",
          preferences({ workspace_id: OTHER, consent_version: "provider-policy-v1-d.1" }),
        );
      return refusal(409, "workspace_mismatch");
    });
    api.install();
    renderPortal();

    await screen.findByRole("heading", { level: 1, name: /policy and preferences/i });
    await userEvent.click(screen.getByRole("button", { name: /acknowledge this statement/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/nothing was saved/i);
    await waitFor(() => expect(api.to("GET", "/v1/workspace/preferences")).toHaveLength(2));
    expect(api.to("POST", "/v1/workspace/preferences/consent")).toHaveLength(1);
  });
});
