/**
 * The test harness: a fake **transport**, not a fake API.
 *
 * The distinction matters and is the reason this file is shaped the way it is. What is
 * replaced here is `fetch` -- the wire -- and nothing above it. Every test still exercises the
 * real client, the real CSRF read, the real path guard, the real error mapping, the real
 * session context, the real router and the real components. The routes below answer with the
 * **exact** shapes `control_plane/api/app.py` returns, including its `{"error": code}`
 * refusals and its `Set-Cookie` behaviour, and the Python suite
 * (`control_plane/tests/test_portal_*.py`) is what holds the server to those shapes against a
 * real PostgreSQL 16. Neither half proves the system alone; together they cover the seam.
 *
 * The fake also carries a **cookie jar**, because the properties under test are cookie
 * properties: that the CSRF cookie survives a reload, that two tabs share it, that logout
 * clears it, that a mutation without it is refused. A jar that ignored `Set-Cookie` would
 * make all four vacuously pass.
 */

import { type RenderResult, render } from "@testing-library/react";
import { type ReactElement, StrictMode } from "react";
import { vi } from "vitest";
import { App } from "../src/App.tsx";
import { SessionProvider } from "../src/auth/session.tsx";
import { RouterProvider } from "../src/lib/router.tsx";

export interface RecordedRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
  /** The signal the client sent, when it sent one: a bounded request, or one an operation owns. */
  signal?: AbortSignal;
  /** The `cache` mode the client asked for, when it asked for one. */
  cache?: RequestCache;
}

type Handler = (request: RecordedRequest) => Response | Promise<Response>;

/** A promise settled by the test, for a response that must arrive at a chosen moment. */
export interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason: unknown) => void;
}

export function deferred<T>(): Deferred<T> {
  let resolve: (value: T) => void = () => undefined;
  let reject: (reason: unknown) => void = () => undefined;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** What an aborted request rejects with: the signal's reason, as `fetch` would. */
function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException("The operation was aborted.", "AbortError");
}

/** The handler's answer as a promise, whether it returned, resolved, threw or rejected. */
function invoke(handler: Handler, record: RecordedRequest): Promise<Response> {
  return new Promise<Response>((resolve, reject) => {
    try {
      Promise.resolve(handler(record)).then(resolve, reject);
    } catch (error) {
      reject(error);
    }
  });
}

/** The answer, unless the signal aborts first -- in which case the abort's reason, promptly. */
function raceAbort(answer: Promise<Response>, signal: AbortSignal): Promise<Response> {
  return new Promise<Response>((resolve, reject) => {
    const onAbort = () => reject(abortReason(signal));
    signal.addEventListener("abort", onAbort, { once: true });
    const release = () => signal.removeEventListener("abort", onAbort);
    answer.then(
      (response) => {
        release();
        resolve(response);
      },
      (error) => {
        release();
        reject(error);
      },
    );
  });
}

/** A minimal document-cookie jar, so cookie behaviour is real inside a test. */
export const jar = {
  set(name: string, value: string): void {
    document.cookie = `${name}=${encodeURIComponent(value)}; path=/`;
  },
  clear(name: string): void {
    document.cookie = `${name}=; Max-Age=0; path=/`;
  },
  get(name: string): string | null {
    for (const entry of document.cookie.split(";")) {
      const [key, ...rest] = entry.trim().split("=");
      if (key === name) return decodeURIComponent(rest.join("="));
    }
    return null;
  },
  all(): string {
    return document.cookie;
  },
};

export const CSRF_VALUE = "fbc_TESTCSRFSECRETVALUEnotarealsecret00000000";
export const SESSION_COOKIE = "fb_session";
export const CSRF_COOKIE = "fb_csrf";

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export function noContent(): Response {
  return new Response(null, { status: 204 });
}

/** The API's refusal shape, exactly: one field, and never a value. */
export function refusal(status: number, code: string): Response {
  return new Response(JSON.stringify({ error: code }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export class FakeApi {
  readonly requests: RecordedRequest[] = [];
  private readonly handlers = new Map<string, Handler>();

  /** `on("GET /v1/account", …)`. A path with no handler is a test bug, and says so. */
  on(route: string, handler: Handler): this {
    this.handlers.set(route, handler);
    return this;
  }

  /** A convenience for the common "this route returns this body" case. */
  reply(route: string, body: unknown, status = 200): this {
    return this.on(route, () => json(body, status));
  }

  /**
   * Replace `fetch`. The fake honours the request's `AbortSignal` the way the wire does: a
   * request whose signal is already aborted rejects at once, and one aborted while the
   * handler is still deciding rejects then, with the signal's reason, whatever the handler
   * later returns. `abortable: false` is a wire that ignores the abort and delivers the
   * handler's answer regardless -- the shape a test needs when it is the *fence* on a late
   * answer, rather than the abort, that is under test.
   */
  install({ abortable = true }: { abortable?: boolean } = {}): void {
    vi.stubGlobal("fetch", (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const record = this.record(input, init);
      const handler =
        this.handlers.get(`${record.method} ${record.path}`) ??
        this.matchTemplate(record.method, record.path);
      if (!handler) {
        return Promise.reject(new Error(`no fake handler for ${record.method} ${record.path}`));
      }
      const signal = record.signal;
      if (signal?.aborted) return Promise.reject(abortReason(signal));
      const answer = invoke(handler, record);
      return abortable && signal ? raceAbort(answer, signal) : answer;
    });
  }

  /** What the client sent, as the wire would see it. */
  private record(input: RequestInfo | URL, init?: RequestInit): RecordedRequest {
    const path = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    // The browser attaches cookies; this fake records what would have been sent so a test
    // can assert on it, and the client's own CSRF read has already happened by now.
    const cookie = jar.all();
    if (cookie) headers.cookie = cookie;
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    const signal = init?.signal ?? undefined;
    const record: RecordedRequest = {
      method,
      path,
      headers,
      body,
      ...(signal ? { signal } : {}),
      ...(init?.cache ? { cache: init.cache } : {}),
    };
    this.requests.push(record);
    return record;
  }

  /** Match a handler registered with `{id}` in place of a path segment. */
  private matchTemplate(method: string, path: string): Handler | undefined {
    for (const [route, handler] of this.handlers) {
      const [routeMethod, routePath] = route.split(" ");
      if (routeMethod !== method || !routePath?.includes("{id}")) continue;
      const pattern = new RegExp(`^${routePath.replace(/\{id\}/g, "[^/]+")}$`);
      if (pattern.test(path)) return handler;
    }
    return undefined;
  }

  /** Every request this test made to one route, for asserting headers and bodies. */
  to(method: string, path: string): RecordedRequest[] {
    return this.requests.filter((request) => request.method === method && request.path === path);
  }

  /** Whether any request carried a given string anywhere -- header, path or body. */
  anyCarried(value: string): boolean {
    return this.requests.some(
      (request) =>
        request.path.includes(value) ||
        Object.values(request.headers).some((header) => header.includes(value)) ||
        JSON.stringify(request.body ?? null).includes(value),
    );
  }
}

// ------------------------------------------------------------------------- fixtures

export const ACCOUNT_ID = "11111111-1111-4111-8111-111111111111";
export const SESSION_ID = "22222222-2222-4222-8222-222222222222";
export const WORKSPACE_ID = "33333333-3333-4333-8333-333333333333";
export const OTHER_WORKSPACE_ID = "44444444-4444-4444-8444-444444444444";
export const MEMBERSHIP_ID = "55555555-5555-4555-8555-555555555555";
export const CREDENTIAL_ID = "66666666-6666-4666-8666-666666666666";

export function profile(overrides: Record<string, unknown> = {}) {
  return {
    account_id: ACCOUNT_ID,
    email: "person@example.com",
    email_verified: true,
    created_at: "2026-09-01T10:00:00+00:00",
    session: {
      session_id: SESSION_ID,
      workspace_id: WORKSPACE_ID,
      role: "owner",
      expires_at: "2026-09-10T10:00:00+00:00",
    },
    ...overrides,
  };
}

export function membershipList(role = "owner") {
  return {
    workspaces: [
      {
        workspace_id: WORKSPACE_ID,
        slug: "acme",
        name: "Acme",
        role,
        membership_id: MEMBERSHIP_ID,
        joined_at: "2026-09-01T10:00:00+00:00",
      },
    ],
  };
}

export function workspaceDetail(role = "owner") {
  return {
    workspace_id: WORKSPACE_ID,
    slug: "acme",
    name: "Acme",
    role,
    membership_id: MEMBERSHIP_ID,
    created_at: "2026-09-01T10:00:00+00:00",
  };
}

export function preferences(overrides: Record<string, unknown> = {}) {
  return {
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
    ...overrides,
  };
}

export const CONSENT_DOCUMENT = {
  version: "provider-policy-v1-d.1",
  title: "Execution placement, subprocessors and what Firmbatch can and cannot honour",
  authority: "Firmbatch v1 target architecture revision D.1, sections 3.3 and 5.4.",
  sections: [
    {
      heading: "The exclusion v1 cannot honour",
      body: [
        "Because the payload plane is Amazon S3, a customer who excludes Amazon altogether cannot be served by Firmbatch v1.",
      ],
    },
  ],
  current_version: "provider-policy-v1-d.1",
  versions: ["provider-policy-v1-d.1"],
};

/**
 * A signed-in, workspace-bound portal, wired to `api`, at `path`.
 *
 * Sets both cookies, because that is what a real login leaves behind, and points the jsdom
 * location at the route under test.
 */
export function signedIn(api: FakeApi, path = "/", role = "owner"): FakeApi {
  jar.set(SESSION_COOKIE, "fbs_TESTSESSIONSECRETnotarealsecret000000000");
  jar.set(CSRF_COOKIE, CSRF_VALUE);
  window.history.replaceState(null, "", path);
  api
    .reply("GET /v1/account", profile())
    .reply("GET /v1/account/workspaces", membershipList(role))
    .reply("GET /v1/workspace", workspaceDetail(role));
  return api;
}

/** A signed-out portal at `path`: no cookies at all. */
export function signedOut(api: FakeApi, path = "/login"): FakeApi {
  window.history.replaceState(null, "", path);
  api.on("GET /v1/account", () => refusal(401, "authentication_required"));
  return api;
}

/**
 * Render the whole portal. `strict` wraps it in `StrictMode`, exactly as `main.tsx` does in
 * production, so that effect replay and double-invoked initializers are part of the test.
 */
export function renderPortal({ strict = false }: { strict?: boolean } = {}): RenderResult {
  const tree = (
    <RouterProvider>
      <SessionProvider>
        <App />
      </SessionProvider>
    </RouterProvider>
  );
  return render(strict ? <StrictMode>{tree}</StrictMode> : tree);
}

/** Render an arbitrary element inside the providers, for a component-level test. */
export function renderWithProviders(element: ReactElement): RenderResult {
  return render(
    <RouterProvider>
      <SessionProvider>{element}</SessionProvider>
    </RouterProvider>,
  );
}
