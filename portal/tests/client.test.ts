/**
 * The API client's contract: CSRF on every mutation, same-origin only, bounded bodies,
 * neutral errors, and nothing logged.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  assertSameOriginPath,
  CSRF_HEADER,
  IDEMPOTENCY_HEADER,
  MAX_BODY_BYTES,
  request,
  requiresCsrf,
  retryKey,
  withDeadline,
} from "../src/api/client.ts";
import { ApiError, isKnownErrorCode, messageForCode } from "../src/api/errors.ts";
import { CSRF_COOKIE_HOST_NAME, CSRF_COOKIE_NAME, readCsrfToken } from "../src/lib/csrf.ts";
import { CSRF_COOKIE, CSRF_VALUE, jar, json, noContent, refusal } from "./harness.tsx";

let calls: Array<{ path: string; init: RequestInit }>;

function stubFetch(response: () => Response): void {
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ path: String(input), init: init ?? {} });
    return response();
  });
}

beforeEach(() => {
  calls = [];
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("path guard", () => {
  it.each([
    "//evil.example/v1/account",
    "https://evil.example/v1/account",
    "http://evil.example/v1/account",
    "/v2/account",
    "v1/account",
    "/account",
    "/v1/\\account",
    "",
  ])("refuses %j before anything is sent", (path) => {
    expect(() => assertSameOriginPath(path)).toThrow(ApiError);
  });

  it("accepts an ordinary /v1 path", () => {
    expect(() => assertSameOriginPath("/v1/account/sessions")).not.toThrow();
  });

  it("never reaches fetch for a refused path", async () => {
    stubFetch(() => json({}));
    await expect(request("//evil.example/v1/account")).rejects.toBeInstanceOf(ApiError);
    expect(calls).toHaveLength(0);
  });
});

describe("CSRF on mutations", () => {
  it("sends the cookie's value in the header", async () => {
    jar.set(CSRF_COOKIE, CSRF_VALUE);
    stubFetch(() => json({ ok: true }));
    await request("/v1/account/logout", { method: "POST" });
    const headers = new Headers(calls[0]?.init.headers);
    expect(headers.get(CSRF_HEADER)).toBe(CSRF_VALUE);
  });

  it("refuses a mutation with no CSRF cookie, without sending it", async () => {
    stubFetch(() => json({ ok: true }));
    await expect(request("/v1/account/logout", { method: "POST" })).rejects.toMatchObject({
      status: 401,
      code: "authentication_required",
    });
    expect(calls).toHaveLength(0);
  });

  it.each(["POST", "PUT", "PATCH", "DELETE"])("requires it for %s", async (method) => {
    stubFetch(() => noContent());
    await expect(request("/v1/workspace", { method: method as "POST" })).rejects.toMatchObject({
      status: 401,
    });
    expect(calls).toHaveLength(0);
  });

  /**
   * The pre-authentication routes are the exception, and the exception is the interesting
   * part: they are not cookie-authenticated, so there is no ambient authority for a CSRF
   * token to defend and no session secret in existence to prove knowledge of. Requiring one
   * would make signing up and signing in impossible, which is how this was found.
   */
  it.each([
    "/v1/account/signup",
    "/v1/account/verification/request",
    "/v1/account/verification/complete",
    "/v1/account/recovery/request",
    "/v1/account/recovery/complete",
    "/v1/account/login",
  ])("sends %s without a CSRF token and without a session", async (path) => {
    stubFetch(() => json({ status: "accepted" }));
    await expect(request(path, { method: "POST", body: {} })).resolves.toBeDefined();
    expect(calls).toHaveLength(1);
    expect(new Headers(calls[0]?.init.headers).get(CSRF_HEADER)).toBeNull();
  });

  it("classifies every route the portal calls", () => {
    expect(requiresCsrf("GET", "/v1/account")).toBe(false);
    expect(requiresCsrf("POST", "/v1/account/login")).toBe(false);
    // A cookie-authenticated mutation, and the one this milestone added.
    expect(requiresCsrf("POST", "/v1/account/password")).toBe(true);
    expect(requiresCsrf("POST", "/v1/account/logout")).toBe(true);
    expect(requiresCsrf("PUT", "/v1/workspace/preferences")).toBe(true);
    expect(requiresCsrf("DELETE", "/v1/workspace/credentials/x")).toBe(true);
  });

  it("does not exempt a path that merely starts with an exempt one", async () => {
    // "/v1/account/login-as" is not "/v1/account/login". Set membership, not a prefix test.
    stubFetch(() => json({}));
    await expect(request("/v1/account/login/elsewhere", { method: "POST" })).rejects.toMatchObject({
      status: 401,
    });
    expect(calls).toHaveLength(0);
  });

  it("does not require it for a read", async () => {
    stubFetch(() => json({ ok: true }));
    await expect(request("/v1/account")).resolves.toEqual({ ok: true });
    const headers = new Headers(calls[0]?.init.headers);
    expect(headers.get(CSRF_HEADER)).toBeNull();
  });

  it("reads the cookie fresh on every request, never a cached copy", async () => {
    jar.set(CSRF_COOKIE, CSRF_VALUE);
    stubFetch(() => json({ ok: true }));
    await request("/v1/account/logout", { method: "POST" });

    // Another tab signed in, or a password change replaced the session: the cookie changed.
    const replacement = "fbc_SECONDSECRETVALUEnotarealsecret0000000000";
    jar.set(CSRF_COOKIE, replacement);
    await request("/v1/account/logout", { method: "POST" });

    expect(new Headers(calls[0]?.init.headers).get(CSRF_HEADER)).toBe(CSRF_VALUE);
    expect(new Headers(calls[1]?.init.headers).get(CSRF_HEADER)).toBe(replacement);
  });

  it("sends credentials same-origin, so the HttpOnly session cookie rides along", async () => {
    jar.set(CSRF_COOKIE, CSRF_VALUE);
    stubFetch(() => json({}));
    await request("/v1/account/logout", { method: "POST" });
    expect(calls[0]?.init.credentials).toBe("same-origin");
  });

  it("passes an idempotency key when one is given", async () => {
    jar.set(CSRF_COOKIE, CSRF_VALUE);
    stubFetch(() => json({}));
    await request("/v1/account/workspaces", { method: "POST", idempotencyKey: "ws-abc" });
    expect(new Headers(calls[0]?.init.headers).get(IDEMPOTENCY_HEADER)).toBe("ws-abc");
  });
});

describe("the CSRF cookie itself", () => {
  it("prefers the __Host- prefixed value when both are present", () => {
    // A sibling subdomain can set an unprefixed cookie of the same name; it cannot set a
    // __Host- one. Preferring the prefixed value means cookie tossing cannot displace the
    // real secret -- and a tossed value could forge nothing anyway, because the database
    // compares the header against the session's own fingerprint.
    const source = `${CSRF_COOKIE_NAME}=tossed; ${CSRF_COOKIE_HOST_NAME}=${CSRF_VALUE}`;
    expect(readCsrfToken(source)).toBe(CSRF_VALUE);
  });

  it("falls back to the unprefixed name where the cookie is not Secure", () => {
    expect(readCsrfToken(`${CSRF_COOKIE_NAME}=${CSRF_VALUE}`)).toBe(CSRF_VALUE);
  });

  it("is null when absent, empty, or malformed", () => {
    expect(readCsrfToken("")).toBeNull();
    expect(readCsrfToken("other=1")).toBeNull();
    expect(readCsrfToken(`${CSRF_COOKIE_NAME}=`)).toBeNull();
    expect(readCsrfToken(`${CSRF_COOKIE_NAME}=%E0%A4%A`)).toBeNull();
  });

  it("decodes a percent-encoded value", () => {
    expect(readCsrfToken(`${CSRF_COOKIE_NAME}=${encodeURIComponent(CSRF_VALUE)}`)).toBe(CSRF_VALUE);
  });

  it("is not confused by another cookie whose name contains it", () => {
    expect(readCsrfToken(`not_fb_csrf=wrong; ${CSRF_COOKIE_NAME}=${CSRF_VALUE}`)).toBe(CSRF_VALUE);
  });
});

describe("bounded bodies", () => {
  it("refuses an oversized body locally, without sending it", async () => {
    jar.set(CSRF_COOKIE, CSRF_VALUE);
    stubFetch(() => json({}));
    const oversized = { note: "x".repeat(MAX_BODY_BYTES + 1) };
    await expect(
      request("/v1/workspace/preferences", { method: "PUT", body: oversized }),
    ).rejects.toMatchObject({ status: 413, code: "request_too_large" });
    expect(calls).toHaveLength(0);
  });

  it("sends a body at the limit", async () => {
    jar.set(CSRF_COOKIE, CSRF_VALUE);
    stubFetch(() => json({}));
    // Leave room for the JSON envelope around the value.
    const fits = { note: "x".repeat(MAX_BODY_BYTES - 100) };
    await expect(
      request("/v1/workspace/preferences", { method: "PUT", body: fits }),
    ).resolves.toBeDefined();
    expect(calls).toHaveLength(1);
  });

  it("counts bytes, not characters, so a multi-byte body cannot slip past", async () => {
    jar.set(CSRF_COOKIE, CSRF_VALUE);
    stubFetch(() => json({}));
    // Each of these is three bytes in UTF-8 and one JavaScript character.
    const body = { note: "☃".repeat(MAX_BODY_BYTES / 2) };
    await expect(
      request("/v1/workspace/preferences", { method: "PUT", body }),
    ).rejects.toMatchObject({ status: 413 });
  });
});

describe("refusals", () => {
  it.each([
    [401, "authentication_required"],
    [403, "forbidden"],
    [404, "not_found"],
    [409, "conflict"],
    [412, "workspace_required"],
    [413, "request_too_large"],
    [422, "invalid_request"],
    [503, "service_unavailable"],
  ])("turns %i %s into an ApiError with a written sentence", async (status, code) => {
    stubFetch(() => refusal(status, code));
    const error = await request("/v1/account").catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(status);
    expect((error as ApiError).code).toBe(code);
    expect((error as ApiError).message).toBe(messageForCode(code));
    expect(isKnownErrorCode(code)).toBe(true);
  });

  it("never renders an unrecognised code, so the error field cannot become a channel", async () => {
    const hostile = "<script>alert(1)</script>";
    stubFetch(() => refusal(400, hostile));
    const error = (await request("/v1/account").catch((caught: unknown) => caught)) as ApiError;
    expect(error.code).toBe(hostile);
    expect(error.message).not.toContain("script");
    expect(error.message).toBe("That did not work. Nothing was changed.");
  });

  it("turns a non-JSON refusal into an ApiError carrying only the status", async () => {
    vi.stubGlobal("fetch", async () => new Response("<html>gateway</html>", { status: 502 }));
    const error = (await request("/v1/account").catch((caught: unknown) => caught)) as ApiError;
    expect(error.status).toBe(502);
    expect(error.message).not.toContain("html");
  });

  it("turns a transport failure into a neutral network error", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new TypeError("Failed to fetch https://internal.host/v1/account");
    });
    const error = (await request("/v1/account").catch((caught: unknown) => caught)) as ApiError;
    expect(error.code).toBe("network_error");
    expect(error.message).not.toContain("internal.host");
  });

  it("returns null for 204, so a delete does not have to parse an empty body", async () => {
    jar.set(CSRF_COOKIE, CSRF_VALUE);
    stubFetch(() => noContent());
    await expect(request("/v1/workspace/members/x", { method: "DELETE" })).resolves.toBeNull();
  });

  it("classifies the statuses the portal branches on", () => {
    expect(new ApiError(401, "authentication_required").isUnauthenticated).toBe(true);
    expect(new ApiError(412, "workspace_required").needsWorkspace).toBe(true);
    expect(new ApiError(403, "forbidden").isForbidden).toBe(true);
    expect(new ApiError(404, "not_found").isUnauthenticated).toBe(false);
  });
});

describe("retry keys", () => {
  it("are unique per call, so a retry is never a replay of a different request", () => {
    const keys = new Set(Array.from({ length: 256 }, () => retryKey("ws")));
    expect(keys.size).toBe(256);
  });

  it("carry their prefix and a 128-bit hex suffix", () => {
    expect(retryKey("issue")).toMatch(/^issue-[0-9a-f]{32}$/);
  });

  it("fit the API's key grammar", () => {
    // control_plane/api/app.py bounds a key at 200 characters and refuses anything that
    // looks like a secret; this is well inside both.
    expect(retryKey("rotate").length).toBeLessThan(60);
  });
});

describe("where a refusal came from", () => {
  it("marks a server answer as the server's", async () => {
    stubFetch(() => refusal(401, "authentication_required"));
    await expect(request("/v1/account")).rejects.toMatchObject({ status: 401, origin: "server" });
  });

  it("marks a refusal the client made before sending as the client's", async () => {
    // No CSRF cookie: refused locally, with the same status a server would use and a
    // different origin, so a sign-out cannot mistake it for the server's verdict.
    stubFetch(() => noContent());
    await expect(request("/v1/account/logout", { method: "POST" })).rejects.toMatchObject({
      status: 401,
      code: "authentication_required",
      origin: "client",
    });
    expect(calls).toHaveLength(0);
  });

  it("marks a transport failure as the client's, and as transient", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new TypeError("Failed to fetch");
    });
    await expect(request("/v1/account")).rejects.toMatchObject({
      status: 0,
      code: "network_error",
      origin: "client",
      isTransient: true,
    });
  });

  it("marks a 5xx as transient and a 4xx as not", () => {
    expect(new ApiError(503, "service_unavailable").isTransient).toBe(true);
    expect(new ApiError(500, "internal_error").isTransient).toBe(true);
    expect(new ApiError(404, "not_found").isTransient).toBe(false);
    expect(new ApiError(409, "workspace_mismatch").isWorkspaceMismatch).toBe(true);
    expect(new ApiError(409, "conflict").isWorkspaceMismatch).toBe(false);
  });

  it("has a sentence for the workspace mismatch, and it says nothing was saved", () => {
    expect(isKnownErrorCode("workspace_mismatch")).toBe(true);
    expect(messageForCode("workspace_mismatch")).toMatch(/nothing was saved/i);
  });
});

describe("a request under a deadline", () => {
  // A sign-out, or the validity read after one, that never answers must become a failure
  // the page can report, not a button that says "Working…" forever over a session that may
  // still be live. These prove the wiring: a real timer, a real abort, and nothing left
  // armed afterwards.
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  /** A request that answers only when its signal tells it to stop. */
  function stalled(signal: AbortSignal): Promise<never> {
    return new Promise((_, reject) => {
      signal.addEventListener("abort", () => reject(signal.reason), { once: true });
    });
  }

  it("aborts the request at the deadline, and not before, with a timeout reason", async () => {
    let seen: AbortSignal | null = null;
    const outcome = withDeadline(1000, undefined, (signal) => {
      seen = signal;
      return stalled(signal);
    });
    expect(seen).toBeInstanceOf(AbortSignal);
    expect(vi.getTimerCount()).toBe(1);

    vi.advanceTimersByTime(999);
    expect((seen as unknown as AbortSignal).aborted).toBe(false);
    vi.advanceTimersByTime(1);
    expect((seen as unknown as AbortSignal).aborted).toBe(true);
    expect(((seen as unknown as AbortSignal).reason as DOMException).name).toBe("TimeoutError");
    await expect(outcome).rejects.toMatchObject({ name: "TimeoutError" });
    // The timer fired and is gone; nothing is left to fire into a later request.
    expect(vi.getTimerCount()).toBe(0);
  });

  it("clears the timer when the request settles first", async () => {
    await expect(withDeadline(1000, undefined, () => Promise.resolve("answered"))).resolves.toBe(
      "answered",
    );
    expect(vi.getTimerCount()).toBe(0);

    await expect(
      withDeadline(1000, undefined, () => Promise.reject(new Error("refused"))),
    ).rejects.toThrow("refused");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("follows the operation's own signal, and detaches from it afterwards", async () => {
    const operation = new AbortController();
    let seen: AbortSignal | null = null;
    const outcome = withDeadline(1000, operation.signal, (signal) => {
      seen = signal;
      return stalled(signal);
    });
    const reason = new DOMException("The session was replaced.", "AbortError");
    operation.abort(reason);
    expect((seen as unknown as AbortSignal).aborted).toBe(true);
    expect((seen as unknown as AbortSignal).reason).toBe(reason);
    await expect(outcome).rejects.toBe(reason);
    // The abort settled the request, so the deadline is released with it.
    expect(vi.getTimerCount()).toBe(0);

    // A request that settles on its own leaves no listener behind on the long-lived signal.
    const another = new AbortController();
    const listened = vi.spyOn(another.signal, "removeEventListener");
    await withDeadline(1000, another.signal, () => Promise.resolve(null));
    expect(listened).toHaveBeenCalledWith("abort", expect.any(Function));
  });

  it("starts already aborted when the operation is already over", async () => {
    const operation = new AbortController();
    operation.abort(new DOMException("Torn down.", "AbortError"));
    let seen: AbortSignal | null = null;
    await expect(
      withDeadline(1000, operation.signal, (signal) => {
        seen = signal;
        return signal.aborted ? Promise.reject(signal.reason) : Promise.resolve(null);
      }),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect((seen as unknown as AbortSignal).aborted).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });
});
