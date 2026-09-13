/**
 * Every API call this portal makes, named once.
 *
 * A thin layer over {@link request}, and it exists for two reasons that are not style. First,
 * every path is built **here**, from a template and an identifier the caller supplies, so a
 * grep of this file is the complete list of what the portal can reach -- and the list
 * contains no supplier, capacity, pool, bridge, settlement, routing or operator route,
 * because no such route exists on the customer boundary at all. Second, the mutations that
 * need a retry key get one here rather than at the call site, so "did we send an
 * Idempotency-Key" is a property of the operation rather than of whoever called it.
 */

import { request, retryKey, withDeadline } from "./client.ts";
import type {
  AccountProfile,
  AccountSession,
  ConsentDocument,
  CredentialHistoryEntry,
  CredentialSummary,
  EvaluationIntent,
  InvitationSummary,
  IssuedCredential,
  MemberSummary,
  OpenedSession,
  Role,
  WorkspaceDetail,
  WorkspaceMembershipSummary,
  WorkspacePreferences,
} from "./types.ts";

/** A path segment that came from the API, checked before it is put in a URL. */
function id(value: string): string {
  if (!/^[0-9a-fA-F-]{36}$/.test(value)) {
    // Identifiers in this system are UUIDs. Anything else is a bug or a hostile value, and
    // encoding it would only make a malformed request; refusing keeps it off the wire.
    throw new Error("identifier is not a UUID");
  }
  return encodeURIComponent(value);
}

// --------------------------------------------------------------------- unauthenticated

export const consent = {
  /** The consent and subprocessor statement. Public: readable before an account exists. */
  read: (version?: string) =>
    request<ConsentDocument>(
      version ? `/v1/consent?version=${encodeURIComponent(version)}` : "/v1/consent",
    ),
};

export const auth = {
  signup: (email: string, password: string) =>
    request<{ status: string }>("/v1/account/signup", {
      method: "POST",
      body: { email, password },
    }),

  requestVerification: (email: string) =>
    request<{ status: string }>("/v1/account/verification/request", {
      method: "POST",
      body: { email },
    }),

  completeVerification: (token: string) =>
    request<{ verified: boolean }>("/v1/account/verification/complete", {
      method: "POST",
      body: { token },
    }),

  requestRecovery: (email: string) =>
    request<{ status: string }>("/v1/account/recovery/request", {
      method: "POST",
      body: { email },
    }),

  completeRecovery: (token: string, password: string) =>
    request<{ recovered: boolean }>("/v1/account/recovery/complete", {
      method: "POST",
      body: { token, password },
    }),

  /**
   * Sign in. The response carries the CSRF token, and the API also sets it as a cookie; the
   * portal reads the cookie from then on, so the token in this body is not stored anywhere.
   */
  login: (email: string, password: string) =>
    request<OpenedSession & { csrf_token: string }>("/v1/account/login", {
      method: "POST",
      body: { email, password },
    }),

  /**
   * Sign out. Bounded by a deadline, so that a sign-out that never answers becomes a
   * failure the page can report: the customer is still signed in until the server says
   * otherwise, and a request hanging forever would leave them unable to tell. `operation`
   * is the sign-out operation's own signal, so an operation that has become obsolete --
   * the session it was ending has been replaced -- can abandon the request.
   */
  logout: (operation?: AbortSignal) =>
    withDeadline(LOGOUT_TIMEOUT_MS, operation, (signal) =>
      request<null>("/v1/account/logout", { method: "POST", signal }),
    ),
};

/** How long a sign-out may take before it is reported as not having happened. */
export const LOGOUT_TIMEOUT_MS = 15_000;

/**
 * How long the one validity read after a failed sign-out may take before the answer is
 * "unknown". Shorter than the logout's own deadline: a read that has not answered in this
 * long is not going to settle anything, and the customer is waiting to be told where they
 * stand.
 */
export const SESSION_CHECK_TIMEOUT_MS = 10_000;

// ------------------------------------------------------------------------------ account

export const account = {
  profile: () => request<AccountProfile>("/v1/account"),

  /**
   * The one read a failed sign-out is allowed, and the only read that *decides* anything
   * about a session: the same `GET /v1/account` as {@link account.profile}, bounded by a
   * deadline, bypassing every cache, and abandoned with the operation it belongs to. A `200`
   * is the server saying the session is live; a `401` is the server having bound the cookie
   * and refused it; anything else has decided nothing.
   */
  checkSession: (operation?: AbortSignal) =>
    withDeadline(SESSION_CHECK_TIMEOUT_MS, operation, (signal) =>
      request<AccountProfile>("/v1/account", { signal, fresh: true }),
    ),

  /**
   * Change the password of the signed-in account.
   *
   * Ends every other session of this account -- other devices, other browsers -- and returns
   * a replacement for this one. The API sets the new session and CSRF cookies on the
   * response, so nothing here has to carry a secret between calls.
   */
  changePassword: (currentPassword: string, newPassword: string) =>
    request<OpenedSession>("/v1/account/password", {
      method: "POST",
      body: { current_password: currentPassword, new_password: newPassword },
    }),

  sessions: () => request<{ sessions: AccountSession[] }>("/v1/account/sessions"),

  revokeSession: (sessionId: string) =>
    request<null>(`/v1/account/sessions/${id(sessionId)}`, { method: "DELETE" }),

  revokeAllSessions: (keepCurrent: boolean) =>
    request<{ revoked: number }>("/v1/account/sessions/revoke-all", {
      method: "POST",
      body: { keep_current: keepCurrent },
    }),

  workspaces: () => request<{ workspaces: WorkspaceMembershipSummary[] }>("/v1/account/workspaces"),

  createWorkspace: (slug: string, name: string) =>
    request<{ workspace_id: string; membership_id: string; role: Role; replayed: boolean }>(
      "/v1/account/workspaces",
      { method: "POST", body: { slug, name }, idempotencyKey: retryKey("ws") },
    ),

  acceptInvitation: (token: string) =>
    request<{ workspace_id: string; membership_id: string; role: Role; replayed: boolean }>(
      "/v1/account/invitations/accept",
      { method: "POST", body: { token }, idempotencyKey: retryKey("inv") },
    ),

  /**
   * Select a workspace. The server re-derives the membership; a stale choice is refused.
   * The answer is the binding itself, which the session provider publishes as-is.
   */
  selectWorkspace: (workspaceId: string) =>
    request<{ workspace_id: string; role: Role; membership_id: string }>("/v1/account/workspace", {
      method: "PUT",
      body: { workspace_id: workspaceId },
    }),
};

// ---------------------------------------------------------------------------- workspace

/**
 * A read that answers for one workspace. Every workspace read the API serves names the
 * workspace it describes, so a page can compare it with the workspace it began under and
 * drop an answer that arrived after a switch rather than render one workspace's data under
 * another.
 */
export interface WorkspaceScoped {
  workspace_id: string;
}

/**
 * **Every operation here is made for a workspace**, and says which. A mutation's first
 * argument is the workspace the page or action began under, sent as the `X-Workspace-Id`
 * header; the database compares it with the workspace the session is bound to, under the
 * workspace lock, inside the mutation, and refuses a mismatch as `409 workspace_mismatch`
 * before anything is written -- the same answer a forged or another tenant's identifier
 * gets. A read answers with the workspace it describes. Neither relies on the session
 * lease alone, because switching workspaces deliberately keeps the browser session and its
 * generation: the workspace is its own dimension of "still the same request".
 */
export const workspace = {
  detail: () => request<WorkspaceDetail>("/v1/workspace"),

  rename: (workspaceId: string, name: string) =>
    request<{ workspace_id: string; name: string; replayed: boolean }>("/v1/workspace", {
      method: "PATCH",
      body: { name },
      idempotencyKey: retryKey("rename"),
      workspace: workspaceId,
    }),

  members: () => request<WorkspaceScoped & { members: MemberSummary[] }>("/v1/workspace/members"),

  removeMember: (workspaceId: string, membershipId: string) =>
    request<null>(`/v1/workspace/members/${id(membershipId)}`, {
      method: "DELETE",
      workspace: workspaceId,
    }),

  changeMemberRole: (workspaceId: string, membershipId: string, role: Role) =>
    request<{ membership_id: string; role: Role; replayed: boolean }>(
      `/v1/workspace/members/${id(membershipId)}`,
      { method: "PATCH", body: { role }, workspace: workspaceId },
    ),

  invitations: () =>
    request<WorkspaceScoped & { invitations: InvitationSummary[] }>("/v1/workspace/invitations"),

  invite: (workspaceId: string, email: string, role: Role) =>
    request<{ invitation_id: string; role: Role; expires_at: string | null; replayed: boolean }>(
      "/v1/workspace/invitations",
      {
        method: "POST",
        body: { email, role },
        idempotencyKey: retryKey("invite"),
        workspace: workspaceId,
      },
    ),

  revokeInvitation: (workspaceId: string, invitationId: string) =>
    request<null>(`/v1/workspace/invitations/${id(invitationId)}`, {
      method: "DELETE",
      workspace: workspaceId,
    }),

  preferences: () => request<WorkspacePreferences>("/v1/workspace/preferences"),

  /**
   * Replace the stated policy of the workspace the page loaded its form for.
   *
   * `workspaceId` is the **expected** workspace, the one the form was loaded for: carried
   * in the body, its original contract, and in the header like every other workspace
   * mutation. The API compares it with the workspace the session is bound to at the moment
   * of the write; a form loaded for one workspace whose shared session another tab has
   * since switched to another is refused rather than applied to the wrong one.
   */
  statePreferences: (
    workspaceId: string,
    body: {
      region_policy: string[];
      excluded_provider_classes: string[];
      model_profile_note: string | null;
      evaluation_intent: EvaluationIntent;
    },
  ) =>
    request<WorkspacePreferences>("/v1/workspace/preferences", {
      method: "PUT",
      body: { workspace_id: workspaceId, ...body },
      workspace: workspaceId,
    }),

  /** Acknowledge the displayed consent version, for the workspace the page loaded for. */
  acknowledgeConsent: (workspaceId: string, version: string) =>
    request<WorkspacePreferences>("/v1/workspace/preferences/consent", {
      method: "POST",
      body: { workspace_id: workspaceId, consent_version: version },
      workspace: workspaceId,
    }),
};

// -------------------------------------------------------------------------- credentials

export const credentials = {
  list: () =>
    request<WorkspaceScoped & { credentials: CredentialSummary[] }>("/v1/workspace/credentials"),

  issue: (workspaceId: string, scopes: string[], label: string | null, expiresAt: string | null) =>
    request<IssuedCredential>("/v1/workspace/credentials", {
      method: "POST",
      body: { scopes, label, expires_at: expiresAt },
      idempotencyKey: retryKey("issue"),
      workspace: workspaceId,
    }),

  rotate: (workspaceId: string, credentialId: string, expiresAt: string | null) =>
    request<IssuedCredential>(`/v1/workspace/credentials/${id(credentialId)}/rotate`, {
      method: "POST",
      body: { expires_at: expiresAt },
      idempotencyKey: retryKey("rotate"),
      workspace: workspaceId,
    }),

  revoke: (workspaceId: string, credentialId: string) =>
    request<null>(`/v1/workspace/credentials/${id(credentialId)}`, {
      method: "DELETE",
      workspace: workspaceId,
    }),

  history: (credentialId: string) =>
    request<WorkspaceScoped & { credential_id: string; history: CredentialHistoryEntry[] }>(
      `/v1/workspace/credentials/${id(credentialId)}/history`,
    ),
};
