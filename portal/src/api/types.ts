/**
 * The shapes the API returns, as this portal reads them.
 *
 * Hand-written rather than generated, and deliberately **narrower than the wire**: a field
 * the portal has no use for is absent here, so it cannot be rendered by accident. Nothing in
 * this file describes a secret, because the boundary returns exactly two -- the CSRF token
 * at session creation, and a freshly minted API credential, once -- and both are handled by
 * name at their single call site rather than flowing through a shared type.
 */

/** The four membership roles. Closed, and the same closed set the database enforces. */
export type Role = "owner" | "admin" | "member" | "viewer";

export const ROLES: readonly Role[] = ["owner", "admin", "member", "viewer"] as const;

export function isRole(value: unknown): value is Role {
  return typeof value === "string" && (ROLES as readonly string[]).includes(value);
}

/** What `GET /v1/account` says about the signed-in person and their current session. */
export interface AccountProfile {
  account_id: string;
  email: string;
  email_verified: boolean;
  created_at: string | null;
  session: {
    session_id: string;
    workspace_id: string | null;
    role: Role | null;
    expires_at: string | null;
  };
}

export interface AccountSession {
  session_id: string;
  created_at: string | null;
  last_seen_at: string | null;
  expires_at: string | null;
  workspace_id: string | null;
  current: boolean;
}

export interface WorkspaceMembershipSummary {
  workspace_id: string;
  slug: string;
  name: string;
  role: Role;
  membership_id: string;
  joined_at: string | null;
}

export interface WorkspaceDetail {
  workspace_id: string;
  slug: string;
  name: string;
  role: Role;
  membership_id: string | null;
  created_at: string | null;
}

export interface MemberSummary {
  membership_id: string;
  account_id: string;
  email: string;
  role: Role;
  joined_at: string | null;
}

export interface InvitationSummary {
  invitation_id: string;
  email: string;
  role: Role;
  created_at: string | null;
  expires_at: string | null;
  status: string;
}

export interface CredentialSummary {
  credential_id: string;
  label: string | null;
  scopes: string[];
  created_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
  rotated_from_id: string | null;
  membership_id: string | null;
  email: string | null;
  active: boolean;
}

/**
 * What `POST /v1/workspace/credentials` and `.../rotate` return.
 *
 * `credential` is the **only** plaintext secret this portal ever receives besides the CSRF
 * token, it is present exactly once, and a replay returns it as `null`. It is deliberately
 * typed as nullable so that every reader has to handle the replay case, and it never enters
 * any other structure.
 */
export interface IssuedCredential {
  credential_id: string;
  scopes: string[];
  expires_at: string | null;
  rotated_from_id: string | null;
  replayed: boolean;
  credential: string | null;
}

export interface CredentialHistoryEntry {
  audit_event_id: string;
  action: string;
  outcome: string;
  actor_kind: string;
  actor_account_id: string | null;
  occurred_at: string | null;
  details: Record<string, unknown>;
}

export type EvaluationIntent = "undecided" | "planning_evaluation" | "evaluation_not_needed";

export interface WorkspacePreferences {
  workspace_id: string;
  region_policy: string[];
  excluded_provider_classes: string[];
  model_profile_note: string | null;
  evaluation_intent: EvaluationIntent;
  consent_version: string | null;
  consent_acknowledged_at: string | null;
  consent_account_id: string | null;
  updated_at: string | null;
  /** Derived by the server from the architecture: an exclusion v1 cannot honour. */
  unservable_exclusion: boolean;
  current_consent_version: string;
}

export interface ConsentSection {
  heading: string;
  body: string[];
}

export interface ConsentDocument {
  version: string;
  title: string;
  authority: string;
  sections: ConsentSection[];
  current_version: string;
  versions: string[];
}

/** What a fresh session hands back. `csrf_token` is also set as a cookie by the API. */
export interface OpenedSession {
  account_id: string;
  session_id: string;
  expires_at: string | null;
  other_sessions_revoked?: boolean;
}
