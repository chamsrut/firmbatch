/**
 * Who is signed in, which workspace is selected, and what the server says they may do.
 *
 * **Nothing here is an authorization decision.** Every value in this context came from the
 * API in the last response, and the server re-derives the membership -- under a workspace
 * lock, from the row as it is now -- on every single request. So `role` is used to decide
 * what to *render*, and never to decide what is *allowed*: a demotion that happens while the
 * page is open makes the next request fail with `403`, which the portal handles by refreshing
 * this state and re-rendering, not by trusting what it already had.
 *
 * Nothing is persisted. The session cookie is `HttpOnly` and the CSRF cookie carries the
 * session's own lifetime, so a reload re-reads the truth from `GET /v1/account` and there is
 * nothing for `localStorage` to be useful for. See `vitest.setup.ts`, which makes touching
 * browser storage throw.
 *
 * **The session identity moves first, and everything else follows it.** The browser's
 * cookie changes the moment a login or a password change answers with a replacement
 * session, so the provider adopts the replacement **synchronously from that answer** --
 * generation advanced, session identity recorded, every pending piece of work from the old
 * session disowned and aborted -- and only then reads the account under the new identity.
 * There is no window in which an old response can be applied to the new session, because
 * the new session exists in the provider before any read under it is even started. If that
 * read fails, the replacement is a **live session whose profile is not loaded yet**, shown
 * with a retry; it is never the old session restored and never an anonymous state.
 *
 * **Every answer is fenced to the session that asked.** A request captures a
 * {@link SessionLease} -- the generation and the session identity -- when it starts, and
 * nothing its answer implies is applied unless that lease is still current. There is no
 * unfenced way to clear authentication: the routes hold no `forget`, only
 * {@link SessionApi.reconcile}, which takes the lease and reads a refusal for what it can
 * mean -- a definitive `401` from a **safe read** clears the matching session; a `401` from
 * a **mutation** is ambiguous and leads to one bounded validity read, which alone may clear.
 *
 * **Reads are ordered and coherent.** Every account load takes a sequence; only the latest
 * may publish, so an older load that answers late describes an older moment and is dropped.
 * A load reads the profile, the memberships and the bound workspace's detail, and publishes
 * only if the profile and the detail name the same workspace -- otherwise it reads again,
 * once, and drops the result rather than publish workspace A's binding with workspace B's
 * role. Selecting a workspace publishes the binding the mutation itself returned, at once
 * and on its own, and reloads the rest separately: a switch that succeeded is a switch,
 * whatever the follow-up read does.
 *
 * **Signing out is one operation, owned here, fenced the same way.** The first `signOut`
 * registers it synchronously; every control that asks while it is pending joins it, and
 * every control renders its shared pending and failure state.
 */

import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  account as accountApi,
  auth as authApi,
  workspace as workspaceApi,
} from "../api/endpoints.ts";
import { ApiError } from "../api/errors.ts";
import type { AccountProfile, Role, WorkspaceMembershipSummary } from "../api/types.ts";
import { SingleFlight } from "../lib/requests.ts";

export type SessionStatus = "loading" | "anonymous" | "authenticated";

export interface SessionState {
  status: SessionStatus;
  /** `null` while an authenticated session's account has not been read yet, or could not be. */
  profile: AccountProfile | null;
  workspaces: WorkspaceMembershipSummary[];
  /** The workspace the *server* says this session is bound to, not the one we last clicked. */
  workspaceId: string | null;
  /** The role the server most recently reported for the selected workspace. */
  role: Role | null;
  /** True once the first `GET /v1/account` has settled, so a guard can stop flashing. */
  ready: boolean;
  /** True while the account, its workspaces and the binding are being read. */
  loading: boolean;
  /**
   * Why the last account load under this session did not complete, or `null`. Set only by
   * a load that was still the latest when it failed; cleared by the next load that starts.
   * A session with a `loadProblem` is still a session: it is shown as signed in, with the
   * problem and a retry, never as signed out.
   */
  loadProblem: string | null;
}

/**
 * What a request captures when it starts, and must still hold for its answer to count.
 *
 * `generation` moves on every adoption, replacement or clearing of the session;
 * `sessionId` is the identity the provider held, or `null` when it held none. A same-session
 * change -- a workspace switch, a re-read of the role -- moves neither: the browser session
 * is the same one, and answers about it are still about it.
 */
export interface SessionLease {
  readonly generation: number;
  readonly sessionId: string | null;
}

/** How the request that was refused was made. A read is safe; a mutation is not. */
export type RequestKind = "read" | "mutation";

/**
 * What {@link SessionApi.reconcile} did with a refusal.
 *
 * `obsolete`: the lease is not current, nothing was done and nothing should be shown.
 * `cleared`: the session was cleared; the application will redirect. `retained`: a `401`
 * was checked and the session is still open (or could not be checked, which is treated the
 * same); the page should say so rather than repeat "your session has ended". `refreshed`: a
 * `403` re-read the session's authority. `unchanged`: the refusal said nothing about the
 * session.
 */
export type Reconciliation =
  | "obsolete"
  | "cleared"
  /**
   * The session was refused while a replacement of it is in flight -- a password change
   * or a login the provider is waiting on -- so the refusal may be the replacement's own
   * effect. Nothing was cleared and nothing should be shown; the replacement's outcome
   * settles it: adopted, the refusal is moot; failed, one bounded read decides.
   */
  | "deferred"
  | "retained"
  | "refreshed"
  | "unchanged";

/** What a page shows after a `401` that the validity read did not confirm. */
export const STILL_SIGNED_IN =
  "That request could not be authenticated, but this session is still open. Reload the page and try again.";

/** What the provider shows when the account behind a live session could not be read. */
export const ACCOUNT_LOAD_FAILED =
  "You are signed in, but your account could not be loaded. Check your connection and retry.";

/**
 * What a page shows after reconciling a refusal: `message` when the refusal said nothing
 * about the session; the still-signed-in sentence when a `401` was checked and found not to
 * be the end of the session; nothing when the session was cleared (the application is
 * leaving), the refusal was about a session that is gone, or a replacement in flight will
 * settle it.
 */
export function afterRefusal(outcome: Reconciliation, message: string): string | null {
  if (outcome === "retained") return STILL_SIGNED_IN;
  if (outcome === "cleared" || outcome === "obsolete" || outcome === "deferred") return null;
  return message;
}

/** How the one sign-out operation ended, for the control that asked. */
export type SignOutOutcome =
  /** The session is over, locally and on the server; the caller may leave for sign-in. */
  | "signed-out"
  /** The session is still live or could not be checked; {@link SignOutStatus.failure} says which. */
  | "incomplete"
  /** The session this operation was ending was replaced or cleared underneath it. Nothing was applied. */
  | "superseded";

/**
 * The shared state of the one sign-out operation, consumed by every sign-out control.
 *
 * `pending` is true from the synchronous moment the operation is registered until it
 * settles or is superseded, whichever control started it. `failure` is why the last
 * operation did not end in a signed-out state, and is cleared when a new one starts or the
 * session changes. No control keeps a busy flag of its own: this is the authority.
 */
export interface SignOutStatus {
  pending: boolean;
  failure: SignOutIncomplete | null;
}

/** What a successful workspace selection published, straight from the mutation's answer. */
export interface WorkspaceBinding {
  workspace_id: string;
  role: Role;
  membership_id: string;
}

export interface SessionApi extends SessionState {
  /** The lease a request must capture when it starts. Cheap; a snapshot, not a subscription. */
  lease: () => SessionLease;
  /** Whether a lease is still the current session. */
  holds: (lease: SessionLease) => boolean;
  /**
   * Re-read the account, its workspaces and the current binding from the server. Never
   * rejects: a load that fails leaves the state as it was and sets {@link SessionState.loadProblem}.
   * With a lease, a no-op when the lease is not current; always a no-op if the session was
   * replaced, or a newer load or a workspace switch started, while the reads were in flight.
   */
  refresh: (lease?: SessionLease) => Promise<void>;
  /**
   * Read the account again for the session held **now** -- the retry behind a
   * {@link SessionState.loadProblem}. The one caller of a refresh that carries no lease,
   * because its whole meaning is "the current session, whatever it is".
   */
  retryLoad: () => Promise<void>;
  /**
   * What a refusal means for the session, applied only if `lease` is still current. A
   * definitive `401` from a safe read clears the session; a `401` from a mutation is checked
   * with one bounded validity read and clears only if that read says the session is gone; a
   * `403` re-reads authority. Never rejects.
   */
  reconcile: (lease: SessionLease, error: unknown, kind: RequestKind) => Promise<Reconciliation>;
  signIn: (email: string, password: string) => Promise<void>;
  /**
   * End this session on the server, then forget it locally. Never rejects: it resolves with
   * the {@link SignOutOutcome}, and while an operation is pending every call returns that
   * operation's promise rather than starting another. The authenticated state is cleared
   * only after a successful logout, or after a failed logout when one validity read confirms
   * the session is already gone; otherwise it is left exactly as it was and
   * {@link SignOutStatus.failure} says why.
   */
  signOut: () => Promise<SignOutOutcome>;
  /** The shared pending and failure state of the sign-out operation. */
  signOutStatus: SignOutStatus;
  /**
   * Select a workspace. The server revalidates membership and may refuse, in which case this
   * rejects and nothing changes. When it accepts, the binding it returned is published at
   * once and this resolves with it; the account is then re-read separately, and a failure of
   * that read leaves the binding in place and sets {@link SessionState.loadProblem}.
   */
  selectWorkspace: (workspaceId: string) => Promise<WorkspaceBinding>;
  /**
   * The browser's session was replaced by a successful response -- a login, a password
   * change -- whose `session_id` this is. Adopts it synchronously: the generation moves,
   * every pending piece of work from the former session is disowned and aborted, and only
   * then is the account read under the new identity. Resolves once that read has settled,
   * whichever way; a failed read is a live session with an unloaded profile and a retry.
   */
  adoptReplacement: (sessionId: string) => Promise<void>;
  /**
   * Make a request that replaces the browser's session -- a login, a password change --
   * and adopt what it answers with, through {@link adoptReplacement}. While it is in flight
   * the provider knows a replacement is coming, so a refusal of the current session that
   * arrives meanwhile is deferred rather than believed: it may be the replacement's own
   * effect. Rejects with the request's failure, in which case a deferred refusal is settled
   * by one bounded read.
   */
  adoptFrom: <T extends { session_id: string }>(request: () => Promise<T>) => Promise<T>;
}

const SessionContext = createContext<SessionApi | null>(null);

/** The session is over. Raised by the readers below so a load has one branch for it. */
class SessionEnded extends Error {}

/** `401`, and only `401`, means "not signed in". Everything else is a failure to report. */
function endedIfUnauthenticated(error: unknown): never {
  if (error instanceof ApiError && error.isUnauthenticated) throw new SessionEnded();
  throw error;
}

async function readProfile(): Promise<AccountProfile> {
  try {
    return await accountApi.profile();
  } catch (error) {
    endedIfUnauthenticated(error);
  }
}

async function readWorkspaces(): Promise<WorkspaceMembershipSummary[]> {
  try {
    return (await accountApi.workspaces()).workspaces;
  } catch (error) {
    endedIfUnauthenticated(error);
  }
}

/**
 * The bound workspace as the server describes it -- its identity and the caller's role --
 * or `null` when nothing is bound.
 *
 * Read from `GET /v1/workspace` rather than taken from the membership list, because the list
 * is a snapshot and the binding is what the next request will actually be evaluated against.
 * When they disagree, the binding wins: a membership revoked since the list was drawn simply
 * is not there, and `412`/`404` here is that fact rather than an error worth showing. The
 * identity comes back with the role so a load can tell that the two reads it made describe
 * the same workspace.
 */
async function readBoundWorkspace(
  boundId: string | null,
): Promise<{ workspaceId: string; role: Role } | null> {
  if (boundId === null) return null;
  try {
    const detail = await workspaceApi.detail();
    return { workspaceId: detail.workspace_id, role: detail.role };
  } catch (error) {
    if (error instanceof ApiError && (error.needsWorkspace || error.status === 404)) return null;
    endedIfUnauthenticated(error);
  }
}

/** What one validity read found: the session is gone, still live, or could not be checked. */
export type SessionValidity = "ended" | "live" | "unknown";

/**
 * A sign-out that did not end in a signed-out state.
 *
 * `reason` is what the logout itself failed with; `validity` is what the one safe read
 * afterwards found. `live` means the customer is definitely still signed in; `unknown` means
 * nothing could be established either way, which the caller must treat as still signed in.
 */
export class SignOutIncomplete extends Error {
  readonly reason: unknown;
  readonly validity: Exclude<SessionValidity, "ended">;

  constructor(reason: unknown, validity: Exclude<SessionValidity, "ended">) {
    super(
      validity === "live"
        ? "The sign-out did not happen; this session is still live."
        : "The sign-out did not complete, and this session could not be checked.",
    );
    this.name = "SignOutIncomplete";
    this.reason = reason;
    this.validity = validity;
  }
}

interface Validity {
  validity: SessionValidity;
  sessionId: string | null;
}

/**
 * Exactly one safe read that says whether the browser's session is still live, and which
 * session it is.
 *
 * A refusal's own status proves nothing about the session. A `401` from a mutation is the
 * same neutral refusal the API gives a wrong CSRF secret on a perfectly live session -- the
 * reproduction the review supplied -- and a `5xx`, a timeout or a lost response may have
 * arrived and revoked the session, or never arrived at all. So the question is put to the
 * server once, through the existing authenticated account read, which is a `GET` with no
 * CSRF proof to get wrong: a `200` means live, and names the session the cookie now carries;
 * a `401` means the server bound the cookie and refused it, so the session is revoked,
 * expired or unknown and there is nothing left to end; anything else -- transport failure,
 * the read's own deadline, `5xx`, the operation being abandoned -- means it could not be
 * checked. Nothing here retries anything, and nothing here is inferred from cookie state.
 */
async function readValidity(operation: AbortSignal): Promise<Validity> {
  try {
    const profile = await accountApi.checkSession(operation);
    return { validity: "live", sessionId: profile.session.session_id };
  } catch (error) {
    if (error instanceof ApiError && error.isUnauthenticated) {
      return { validity: "ended", sessionId: null };
    }
    return { validity: "unknown", sessionId: null };
  }
}

/**
 * Whether a `401` says anything about the session at all. The API answers a wrong current
 * password with `401 invalid_credentials`: a verdict on the password, not on the session.
 * A `401 authentication_required` from the server, or the client's own refusal to send a
 * mutation with no CSRF cookie behind it, is about the session -- ambiguously.
 */
function concernsSession(error: ApiError): boolean {
  if (!error.isUnauthenticated) return false;
  return error.origin === "client" || error.code === "authentication_required";
}

/**
 * One sign-out, from the synchronous moment it is registered until it settles.
 *
 * `lease` is what the provider held when the operation began, and is the fence: an answer
 * is applied only while it is still current. `controller` aborts the logout and the validity
 * read together when the operation becomes obsolete. `obsolete` is set the moment the
 * provider disowns it, so a response that has already been received but not yet applied is
 * dropped too.
 */
interface SignOutOperation {
  readonly id: number;
  readonly lease: SessionLease;
  readonly controller: AbortController;
  obsolete: boolean;
  promise: Promise<SignOutOutcome>;
}

type SignOutResult = { kind: "signed-out" } | { kind: "incomplete"; failure: SignOutIncomplete };

/** One account load: its sequence, the lease it began under, and its promise for joiners. */
interface AccountLoad {
  readonly sequence: number;
  readonly lease: SessionLease;
  readonly promise: Promise<void>;
}

const EMPTY: SessionState = {
  status: "loading",
  profile: null,
  workspaces: [],
  workspaceId: null,
  role: null,
  ready: false,
  loading: true,
  loadProblem: null,
};

const IDLE: SignOutStatus = { pending: false, failure: null };

function abandoned(reason: string): DOMException {
  return new DOMException(reason, "AbortError");
}

/**
 * The state one coherent read publishes. A binding whose membership has gone is not a
 * binding: reporting the workspace id without a role would let a guard admit a page the next
 * request will refuse.
 */
function loaded(
  profile: AccountProfile,
  workspaces: WorkspaceMembershipSummary[],
  bound: { workspaceId: string; role: Role } | null,
): SessionState {
  return {
    status: "authenticated",
    profile,
    workspaces,
    workspaceId: bound === null ? null : bound.workspaceId,
    role: bound === null ? null : bound.role,
    ready: true,
    loading: false,
    loadProblem: null,
  };
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<SessionState>(EMPTY);
  const [signOutStatus, setSignOutStatus] = useState<SignOutStatus>(IDLE);

  // The fence. Refs rather than state, because an operation reads them at the moment it
  // applies an answer -- inside a promise continuation, with no render in between -- and a
  // value captured by a closure at render time is exactly the stale reading this exists to
  // prevent. `generation` only ever increases; `sessionId` is the identity of the session
  // the provider currently holds, `null` when it holds none.
  const generation = useRef(0);
  const sessionId = useRef<string | null>(null);
  // The account loads. `sequence` numbers every load; `latest` is the one that may publish
  // -- moved past every in-flight load by an adoption or a workspace switch, so that what
  // those loads answer is about a moment that has passed. `inFlight` lets a second ask join
  // the latest load rather than start a duplicate.
  const sequence = useRef(0);
  const latest = useRef(0);
  const inFlight = useRef<AccountLoad | null>(null);
  const operation = useRef<SignOutOperation | null>(null);
  const operationSequence = useRef(0);
  // The bounded validity reads in flight, so a session change can abandon them, and the one
  // in-flight read at a time that concurrent askers share. Correctness never depends on the
  // abort -- an answer may arrive regardless, and the lease drops it -- but a request whose
  // answer cannot matter should not be left to finish.
  const checks = useRef(new Set<AbortController>());
  const validity = useRef(new SingleFlight());
  // Replacements in flight (`adoptFrom`), and the refusal of the current session deferred
  // while one is: believed only if the replacement does not happen.
  const replacing = useRef(0);
  const deferredRefusal = useRef<SessionLease | null>(null);

  const lease = useCallback(
    (): SessionLease => ({ generation: generation.current, sessionId: sessionId.current }),
    [],
  );

  const holds = useCallback(
    (candidate: SessionLease): boolean =>
      candidate.generation === generation.current && candidate.sessionId === sessionId.current,
    [],
  );

  /** Make every in-flight load a stranger: none of them may publish or finish anything. */
  const invalidateLoads = useCallback(() => {
    sequence.current += 1;
    latest.current = sequence.current;
    inFlight.current = null;
  }, []);

  /**
   * Disown the pending sign-out and the pending validity reads: they belong to a session
   * that is no longer the current one. Their requests are aborted so they settle promptly,
   * and the sign-out's `obsolete` flag makes any answer that arrives anyway a no-op.
   */
  const supersede = useCallback((reason: string) => {
    const pending = operation.current;
    if (pending !== null) {
      operation.current = null;
      pending.obsolete = true;
      pending.controller.abort(abandoned(reason));
    }
    for (const check of checks.current) check.abort(abandoned(reason));
    checks.current.clear();
  }, []);

  /**
   * The one place the session identity changes, and it changes **synchronously**.
   *
   * Adopting a session -- a replacement from a login or a password change, one another tab
   * opened, or none at all -- moves the generation, records the identity, disowns and aborts
   * every pending piece of work from the former session, makes every in-flight load a
   * stranger and resets the sign-out status. All of that happens before this returns, so by
   * the time any read under the new identity is started there is no old answer that could
   * still be applied: every one of them now fails its lease.
   */
  const adopt = useCallback(
    (id: string | null, { keep = false }: { keep?: boolean } = {}) => {
      generation.current += 1;
      sessionId.current = id;
      supersede("The session this operation belonged to has been replaced.");
      invalidateLoads();
      setSignOutStatus(IDLE);
      setState((previous) => ({
        // A replacement of this account's own session -- a password change -- keeps the
        // account on screen while the replacement is read, so the page the customer is on
        // stays mounted and keeps what it was showing; a session of unknown provenance --
        // one another tab opened -- shows nothing until it has been read.
        ...(keep && previous.status === "authenticated" ? previous : EMPTY),
        status: id === null ? "anonymous" : "authenticated",
        ready: true,
        loading: id !== null,
        loadProblem: null,
      }));
    },
    [supersede, invalidateLoads],
  );

  /** Forget the session. Internal: every caller outside this file goes through a lease. */
  const forget = useCallback(() => adopt(null), [adopt]);

  /**
   * The one way a definitive refusal clears the session: only if `candidate` is still the
   * session there is, and not while a replacement of it is in flight -- then the refusal is
   * remembered, and settled by the replacement's outcome.
   */
  const clearForRefusal = useCallback(
    (candidate: SessionLease): Reconciliation => {
      if (!holds(candidate)) return "obsolete";
      if (replacing.current > 0) {
        deferredRefusal.current = candidate;
        return "deferred";
      }
      forget();
      return "cleared";
    },
    [holds, forget],
  );

  /** Whether load `number`, begun under `began`, is still the one that may publish. */
  const current = useCallback(
    (began: SessionLease, number: number): boolean => holds(began) && latest.current === number,
    [holds],
  );

  /**
   * One coherent read of the account: the profile, the memberships and the bound workspace.
   *
   * The three reads may straddle a workspace switch made elsewhere -- another tab, or this
   * page's own switcher -- and then the profile names one workspace and the detail another.
   * Such a set is not published: it is read again, once, and a second inconsistent set is
   * dropped with a problem rather than shown. `null` means "dropped".
   */
  // A load that discovers a session this provider did not know about adopts it, and the
  // adoption starts a load: the pair is mutually recursive, so the later one is reached
  // through a ref that is assigned once it exists.
  const adoptFromRead = useRef<(id: string) => void>(() => undefined);

  /**
   * The very first read, made while the provider holds no identity at all, finds the session
   * the cookie carries: that session is claimed in place. The generation moves and the
   * identity is recorded, exactly as an adoption does, but the load that found it goes on as
   * the load under it rather than being thrown away for a second read of the same thing.
   */
  const claim = useCallback(
    (id: string): SessionLease => {
      generation.current += 1;
      sessionId.current = id;
      supersede("The session this operation belonged to has been replaced.");
      setSignOutStatus(IDLE);
      return lease();
    },
    [supersede, lease],
  );

  /** What a load that did not complete leaves behind, if it is still the load that counts. */
  const failLoad = useCallback(
    (under: SessionLease, number: number, error: unknown) => {
      if (!current(under, number)) return;
      // A definitive refusal of this session on a safe read, or a first load that could
      // not reach the API at all, both end in the sign-in page: the first because the
      // server said so, the second because an indefinite spinner helps nobody and the
      // sign-in attempt will report the failure with a sentence they can act on. A
      // refusal while a replacement is in flight is deferred, like every other.
      if (error instanceof SessionEnded) {
        clearForRefusal(under);
        return;
      }
      if (under.sessionId === null) {
        forget();
        return;
      }
      // A network failure or a 500 under a live session must **not** sign the customer
      // out, and must not put the old session back either: the state stays what it is --
      // a replacement with no profile yet, or the last-known profile -- with the problem
      // and a retry.
      setState((previous) => ({ ...previous, loading: false, loadProblem: ACCOUNT_LOAD_FAILED }));
    },
    [current, forget, clearForRefusal],
  );

  /**
   * The lease a load goes on under once it has read the profile: the same one when the
   * profile names the session it began under; a claimed one when it began under none; and
   * `null` -- this load is a stranger now -- when the cookie carries a session this provider
   * did not know about (another tab signed in), which is adopted instead, and whose own load
   * reads the account again under it.
   */
  const identify = useCallback(
    (profile: AccountProfile, under: SessionLease): SessionLease | null => {
      if (profile.session.session_id === under.sessionId) return under;
      if (under.sessionId === null) return claim(profile.session.session_id);
      adoptFromRead.current(profile.session.session_id);
      return null;
    },
    [claim],
  );

  /**
   * One pass over the three reads. `null` when this load has become a stranger; otherwise
   * the lease it went on under and whether the pass was coherent enough to publish.
   */
  const readOnce = useCallback(
    async (
      under: SessionLease,
      number: number,
    ): Promise<{ lease: SessionLease; published: boolean } | null> => {
      const profile = await readProfile();
      if (!current(under, number)) return null;
      const identified = identify(profile, under);
      if (identified === null) return null;
      const workspaces = await readWorkspaces();
      const bound = await readBoundWorkspace(profile.session.workspace_id);
      if (!current(identified, number)) return null;
      const coherent = bound === null || bound.workspaceId === profile.session.workspace_id;
      if (coherent) setState(loaded(profile, workspaces, bound));
      return { lease: identified, published: coherent };
    },
    [current, identify],
  );

  const readAccount = useCallback(
    async (began: SessionLease, number: number): Promise<void> => {
      let under = began;
      try {
        for (let attempt = 0; attempt < 2; attempt += 1) {
          const outcome = await readOnce(under, number);
          if (outcome === null || outcome.published) return;
          under = outcome.lease;
        }
        failLoad(under, number, new Error("the reads describe different workspaces"));
      } catch (error) {
        failLoad(under, number, error);
      }
    },
    [readOnce, failLoad],
  );

  const load = useCallback(
    (candidate?: SessionLease): Promise<void> => {
      const began = candidate ?? lease();
      if (!holds(began)) return Promise.resolve();
      const joined = inFlight.current;
      if (joined !== null && joined.sequence === latest.current && holds(joined.lease)) {
        // The latest load is still in flight under this very session: one request serves
        // every asker, which is what a StrictMode replay of a mount effect becomes.
        return joined.promise;
      }
      sequence.current += 1;
      const number = sequence.current;
      latest.current = number;
      setState((previous) => ({ ...previous, loading: true, loadProblem: null }));
      const promise = readAccount(began, number).finally(() => {
        if (inFlight.current?.sequence === number) inFlight.current = null;
      });
      inFlight.current = { sequence: number, lease: began, promise };
      return promise;
    },
    [lease, holds, readAccount],
  );

  const adoptReplacement = useCallback(
    (id: string): Promise<void> => {
      adopt(id, { keep: true });
      return load();
    },
    [adopt, load],
  );
  adoptFromRead.current = (id: string) => {
    adopt(id);
    void load();
  };

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    // Teardown: a sign-out or validity read still pending when the provider unmounts is
    // abandoned, so its requests are aborted and its deadline cleared rather than left to
    // fire into nothing.
    return () => supersede("The portal was torn down.");
  }, [supersede]);

  /**
   * One validity read, shared: whoever asks while it is in flight gets the same answer. The
   * controller is registered so a session change abandons it.
   */
  const checkValidity = useCallback(
    (): Promise<Validity> =>
      validity.current.run(`validity:${generation.current}`, async () => {
        const controller = new AbortController();
        checks.current.add(controller);
        try {
          return await readValidity(controller.signal);
        } finally {
          checks.current.delete(controller);
        }
      }),
    [],
  );

  /**
   * The ambiguous case -- a mutation's `401`, or the client's own refusal to send one: one
   * bounded read decides, and only for the session that is still the current one when it
   * answers. Its answer is fenced regardless of the abort, because an answer may arrive
   * despite it.
   */
  const checkAmbiguous = useCallback(
    async (candidate: SessionLease): Promise<Reconciliation> => {
      const found = await checkValidity();
      if (!holds(candidate)) return "obsolete";
      if (found.validity === "ended") return clearForRefusal(candidate);
      if (found.validity === "live" && found.sessionId !== candidate.sessionId) {
        // The cookie now carries a different session -- another tab signed in -- and the
        // refusal was that session's. Adopt it; the lease moves with the adoption.
        await adoptReplacement(found.sessionId as string);
      }
      return "retained";
    },
    [checkValidity, holds, clearForRefusal, adoptReplacement],
  );

  const reconcile = useCallback(
    async (candidate: SessionLease, error: unknown, kind: RequestKind): Promise<Reconciliation> => {
      if (!holds(candidate)) return "obsolete";
      if (!(error instanceof ApiError)) return "unchanged";
      if (error.isForbidden) {
        // Authenticated, and not allowed: the role changed while the page was open. Re-read
        // the authority so the controls follow; the session itself is not in question.
        await load(candidate);
        return "refreshed";
      }
      if (!concernsSession(error)) return "unchanged";
      if (kind === "read" && error.origin === "server") {
        // A safe read, under this session, refused by the server: definitive.
        return clearForRefusal(candidate);
      }
      return checkAmbiguous(candidate);
    },
    [holds, load, clearForRefusal, checkAmbiguous],
  );

  const adoptFrom = useCallback(
    async <T extends { session_id: string }>(request: () => Promise<T>): Promise<T> => {
      replacing.current += 1;
      let opened: T;
      try {
        opened = await request();
      } catch (error) {
        replacing.current -= 1;
        const deferred = deferredRefusal.current;
        deferredRefusal.current = null;
        if (deferred !== null && replacing.current === 0 && holds(deferred)) {
          // The session was refused while this replacement was in flight, and the
          // replacement did not happen: the refusal is now the ambiguous kind, and one
          // bounded read settles it.
          void checkAmbiguous(deferred);
        }
        throw error;
      }
      replacing.current -= 1;
      deferredRefusal.current = null;
      // The API set the cookies on that response, and the response names the session they
      // belong to. It is adopted from the response -- before anything is read under it.
      await adoptReplacement(opened.session_id);
      return opened;
    },
    [holds, checkAmbiguous, adoptReplacement],
  );

  const signIn = useCallback(
    async (email: string, password: string) => {
      await adoptFrom(() => authApi.login(email, password));
    },
    [adoptFrom],
  );

  /** Whether `candidate` is still the operation whose answers may be applied. */
  const owns = useCallback(
    (candidate: SignOutOperation): boolean =>
      !candidate.obsolete && operation.current === candidate && holds(candidate.lease),
    [holds],
  );

  /**
   * Apply what an operation concluded -- if, and only if, it is still the current one. The
   * operation is released *before* the session is forgotten, because forgetting moves the
   * generation and would otherwise disown the very operation that is being applied.
   */
  const conclude = useCallback(
    (candidate: SignOutOperation, result: SignOutResult): SignOutOutcome => {
      if (!owns(candidate)) return "superseded";
      operation.current = null;
      if (result.kind === "signed-out") {
        setSignOutStatus(IDLE);
        forget();
        return "signed-out";
      }
      setSignOutStatus({ pending: false, failure: result.failure });
      return "incomplete";
    },
    [owns, forget],
  );

  const run = useCallback(
    async (candidate: SignOutOperation): Promise<SignOutOutcome> => {
      let failure: unknown = null;
      let ended = false;
      try {
        await authApi.logout(candidate.controller.signal);
        ended = true;
      } catch (error) {
        failure = error;
      }
      if (ended) return conclude(candidate, { kind: "signed-out" });
      // The logout failed or its outcome is unknown. Its status, its body and the cookies
      // this page can see decide nothing; one safe read of the account decides everything
      // -- and only for the session that is still the current one.
      if (!owns(candidate)) return "superseded";
      const found = await checkValidity();
      if (!owns(candidate)) return "superseded";
      if (found.validity === "ended") {
        // The server itself says the session is gone: forgetting it locally is catching up,
        // not pretending.
        return conclude(candidate, { kind: "signed-out" });
      }
      // Still live, or not checkable: the authenticated state stays exactly as it is, and
      // every control shows the failure and offers to try again. The one thing this must
      // never do is show a signed-out screen over a session that may still be open.
      return conclude(candidate, {
        kind: "incomplete",
        failure: new SignOutIncomplete(failure, found.validity),
      });
    },
    [conclude, owns, checkValidity],
  );

  const signOut = useCallback((): Promise<SignOutOutcome> => {
    const pending = operation.current;
    if (pending !== null) return pending.promise;
    // Registered synchronously, before the first await: a second call from anywhere in the
    // same tick finds it and joins it, so two controls clicked together send one logout.
    operationSequence.current += 1;
    const started: SignOutOperation = {
      id: operationSequence.current,
      lease: lease(),
      controller: new AbortController(),
      obsolete: false,
      promise: Promise.resolve("superseded"),
    };
    operation.current = started;
    setSignOutStatus({ pending: true, failure: null });
    started.promise = run(started);
    return started.promise;
  }, [lease, run]);

  const selectWorkspace = useCallback(
    async (workspaceId: string): Promise<WorkspaceBinding> => {
      const began = lease();
      const bound = await accountApi.selectWorkspace(workspaceId);
      if (!holds(began)) {
        // The session was replaced while the bind was in flight: the bind belongs to the
        // former session, and the replacement's own load describes the replacement.
        return bound;
      }
      // The bind succeeded, and the mutation's own answer is the binding: published at
      // once, as the selected workspace, before any follow-up read. Every load in flight
      // describes the previous binding and is made a stranger first.
      invalidateLoads();
      setState((previous) => ({
        ...previous,
        workspaceId: bound.workspace_id,
        role: bound.role,
        profile:
          previous.profile === null
            ? null
            : {
                ...previous.profile,
                session: {
                  ...previous.profile.session,
                  workspace_id: bound.workspace_id,
                  role: bound.role,
                },
              },
        loadProblem: null,
      }));
      // The supplementary read -- the membership list, the profile -- is its own operation:
      // its failure keeps the binding and reports itself as a load problem, never as a
      // switch that did not happen.
      void load(began);
      return bound;
    },
    [lease, holds, invalidateLoads, load],
  );

  const retryLoad = useCallback(() => load(), [load]);

  const value = useMemo<SessionApi>(
    () => ({
      ...state,
      lease,
      holds,
      refresh: load,
      retryLoad,
      reconcile,
      signIn,
      signOut,
      signOutStatus,
      selectWorkspace,
      adoptReplacement,
      adoptFrom,
    }),
    [
      state,
      lease,
      holds,
      load,
      retryLoad,
      reconcile,
      signIn,
      signOut,
      signOutStatus,
      selectWorkspace,
      adoptReplacement,
      adoptFrom,
    ],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionApi {
  const value = useContext(SessionContext);
  if (value === null) {
    throw new Error("useSession must be used inside a SessionProvider");
  }
  return value;
}

/**
 * What the *rendering* layer may assume about a role. Never what the server enforces.
 *
 * Named so that every call site reads as a statement about the interface -- "may this
 * control be shown" -- rather than as a statement about authority. The server decides
 * authority, on every request, from the membership as it is at that moment.
 */
export const shows = {
  teamManagement: (role: Role | null): boolean => role === "owner" || role === "admin",
  workspaceSettings: (role: Role | null): boolean => role === "owner" || role === "admin",
  credentialIssuing: (role: Role | null): boolean =>
    role === "owner" || role === "admin" || role === "member",
  ownerActions: (role: Role | null): boolean => role === "owner",
  auditHistory: (role: Role | null): boolean => role === "owner" || role === "admin",
};
