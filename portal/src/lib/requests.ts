/**
 * The lifecycle of a page's requests: which completions are still allowed to do anything.
 *
 * A page starts reads when it mounts and when the customer acts, and every one of them
 * completes later, into whatever the page has become. Three things can have changed by
 * then, and each one makes the completion a stranger: the page may have been left (the
 * component unmounted), the session may have been replaced or ended (the
 * {@link SessionLease} the request began under is no longer current), and -- for a page
 * inside a workspace -- the workspace may have been switched (the binding the request
 * began under is no longer the one selected). A completion that is a stranger must be
 * **inert**: it publishes no data, changes no loading flag, replaces no message, clears no
 * form, reconciles nothing and navigates nowhere.
 *
 * On top of that, loads are ordered. A page may start a second load before the first has
 * answered -- a reload after an action, a StrictMode replay of the mount effect -- and
 * only the **newest** load may publish, or finish the loading state, because an older
 * load's answer describes an older moment and its `finally` would otherwise end a newer
 * load's spinner while that load is still in flight.
 *
 * So every request takes a **ticket** when it starts. A *load* ticket carries a sequence
 * number and is `latest` only while no newer load has started; an *action* ticket carries
 * the current sequence and is `live` while the page, the session and the workspace are the
 * ones it began under. The page consults the ticket after every `await`, and the hook
 * answers from refs, not from render-time closures, because the answer has to be about now.
 */

import { useCallback, useEffect, useRef } from "react";
import type { SessionLease } from "../auth/session.tsx";

export interface PageTicket {
  /** The load sequence this request belongs to. */
  readonly sequence: number;
  /** The session the request began under. */
  readonly lease: SessionLease;
  /** The workspace the request began under; `null` for a page outside any workspace. */
  readonly workspaceId: string | null;
}

export interface PageRequests {
  /** Start a load: a new sequence, so every earlier load's completion becomes inert. */
  beginLoad: () => PageTicket;
  /** Start an action: the current sequence, so a load it triggers afterwards is newer. */
  beginAction: () => PageTicket;
  /** The page is still mounted, under the same session, in the same workspace. */
  live: (ticket: PageTicket) => boolean;
  /** {@link live}, and no newer load has started since. */
  latest: (ticket: PageTicket) => boolean;
  /**
   * The page is still mounted, whatever else changed. The one thing a stranger completion
   * may still do: put back the control it disabled when it started, so a page that stayed
   * open across a session replacement is not left with a button stuck at "Working…".
   */
  mounted: () => boolean;
}

interface Session {
  lease: () => SessionLease;
  holds: (lease: SessionLease) => boolean;
  workspaceId: string | null;
}

/**
 * The tickets for one page.
 *
 * `scoped` says whether the page belongs to a workspace: a scoped page's tickets are tied
 * to the workspace they began under and a switch makes them strangers; an account page's
 * are not, because switching workspaces changes nothing an account page shows.
 */
export function usePageRequests(session: Session, { scoped }: { scoped: boolean }): PageRequests {
  const mounted = useRef(true);
  const sequence = useRef(0);
  // Read at the moment a ticket is taken or checked, not at the render that took it.
  const workspace = useRef<string | null>(session.workspaceId);
  workspace.current = session.workspaceId;
  const { lease, holds } = session;

  useEffect(() => {
    // StrictMode runs this cleanup and then the effect again on mount; the flag follows.
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const ticket = useCallback(
    (next: number): PageTicket => ({
      sequence: next,
      lease: lease(),
      workspaceId: scoped ? workspace.current : null,
    }),
    [lease, scoped],
  );

  const beginLoad = useCallback(() => {
    sequence.current += 1;
    return ticket(sequence.current);
  }, [ticket]);

  const beginAction = useCallback(() => ticket(sequence.current), [ticket]);

  const live = useCallback(
    (candidate: PageTicket): boolean =>
      mounted.current &&
      holds(candidate.lease) &&
      (!scoped || candidate.workspaceId === workspace.current),
    [holds, scoped],
  );

  const latest = useCallback(
    (candidate: PageTicket): boolean => live(candidate) && candidate.sequence === sequence.current,
    [live],
  );

  const isMounted = useCallback((): boolean => mounted.current, []);

  return { beginLoad, beginAction, live, latest, mounted: isMounted };
}

/**
 * One in-flight promise per key, shared by everyone who asks while it is pending.
 *
 * Two instances exist. Every page read goes through {@link reads}, below, so that a
 * StrictMode replay of a mount effect, or two controls asking the same question in one tick,
 * produce one request rather than two; and the session provider keeps its own for the
 * bounded validity read, so concurrent askers share one. The provider's account loads are
 * not here: they are sequenced, and a second ask joins the latest load through the
 * provider's own in-flight record. The entry is released the moment the promise settles,
 * so a later ask -- a customer coming back to a route -- is a fresh request, as it should
 * be.
 */
export class SingleFlight {
  private readonly pending = new Map<string, Promise<unknown>>();

  /**
   * The in-flight promise for `key`, or a new one. `fresh` starts a new request even while
   * one is in flight and makes it the one later askers join: what a reload after an action
   * must do, because the request already in flight may have been answered before the action.
   */
  run<T>(
    key: string,
    start: () => Promise<T>,
    { fresh = false }: { fresh?: boolean } = {},
  ): Promise<T> {
    const inFlight = this.pending.get(key);
    if (inFlight !== undefined && !fresh) return inFlight as Promise<T>;
    const promise: Promise<T> = start().finally(() => {
      if (this.pending.get(key) === promise) this.pending.delete(key);
    });
    this.pending.set(key, promise);
    return promise;
  }

  /** Whether a request for `key` is in flight. */
  has(key: string): boolean {
    return this.pending.has(key);
  }

  /**
   * Forget every in-flight entry. A real page holds nothing between one document and the
   * next; the test setup calls this between tests for the same reason it forgets held
   * one-time tokens, so a request one test left pending is not joined by the next.
   */
  clear(): void {
    this.pending.clear();
  }
}

/**
 * The keyed single flight every page read goes through. A StrictMode replay of a mount
 * effect, or two components asking for the same list in one tick, produce one request; the
 * entry is released when it settles, so a customer coming back to a route reads afresh.
 */
export const reads = new SingleFlight();
