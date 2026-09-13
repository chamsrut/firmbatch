/**
 * The authenticated layout: skip link, workspace switcher, navigation, main region.
 *
 * **What is not in this navigation, and never will be.** There is no supplier, capacity,
 * pool, window-offer, bridge-budget, settlement, routing, certification or provider-
 * reconciliation entry, and no operator entry of any kind. The operator capacity agent is
 * separate operator-side software that runs in an operator's own cluster; it is not a
 * customer feature, it has no customer route, and the API this portal talks to exposes no
 * scope that would reach one. Roadmap "Internal and supplier surfaces"; target §17 invariant
 * 11.
 *
 * The four product sections the roadmap names -- Evaluation, Jobs, Results, Billing -- are
 * here, and are honestly marked as unavailable. Showing the shape of the product without
 * fabricating its contents is the M3.2 gate: "honest empty states for later features".
 *
 * Focus after navigation is not handled here. The shells mount and unmount as the route
 * changes, so the one place that can see every transition is the top of the tree: `App.tsx`.
 */

import type { ReactNode } from "react";
import { useState } from "react";
import { ApiError } from "../api/errors.ts";
import type { Role, WorkspaceMembershipSummary } from "../api/types.ts";
import { afterRefusal, SignOutIncomplete, useSession } from "../auth/session.tsx";
import { type PageTicket, usePageRequests } from "../lib/requests.ts";
import { Link, useRouter } from "../lib/router.tsx";
import { Button } from "./components.tsx";

interface NavItem {
  to: string;
  label: string;
  /** Marked in the navigation itself, so the customer is not led to a dead end. */
  unavailable?: boolean;
  /** Rendered only when the customer's role would let them use the page at all. */
  visible?: (role: Role | null) => boolean;
}

const PRODUCT_NAV: readonly NavItem[] = [
  { to: "/", label: "Overview" },
  { to: "/evaluation", label: "Evaluation", unavailable: true },
  { to: "/jobs", label: "Jobs", unavailable: true },
  { to: "/results", label: "Results", unavailable: true },
  { to: "/billing", label: "Billing", unavailable: true },
];

const WORKSPACE_NAV: readonly NavItem[] = [
  { to: "/settings/workspace", label: "Workspace" },
  { to: "/settings/team", label: "Team" },
  { to: "/settings/preferences", label: "Policy and preferences" },
  { to: "/settings/credentials", label: "API credentials" },
];

const ACCOUNT_NAV: readonly NavItem[] = [
  { to: "/account", label: "Your account" },
  { to: "/account/security", label: "Security" },
];

function NavList({
  heading,
  items,
  pathname,
  role,
}: {
  heading: string;
  items: readonly NavItem[];
  pathname: string;
  role: Role | null;
}) {
  const visible = items.filter((item) => (item.visible ? item.visible(role) : true));
  if (visible.length === 0) return null;
  return (
    <div className="nav-group">
      <h2 className="nav-heading">{heading}</h2>
      <ul>
        {visible.map((item) => {
          const active = pathname === item.to;
          return (
            <li key={item.to}>
              <Link to={item.to} className={active ? "nav-link nav-link-active" : "nav-link"}>
                <span>{item.label}</span>
                {item.unavailable ? (
                  // A plain <span> has no role, so an aria-label on it is ignored. The full
                  // phrase is in the markup for assistive technology and the short form is
                  // the visual one, which is the only arrangement that works for both.
                  <span className="nav-badge">
                    <span aria-hidden="true">soon</span>
                    <span className="visually-hidden">not available yet</span>
                  </span>
                ) : null}
              </Link>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/**
 * The workspace switcher.
 *
 * Selecting is a server operation, not a local one: the API re-derives the membership and
 * refuses a workspace this account is no longer in. When it accepts, the session provider
 * publishes the binding the mutation returned -- the switch has happened -- and this control
 * leaves for the new workspace's overview at once. The provider then re-reads the account
 * separately; if that read fails, the provider says so (`loadProblem`, shown by the shell
 * with a retry) and the binding stands. Nothing here ever reports a workspace as unavailable
 * after the server has selected it.
 */
function WorkspaceSwitcher({
  workspaces,
  workspaceId,
}: {
  workspaces: WorkspaceMembershipSummary[];
  workspaceId: string | null;
}) {
  const session = useSession();
  const router = useRouter();
  const { beginAction, live, mounted } = usePageRequests(session, { scoped: false });
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);

  /** A refused switch, reconciled with the session it was asked under; nothing if obsolete. */
  const refused = async (ticket: PageTicket, error: unknown) => {
    if (!live(ticket)) return;
    const outcome = await session.reconcile(ticket.lease, error, "mutation");
    setProblem(afterRefusal(outcome, "That workspace is no longer available to you."));
    if (outcome === "unchanged") await session.refresh(ticket.lease);
  };

  const change = async (next: string) => {
    if (next === workspaceId) return;
    setBusy(true);
    setProblem(null);
    const ticket = beginAction();
    try {
      // The list this control renders may be a moment out of date, and the server is what
      // settles it. A success is published by the provider before this line resumes.
      await session.selectWorkspace(next);
      if (!live(ticket)) return;
      router.navigate("/");
    } catch (error) {
      await refused(ticket, error);
    } finally {
      if (mounted()) setBusy(false);
    }
  };

  return (
    <div className="workspace-switcher">
      <label htmlFor="workspace-switcher">Workspace</label>
      <select
        id="workspace-switcher"
        value={workspaceId ?? ""}
        disabled={busy}
        onChange={(event) => void change(event.target.value)}
      >
        {workspaceId === null ? <option value="">Choose a workspace…</option> : null}
        {workspaces.map((workspace) => (
          <option key={workspace.workspace_id} value={workspace.workspace_id}>
            {workspace.name}
          </option>
        ))}
      </select>
      <p aria-live="polite" className="switcher-status">
        {problem}
      </p>
    </div>
  );
}

/**
 * The provider's own report that the account behind a live session could not be re-read --
 * after a workspace switch, a password change or a retry -- with the retry. The session and
 * the binding stand; only the supplementary reads are missing, and this says exactly that.
 */
function AccountLoadProblem() {
  const session = useSession();
  if (session.loadProblem === null) return null;
  return (
    <div className="load-problem" role="alert">
      <span>{session.loadProblem}</span>
      <Button variant="quiet" busy={session.loading} onClick={() => void session.retryLoad()}>
        Retry
      </Button>
    </div>
  );
}

/**
 * Why a sign-out did not end in a signed-out state, in a sentence that starts with the fact
 * that matters.
 *
 * When the validity read found the session **live**, the customer is still signed in, and
 * the sentence says so and why the request failed -- a refused request (the neutral `401`
 * the API gives a wrong CSRF secret, among other things) is reported as a refusal, never as
 * a sign-out. When the read could not settle it, the sentence says that too, and tells the
 * customer to treat themselves as signed in. The one thing it must never do is imply that a
 * session which may still be open has ended.
 */
function signOutFailure(error: unknown): string {
  if (error instanceof SignOutIncomplete && error.validity === "unknown") {
    return "The sign-out did not complete, and whether this session is still open could not be checked. Treat yourself as signed in, check your connection, and try again.";
  }
  const reason = error instanceof SignOutIncomplete ? error.reason : error;
  if (reason instanceof ApiError && reason.status === 401) {
    return "You are still signed in: the sign-out request was refused. Reload the page and try again.";
  }
  const detail = reason instanceof ApiError ? reason.message : "The sign-out did not complete.";
  return `You are still signed in. ${detail}`;
}

/**
 * The one sign-out control, used by the masthead and by the security page.
 *
 * It holds no state of its own. The session provider owns the one sign-out operation, and
 * every instance of this control renders the provider's shared pending and failure state:
 * two of them on the same page say "Working…" together, are restored together, and show the
 * same sentence. Clicking either while an operation is pending joins that operation rather
 * than sending another logout.
 *
 * The provider ends the session on the server first and only then forgets it, and this
 * leaves for the sign-in page only when the provider says the outcome was a sign-out. When
 * the logout did not succeed, the provider makes one safe read to learn whether the session
 * is gone anyway; if it is, this leaves too. Otherwise the customer is told, in an alert
 * next to the button, that they are still signed in -- or that it could not be checked --
 * and the button is there to try again; nothing retries on its own, and the authenticated
 * page stays exactly as it was, because that is the truth. A signed-out screen over a live
 * session would be a lie a customer at a shared machine would pay for. An operation the
 * provider superseded -- the session was replaced while it was pending -- navigates nowhere.
 */
export function SignOutButton({ variant = "quiet" }: { variant?: "quiet" | "default" }) {
  const session = useSession();
  const router = useRouter();
  const { pending, failure } = session.signOutStatus;

  const signOut = async () => {
    const outcome = await session.signOut();
    // Two controls that joined one operation both learn of its outcome; one navigation is
    // enough, and the location is read live because this closure's router is a render old.
    if (outcome === "signed-out" && window.location.pathname !== "/login") {
      router.navigate("/login");
    }
  };

  return (
    <span className="sign-out">
      <Button variant={variant} busy={pending} onClick={() => void signOut()}>
        Sign out
      </Button>
      {failure ? (
        <span role="alert" className="sign-out-problem">
          {signOutFailure(failure)}
        </span>
      ) : null}
    </span>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const session = useSession();
  const router = useRouter();

  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <header className="masthead">
        <Link to="/" className="wordmark">
          Firmbatch
        </Link>
        <div className="masthead-right">
          {session.workspaces.length > 0 ? (
            <WorkspaceSwitcher workspaces={session.workspaces} workspaceId={session.workspaceId} />
          ) : null}
          <span className="signed-in-as">{session.profile?.email}</span>
          <SignOutButton />
        </div>
      </header>
      <AccountLoadProblem />
      <div className="body">
        <nav className="sidebar" aria-label="Portal sections">
          <NavList
            heading="Product"
            items={PRODUCT_NAV}
            pathname={router.pathname}
            role={session.role}
          />
          <NavList
            heading="Workspace"
            items={WORKSPACE_NAV}
            pathname={router.pathname}
            role={session.role}
          />
          <NavList
            heading="Account"
            items={ACCOUNT_NAV}
            pathname={router.pathname}
            role={session.role}
          />
        </nav>
        <main id="main" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
}

/**
 * The layout for the pages a signed-out visitor sees. Same skip link, no navigation.
 *
 * The wordmark is a paragraph, not a heading: the page's own title is its `h1`, which is
 * what a screen reader announces and what focus lands on after a navigation. A brand mark
 * as the document's first heading would put every public page's real title one level
 * down and hand focus to the word "Firmbatch" instead of "Sign in".
 */
export function PublicShell({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="public-shell">
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <main id="main" className="public-main" tabIndex={-1}>
        <p className="wordmark-large">Firmbatch</p>
        <section className="card" aria-label={title}>
          {children}
        </section>
      </main>
    </div>
  );
}
