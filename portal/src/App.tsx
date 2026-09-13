/**
 * The route table, the two guards, and focus after navigation.
 *
 * A guard here decides **what to render**, never what is permitted. Every route below still
 * calls an API that re-derives the account, the membership and the role on every request, so
 * a customer who reaches a page they should not see gets an empty page and a refusal rather
 * than data. The guards exist so the common case is not a wall of errors.
 *
 * Three states a signed-in customer can be in, and the portal distinguishes all three,
 * because collapsing them is how a first-time customer ends up staring at "not found":
 *
 *   - **no session** -> the public pages, with the page they wanted remembered in `next`;
 *   - **a session, no workspace** -> the picker, or the create-your-first-workspace page.
 *     This is `AUTH-MEMBERSHIP-BOUND-IDENTITY` case 1: the account-level session is real and
 *     usable, and it simply is not bound to anything yet;
 *   - **a session bound to a workspace** -> the portal proper.
 *
 * The invitation landing page is **public**: an emailed invitation link is opened signed out
 * as often as not, and a guard that redirected it to the sign-in page would drop the token
 * with the URL. The router has already moved the token into memory by the time this renders
 * (`lib/one-time-token.ts`); the page then offers sign-in or sign-up with `/accept-invitation`
 * as the checked continuation route, and accepts once the customer is back.
 */

import { useEffect, useRef } from "react";
import { useSession } from "./auth/session.tsx";
import { destinationFromSearch, destinationQuery } from "./lib/redirect.ts";
import { useRouter } from "./lib/router.tsx";
import { AccountPage, SecurityPage } from "./routes/account.tsx";
import {
  AcceptInvitationPage,
  LoginPage,
  RecoverPage,
  ResetPasswordPage,
  SignupPage,
  VerifyEmailPage,
} from "./routes/auth.tsx";
import { CredentialsPage } from "./routes/credentials.tsx";
import { PreferencesPage } from "./routes/preferences.tsx";
import {
  BillingPage,
  EvaluationPage,
  JobsPage,
  NotFoundPage,
  OverviewPage,
  ResultsPage,
} from "./routes/product.tsx";
import { TeamPage, WorkspaceSettingsPage } from "./routes/team.tsx";
import { ChooseWorkspacePage, CreateWorkspacePage } from "./routes/workspaces.tsx";
import { Button, Notice, Spinner } from "./ui/components.tsx";
import { PublicShell, Shell } from "./ui/Shell.tsx";

/** Pages a signed-out visitor may open. Everything else needs a session. */
const PUBLIC_ROUTES: Record<string, () => React.JSX.Element> = {
  "/login": LoginPage,
  "/signup": SignupPage,
  "/verify-email": VerifyEmailPage,
  "/recover": RecoverPage,
  "/reset-password": ResetPasswordPage,
  // Reachable signed out on purpose: the page itself decides what to show, and the token
  // it needs was captured before this table was consulted.
  "/accept-invitation": AcceptInvitationPage,
};

/** Pages that need a session but **not** a workspace. The first-workspace journey. */
const ACCOUNT_ROUTES: Record<string, () => React.JSX.Element> = {
  "/workspaces": ChooseWorkspacePage,
  "/workspaces/new": CreateWorkspacePage,
};

/** Pages inside a workspace. Every one of them needs a bound session. */
const WORKSPACE_ROUTES: Record<string, () => React.JSX.Element> = {
  "/": OverviewPage,
  "/evaluation": EvaluationPage,
  "/jobs": JobsPage,
  "/results": ResultsPage,
  "/billing": BillingPage,
  "/settings/workspace": WorkspaceSettingsPage,
  "/settings/team": TeamPage,
  "/settings/preferences": PreferencesPage,
  "/settings/credentials": CredentialsPage,
};

/** Pages that need a session but sit outside any workspace, and use the full shell. */
const ACCOUNT_SHELL_ROUTES: Record<string, () => React.JSX.Element> = {
  "/account": AccountPage,
  "/account/security": SecurityPage,
};

/**
 * A live session whose account has not been read yet, or could not be: a replacement a login
 * or a password change just adopted, with its read still in flight or failed. Still signed
 * in -- never the old session put back, never a sign-in page -- with the problem and a retry
 * when the read failed. No route is chosen until the account is known, so nothing here
 * oscillates between a page and a redirect.
 */
function AccountLoading() {
  const session = useSession();
  return (
    <PublicShell title="Loading your account">
      {session.loadProblem === null ? (
        <Spinner label="Loading your account…" />
      ) : (
        <>
          <Notice kind="error">{session.loadProblem}</Notice>
          <Button variant="primary" busy={session.loading} onClick={() => void session.retryLoad()}>
            Retry
          </Button>
        </>
      )}
    </PublicShell>
  );
}

function Redirect({ to }: { to: string }) {
  const router = useRouter();
  useEffect(() => {
    router.navigate(to, { replace: true });
  }, [router, to]);
  return <Spinner label="Taking you there…" />;
}

/** The page heading a route transition should hand focus to, inside the main region. */
function pageHeading(main: HTMLElement): HTMLElement | null {
  return main.querySelector<HTMLElement>("h1");
}

function focusElement(element: HTMLElement): void {
  // A heading is not focusable by itself; `tabindex="-1"` makes it a programmatic focus
  // target without adding it to the Tab order.
  if (!element.hasAttribute("tabindex")) element.setAttribute("tabindex", "-1");
  element.focus();
}

/**
 * Move focus to the new page's heading after every **actual** route transition.
 *
 * A single-page application replaces the page without a page load, so nothing tells a
 * keyboard or screen-reader user that anything happened: focus stays on the link they
 * pressed, in a navigation that has not changed, and the new content is never announced.
 * Handing focus to the page heading is what a page load would have done.
 *
 * Two things this deliberately does not do. It does not move focus on the first render --
 * the browser's own restoration wins there -- and it does not move focus when the route has
 * not changed, so a re-render, a StrictMode replay or a state change inside a page leaves
 * focus where the customer put it. When the page is still loading and has no heading yet,
 * focus goes to the main region, and moves on to the heading when it appears **only if**
 * the customer has not moved focus elsewhere in the meantime.
 *
 * This lives at the top of the tree rather than in a shell, because the shells mount and
 * unmount as the route changes and a ref inside one cannot see across that boundary.
 */
function useHeadingFocusOnNavigation(pathname: string): void {
  const previous = useRef<string | null>(null);
  useEffect(() => {
    if (previous.current === null) {
      previous.current = pathname;
      return;
    }
    if (previous.current === pathname) return;
    previous.current = pathname;

    const main = document.getElementById("main");
    if (main === null) return;
    const heading = pageHeading(main);
    if (heading !== null) {
      focusElement(heading);
      return;
    }
    focusElement(main);
    const observer = new MutationObserver(() => {
      const arrived = pageHeading(main);
      if (arrived === null) return;
      observer.disconnect();
      if (document.activeElement === main) focusElement(arrived);
    });
    observer.observe(main, { childList: true, subtree: true });
    return () => observer.disconnect();
  }, [pathname]);
}

export function App() {
  const session = useSession();
  const { pathname, search } = useRouter();
  useHeadingFocusOnNavigation(pathname);

  if (!session.ready) {
    return (
      <PublicShell title="Loading">
        <Spinner label="Loading…" />
      </PublicShell>
    );
  }

  const Public = PUBLIC_ROUTES[pathname];
  if (Public) {
    // A signed-in customer who lands on the sign-in page belongs inside the portal, not
    // looking at a form they do not need -- at the page they were on their way to, when the
    // URL names a safe one, and at the overview otherwise.
    if (session.status === "authenticated" && (pathname === "/login" || pathname === "/signup")) {
      return <Redirect to={destinationFromSearch(search)} />;
    }
    return <Public />;
  }

  if (session.status !== "authenticated") {
    // Remember where they were going, checked on the way in and again on the way out.
    return <Redirect to={`/login${destinationQuery(pathname)}`} />;
  }

  if (session.profile === null) return <AccountLoading />;

  return <SignedInRoutes pathname={pathname} />;
}

/** The pages a signed-in customer with a loaded account can be on. */
function SignedInRoutes({ pathname }: { pathname: string }) {
  const session = useSession();

  const AccountOnly = ACCOUNT_ROUTES[pathname];
  if (AccountOnly) return <AccountOnly />;

  const AccountInShell = ACCOUNT_SHELL_ROUTES[pathname];
  if (AccountInShell) {
    return (
      <Shell>
        <AccountInShell />
      </Shell>
    );
  }

  const InWorkspace = WORKSPACE_ROUTES[pathname];
  if (InWorkspace) {
    if (session.workspaceId === null) {
      // A real session with no workspace behind it. Not an error: either this account has
      // never made one, or the membership it was using has just been revoked. Both lead to
      // the same place, and the picker tells them which.
      return <Redirect to={session.workspaces.length === 0 ? "/workspaces/new" : "/workspaces"} />;
    }
    return (
      <Shell>
        <InWorkspace />
      </Shell>
    );
  }

  return (
    <Shell>
      <NotFoundPage />
    </Shell>
  );
}
