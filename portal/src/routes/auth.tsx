/**
 * Signing up, confirming an address, signing in, recovering an account, and accepting an
 * invitation.
 *
 * Three rules run through all of them.
 *
 * **The API's neutrality is preserved, not undone.** Signup, verification-resend and
 * recovery-request all answer `202` whether or not the address has an account, so that the
 * boundary is not an oracle for who has one. A portal that said "check your inbox" for a
 * known address and "no such account" for an unknown one would hand that oracle straight
 * back. Every one of these pages therefore shows the *same* confirmation in both cases.
 *
 * **A token in a URL is captured once, taken out of the URL, and submitted at most once at
 * a time.** Verification, recovery and invitation links carry a secret in the query string,
 * which is the one place this design cannot avoid putting one. The router moves it into
 * memory and scrubs the address bar before any page renders (`lib/one-time-token.ts`); these
 * pages read it from there, submit it through {@link submitOnce} so a replayed effect joins
 * the submission in flight rather than spending the token twice, keep it for an explicit
 * retry after a transport failure, and release it once it has been used. A reload loses it,
 * by design, and the page then says so.
 *
 * **A continuation is a route, never a token.** A signed-out visitor who lands on an
 * invitation is sent to sign in or sign up with `/accept-invitation` as the checked `next`
 * destination; the token stays in memory for that same mounted application and is never put
 * in `next`, in storage, or in any request but the acceptance itself.
 */

import { useCallback, useEffect, useState } from "react";
import { account, auth } from "../api/endpoints.ts";
import { ApiError } from "../api/errors.ts";
import { afterRefusal, useSession } from "../auth/session.tsx";
import { heldToken, releaseToken, submitOnce } from "../lib/one-time-token.ts";
import { destinationFromSearch, destinationQuery } from "../lib/redirect.ts";
import { usePageRequests } from "../lib/requests.ts";
import { Link, useRouter } from "../lib/router.tsx";
import { Button, Field, Form, Notice, Spinner } from "../ui/components.tsx";
import { PublicShell } from "../ui/Shell.tsx";

function messageOf(error: unknown): string {
  return error instanceof ApiError ? error.message : "That did not work. Nothing was changed.";
}

/** The checked continuation carried by this page's URL, as a `?next=` suffix or nothing. */
function continuationQuery(): string {
  return destinationQuery(destinationFromSearch(window.location.search));
}

// ------------------------------------------------------------------------------- signup

export function SignupPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [fieldProblem, setFieldProblem] = useState<string | null>(null);
  const [sent, setSent] = useState(false);
  // Preserved through to sign-in, so an invitation accepted after signing up comes back to
  // the page that holds it. A route, checked; never a token.
  const next = continuationQuery();

  const submit = async () => {
    setProblem(null);
    setFieldProblem(null);
    if (password !== confirmation) {
      setFieldProblem("The two passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      await auth.signup(email, password);
      setSent(true);
    } catch (error) {
      setProblem(messageOf(error));
    } finally {
      setBusy(false);
    }
  };

  if (sent) {
    return (
      <PublicShell title="Check your email">
        <h1>Check your email</h1>
        {/* The same sentence whether or not the address already had an account: the API
            answers identically, and saying otherwise here would leak what it withholds. */}
        <p>
          If <strong>{email}</strong> can receive mail, a confirmation link is on its way. The link
          works once and expires.
        </p>
        <p>
          <Link to={`/login${next}`}>Back to sign in</Link>
        </p>
      </PublicShell>
    );
  }

  return (
    <PublicShell title="Create an account">
      <h1>Create an account</h1>
      {problem ? <Notice kind="error">{problem}</Notice> : null}
      <Form onSubmit={() => void submit()} label="Create an account">
        <Field
          label="Email address"
          name="email"
          type="email"
          inputMode="email"
          autoComplete="email"
          value={email}
          onChange={setEmail}
          required
          maxLength={254}
        />
        <Field
          label="Password"
          name="password"
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={setPassword}
          required
          hint="At least 12 characters. Longer is better than more complicated."
        />
        <Field
          label="Confirm password"
          name="password_confirmation"
          type="password"
          autoComplete="new-password"
          value={confirmation}
          onChange={setConfirmation}
          required
          error={fieldProblem}
        />
        <Button type="submit" variant="primary" busy={busy}>
          Create account
        </Button>
      </Form>
      <p className="muted">
        Already have an account? <Link to={`/login${next}`}>Sign in</Link>
      </p>
    </PublicShell>
  );
}

// ------------------------------------------------------------------- email verification

type VerificationState = "idle" | "working" | "done" | "spent" | "unreachable";

export function VerifyEmailPage() {
  const router = useRouter();
  const [state, setState] = useState<VerificationState>(() =>
    heldToken("verification") === null ? "idle" : "working",
  );
  const [resendTo, setResendTo] = useState("");
  const [resent, setResent] = useState(false);

  const submit = useCallback(() => {
    // At most one submission in flight: a StrictMode replay of the effect below joins the
    // request already running instead of presenting the token a second time.
    const pending = submitOnce("verification", (token) => auth.completeVerification(token));
    if (pending === null) return;
    setState("working");
    pending
      .then(() => {
        releaseToken("verification");
        setState("done");
      })
      .catch((error: unknown) => {
        // A 400 is the server saying the token is spent, expired or unknown: it is gone.
        // Anything else -- a dropped connection, a 5xx -- says nothing about the token, so
        // it is kept and the customer is offered a retry rather than a new link.
        setState(error instanceof ApiError && error.status === 400 ? "spent" : "unreachable");
      });
  }, []);

  useEffect(() => {
    submit();
  }, [submit]);

  if (state === "working") {
    return (
      <PublicShell title="Confirming your address">
        <Spinner label="Confirming your address…" />
      </PublicShell>
    );
  }

  if (state === "done") {
    return (
      <PublicShell title="Address confirmed">
        <h1>Address confirmed</h1>
        <p>Your email address is confirmed. You can sign in now.</p>
        <Button variant="primary" onClick={() => router.navigate("/login")}>
          Go to sign in
        </Button>
      </PublicShell>
    );
  }

  if (state === "unreachable") {
    return (
      <PublicShell title="Confirm your email address">
        <h1>Confirm your email address</h1>
        <Notice kind="error">
          Your address could not be confirmed just now: the service could not be reached. The link
          is still valid. Try again.
        </Notice>
        <Button variant="primary" onClick={() => submit()}>
          Try again
        </Button>
        <p className="muted">
          <Link to="/login">Back to sign in</Link>
        </p>
      </PublicShell>
    );
  }

  return (
    <PublicShell title="Confirm your email address">
      <h1>Confirm your email address</h1>
      {state === "spent" ? (
        <Notice kind="error">
          That link is no longer valid. Links expire, and each one works once. Ask for a new one
          below.
        </Notice>
      ) : (
        <p>Enter your address and we will send a new confirmation link.</p>
      )}
      {resent ? (
        <Notice kind="success">If that address can receive mail, a new link is on its way.</Notice>
      ) : (
        <Form
          onSubmit={() => {
            void auth
              .requestVerification(resendTo)
              .catch(() => undefined)
              .finally(() => setResent(true));
          }}
          label="Send a new confirmation link"
        >
          <Field
            label="Email address"
            name="email"
            type="email"
            inputMode="email"
            autoComplete="email"
            value={resendTo}
            onChange={setResendTo}
            required
            maxLength={254}
          />
          <Button type="submit" variant="primary">
            Send a new link
          </Button>
        </Form>
      )}
      <p className="muted">
        <Link to="/login">Back to sign in</Link>
      </p>
    </PublicShell>
  );
}

// -------------------------------------------------------------------------------- login

export function LoginPage() {
  const session = useSession();
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [needsVerification, setNeedsVerification] = useState(false);
  const next = continuationQuery();

  const submit = async () => {
    setProblem(null);
    setNeedsVerification(false);
    setBusy(true);
    try {
      await session.signIn(email, password);
      // Only ever an in-application path. `destinationFromSearch` refuses anything else, so
      // ?next=https://evil.example on this page sends the customer to the overview.
      router.navigate(destinationFromSearch(window.location.search), { replace: true });
    } catch (error) {
      if (error instanceof ApiError && error.code === "email_verification_required") {
        setNeedsVerification(true);
      }
      setProblem(messageOf(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <PublicShell title="Sign in">
      <h1>Sign in</h1>
      {problem ? <Notice kind="error">{problem}</Notice> : null}
      {needsVerification ? (
        <p>
          <Link to="/verify-email">Send a new confirmation link</Link>
        </p>
      ) : null}
      <Form onSubmit={() => void submit()} label="Sign in">
        <Field
          label="Email address"
          name="email"
          type="email"
          inputMode="email"
          autoComplete="username"
          value={email}
          onChange={setEmail}
          required
          maxLength={254}
        />
        <Field
          label="Password"
          name="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={setPassword}
          required
        />
        <Button type="submit" variant="primary" busy={busy}>
          Sign in
        </Button>
      </Form>
      <p className="muted">
        <Link to="/recover">Forgotten your password?</Link>
      </p>
      <p className="muted">
        No account yet? <Link to={`/signup${next}`}>Create one</Link>
      </p>
    </PublicShell>
  );
}

// ----------------------------------------------------------------------------- recovery

export function RecoverPage() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);

  const submit = async () => {
    setBusy(true);
    try {
      await auth.requestRecovery(email);
    } catch {
      // The API answers 202 for a known and an unknown address alike. A failure here is a
      // transport problem, and showing it differently for one address than another would be
      // the oracle the neutral response exists to prevent.
    } finally {
      setBusy(false);
      setSent(true);
    }
  };

  if (sent) {
    return (
      <PublicShell title="Check your email">
        <h1>Check your email</h1>
        <p>
          If <strong>{email}</strong> has an account, a reset link is on its way. The link works
          once and expires.
        </p>
        <p className="muted">
          <Link to="/login">Back to sign in</Link>
        </p>
      </PublicShell>
    );
  }

  return (
    <PublicShell title="Reset your password">
      <h1>Reset your password</h1>
      <p>Enter your address and we will send a link to set a new password.</p>
      <Form onSubmit={() => void submit()} label="Reset your password">
        <Field
          label="Email address"
          name="email"
          type="email"
          inputMode="email"
          autoComplete="username"
          value={email}
          onChange={setEmail}
          required
          maxLength={254}
        />
        <Button type="submit" variant="primary" busy={busy}>
          Send a reset link
        </Button>
      </Form>
      <p className="muted">
        <Link to="/login">Back to sign in</Link>
      </p>
    </PublicShell>
  );
}

export function ResetPasswordPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [fieldProblem, setFieldProblem] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  // Read from memory on every render, never from the URL: the router took it out of the URL
  // before this page existed, and it is released the moment it has been used.
  const token = heldToken("recovery");

  const submit = async () => {
    setProblem(null);
    setFieldProblem(null);
    if (password !== confirmation) {
      setFieldProblem("The two passwords do not match.");
      return;
    }
    const pending = submitOnce("recovery", (held) => auth.completeRecovery(held, password));
    if (pending === null) {
      setProblem("That link is no longer valid. Ask for a new one.");
      return;
    }
    setBusy(true);
    try {
      await pending;
      releaseToken("recovery");
      setDone(true);
    } catch (error) {
      // The token stays held: a transport failure is not a spent link, and the next press
      // of the button submits it again. A 400 says it is spent, and the sentence says so.
      setProblem(messageOf(error));
    } finally {
      setBusy(false);
    }
  };

  if (done) {
    return (
      <PublicShell title="Password set">
        <h1>Password set</h1>
        <p>
          Your password is set, and every session that was open under the old one has been ended.
          Sign in again to continue.
        </p>
        <Button variant="primary" onClick={() => router.navigate("/login")}>
          Go to sign in
        </Button>
      </PublicShell>
    );
  }

  return (
    <PublicShell title="Set a new password">
      <h1>Set a new password</h1>
      {problem ? <Notice kind="error">{problem}</Notice> : null}
      {token === null ? (
        <p>
          This page needs the link from your email. If you reloaded the page, open the link from the
          email again; otherwise <Link to="/recover">ask for a new one</Link>.
        </p>
      ) : (
        <Form onSubmit={() => void submit()} label="Set a new password">
          <Field
            label="New password"
            name="password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={setPassword}
            required
            hint="At least 12 characters."
          />
          <Field
            label="Confirm new password"
            name="password_confirmation"
            type="password"
            autoComplete="new-password"
            value={confirmation}
            onChange={setConfirmation}
            required
            error={fieldProblem}
          />
          <Button type="submit" variant="primary" busy={busy}>
            Set password
          </Button>
        </Form>
      )}
    </PublicShell>
  );
}

// --------------------------------------------------------------------------- invitation

/** The route a signed-out visitor comes back to after signing in or up. A route, not a token. */
const INVITATION_CONTINUATION = "/accept-invitation";

/**
 * Why an invitation was not accepted, in a sentence that names no identifier.
 *
 * The API answers a spent, revoked, expired, malformed or mis-addressed invitation with one
 * neutral `404`, so that the portal cannot be used to ask whether an invitation exists; the
 * sentence lists the possibilities rather than pretending to know which one applies.
 */
function invitationFailure(error: unknown): string {
  if (error instanceof ApiError && error.status === 404) {
    return "This invitation cannot be accepted by the account you are signed in as. It may have been used already, revoked or expired, or it may name a different email address.";
  }
  if (error instanceof ApiError && error.status === 409) {
    return "You are already a member of that workspace.";
  }
  return messageOf(error);
}

export function AcceptInvitationPage() {
  const session = useSession();
  const router = useRouter();
  const { beginAction, live } = usePageRequests(session, { scoped: false });
  const token = heldToken("invitation");
  const [state, setState] = useState<"idle" | "working" | "failed">("idle");
  const [problem, setProblem] = useState<string | null>(null);
  const continuation = destinationQuery(INVITATION_CONTINUATION);

  const accept = async () => {
    // The ticket -- the page, the session and the lease -- is taken before the request is
    // started, so that nothing the request answers is applied to a session it did not begin
    // under.
    const ticket = beginAction();
    const pending = submitOnce("invitation", (held) => account.acceptInvitation(held));
    if (pending === null) return;
    setState("working");
    setProblem(null);
    try {
      const accepted = await pending;
      if (!live(ticket)) return;
      releaseToken("invitation");
      await session.selectWorkspace(accepted.workspace_id);
      if (!live(ticket)) return;
      router.navigate("/", { replace: true });
    } catch (error) {
      if (!live(ticket)) return;
      setState("failed");
      setProblem(
        afterRefusal(
          await session.reconcile(ticket.lease, error, "mutation"),
          invitationFailure(error),
        ),
      );
    }
  };

  if (session.status !== "authenticated") {
    return (
      <PublicShell title="Sign in to accept">
        <h1>Sign in to accept this invitation</h1>
        {token === null ? (
          <p>
            This page needs the link from your invitation email. If you reloaded the page, open the
            link from the email again.
          </p>
        ) : (
          <p>
            An invitation is accepted by the account whose address it names. Sign in, or create an
            account with that address, and you will come back here to accept it.
          </p>
        )}
        <Button variant="primary" onClick={() => router.navigate(`/login${continuation}`)}>
          Sign in
        </Button>
        <p className="muted">
          No account yet? <Link to={`/signup${continuation}`}>Create one</Link>
        </p>
      </PublicShell>
    );
  }

  return (
    <PublicShell title="Accept invitation">
      <h1>Accept this invitation</h1>
      {problem ? <Notice kind="error">{problem}</Notice> : null}
      {token === null ? (
        <>
          <p>
            This page needs the link from your invitation email. If you reloaded the page, open the
            link from the email again.
          </p>
          <p className="muted">
            <Link to="/workspaces">Your workspaces</Link>
          </p>
        </>
      ) : (
        <>
          <p>
            You are signed in as <strong>{session.profile?.email}</strong>. An invitation can only
            be accepted by the account it names.
          </p>
          <Button variant="primary" busy={state === "working"} onClick={() => void accept()}>
            Accept invitation
          </Button>
          {state === "failed" ? (
            <p className="muted">
              <Link to="/workspaces">Your workspaces</Link>
            </p>
          ) : null}
        </>
      )}
    </PublicShell>
  );
}
