/**
 * The account: who you are, whether your address is confirmed, your password, your sessions.
 *
 * The password change is the flow Milestone 3.1 explicitly left to 3.2. Three proofs, none
 * of which substitutes for another: the session cookie says which account is asking, the
 * CSRF secret says the request came from this page, and the **current password** says the
 * person at the keyboard is the account holder rather than somebody who sat down at an
 * unlocked screen.
 *
 * What happens on success is stated in the interface before it is done, because it is
 * drastic and irreversible: **every other session ends**. The API replaces this session
 * atomically and sets the new cookies on the same response, and the response names the
 * replacement; the session provider adopts it from that answer, synchronously, before it
 * reads anything under it -- so nothing an older request answers can be applied to the new
 * session, and the page stays signed in without anything having to carry a secret between
 * requests.
 *
 * Every request here takes a ticket (`usePageRequests`) and its answer counts only while
 * the page is still mounted, under the same session, with no newer load started.
 */

import { useCallback, useEffect, useState } from "react";
import { account as accountApi, auth as authApi } from "../api/endpoints.ts";
import { ApiError } from "../api/errors.ts";
import type { AccountSession } from "../api/types.ts";
import { afterRefusal, useSession } from "../auth/session.tsx";
import { type PageTicket, reads, usePageRequests } from "../lib/requests.ts";
import { Button, DataTable, Empty, Field, Form, Notice, Spinner } from "../ui/components.tsx";
import { SignOutButton } from "../ui/Shell.tsx";

function when(value: string | null): string {
  if (value === null) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleString();
}

/**
 * Why a password change did not happen, in a sentence.
 *
 * `409` is the compare-and-swap losing: somebody changed this account's password -- another
 * session, or a recovery link -- while this request was running Argon2. **Nothing was
 * changed**, and saying so matters, because the alternative reading ("did it half work?") is
 * exactly what makes a person try again in a panic.
 *
 * `401` here is a wrong current password and nothing else: the session cookie was already
 * proved by the same request, so an unauthenticated answer cannot mean the session is gone.
 */
function reason(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.message : fallback;
}

function passwordChangeFailure(error: unknown): string {
  if (!(error instanceof ApiError)) return "Your password was not changed.";
  if (error.status === 409) {
    return "Your password was changed somewhere else while this was being saved. Nothing was changed here; try again.";
  }
  if (error.isUnauthenticated) return "That current password is not right.";
  return error.message;
}

export function AccountPage() {
  const session = useSession();
  const { beginAction, live, mounted } = usePageRequests(session, { scoped: false });
  const [resent, setResent] = useState(false);
  const [sending, setSending] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const profile = session.profile;

  if (profile === null) return <Spinner label="Loading your account…" />;

  const resend = async () => {
    setSending(true);
    setProblem(null);
    const ticket = beginAction();
    try {
      // The confirmation is "on its way" only once the server has accepted the request, and
      // only for a page still showing this account.
      await authApi.requestVerification(profile.email);
      if (!live(ticket)) return;
      setResent(true);
    } catch {
      if (!live(ticket)) return;
      setProblem("A new confirmation link could not be requested. Try again in a moment.");
    } finally {
      if (mounted()) setSending(false);
    }
  };

  return (
    <>
      <h1>Your account</h1>
      <dl className="detail-list">
        <dt>Email address</dt>
        <dd>{profile.email}</dd>
        <dt>Confirmed</dt>
        <dd>{profile.email_verified ? "Yes" : "Not yet"}</dd>
        <dt>Account created</dt>
        <dd>{when(profile.created_at)}</dd>
        <dt>This session expires</dt>
        <dd>{when(profile.session.expires_at)}</dd>
      </dl>

      {profile.email_verified ? null : (
        <Notice kind="warning">
          <p>
            Your address is not confirmed yet. Some actions, including creating a workspace and
            accepting an invitation, need a confirmed address.
          </p>
          {problem ? <p role="alert">{problem}</p> : null}
          {resent ? (
            <p>A new confirmation link is on its way.</p>
          ) : (
            <Button busy={sending} onClick={() => void resend()}>
              Send a new confirmation link
            </Button>
          )}
        </Notice>
      )}

      <p className="muted">
        Your email address is your identity here. Changing it is not available yet.
      </p>
    </>
  );
}

export function SecurityPage() {
  const session = useSession();
  const { reconcile, adoptFrom } = session;
  const { beginLoad, beginAction, live, latest, mounted } = usePageRequests(session, {
    scoped: false,
  });
  const [sessions, setSessions] = useState<AccountSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [problem, setProblem] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [fieldProblem, setFieldProblem] = useState<string | null>(null);
  const [changing, setChanging] = useState(false);

  /** A read refused: reconciled with the session, then said, if still the newest load. */
  const readFailed = useCallback(
    async (ticket: PageTicket, error: unknown, fallback: string) => {
      const outcome = await reconcile(ticket.lease, error, "read");
      if (latest(ticket)) setProblem(afterRefusal(outcome, reason(error, fallback)));
    },
    [reconcile, latest],
  );

  const load = useCallback(
    async (fresh = false) => {
      const ticket = beginLoad();
      setLoading(true);
      try {
        const listed = (await reads.run("sessions", () => accountApi.sessions(), { fresh }))
          .sessions;
        if (!latest(ticket)) return;
        setSessions(listed);
        setProblem(null);
      } catch (error) {
        if (latest(ticket)) await readFailed(ticket, error, "Your sessions could not be loaded.");
      } finally {
        if (latest(ticket)) setLoading(false);
      }
    },
    [beginLoad, latest, readFailed],
  );

  useEffect(() => {
    void load();
  }, [load]);

  /**
   * A refused mutation: reported, and reconciled with the session it was made under. A
   * wrong current password is `401 invalid_credentials`, a verdict on the password;
   * `reconcile` knows the difference and leaves the session alone for it.
   */
  const refused = async (ticket: PageTicket, error: unknown, sentence: string) => {
    if (!live(ticket)) return;
    setProblem(afterRefusal(await reconcile(ticket.lease, error, "mutation"), sentence));
  };

  const changePassword = async () => {
    setProblem(null);
    setNote(null);
    setFieldProblem(null);
    if (newPassword !== confirmation) {
      setFieldProblem("The two passwords do not match.");
      return;
    }
    if (newPassword === currentPassword) {
      setFieldProblem("The new password must be different from the current one.");
      return;
    }
    setChanging(true);
    const ticket = beginAction();
    try {
      await adoptFrom(() => accountApi.changePassword(currentPassword, newPassword));
      // The API replaced this session and set the new cookies on that response, and the
      // response names the replacement. Clear the fields first, so the plaintext passwords
      // stop existing in component state at the earliest possible moment; then the provider
      // adopts the replacement from the answer -- synchronously, before it reads anything
      // under it -- whatever else happened meanwhile: the cookie now carries the
      // replacement, and that is what the provider must hold.
      setCurrentPassword("");
      setNewPassword("");
      setConfirmation("");
      // The page is now under the replacement; its own ticket is a fresh one.
      const after = beginAction();
      if (!live(after)) return;
      setNote(
        "Password changed. Every other session has been signed out, and any API credential you issued has been revoked.",
      );
      await load(true);
    } catch (error) {
      // The current password is cleared on every failure, so a wrong value is not left in the
      // field to be submitted again by a reflexive second click.
      setCurrentPassword("");
      await refused(ticket, error, passwordChangeFailure(error));
    } finally {
      setChanging(false);
    }
  };

  const revoke = async (sessionId: string) => {
    setBusy(sessionId);
    setProblem(null);
    setNote(null);
    const ticket = beginAction();
    try {
      await accountApi.revokeSession(sessionId);
      if (!live(ticket)) return;
      setNote("That session has been signed out.");
      await load(true);
    } catch (error) {
      await refused(
        ticket,
        error,
        error instanceof ApiError ? error.message : "That session could not be signed out.",
      );
    } finally {
      if (mounted()) setBusy(null);
    }
  };

  const revokeOthers = async () => {
    setBusy("all");
    setProblem(null);
    setNote(null);
    const ticket = beginAction();
    try {
      const result = await accountApi.revokeAllSessions(true);
      if (!live(ticket)) return;
      setNote(
        result.revoked === 0
          ? "There were no other sessions."
          : `Signed out of ${result.revoked} other session${result.revoked === 1 ? "" : "s"}.`,
      );
      await load(true);
    } catch (error) {
      await refused(
        ticket,
        error,
        error instanceof ApiError ? error.message : "Those sessions were not ended.",
      );
    } finally {
      if (mounted()) setBusy(null);
    }
  };

  return (
    <>
      <h1>Security</h1>
      {problem ? <Notice kind="error">{problem}</Notice> : null}
      {note ? (
        <Notice kind="success" onDismiss={() => setNote(null)}>
          {note}
        </Notice>
      ) : null}

      <section aria-labelledby="password">
        <h2 id="password">Change your password</h2>
        <p className="muted">
          Changing your password signs out <strong>every other session</strong> and revokes every
          API credential you have issued. This browser stays signed in.
        </p>
        <Form onSubmit={() => void changePassword()} label="Change your password">
          <Field
            label="Current password"
            name="current_password"
            type="password"
            autoComplete="current-password"
            value={currentPassword}
            onChange={setCurrentPassword}
            required
          />
          <Field
            label="New password"
            name="new_password"
            type="password"
            autoComplete="new-password"
            value={newPassword}
            onChange={setNewPassword}
            required
            hint="At least 12 characters."
          />
          <Field
            label="Confirm new password"
            name="new_password_confirmation"
            type="password"
            autoComplete="new-password"
            value={confirmation}
            onChange={setConfirmation}
            required
            error={fieldProblem}
          />
          <Button type="submit" variant="primary" busy={changing}>
            Change password
          </Button>
        </Form>
      </section>

      <section aria-labelledby="sessions">
        <h2 id="sessions">Where you are signed in</h2>
        {loading ? (
          <Spinner label="Loading your sessions…" />
        ) : (
          <>
            <DataTable
              caption="Open browser sessions on this account"
              rows={sessions}
              rowKey={(row) => row.session_id}
              empty={<Empty title="No open sessions." />}
              columns={[
                {
                  header: "Session",
                  cell: (row: AccountSession) => (row.current ? "This browser" : "Another browser"),
                },
                { header: "Started", cell: (row: AccountSession) => when(row.created_at) },
                { header: "Last seen", cell: (row: AccountSession) => when(row.last_seen_at) },
                { header: "Expires", cell: (row: AccountSession) => when(row.expires_at) },
                {
                  header: "End",
                  cell: (row: AccountSession) =>
                    row.current ? (
                      // The same control as the masthead's: it ends the session on the
                      // server first, and says so -- and offers a retry -- when it could not.
                      <SignOutButton />
                    ) : (
                      <Button
                        variant="danger"
                        busy={busy === row.session_id}
                        onClick={() => void revoke(row.session_id)}
                      >
                        Sign out
                      </Button>
                    ),
                },
              ]}
            />
            <Button variant="danger" busy={busy === "all"} onClick={() => void revokeOthers()}>
              Sign out of every other session
            </Button>
          </>
        )}
      </section>
    </>
  );
}
