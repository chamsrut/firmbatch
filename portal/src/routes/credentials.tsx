/**
 * API credentials: list, issue, rotate, revoke, and the audit trail for one.
 *
 * **A browser session and an API credential are different credential types**, and this page
 * is where a customer meets both without them ever touching. The session authorises the
 * *operation*; the operation asks the database to **mint a new credential** after re-deriving
 * the membership and bounding the requested scopes by what that membership actually holds. It
 * is not a token exchange: nothing here sends the session's secret, receives it back in
 * another shape, or converts one into the other. The API refuses a session secret at the
 * bearer boundary and a bearer token at the browser boundary, in both directions.
 *
 * **The secret is shown once.** `POST` returns it in the response body, this component holds
 * it in one piece of React state, and it is rendered in one place. It is never put in a URL,
 * a cookie, browser storage (which throws in tests), a log (there is none), the session
 * context, or any list. A replay of the same idempotency key returns `credential: null`,
 * which is rendered as "already issued" rather than as an error -- and the value is genuinely
 * unrecoverable, because the database stores a fingerprint.
 *
 * Every request is made for the workspace the page began under and every answer is taken
 * only while that is still the page's workspace under the same session, on a page still
 * mounted, with no newer load started -- see `usePageRequests` and `routes/team.tsx`.
 */

import { useCallback, useEffect, useState } from "react";
import { credentials as credentialsApi } from "../api/endpoints.ts";
import { ApiError } from "../api/errors.ts";
import type { CredentialHistoryEntry, CredentialSummary } from "../api/types.ts";
import { afterRefusal, shows, useSession } from "../auth/session.tsx";
import { type PageTicket, reads, usePageRequests } from "../lib/requests.ts";
import {
  Button,
  Checkbox,
  DataTable,
  Dialog,
  Empty,
  Field,
  Form,
  Notice,
  OneTimeSecret,
  PermissionButton,
  Spinner,
} from "../ui/components.tsx";
import { OTHER_WORKSPACE_ANSWERED } from "./team.tsx";

/**
 * The scopes a customer may place on a credential.
 *
 * The API bounds every request by the closed Milestone 2.3 catalogue **and** by the issuing
 * member's own permissions, so this list is what to *offer*, never what is allowed. Two
 * scopes are deliberately absent from the whole system and so cannot appear: there is no
 * supplier, capacity, settlement or operator scope in the catalogue at all, and
 * `credential:manage` -- which would mint a credential tied to no membership -- is issuable
 * by nobody.
 */
const OFFERED_SCOPES: ReadonlyArray<{ value: string; label: string; hint: string }> = [
  { value: "tenant:read", label: "Read your account record", hint: "One row: your own." },
  { value: "workspace:read", label: "Read workspaces", hint: "List and read this workspace." },
  {
    value: "workspace:write",
    label: "Change workspaces",
    hint: "Create, amend and remove workspace resources.",
  },
  {
    value: "mutation:execute",
    label: "Record mutations",
    hint: "Claim retry keys and record that a change happened. Most automation needs this.",
  },
  { value: "audit:read", label: "Read the audit trail", hint: "This workspace's history." },
];

function when(value: string | null): string {
  if (value === null) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleString();
}

function reason(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.message : fallback;
}

function state(row: CredentialSummary): string {
  if (row.revoked_at !== null) return "revoked";
  if (row.expires_at !== null && new Date(row.expires_at).getTime() < Date.now()) return "expired";
  return row.active ? "active" : "inactive";
}

export function CredentialsPage() {
  const session = useSession();
  const { reconcile, refresh } = session;
  const { beginLoad, beginAction, live, latest, mounted } = usePageRequests(session, {
    scoped: true,
  });
  const [rows, setRows] = useState<CredentialSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [problem, setProblem] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  // The one place a plaintext credential lives, for as long as the customer is looking at it.
  const [issued, setIssued] = useState<string | null>(null);

  const [label, setLabel] = useState("");
  const [scopes, setScopes] = useState<string[]>(["workspace:read", "mutation:execute"]);
  const [expiresAt, setExpiresAt] = useState("");
  const [history, setHistory] = useState<{
    id: string;
    entries: CredentialHistoryEntry[];
  } | null>(null);

  const mayIssue = shows.credentialIssuing(session.role);
  const maySeeHistory = shows.auditHistory(session.role);

  /** A read that answered for another workspace: not rendered; the binding is re-read. */
  const answeredForAnother = useCallback(
    (ticket: PageTicket, say: (message: string | null) => void) => {
      say(OTHER_WORKSPACE_ANSWERED);
      void refresh(ticket.lease);
    },
    [refresh],
  );

  /** A read refused: reconciled with the session, then said, if still the newest load. */
  const readFailed = useCallback(
    async (
      ticket: PageTicket,
      error: unknown,
      fallback: string,
      say: (m: string | null) => void,
    ) => {
      const outcome = await reconcile(ticket.lease, error, "read");
      if (latest(ticket)) say(afterRefusal(outcome, reason(error, fallback)));
    },
    [reconcile, latest],
  );

  const load = useCallback(
    async (fresh = false) => {
      const ticket = beginLoad();
      setLoading(true);
      try {
        const listed = await reads.run(
          `credentials:${ticket.workspaceId}`,
          () => credentialsApi.list(),
          { fresh },
        );
        if (!latest(ticket)) return;
        if (listed.workspace_id !== ticket.workspaceId)
          return answeredForAnother(ticket, setProblem);
        setRows(listed.credentials);
        setProblem(null);
      } catch (error) {
        if (latest(ticket)) {
          await readFailed(ticket, error, "Your credentials could not be loaded.", setProblem);
        }
      } finally {
        if (latest(ticket)) setLoading(false);
      }
    },
    [beginLoad, latest, answeredForAnother, readFailed],
  );

  const boundWorkspace = session.workspaceId;
  // biome-ignore lint/correctness/useExhaustiveDependencies: the selected workspace is a reason to load again, not an input to the load
  useEffect(() => {
    void load();
  }, [load, boundWorkspace]);

  /** A refused mutation: reported, and reconciled with the session it was made under. */
  const refused = async (ticket: PageTicket, error: unknown, fallback: string) => {
    if (!live(ticket)) return;
    setProblem(
      afterRefusal(
        await reconcile(ticket.lease, error, "mutation"),
        error instanceof ApiError ? error.message : fallback,
      ),
    );
  };

  const issue = async () => {
    setBusy("issue");
    setProblem(null);
    setNote(null);
    const ticket = beginAction();
    if (ticket.workspaceId === null) return;
    try {
      const result = await credentialsApi.issue(
        ticket.workspaceId,
        scopes,
        label.trim() === "" ? null : label.trim(),
        expiresAt === "" ? null : new Date(expiresAt).toISOString(),
      );
      if (!live(ticket)) return;
      if (result.credential === null) {
        // A replay. The secret was displayed when it was minted and cannot be produced
        // again, so say that rather than showing an empty box.
        setNote(
          "That credential was already issued. Its key was shown once and cannot be shown again.",
        );
      } else {
        setIssued(result.credential);
      }
      setLabel("");
      await load(true);
    } catch (error) {
      await refused(ticket, error, "That credential was not issued.");
    } finally {
      if (mounted()) setBusy((current) => (current === "issue" ? null : current));
    }
  };

  const rotate = async (credentialId: string) => {
    setBusy(credentialId);
    setProblem(null);
    setNote(null);
    const ticket = beginAction();
    if (ticket.workspaceId === null) return;
    try {
      const result = await credentialsApi.rotate(ticket.workspaceId, credentialId, null);
      if (!live(ticket)) return;
      if (result.credential === null) {
        setNote("That rotation had already happened. Its key was shown once.");
      } else {
        setIssued(result.credential);
        setNote("Rotated. The previous key stopped working immediately.");
      }
      await load(true);
    } catch (error) {
      await refused(ticket, error, "That credential could not be rotated.");
    } finally {
      if (mounted()) setBusy((current) => (current === credentialId ? null : current));
    }
  };

  const revoke = async (credentialId: string) => {
    setBusy(credentialId);
    setProblem(null);
    setNote(null);
    const ticket = beginAction();
    if (ticket.workspaceId === null) return;
    try {
      await credentialsApi.revoke(ticket.workspaceId, credentialId);
      if (!live(ticket)) return;
      setNote("Revoked. It stops working immediately.");
      await load(true);
    } catch (error) {
      await refused(ticket, error, "That credential could not be revoked.");
    } finally {
      if (mounted()) setBusy((current) => (current === credentialId ? null : current));
    }
  };

  const historyFailure = (error: unknown): string =>
    error instanceof ApiError && error.status === 404
      ? "There is no history you can see for that credential."
      : "That history could not be loaded.";

  const openHistory = async (credentialId: string) => {
    setBusy(credentialId);
    setProblem(null);
    const ticket = beginAction();
    try {
      const result = await credentialsApi.history(credentialId);
      if (!live(ticket)) return;
      if (result.workspace_id !== ticket.workspaceId) answeredForAnother(ticket, setProblem);
      else setHistory({ id: credentialId, entries: result.history });
    } catch (error) {
      if (!live(ticket)) return;
      const outcome = await reconcile(ticket.lease, error, "read");
      if (live(ticket)) setProblem(afterRefusal(outcome, historyFailure(error)));
    } finally {
      if (mounted()) setBusy((current) => (current === credentialId ? null : current));
    }
  };

  if (loading) return <Spinner label="Loading credentials…" />;

  return (
    <>
      <h1>API credentials</h1>
      <p className="lede">
        API credentials are how the SDK, the CLI and your own automation authenticate. They are a
        different kind of credential from your browser session: neither is accepted where the other
        belongs, and neither is ever converted into the other.
      </p>

      {problem ? <Notice kind="error">{problem}</Notice> : null}
      {note ? (
        <Notice kind="info" onDismiss={() => setNote(null)}>
          {note}
        </Notice>
      ) : null}
      {issued !== null ? <OneTimeSecret secret={issued} onDismiss={() => setIssued(null)} /> : null}

      <section aria-labelledby="existing">
        <h2 id="existing">Your credentials</h2>
        <DataTable
          caption="API credentials in this workspace"
          rows={rows}
          rowKey={(row) => row.credential_id}
          empty={
            <Empty title="No credentials yet.">
              <p>Create one below when you are ready to call the API.</p>
            </Empty>
          }
          columns={[
            { header: "Label", cell: (row: CredentialSummary) => row.label ?? "—" },
            { header: "Issued to", cell: (row: CredentialSummary) => row.email ?? "—" },
            {
              header: "Scopes",
              cell: (row: CredentialSummary) => (
                <ul className="scope-list">
                  {row.scopes.map((scope) => (
                    <li key={scope}>{scope}</li>
                  ))}
                </ul>
              ),
            },
            { header: "State", cell: (row: CredentialSummary) => state(row) },
            { header: "Created", cell: (row: CredentialSummary) => when(row.created_at) },
            { header: "Last used", cell: (row: CredentialSummary) => when(row.last_used_at) },
            {
              header: "Actions",
              cell: (row: CredentialSummary) => (
                <span className="row">
                  <PermissionButton
                    allowed={mayIssue && row.active}
                    busy={busy === row.credential_id}
                    reason={
                      row.active
                        ? "Only the member who issued a credential can rotate it."
                        : "This credential is no longer active."
                    }
                    onClick={() => void rotate(row.credential_id)}
                  >
                    Rotate
                  </PermissionButton>
                  <PermissionButton
                    variant="danger"
                    allowed={row.active}
                    busy={busy === row.credential_id}
                    reason="This credential is no longer active."
                    onClick={() => void revoke(row.credential_id)}
                  >
                    Revoke
                  </PermissionButton>
                  {maySeeHistory ? (
                    <Button
                      variant="quiet"
                      busy={busy === row.credential_id}
                      onClick={() => void openHistory(row.credential_id)}
                    >
                      History
                    </Button>
                  ) : null}
                </span>
              ),
            },
          ]}
        />
      </section>

      <section aria-labelledby="issue">
        <h2 id="issue">Create a credential</h2>
        <Form onSubmit={() => void issue()} label="Create an API credential">
          <Field
            label="Label"
            name="label"
            value={label}
            onChange={setLabel}
            maxLength={100}
            disabled={!mayIssue}
            hint="What it is for. Never put a secret in a label."
          />
          <fieldset>
            <legend>What it may do</legend>
            <p className="field-hint">
              A credential can never hold more than your own role allows. Ask for the least that
              works.
            </p>
            {OFFERED_SCOPES.map((scope) => (
              <Checkbox
                key={scope.value}
                label={scope.label}
                hint={scope.hint}
                checked={scopes.includes(scope.value)}
                disabled={!mayIssue}
                onChange={(checked) =>
                  setScopes(
                    checked
                      ? [...scopes, scope.value]
                      : scopes.filter((value) => value !== scope.value),
                  )
                }
              />
            ))}
          </fieldset>
          <Field
            label="Expires"
            name="expires_at"
            value={expiresAt}
            onChange={setExpiresAt}
            disabled={!mayIssue}
            hint="Optional. An ISO date, for example 2027-01-31. Leave blank for no expiry."
          />
          <PermissionButton
            type="submit"
            variant="primary"
            busy={busy === "issue"}
            allowed={mayIssue && scopes.length > 0}
            reason={
              scopes.length === 0
                ? "Choose at least one thing the credential may do."
                : "A viewer cannot create API credentials."
            }
          >
            Create credential
          </PermissionButton>
        </Form>
      </section>

      {history !== null ? (
        <Dialog title="Credential history" onClose={() => setHistory(null)}>
          {history.entries.length === 0 ? (
            <Empty title="No recorded history." />
          ) : (
            <DataTable
              caption="Audit trail for this credential"
              rows={history.entries}
              rowKey={(entry) => entry.audit_event_id}
              empty={<Empty title="No recorded history." />}
              columns={[
                { header: "When", cell: (e: CredentialHistoryEntry) => when(e.occurred_at) },
                { header: "Action", cell: (e: CredentialHistoryEntry) => e.action },
                { header: "Outcome", cell: (e: CredentialHistoryEntry) => e.outcome },
              ]}
            />
          )}
          <Button onClick={() => setHistory(null)}>Close</Button>
        </Dialog>
      ) : null}
    </>
  );
}
