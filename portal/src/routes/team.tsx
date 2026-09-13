/**
 * Workspace details, members and invitations.
 *
 * **Hiding a control is not authorization.** Every button here is gated on the role the
 * server last reported, and every operation behind it is checked again by the server against
 * the membership as it is at that moment -- re-derived under a workspace lock, not read from
 * the session's cached context. A customer demoted while this page is open sees the controls
 * until the page next hears from the server, and gets a `403` if they use one; the page then
 * refreshes its authority and re-renders. That order is deliberate: the interface follows the
 * server, never the other way round.
 *
 * The two owner rules the database enforces are stated in the interface too, so a customer
 * is not surprised by a refusal: only an owner may act on an owner, and the last active owner
 * cannot be removed or demoted.
 *
 * **Every request here is made for the workspace the page began under**, and every answer is
 * taken only while that is still the page's workspace, the session is still the session, the
 * page is still mounted and no newer load has started (`usePageRequests`). A mutation carries
 * the workspace it was made for, and the database refuses it if the shared session has since
 * been switched to another; a read names the workspace it describes, and one that names a
 * different workspace is never rendered here.
 */

import { useCallback, useEffect, useState } from "react";
import { workspace as workspaceApi } from "../api/endpoints.ts";
import { ApiError } from "../api/errors.ts";
import type { InvitationSummary, MemberSummary, Role, WorkspaceDetail } from "../api/types.ts";
import { afterRefusal, shows, useSession } from "../auth/session.tsx";
import { type PageTicket, reads, usePageRequests } from "../lib/requests.ts";
import {
  DataTable,
  Empty,
  Field,
  Form,
  Notice,
  PermissionButton,
  Select,
  Spinner,
} from "../ui/components.tsx";

const ROLE_OPTIONS: ReadonlyArray<{ value: Role; label: string }> = [
  { value: "viewer", label: "Viewer — reads only" },
  { value: "member", label: "Member — works in the workspace, issues own credentials" },
  { value: "admin", label: "Admin — everything except acting on owners" },
  { value: "owner", label: "Owner — full authority, including over other owners" },
];

/** What a page says when a read answered for a workspace other than the one it began under. */
export const OTHER_WORKSPACE_ANSWERED =
  "This page received another workspace's data and did not show it. The selected workspace has been re-read; reload to continue.";

function when(value: string | null): string {
  if (value === null) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleString();
}

function reason(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.message : fallback;
}

// -------------------------------------------------------------------- workspace details

export function WorkspaceSettingsPage() {
  const session = useSession();
  const { reconcile, refresh } = session;
  const { beginLoad, beginAction, live, latest, mounted } = usePageRequests(session, {
    scoped: true,
  });
  const [detail, setDetail] = useState<WorkspaceDetail | null>(null);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [loading, setLoading] = useState(true);

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
      // The ticket this read is made under. Its answer -- the detail, or a refusal -- counts
      // only while this is still the newest load of a page still showing this workspace under
      // this session; see `usePageRequests`.
      const ticket = beginLoad();
      setLoading(true);
      try {
        const value = await reads.run(
          `workspace:${ticket.workspaceId}`,
          () => workspaceApi.detail(),
          { fresh },
        );
        if (!latest(ticket)) return;
        // The session may be bound elsewhere than this page believes -- another tab switched
        // it -- and nothing of that workspace is rendered here; the binding is re-read, and
        // the page reloads for whatever it turns out to be.
        if (value.workspace_id !== ticket.workspaceId)
          return answeredForAnother(ticket, setProblem);
        setDetail(value);
        setName(value.name);
        setProblem(null);
      } catch (error) {
        if (latest(ticket))
          await readFailed(ticket, error, "This workspace could not be loaded.", setProblem);
      } finally {
        if (latest(ticket)) setLoading(false);
      }
    },
    [beginLoad, latest, answeredForAnother, readFailed],
  );

  // On mount, and again whenever the selected workspace changes while this page stays open.
  const boundWorkspace = session.workspaceId;
  // biome-ignore lint/correctness/useExhaustiveDependencies: the selected workspace is a reason to load again, not an input to the load
  useEffect(() => {
    void load();
  }, [load, boundWorkspace]);

  const rename = async () => {
    setBusy(true);
    setProblem(null);
    setSaved(false);
    const ticket = beginAction();
    if (ticket.workspaceId === null) return;
    try {
      await workspaceApi.rename(ticket.workspaceId, name.trim());
      if (!live(ticket)) return;
      setSaved(true);
      await load(true);
      await refresh(ticket.lease);
    } catch (error) {
      if (!live(ticket)) return;
      setProblem(
        afterRefusal(
          await reconcile(ticket.lease, error, "mutation"),
          reason(error, "The workspace could not be renamed."),
        ),
      );
    } finally {
      if (mounted()) setBusy(false);
    }
  };

  if (loading) return <Spinner label="Loading workspace…" />;

  const mayRename = shows.workspaceSettings(session.role);

  return (
    <>
      <h1>Workspace</h1>
      {problem ? <Notice kind="error">{problem}</Notice> : null}
      {saved ? (
        <Notice kind="success" onDismiss={() => setSaved(false)}>
          Workspace renamed.
        </Notice>
      ) : null}

      <dl className="detail-list">
        <dt>Short name</dt>
        <dd>{detail?.slug ?? "—"}</dd>
        <dt>Created</dt>
        <dd>{when(detail?.created_at ?? null)}</dd>
        <dt>Your role</dt>
        <dd>{detail?.role ?? "—"}</dd>
      </dl>

      <section aria-labelledby="rename">
        <h2 id="rename">Rename</h2>
        <Form onSubmit={() => void rename()} label="Rename this workspace">
          <Field
            label="Workspace name"
            name="name"
            value={name}
            onChange={setName}
            required
            maxLength={200}
            disabled={!mayRename}
          />
          <PermissionButton
            type="submit"
            variant="primary"
            busy={busy}
            allowed={mayRename}
            reason="Only an owner or an admin can rename this workspace."
          >
            Save name
          </PermissionButton>
        </Form>
      </section>
    </>
  );
}

// ------------------------------------------------------------------------------- people

export function TeamPage() {
  const session = useSession();
  const { reconcile, refresh } = session;
  const { beginLoad, beginAction, live, latest, mounted } = usePageRequests(session, {
    scoped: true,
  });
  const [members, setMembers] = useState<MemberSummary[]>([]);
  const [invitations, setInvitations] = useState<InvitationSummary[]>([]);
  const [loading, setLoading] = useState(true);
  // Two error states, deliberately. `problem` is "the thing you just asked for did not
  // happen"; `loadProblem` is "these lists could not be fetched". They have different
  // lifetimes, and collapsing them means a reload wipes the explanation of a failed action.
  const [problem, setProblem] = useState<string | null>(null);
  const [loadProblem, setLoadProblem] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<Role>("member");
  const [inviting, setInviting] = useState(false);
  const [workingOn, setWorkingOn] = useState<string | null>(null);

  const mayManage = shows.teamManagement(session.role);
  const isOwner = shows.ownerActions(session.role);
  const activeOwners = members.filter((member) => member.role === "owner").length;

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

  /**
   * Reload both lists.
   *
   * Sets and clears **`loadProblem` only**, never `problem`. That separation is the whole
   * point of two states: after an action fails, the page reloads the lists so the customer
   * sees where things actually stand -- and a reload that cleared `problem` on its way would
   * erase the explanation of the failure they are looking for, leaving a page that silently
   * did nothing.
   */
  const load = useCallback(
    async (fresh = false) => {
      const ticket = beginLoad();
      setLoading(true);
      try {
        // A viewer holds membership:read, so both lists load for every role. What differs is
        // what can be done with them.
        const [memberList, invitationList] = await Promise.all([
          reads.run(`members:${ticket.workspaceId}`, () => workspaceApi.members(), { fresh }),
          reads.run(`invitations:${ticket.workspaceId}`, () => workspaceApi.invitations(), {
            fresh,
          }),
        ]);
        if (!latest(ticket)) return;
        const elsewhere =
          memberList.workspace_id !== ticket.workspaceId ||
          invitationList.workspace_id !== ticket.workspaceId;
        if (elsewhere) return answeredForAnother(ticket, setLoadProblem);
        setMembers(memberList.members);
        setInvitations(invitationList.invitations);
        setLoadProblem(null);
      } catch (error) {
        if (latest(ticket))
          await readFailed(ticket, error, "The team could not be loaded.", setLoadProblem);
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

  const act = async (
    key: string,
    action: (workspace: string) => Promise<unknown>,
    success: string,
  ) => {
    setWorkingOn(key);
    setProblem(null);
    setNote(null);
    const ticket = beginAction();
    if (ticket.workspaceId === null) return;
    try {
      await action(ticket.workspaceId);
      if (!live(ticket)) return;
      setNote(success);
      await load(true);
      // The acting customer may have changed their own role, or removed themselves. Refresh
      // the session's authority so the navigation and the controls follow.
      await refresh(ticket.lease);
    } catch (error) {
      if (!live(ticket)) return;
      setProblem(
        afterRefusal(
          await reconcile(ticket.lease, error, "mutation"),
          reason(error, "That did not work. Nothing was changed."),
        ),
      );
      await load(true);
    } finally {
      if (mounted()) setWorkingOn((current) => (current === key ? null : current));
    }
  };

  const invite = async () => {
    setInviting(true);
    setProblem(null);
    setNote(null);
    const ticket = beginAction();
    if (ticket.workspaceId === null) return;
    try {
      await workspaceApi.invite(ticket.workspaceId, inviteEmail.trim(), inviteRole);
      if (!live(ticket)) return;
      setNote("Invitation sent. It works once and expires.");
      setInviteEmail("");
      await load(true);
    } catch (error) {
      if (!live(ticket)) return;
      setProblem(
        afterRefusal(
          await reconcile(ticket.lease, error, "mutation"),
          reason(error, "That invitation could not be sent."),
        ),
      );
    } finally {
      if (mounted()) setInviting(false);
    }
  };

  if (loading) return <Spinner label="Loading your team…" />;

  return (
    <>
      <h1>Team</h1>
      {loadProblem ? <Notice kind="error">{loadProblem}</Notice> : null}
      {problem ? <Notice kind="error">{problem}</Notice> : null}
      {note ? (
        <Notice kind="success" onDismiss={() => setNote(null)}>
          {note}
        </Notice>
      ) : null}
      {mayManage ? null : (
        <Notice kind="info">
          You can see who is in this workspace. Inviting, removing and changing roles needs an owner
          or an admin.
        </Notice>
      )}

      <section aria-labelledby="members">
        <h2 id="members">Members</h2>
        <DataTable
          caption="People in this workspace"
          rows={members}
          rowKey={(member) => member.membership_id}
          empty={<Empty title="No members yet." />}
          columns={[
            { header: "Email", cell: (member: MemberSummary) => member.email },
            { header: "Role", cell: (member: MemberSummary) => member.role },
            { header: "Joined", cell: (member: MemberSummary) => when(member.joined_at) },
            {
              header: "Role change",
              cell: (member: MemberSummary) => {
                // The two owner rules, stated where they bite. The server enforces both; this
                // is so a customer is not surprised by the refusal.
                const targetIsOwner = member.role === "owner";
                const lastOwner = targetIsOwner && activeOwners <= 1;
                const allowed = mayManage && (!targetIsOwner || isOwner) && !lastOwner;
                const why = lastOwner
                  ? "A workspace must keep at least one owner."
                  : targetIsOwner && !isOwner
                    ? "Only an owner can change an owner's role."
                    : "Only an owner or an admin can change roles.";
                return (
                  <span className="row">
                    <Select
                      label={`Role for ${member.email}`}
                      value={member.role}
                      options={ROLE_OPTIONS.filter((option) => option.value !== "owner" || isOwner)}
                      disabled={!allowed || workingOn !== null}
                      onChange={(role) =>
                        void act(
                          member.membership_id,
                          (workspace) =>
                            workspaceApi.changeMemberRole(workspace, member.membership_id, role),
                          "Role changed.",
                        )
                      }
                    />
                    {allowed ? null : <span className="permission-reason">{why}</span>}
                  </span>
                );
              },
            },
            {
              header: "Remove",
              cell: (member: MemberSummary) => {
                const targetIsOwner = member.role === "owner";
                const lastOwner = targetIsOwner && activeOwners <= 1;
                const allowed = mayManage && (!targetIsOwner || isOwner) && !lastOwner;
                return (
                  <PermissionButton
                    variant="danger"
                    allowed={allowed}
                    busy={workingOn === member.membership_id}
                    reason={
                      lastOwner
                        ? "A workspace must keep at least one owner."
                        : targetIsOwner
                          ? "Only an owner can remove an owner."
                          : "Only an owner or an admin can remove members."
                    }
                    onClick={() =>
                      void act(
                        member.membership_id,
                        (workspace) => workspaceApi.removeMember(workspace, member.membership_id),
                        "Member removed. Their credentials for this workspace are revoked.",
                      )
                    }
                  >
                    Remove
                  </PermissionButton>
                );
              },
            },
          ]}
        />
      </section>

      <section aria-labelledby="invitations">
        <h2 id="invitations">Invitations</h2>
        <DataTable
          caption="Outstanding invitations"
          rows={invitations}
          rowKey={(invitation) => invitation.invitation_id}
          empty={<Empty title="No outstanding invitations." />}
          columns={[
            { header: "Email", cell: (row: InvitationSummary) => row.email },
            { header: "Role", cell: (row: InvitationSummary) => row.role },
            { header: "Status", cell: (row: InvitationSummary) => row.status },
            { header: "Expires", cell: (row: InvitationSummary) => when(row.expires_at) },
            {
              header: "Revoke",
              cell: (row: InvitationSummary) => (
                <PermissionButton
                  variant="danger"
                  allowed={mayManage && row.status === "pending"}
                  busy={workingOn === row.invitation_id}
                  reason={
                    row.status === "pending"
                      ? "Only an owner or an admin can revoke an invitation."
                      : "This invitation is no longer outstanding."
                  }
                  onClick={() =>
                    void act(
                      row.invitation_id,
                      (workspace) => workspaceApi.revokeInvitation(workspace, row.invitation_id),
                      "Invitation revoked.",
                    )
                  }
                >
                  Revoke
                </PermissionButton>
              ),
            },
          ]}
        />
      </section>

      <section aria-labelledby="invite">
        <h2 id="invite">Invite someone</h2>
        <Form onSubmit={() => void invite()} label="Invite someone to this workspace">
          <Field
            label="Email address"
            name="invite_email"
            type="email"
            inputMode="email"
            value={inviteEmail}
            onChange={setInviteEmail}
            required
            maxLength={254}
            disabled={!mayManage}
            hint="The invitation can only be accepted by an account with this address."
          />
          <Select
            label="Role"
            value={inviteRole}
            options={ROLE_OPTIONS.filter((option) => option.value !== "owner" || isOwner)}
            disabled={!mayManage}
            onChange={setInviteRole}
          />
          <PermissionButton
            type="submit"
            variant="primary"
            busy={inviting}
            allowed={mayManage}
            reason="Only an owner or an admin can invite people."
          >
            Send invitation
          </PermissionButton>
        </Form>
      </section>
    </>
  );
}

/** Exported for the page tests, which assert a ticket's shape without a network. */
export type { PageTicket };
