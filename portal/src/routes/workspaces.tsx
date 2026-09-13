/**
 * The first-workspace journey, and the picker a returning customer lands on.
 *
 * The gate case this implements is `AUTH-MEMBERSHIP-BOUND-IDENTITY` case 1, from the portal's
 * side: **a verified account with no membership anywhere keeps its account-level session**,
 * can see this page, and can create its first workspace. What it cannot do is bind that
 * session to a workspace it is not a member of, and the portal does not try -- it asks the
 * server to select, and the server derives the membership.
 *
 * Nothing here enumerates. The picker renders `GET /v1/account/workspaces`, which is the
 * account's own memberships; there is no lookup by slug, no "join by id", and no route that
 * would answer whether a workspace exists.
 *
 * A selection that the server accepts is a selection: the provider publishes the binding the
 * mutation returned and this page leaves for the overview at once. Whatever the follow-up
 * account read does is the provider's to report, never a reason to say the workspace could
 * not be opened.
 */

import { useState } from "react";
import { account } from "../api/endpoints.ts";
import { ApiError } from "../api/errors.ts";
import { afterRefusal, useSession } from "../auth/session.tsx";
import { type PageTicket, usePageRequests } from "../lib/requests.ts";
import { Link, useRouter } from "../lib/router.tsx";
import { Button, Empty, Field, Form, Notice, Spinner } from "../ui/components.tsx";
import { PublicShell } from "../ui/Shell.tsx";

/** A slug the API will accept: lower-case, digits and hyphens, not starting or ending with one. */
function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 62);
}

function selectionFailure(error: unknown): string {
  return error instanceof ApiError && error.status === 404
    ? "You are no longer a member of that workspace."
    : "That workspace could not be opened.";
}

function creationFailure(error: unknown): string {
  if (error instanceof ApiError && error.status === 409) {
    return "A workspace with that short name already exists here. Choose another.";
  }
  return error instanceof ApiError ? error.message : "The workspace could not be created.";
}

export function ChooseWorkspacePage() {
  const session = useSession();
  const router = useRouter();
  const { beginAction, live, mounted } = usePageRequests(session, { scoped: false });
  const [busy, setBusy] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);

  if (!session.ready) {
    return (
      <PublicShell title="Loading">
        <Spinner label="Loading your workspaces…" />
      </PublicShell>
    );
  }

  /**
   * A refused selection. The membership was removed between the list being drawn and this
   * click: the list is refreshed rather than the click retried, because what changed is the
   * truth, not the request. A `401` is ambiguous and is checked, never believed. Nothing at
   * all if the page, the session or the ticket this was asked under is no longer current.
   */
  const refused = async (ticket: PageTicket, error: unknown) => {
    if (!live(ticket)) return;
    const outcome = await session.reconcile(ticket.lease, error, "mutation");
    setProblem(afterRefusal(outcome, selectionFailure(error)));
    if (outcome === "unchanged") await session.refresh(ticket.lease);
  };

  const select = async (workspaceId: string) => {
    setBusy(workspaceId);
    setProblem(null);
    const ticket = beginAction();
    try {
      await session.selectWorkspace(workspaceId);
      if (!live(ticket)) return;
      router.navigate("/");
    } catch (error) {
      await refused(ticket, error);
    } finally {
      if (mounted()) setBusy(null);
    }
  };

  return (
    <PublicShell title="Choose a workspace">
      <h1>Choose a workspace</h1>
      {problem ? <Notice kind="error">{problem}</Notice> : null}
      {session.workspaces.length === 0 ? (
        <Empty title="You are not in any workspace yet.">
          <p>
            A workspace is where your jobs, credentials and team live. Create the first one, or ask
            a colleague to invite you to theirs.
          </p>
          <Button variant="primary" onClick={() => router.navigate("/workspaces/new")}>
            Create your first workspace
          </Button>
        </Empty>
      ) : (
        <>
          <ul className="workspace-list">
            {session.workspaces.map((workspace) => (
              <li key={workspace.workspace_id}>
                <button
                  type="button"
                  className="workspace-choice"
                  disabled={busy !== null}
                  onClick={() => void select(workspace.workspace_id)}
                >
                  <span className="workspace-name">{workspace.name}</span>
                  <span className="workspace-role">{workspace.role}</span>
                </button>
              </li>
            ))}
          </ul>
          <p className="muted">
            <Link to="/workspaces/new">Create another workspace</Link>
          </p>
        </>
      )}
    </PublicShell>
  );
}

export function CreateWorkspacePage() {
  const session = useSession();
  const router = useRouter();
  const { beginAction, live, mounted } = usePageRequests(session, { scoped: false });
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugEdited, setSlugEdited] = useState(false);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);

  const effectiveSlug = slugEdited ? slug : slugify(name);
  const first = session.workspaces.length === 0;

  const submit = async () => {
    setProblem(null);
    if (effectiveSlug === "") {
      setProblem("Give the workspace a name.");
      return;
    }
    setBusy(true);
    const ticket = beginAction();
    try {
      const created = await account.createWorkspace(effectiveSlug, name.trim());
      // Creating does not select. The session binds through membership, and the server is
      // asked to do that as a separate, revalidated step.
      await session.selectWorkspace(created.workspace_id);
      if (!live(ticket)) return;
      router.navigate("/", { replace: true });
    } catch (error) {
      if (!live(ticket)) return;
      setProblem(
        afterRefusal(
          await session.reconcile(ticket.lease, error, "mutation"),
          creationFailure(error),
        ),
      );
    } finally {
      if (mounted()) setBusy(false);
    }
  };

  return (
    <PublicShell title="Create a workspace">
      <h1>{first ? "Create your first workspace" : "Create a workspace"}</h1>
      <p>A workspace holds your jobs, your API credentials and your team. You will be its owner.</p>
      {problem ? <Notice kind="error">{problem}</Notice> : null}
      <Form onSubmit={() => void submit()} label="Create a workspace">
        <Field
          label="Workspace name"
          name="name"
          value={name}
          onChange={setName}
          required
          maxLength={200}
          hint="What your team will call it."
        />
        <Field
          label="Short name"
          name="slug"
          value={effectiveSlug}
          onChange={(value) => {
            setSlugEdited(true);
            setSlug(value);
          }}
          required
          maxLength={62}
          hint="Lower-case letters, digits and hyphens. Used in URLs."
        />
        <Button type="submit" variant="primary" busy={busy}>
          Create workspace
        </Button>
      </Form>
      {session.workspaces.length > 0 ? (
        <p className="muted">
          <Link to="/workspaces">Back to your workspaces</Link>
        </p>
      ) : null}
    </PublicShell>
  );
}
