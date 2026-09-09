"""Workspaces, memberships and invitations: the Python side of Milestone 3.1's membership functions.

Thin, like ``db/accounts.py`` and for the same reason: every decision is made again inside
a ``SECURITY DEFINER`` function in migration ``0005``. Every function here requires a
transaction that :func:`~firmbatch.control_plane.db.accounts.bind_session_context` has
already bound -- in ``account`` mode for the account-level operations (listing and
creating workspaces, selecting one, accepting an invitation) and in ``workspace`` mode for
everything that acts inside a workspace.

The rules a reader should know before calling anything
------------------------------------------------------

* **A workspace is created with its own tenant.** In Milestone 3.1 the customer-visible
  unit of membership is the database's unit of isolation, so :func:`create_workspace`
  produces a tenant, a workspace and the creator's owner membership in one call. The
  tenant's slug is generated; the customer's slug is the workspace's, which is
  tenant-local -- a customer-chosen global slug would be a cross-tenant existence oracle.
* **Selecting a workspace is deriving a membership.** :func:`bind_session_workspace`
  succeeds only for a workspace the account holds an active membership in, and every
  later request re-derives that membership before a tenant context is established.
* **And so does every workspace operation, mutation and disclosure alike.** The scope set a
  bind establishes is a cache of an authorization decision, so each function re-derives the
  membership through one mechanism -- ``firmbatch.workspace_membership_authority``, which
  :func:`require_membership` also exposes for the one disclosure the HTTP boundary performs
  itself -- after taking its serialisation lock and before any replay lookup, disclosure or
  mutation. A caller demoted or removed since it bound is refused, whatever its session
  cached.
* **Only an owner may act on an owner**, and **the last active owner cannot be removed or
  demoted** (:data:`~firmbatch.control_plane.security.permissions.OWNER_ONLY_RULES`).
* **Invitations are bound and one-time.** Workspace, tenant, recipient, role and expiry
  are fixed when the invitation is created; acceptance requires the signed-in, verified
  account whose address the invitation names, locks the row, and consumes it.
* **Every mutation takes an optional idempotency key.** With one, a retry replays the
  stored result and a reuse for a different request is refused; the claim and one linked
  outbox event are written by the database function itself. Without one, one unlinked
  event is written. The account-level operations keep their replay record by account,
  because they run before a tenant context exists.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

from ..security.permissions import MembershipRole
from ..security.secrets import Secret, is_well_formed_identity_secret, looks_like_secret
from .accounts import IdentityError, _execute, _require_secret, normalize_email
from .base import SCHEMA
from .idempotency import _require_valid_key
from .models import MEMBERSHIP_ROLES

DEFAULT_INVITATION_TTL = timedelta(days=7)


@dataclass(frozen=True)
class MembershipAuthority:
    """The caller's own membership, re-derived from committed state under the workspace lock."""

    session_id: uuid.UUID
    account_id: uuid.UUID
    workspace_id: uuid.UUID
    tenant_id: uuid.UUID
    membership_id: uuid.UUID
    role: str


def require_membership(session: Session, *, scope: str | None = None, lock: bool = False) -> MembershipAuthority:
    """Re-derive this session's membership, and require ``scope`` of the role it holds **now**.

    The one membership revalidation, called from Python for the one disclosure the HTTP
    boundary performs itself (a credential's audit history, which it reads through
    ``db/audit.py`` rather than through an identity function). Everything it checks --
    the workspace serialisation lock, then tenant, workspace, account, membership identity,
    both active states and the current role -- is checked inside
    ``firmbatch.workspace_membership_authority``; nothing here is load-bearing.

    ``lock`` selects the ``FOR UPDATE`` form, for a caller that is about to mutate. A caller
    that will mutate must ask for it **first**: taking the share form and upgrading later is
    the one way two transactions deadlock here.

    Raises :class:`~firmbatch.control_plane.db.accounts.IdentityRefused` when the membership
    or the workspace is gone, and
    :class:`~firmbatch.control_plane.security.authorization.AuthorizationError` when the
    role does not hold ``scope``.
    """
    if scope is not None and not isinstance(scope, str):
        raise IdentityError("a permission is named by a string")
    row = _execute(
        session,
        text(
            "SELECT session_id, account_id, workspace_id, tenant_id, membership_id, role "
            f"FROM {SCHEMA}.workspace_membership_authority(:scope, :lock)"
        ),
        {"scope": scope, "lock": bool(lock)},
    ).one()
    return MembershipAuthority(
        session_id=row.session_id,
        account_id=row.account_id,
        workspace_id=row.workspace_id,
        tenant_id=row.tenant_id,
        membership_id=row.membership_id,
        role=row.role,
    )


@dataclass(frozen=True)
class WorkspaceSummary:
    workspace_id: uuid.UUID
    tenant_id: uuid.UUID
    slug: str
    name: str
    role: str
    membership_id: uuid.UUID
    joined_at: datetime


@dataclass(frozen=True)
class CreatedWorkspace:
    workspace_id: uuid.UUID
    tenant_id: uuid.UUID
    membership_id: uuid.UUID
    event_id: uuid.UUID | None
    record_id: uuid.UUID | None
    replayed: bool


@dataclass(frozen=True)
class WorkspaceBinding:
    workspace_id: uuid.UUID
    tenant_id: uuid.UUID
    membership_id: uuid.UUID
    role: str


@dataclass(frozen=True)
class MembershipSummary:
    membership_id: uuid.UUID
    account_id: uuid.UUID
    email: str
    role: str
    created_at: datetime


@dataclass(frozen=True)
class MembershipChange:
    membership_id: uuid.UUID
    role: str | None
    event_id: uuid.UUID | None
    record_id: uuid.UUID | None
    replayed: bool


@dataclass(frozen=True)
class CreatedInvitation:
    """``secret`` is present on the first execution only; a replay returns ``None``."""

    invitation_id: uuid.UUID
    secret: Secret | None
    expires_at: datetime
    event_id: uuid.UUID | None
    record_id: uuid.UUID | None
    replayed: bool

    def __repr__(self) -> str:
        return f"CreatedInvitation(invitation_id={self.invitation_id}, replayed={self.replayed}, secret=<redacted>)"


@dataclass(frozen=True)
class InvitationSummary:
    invitation_id: uuid.UUID
    email: str
    role: str
    created_at: datetime
    expires_at: datetime
    status: str


@dataclass(frozen=True)
class AcceptedInvitation:
    workspace_id: uuid.UUID
    tenant_id: uuid.UUID
    membership_id: uuid.UUID
    role: str
    event_id: uuid.UUID | None
    record_id: uuid.UUID | None
    replayed: bool


@dataclass(frozen=True)
class Revocation:
    revoked: bool
    event_id: uuid.UUID | None
    record_id: uuid.UUID | None
    replayed: bool


def _key(idempotency_key: str | None) -> str | None:
    if idempotency_key is None:
        return None
    _require_valid_key(idempotency_key)
    return idempotency_key


def _require_uuid(value, *, what: str) -> uuid.UUID:
    if not isinstance(value, uuid.UUID):
        raise IdentityError(f"a {what} is a UUID; got {type(value).__name__}")
    return value


def _require_role(role) -> str:
    value = role.value if isinstance(role, MembershipRole) else role
    if looks_like_secret(value) is not None or value not in MEMBERSHIP_ROLES:
        raise IdentityError(
            "the membership role is not in the closed model; the rejected value is deliberately not repeated"
        )
    return value


def _require_text(value, *, what: str, maximum: int) -> str:
    shape = looks_like_secret(value)
    if shape is not None:
        raise IdentityError(f"the {what} looks like {shape}; the value is deliberately not repeated")
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise IdentityError(
            f"the {what} is a string of 1 to {maximum} characters; the value is deliberately not repeated"
        )
    return value


# --------------------------------------------------------------------------- workspaces


def account_workspaces(session: Session) -> list[WorkspaceSummary]:
    """The workspaces this session's account holds an active membership in. Account mode."""
    rows = _execute(
        session,
        text(
            "SELECT workspace_id, tenant_id, slug, name, role, membership_id, joined_at "
            f"FROM {SCHEMA}.account_workspaces()"
        ),
    ).all()
    return [
        WorkspaceSummary(
            workspace_id=row.workspace_id,
            tenant_id=row.tenant_id,
            slug=row.slug,
            name=row.name,
            role=row.role,
            membership_id=row.membership_id,
            joined_at=row.joined_at,
        )
        for row in rows
    ]


def create_workspace(session: Session, *, slug: str, name: str, idempotency_key: str | None = None) -> CreatedWorkspace:
    """Create a workspace, its tenant and the creator's owner membership. Account mode, CSRF-verified.

    After this call the transaction holds the new tenant's context; commit and start a new
    transaction for anything else.
    """
    _require_text(slug, what="workspace slug", maximum=62)
    _require_text(name, what="workspace name", maximum=200)
    row = _execute(
        session,
        text(
            "SELECT workspace_id, tenant_id, membership_id, event_id, record_id, replayed "
            f"FROM {SCHEMA}.create_workspace(:slug, :name, :key)"
        ),
        {"slug": slug, "name": name, "key": _key(idempotency_key)},
    ).one()
    return CreatedWorkspace(
        workspace_id=row.workspace_id,
        tenant_id=row.tenant_id,
        membership_id=row.membership_id,
        event_id=row.event_id,
        record_id=row.record_id,
        replayed=bool(row.replayed),
    )


def bind_session_workspace(session: Session, workspace_id: uuid.UUID) -> WorkspaceBinding:
    """Select a workspace for this session. Account mode, CSRF-verified.

    Refused, with the neutral message, unless the account holds an active membership there.
    The transaction then holds that tenant's context, in which the binding is audited.
    """
    _require_uuid(workspace_id, what="workspace id")
    row = _execute(
        session,
        text(
            "SELECT workspace_id, tenant_id, membership_id, role "
            f"FROM {SCHEMA}.bind_session_workspace(:workspace_id)"
        ),
        {"workspace_id": workspace_id},
    ).one()
    return WorkspaceBinding(
        workspace_id=row.workspace_id, tenant_id=row.tenant_id, membership_id=row.membership_id, role=row.role
    )


def unbind_session_workspace(session: Session) -> bool:
    return bool(_execute(session, text(f"SELECT {SCHEMA}.unbind_session_workspace()")).scalar_one())


def rename_workspace(session: Session, *, name: str, idempotency_key: str | None = None) -> MembershipChange:
    """Rename the bound workspace. Workspace mode, CSRF-verified, ``workspace:write``."""
    _require_text(name, what="workspace name", maximum=200)
    row = _execute(
        session,
        text(f"SELECT workspace_id, name, event_id, record_id, replayed FROM {SCHEMA}.rename_workspace(:name, :key)"),
        {"name": name, "key": _key(idempotency_key)},
    ).one()
    return MembershipChange(
        membership_id=row.workspace_id, role=None, event_id=row.event_id, record_id=row.record_id, replayed=bool(row.replayed)
    )


# --------------------------------------------------------------------------- memberships


def workspace_memberships(session: Session) -> list[MembershipSummary]:
    """The active members of the bound workspace. Workspace mode, ``membership:read``."""
    rows = _execute(
        session,
        text(f"SELECT membership_id, account_id, email, role, created_at FROM {SCHEMA}.workspace_memberships()"),
    ).all()
    return [
        MembershipSummary(
            membership_id=row.membership_id,
            account_id=row.account_id,
            email=row.email,
            role=row.role,
            created_at=row.created_at,
        )
        for row in rows
    ]


def remove_membership(session: Session, membership_id: uuid.UUID, *, idempotency_key: str | None = None) -> MembershipChange:
    """Revoke a membership of the bound workspace. Workspace mode, CSRF-verified, ``membership:manage``.

    Refused neutrally for a membership that is absent, another workspace's or already
    revoked; refused by name for an owner membership when the caller is not an owner, and
    for the last active owner.
    """
    _require_uuid(membership_id, what="membership id")
    row = _execute(
        session,
        text(
            "SELECT membership_id, event_id, record_id, replayed "
            f"FROM {SCHEMA}.remove_membership(:membership_id, :key)"
        ),
        {"membership_id": membership_id, "key": _key(idempotency_key)},
    ).one()
    return MembershipChange(
        membership_id=row.membership_id, role=None, event_id=row.event_id, record_id=row.record_id, replayed=bool(row.replayed)
    )


def change_membership_role(
    session: Session, membership_id: uuid.UUID, role: str | MembershipRole, *, idempotency_key: str | None = None
) -> MembershipChange:
    _require_uuid(membership_id, what="membership id")
    row = _execute(
        session,
        text(
            "SELECT membership_id, role, event_id, record_id, replayed "
            f"FROM {SCHEMA}.change_membership_role(:membership_id, :role, :key)"
        ),
        {"membership_id": membership_id, "role": _require_role(role), "key": _key(idempotency_key)},
    ).one()
    return MembershipChange(
        membership_id=row.membership_id,
        role=row.role,
        event_id=row.event_id,
        record_id=row.record_id,
        replayed=bool(row.replayed),
    )


# --------------------------------------------------------------------------- invitations


def create_invitation(
    session: Session,
    *,
    email: str,
    role: str | MembershipRole,
    ttl: timedelta = DEFAULT_INVITATION_TTL,
    idempotency_key: str | None = None,
) -> CreatedInvitation:
    """Invite an address to the bound workspace at a role. Workspace mode, CSRF-verified, ``membership:manage``.

    The secret comes back once, for the email-delivery boundary. A replay returns the
    invitation and no secret.
    """
    if not isinstance(ttl, timedelta) or ttl <= timedelta(0):
        raise IdentityError("the invitation lifetime is a positive timedelta")
    row = _execute(
        session,
        text(
            "SELECT invitation_id, invitation_secret, expires_at, event_id, record_id, replayed "
            f"FROM {SCHEMA}.create_invitation(:email, :role, CAST(:ttl AS interval), :key)"
        ),
        {"email": normalize_email(email), "role": _require_role(role), "ttl": ttl, "key": _key(idempotency_key)},
    ).one()
    return CreatedInvitation(
        invitation_id=row.invitation_id,
        secret=Secret(row.invitation_secret) if row.invitation_secret else None,
        expires_at=row.expires_at,
        event_id=row.event_id,
        record_id=row.record_id,
        replayed=bool(row.replayed),
    )


def revoke_invitation(session: Session, invitation_id: uuid.UUID, *, idempotency_key: str | None = None) -> Revocation:
    _require_uuid(invitation_id, what="invitation id")
    row = _execute(
        session,
        text(f"SELECT revoked, event_id, record_id, replayed FROM {SCHEMA}.revoke_invitation(:invitation_id, :key)"),
        {"invitation_id": invitation_id, "key": _key(idempotency_key)},
    ).one()
    return Revocation(revoked=bool(row.revoked), event_id=row.event_id, record_id=row.record_id, replayed=bool(row.replayed))


def workspace_invitations(session: Session) -> list[InvitationSummary]:
    rows = _execute(
        session,
        text(
            "SELECT invitation_id, email, role, created_at, expires_at, status "
            f"FROM {SCHEMA}.workspace_invitations()"
        ),
    ).all()
    return [
        InvitationSummary(
            invitation_id=row.invitation_id,
            email=row.email,
            role=row.role,
            created_at=row.created_at,
            expires_at=row.expires_at,
            status=row.status,
        )
        for row in rows
    ]


def accept_invitation(session: Session, secret: Secret | str, *, idempotency_key: str | None = None) -> AcceptedInvitation:
    """Accept an invitation addressed to this session's verified account. Account mode, CSRF-verified.

    After this call the transaction holds the invitation's tenant context as the new
    member; the session itself stays account-level until it selects the workspace.
    """
    if not is_well_formed_identity_secret(secret, "invitation"):
        # Refused without a database round trip, with the same message the database would
        # give: a malformed secret is not one anybody issued.
        from .accounts import IDENTITY_REFUSED_MESSAGE, IdentityRefused

        raise IdentityRefused(IDENTITY_REFUSED_MESSAGE)
    value = _require_secret(secret, "invitation")
    row = _execute(
        session,
        text(
            "SELECT workspace_id, tenant_id, membership_id, role, event_id, record_id, replayed "
            f"FROM {SCHEMA}.accept_invitation(:secret, :key)"
        ),
        {"secret": value, "key": _key(idempotency_key)},
        scrub=(value,),
    ).one()
    return AcceptedInvitation(
        workspace_id=row.workspace_id,
        tenant_id=row.tenant_id,
        membership_id=row.membership_id,
        role=row.role,
        event_id=row.event_id,
        record_id=row.record_id,
        replayed=bool(row.replayed),
    )
