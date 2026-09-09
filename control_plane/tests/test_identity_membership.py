"""Workspaces, memberships and invitations -- Milestone 3.1's membership-bound identity, against PostgreSQL 16.

The four ``AUTH-MEMBERSHIP-BOUND-IDENTITY`` completion cases live here and in
``test_identity_issuance.py``; each is named in its docstring. Every test runs as the
restricted application role and fails closed.
"""

from __future__ import annotations

import uuid

import pytest
from psycopg.errors import InsufficientPrivilege
from sqlalchemy import func, select, text
from sqlalchemy.exc import ProgrammingError

from firmbatch.control_plane.db import accounts, membership
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.audit import audit_events
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.idempotency import IdempotencyConflict, outbox_events
from firmbatch.control_plane.db.models import IdempotencyRecord, OutboxEvent, Tenant, Workspace
from firmbatch.control_plane.security.authorization import AuthorizationError
from firmbatch.control_plane.security.secrets import Secret
from firmbatch.control_plane.tests.conftest import exception_chain
from firmbatch.control_plane.tests.identity_helpers import (
    account_session,
    bind,
    create_workspace,
    everything_stored,
    invite_and_accept,
    key,
    login_session,
    owner_rows,
    owner_with_workspace,
    person,
    workspace_session,
)


# --------------------------------------------------------------------------- workspaces


def test_the_first_workspace_creates_tenant_workspace_and_owner_membership_atomically(application_engine, owner_engine):
    who = person(application_engine)
    created = create_workspace(application_engine, who, slug="first")
    assert not created.replayed
    # The tenant and the workspace are policed rows: read them the way the product does,
    # through the new owner's own context. The protected rows are read as the schema owner.
    bind(application_engine, who, created.workspace_id)
    with workspace_session(application_engine, who, csrf=False) as (session, _):
        tenant = session.get(Tenant, created.tenant_id)
        workspace = session.get(Workspace, created.workspace_id)
        assert tenant is not None and tenant.slug.startswith("ws-")  # generated, never the customer's slug
        assert workspace is not None and workspace.tenant_id == created.tenant_id and workspace.slug == "first"
    (member,) = owner_rows(owner_engine, "memberships", id=created.membership_id)
    assert member["role"] == "owner" and member["account_id"] == who.account_id
    assert member["workspace_id"] == created.workspace_id and member["tenant_id"] == created.tenant_id
    (directory,) = owner_rows(owner_engine, "workspace_directory", id=created.workspace_id)
    assert directory["name"] == "Workspace first"


def test_creating_a_workspace_writes_one_claim_one_linked_event_and_an_audit_row(application_engine, owner_engine):
    who = person(application_engine)
    created = create_workspace(application_engine, who, idempotency_key=key("ws"))
    bind(application_engine, who, created.workspace_id)
    with workspace_session(application_engine, who) as (session, _):
        events = outbox_events(session)
        assert [event.id for event in events] == [created.event_id]
        assert events[0].event_type == "workspace.created"
        assert events[0].idempotency_record_id == created.record_id
        record = session.get(IdempotencyRecord, created.record_id)
        assert record is not None and record.operation == "workspace.create"
        trail = [event for event in audit_events(session) if event.action == "workspace.created"]
        assert len(trail) == 1
        assert trail[0].actor_kind == "session"
        assert trail[0].actor_principal_id == who.account_id
        assert trail[0].actor_binding_id is None


def test_a_duplicate_creation_request_produces_one_workspace_and_replays(application_engine, owner_engine):
    who = person(application_engine)
    k = key("dup")
    first = create_workspace(application_engine, who, slug="dup", idempotency_key=k)
    second = create_workspace(application_engine, who, slug="dup", idempotency_key=k)
    assert second.replayed and not first.replayed
    assert (second.workspace_id, second.tenant_id, second.membership_id, second.event_id) == (
        first.workspace_id, first.tenant_id, first.membership_id, first.event_id
    )
    with account_session(application_engine, who, csrf=False) as (session, _):
        assert [row.slug for row in membership.account_workspaces(session)] == ["dup"]
    assert len(owner_rows(owner_engine, "memberships", account_id=who.account_id)) == 1
    with pytest.raises(IdempotencyConflict):
        create_workspace(application_engine, who, slug="different", idempotency_key=k)


def test_a_workspace_without_a_key_still_writes_its_event(application_engine):
    who = person(application_engine)
    created = create_workspace(application_engine, who)
    assert created.record_id is None and created.event_id is not None


def test_an_unverified_account_cannot_create_a_workspace(application_engine, authenticator_engine):
    email = f"pending-{uuid.uuid4().hex[:8]}@example.com"
    with db_engine.transaction(authenticator_engine) as session:
        accounts.signup(session, email=email, password=Secret("a password long enough"))
    # It cannot even sign in, so the refusal is at the session; asserted through the
    # database rule as well by verifying, signing in, then un-verifying by hand is not a
    # supported route -- so the assertion is the one the boundary makes. Signup, login and
    # session opening are all the authenticator role's, so they run on that engine.
    with pytest.raises(accounts.IdentityRefused):
        with db_engine.transaction(authenticator_engine) as session:
            accounts.login(session, email=email, password=Secret("a password long enough"))
            accounts.open_session(session)


def test_a_workspace_mutation_requires_the_csrf_verified_bind(application_engine):
    who = person(application_engine)
    with pytest.raises(accounts.SessionContextError):
        with account_session(application_engine, who, csrf=False) as (session, _):
            membership.create_workspace(session, slug="nocsrf", name="No CSRF")


def test_account_workspaces_lists_only_active_memberships(application_engine):
    who = person(application_engine)
    a = create_workspace(application_engine, who, slug="alpha")
    b = create_workspace(application_engine, who, slug="beta")
    with account_session(application_engine, who, csrf=False) as (session, _):
        listed = membership.account_workspaces(session)
    assert [(row.workspace_id, row.slug, row.role) for row in listed] == [
        (a.workspace_id, "alpha", "owner"), (b.workspace_id, "beta", "owner")
    ]


def test_rename_changes_the_workspace_and_the_directory_and_is_idempotent(application_engine, owner_engine):
    who, created = owner_with_workspace(application_engine)
    k = key("rename")
    with workspace_session(application_engine, who) as (session, _):
        first = membership.rename_workspace(session, name="Renamed", idempotency_key=k)
    with workspace_session(application_engine, who) as (session, _):
        second = membership.rename_workspace(session, name="Renamed", idempotency_key=k)
    assert not first.replayed and second.replayed and second.event_id == first.event_id
    with workspace_session(application_engine, who, csrf=False) as (session, _):
        assert session.get(Workspace, created.workspace_id).name == "Renamed"
    (directory,) = owner_rows(owner_engine, "workspace_directory", id=created.workspace_id)
    assert directory["name"] == "Renamed"
    with account_session(application_engine, who, csrf=False) as (session, _):
        assert membership.account_workspaces(session)[0].name == "Renamed"


def test_a_viewer_cannot_rename(application_engine):
    owner, created = owner_with_workspace(application_engine)
    viewer = person(application_engine, "viewer")
    invite_and_accept(application_engine, owner, viewer, role="viewer")
    bind(application_engine, viewer, created.workspace_id)
    with pytest.raises(AuthorizationError):
        with workspace_session(application_engine, viewer) as (session, _):
            membership.rename_workspace(session, name="Nope")


# --------------------------------------------------------------------------- binding (gate case 1)


def test_gate_case_1_a_non_member_keeps_its_account_session_and_cannot_bind_the_workspace(application_engine):
    """AUTH-MEMBERSHIP-BOUND-IDENTITY case 1.

    A verified account with no membership in the workspace keeps its account-level
    session, can create its own first workspace, and cannot bind to the other workspace
    -- and the refusal is the same as for a workspace that does not exist.
    """
    owner, theirs = owner_with_workspace(application_engine, "theirs")
    stranger = person(application_engine, "stranger")
    # The account-level session works.
    with account_session(application_engine, stranger, csrf=False) as (session, context):
        assert context.account_id == stranger.account_id and context.workspace_id is None
        assert membership.account_workspaces(session) == []
    # The unauthorized workspace cannot be bound, and the refusal is the absent-id refusal.
    messages = set()
    for target in (theirs.workspace_id, uuid.uuid4()):
        with pytest.raises(accounts.IdentityRefused) as exc:
            bind(application_engine, stranger, target)
        messages.add(str(exc.value))
    assert len(messages) == 1
    # Workspace mode is refused on an unbound session, so no tenant context can exist.
    with pytest.raises(accounts.IdentityRefused):
        with workspace_session(application_engine, stranger):
            pass
    # Its own first workspace is fine, and binding that one works.
    mine = create_workspace(application_engine, stranger, slug="mine")
    binding = bind(application_engine, stranger, mine.workspace_id)
    assert binding.role == "owner" and binding.tenant_id == mine.tenant_id
    with workspace_session(application_engine, stranger, csrf=False) as (session, context):
        assert db_engine.current_tenant_context(session) == mine.tenant_id
        assert session.scalars(select(Workspace)).one().id == mine.workspace_id
        # And nothing of the other tenant is visible.
        assert session.get(Workspace, theirs.workspace_id) is None
        assert session.get(Tenant, theirs.tenant_id) is None


def test_a_bound_session_carries_its_role_permissions_and_no_more(application_engine):
    who, created = owner_with_workspace(application_engine)
    with workspace_session(application_engine, who, csrf=False) as (session, context):
        ctx = session.execute(text(f"SELECT actor_kind, scopes, binding_id, principal_id FROM {SCHEMA}.auth_context()")).one()
        assert ctx.actor_kind == "session"
        assert ctx.binding_id is None and ctx.principal_id == who.account_id
        assert set(ctx.scopes) == {
            "audit:read", "credential:issue", "membership:manage", "membership:read",
            "mutation:execute", "tenant:read", "workspace:read", "workspace:write",
        }
        assert "credential:manage" not in ctx.scopes
        assert "tenant:provision" not in ctx.scopes
        assert context.role == "owner"


def test_a_session_context_cannot_call_the_untied_credential_minter(application_engine):
    """No role grants credential:manage, so the Milestone 2.3 minter refuses every session."""
    from firmbatch.control_plane.db import auth

    who, _ = owner_with_workspace(application_engine)
    with pytest.raises(AuthorizationError):
        with workspace_session(application_engine, who) as (session, _):
            auth.register_auth_binding(session, principal_id=uuid.uuid4(), scopes=["workspace:read"])
    with pytest.raises(ProgrammingError) as exc:
        with workspace_session(application_engine, who) as (session, _):
            session.execute(
                text(f"SELECT * FROM {SCHEMA}.register_auth_binding(:p, ARRAY['workspace:read']::text[], NULL)"),
                {"p": uuid.uuid4()},
            )
    assert isinstance(exc.value.orig, InsufficientPrivilege)
    assert "credential:manage" in str(exc.value.orig)


def test_binding_and_unbinding_are_audited_in_the_workspace_tenant(application_engine):
    who, created = owner_with_workspace(application_engine)
    with account_session(application_engine, who) as (session, _):
        assert membership.unbind_session_workspace(session) is True
    with pytest.raises(accounts.IdentityRefused):
        with workspace_session(application_engine, who):
            pass
    bind(application_engine, who, created.workspace_id)
    with workspace_session(application_engine, who, csrf=False) as (session, _):
        bound = [event for event in audit_events(session) if event.action == "session.bound"]
        assert len(bound) == 2
        assert all(event.resource_id == who.session_id for event in bound)


def test_two_unrelated_tenants_cannot_observe_or_affect_one_another(application_engine):
    alice, a = owner_with_workspace(application_engine, "alice")
    bob, b = owner_with_workspace(application_engine, "bob")
    with workspace_session(application_engine, alice) as (session, _):
        assert session.scalars(select(Workspace)).all() and session.get(Workspace, b.workspace_id) is None
        assert membership.workspace_memberships(session)[0].account_id == alice.account_id
    # Bob's membership is not removable, re-roled, or even acknowledged from Alice's tenant.
    with pytest.raises(accounts.IdentityRefused):
        with workspace_session(application_engine, alice) as (session, _):
            membership.remove_membership(session, b.membership_id)
    with pytest.raises(accounts.IdentityRefused):
        with workspace_session(application_engine, bob) as (session, _):
            membership.change_membership_role(session, a.membership_id, "viewer")
    with workspace_session(application_engine, bob) as (session, _):
        assert [row.membership_id for row in membership.workspace_memberships(session)] == [b.membership_id]


# --------------------------------------------------------------------------- invitations (gate case 3)


def test_an_invitation_creates_a_membership_for_its_recipient_and_only_once(application_engine, owner_engine):
    owner, created = owner_with_workspace(application_engine)
    invitee = person(application_engine, "invitee")
    with workspace_session(application_engine, owner) as (session, _):
        invitation = membership.create_invitation(session, email=invitee.email, role="member", idempotency_key=key("i"))
    assert invitation.secret is not None and invitation.secret.reveal().startswith("fbi_")
    assert invitation.secret.reveal() not in everything_stored(owner_engine)
    with account_session(application_engine, invitee) as (session, _):
        accepted = membership.accept_invitation(session, invitation.secret)
    assert accepted.workspace_id == created.workspace_id and accepted.role == "member"
    assert accepted.tenant_id == created.tenant_id
    # Reuse fails closed.
    with pytest.raises(accounts.IdentityRefused):
        with account_session(application_engine, invitee) as (session, _):
            membership.accept_invitation(session, invitation.secret)
    binding = bind(application_engine, invitee, created.workspace_id)
    assert binding.role == "member"
    with workspace_session(application_engine, owner, csrf=False) as (session, _):
        assert {row.role for row in membership.workspace_memberships(session)} == {"owner", "member"}
        assert [row.status for row in membership.workspace_invitations(session)] == ["accepted"]


def test_gate_case_3_an_invitation_accepted_for_one_tenant_grants_nothing_in_another(application_engine):
    """AUTH-MEMBERSHIP-BOUND-IDENTITY case 3."""
    alice, a = owner_with_workspace(application_engine, "alice")
    bob, b = owner_with_workspace(application_engine, "bob")
    carol = person(application_engine, "carol")
    invite_and_accept(application_engine, alice, carol, role="admin")
    # Carol may bind Alice's workspace and not Bob's; Bob's tenant is untouched.
    assert bind(application_engine, carol, a.workspace_id).role == "admin"
    with pytest.raises(accounts.IdentityRefused):
        bind(application_engine, carol, b.workspace_id)
    with workspace_session(application_engine, carol, csrf=False) as (session, _):
        assert db_engine.current_tenant_context(session) == a.tenant_id
        assert session.get(Workspace, b.workspace_id) is None
        assert {row.account_id for row in membership.workspace_memberships(session)} == {alice.account_id, carol.account_id}
    with workspace_session(application_engine, bob, csrf=False) as (session, _):
        assert [row.account_id for row in membership.workspace_memberships(session)] == [bob.account_id]
        assert [event for event in outbox_events(session) if event.event_type == "membership.created"] == []


def test_wrong_recipient_expired_revoked_reused_and_cross_tenant_invitations_fail_closed(application_engine, owner_engine):
    owner, created = owner_with_workspace(application_engine)
    intended = person(application_engine, "intended")
    other = person(application_engine, "other")
    with workspace_session(application_engine, owner) as (session, _):
        for_intended = membership.create_invitation(session, email=intended.email, role="member")
        to_revoke = membership.create_invitation(session, email=other.email, role="viewer")
        to_expire = membership.create_invitation(session, email=f"third-{uuid.uuid4().hex[:6]}@example.com", role="viewer")
    # Wrong recipient: the secret is valid, the account is not the one it names.
    with pytest.raises(accounts.IdentityRefused) as wrong:
        with account_session(application_engine, other) as (session, _):
            membership.accept_invitation(session, for_intended.secret)
    # Revoked.
    with workspace_session(application_engine, owner) as (session, _):
        assert membership.revoke_invitation(session, to_revoke.invitation_id).revoked is True
        assert membership.revoke_invitation(session, to_revoke.invitation_id).revoked is False
        assert membership.revoke_invitation(session, uuid.uuid4()).revoked is False
    with pytest.raises(accounts.IdentityRefused) as revoked:
        with account_session(application_engine, other) as (session, _):
            membership.accept_invitation(session, to_revoke.secret)
    # Expired, by moving the clock on the row.
    with owner_engine.connect() as connection:
        connection.execute(
            text(
                f"UPDATE {SCHEMA}.workspace_invitations SET created_at = now() - interval '1 hour', "
                "expires_at = now() - interval '59 minutes' WHERE id = :i"
            ),
            {"i": to_expire.invitation_id},
        )
        connection.commit()
    expired_recipient = person(application_engine, "third")
    with pytest.raises(accounts.IdentityRefused) as expired:
        with account_session(application_engine, expired_recipient) as (session, _):
            membership.accept_invitation(session, to_expire.secret)
    # Unknown and malformed.
    with pytest.raises(accounts.IdentityRefused) as unknown:
        with account_session(application_engine, intended) as (session, _):
            membership.accept_invitation(session, Secret("fbi_" + "C" * 43))
    with pytest.raises(accounts.IdentityRefused) as malformed:
        with account_session(application_engine, intended) as (session, _):
            membership.accept_invitation(session, Secret("fbk_" + "C" * 43))
    assert len({str(e.value) for e in (wrong, revoked, expired, unknown, malformed)}) == 1
    for e in (wrong, revoked, expired, unknown, malformed):
        assert for_intended.secret.reveal() not in exception_chain(e.value)
    # And the intended recipient, holding the right secret, is still fine.
    with account_session(application_engine, intended) as (session, _):
        assert membership.accept_invitation(session, for_intended.secret).role == "member"


def test_invitation_rules_are_named_when_they_are_safe_to_name(application_engine):
    owner, created = owner_with_workspace(application_engine)
    admin = person(application_engine, "admin")
    invite_and_accept(application_engine, owner, admin, role="admin")
    bind(application_engine, admin, created.workspace_id)
    # An admin may not invite at the owner role.
    with pytest.raises(AuthorizationError):
        with workspace_session(application_engine, admin) as (session, _):
            membership.create_invitation(session, email="x@example.com", role="owner")
    # An existing member is a conflict.
    with pytest.raises(accounts.IdentityConflict):
        with workspace_session(application_engine, admin) as (session, _):
            membership.create_invitation(session, email=owner.email, role="member")
    with workspace_session(application_engine, admin) as (session, _):
        first = membership.create_invitation(session, email="pending@example.com", role="member")
    assert first.invitation_id is not None
    # A second pending invitation to the same address is a conflict, however it is spelled.
    with pytest.raises(accounts.IdentityConflict):
        with workspace_session(application_engine, admin) as (session, _):
            membership.create_invitation(session, email="Pending@Example.com ", role="viewer")
    member = person(application_engine, "member")
    invite_and_accept(application_engine, owner, member, role="member")
    bind(application_engine, member, created.workspace_id)
    with pytest.raises(AuthorizationError):
        with workspace_session(application_engine, member) as (session, _):
            membership.create_invitation(session, email="y@example.com", role="viewer")
    with pytest.raises(AuthorizationError):
        with workspace_session(application_engine, member, csrf=False) as (session, _):
            membership.workspace_invitations(session)


def test_an_invitation_replay_returns_no_secret(application_engine):
    owner, _ = owner_with_workspace(application_engine)
    k = key("inv")
    with workspace_session(application_engine, owner) as (session, _):
        first = membership.create_invitation(session, email="replay@example.com", role="member", idempotency_key=k)
    with workspace_session(application_engine, owner) as (session, _):
        second = membership.create_invitation(session, email="replay@example.com", role="member", idempotency_key=k)
    assert second.replayed and second.secret is None and second.invitation_id == first.invitation_id
    assert second.event_id == first.event_id


# --------------------------------------------------------------------------- removal (gate case 2)


def test_gate_case_2_revoking_a_membership_stops_the_identity_acting_in_the_workspace(application_engine, owner_engine):
    """AUTH-MEMBERSHIP-BOUND-IDENTITY case 2, the session half.

    The member is bound and working; the owner revokes the membership; the member's very
    next bind observes it -- the session survives as an account-level session, and the
    workspace is not reachable through it by any route.
    """
    owner, created = owner_with_workspace(application_engine)
    member = person(application_engine, "member")
    accepted = invite_and_accept(application_engine, owner, member, role="member")
    bind(application_engine, member, created.workspace_id)
    with workspace_session(application_engine, member, csrf=False) as (session, context):
        assert context.membership_id == accepted.membership_id
        assert db_engine.current_tenant_context(session) == created.tenant_id
    with workspace_session(application_engine, owner) as (session, _):
        result = membership.remove_membership(session, accepted.membership_id, idempotency_key=key("rm"))
        assert not result.replayed
    (row,) = owner_rows(owner_engine, "memberships", id=accepted.membership_id)
    assert row["revoked_at"] is not None and row["revoked_by_account_id"] == owner.account_id
    # The session's binding was dropped in the revoking statement sequence.
    (session_row,) = owner_rows(owner_engine, "browser_sessions", id=member.session_id)
    assert session_row["workspace_id"] is None and session_row["membership_id"] is None
    with pytest.raises(accounts.IdentityRefused):
        with workspace_session(application_engine, member, csrf=False):
            pass
    with account_session(application_engine, member, csrf=False) as (session, context):
        assert context.account_id == member.account_id and context.workspace_id is None
        assert membership.account_workspaces(session) == []
    with pytest.raises(accounts.IdentityRefused):
        bind(application_engine, member, created.workspace_id)
    # The owner is unaffected, and the removal is in the trail.
    with workspace_session(application_engine, owner, csrf=False) as (session, _):
        assert [row.account_id for row in membership.workspace_memberships(session)] == [owner.account_id]
        assert any(event.action == "membership.revoked" for event in audit_events(session))


def test_a_stale_binding_on_a_session_row_is_not_honoured(application_engine, owner_engine):
    """Belt to the cascade's braces: even if the session row still named the membership,
    the bind re-derives it and refuses."""
    owner, created = owner_with_workspace(application_engine)
    member = person(application_engine, "member")
    accepted = invite_and_accept(application_engine, owner, member, role="member")
    bind(application_engine, member, created.workspace_id)
    # Revoke by hand as the owner -- the trigger still runs and unbinds; re-bind the row by
    # hand afterwards to simulate a stale cache, then watch the bind refuse it anyway.
    with owner_engine.connect() as connection:
        connection.execute(
            text(f"UPDATE {SCHEMA}.memberships SET revoked_at = now() WHERE id = :m"), {"m": accepted.membership_id}
        )
        connection.commit()
    # A revoked membership cannot be pointed at by a session row: the FK is satisfied but
    # the bind rechecks revoked_at. Restore the pointer by hand to prove the recheck.
    with owner_engine.connect() as connection:
        connection.execute(
            text(
                f"UPDATE {SCHEMA}.browser_sessions SET workspace_id = :w, tenant_id = :t, membership_id = :m, "
                "bound_at = now() WHERE id = :s"
            ),
            {"w": created.workspace_id, "t": created.tenant_id, "m": accepted.membership_id, "s": member.session_id},
        )
        connection.commit()
    with pytest.raises(accounts.IdentityRefused):
        with workspace_session(application_engine, member, csrf=False):
            pass
    # The refusal rolled its transaction back, pointer and all; an account-mode bind of the
    # same session makes the same recheck, keeps no workspace, and its unbinding commits.
    with account_session(application_engine, member, csrf=False) as (session, context):
        assert context.workspace_id is None and context.membership_id is None
    (row,) = owner_rows(owner_engine, "browser_sessions", id=member.session_id)
    assert row["workspace_id"] is None and row["membership_id"] is None


def test_the_last_owner_cannot_be_removed_or_demoted_and_only_owners_touch_owners(application_engine):
    owner, created = owner_with_workspace(application_engine)
    admin = person(application_engine, "admin")
    admin_membership = invite_and_accept(application_engine, owner, admin, role="admin")
    bind(application_engine, admin, created.workspace_id)
    with pytest.raises(accounts.IdentityConflict):
        with workspace_session(application_engine, owner) as (session, _):
            membership.remove_membership(session, created.membership_id)
    with pytest.raises(accounts.IdentityConflict):
        with workspace_session(application_engine, owner) as (session, _):
            membership.change_membership_role(session, created.membership_id, "admin")
    with pytest.raises(AuthorizationError):
        with workspace_session(application_engine, admin) as (session, _):
            membership.remove_membership(session, created.membership_id)
    with pytest.raises(AuthorizationError):
        with workspace_session(application_engine, admin) as (session, _):
            membership.change_membership_role(session, created.membership_id, "member")
    with pytest.raises(AuthorizationError):
        with workspace_session(application_engine, admin) as (session, _):
            membership.change_membership_role(session, admin_membership.membership_id, "owner")
    # An owner promotes the admin; then the original owner may step down.
    with workspace_session(application_engine, owner) as (session, _):
        promoted = membership.change_membership_role(session, admin_membership.membership_id, "owner", idempotency_key=key("p"))
        assert promoted.role == "owner"
        demoted = membership.change_membership_role(session, created.membership_id, "member")
        assert demoted.role == "member"
    with workspace_session(application_engine, owner, csrf=False) as (session, context):
        assert context.role == "member"
        with pytest.raises(AuthorizationError):
            membership.workspace_invitations(session)


def test_a_demotion_revokes_the_credentials_the_membership_issued_and_a_promotion_keeps_them(application_engine, owner_engine):
    from firmbatch.control_plane.db import auth
    from firmbatch.control_plane.tests.identity_helpers import issue_credential

    owner, created = owner_with_workspace(application_engine)
    admin = person(application_engine, "admin")
    admin_membership = invite_and_accept(application_engine, owner, admin, role="admin")
    bind(application_engine, admin, created.workspace_id)
    issued = issue_credential(application_engine, admin, scopes=("workspace:read", "audit:read"))
    with workspace_session(application_engine, owner) as (session, _):
        membership.change_membership_role(session, admin_membership.membership_id, "owner")
    with auth.authenticated_transaction(application_engine, issued.credential) as session:
        assert auth.current_authenticated_context(session).tenant_id == created.tenant_id
    with workspace_session(application_engine, owner) as (session, _):
        membership.change_membership_role(session, admin_membership.membership_id, "viewer")
    with pytest.raises(auth.AuthenticationError):
        with auth.authenticated_transaction(application_engine, issued.credential):
            pass
    (row,) = owner_rows(owner_engine, "auth_bindings", id=issued.binding_id)
    assert row["revoked_at"] is not None


def test_a_revoked_membership_is_final_even_for_the_schema_owner(owner_engine, application_engine):
    owner, _ = owner_with_workspace(application_engine)
    member = person(application_engine, "member")
    accepted = invite_and_accept(application_engine, owner, member, role="member")
    with workspace_session(application_engine, owner) as (session, _):
        membership.remove_membership(session, accepted.membership_id)
    with owner_engine.connect() as connection:
        with pytest.raises(Exception) as exc:
            connection.execute(text(f"UPDATE {SCHEMA}.memberships SET revoked_at = NULL WHERE id = :m"), {"m": accepted.membership_id})
        assert "cannot be reinstated" in str(exc.value)
        connection.rollback()
        with pytest.raises(Exception) as exc:
            connection.execute(
                text(f"UPDATE {SCHEMA}.memberships SET account_id = gen_random_uuid() WHERE id = :m"),
                {"m": accepted.membership_id},
            )
        assert "immutable" in str(exc.value)
        connection.rollback()


def test_removed_members_can_be_invited_again_as_a_new_membership(application_engine):
    owner, created = owner_with_workspace(application_engine)
    member = person(application_engine, "member")
    first = invite_and_accept(application_engine, owner, member, role="member")
    with workspace_session(application_engine, owner) as (session, _):
        membership.remove_membership(session, first.membership_id)
    second = invite_and_accept(application_engine, owner, member, role="viewer")
    assert second.membership_id != first.membership_id and second.role == "viewer"
    assert bind(application_engine, member, created.workspace_id).membership_id == second.membership_id


def test_hidden_and_absent_membership_identifiers_are_not_oracular(application_engine):
    alice, a = owner_with_workspace(application_engine, "alice")
    bob, b = owner_with_workspace(application_engine, "bob")
    probes = (b.membership_id, uuid.uuid4())
    for function in (
        lambda session, target: membership.remove_membership(session, target),
        lambda session, target: membership.change_membership_role(session, target, "viewer"),
    ):
        messages = set()
        for target in probes:
            with pytest.raises(accounts.IdentityRefused) as exc:
                with workspace_session(application_engine, alice) as (session, _):
                    function(session, target)
            messages.add(str(exc.value))
            assert str(b.membership_id) not in exception_chain(exc.value)
        assert len(messages) == 1
    with workspace_session(application_engine, alice) as (session, _):
        assert membership.revoke_invitation(session, uuid.uuid4()).revoked is False


def test_a_workspace_session_survives_an_unrelated_sessions_revocation(application_engine):
    who, created = owner_with_workspace(application_engine)
    other = login_session(application_engine, who.email)
    with account_session(application_engine, who) as (session, _):
        accounts.revoke_session(session, other.session_id)
    with workspace_session(application_engine, who, csrf=False) as (session, context):
        assert context.workspace_id == created.workspace_id
        assert session.scalar(select(func.count()).select_from(OutboxEvent)) >= 1
