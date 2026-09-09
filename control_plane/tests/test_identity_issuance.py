"""Trusted credential issuance -- Milestone 3.1's bridge from a membership to Milestone 2.3.

``AUTH-MEMBERSHIP-BOUND-IDENTITY`` case 4 lives here, named in its docstring: a session
issues an API credential, the credential authenticates through the unchanged Milestone 2.3
boundary as exactly that membership, and the two credential types never stand in for one
another. The rest of this module is the adversarial edge of the same property: raw SQL
cannot mint, widen, forge or un-revoke; rotation is atomic; duplicate requests produce one
binding; identifiers are not oracles; and no secret reaches a row, an audit entry, an outbox
attribute or an exception chain.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from psycopg.errors import InsufficientPrivilege
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from firmbatch.control_plane.db import accounts, auth, credentials, membership
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.audit import audit_events
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.idempotency import IdempotencyConflict, outbox_events
from firmbatch.control_plane.db.models import Workspace
from firmbatch.control_plane.security.authorization import AuthorizationError
from firmbatch.control_plane.security.permissions import API_ISSUABLE_SCOPES, effective_permissions
from firmbatch.control_plane.security.secrets import Secret
from firmbatch.control_plane.tests.conftest import exception_chain
from firmbatch.control_plane.tests.identity_helpers import (
    bind,
    everything_stored,
    invite_and_accept,
    issue_credential,
    key,
    owner_rows,
    owner_with_workspace,
    person,
    workspace_session,
)


def _fingerprint(secret: Secret) -> str:
    return hashlib.sha256(secret.reveal().encode("utf-8")).hexdigest()


def _refused_raw(engine, who, statement: str, params=None):
    """Run one raw statement in ``who``'s workspace session and return the database's refusal."""
    with pytest.raises(ProgrammingError) as exc:
        with workspace_session(engine, who) as (session, _):
            session.execute(text(statement), params or {})
    assert isinstance(exc.value.orig, InsufficientPrivilege), exc.value.orig
    return exc


# --------------------------------------------------------------------------- gate case 4


def test_gate_case_4_a_session_issues_a_credential_that_authenticates_as_its_membership_and_nothing_else(
    application_engine, owner_engine, principal_a
):
    """AUTH-MEMBERSHIP-BOUND-IDENTITY case 4.

    A workspace-bound session explicitly authorizes an API credential; the credential then
    authenticates through Milestone 2.3's unchanged ``bind_authenticated_context`` as a
    ``credential`` actor whose principal is the issuing account, in the workspace's tenant,
    with exactly the requested scopes. It sees that tenant and no other, and it is recorded
    as issued from the membership -- which an out-of-band credential is not.
    """
    owner, created = owner_with_workspace(application_engine)
    issued = issue_credential(application_engine, owner, scopes=("workspace:read", "audit:read"), label="ci")
    assert issued.credential is not None and not issued.replayed
    assert issued.scopes == ("audit:read", "workspace:read")
    assert issued.credential.reveal().startswith("fbk_")

    with auth.authenticated_transaction(application_engine, issued.credential) as session:
        context = auth.current_authenticated_context(session)
        assert context.actor_kind == "credential"
        assert context.tenant_id == created.tenant_id
        assert context.principal_id == owner.account_id
        assert context.binding_id == issued.binding_id
        assert context.scopes == frozenset({"audit:read", "workspace:read"})
        assert session.get(Workspace, created.workspace_id) is not None
        # The credential holds workspace:read and not the membership permissions.
        assert not context.has_scope("membership:read")
        assert not context.has_scope("credential:issue")
        credentials.record_use(session)
    # Another tenant's credential sees nothing of this one.
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert session.get(Workspace, created.workspace_id) is None

    (row,) = owner_rows(owner_engine, "auth_bindings", id=issued.binding_id)
    assert row["membership_id"] == created.membership_id
    assert row["workspace_id"] == created.workspace_id
    assert row["tenant_id"] == created.tenant_id
    assert row["principal_id"] == owner.account_id
    assert row["label"] == "ci"
    assert row["fingerprint"] == _fingerprint(issued.credential)
    assert row["last_used_at"] is not None
    (out_of_band,) = owner_rows(owner_engine, "auth_bindings", id=principal_a.binding_id)
    assert out_of_band["membership_id"] is None and out_of_band["workspace_id"] is None

    with workspace_session(application_engine, owner, csrf=False) as (session, _):
        listed = credentials.list_credentials(session)
        assert [row.binding_id for row in listed] == [issued.binding_id]
        assert listed[0].membership_id == created.membership_id
        assert listed[0].account_id == owner.account_id and listed[0].email == owner.email
        assert listed[0].last_used_at is not None and listed[0].active
        trail = [event for event in audit_events(session) if event.action == "credential.issued"]
        assert len(trail) == 1 and trail[0].resource_id == issued.binding_id
        assert trail[0].actor_kind == "session" and trail[0].actor_principal_id == owner.account_id


# --------------------------------------------------------------------------- the two credential types


def test_a_session_secret_is_not_a_bearer_credential_and_a_credential_is_not_a_session(application_engine):
    owner, _ = owner_with_workspace(application_engine)
    issued = issue_credential(application_engine, owner)
    # The session secret at the credential boundary: refused, and never as a credential.
    with pytest.raises(auth.AuthenticationError) as exc:
        with auth.authenticated_transaction(application_engine, owner.session_secret):
            pass
    assert owner.session_secret.reveal() not in exception_chain(exc.value)
    # The CSRF secret and an invitation-shaped value, the same way.
    with pytest.raises(auth.AuthenticationError):
        with auth.authenticated_transaction(application_engine, owner.csrf_secret):
            pass
    # The credential at the session boundary: refused before the database is consulted.
    with pytest.raises(accounts.SessionAuthenticationError) as exc:
        with accounts.session_transaction(application_engine, issued.credential):
            pass
    assert "without being sent to the database" in str(exc.value)
    assert issued.credential.reveal() not in exception_chain(exc.value)
    # And the two secrets are unrelated values with unrelated digests.
    assert issued.credential.reveal() != owner.session_secret.reveal()
    assert _fingerprint(issued.credential) != _fingerprint(owner.session_secret)


def test_a_credential_context_cannot_reach_the_identity_plane(application_engine):
    """Nothing converts a credential into a session, a workspace or another credential."""
    owner, created = owner_with_workspace(application_engine)
    issued = issue_credential(application_engine, owner, scopes=tuple(API_ISSUABLE_SCOPES))
    operations = (
        lambda session: accounts.account_profile(session),
        lambda session: accounts.open_session(session),
        lambda session: membership.workspace_memberships(session),
        lambda session: membership.bind_session_workspace(session, created.workspace_id),
        lambda session: membership.create_workspace(session, slug="via-credential", name="No"),
        lambda session: credentials.issue(session, role="owner", scopes=("workspace:read",)),
        lambda session: credentials.rotate(session, issued.binding_id),
        lambda session: credentials.revoke(session, issued.binding_id),
    )
    for operation in operations:
        # A credential context reaches none of these. Most are refused by the session
        # precondition (SessionContextError); open_session, now the authenticator role's
        # alone, is refused one layer earlier still -- the application role the credential
        # authenticated through cannot even execute it (AuthorizationError). Either way,
        # nothing converts a credential into a session.
        with pytest.raises((accounts.SessionContextError, AuthorizationError)) as exc:
            with auth.authenticated_transaction(application_engine, issued.credential) as session:
                operation(session)
        assert issued.credential.reveal() not in exception_chain(exc.value)
    # Every one of those is a refusal of the session precondition or of an authority the
    # application role does not hold -- never a credential that reached the identity plane.
    # The credential carries every issuable scope there is.
    with auth.authenticated_transaction(application_engine, issued.credential) as session:
        assert auth.current_authenticated_context(session).scopes == frozenset(API_ISSUABLE_SCOPES)


def test_a_session_cannot_use_the_untied_minter_or_the_untied_revoker(application_engine):
    owner, _ = owner_with_workspace(application_engine)
    issued = issue_credential(application_engine, owner)
    with pytest.raises(AuthorizationError):
        with workspace_session(application_engine, owner) as (session, _):
            auth.register_auth_binding(session, principal_id=owner.account_id, scopes=["workspace:read"])
    with pytest.raises(AuthorizationError):
        with workspace_session(application_engine, owner) as (session, _):
            auth.revoke_auth_binding(session, issued.binding_id)
    # The credential is untouched by the refused attempt.
    with auth.authenticated_transaction(application_engine, issued.credential):
        pass


# --------------------------------------------------------------------------- scope derivation


def test_issuance_is_bounded_by_the_membership_and_the_issuable_catalogue_in_the_database(application_engine):
    owner, created = owner_with_workspace(application_engine)
    member = person(application_engine, "member")
    viewer = person(application_engine, "viewer")
    invite_and_accept(application_engine, owner, member, role="member")
    invite_and_accept(application_engine, owner, viewer, role="viewer")
    bind(application_engine, member, created.workspace_id)
    bind(application_engine, viewer, created.workspace_id)

    # A viewer holds no credential:issue and issues nothing, through the wrapper or around it.
    with pytest.raises(AuthorizationError) as exc:
        with workspace_session(application_engine, viewer) as (session, context):
            credentials.issue(session, role="owner", scopes=("workspace:read",))
    assert "credential:issue" in str(exc.value)
    exc = _refused_raw(
        application_engine, viewer,
        f"SELECT * FROM {SCHEMA}.issue_api_credential(ARRAY['workspace:read']::text[], NULL, NULL, NULL)",
    )
    assert "credential:issue" in str(exc.value.orig)
    # The Python check names the rule; the database check holds when Python is bypassed.
    with pytest.raises(ValueError):
        with workspace_session(application_engine, member) as (session, context):
            credentials.issue(session, role=context.role, scopes=("audit:read",))
    exc = _refused_raw(
        application_engine, member,
        f"SELECT * FROM {SCHEMA}.issue_api_credential(ARRAY['audit:read']::text[], NULL, NULL, NULL)",
    )
    assert "exceeds what this membership may issue" in str(exc.value.orig)
    assert "audit:read" not in str(exc.value.orig)
    # The two catalogue scopes no credential may carry are refused for every role, the
    # owner included: credential:manage is session-only by design, tenant:provision is
    # nobody's to delegate. The rule is named; the rejected value is not echoed.
    for scope in ("credential:manage", "tenant:provision"):
        exc = _refused_raw(
            application_engine, owner,
            f"SELECT * FROM {SCHEMA}.issue_api_credential(ARRAY[:s]::text[], NULL, NULL, NULL)", {"s": scope},
        )
        primary = str(exc.value.orig).splitlines()[0]
        assert "may not be placed on an API credential" in primary or "exceeds what this membership may issue" in primary
        assert scope not in primary
    # The membership permissions are not Milestone 2.3 scopes at all, so they are refused
    # one step earlier, as values outside the closed catalogue.
    for scope in ("membership:manage", "membership:read", "credential:issue"):
        with pytest.raises(accounts.IdentityError) as exc:
            with workspace_session(application_engine, owner) as (session, _):
                credentials._execute(
                    session,
                    text(f"SELECT * FROM {SCHEMA}.issue_api_credential(ARRAY[:s]::text[], NULL, NULL, NULL)"),
                    {"s": scope},
                )
        assert "not in the catalogue" in str(exc.value) and scope not in str(exc.value)
    # An unknown scope is refused by the function, not by a constraint that would echo it.
    with pytest.raises(accounts.IdentityError) as exc:
        with workspace_session(application_engine, owner) as (session, _):
            credentials._execute(
                session,
                text(f"SELECT * FROM {SCHEMA}.issue_api_credential(ARRAY['not:a-scope']::text[], NULL, NULL, NULL)"),
            )
    assert "not:a-scope" not in exception_chain(exc.value)
    # Duplicates and an empty set are refused; and what every role may issue is exactly
    # its effective permissions intersected with the issuable catalogue.
    with pytest.raises(accounts.IdentityError):
        with workspace_session(application_engine, owner) as (session, _):
            credentials._execute(
                session,
                text(
                    f"SELECT * FROM {SCHEMA}.issue_api_credential("
                    "ARRAY['workspace:read', 'workspace:read']::text[], NULL, NULL, NULL)"
                ),
            )
    for who in (owner, member):
        with workspace_session(application_engine, who) as (session, context):
            issued = credentials.issue(
                session, role=context.role, scopes=set(effective_permissions(context.role)) & set(API_ISSUABLE_SCOPES)
            )
            assert set(issued.scopes) == set(effective_permissions(context.role)) & set(API_ISSUABLE_SCOPES)
            assert "credential:manage" not in issued.scopes


def test_the_membership_is_re_read_at_issuance_not_taken_from_the_session(application_engine, owner_engine):
    """A session whose membership was demoted between bind and issue issues at the new role."""
    owner, created = owner_with_workspace(application_engine)
    admin = person(application_engine, "admin")
    accepted = invite_and_accept(application_engine, owner, admin, role="admin")
    bind(application_engine, admin, created.workspace_id)
    with workspace_session(application_engine, owner) as (session, _):
        membership.change_membership_role(session, accepted.membership_id, "member")
    # The bind re-derives the role, so the Python pre-check sees "member" too; go around it
    # to show the database's own check holding against the session's cached authority.
    exc = _refused_raw(
        application_engine, admin,
        f"SELECT * FROM {SCHEMA}.issue_api_credential(ARRAY['audit:read']::text[], NULL, NULL, NULL)",
    )
    assert "exceeds what this membership may issue" in str(exc.value.orig)


# --------------------------------------------------------------------------- forgery


@pytest.mark.parametrize(
    "statement",
    (
        f"INSERT INTO {SCHEMA}.auth_bindings (tenant_id, principal_id, fingerprint, scopes) "
        "VALUES (gen_random_uuid(), gen_random_uuid(), repeat('a', 64), ARRAY['workspace:read'])",
        f"UPDATE {SCHEMA}.auth_bindings SET scopes = ARRAY['credential:manage']",
        f"UPDATE {SCHEMA}.auth_bindings SET revoked_at = NULL",
        f"UPDATE {SCHEMA}.auth_bindings SET membership_id = NULL",
        f"DELETE FROM {SCHEMA}.auth_bindings",
        f"SELECT fingerprint FROM {SCHEMA}.auth_bindings",
        f"SELECT {SCHEMA}.identity_mint_secret('fbk_')",
        f"SELECT {SCHEMA}.identity_fingerprint('x')",
        f"SELECT {SCHEMA}.identity_context_narrow(ARRAY['credential:manage'])",
        f"SELECT {SCHEMA}.identity_claim('x', NULL, NULL, NULL, 'x', 'x', gen_random_uuid(), NULL)",
        f"SELECT {SCHEMA}.auth_context_begin(NULL, gen_random_uuid(), gen_random_uuid(), 'session', "
        "ARRAY['credential:manage'])",
        f"INSERT INTO {SCHEMA}.memberships (tenant_id, workspace_id, account_id, role) "
        "VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), 'owner')",
        f"UPDATE {SCHEMA}.memberships SET role = 'owner'",
        f"INSERT INTO {SCHEMA}.browser_sessions (account_id, fingerprint, csrf_fingerprint, expires_at) "
        "VALUES (gen_random_uuid(), repeat('a', 64), repeat('b', 64), now() + interval '1 day')",
        f"UPDATE {SCHEMA}.auth_transaction_context SET scopes = ARRAY['credential:manage']",
    ),
)
def test_raw_sql_in_a_workspace_session_cannot_forge_mint_widen_or_unrevoke(application_engine, statement):
    """The strongest session there is -- an owner's, CSRF-verified, workspace-bound -- and
    every direct route to the registry, the identity tables and the context is refused."""
    owner, _ = owner_with_workspace(application_engine)
    _refused_raw(application_engine, owner, statement)


def test_a_scope_widening_is_impossible_even_for_the_owner_of_the_workspace(application_engine):
    """There is no function that adds a scope to an existing binding; rotation copies."""
    owner, _ = owner_with_workspace(application_engine)
    issued = issue_credential(application_engine, owner, scopes=("workspace:read",))
    with workspace_session(application_engine, owner) as (session, _):
        rotated = credentials.rotate(session, issued.binding_id)
    assert rotated.scopes == ("workspace:read",)
    with auth.authenticated_transaction(application_engine, rotated.credential) as session:
        assert auth.current_authenticated_context(session).scopes == frozenset({"workspace:read"})


# --------------------------------------------------------------------------- rotation and revocation


def test_rotation_is_an_atomic_cutover_that_keeps_the_scopes_and_the_label(application_engine, owner_engine):
    owner, created = owner_with_workspace(application_engine)
    issued = issue_credential(application_engine, owner, scopes=("workspace:read", "workspace:write"), label="deploy")
    with workspace_session(application_engine, owner) as (session, _):
        rotated = credentials.rotate(session, issued.binding_id, idempotency_key=key("rot"))
    assert rotated.binding_id != issued.binding_id
    assert rotated.rotated_from_id == issued.binding_id
    assert rotated.scopes == issued.scopes and rotated.credential is not None
    assert rotated.credential.reveal() != issued.credential.reveal()
    # The old secret stopped working in the same transaction the new one started.
    with pytest.raises(auth.AuthenticationError):
        with auth.authenticated_transaction(application_engine, issued.credential):
            pass
    with auth.authenticated_transaction(application_engine, rotated.credential) as session:
        assert auth.current_authenticated_context(session).binding_id == rotated.binding_id
    (old,) = owner_rows(owner_engine, "auth_bindings", id=issued.binding_id)
    (new,) = owner_rows(owner_engine, "auth_bindings", id=rotated.binding_id)
    assert old["revoked_at"] is not None and new["revoked_at"] is None
    assert new["label"] == "deploy" and new["membership_id"] == created.membership_id
    assert new["rotated_from_id"] == issued.binding_id
    # A revoked binding cannot be rotated again, and the history is visible to its member.
    with pytest.raises(accounts.IdentityRefused):
        with workspace_session(application_engine, owner) as (session, _):
            credentials.rotate(session, issued.binding_id)
    with workspace_session(application_engine, owner, csrf=False) as (session, _):
        listed = {row.binding_id: row for row in credentials.list_credentials(session)}
        assert listed[issued.binding_id].active is False and listed[rotated.binding_id].active is True
        assert listed[rotated.binding_id].rotated_from_id == issued.binding_id
        assert [event.action for event in audit_events(session) if event.action.startswith("credential.")] == [
            "credential.issued", "credential.rotated"
        ]


def test_a_manager_may_revoke_any_workspace_credential_and_rotate_none_but_its_own(application_engine):
    owner, created = owner_with_workspace(application_engine)
    admin = person(application_engine, "admin")
    member = person(application_engine, "member")
    invite_and_accept(application_engine, owner, admin, role="admin")
    invite_and_accept(application_engine, owner, member, role="member")
    bind(application_engine, admin, created.workspace_id)
    bind(application_engine, member, created.workspace_id)
    admins = issue_credential(application_engine, admin, scopes=("workspace:read",))
    owners = issue_credential(application_engine, owner, scopes=("workspace:read",))
    # A member sees only its own credentials and revokes nobody else's -- and learns
    # nothing from the answer.
    with workspace_session(application_engine, member) as (session, _):
        assert credentials.list_credentials(session) == []
        assert credentials.revoke(session, owners.binding_id).revoked is False
        assert credentials.revoke(session, uuid.uuid4()).revoked is False
    with auth.authenticated_transaction(application_engine, owners.credential):
        pass
    # An owner may not rotate the admin's credential: the rotated secret would authenticate
    # as the admin.
    with pytest.raises(accounts.IdentityRefused):
        with workspace_session(application_engine, owner) as (session, _):
            credentials.rotate(session, admins.binding_id)
    # But may revoke it, once.
    with workspace_session(application_engine, owner) as (session, _):
        assert {row.binding_id for row in credentials.list_credentials(session)} == {admins.binding_id, owners.binding_id}
        assert credentials.revoke(session, admins.binding_id, idempotency_key=key("rev")).revoked is True
        assert credentials.revoke(session, admins.binding_id).revoked is False
    with pytest.raises(auth.AuthenticationError):
        with auth.authenticated_transaction(application_engine, admins.credential):
            pass
    # Every attempt is in the trail -- the member's two refusals, the owner's revocation
    # and the owner's second, empty one -- and only the one that revoked names a resource.
    with workspace_session(application_engine, owner, csrf=False) as (session, _):
        revoked = [event for event in audit_events(session) if event.action == "credential.revoked"]
        assert [event.outcome for event in revoked] == ["failed", "failed", "succeeded", "failed"]
        assert [event.resource_id for event in revoked] == [None, None, admins.binding_id, None]
        assert [event.actor_principal_id for event in revoked] == [
            member.account_id, member.account_id, owner.account_id, owner.account_id
        ]


def test_removing_a_membership_revokes_every_credential_it_issued(application_engine, owner_engine):
    owner, created = owner_with_workspace(application_engine)
    member = person(application_engine, "member")
    accepted = invite_and_accept(application_engine, owner, member, role="member")
    bind(application_engine, member, created.workspace_id)
    first = issue_credential(application_engine, member)
    second = issue_credential(application_engine, member, scopes=("workspace:write",))
    with workspace_session(application_engine, owner) as (session, _):
        membership.remove_membership(session, accepted.membership_id)
    for issued in (first, second):
        with pytest.raises(auth.AuthenticationError):
            with auth.authenticated_transaction(application_engine, issued.credential):
                pass
        (row,) = owner_rows(owner_engine, "auth_bindings", id=issued.binding_id)
        assert row["revoked_at"] is not None and row["membership_id"] == accepted.membership_id
    # The removed member's session is unbound and cannot rotate its way back in.
    with pytest.raises(accounts.IdentityRefused):
        with workspace_session(application_engine, member) as (session, _):
            credentials.rotate(session, first.binding_id)


# --------------------------------------------------------------------------- idempotency


def test_duplicate_issuance_requests_produce_one_binding_one_claim_and_one_linked_event(
    application_engine, owner_engine
):
    owner, created = owner_with_workspace(application_engine)
    k = key("issue")
    with workspace_session(application_engine, owner) as (session, context):
        first = credentials.issue(session, role=context.role, scopes=("workspace:read",), label="k", idempotency_key=k)
    with workspace_session(application_engine, owner) as (session, context):
        second = credentials.issue(session, role=context.role, scopes=("workspace:read",), label="k", idempotency_key=k)
    assert not first.replayed and second.replayed
    assert second.binding_id == first.binding_id and second.event_id == first.event_id
    assert second.record_id == first.record_id and first.record_id is not None
    # The secret was shown once; a replay says so by returning none.
    assert first.credential is not None and second.credential is None
    assert len(owner_rows(owner_engine, "auth_bindings", membership_id=created.membership_id)) == 1
    with workspace_session(application_engine, owner, csrf=False) as (session, _):
        events = [event for event in outbox_events(session) if event.event_type == "credential.issued"]
        assert [event.id for event in events] == [first.event_id]
        assert events[0].idempotency_record_id == first.record_id
        assert events[0].attributes["membership_id"] == str(created.membership_id)
        assert len([event for event in audit_events(session) if event.action == "credential.issued"]) == 1
    # The same key for a different request is a caller bug, and says so.
    with pytest.raises(IdempotencyConflict):
        with workspace_session(application_engine, owner) as (session, context):
            credentials.issue(session, role=context.role, scopes=("workspace:write",), label="k", idempotency_key=k)
    # A revocation replay returns the original answer and revokes nothing twice.
    with workspace_session(application_engine, owner) as (session, _):
        revoked = credentials.revoke(session, first.binding_id, idempotency_key=key("rv"))
    with workspace_session(application_engine, owner) as (session, _):
        again = credentials.revoke(session, first.binding_id, idempotency_key=key("rv2"))
    assert revoked.revoked is True and again.revoked is False


def test_a_keyed_rotation_replays_without_a_secret_and_rotates_once(application_engine, owner_engine):
    owner, created = owner_with_workspace(application_engine)
    issued = issue_credential(application_engine, owner)
    k = key("rotate")
    with workspace_session(application_engine, owner) as (session, _):
        first = credentials.rotate(session, issued.binding_id, idempotency_key=k)
    with workspace_session(application_engine, owner) as (session, _):
        second = credentials.rotate(session, issued.binding_id, idempotency_key=k)
    assert second.replayed and second.credential is None
    assert second.binding_id == first.binding_id and second.rotated_from_id == issued.binding_id
    assert second.event_id == first.event_id
    active = [row for row in owner_rows(owner_engine, "auth_bindings", membership_id=created.membership_id)
              if row["revoked_at"] is None]
    assert [row["id"] for row in active] == [first.binding_id]


# --------------------------------------------------------------------------- oracles and secrets


def test_credential_identifiers_are_not_oracular_across_tenants(application_engine):
    alice, _ = owner_with_workspace(application_engine, "alice")
    bob, _ = owner_with_workspace(application_engine, "bob")
    bobs = issue_credential(application_engine, bob)
    probes = (bobs.binding_id, uuid.uuid4())
    messages = set()
    for probe in probes:
        with pytest.raises(accounts.IdentityRefused) as exc:
            with workspace_session(application_engine, alice) as (session, _):
                credentials.rotate(session, probe)
        messages.add(str(exc.value))
        assert str(bobs.binding_id) not in exception_chain(exc.value)
    assert len(messages) == 1
    with workspace_session(application_engine, alice) as (session, _):
        assert [credentials.revoke(session, probe).revoked for probe in probes] == [False, False]
        assert credentials.list_credentials(session) == []
    with auth.authenticated_transaction(application_engine, bobs.credential):
        pass


def test_credential_secrets_never_reach_persistence_audit_outbox_or_exception_chains(
    application_engine, owner_engine
):
    owner, _ = owner_with_workspace(application_engine)
    issued = issue_credential(application_engine, owner, scopes=("workspace:read",), label="never stored")
    with workspace_session(application_engine, owner) as (session, _):
        rotated = credentials.rotate(session, issued.binding_id)
    secrets = (issued.credential, rotated.credential, owner.session_secret, owner.csrf_secret)
    stored = everything_stored(owner_engine)
    for secret in secrets:
        assert secret.reveal() not in stored
        assert _fingerprint(secret) in stored  # stored as its digest, and only as its digest
    with workspace_session(application_engine, owner, csrf=False) as (session, _):
        rendered = "\n".join(
            [repr((e.action, e.details, e.resource_id)) for e in audit_events(session)]
            + [repr((e.event_type, e.attributes)) for e in outbox_events(session)]
        )
    for secret in secrets:
        assert secret.reveal() not in rendered
    assert "never stored" in stored
    # A refusal that carries the credential as a parameter does not render it.
    with pytest.raises(auth.AuthenticationError) as exc:
        with auth.authenticated_transaction(application_engine, issued.credential):
            pass
    assert issued.credential.reveal() not in exception_chain(exc.value)
    assert "<redacted>" in repr(issued) and issued.credential.reveal() not in repr(issued)


def test_an_expiry_in_the_past_is_refused_and_a_future_one_is_honoured_by_the_bind(application_engine):
    owner, _ = owner_with_workspace(application_engine)
    with pytest.raises(accounts.IdentityError):
        with workspace_session(application_engine, owner) as (session, context):
            credentials.issue(
                session, role=context.role, scopes=("workspace:read",),
                expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
            )
    soon = datetime.now(timezone.utc) + timedelta(hours=1)
    with workspace_session(application_engine, owner) as (session, context):
        issued = credentials.issue(session, role=context.role, scopes=("workspace:read",), expires_at=soon)
    assert issued.expires_at is not None and abs((issued.expires_at - soon).total_seconds()) < 1
    with auth.authenticated_transaction(application_engine, issued.credential):
        pass


def _expire(owner_engine, binding_id) -> None:
    """Move a binding's expiry into the past, as the schema owner.

    An expiry cannot be moved by any runtime role -- ``auth_bindings`` carries no grant --
    and no function offers it, which is the point. A test that needs an elapsed credential
    therefore reaches the row the way the design says the truth is read: as the owner. The
    creation timestamp moves with it because ``ck_auth_bindings_expiry_after_creation``
    refuses a binding that was born already expired, which is itself worth knowing.
    """
    with owner_engine.connect() as connection:
        connection.execute(
            text(
                f"UPDATE {SCHEMA}.auth_bindings "
                "SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 minute' "
                "WHERE id = :i"
            ),
            {"i": binding_id},
        )
        connection.commit()


def test_an_expired_credential_is_inactive_unauthenticated_and_unrotatable(application_engine, owner_engine):
    """Finding: revoked and expired are one state, and every surface must say so.

    An elapsed credential appears inactive in the listing (the state is computed by
    PostgreSQL, against its own clock, not derived here from ``revoked_at``); it does not
    authenticate; and it is refused rotation with the same neutral refusal a revoked one
    gets. That last rule is the narrowest fail-closed reading of ADR 0009 decision 5:
    rotation carries the predecessor's scope set forward without rebounding it by the
    member's current role, so reviving a dead credential through it would revive a scope set
    the member may no longer hold. Re-issuance -- which does rebound the scopes -- is the
    supported way back.
    """
    owner, _ = owner_with_workspace(application_engine)
    soon = datetime.now(timezone.utc) + timedelta(hours=1)
    with workspace_session(application_engine, owner) as (session, context):
        issued = credentials.issue(
            session, role=context.role, scopes=("workspace:read",), expires_at=soon, idempotency_key=key("iss")
        )
    # While it is live it is active, it authenticates, and the listing agrees.
    with workspace_session(application_engine, owner) as (session, _):
        (live,) = [row for row in credentials.list_credentials(session) if row.binding_id == issued.binding_id]
    assert live.active is True and live.revoked_at is None
    with auth.authenticated_transaction(application_engine, issued.credential):
        pass

    _expire(owner_engine, issued.binding_id)

    # 1. Inactive in the listing, though nothing revoked it.
    with workspace_session(application_engine, owner) as (session, _):
        (dead,) = [row for row in credentials.list_credentials(session) if row.binding_id == issued.binding_id]
    assert dead.revoked_at is None, "nothing revoked it; it simply elapsed"
    assert dead.active is False, "an elapsed credential must not be reported as active"
    assert dead.expires_at is not None

    # 2. It does not authenticate.
    with pytest.raises(auth.AuthenticationError):
        with auth.authenticated_transaction(application_engine, issued.credential):
            pass

    # 3. It is refused rotation -- with no expiry offered, and with an explicit future one.
    for supplied in (None, datetime.now(timezone.utc) + timedelta(days=1)):
        with pytest.raises(accounts.IdentityRefused):
            with workspace_session(application_engine, owner) as (session, _):
                credentials.rotate(session, issued.binding_id, expires_at=supplied, idempotency_key=key("rot"))

    # 4. And no successor exists at all -- least of all one that never expires.
    successors = owner_rows(owner_engine, "auth_bindings", rotated_from_id=issued.binding_id)
    assert successors == [], "a refused rotation must mint nothing"
    (row,) = owner_rows(owner_engine, "auth_bindings", id=issued.binding_id)
    assert row["expires_at"] is not None, "an elapsed expiry is never turned into NULL"


def test_rotating_a_live_credential_never_widens_or_drops_its_expiry(application_engine, owner_engine):
    """The other half: rotation of a *live* credential carries a real expiry forward, and an
    explicitly supplied future one replaces it. Neither ever becomes ``NULL``."""
    owner, _ = owner_with_workspace(application_engine)
    soon = datetime.now(timezone.utc) + timedelta(hours=2)
    with workspace_session(application_engine, owner) as (session, context):
        issued = credentials.issue(
            session, role=context.role, scopes=("workspace:read",), expires_at=soon, idempotency_key=key("iss")
        )
    # Inherited: no expiry supplied, so the predecessor's travels to the successor.
    with workspace_session(application_engine, owner) as (session, _):
        inherited = credentials.rotate(session, issued.binding_id, idempotency_key=key("rot"))
    assert inherited.expires_at is not None
    assert abs((inherited.expires_at - soon).total_seconds()) < 1

    # Replaced: an explicit future expiry wins, and the successor still expires.
    later = datetime.now(timezone.utc) + timedelta(days=3)
    with workspace_session(application_engine, owner) as (session, _):
        replaced = credentials.rotate(session, inherited.binding_id, expires_at=later, idempotency_key=key("rot"))
    assert replaced.expires_at is not None
    assert abs((replaced.expires_at - later).total_seconds()) < 1
    for binding_id in (inherited.binding_id, replaced.binding_id):
        (row,) = owner_rows(owner_engine, "auth_bindings", id=binding_id)
        assert row["expires_at"] is not None, "no rotation of an expiring credential produces an unlimited one"

    # And a past expiry is refused at rotation exactly as it is at issuance.
    with pytest.raises(accounts.IdentityError):
        with workspace_session(application_engine, owner) as (session, _):
            credentials.rotate(
                session, replaced.binding_id,
                expires_at=datetime.now(timezone.utc) - timedelta(minutes=1), idempotency_key=key("rot"),
            )


def test_last_use_is_recorded_only_from_a_credential_context(application_engine, owner_engine):
    owner, _ = owner_with_workspace(application_engine)
    issued = issue_credential(application_engine, owner)
    with pytest.raises(AuthorizationError):
        with workspace_session(application_engine, owner) as (session, _):
            credentials.record_use(session)
    (before,) = owner_rows(owner_engine, "auth_bindings", id=issued.binding_id)
    assert before["last_used_at"] is None
    with auth.authenticated_transaction(application_engine, issued.credential) as session:
        credentials.record_use(session)
    (after,) = owner_rows(owner_engine, "auth_bindings", id=issued.binding_id)
    assert after["last_used_at"] is not None
    # A plain transaction, holding nothing, records nothing either.
    with pytest.raises(AuthorizationError):
        with db_engine.transaction(application_engine) as session:
            credentials.record_use(session)
