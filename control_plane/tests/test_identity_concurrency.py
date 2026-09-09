"""Concurrent identity mutations are deterministic: one effect, one event, one answer.

The same choreography as ``test_idempotency_concurrency.py``: the first caller runs its
mutation and pauses **inside its transaction**, so the row it locked or the key it claimed
is held uncommitted; the second caller starts and blocks; the watcher confirms through
``pg_stat_activity`` that the second is really waiting on a lock; the first is released.
What is asserted afterwards is what the design promises -- the winner's result replayed to
the loser, or a refusal the loser can act on -- and never a second effect.
"""

from __future__ import annotations

import threading
import time
from datetime import timedelta

import pytest
from sqlalchemy import text

from firmbatch.control_plane.db import accounts, credentials, membership
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.audit import audit_events
from firmbatch.control_plane.security.authorization import AuthorizationError
from firmbatch.control_plane.security.secrets import Secret
from firmbatch.control_plane.db.idempotency import outbox_events
from firmbatch.control_plane.tests.identity_helpers import (
    PASSWORD,
    account_session,
    bind,
    invite_and_accept,
    issue_credential,
    key,
    owner_rows,
    owner_with_workspace,
    person,
    signup_verified,
    workspace_session,
)

#: What a recovery in these tests sets the password to. Long enough for the policy.
REPLACEMENT_PASSWORD = "a replacement password for the race 2026"

BLOCK_TIMEOUT_SECONDS = 20.0


def _thread(label: str, into: dict, body):
    def run():
        try:
            into[label] = body()
        except BaseException as exc:  # re-raised in the main thread, where it is visible
            into[label] = exc

    return threading.Thread(target=run, name=label, daemon=True)


def _unwrap(value):
    if isinstance(value, BaseException):
        raise value
    return value


def _join(threads) -> None:
    for thread in threads:
        thread.join(timeout=BLOCK_TIMEOUT_SECONDS * 2)
        assert not thread.is_alive(), f"{thread.name} did not finish"


def _wait_for_a_blocked_backend(engine) -> bool:
    """Whether some other backend of this database is waiting on a lock.

    Read from ``pg_locks`` and not from ``pg_stat_activity.wait_event_type``: a
    non-superuser sees ``NULL`` in the state and wait columns for a backend belonging to a
    **different role**, and the recovery/login race runs its two sides as the authenticator
    and the application roles. An ungranted lock request is visible to everybody and says
    exactly the same thing. ``pg_stat_activity`` is still joined for ``datname``, which is
    not one of the columns it hides.
    """
    deadline = time.monotonic() + BLOCK_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        with engine.connect() as connection:
            waiting = connection.execute(
                text(
                    "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid "
                    "WHERE NOT l.granted AND l.pid <> pg_backend_pid() "
                    "AND a.datname = current_database()"
                )
            ).scalar()
        if waiting:
            return True
        time.sleep(0.05)
    return False


class _Race:
    """The winner runs ``winner`` inside its transaction and pauses before commit; the loser
    starts once the winner has paused; the watcher looks for the block; then release."""

    def __init__(self, engine):
        self.engine = engine
        self.paused = threading.Event()
        self.release = threading.Event()
        self.results: dict = {}

    def hold(self) -> None:
        self.paused.set()
        assert self.release.wait(timeout=BLOCK_TIMEOUT_SECONDS), "the winner was never released"

    def run(self, winner, loser) -> bool:
        first = _thread("winner", self.results, winner)
        second = _thread("loser", self.results, loser)
        first.start()
        assert self.paused.wait(timeout=BLOCK_TIMEOUT_SECONDS), "the first caller never paused"
        second.start()
        observed = _wait_for_a_blocked_backend(self.engine)
        self.release.set()
        _join((first, second))
        return observed


# --------------------------------------------------------------------------- workspaces


def test_two_concurrent_workspace_creations_with_one_key_produce_one_workspace(application_engine, owner_engine):
    who = person(application_engine)
    k = key("ws")
    race = _Race(application_engine)

    def create(pause: bool):
        def body():
            with account_session(application_engine, who) as (session, _):
                created = membership.create_workspace(session, slug="raced", name="Raced", idempotency_key=k)
                if pause:
                    race.hold()
                return created
        return body

    assert race.run(create(True), create(False)) is True
    winner = _unwrap(race.results["winner"])
    loser = _unwrap(race.results["loser"])
    assert not winner.replayed and loser.replayed
    assert (loser.workspace_id, loser.tenant_id, loser.membership_id, loser.event_id, loser.record_id) == (
        winner.workspace_id, winner.tenant_id, winner.membership_id, winner.event_id, winner.record_id
    )
    assert len(owner_rows(owner_engine, "memberships", account_id=who.account_id)) == 1
    assert len(owner_rows(owner_engine, "account_idempotency_records", account_id=who.account_id)) == 1
    with account_session(application_engine, who, csrf=False) as (session, _):
        assert [row.slug for row in membership.account_workspaces(session)] == ["raced"]


def test_two_concurrent_owners_removing_each_other_leave_exactly_one(application_engine, owner_engine):
    owner, created = owner_with_workspace(application_engine)
    other = person(application_engine, "other")
    accepted = invite_and_accept(application_engine, owner, other, role="member")
    with workspace_session(application_engine, owner) as (session, _):
        membership.change_membership_role(session, accepted.membership_id, "owner")
    bind(application_engine, other, created.workspace_id)
    race = _Race(application_engine)

    def remove(who, target, pause: bool):
        def body():
            with workspace_session(application_engine, who) as (session, _):
                outcome = membership.remove_membership(session, target, idempotency_key=key("rm"))
                if pause:
                    race.hold()
                return outcome
        return body

    assert race.run(remove(owner, accepted.membership_id, True), remove(other, created.membership_id, False)) is True
    winner = _unwrap(race.results["winner"])
    assert not winner.replayed
    # The loser's own membership was revoked by the winner before the loser took the lock, so
    # the centralized membership revalidation refuses it outright: a removed member manages
    # nobody, and a membership that is gone is the one neutral refusal (IdentityRefused),
    # never a message that would tell a stranger what became of it. AuthorizationError is the
    # answer if the interleaving leaves the loser a member of a lesser role, and the
    # last-owner conflict if it leaves it an owner. Either way, one owner remains.
    with pytest.raises((accounts.IdentityRefused, accounts.IdentityConflict, AuthorizationError)):
        _unwrap(race.results["loser"])
    active = [row for row in owner_rows(owner_engine, "memberships", workspace_id=created.workspace_id)
              if row["revoked_at"] is None]
    assert [row["id"] for row in active] == [created.membership_id]
    assert active[0]["role"] == "owner"


# --------------------------------------------------------------------------- invitations


def test_one_invitation_accepted_twice_concurrently_creates_one_membership(application_engine, owner_engine):
    owner, created = owner_with_workspace(application_engine)
    invitee = person(application_engine, "invitee")
    with workspace_session(application_engine, owner) as (session, _):
        invitation = membership.create_invitation(session, email=invitee.email, role="member")
    race = _Race(application_engine)

    def accept(pause: bool):
        def body():
            with account_session(application_engine, invitee) as (session, _):
                accepted = membership.accept_invitation(session, invitation.secret, idempotency_key=key("acc"))
                if pause:
                    race.hold()
                return accepted
        return body

    assert race.run(accept(True), accept(False)) is True
    winner = _unwrap(race.results["winner"])
    with pytest.raises(accounts.IdentityRefused):
        _unwrap(race.results["loser"])
    rows = owner_rows(owner_engine, "memberships", account_id=invitee.account_id)
    assert [row["id"] for row in rows] == [winner.membership_id]
    with workspace_session(application_engine, owner, csrf=False) as (session, _):
        assert len([e for e in outbox_events(session) if e.event_type == "membership.created"]) == 1
        assert len([e for e in audit_events(session) if e.action == "membership.created"]) == 1


# --------------------------------------------------------------------------- credentials


def test_two_concurrent_issuances_with_one_key_mint_one_credential(application_engine, owner_engine):
    owner, created = owner_with_workspace(application_engine)
    k = key("iss")
    race = _Race(application_engine)

    def issue(pause: bool):
        def body():
            with workspace_session(application_engine, owner) as (session, context):
                issued = credentials.issue(
                    session, role=context.role, scopes=("workspace:read",), label="raced", idempotency_key=k
                )
                if pause:
                    race.hold()
                return issued
        return body

    assert race.run(issue(True), issue(False)) is True
    winner = _unwrap(race.results["winner"])
    loser = _unwrap(race.results["loser"])
    assert winner.credential is not None and not winner.replayed
    assert loser.replayed and loser.credential is None and loser.binding_id == winner.binding_id
    assert loser.event_id == winner.event_id and loser.record_id == winner.record_id
    assert len(owner_rows(owner_engine, "auth_bindings", membership_id=created.membership_id)) == 1
    with workspace_session(application_engine, owner, csrf=False) as (session, _):
        assert len([e for e in outbox_events(session) if e.event_type == "credential.issued"]) == 1


def test_two_concurrent_rotations_of_one_credential_produce_one_successor(application_engine, owner_engine):
    owner, created = owner_with_workspace(application_engine)
    issued = issue_credential(application_engine, owner)
    race = _Race(application_engine)

    def rotate(pause: bool):
        def body():
            with workspace_session(application_engine, owner) as (session, _):
                rotated = credentials.rotate(session, issued.binding_id, idempotency_key=key("rot"))
                if pause:
                    race.hold()
                return rotated
        return body

    assert race.run(rotate(True), rotate(False)) is True
    winner = _unwrap(race.results["winner"])
    with pytest.raises(accounts.IdentityRefused):
        _unwrap(race.results["loser"])
    rows = owner_rows(owner_engine, "auth_bindings", membership_id=created.membership_id)
    active = [row for row in rows if row["revoked_at"] is None]
    assert [row["id"] for row in active] == [winner.binding_id]
    assert len(rows) == 2 and winner.rotated_from_id == issued.binding_id


# ------------------------------------------- Milestone 3.1 security-correction races
#
# Deterministic two-transaction races for the workspace-serializer findings. Each uses the
# same choreography as above: the winner does its work and pauses inside its transaction
# holding the workspace lock; the loser starts, blocks on that lock, and the watcher confirms
# a blocked backend before the winner is released.


def test_issuance_racing_a_membership_removal_leaves_no_active_credential(application_engine, owner_engine):
    """Finding: credential issuance must not commit an active key after membership revocation.
    The shared workspace lock makes issuance re-read the membership under it: a removal that
    committed first is seen, and issuance refuses."""
    owner, created = owner_with_workspace(application_engine)
    member = person(application_engine, "member")
    accepted = invite_and_accept(application_engine, owner, member, role="member")
    bind(application_engine, member, created.workspace_id)
    race = _Race(application_engine)

    def remove(pause: bool):
        def body():
            with workspace_session(application_engine, owner) as (session, _):
                outcome = membership.remove_membership(session, accepted.membership_id, idempotency_key=key("rm"))
                if pause:
                    race.hold()
                return outcome
        return body

    def issue():
        with workspace_session(application_engine, member) as (session, context):
            return credentials.issue(session, role=context.role, scopes=("workspace:read",), idempotency_key=key("iss"))

    assert race.run(remove(True), issue) is True
    _unwrap(race.results["winner"])
    with pytest.raises(accounts.IdentityRefused):
        _unwrap(race.results["loser"])
    active = [
        row for row in owner_rows(owner_engine, "auth_bindings", membership_id=accepted.membership_id)
        if row["revoked_at"] is None
    ]
    assert active == [], "no active credential may survive a completed membership removal"


def test_rotation_racing_a_membership_removal_leaves_no_active_successor(application_engine, owner_engine):
    """Finding: rotation, successor insertion and revocation must share the workspace lock, so
    a removal cannot miss a concurrently created successor."""
    owner, created = owner_with_workspace(application_engine)
    member = person(application_engine, "member")
    accepted = invite_and_accept(application_engine, owner, member, role="member")
    bind(application_engine, member, created.workspace_id)
    issued = issue_credential(application_engine, member)
    race = _Race(application_engine)

    def remove(pause: bool):
        def body():
            with workspace_session(application_engine, owner) as (session, _):
                outcome = membership.remove_membership(session, accepted.membership_id, idempotency_key=key("rm"))
                if pause:
                    race.hold()
                return outcome
        return body

    def rotate():
        with workspace_session(application_engine, member) as (session, _):
            return credentials.rotate(session, issued.binding_id, idempotency_key=key("rot"))

    assert race.run(remove(True), rotate) is True
    _unwrap(race.results["winner"])
    with pytest.raises(accounts.IdentityRefused):
        _unwrap(race.results["loser"])
    active = [
        row for row in owner_rows(owner_engine, "auth_bindings", membership_id=accepted.membership_id)
        if row["revoked_at"] is None
    ]
    assert active == [], "neither the predecessor nor any successor may survive the removal"


def test_a_demoted_owner_cannot_restore_itself_by_racing_the_demotion(application_engine, owner_engine):
    """Finding: owner authority must be re-read under the workspace lock. A concurrently demoted
    owner, resuming on stale cached authority, must not promote itself back to owner."""
    owner, created = owner_with_workspace(application_engine)
    other = person(application_engine, "other")
    accepted = invite_and_accept(application_engine, owner, other, role="member")
    with workspace_session(application_engine, owner) as (session, _):
        membership.change_membership_role(session, accepted.membership_id, "owner")
    bind(application_engine, other, created.workspace_id)
    race = _Race(application_engine)

    def demote(pause: bool):
        # The original owner demotes `other` to member.
        def body():
            with workspace_session(application_engine, owner) as (session, _):
                outcome = membership.change_membership_role(session, accepted.membership_id, "member", idempotency_key=key("dm"))
                if pause:
                    race.hold()
                return outcome
        return body

    def self_promote():
        # `other`, still cached as owner, tries to promote its own membership back to owner.
        with workspace_session(application_engine, other) as (session, _):
            return membership.change_membership_role(session, accepted.membership_id, "owner", idempotency_key=key("sp"))

    assert race.run(demote(True), self_promote) is True
    _unwrap(race.results["winner"])
    # The self-promotion is refused: its caller-role re-read under the lock finds it is no
    # longer an owner (indeed no longer a manager), so it cannot act.
    with pytest.raises((AuthorizationError, accounts.IdentityConflict)):
        _unwrap(race.results["loser"])
    (row,) = owner_rows(owner_engine, "memberships", id=accepted.membership_id)
    assert row["role"] == "member", "the demotion must stand; the demoted owner cannot restore itself"


# The concurrency of account recovery against credential issuance is proven deterministically
# rather than by a thread race, in test_identity_security_corrections.py: issuance and recovery
# share no lock, so the durable security epoch is what closes the window -- a credential stamped
# with the pre-recovery epoch (exactly what a raced issuance produces) is refused at bearer
# authentication (see test_finding6_a_credential_stamped_with_a_stale_epoch_is_refused and
# test_finding6_account_recovery_evicts_credentials_via_the_security_epoch).


# ------------------------------------------------- a bound session against its own membership
#
# The stale-scope finding, in the shape that produced it: a session binds, which caches an
# authorization decision in the transaction context, and the membership behind it changes
# before the transaction acts. Every workspace-mode operation now revalidates through the one
# mechanism, so the cached decision is never the one that decides.


def _stale_transaction(application_engine, who, act):
    """Bind ``who``'s workspace session, pause, and run ``act`` after the caller resumes it.

    Deterministic rather than a lock race: the bind takes no lock, so the mutation the test
    runs while it is paused commits without contention, and what is under test is that the
    *later* statement re-derives the membership rather than trusting what the bind cached.
    """
    paused = threading.Event()
    released = threading.Event()
    results: dict = {}

    def body():
        with workspace_session(application_engine, who) as (session, context):
            cached = context.role
            paused.set()
            assert released.wait(timeout=BLOCK_TIMEOUT_SECONDS), "the stale transaction was never released"
            return act(session, cached)

    thread = _thread("stale", results, body)
    thread.start()
    assert paused.wait(timeout=BLOCK_TIMEOUT_SECONDS), "the stale transaction never bound"
    return thread, released, results


#: Every M3.1 workspace operation an admin may perform and a viewer may not, as a callable
#: taking the stale transaction's session. The last entry is the HTTP boundary's own
#: revalidation, which the credential-history route makes before it reads the audit trail.
_ADMIN_ONLY_OPERATIONS = {
    "rename_workspace": lambda session, ctx: membership.rename_workspace(
        session, name="Renamed by a demoted admin", idempotency_key=key("rn")
    ),
    "revoke_invitation": lambda session, ctx: membership.revoke_invitation(
        session, ctx["invitation_id"], idempotency_key=key("ri")
    ),
    "list_invitations": lambda session, ctx: membership.workspace_invitations(session),
    "revoke_credential": lambda session, ctx: credentials.revoke(
        session, ctx["credential_id"], idempotency_key=key("rc")
    ),
    "issue_credential": lambda session, ctx: credentials.issue(
        session, role="admin", scopes=("workspace:read",), idempotency_key=key("ic")
    ),
    "credential_history_authority": lambda session, ctx: membership.require_membership(
        session, scope="audit:read"
    ),
}


@pytest.mark.parametrize("operation", sorted(_ADMIN_ONLY_OPERATIONS))
def test_a_demoted_admin_is_denied_the_authority_its_bound_session_cached(
    application_engine, owner_engine, operation
):
    """An admin binds, an owner demotes it to viewer and commits, and the stale transaction
    is refused the manager and issuance authority its bind cached -- for a mutation, for a
    manager-only listing, and for the audit disclosure the HTTP boundary performs itself."""
    owner, created = owner_with_workspace(application_engine)
    admin = person(application_engine, "admin")
    accepted = invite_and_accept(application_engine, owner, admin, role="admin")
    bind(application_engine, admin, created.workspace_id)
    # Something for the revocation operations to name. Both are the admin's own, so the
    # refusal cannot be mistaken for a "not yours" answer.
    with workspace_session(application_engine, admin) as (session, context):
        invitation = membership.create_invitation(
            session, email=f"invitee-{key('e')}@example.com", role="member", idempotency_key=key("inv")
        )
        credential = credentials.issue(
            session, role=context.role, scopes=("workspace:read",), idempotency_key=key("cr")
        )
    context = {"invitation_id": invitation.invitation_id, "credential_id": credential.binding_id}

    act = _ADMIN_ONLY_OPERATIONS[operation]
    thread, released, results = _stale_transaction(
        application_engine, admin, lambda session, cached: (
            _assert_cached(cached, "admin"), act(session, context)
        )[1]
    )
    # The demotion commits while the stale transaction is paused.
    with workspace_session(application_engine, owner) as (session, _):
        membership.change_membership_role(session, accepted.membership_id, "viewer", idempotency_key=key("dm"))
    released.set()
    _join((thread,))

    with pytest.raises(AuthorizationError):
        _unwrap(results["stale"])
    # Nothing the refused operation would have done happened. The workspace's name is read
    # from the protected directory copy: ``workspaces`` is under forced row security, so a
    # connection holding no tenant context -- which the owner engine is -- sees no row.
    (row,) = owner_rows(owner_engine, "workspace_directory", id=created.workspace_id)
    assert row["name"] != "Renamed by a demoted admin"
    (invite_row,) = owner_rows(owner_engine, "workspace_invitations", id=invitation.invitation_id)
    assert invite_row["revoked_at"] is None
    # The credential is not asserted live here: the demotion itself revokes every credential
    # of a membership whose new role no longer contains the old one's permissions, which is
    # the narrowing rule in change_membership_role and is what should happen.
    assert len(owner_rows(owner_engine, "auth_bindings", id=credential.binding_id)) == 1


def _assert_cached(cached: str | None, expected: str) -> None:
    assert cached == expected, f"the bind should have cached {expected!r}, cached {cached!r}"


@pytest.mark.parametrize(
    "act",
    (
        pytest.param(lambda session: membership.workspace_memberships(session), id="list_members"),
        pytest.param(lambda session: credentials.list_credentials(session), id="list_credentials"),
        pytest.param(lambda session: membership.require_membership(session), id="authority"),
    ),
)
def test_a_removed_member_is_denied_even_the_listings_its_bound_session_cached(application_engine, act):
    """Removal, not demotion: the membership is gone, so every workspace operation is the one
    neutral refusal -- including the listings a viewer would still have been allowed.

    A lock race rather than the deterministic pause the demotion tests use, because removal
    is not free of contention: the revocation cascade unbinds every session bound through the
    membership, and a session paused mid-transaction holds the row lock on its own
    ``browser_sessions`` row -- so a paused member would block the very removal it is meant
    to observe. Here the removal pauses instead, and the member's transaction blocks on that
    lock. Both admissible interleavings end the same way: the bind either re-derives the
    membership before the removal commits and is refused later by the revalidation, or after
    and is refused at the bind. ``IdentityRefused`` either way, and never a listing.
    """
    owner, created = owner_with_workspace(application_engine)
    member = person(application_engine, "member")
    accepted = invite_and_accept(application_engine, owner, member, role="member")
    bind(application_engine, member, created.workspace_id)
    race = _Race(application_engine)

    def remove():
        with workspace_session(application_engine, owner) as (session, _):
            outcome = membership.remove_membership(session, accepted.membership_id, idempotency_key=key("rm"))
            race.hold()
            return outcome

    def stale():
        with workspace_session(application_engine, member) as (session, _):
            return act(session)

    assert race.run(remove, stale) is True, "the member's transaction must block on the removal"
    _unwrap(race.results["winner"])
    with pytest.raises(accounts.IdentityRefused):
        _unwrap(race.results["loser"])


def test_a_demoted_manager_loses_the_workspace_wide_credential_reach_it_cached(
    application_engine, owner_engine
):
    """The manager *reach* is narrowed too, not only the manager operations.

    An admin sees every credential of the workspace; a member sees its own. A session that
    bound as an admin and was demoted to member in the meantime must see its own -- the
    listing derives the reach from the role it re-reads, never from the cached scope set.
    """
    owner, created = owner_with_workspace(application_engine)
    owner_credential = issue_credential(application_engine, owner, label="owners")
    admin = person(application_engine, "admin")
    accepted = invite_and_accept(application_engine, owner, admin, role="admin")
    bind(application_engine, admin, created.workspace_id)
    own_credential = issue_credential(application_engine, admin, label="admins")

    # As an admin, and uninterrupted, it sees both.
    with workspace_session(application_engine, admin) as (session, _):
        both = {row.binding_id for row in credentials.list_credentials(session)}
    assert {owner_credential.binding_id, own_credential.binding_id} <= both

    thread, released, results = _stale_transaction(
        application_engine, admin, lambda session, _cached: credentials.list_credentials(session)
    )
    with workspace_session(application_engine, owner) as (session, _):
        membership.change_membership_role(session, accepted.membership_id, "member", idempotency_key=key("dm"))
    released.set()
    _join((thread,))

    visible = {row.binding_id for row in _unwrap(results["stale"])}
    assert own_credential.binding_id in visible
    assert owner_credential.binding_id not in visible, (
        "a demoted manager must not keep the workspace-wide reach its session cached"
    )


# --------------------------------------------------------------- recovery against login
#
# The recovery/login race, in **both** transaction orderings. Password verification runs in
# the process (ADR 0009 decision 6), so a login is a database read, an out-of-database
# comparison, and a database write -- and a recovery can commit in the gap. The correction
# binds the challenge to the account's security (password) version and makes
# ``open_browser_session`` compare it under a lock that conflicts with the recovery's own
# update of the account row, held to commit. Each ordering is therefore closed by a
# different half of that: ordering 1 by the version comparison, ordering 2 by the lock.


def test_a_password_verified_against_a_replaced_hash_opens_no_session(
    application_engine, authenticator_engine, owner_engine
):
    """Ordering 1: the verification of the old password pauses, the recovery commits, and
    the session opening that follows it is refused.

    Without the version on the challenge the session would be opened *after* the recovery
    revoked every session it could see -- so the password the mailbox owner had just
    replaced would end up signed in, durably, with nothing left to revoke it.
    """
    email, account_id = signup_verified(application_engine)
    with db_engine.transaction(authenticator_engine) as session:
        issued = accounts.request_recovery(session, email=email)
    assert issued.secret is not None

    paused = threading.Event()
    released = threading.Event()
    results: dict = {}

    def login_then_open():
        with db_engine.transaction(authenticator_engine) as session:
            outcome = accounts.login(session, email=email, password=Secret(PASSWORD))
            # The old password verifies here: this is the moment the challenge is bound to
            # the version of the hash it was checked against.
            assert outcome.account_id == account_id
            paused.set()
            assert released.wait(timeout=BLOCK_TIMEOUT_SECONDS), "the login was never released"
            return accounts.open_session(session, ttl=timedelta(hours=1))

    thread = _thread("login", results, login_then_open)
    thread.start()
    assert paused.wait(timeout=BLOCK_TIMEOUT_SECONDS), "the login never reached the pause"
    # The recovery runs to completion -- and commits -- while the login is paused.
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.complete_recovery(
            session, secret=issued.secret, new_password=Secret(REPLACEMENT_PASSWORD)
        ) is True
    released.set()
    _join((thread,))

    with pytest.raises(accounts.IdentityRefused):
        _unwrap(results["login"])
    assert owner_rows(owner_engine, "browser_sessions", account_id=account_id) == [], (
        "a password verified against a replaced hash must leave no session behind"
    )
    # And the account is exactly where the recovery left it: the new password signs in,
    # the old one does not.
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.login(session, email=email, password=Secret(PASSWORD)).account_id is None
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.login(
            session, email=email, password=Secret(REPLACEMENT_PASSWORD)
        ).account_id == account_id


def test_a_session_opened_in_a_transaction_the_recovery_waits_for_is_revoked_by_it(
    application_engine, authenticator_engine, owner_engine
):
    """Ordering 2: the session opening commits first, and the recovery -- which really does
    block on the account row lock, asserted through ``pg_stat_activity`` -- revokes it.

    The lock is what makes the two orderings exhaustive. A recovery cannot slip past a
    session opening that has already read the version: it waits, and then its own
    ``UPDATE browser_sessions`` takes a fresh READ COMMITTED snapshot that contains the
    session just committed.
    """
    email, account_id = signup_verified(application_engine)
    with db_engine.transaction(authenticator_engine) as session:
        issued = accounts.request_recovery(session, email=email)
    assert issued.secret is not None
    race = _Race(application_engine)

    def open_session_and_hold():
        with db_engine.transaction(authenticator_engine) as session:
            assert accounts.login(session, email=email, password=Secret(PASSWORD)).account_id == account_id
            opened = accounts.open_session(session, ttl=timedelta(hours=1))
            # The account row lock open_browser_session took is held until this commits.
            race.hold()
            return opened

    def recover():
        with db_engine.transaction(authenticator_engine) as session:
            return accounts.complete_recovery(
                session, secret=issued.secret, new_password=Secret(REPLACEMENT_PASSWORD)
            )

    assert race.run(open_session_and_hold, recover) is True, (
        "the recovery must block on the account row lock the session opening holds"
    )
    opened = _unwrap(race.results["winner"])
    assert _unwrap(race.results["loser"]) is True
    (row,) = owner_rows(owner_engine, "browser_sessions", id=opened.session_id)
    assert row["revoked_at"] is not None, "the recovery must revoke the session it waited for"
    with pytest.raises(accounts.IdentityRefused):
        with accounts.session_transaction(application_engine, opened.session_secret, mode="account"):
            pass
