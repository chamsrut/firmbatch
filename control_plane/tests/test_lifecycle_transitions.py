"""The transition itself: what it accepts, what it refuses, and what it writes.

One move, and six effects that arrive together or not at all -- the state change, the
revision increment, the history row, the audit event, the outbox intent, and nothing else.
This module walks each of those, and then walks the refusals: an edge the machine does not
have, a state the instance is not in, a revision it is no longer at, a terminal state it
cannot leave, and metadata it may not carry.

Two things worth reading before the tests:

**A conflict says nothing.** Stale state, stale revision, an instance in another tenant and
an instance that never existed all produce the same :class:`LifecycleConflict` with the same
message. That is asserted rather than assumed, because a refusal that distinguished them
would answer "does this id exist somewhere else", which is the question tenant isolation
exists to refuse.

**A refusal never repeats a value.** A state name, a machine key and a reason are all
caller-supplied text that reaches a stored row and a ``jsonb`` audit document, so every
refusal here is checked against the whole ``__cause__``/``__context__`` graph rather than
against ``str(exc)`` -- ``raise ... from None`` suppresses a printed traceback without
detaching anything.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from firmbatch.control_plane.db import auth
from firmbatch.control_plane.db.audit import audit_events
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.idempotency import outbox_events
from firmbatch.control_plane.db.lifecycle import (
    INSTANCE_CREATED_ACTION,
    TRANSITIONED_ACTION,
    LifecycleConflict,
    LifecycleError,
    LifecycleTransitionNotAllowed,
    lifecycle_history,
    lifecycle_instance,
    transition_lifecycle_instance,
)
from firmbatch.control_plane.db.metadata import MetadataPolicyError
from firmbatch.control_plane.db.models import MAX_LIFECYCLE_REASON_LENGTH, LifecycleTransition
from firmbatch.control_plane.security.authorization import AuthorizationError, Scope
from firmbatch.control_plane.security.secrets import Secret

from .conftest import TEST_CYCLIC, TEST_RESTRICTED, TEST_WORKFLOW, exception_chain


def _move(engine, principal, position, target, **kwargs):
    with auth.authenticated_transaction(engine, principal.credential) as session:
        return transition_lifecycle_instance(
            session,
            instance_id=position.id,
            expected_state=position.current_state,
            expected_revision=position.revision,
            target_state=target,
            **kwargs,
        )


def _events(session, instance_id, suffix):
    """The outbox intents about one instance, of one kind.

    Creating an instance now commits ``<machine>.created`` and moving one commits
    ``<machine>.transitioned``, so a count of "events about this instance" is no longer
    a count of moves. Every assertion below says which kind it means.
    """
    return [
        event
        for event in outbox_events(session)
        if event.aggregate_id == instance_id and event.event_type.endswith(suffix)
    ]


def _read(engine, principal, instance_id):
    with auth.authenticated_transaction(engine, principal.credential) as session:
        row = lifecycle_instance(session, instance_id)
        return (row.current_state, row.revision) if row is not None else None


# ------------------------------------------------------------------------ what succeeds


@pytest.mark.parametrize("edge", TEST_WORKFLOW.transitions)
def test_every_declared_edge_can_be_taken(application_engine, principal_a, new_instance, edge):
    """Each edge of the test machine, walked to from the initial state and then taken.

    Enumerated rather than sampled: an edge the kernel silently refuses would be a machine
    that cannot be used, and a machine that cannot be used is discovered in production.
    """
    source, target = edge
    position = new_instance(principal_a)
    if source != TEST_WORKFLOW.initial_state:
        # The only non-initial sources in this machine are reachable in one or two moves.
        route = {"active": ("active",), "paused": ("active", "paused")}[source]
        for step in route:
            applied = _move(application_engine, principal_a, position, step)
            position = applied.position()

    applied = _move(application_engine, principal_a, position, target)
    assert applied.from_state == source
    assert applied.to_state == target
    assert applied.to_revision == applied.from_revision + 1
    assert _read(application_engine, principal_a, position.id) == (target, applied.to_revision)


def test_a_self_edge_advances_only_the_revision(application_engine, principal_a, new_instance):
    """A cycle of length one is a legal machine, and this is what taking it looks like."""
    position = new_instance(principal_a, TEST_CYCLIC)
    applied = _move(application_engine, principal_a, position, "idle")
    assert (applied.from_state, applied.to_state) == ("idle", "idle")
    assert _read(application_engine, principal_a, position.id) == ("idle", 1)


def test_a_cycle_can_be_traversed_repeatedly_with_monotonic_revisions(
    application_engine, principal_a, new_instance
):
    """``active <-> paused``, three times round, and no revision repeats or is skipped."""
    position = new_instance(principal_a).id
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        state, revision = "draft", 0
        for target in ("active", "paused", "active", "paused", "active"):
            applied = transition_lifecycle_instance(
                session,
                instance_id=position,
                expected_state=state,
                expected_revision=revision,
                target_state=target,
            )
            assert applied.to_revision == revision + 1
            state, revision = target, applied.to_revision

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        history = lifecycle_history(session, position)
        assert [row.to_revision for row in history] == [1, 2, 3, 4, 5]
        assert [row.from_revision for row in history] == [0, 1, 2, 3, 4]
        assert [(row.from_state, row.to_state) for row in history] == [
            ("draft", "active"),
            ("active", "paused"),
            ("paused", "active"),
            ("active", "paused"),
            ("paused", "active"),
        ]


def test_one_transition_writes_exactly_one_of_each_record(
    application_engine, principal_a, new_instance
):
    """The whole contract, counted after a real commit.

    One revision, one history row, one audit event for the move, and one outbox intent. The
    counts are taken from committed rows rather than from what the primitive returned,
    because what the primitive returned is what is under test.
    """
    position = new_instance(principal_a)
    applied = _move(application_engine, principal_a, position, "active", reason="starting work")

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        instance = lifecycle_instance(session, position.id)
        assert (instance.current_state, instance.revision) == ("active", 1)

        history = lifecycle_history(session, position.id)
        assert len(history) == 1
        row = history[0]
        assert row.id == applied.transition_id
        assert (row.from_state, row.to_state) == ("draft", "active")
        assert (row.from_revision, row.to_revision) == (0, 1)
        assert row.reason == "starting work"
        assert row.machine_key == TEST_WORKFLOW.machine_key
        assert row.machine_version == TEST_WORKFLOW.version

        moves = [e for e in audit_events(session) if e.action == TRANSITIONED_ACTION]
        assert len(moves) == 1
        assert moves[0].resource_id == position.id
        assert moves[0].details["to_state"] == "active"
        assert moves[0].details["to_revision"] == 1

        events = _events(session, position.id, ".transitioned")
        assert len(events) == 1
        assert events[0].id == applied.event_id
        assert events[0].event_type == f"{TEST_WORKFLOW.machine_key}.transitioned"
        assert events[0].aggregate_type == TEST_WORKFLOW.machine_key
        assert events[0].attributes["from_state"] == "draft"
        assert events[0].attributes["to_state"] == "active"
        assert events[0].attributes["to_revision"] == 1
        assert events[0].idempotency_record_id is None
        # And it is tagged with the machine, which is what makes reading it require
        # that machine's capability rather than the framework one alone.
        assert events[0].lifecycle_machine_key == TEST_WORKFLOW.machine_key
        assert events[0].lifecycle_machine_version == TEST_WORKFLOW.version


def test_creating_an_instance_is_audited_and_announced(
    application_engine, principal_a, new_instance
):
    """Both, and both come from the one database call.

    Audited because durable tenant state appeared and the trail exists to say who made
    it. **Announced** because it is a lifecycle state change, and the rule this kernel
    now keeps without exception is that no call changes lifecycle state without writing
    every artifact -- there is no ordering in which a caller gets the instance and skips
    the event, because the caller does not write the event.
    """
    position = new_instance(principal_a)
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        created = [e for e in audit_events(session) if e.action == INSTANCE_CREATED_ACTION]
        assert len(created) == 1
        assert created[0].resource_id == position.id
        assert created[0].details["initial_state"] == TEST_WORKFLOW.initial_state

        events = _events(session, position.id, ".created")
        assert len(events) == 1
        assert events[0].id == position.event_id
        assert events[0].attributes["initial_state"] == TEST_WORKFLOW.initial_state
        assert events[0].idempotency_record_id is None
        assert events[0].lifecycle_machine_key == TEST_WORKFLOW.machine_key
        # And nothing about a move, because nothing has moved.
        assert _events(session, position.id, ".transitioned") == []


# --------------------------------------------------------------------------- the actor


def test_the_history_records_the_authenticated_actor_and_tenant(
    application_engine, principal_a, new_instance
):
    """Neither is a parameter of anything in this module or of the database function."""
    position = new_instance(principal_a)
    _move(application_engine, principal_a, position, "active")

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        row = lifecycle_history(session, position.id)[0]
    assert row.tenant_id == principal_a.id
    assert row.actor_kind == "credential"
    assert row.actor_principal_id == principal_a.principal_id
    assert row.actor_binding_id == principal_a.binding_id


def test_two_credentials_in_one_tenant_are_distinguishable_in_the_history(
    application_engine, principal_a, issue_credential, new_instance
):
    """The trail answers *who*, not merely *which tenant*."""
    position = new_instance(principal_a)
    second = issue_credential(principal_a, [Scope.WORKSPACE_READ, Scope.WORKSPACE_WRITE, Scope.MUTATION_EXECUTE])

    first = _move(application_engine, principal_a, position, "active")
    _move(application_engine, second, first.position(), "paused")

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        actors = [row.actor_binding_id for row in lifecycle_history(session, position.id)]
    assert actors == [principal_a.binding_id, second.binding_id]


def test_the_transition_function_has_no_parameter_for_any_derived_column(owner_engine):
    """Asserted from the catalogue: there is no argument a caller could get wrong.

    No tenant, no actor kind, no principal, no binding, no timestamp -- and no *required
    scope* either, which is the Milestone 2.4 addition. A caller states what it wants to
    happen and nothing about who it is or what it is allowed to do.
    """
    with owner_engine.connect() as connection:
        arguments = connection.execute(
            text(
                "SELECT pg_get_function_arguments(p.oid) FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = :s AND p.proname = 'transition_lifecycle_instance'"
            ),
            {"s": SCHEMA},
        ).scalar_one()
    for forbidden in (
        "tenant",
        "actor",
        "principal",
        "binding",
        "occurred",
        "scope",
        "machine_key",
    ):
        assert f"p_{forbidden}" not in arguments, (forbidden, arguments)
    assert "p_instance_id" in arguments and "p_expected_revision" in arguments


def test_the_transition_time_is_the_servers(application_engine, principal_a, new_instance):
    """Written by a ``BEFORE INSERT`` trigger from ``clock_timestamp()``.

    Bracketed by two server clock readings rather than by the test process's clock, which
    may be a different machine's.
    """
    position = new_instance(principal_a)
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        before = session.execute(text("SELECT clock_timestamp()")).scalar_one()
    _move(application_engine, principal_a, position, "active")
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        after = session.execute(text("SELECT clock_timestamp()")).scalar_one()
        occurred = lifecycle_history(session, position.id)[0].occurred_at
    assert before <= occurred <= after
    assert occurred.tzinfo is not None


def test_an_instances_updated_at_moves_with_it(application_engine, principal_a, new_instance):
    position = new_instance(principal_a)
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        created = lifecycle_instance(session, position.id).created_at
    _move(application_engine, principal_a, position, "active")
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        row = lifecycle_instance(session, position.id)
    assert row.updated_at > created
    assert row.created_at == created


# ------------------------------------------------------------------------ what refuses


def test_an_undeclared_edge_changes_nothing(application_engine, principal_a, new_instance):
    """``draft -> closed`` is not an edge of version 1."""
    position = new_instance(principal_a)
    with pytest.raises(LifecycleTransitionNotAllowed) as exc:
        _move(application_engine, principal_a, position, "closed")
    assert "not an edge of this machine version" in str(exc.value)
    assert "closed" not in exception_chain(exc.value)
    assert _read(application_engine, principal_a, position.id) == ("draft", 0)


def test_a_state_the_machine_does_not_have_is_refused(application_engine, principal_a, new_instance):
    position = new_instance(principal_a)
    with pytest.raises(LifecycleTransitionNotAllowed):
        _move(application_engine, principal_a, position, "invented")
    assert _read(application_engine, principal_a, position.id) == ("draft", 0)


def test_a_terminal_state_cannot_be_left(application_engine, principal_a, new_instance):
    """And the refusal says so, rather than reporting a missing edge.

    Both are true -- a terminal state has no outgoing edge by construction -- and the
    clearer diagnosis is the one worth giving.
    """
    position = new_instance(principal_a)
    settled = _move(application_engine, principal_a, position, "cancelled")
    with pytest.raises(LifecycleTransitionNotAllowed) as exc:
        _move(application_engine, principal_a, settled.position(), "active")
    assert "terminal state" in str(exc.value)
    assert _read(application_engine, principal_a, position.id) == ("cancelled", 1)


def test_a_stale_expected_state_changes_nothing(application_engine, principal_a, new_instance):
    """The compare-and-swap, from the state side.

    The instance really is movable to ``paused`` -- from ``active``. The caller believes it
    is still in ``draft``, so its expectation is what fails.
    """
    position = new_instance(principal_a)
    _move(application_engine, principal_a, position, "active")

    with pytest.raises(LifecycleConflict):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            transition_lifecycle_instance(
                session,
                instance_id=position.id,
                expected_state="draft",
                expected_revision=1,
                target_state="paused",
            )
    assert _read(application_engine, principal_a, position.id) == ("active", 1)


def test_a_stale_expected_revision_changes_nothing(application_engine, principal_a, new_instance):
    """The compare-and-swap, from the revision side.

    Everything the caller says is true except *when*: the state is right, the edge is right,
    and the instance has moved on since it was read.
    """
    position = new_instance(principal_a)
    first = _move(application_engine, principal_a, position, "active")
    _move(application_engine, principal_a, first.position(), "paused")

    with pytest.raises(LifecycleConflict):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            transition_lifecycle_instance(
                session,
                instance_id=position.id,
                expected_state="paused",
                expected_revision=1,  # it is 2
                target_state="active",
            )
    assert _read(application_engine, principal_a, position.id) == ("paused", 2)


def test_a_future_revision_is_refused_too(application_engine, principal_a, new_instance):
    """Not merely "behind": any revision that is not the current one fails the predicate."""
    position = new_instance(principal_a)
    with pytest.raises(LifecycleConflict):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            transition_lifecycle_instance(
                session,
                instance_id=position.id,
                expected_state="draft",
                expected_revision=5,
                target_state="active",
            )
    assert _read(application_engine, principal_a, position.id) == ("draft", 0)


def test_every_conflict_reports_the_same_thing(application_engine, principal_a, new_instance):
    """Stale state, stale revision, an unknown instance -- one message, deliberately.

    Distinguishing them would let a caller ask whether an id exists in another tenant by
    watching which refusal it got.
    """
    position = new_instance(principal_a)
    _move(application_engine, principal_a, position, "active")

    messages = set()
    attempts = (
        {"instance_id": position.id, "expected_state": "draft", "expected_revision": 1},
        {"instance_id": position.id, "expected_state": "active", "expected_revision": 0},
        {"instance_id": uuid.uuid4(), "expected_state": "draft", "expected_revision": 0},
    )
    for attempt in attempts:
        with pytest.raises(LifecycleConflict) as exc:
            with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
                transition_lifecycle_instance(session, target_state="paused", **attempt)
        messages.add(str(exc.value))
    assert len(messages) == 1, messages


def test_a_refused_transition_leaves_no_record_of_any_kind(
    application_engine, principal_a, new_instance
):
    """No history row, no audit event, no outbox intent, and no revision.

    The audit trail is the interesting one: the transition function appends its event
    *after* the conditional update, so a refusal that happened earlier can leave nothing --
    and a refusal that happened later would still be rolled back with the transaction.
    """
    position = new_instance(principal_a)
    with pytest.raises(LifecycleTransitionNotAllowed):
        _move(application_engine, principal_a, position, "closed")

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert lifecycle_history(session, position.id) == []
        assert [e for e in audit_events(session) if e.action == TRANSITIONED_ACTION] == []
        # The creation event is still there and should be: it records something that
        # really happened. What must not exist is an announcement of the move.
        assert _events(session, position.id, ".transitioned") == []
        assert len(_events(session, position.id, ".created")) == 1
        assert lifecycle_instance(session, position.id).revision == 0


def test_a_rollback_after_a_successful_transition_removes_every_effect(
    application_engine, principal_a, new_instance
):
    """Six effects, one transaction. A failure after the primitive returns takes them all.

    This is the atomicity claim stated the only way it can be checked: the move succeeds,
    the caller then fails, and the committed state is as though nothing happened.
    """
    position = new_instance(principal_a)

    class Deliberate(RuntimeError):
        pass

    with pytest.raises(Deliberate):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            transition_lifecycle_instance(
                session,
                instance_id=position.id,
                expected_state="draft",
                expected_revision=0,
                target_state="active",
            )
            raise Deliberate("the caller failed after the move")

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert lifecycle_instance(session, position.id).revision == 0
        assert lifecycle_history(session, position.id) == []
        assert [e for e in audit_events(session) if e.action == TRANSITIONED_ACTION] == []
        assert _events(session, position.id, ".transitioned") == []


# ------------------------------------------------------------------------ authorization


def test_a_credential_without_the_machines_transition_scope_is_refused(
    application_engine, new_principal, issue_credential, lifecycle_definitions
):
    owner = new_principal("transition-scope")
    with auth.authenticated_transaction(application_engine, owner.credential) as session:
        from firmbatch.control_plane.db.lifecycle import create_lifecycle_instance

        position = create_lifecycle_instance(
            session,
            machine_key=TEST_RESTRICTED.machine_key,
            machine_version=TEST_RESTRICTED.version,
        )

    unentitled = issue_credential(
        owner, [Scope.WORKSPACE_WRITE, Scope.MUTATION_EXECUTE, Scope.AUDIT_READ]
    )
    with pytest.raises(AuthorizationError) as exc:
        _move(application_engine, unentitled, position, "settled")
    assert "not permitted" in str(exc.value)
    assert _read(application_engine, owner, position.id) == ("opened", 0)


def test_a_transition_also_needs_mutation_execute(
    application_engine, new_principal, issue_credential, new_instance
):
    """Because committing the outbox intent is part of the transition, not an extra.

    Named here rather than left to be discovered: a credential that can move an instance
    and cannot record that it moved would be able to change state silently, which is the
    outcome the outbox exists to prevent.
    """
    owner = new_principal("transition-mutation")
    position = new_instance(owner)
    without = issue_credential(owner, [Scope.WORKSPACE_READ, Scope.WORKSPACE_WRITE])

    with pytest.raises(AuthorizationError) as exc:
        _move(application_engine, without, position, "active")
    assert "mutation:execute" in str(exc.value)
    assert _read(application_engine, owner, position.id) == ("draft", 0)


def test_the_provisioning_role_holds_no_lifecycle_authority(
    provisioning_engine, principal_a, new_instance
):
    """It creates a tenant and mints its first credential. It does not move anything."""
    position = new_instance(principal_a)
    from sqlalchemy.exc import ProgrammingError

    with pytest.raises(ProgrammingError) as exc:
        with auth.authenticated_transaction(provisioning_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"SELECT {SCHEMA}.transition_lifecycle_instance("
                    ":i, 'draft', 0, 'active', NULL, NULL, NULL)"
                ),
                {"i": position.id},
            )
    assert "permission denied" in str(exc.value).lower()


# ------------------------------------------------------------- reasons and metadata


def test_a_reason_is_optional_and_stored_verbatim(application_engine, principal_a, new_instance):
    position = new_instance(principal_a)
    first = _move(application_engine, principal_a, position, "active", reason="operator asked")
    _move(application_engine, principal_a, first.position(), "paused")

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        reasons = [row.reason for row in lifecycle_history(session, position.id)]
    assert reasons == ["operator asked", None]


def test_an_over_long_reason_is_refused_without_its_length(
    application_engine, principal_a, new_instance
):
    position = new_instance(principal_a)
    hostile = "x" * (MAX_LIFECYCLE_REASON_LENGTH + 1)
    with pytest.raises(LifecycleError) as exc:
        _move(application_engine, principal_a, position, "active", reason=hostile)
    rendered = exception_chain(exc.value)
    assert hostile not in rendered
    assert str(len(hostile)) not in str(exc.value)
    assert _read(application_engine, principal_a, position.id) == ("draft", 0)


def test_a_secret_shaped_reason_is_refused_before_the_row(
    application_engine, principal_a, new_instance
):
    position = new_instance(principal_a)
    hostile = "Bearer abcdefghijklmnop"
    with pytest.raises(LifecycleError) as exc:
        _move(application_engine, principal_a, position, "active", reason=hostile)
    assert "looks like an HTTP authorization header value" in str(exc.value)
    assert hostile not in exception_chain(exc.value)
    assert _read(application_engine, principal_a, position.id) == ("draft", 0)


def test_a_secret_object_cannot_be_smuggled_into_a_reason(
    application_engine, principal_a, new_instance
):
    position = new_instance(principal_a)
    with pytest.raises(LifecycleError):
        _move(application_engine, principal_a, position, "active", reason=Secret("fbk_" + "a" * 43))


def test_transition_details_are_bounded_metadata(application_engine, principal_a, new_instance):
    position = new_instance(principal_a)
    applied = _move(
        application_engine,
        principal_a,
        position,
        "active",
        details={"attempt": 3, "operator_id": uuid.uuid4(), "note": "resumed"},
    )
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        stored = lifecycle_history(session, position.id)[0].details
    assert stored["attempt"] == 3
    assert stored["note"] == "resumed"
    assert applied.to_revision == 1


@pytest.mark.parametrize(
    "details",
    [
        {"payload": "anything"},
        {"token": "anything"},
        {"nested": {"a": 1}},
        {"note": "fbk_" + "a" * 43},
        {"note": "x" * 300},
        {"Uppercase": 1},
    ],
    ids=["denied-key", "credential-key", "nested", "credential-value", "long-value", "bad-key"],
)
def test_unacceptable_details_are_refused_before_the_move(
    application_engine, principal_a, new_instance, details
):
    position = new_instance(principal_a)
    with pytest.raises((MetadataPolicyError, LifecycleError)) as exc:
        _move(application_engine, principal_a, position, "active", details=details)
    rendered = exception_chain(exc.value)
    for value in details.values():
        if isinstance(value, str):
            assert value not in rendered, value
    assert _read(application_engine, principal_a, position.id) == ("draft", 0)


def test_the_database_applies_the_same_metadata_policy(application_engine, principal_a, new_instance):
    """The half that holds when the caller writes the SQL itself.

    The Python boundary is a courtesy; the application role can call
    ``firmbatch.transition_lifecycle_instance`` directly, and the same document is refused
    there -- by the one shared bounded-metadata implementation, not a second copy of it.
    """
    position = new_instance(principal_a)
    from sqlalchemy.exc import DBAPIError

    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"SELECT {SCHEMA}.transition_lifecycle_instance("
                    ":i, 'draft', 0, 'active', NULL, CAST(:d AS jsonb), NULL)"
                ),
                {"i": position.id, "d": '{"token": "anything"}'},
            )
    assert "names content or a credential" in str(exc.value)
    assert _read(application_engine, principal_a, position.id) == ("draft", 0)


def test_a_malformed_state_name_is_refused_without_being_repeated(
    application_engine, principal_a, new_instance
):
    position = new_instance(principal_a)
    for target in ("Active", "active state", "fbk_" + "a" * 43):
        with pytest.raises(LifecycleError) as exc:
            _move(application_engine, principal_a, position, target)
        assert target not in exception_chain(exc.value), target
    assert _read(application_engine, principal_a, position.id) == ("draft", 0)


def test_a_malformed_expected_revision_is_refused(application_engine, principal_a, new_instance):
    position = new_instance(principal_a)
    for revision in (-1, "0", 1.0, True):
        with pytest.raises(LifecycleError):
            with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
                transition_lifecycle_instance(
                    session,
                    instance_id=position.id,
                    expected_state="draft",
                    expected_revision=revision,
                    target_state="active",
                )


def test_an_instance_id_must_be_a_uuid(application_engine, principal_a):
    with pytest.raises(LifecycleError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            transition_lifecycle_instance(
                session,
                instance_id="not-a-uuid",
                expected_state="draft",
                expected_revision=0,
                target_state="active",
            )
    assert "is a UUID" in str(exc.value)
    assert "not-a-uuid" not in exception_chain(exc.value)


def test_a_transition_outside_a_transaction_is_refused(application_engine, principal_a, new_instance):
    from sqlalchemy.orm import Session

    position = new_instance(principal_a)
    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with pytest.raises(LifecycleError) as exc:
            transition_lifecycle_instance(
                session,
                instance_id=position.id,
                expected_state="draft",
                expected_revision=0,
                target_state="active",
            )
        assert "requires an open transaction" in str(exc.value)
    finally:
        session.close()


def test_the_history_is_ordered_by_revision_not_by_clock(
    application_engine, principal_a, new_instance
):
    """Two rows written in the same microsecond would be indistinguishable by clock.

    The revision is the order the machine itself defines, and the unique constraint on
    ``(tenant, instance, to_revision)`` is what makes it complete.
    """
    position = new_instance(principal_a).id
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        state, revision = "draft", 0
        for target in ("active", "paused", "active", "closed"):
            applied = transition_lifecycle_instance(
                session,
                instance_id=position,
                expected_state=state,
                expected_revision=revision,
                target_state=target,
            )
            state, revision = target, applied.to_revision

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        history = lifecycle_history(session, position)
    assert [row.to_revision for row in history] == [1, 2, 3, 4]
    # Contiguous: no gaps, which is what "monotonic with no gaps" means for a history.
    assert [row.from_revision for row in history] == [0, 1, 2, 3]
    assert all(
        earlier.occurred_at <= later.occurred_at
        for earlier, later in zip(history, history[1:])
    )


def test_an_audit_event_cannot_be_dated_from_the_transactions_start(
    application_engine, principal_a, new_instance
):
    """Four moves in one transaction, and their times are not all equal.

    ``now()`` is transaction-start time; ``clock_timestamp()`` is not. If the trigger used
    the first, every row of a batch would carry the same instant and a timeline built from
    them would be useless.
    """
    position = new_instance(principal_a).id
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        state, revision = "draft", 0
        for target in ("active", "paused", "active", "closed"):
            applied = transition_lifecycle_instance(
                session,
                instance_id=position,
                expected_state=state,
                expected_revision=revision,
                target_state=target,
            )
            state, revision = target, applied.to_revision
        started = session.execute(text("SELECT now()")).scalar_one()

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        times = [row.occurred_at for row in lifecycle_history(session, position)]
    assert len(set(times)) > 1, "every row carried the transaction's start time"
    assert all(time >= started for time in times)
    assert times == sorted(times)


def test_the_audit_trail_and_the_history_are_different_records(
    application_engine, principal_a, new_instance
):
    """Neither is derivable from the other, which is why both exist.

    The history carries a revision pair and no outcome; the trail carries an outcome and no
    revision. A denied attempt would appear in neither at this milestone, because a refused
    transition rolls its own transaction back -- which is stated here rather than implied.
    """
    position = new_instance(principal_a)
    _move(application_engine, principal_a, position, "active")

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        history = lifecycle_history(session, position.id)[0]
        event = [e for e in audit_events(session) if e.action == TRANSITIONED_ACTION][0]

    assert hasattr(history, "to_revision") and not hasattr(history, "outcome")
    assert hasattr(event, "outcome") and not hasattr(event, "to_revision")
    assert event.resource_type == "lifecycle_instance"
    assert event.outcome == "succeeded"
    assert history.to_revision == event.details["to_revision"]


def test_the_transition_columns_and_the_audit_columns_do_not_overlap_by_accident(owner_engine):
    """A shape check on the two tables, so a later merge of them is a deliberate act."""
    with owner_engine.connect() as connection:
        columns = {
            table: {
                name
                for (name,) in connection.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = :s AND table_name = :t"
                    ),
                    {"s": SCHEMA, "t": table},
                ).all()
            }
            for table in ("lifecycle_transitions", "audit_events")
        }
    assert "outcome" not in columns["lifecycle_transitions"]
    assert "to_revision" not in columns["audit_events"]
    assert {"from_revision", "to_revision", "from_state", "to_state"} <= columns[
        "lifecycle_transitions"
    ]


def test_the_transition_history_model_carries_no_delivery_state(owner_engine):
    """It is a record of what happened, not a queue. A dispatcher reads the outbox."""
    with owner_engine.connect() as connection:
        columns = {
            name
            for (name,) in connection.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = :s AND table_name = 'lifecycle_transitions'"
                ),
                {"s": SCHEMA},
            ).all()
        }
    for absent in ("delivered_at", "attempts", "status", "published", "hash", "previous_hash"):
        assert absent not in columns, absent


def test_the_transition_history_and_the_outbox_agree_on_what_moved(
    application_engine, principal_a, new_instance
):
    """The event is derived from what the database returned, so the two cannot disagree."""
    position = new_instance(principal_a)
    applied = _move(application_engine, principal_a, position, "active")

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        row = lifecycle_history(session, position.id)[0]
        event = _events(session, position.id, ".transitioned")[0]
    assert event.attributes["transition_id"] == str(row.id)
    assert event.attributes["from_revision"] == row.from_revision
    assert event.attributes["to_revision"] == row.to_revision
    assert event.attributes["machine_version"] == row.machine_version
    assert applied.event_id == event.id


def test_the_transition_row_and_the_instance_agree_after_the_move(
    application_engine, principal_a, new_instance
):
    position = new_instance(principal_a)
    applied = _move(application_engine, principal_a, position, "active")
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        instance = lifecycle_instance(session, position.id)
        row = session.get(LifecycleTransition, applied.transition_id)
    assert instance.current_state == row.to_state
    assert instance.revision == row.to_revision


def test_an_audit_event_is_written_for_every_move_including_the_last(
    application_engine, principal_a, new_instance
):
    position = new_instance(principal_a).id
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        state, revision = "draft", 0
        for target in ("active", "closed"):
            applied = transition_lifecycle_instance(
                session,
                instance_id=position,
                expected_state=state,
                expected_revision=revision,
                target_state=target,
            )
            state, revision = target, applied.to_revision

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        actions = [e.action for e in audit_events(session)]
    # One per move, one for the instance, and the tenant's first credential registration --
    # which the fixture wrote when it minted the credential this test authenticates with.
    assert actions.count(TRANSITIONED_ACTION) == 2
    assert actions.count(INSTANCE_CREATED_ACTION) == 1
    assert set(actions) == {TRANSITIONED_ACTION, INSTANCE_CREATED_ACTION, "auth.binding_registered"}


# ------------------------------------------- every artifact, or none (review finding 1)


def test_raw_sql_cannot_change_state_without_an_outbox_event(
    application_engine, principal_a, new_instance
):
    """The correction, asserted the only way it can be: from raw SQL, as the runtime role.

    The database function is the sole path that changes lifecycle state, and it writes the
    state change, the history row, the audit event **and** the outbox intent in one call. So
    a caller composing its own SQL cannot pick a subset -- there is no lower-level function
    to call and no ordering in which the event is skipped.

    Before the correction this exact statement produced a committed move with nothing
    announcing it, because the event was appended by Python afterwards.
    """
    position = new_instance(principal_a)
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        session.execute(
            text(
                f"SELECT {SCHEMA}.transition_lifecycle_instance("
                ":i, 'draft', 0, 'active', NULL, NULL, NULL)"
            ),
            {"i": position.id},
        )

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert lifecycle_instance(session, position.id).revision == 1
        assert len(lifecycle_history(session, position.id)) == 1
        assert len([e for e in audit_events(session) if e.action == TRANSITIONED_ACTION]) == 1
        assert len(_events(session, position.id, ".transitioned")) == 1


def test_there_is_no_lower_level_state_changing_function_the_runtime_can_call(
    application_engine, principal_a, new_instance
):
    """The other half: nothing else reachable from the runtime writes lifecycle state.

    The two entry points write every artifact. Every other lifecycle function -- the four
    definition readers, publication, and the seven trigger functions -- is executable by
    nobody, so there is no partial path to take instead. Asserted by trying the two whose
    names most invite it.
    """
    position = new_instance(principal_a)
    for statement in (
        f"UPDATE {SCHEMA}.lifecycle_instances SET current_state = 'active', "
        "revision = revision + 1 WHERE id = :i",
        f"SELECT {SCHEMA}.lifecycle_instances_before_update()",
    ):
        with pytest.raises(ProgrammingError) as exc:
            with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
                session.execute(text(statement), {"i": position.id})
        assert "permission denied" in str(exc.value).lower(), statement

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert lifecycle_instance(session, position.id).revision == 0


def test_catching_the_python_error_cannot_leave_a_move_without_its_event(
    application_engine, principal_a, new_instance
):
    """A caller that swallows a refusal cannot commit a subset of the artifacts.

    The shape this guards against is specific: Python raises somewhere after the move, the
    caller catches it and carries on, and the transaction goes on to commit -- leaving the
    state change without whatever the Python layer had not written yet. That is unreachable
    now for two independent reasons, and both are asserted here.

    **There is nothing left for Python to write.** The move and all four records are one
    database call, so a Python-level failure cannot land between them.

    **And a caught database refusal aborts the transaction anyway.** The second transition
    below is refused by the server, which puts the session into a failed transaction; the
    caller catches the Python exception, but the surrounding ``COMMIT`` then commits
    *nothing* -- the earlier, entirely successful move is discarded with it. Measured
    against a real server: the committed revision is zero.

    That second fact is worth stating rather than relying on: a caller which swallows a
    lifecycle refusal and reports success to its own caller will have committed nothing at
    all. Refusals from this module are meant to unwind the transaction, not to be caught.
    """
    position = new_instance(principal_a)
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        transition_lifecycle_instance(
            session,
            instance_id=position.id,
            expected_state="draft",
            expected_revision=0,
            target_state="active",
        )
        try:
            transition_lifecycle_instance(
                session,
                instance_id=position.id,
                expected_state="active",
                expected_revision=1,
                target_state="draft",  # not an edge of this machine, in either direction
            )
        except LifecycleTransitionNotAllowed:
            pass

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        instance = lifecycle_instance(session, position.id)
        history = lifecycle_history(session, position.id)
        moves = [e for e in audit_events(session) if e.action == TRANSITIONED_ACTION]
        events = _events(session, position.id, ".transitioned")

    # The invariant, whichever way the transaction went: a committed move has every record,
    # and a discarded one has none. There is no arrangement with some of them.
    assert (instance.revision, len(history), len(moves), len(events)) in {
        (0, 0, 0, 0),
        (1, 1, 1, 1),
    }, (instance.revision, len(history), len(moves), len(events))
    # And on a real server it is the first: the aborted transaction takes everything.
    assert instance.revision == 0
    assert instance.current_state == "draft"


def test_the_transition_function_writes_the_event_itself(owner_engine):
    """Asserted on the function body, so the property is not a property of one test path.

    ``db/lifecycle.py`` appends nothing; if the ``INSERT`` into ``outbox_events`` ever left
    the database function, every caller would be back to being able to skip it.
    """
    with owner_engine.connect() as connection:
        body = connection.execute(
            text(
                "SELECT p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = :s AND p.proname = 'transition_lifecycle_instance'"
            ),
            {"s": SCHEMA},
        ).scalar_one()
    assert f"INSERT INTO {SCHEMA}.outbox_events" in body
    assert f"INSERT INTO {SCHEMA}.lifecycle_transitions" in body
    assert f"INSERT INTO {SCHEMA}.idempotency_records" in body
    assert f"INSERT INTO {SCHEMA}.lifecycle_claim_provenance" in body
    assert "append_lifecycle_audit_event" in body

    import pathlib

    from firmbatch.control_plane.db import lifecycle as lifecycle_module

    source = pathlib.Path(lifecycle_module.__file__).read_text()
    assert "append_outbox_event" not in source, (
        "db/lifecycle.py appends an outbox event, which means a caller could not"
    )
    # And it computes no fingerprint of its own. While it did, the value it computed was a
    # parameter of the database call -- and a fingerprint a caller supplies can bind a claim
    # to a request that was never made.
    assert "hashlib" not in source
    assert "request_fingerprint(" not in source


# ------------------------- the whole expectation before the graph (review finding 5)


def test_a_stale_revision_against_a_terminal_state_is_a_conflict(
    application_engine, principal_a, new_instance
):
    """Not "this instance is terminal", which is a fact about a row the caller misdescribed.

    The instance really is terminal. The caller's revision is stale, so it is told that and
    nothing else -- the graph is only ever asked about a row the caller has described
    correctly.
    """
    position = new_instance(principal_a)
    _move(application_engine, principal_a, position, "cancelled")

    with pytest.raises(LifecycleConflict) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            transition_lifecycle_instance(
                session,
                instance_id=position.id,
                expected_state="cancelled",
                expected_revision=0,  # it is 1
                target_state="active",
            )
    assert "expected state at the expected revision" in str(exc.value)
    assert "terminal" not in str(exc.value)


def test_a_stale_revision_against_an_invalid_edge_is_a_conflict(
    application_engine, principal_a, new_instance
):
    """Same rule, the other diagnosis. ``draft -> closed`` is not an edge and is not the news."""
    position = new_instance(principal_a)
    _move(application_engine, principal_a, position, "active")

    with pytest.raises(LifecycleConflict) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            transition_lifecycle_instance(
                session,
                instance_id=position.id,
                expected_state="draft",
                expected_revision=0,
                target_state="closed",
            )
    assert "not an edge" not in str(exc.value)


def test_a_correct_state_with_a_stale_revision_is_still_a_conflict(
    application_engine, principal_a, new_instance
):
    """The case only the revision catches: the state came back around a cycle.

    ``active -> paused -> active`` leaves the instance in the state a stale caller thinks it
    is in, two revisions later. With only the state compared, that caller would have been
    asked a graph question about a row it was describing by accident.
    """
    position = new_instance(principal_a)
    first = _move(application_engine, principal_a, position, "active")
    second = _move(application_engine, principal_a, first.position(), "paused")
    _move(application_engine, principal_a, second.position(), "active")

    with pytest.raises(LifecycleConflict):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            transition_lifecycle_instance(
                session,
                instance_id=position.id,
                expected_state="active",
                expected_revision=1,  # it is 3, and the state matches by coincidence
                target_state="closed",
            )
    assert _read(application_engine, principal_a, position.id) == ("active", 3)


def test_a_missing_and_a_cross_tenant_identifier_report_what_a_stale_one_does(
    application_engine, principal_a, principal_b, new_instance
):
    """Four situations, one message, and the graph asked about none of them."""
    mine = new_instance(principal_a)
    theirs = new_instance(principal_b)
    _move(application_engine, principal_a, mine, "cancelled")

    messages = set()
    attempts = (
        # stale revision, against a terminal state
        {"instance_id": mine.id, "expected_state": "cancelled", "expected_revision": 0},
        # correct state and revision would be an invalid edge; the revision is wrong first
        {"instance_id": mine.id, "expected_state": "draft", "expected_revision": 0},
        {"instance_id": theirs.id, "expected_state": "draft", "expected_revision": 0},
        {"instance_id": uuid.uuid4(), "expected_state": "draft", "expected_revision": 0},
    )
    for attempt in attempts:
        with pytest.raises(LifecycleConflict) as exc:
            with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
                transition_lifecycle_instance(session, target_state="active", **attempt)
        messages.add(str(exc.value))
    assert len(messages) == 1, messages
