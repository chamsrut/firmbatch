"""Instances and history inherit the isolation boundary, and add the graph to it.

``test_tenant_isolation.py`` establishes the boundary on the spine and
``test_outbox_isolation.py`` establishes it on the append-only tables. Neither is inherited
by being written in the same style, so this module asserts it again on the two Milestone 2.4
tenant-owned tables -- and then asserts the two things they add that nothing before them
had:

* an instance **starts where its machine says**, at revision zero, and its identity, tenant
  and machine version are fixed for its whole life;
* a history row **cannot be fabricated**: not across tenants, not across machines, not for
  an edge the machine does not declare, and not at all by a runtime role, which holds no
  ``INSERT``.

The composite foreign keys are the ones worth reading closely. PostgreSQL checks
referential integrity with row security bypassed, so a single-column reference to an
instance would be satisfied by another tenant's row -- which is why the reference names
``(id, tenant_id, machine_key, machine_version)`` and the edge reference names all four of
its columns.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

from firmbatch.control_plane.db import auth
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.lifecycle import (
    LifecycleConflict,
    create_lifecycle_instance,
    lifecycle_history,
    lifecycle_instance,
    transition_lifecycle_instance,
)
from firmbatch.control_plane.db.models import LifecycleInstance, LifecycleTransition
from firmbatch.control_plane.security.authorization import AuthorizationError, Scope

from .conftest import TEST_CYCLIC, TEST_RESTRICTED, TEST_WORKFLOW, TEST_WORKFLOW_V2

LIFECYCLE_TABLES = ("lifecycle_instances", "lifecycle_transitions")


def _advance(engine, principal, position, target, **kwargs):
    with auth.authenticated_transaction(engine, principal.credential) as session:
        return transition_lifecycle_instance(
            session,
            instance_id=position.id,
            expected_state=position.current_state,
            expected_revision=position.revision,
            target_state=target,
            **kwargs,
        )


# ------------------------------------------------------------------------- where it starts


def test_an_instance_starts_at_revision_zero_in_the_initial_state(
    application_engine, principal_a, new_instance, workflow
):
    position = new_instance(principal_a)
    assert position.current_state == workflow.initial_state
    assert position.revision == 0

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        row = lifecycle_instance(session, position.id)
        assert row is not None
        assert row.tenant_id == principal_a.id
        assert row.machine_key == workflow.machine_key
        assert row.machine_version == workflow.version
        assert row.current_state == workflow.initial_state
        assert row.revision == 0
        assert row.created_at is not None and row.updated_at == row.created_at


def test_the_instance_id_is_generated_by_the_database(application_engine, principal_a, new_instance):
    """Opaque, and not a value any caller chose -- there is no parameter for one."""
    first = new_instance(principal_a)
    second = new_instance(principal_a)
    assert first.id != second.id
    assert isinstance(first.id, uuid.UUID) and first.id.version == 4


def test_two_versions_of_one_machine_start_in_their_own_graphs(
    application_engine, principal_a, new_instance
):
    """An instance pins a version, and a later version does not reach back to it."""
    v1 = new_instance(principal_a, TEST_WORKFLOW)
    v2 = new_instance(principal_a, TEST_WORKFLOW_V2)
    assert v1.machine_version == 1 and v2.machine_version == 2

    # ``draft -> cancelled`` is an edge of version 1 only.
    _advance(application_engine, principal_a, v1, "cancelled")
    with pytest.raises(Exception) as exc:
        _advance(application_engine, principal_a, v2, "cancelled")
    assert "not an edge of this machine version" in str(exc.value)


def test_an_unregistered_machine_version_is_refused_as_a_definition_problem(
    application_engine, principal_a, lifecycle_definitions
):
    """Machines are global, so saying which is wrong reveals nothing about any tenant.

    That is why this refusal may be specific where a transition conflict may not be.
    """
    from firmbatch.control_plane.db.lifecycle import LifecycleDefinitionError

    with pytest.raises(LifecycleDefinitionError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            create_lifecycle_instance(session, machine_key="test_workflow", machine_version=99)
    assert "no such lifecycle machine version is registered" in str(exc.value)


# ------------------------------------------------------------------------------ immutable


def test_the_tenant_machine_and_identity_of_an_instance_cannot_change(
    owner_engine, principal_a, principal_b, new_instance
):
    """Enforced by a row trigger, so it binds the owner as well as every runtime role.

    Run as the **owner under a valid context**, and both halves of that matter. No runtime
    role holds ``UPDATE`` at all, so the owner is the only identity that can issue the
    statement -- and row security is ``FORCE``d, so even the owner needs a context for the
    ``UPDATE`` policy to match a row. Without one the statement is a silent no-op and the
    trigger never fires, which would have made this test pass for no reason.
    """
    position = new_instance(principal_a)
    for column, value in (
        ("tenant_id", principal_b.id),
        ("machine_key", "test_cyclic"),
        ("machine_version", 2),
        ("id", uuid.uuid4()),
    ):
        with pytest.raises(DBAPIError) as exc:
            with auth.authenticated_transaction(owner_engine, principal_a.credential) as session:
                session.execute(
                    text(
                        f"UPDATE {SCHEMA}.lifecycle_instances SET {column} = :v, "
                        "revision = revision + 1 WHERE id = :id"
                    ),
                    {"v": value, "id": position.id},
                )
        assert "identity and machine are immutable" in str(exc.value), column


def test_a_revision_may_not_skip_or_repeat(owner_engine, principal_a, new_instance):
    """The compare-and-swap token advances by exactly one, whoever is writing.

    A writer that could skip a revision could make two callers' stale expectations agree
    when they should not; one that could repeat one could make a history row's ``to_revision``
    ambiguous.
    """
    position = new_instance(principal_a)
    for revision in (position.revision, position.revision + 2, 0):
        with pytest.raises(DBAPIError) as exc:
            with auth.authenticated_transaction(owner_engine, principal_a.credential) as session:
                session.execute(
                    text(
                        f"UPDATE {SCHEMA}.lifecycle_instances "
                        "SET current_state = 'active', revision = :r WHERE id = :id"
                    ),
                    {"r": revision, "id": position.id},
                )
        assert "advances by exactly one" in str(exc.value), revision


def test_an_instance_cannot_be_created_in_a_state_that_is_not_the_initial_one(
    owner_engine, principal_a, workflow
):
    """A ``BEFORE INSERT`` trigger, so a direct writer cannot start half-way through.

    Written as the owner under a context for the same two reasons as above: the runtime
    holds no ``INSERT``, and the ``INSERT`` policy binds the owner too.
    """
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(owner_engine, principal_a.credential) as session:
            # The state travels as a bound parameter, so the statement text carries no copy
            # of it and the assertion below is about what the *trigger* said rather than
            # about what SQLAlchemy echoed back.
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.lifecycle_instances "
                    "(tenant_id, machine_key, machine_version, current_state) "
                    "VALUES (:t, :k, :v, :s)"
                ),
                {
                    "t": principal_a.id,
                    "k": workflow.machine_key,
                    "v": workflow.version,
                    "s": "closed",
                },
            )
    assert "starts in its machine" in str(exc.value)
    assert "closed" not in str(exc.value.orig), "the trigger repeated the state it refused"


def test_a_supplied_revision_and_timestamp_are_discarded_at_creation(
    owner_engine, principal_a, workflow
):
    """Revision zero and both timestamps are server facts, overwritten unconditionally.

    ``now()`` would not have been enough for either: it is transaction-*start* time, so a
    caller that opened its transaction an hour ago would date the instance an hour into the
    past by supplying nothing at all.
    """
    stale = "2000-01-01T00:00:00+00:00"
    with auth.authenticated_transaction(owner_engine, principal_a.credential) as session:
        written = session.execute(
            text(
                f"INSERT INTO {SCHEMA}.lifecycle_instances "
                "(tenant_id, machine_key, machine_version, current_state, revision, "
                "created_at, updated_at) "
                "VALUES (:t, :k, :v, :s, 7, :ts, :ts) RETURNING revision, created_at"
            ),
            {
                "t": principal_a.id,
                "k": workflow.machine_key,
                "v": workflow.version,
                "s": workflow.initial_state,
                "ts": stale,
            },
        ).one()
        assert written.revision == 0
        assert written.created_at.year > 2000


# ------------------------------------------------------------------------ fails closed


def test_without_a_context_neither_lifecycle_table_is_readable(
    application_engine, principal_a, new_instance
):
    position = new_instance(principal_a)
    _advance(application_engine, principal_a, position, "active")
    with db_engine.transaction(application_engine) as session:
        assert session.scalars(select(LifecycleInstance)).all() == []
        assert session.scalars(select(LifecycleTransition)).all() == []


def test_without_a_context_an_instance_cannot_be_created(application_engine, workflow):
    from firmbatch.control_plane.db.auth import AuthenticationError

    with pytest.raises(AuthenticationError):
        with db_engine.transaction(application_engine) as session:
            create_lifecycle_instance(
                session, machine_key=workflow.machine_key, machine_version=workflow.version
            )


def test_without_a_context_the_database_refuses_the_creation_function_too(
    application_engine, workflow
):
    """The Python check is a courtesy; this is what holds for a caller writing the SQL."""
    with pytest.raises(DBAPIError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(
                text(f"SELECT {SCHEMA}.create_lifecycle_instance(:k, :v)"),
                {"k": workflow.machine_key, "v": workflow.version},
            )
    assert "requires an authenticated context" in str(exc.value)


def test_a_credential_without_the_machines_create_scope_cannot_create_an_instance(
    application_engine, new_principal, issue_credential, lifecycle_definitions
):
    """The capability comes from the machine version, not from this catalogue.

    ``test_restricted`` requires ``credential:manage`` to create, so a credential holding
    every workspace capability -- which is enough for ``test_workflow`` -- reaches none of
    it.
    """
    owner = new_principal("lifecycle-scope")
    # Every workspace capability and the framework one, so the only thing missing is the
    # capability *this machine* declares -- which is what the test is about.
    workspace_only = issue_credential(
        owner, [Scope.WORKSPACE_READ, Scope.WORKSPACE_WRITE, Scope.MUTATION_EXECUTE]
    )

    with pytest.raises(AuthorizationError) as exc:
        with auth.authenticated_transaction(application_engine, workspace_only.credential) as session:
            create_lifecycle_instance(
                session,
                machine_key=TEST_RESTRICTED.machine_key,
                machine_version=TEST_RESTRICTED.version,
            )
    assert "not permitted" in str(exc.value)

    # And the control: the same machine, with the capability it declares.
    entitled = issue_credential(
        owner, [Scope.CREDENTIAL_MANAGE, Scope.AUDIT_READ, Scope.MUTATION_EXECUTE]
    )
    with auth.authenticated_transaction(application_engine, entitled.credential) as session:
        position = create_lifecycle_instance(
            session,
            machine_key=TEST_RESTRICTED.machine_key,
            machine_version=TEST_RESTRICTED.version,
        )
    assert position.current_state == TEST_RESTRICTED.initial_state


def test_a_credential_without_the_machines_read_scope_sees_no_instance(
    application_engine, new_principal, issue_credential, lifecycle_definitions
):
    """A policy produces nothing rather than an error, which is what a policy does."""
    owner = new_principal("lifecycle-read")
    entitled = issue_credential(
        owner, [Scope.CREDENTIAL_MANAGE, Scope.AUDIT_READ, Scope.MUTATION_EXECUTE]
    )
    with auth.authenticated_transaction(application_engine, entitled.credential) as session:
        position = create_lifecycle_instance(
            session,
            machine_key=TEST_RESTRICTED.machine_key,
            machine_version=TEST_RESTRICTED.version,
        )

    blind = issue_credential(
        owner, [Scope.WORKSPACE_READ, Scope.WORKSPACE_WRITE, Scope.MUTATION_EXECUTE]
    )
    with auth.authenticated_transaction(application_engine, blind.credential) as session:
        assert lifecycle_instance(session, position.id) is None
        assert session.scalar(select(func.count()).select_from(LifecycleInstance)) == 0

    with auth.authenticated_transaction(application_engine, entitled.credential) as session:
        assert lifecycle_instance(session, position.id) is not None


# ------------------------------------------------------------------------ cross-tenant


def test_one_tenant_cannot_see_anothers_instance_or_history(
    application_engine, principal_a, principal_b, new_instance
):
    position = new_instance(principal_b)
    _advance(application_engine, principal_b, position, "active")

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert lifecycle_instance(session, position.id) is None
        assert session.scalars(select(LifecycleInstance)).all() == []
        assert lifecycle_history(session, position.id) == []
        assert session.scalar(select(func.count()).select_from(LifecycleTransition)) == 0


def test_one_tenant_cannot_move_anothers_instance(
    application_engine, principal_a, principal_b, new_instance
):
    """And the refusal is the ordinary conflict, so it is not an existence oracle.

    Tenant A gets exactly the error it would get for an id that never existed, which is the
    point: a distinguishable refusal would answer "is this id real somewhere else".
    """
    position = new_instance(principal_b)

    with pytest.raises(LifecycleConflict) as cross_tenant:
        _advance(application_engine, principal_a, position, "active")
    with pytest.raises(LifecycleConflict) as invented:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            transition_lifecycle_instance(
                session,
                instance_id=uuid.uuid4(),
                expected_state="draft",
                expected_revision=0,
                target_state="active",
            )
    assert str(cross_tenant.value) == str(invented.value)

    with auth.authenticated_transaction(application_engine, principal_b.credential) as session:
        assert lifecycle_instance(session, position.id).revision == 0


# --------------------------------------------------------------------- no direct DML


@pytest.mark.parametrize("table", LIFECYCLE_TABLES)
def test_the_application_role_cannot_write_either_table_directly(raw_application_connection, table):
    """``SELECT`` and nothing else, so the hardened functions are the only way in.

    A direct ``INSERT`` on ``lifecycle_instances`` could start an instance in any state; a
    direct ``UPDATE`` could move it to any state at any revision, which is the
    compare-and-swap gone. On ``lifecycle_transitions`` an ``INSERT`` could record a move
    that never happened.
    """
    for statement in (
        f"UPDATE {SCHEMA}.{table} SET tenant_id = tenant_id",
        f"DELETE FROM {SCHEMA}.{table}",
        f"TRUNCATE {SCHEMA}.{table}",
    ):
        with pytest.raises(ProgrammingError) as exc:
            raw_application_connection.execute(text(statement))
        assert "permission denied" in str(exc.value).lower(), statement
        raw_application_connection.rollback()


def test_the_application_role_cannot_insert_an_instance_directly(
    application_engine, principal_a, workflow
):
    with pytest.raises(ProgrammingError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.lifecycle_instances "
                    "(tenant_id, machine_key, machine_version, current_state) "
                    "VALUES (:t, :k, :v, :s)"
                ),
                {
                    "t": principal_a.id,
                    "k": workflow.machine_key,
                    "v": workflow.version,
                    "s": workflow.initial_state,
                },
            )
    assert "permission denied" in str(exc.value).lower()


@pytest.mark.parametrize("table", LIFECYCLE_TABLES)
def test_row_security_is_enabled_and_forced(owner_engine, table):
    with owner_engine.connect() as connection:
        enabled, forced = connection.execute(
            text(
                "SELECT c.relrowsecurity, c.relforcerowsecurity FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = :s AND c.relname = :t"
            ),
            {"s": SCHEMA, "t": table},
        ).one()
    assert enabled, table
    assert forced, f"{table}: row security is not FORCEd, so the owner is exempt"


def test_the_history_carries_no_update_or_delete_policy_at_all(owner_engine):
    """Append-only in the half a grant cannot buy: even the owner reaches no row."""
    with owner_engine.connect() as connection:
        commands = {
            row[0]
            for row in connection.execute(
                text(
                    "SELECT cmd FROM pg_policies WHERE schemaname = :s AND tablename = "
                    "'lifecycle_transitions'"
                ),
                {"s": SCHEMA},
            ).all()
        }
    assert commands == {"SELECT", "INSERT"}


def test_the_instance_table_carries_no_delete_policy(owner_engine):
    """There is no retention operation in Milestone 2.4, and no role can invent one."""
    with owner_engine.connect() as connection:
        commands = {
            row[0]
            for row in connection.execute(
                text(
                    "SELECT cmd FROM pg_policies WHERE schemaname = :s AND tablename = "
                    "'lifecycle_instances'"
                ),
                {"s": SCHEMA},
            ).all()
        }
    assert commands == {"SELECT", "INSERT", "UPDATE"}


def test_even_the_owner_reaches_no_history_row_to_change(
    owner_engine, application_engine, principal_a, new_instance
):
    position = new_instance(principal_a)
    _advance(application_engine, principal_a, position, "active")

    with auth.authenticated_transaction(owner_engine, principal_a.credential) as session:
        # The owner really can see the row, so a zero rowcount below is the policy and not
        # an empty table.
        assert session.scalar(select(func.count()).select_from(LifecycleTransition)) == 1
        for statement in (
            f"UPDATE {SCHEMA}.lifecycle_transitions SET to_state = 'closed'",
            f"DELETE FROM {SCHEMA}.lifecycle_transitions",
            f"DELETE FROM {SCHEMA}.lifecycle_instances",
        ):
            assert session.execute(text(statement)).rowcount == 0, statement

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert lifecycle_history(session, position.id)[0].to_state == "active"


# -------------------------------------------------------------- composite foreign keys


#: A history ``INSERT`` written out in full, as the owner under a valid context.
#:
#: The context is required twice over: the ``INSERT`` policy binds the owner because row
#: security is ``FORCE``d, and it additionally requires every derived column to agree with
#: the authenticated actor. So each statement below carries the *correct* tenant, actor kind,
#: principal and binding, and differs from a legitimate row in exactly the one respect under
#: test -- which is what makes the refusal attributable to the constraint named rather than
#: to the policy.
_HISTORY_INSERT = (
    f"INSERT INTO {SCHEMA}.lifecycle_transitions "
    "(tenant_id, lifecycle_instance_id, machine_key, machine_version, "
    "from_state, to_state, from_revision, to_revision, "
    "actor_kind, actor_principal_id, actor_binding_id) "
    "VALUES (:t, :i, :k, :v, :f, :s, :fr, :tr, 'credential', :p, :b)"
)


def _forge_history(owner_engine, principal, **values):
    """Attempt one hand-written history row as the owner, in the principal's tenant."""
    parameters = {
        "t": principal.id,
        "p": principal.principal_id,
        "b": principal.binding_id,
        "fr": 0,
        "tr": 1,
    }
    parameters.update(values)
    with auth.authenticated_transaction(owner_engine, principal.credential) as session:
        session.execute(text(_HISTORY_INSERT), parameters)


def test_a_history_row_cannot_point_at_another_tenants_instance(
    owner_engine, principal_a, principal_b, new_instance
):
    """The composite reference, because referential integrity bypasses row security.

    A single-column ``REFERENCES lifecycle_instances(id)`` would have accepted this: tenant
    B's instance id is perfectly valid there, and the FK check does not evaluate policies.
    """
    victim = new_instance(principal_b)
    with pytest.raises(IntegrityError) as exc:
        _forge_history(
            owner_engine,
            principal_a,
            i=victim.id,
            k=victim.machine_key,
            v=victim.machine_version,
            f="draft",
            s="active",
        )
    assert "foreign key" in str(exc.value).lower()


def test_a_history_row_cannot_claim_a_different_machine_than_its_instance(
    owner_engine, principal_a, new_instance
):
    """Cross-machine fabrication, refused structurally rather than by a check in code."""
    position = new_instance(principal_a, TEST_WORKFLOW)
    with pytest.raises(IntegrityError) as exc:
        _forge_history(
            owner_engine,
            principal_a,
            i=position.id,
            k=TEST_CYCLIC.machine_key,
            v=TEST_CYCLIC.version,
            f="idle",
            s="idle",
        )
    assert "foreign key" in str(exc.value).lower()


def test_a_history_row_cannot_record_an_edge_the_machine_does_not_have(
    owner_engine, principal_a, new_instance
):
    """The graph, in the history. ``draft -> closed`` is not an edge of version 1.

    So "an invalid transition leaves no history" is a referential fact and not only a
    property of the function that refuses one.
    """
    position = new_instance(principal_a, TEST_WORKFLOW)
    with pytest.raises(IntegrityError) as exc:
        _forge_history(
            owner_engine,
            principal_a,
            i=position.id,
            k=position.machine_key,
            v=position.machine_version,
            f="draft",
            s="closed",
        )
    assert "foreign key" in str(exc.value).lower()


def test_two_history_rows_cannot_claim_the_same_revision(
    owner_engine, application_engine, principal_a, new_instance
):
    """One row per revision, which is what makes the history a total order.

    Two accounts of revision 1 would be two accounts of the same moment.
    """
    position = new_instance(principal_a)
    _advance(application_engine, principal_a, position, "active")

    with pytest.raises(IntegrityError) as exc:
        _forge_history(
            owner_engine,
            principal_a,
            i=position.id,
            k=position.machine_key,
            v=position.machine_version,
            f="draft",
            s="cancelled",
        )
    assert "uq_lifecycle_transitions_tenant_id_instance_id_to_revision" in str(exc.value)


def test_a_history_rows_revision_pair_must_advance_by_one(owner_engine, principal_a, new_instance):
    position = new_instance(principal_a)
    with pytest.raises(IntegrityError) as exc:
        _forge_history(
            owner_engine,
            principal_a,
            i=position.id,
            k=position.machine_key,
            v=position.machine_version,
            f="draft",
            s="active",
            fr=0,
            tr=5,
        )
    assert "revision_advances_by_one" in str(exc.value)


def test_a_history_row_cannot_be_attributed_to_another_actor(
    owner_engine, principal_a, principal_b, new_instance
):
    """The actor is derived, and the insert policy re-derives it.

    The owner is the only identity that can issue this statement at all, and it still
    cannot write a row saying somebody else made the move.
    """
    position = new_instance(principal_a)
    with pytest.raises(DBAPIError) as exc:
        _forge_history(
            owner_engine,
            principal_a,
            i=position.id,
            k=position.machine_key,
            v=position.machine_version,
            f="draft",
            s="active",
            p=principal_b.principal_id,
        )
    assert "row-level security" in str(exc.value).lower()


def test_the_instance_state_column_references_the_declared_state_set(owner_engine):
    """An instance cannot hold a state its machine version does not declare.

    Asserted from the catalogue rather than by attempting a violation, and the reason is
    worth recording: the ``BEFORE INSERT`` trigger refuses a non-initial state before the
    foreign key is ever consulted, and the ``BEFORE UPDATE`` trigger refuses an undeclared
    target as a missing edge. So the key is unreachable in practice -- which is the correct
    layering and makes it defence in depth rather than the first line. What matters is that
    it is **there**, composite, and pointed at the state set, so that a future writer added
    without those triggers still cannot store a state the machine does not have.
    """
    with owner_engine.connect() as connection:
        definition = connection.execute(
            text(
                "SELECT pg_get_constraintdef(con.oid) FROM pg_constraint con "
                "JOIN pg_class c ON c.oid = con.conrelid "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = :s AND c.relname = 'lifecycle_instances' "
                "AND con.conname = 'fk_lifecycle_instances_state_lifecycle_states'"
            ),
            {"s": SCHEMA},
        ).scalar_one()
    assert "machine_key, machine_version, current_state" in definition
    assert "lifecycle_states" in definition
