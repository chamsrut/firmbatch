"""A machine definition is protected, versioned, and immutable once registered.

The definition is the thing every other lifecycle property rests on. An instance is only in
a legal state because a state row says so; a transition is only legal because an edge row
says so; a caller is only permitted to move one because a machine row says which capability
it takes. So this module asserts, in order:

* the **integrity rules** a definition has to satisfy, in Python and again in PostgreSQL --
  because the Python registrar is the supported interface and the schema is what holds when
  somebody writes the inserts by hand;
* that a registered version is **immutable**, for the schema owner as well as for every
  runtime role;
* that a change is a **new version**, and that an existing instance is unaffected by one;
* that migration ``0004`` seeds **no machine at all**, so the test-only definitions this
  suite installs leave nothing behind in a fresh database.

The refusals are checked for what they say as well as for happening: a definition names
states, and a state name is caller-supplied text that reaches a stored history row and a
``jsonb`` audit document, so no refusal here may repeat one.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from firmbatch.control_plane import migrate
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.lifecycle import (
    LifecycleDefinition,
    LifecycleDefinitionError,
    register_lifecycle_definition,
    registered_lifecycle_machines,
    validated_lifecycle_definition,
)
from firmbatch.control_plane.db.models import (
    IMMUTABLE_DEFINITION_TABLES,
    MAX_LIFECYCLE_STATES,
    MAX_LIFECYCLE_TRANSITIONS,
)
from firmbatch.control_plane.security.authorization import Scope
from firmbatch.control_plane.testing.bootstrap import create_disposable_database, drop_disposable_database

from .conftest import TEST_WORKFLOW, exception_chain

#: A well-formed definition nothing else in the suite registers, so a test may break one
#: rule at a time and see only that rule refuse it.
CANDIDATE = LifecycleDefinition(
    machine_key="test_candidate",
    version=1,
    initial_state="one",
    states=("one", "two", "three"),
    terminal_states=("three",),
    transitions=(("one", "two"), ("two", "three")),
    read_scope=Scope.WORKSPACE_READ.value,
    create_scope=Scope.WORKSPACE_WRITE.value,
    transition_scope=Scope.WORKSPACE_WRITE.value,
)


@contextmanager
def owner_transaction(owner_engine):
    """An owner transaction that always rolls back.

    Tests here write definition rows by hand, which is the only way to ask whether the
    *schema* refuses what the registrar refuses. Rolling back keeps the session's disposable
    database exactly as the ``lifecycle_definitions`` fixture left it -- and it has to be a
    rollback rather than a cleanup ``DELETE``, because these tables refuse ``DELETE`` for
    every role including this one.
    """
    with owner_engine.connect() as connection:
        transaction = connection.begin()
        try:
            yield connection
        finally:
            transaction.rollback()


def _insert_machine(connection, definition: LifecycleDefinition) -> None:
    connection.execute(
        text(
            f"INSERT INTO {SCHEMA}.lifecycle_machines "
            "(machine_key, version, read_scope, create_scope, transition_scope) "
            "VALUES (:k, :v, :r, :c, :t)"
        ),
        {
            "k": definition.machine_key,
            "v": definition.version,
            "r": definition.read_scope,
            "c": definition.create_scope,
            "t": definition.transition_scope,
        },
    )


def _insert_state(connection, definition, state, *, initial=False, terminal=False) -> None:
    connection.execute(
        text(
            f"INSERT INTO {SCHEMA}.lifecycle_states "
            "(machine_key, machine_version, state, is_initial, is_terminal) "
            "VALUES (:k, :v, :s, :i, :t)"
        ),
        {
            "k": definition.machine_key,
            "v": definition.version,
            "s": state,
            "i": initial,
            "t": terminal,
        },
    )


def _insert_edge(connection, definition, source, target) -> None:
    connection.execute(
        text(
            f"INSERT INTO {SCHEMA}.lifecycle_transition_edges "
            "(machine_key, machine_version, from_state, to_state) VALUES (:k, :v, :f, :t)"
        ),
        {"k": definition.machine_key, "v": definition.version, "f": source, "t": target},
    )


# --------------------------------------------------------------- the Python integrity rules


def test_a_well_formed_definition_is_accepted_unchanged():
    """The control. Without it every refusal below could be a validator that refuses all."""
    checked = validated_lifecycle_definition(CANDIDATE)
    assert checked == CANDIDATE


def test_a_definition_with_no_states_is_refused():
    with pytest.raises(LifecycleDefinitionError) as exc:
        validated_lifecycle_definition(replace(CANDIDATE, states=(), transitions=()))
    assert "at least one state" in str(exc.value)


def test_an_initial_state_outside_the_state_set_is_refused():
    with pytest.raises(LifecycleDefinitionError) as exc:
        validated_lifecycle_definition(replace(CANDIDATE, initial_state="elsewhere"))
    assert "not in the declared state set" in str(exc.value)
    assert "elsewhere" not in exception_chain(exc.value)


def test_a_duplicate_state_is_refused():
    with pytest.raises(LifecycleDefinitionError) as exc:
        validated_lifecycle_definition(replace(CANDIDATE, states=("one", "two", "two")))
    assert "repeats a state" in str(exc.value)


def test_a_duplicate_edge_is_refused():
    with pytest.raises(LifecycleDefinitionError) as exc:
        validated_lifecycle_definition(
            replace(CANDIDATE, transitions=(("one", "two"), ("two", "three"), ("one", "two")))
        )
    assert "declared twice" in str(exc.value)
    assert "position 2" in str(exc.value)


def test_an_edge_from_an_unknown_state_is_refused():
    with pytest.raises(LifecycleDefinitionError) as exc:
        validated_lifecycle_definition(replace(CANDIDATE, transitions=(("nowhere", "two"),)))
    assert "starts from a state that is not declared" in str(exc.value)
    assert "nowhere" not in exception_chain(exc.value)


def test_an_edge_to_an_unknown_state_is_refused():
    with pytest.raises(LifecycleDefinitionError) as exc:
        validated_lifecycle_definition(replace(CANDIDATE, transitions=(("one", "nowhere"),)))
    assert "ends at a state that is not declared" in str(exc.value)
    assert "nowhere" not in exception_chain(exc.value)


def test_an_edge_out_of_a_terminal_state_is_refused():
    """The one graph rule this kernel imposes beyond "the states are known"."""
    with pytest.raises(LifecycleDefinitionError) as exc:
        validated_lifecycle_definition(
            replace(CANDIDATE, transitions=CANDIDATE.transitions + (("three", "one"),))
        )
    assert "leaves a terminal state" in str(exc.value)


def test_a_terminal_state_outside_the_state_set_is_refused():
    with pytest.raises(LifecycleDefinitionError) as exc:
        validated_lifecycle_definition(replace(CANDIDATE, terminal_states=("elsewhere",)))
    assert "not in the declared state set" in str(exc.value)


def test_a_non_positive_version_is_refused():
    for version in (0, -1):
        with pytest.raises(LifecycleDefinitionError) as exc:
            validated_lifecycle_definition(replace(CANDIDATE, version=version))
        assert "positive integer" in str(exc.value)


def test_a_boolean_is_not_a_version():
    """``True`` is an ``int`` in Python, and a version of 1 arrived at by accident."""
    with pytest.raises(LifecycleDefinitionError) as exc:
        validated_lifecycle_definition(replace(CANDIDATE, version=True))
    assert "is an integer" in str(exc.value)


def test_a_malformed_machine_key_is_refused_without_being_repeated():
    for key in ("Test-Workflow", "test workflow", "1workflow", "workflow\n", "a" * 64):
        with pytest.raises(LifecycleDefinitionError) as exc:
            validated_lifecycle_definition(replace(CANDIDATE, machine_key=key))
        rendered = exception_chain(exc.value)
        assert "lowercase identifier" in str(exc.value)
        assert key not in rendered, key


def test_a_malformed_state_name_is_refused_by_position():
    with pytest.raises(LifecycleDefinitionError) as exc:
        validated_lifecycle_definition(replace(CANDIDATE, states=("one", "Two", "three")))
    assert "position 1" in str(exc.value)
    assert "Two" not in exception_chain(exc.value)


def test_a_credential_shaped_state_name_is_refused_as_a_shape():
    """The identifier grammar accepts an all-lowercase credential, so the shape test is not
    decoration: a state name reaches a stored history row and an audit document."""
    hostile = "fbk_" + "a" * 43
    with pytest.raises(LifecycleDefinitionError) as exc:
        validated_lifecycle_definition(replace(CANDIDATE, states=(hostile, "two", "three")))
    assert "looks like a Firmbatch bearer credential" in str(exc.value)
    assert hostile not in exception_chain(exc.value)


def test_a_scope_outside_the_eligible_set_is_refused():
    with pytest.raises(LifecycleDefinitionError) as exc:
        validated_lifecycle_definition(replace(CANDIDATE, transition_scope="workspace:destroy"))
    assert "not a scope a lifecycle machine may require" in str(exc.value)
    assert "workspace:destroy" not in exception_chain(exc.value)


def test_tenant_provision_may_not_be_a_lifecycle_scope():
    """It cannot be placed on any credential, so a machine requiring it is unreachable."""
    with pytest.raises(LifecycleDefinitionError) as exc:
        validated_lifecycle_definition(
            replace(CANDIDATE, create_scope=Scope.TENANT_PROVISION.value)
        )
    assert "tenant:provision is excluded deliberately" in str(exc.value)


def test_the_state_and_edge_bounds_are_enforced():
    too_many_states = tuple(f"s{index}" for index in range(MAX_LIFECYCLE_STATES + 1))
    with pytest.raises(LifecycleDefinitionError) as exc:
        validated_lifecycle_definition(
            replace(CANDIDATE, initial_state="s0", states=too_many_states, terminal_states=(), transitions=())
        )
    assert f"over the {MAX_LIFECYCLE_STATES} allowed" in str(exc.value)

    states = tuple(f"s{index}" for index in range(40))
    edges = tuple(
        (source, target) for source in states for target in states
    )[: MAX_LIFECYCLE_TRANSITIONS + 1]
    with pytest.raises(LifecycleDefinitionError) as exc:
        validated_lifecycle_definition(
            replace(CANDIDATE, initial_state="s0", states=states, terminal_states=(), transitions=edges)
        )
    assert f"over the {MAX_LIFECYCLE_TRANSITIONS} allowed" in str(exc.value)


def test_a_cycle_and_a_self_edge_are_both_permitted():
    """Stated as a test rather than as a sentence, so removing the freedom is deliberate.

    A window offer that is revoked and re-offered is a cycle; a move that changes only the
    revision is a self-edge. Neither is a mistake, and a kernel that refused them would have
    to be argued with by every domain that needs one.
    """
    cyclic = replace(
        CANDIDATE,
        terminal_states=(),
        transitions=(("one", "two"), ("two", "one"), ("three", "three")),
    )
    assert validated_lifecycle_definition(cyclic).transitions == cyclic.transitions


def test_an_unreachable_state_is_permitted_and_says_so():
    """A rule this kernel deliberately does not impose.

    ``three`` is declared and no edge leads to it. That is odd and it is not wrong -- a
    definition may be built up across versions -- and diagnosing it is not something a
    foundation is entitled to do on a domain's behalf.
    """
    sparse = replace(CANDIDATE, terminal_states=("three",), transitions=(("one", "two"),))
    assert validated_lifecycle_definition(sparse) == sparse


# ------------------------------------------------------- the same rules, in the database


def test_the_database_refuses_a_second_initial_state(owner_engine, lifecycle_definitions):
    """Exactly one initial state, enforced by a partial unique index rather than by code.

    A trigger would have been enough for the serial registrar and not for two concurrent
    ones: both would see no initial state and both would insert one. Only an index refuses
    that.
    """
    with owner_transaction(owner_engine) as connection:
        _insert_machine(connection, CANDIDATE)
        _insert_state(connection, CANDIDATE, "one", initial=True)
        with pytest.raises(IntegrityError) as exc:
            _insert_state(connection, CANDIDATE, "two", initial=True)
    assert "uq_lifecycle_states_one_initial_per_version" in str(exc.value)


def test_the_database_refuses_an_edge_from_an_unknown_state(owner_engine, lifecycle_definitions):
    """A foreign key, so it holds for the owner and for anything a later migration adds."""
    with owner_transaction(owner_engine) as connection:
        _insert_machine(connection, CANDIDATE)
        _insert_state(connection, CANDIDATE, "one", initial=True)
        with pytest.raises(IntegrityError) as exc:
            _insert_edge(connection, CANDIDATE, "nowhere", "one")
    assert "foreign key" in str(exc.value).lower()


def test_the_database_refuses_an_edge_out_of_a_terminal_state(owner_engine, lifecycle_definitions):
    with owner_transaction(owner_engine) as connection:
        _insert_machine(connection, CANDIDATE)
        _insert_state(connection, CANDIDATE, "one", initial=True)
        _insert_state(connection, CANDIDATE, "three", terminal=True)
        with pytest.raises(DBAPIError) as exc:
            _insert_edge(connection, CANDIDATE, "three", "one")
    assert "terminal lifecycle state may not have an outgoing edge" in str(exc.value)


def test_the_database_refuses_a_duplicate_edge(owner_engine, lifecycle_definitions):
    with owner_transaction(owner_engine) as connection:
        _insert_machine(connection, CANDIDATE)
        _insert_state(connection, CANDIDATE, "one", initial=True)
        _insert_state(connection, CANDIDATE, "two")
        _insert_edge(connection, CANDIDATE, "one", "two")
        with pytest.raises(IntegrityError):
            _insert_edge(connection, CANDIDATE, "one", "two")


def test_the_database_refuses_a_malformed_machine_key_and_state(owner_engine, lifecycle_definitions):
    with owner_transaction(owner_engine) as connection:
        with pytest.raises(IntegrityError) as exc:
            _insert_machine(connection, replace(CANDIDATE, machine_key="Not-A-Key"))
    assert "machine_key_format" in str(exc.value)

    with owner_transaction(owner_engine) as connection:
        _insert_machine(connection, CANDIDATE)
        with pytest.raises(IntegrityError) as exc:
            _insert_state(connection, CANDIDATE, "Not A State", initial=True)
    assert "state_format" in str(exc.value)


def test_the_database_refuses_a_non_positive_version(owner_engine, lifecycle_definitions):
    with owner_transaction(owner_engine) as connection:
        with pytest.raises(IntegrityError) as exc:
            _insert_machine(connection, replace(CANDIDATE, version=0))
    assert "version_positive" in str(exc.value)


def test_the_database_refuses_a_scope_outside_the_eligible_set(owner_engine, lifecycle_definitions):
    """The check constraint behind :data:`LIFECYCLE_ELIGIBLE_SCOPES`.

    Both halves: an invented scope, and ``tenant:provision``, which is a real scope and
    still not one a machine may require.
    """
    for scope in ("workspace:destroy", Scope.TENANT_PROVISION.value):
        with owner_transaction(owner_engine) as connection:
            with pytest.raises(IntegrityError) as exc:
                _insert_machine(connection, replace(CANDIDATE, transition_scope=scope))
        assert "transition_scope_eligible" in str(exc.value), scope


def test_the_database_refuses_a_state_belonging_to_no_machine(owner_engine, lifecycle_definitions):
    """Refused by the publication trigger now, one statement earlier than the foreign key.

    The trigger has to look the machine row up in order to lock it against a concurrent
    publication, so "there is no machine row" is something it discovers before the composite
    foreign key would. The foreign key is still there and is asserted below; what changed is
    which of the two speaks first, and the earlier one gives a better answer.
    """
    with owner_transaction(owner_engine) as connection:
        with pytest.raises(DBAPIError) as exc:
            _insert_state(connection, CANDIDATE, "one", initial=True)
    assert "no such lifecycle machine version" in str(exc.value)


@pytest.mark.parametrize(
    ("table", "constraint"),
    (
        ("lifecycle_states", "fk_lifecycle_states_machine_lifecycle_machines"),
        (
            "lifecycle_transition_edges",
            "fk_lifecycle_transition_edges_from_lifecycle_states",
        ),
    ),
)
def test_the_composite_foreign_key_behind_the_trigger_is_still_there(
    owner_engine, table, constraint
):
    """The backstop the trigger now speaks ahead of, asserted from the catalogue.

    A trigger is ordinary DML enforcement and a foreign key is not: referential integrity is
    checked with row security bypassed and cannot be disabled by a session setting. So the
    test above must not be read as evidence that the constraint was replaced.
    """
    with owner_engine.connect() as connection:
        assert connection.execute(
            text(
                "SELECT count(*) FROM pg_catalog.pg_constraint c "
                "JOIN pg_catalog.pg_class t ON t.oid = c.conrelid "
                "JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace "
                "WHERE n.nspname = :schema AND t.relname = :table "
                "AND c.conname = :constraint AND c.contype = 'f'"
            ),
            {"schema": SCHEMA, "table": table, "constraint": constraint},
        ).scalar_one() == 1


# ------------------------------------------------------------------------- immutability


def test_a_registered_version_cannot_be_registered_again(owner_engine, lifecycle_definitions):
    """A change is a new version. The refusal names the rule and not the machine."""
    with owner_transaction(owner_engine) as connection:
        with pytest.raises(LifecycleDefinitionError) as exc:
            register_lifecycle_definition(connection, TEST_WORKFLOW)
    assert "already registered" in str(exc.value)
    assert "immutable" in str(exc.value)


def test_a_registered_version_cannot_be_registered_again_with_a_different_graph(
    owner_engine, lifecycle_definitions
):
    """The dangerous shape of the same mistake: same key and version, different edges.

    Silently merging this would leave a machine whose graph nobody had reviewed and whose
    existing instances were suddenly interpreted against it.
    """
    altered = replace(TEST_WORKFLOW, transitions=TEST_WORKFLOW.transitions + (("draft", "closed"),))
    with owner_transaction(owner_engine) as connection:
        with pytest.raises(LifecycleDefinitionError):
            register_lifecycle_definition(connection, altered)


@pytest.mark.parametrize("table", sorted(IMMUTABLE_DEFINITION_TABLES))
def test_not_even_the_owner_can_revise_a_definition(owner_engine, lifecycle_definitions, table):
    """A row trigger, so this binds the schema owner -- which no grant or policy could.

    The owner holds every privilege on these tables and row security is not enabled on them
    at all, so nothing but the trigger stands between an ``UPDATE`` and a machine whose
    meaning changed under the instances already running it.

    The refusals differ by table on purpose. A state or an edge has **no** legal update, so
    both statements meet the blanket immutability trigger. A machine row has exactly one --
    its publication -- so its update goes through a trigger that permits that transition and
    refuses every other, which is what makes unpublishing and metadata edits impossible
    rather than merely undone.

    **What this does not claim**, and it is worth saying where the test is: a trigger binds
    ordinary DML. It does not bind a superuser, and it does not bind an owner who first runs
    ``ALTER TABLE ... DISABLE TRIGGER``. Both are deliberate DDL-shaped acts by a role that
    already owns the definitions; see ADR 0007.
    """
    for statement, expected in (
        (
            f"UPDATE {SCHEMA}.{table} SET machine_key = machine_key",
            "publication" if table == "lifecycle_machines" else "immutable",
        ),
        (f"DELETE FROM {SCHEMA}.{table}", "immutable"),
    ):
        with owner_transaction(owner_engine) as connection:
            with pytest.raises(DBAPIError) as exc:
                connection.execute(text(statement))
        assert expected in str(exc.value), statement


def test_the_owner_can_read_a_definition_so_the_refusals_mean_something(
    owner_engine, lifecycle_definitions
):
    """A positive control. Without it every refusal above could be an empty table."""
    with owner_engine.connect() as connection:
        states = set(
            connection.execute(
                text(
                    f"SELECT state FROM {SCHEMA}.lifecycle_states "
                    "WHERE machine_key = :k AND machine_version = :v"
                ),
                {"k": TEST_WORKFLOW.machine_key, "v": TEST_WORKFLOW.version},
            ).scalars()
        )
        edges = set(
            connection.execute(
                text(
                    f"SELECT from_state, to_state FROM {SCHEMA}.lifecycle_transition_edges "
                    "WHERE machine_key = :k AND machine_version = :v"
                ),
                {"k": TEST_WORKFLOW.machine_key, "v": TEST_WORKFLOW.version},
            ).all()
        )
    assert states == set(TEST_WORKFLOW.states)
    assert edges == {tuple(edge) for edge in TEST_WORKFLOW.transitions}


def test_two_versions_of_one_machine_coexist_with_different_graphs(
    owner_engine, lifecycle_definitions
):
    """Versioning, as rows. ``draft -> cancelled`` exists in version 1 and not in version 2."""
    with owner_engine.connect() as connection:
        edges = {
            (version, source, target)
            for version, source, target in connection.execute(
                text(
                    f"SELECT machine_version, from_state, to_state FROM "
                    f"{SCHEMA}.lifecycle_transition_edges WHERE machine_key = :k"
                ),
                {"k": TEST_WORKFLOW.machine_key},
            ).all()
        }
    assert (1, "draft", "cancelled") in edges
    assert (2, "draft", "cancelled") not in edges
    assert (2, "draft", "active") in edges


# ------------------------------------------------------- nothing is seeded into production


def test_a_fresh_database_carries_no_lifecycle_definition(environment):
    """Migration ``0004`` registers **no machine**, and that is the assertion.

    The job lifecycle and the window-offer machine are Milestone 5 and 6 definitions,
    registered alongside the domain tables they describe. A demonstration graph seeded here
    would be a product decision taken by a foundation, and it would arrive in every
    production database.

    Runs on its own disposable database, so what it observes is the migration's output and
    not the state this suite's fixtures left behind.
    """
    handle = create_disposable_database(environment)
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, _expected):
            assert registered_lifecycle_machines(connection) == ()
            for table in sorted(IMMUTABLE_DEFINITION_TABLES):
                assert connection.execute(
                    text(f"SELECT count(*) FROM {SCHEMA}.{table}")
                ).scalar_one() == 0, table
    finally:
        drop_disposable_database(handle)


def test_the_suite_registered_exactly_the_test_only_machines(owner_engine, lifecycle_definitions):
    """And every one of them is named so that it could not be mistaken for a product machine."""
    with owner_engine.connect() as connection:
        registered = registered_lifecycle_machines(connection)
    assert set(registered) == set(lifecycle_definitions)
    for machine_key, _version in registered:
        assert machine_key.startswith("test_"), machine_key


# ------------------------------- draft, then publish (review finding 4)
#
# A definition is assembled over several statements and is only usable once, at the end, it
# is **published**. That boundary is what makes "only complete definitions are consumable" a
# fact rather than a convention: every consumer goes through a reader that requires
# ``published_at``, and publication is the last statement of registration.
#
# It is also where whole-graph properties are checked. *At least one initial state* is
# exactly such a property: a partial unique index bounds it at one and cannot require that
# one exists, the same limit the Milestone 2.2 outbox link has.


def yield_partial(connection, definition):
    """Insert the machine and its states and stop -- a draft, never published."""
    _insert_machine(connection, definition)
    for state in definition.states:
        _insert_state(
            connection,
            definition,
            state,
            initial=state == definition.initial_state,
            terminal=state in set(definition.terminal_states),
        )


def test_a_machine_with_no_initial_state_cannot_be_published(owner_engine, lifecycle_definitions):
    """The property a unique index cannot state: at least one.

    Checked at publication, because that is the only moment the definition claims to be
    complete. Before it, "no initial state yet" is an ordinary intermediate step.
    """
    with owner_transaction(owner_engine) as connection:
        _insert_machine(connection, CANDIDATE)
        for state in CANDIDATE.states:
            _insert_state(connection, CANDIDATE, state)  # none marked initial
        with pytest.raises(DBAPIError) as exc:
            connection.execute(
                text(f"SELECT {SCHEMA}.publish_lifecycle_machine(:k, :v)"),
                {"k": CANDIDATE.machine_key, "v": CANDIDATE.version},
            )
    assert "exactly one initial state, not 0" in str(exc.value)


def test_a_machine_with_no_states_at_all_cannot_be_published(owner_engine, lifecycle_definitions):
    with owner_transaction(owner_engine) as connection:
        _insert_machine(connection, CANDIDATE)
        with pytest.raises(DBAPIError) as exc:
            connection.execute(
                text(f"SELECT {SCHEMA}.publish_lifecycle_machine(:k, :v)"),
                {"k": CANDIDATE.machine_key, "v": CANDIDATE.version},
            )
    assert "at least one state" in str(exc.value)


def test_two_initial_states_cannot_even_be_written(owner_engine, lifecycle_definitions):
    """The other side of the same rule, and it is refused earlier -- by the index.

    So "exactly one" is two mechanisms: the index bounds it above at insert time, and
    publication bounds it below once the definition is finished.
    """
    with owner_transaction(owner_engine) as connection:
        _insert_machine(connection, CANDIDATE)
        _insert_state(connection, CANDIDATE, "one", initial=True)
        with pytest.raises(IntegrityError) as exc:
            _insert_state(connection, CANDIDATE, "two", initial=True)
    assert "uq_lifecycle_states_one_initial_per_version" in str(exc.value)


def test_publication_refuses_an_outgoing_edge_from_a_terminal_state(
    owner_engine, lifecycle_definitions
):
    """The whole-graph check, exercised by marking the source terminal before publishing.

    The insert trigger already refuses an edge whose source is *already* terminal. This is
    the completed-graph check that backs it up, and it is what a registrar which wrote its
    states in a different order would meet.
    """
    with owner_transaction(owner_engine) as connection:
        _insert_machine(connection, CANDIDATE)
        _insert_state(connection, CANDIDATE, "one", initial=True)
        _insert_state(connection, CANDIDATE, "two", terminal=True)
        with pytest.raises(DBAPIError) as exc:
            _insert_edge(connection, CANDIDATE, "two", "one")
    assert "terminal lifecycle state may not have an outgoing edge" in str(exc.value)


def test_a_published_machine_cannot_gain_a_state_or_an_edge(owner_engine, lifecycle_definitions):
    """Sealed in the one direction the immutability trigger does not cover.

    ``UPDATE`` and ``DELETE`` are refused outright; ``INSERT`` is refused once the machine is
    published, which is what stops an edge being added to a graph that instances are already
    running.
    """
    for statement, parameters in (
        (
            f"INSERT INTO {SCHEMA}.lifecycle_states "
            "(machine_key, machine_version, state) VALUES (:k, 1, 'sneaked')",
            {"k": TEST_WORKFLOW.machine_key},
        ),
        (
            f"INSERT INTO {SCHEMA}.lifecycle_transition_edges "
            "(machine_key, machine_version, from_state, to_state) "
            "VALUES (:k, 1, 'draft', 'closed')",
            {"k": TEST_WORKFLOW.machine_key},
        ),
    ):
        with owner_transaction(owner_engine) as connection:
            with pytest.raises(DBAPIError) as exc:
                connection.execute(text(statement), parameters)
        assert "published lifecycle machine version cannot gain" in str(exc.value), statement


def test_a_published_machine_cannot_be_unpublished_or_republished(
    owner_engine, lifecycle_definitions
):
    """The only legal update is the one that publishes, and it happens once."""
    for statement in (
        f"UPDATE {SCHEMA}.lifecycle_machines SET published_at = NULL "
        "WHERE machine_key = 'test_workflow'",
        f"UPDATE {SCHEMA}.lifecycle_machines SET published_at = now() "
        "WHERE machine_key = 'test_workflow'",
        f"UPDATE {SCHEMA}.lifecycle_machines SET transition_scope = 'workspace:read' "
        "WHERE machine_key = 'test_workflow'",
    ):
        with owner_transaction(owner_engine) as connection:
            with pytest.raises(DBAPIError) as exc:
                connection.execute(text(statement))
        assert "only legal update" in str(exc.value), statement

    with owner_transaction(owner_engine) as connection:
        with pytest.raises(DBAPIError) as exc:
            connection.execute(
                text(f"SELECT {SCHEMA}.publish_lifecycle_machine('test_workflow', 1)")
            )
    assert "already published" in str(exc.value)


def test_an_unpublished_machine_is_invisible_to_every_consumer(owner_engine, lifecycle_definitions):
    """A draft has no scope, no initial state, no terminal states and no edges.

    Which is what makes a failed registration harmless before the rollback even happens: a
    concurrent reader never resolves a half-built graph at any instant.
    """
    with owner_transaction(owner_engine) as connection:
        _insert_machine(connection, CANDIDATE)
        for state in CANDIDATE.states:
            _insert_state(
                connection,
                CANDIDATE,
                state,
                initial=state == CANDIDATE.initial_state,
                terminal=state in set(CANDIDATE.terminal_states),
            )
        for source, target in CANDIDATE.transitions:
            _insert_edge(connection, CANDIDATE, source, target)

        key, version = CANDIDATE.machine_key, CANDIDATE.version
        assert connection.execute(
            text(f"SELECT {SCHEMA}.lifecycle_required_scope(:k, :v, 'create')"),
            {"k": key, "v": version},
        ).scalar_one() is None
        assert connection.execute(
            text(f"SELECT {SCHEMA}.lifecycle_initial_state(:k, :v)"), {"k": key, "v": version}
        ).scalar_one() is None
        assert connection.execute(
            text(f"SELECT {SCHEMA}.lifecycle_state_is_terminal(:k, :v, 'three')"),
            {"k": key, "v": version},
        ).scalar_one() is False
        assert connection.execute(
            text(f"SELECT {SCHEMA}.lifecycle_edge_exists(:k, :v, 'one', 'two')"),
            {"k": key, "v": version},
        ).scalar_one() is False
        # And it is not a registered machine as far as the registrar's own reader is
        # concerned either.
        assert (key, version) not in registered_lifecycle_machines(connection)

        # Publication makes all four answer.
        connection.execute(
            text(f"SELECT {SCHEMA}.publish_lifecycle_machine(:k, :v)"), {"k": key, "v": version}
        )
        assert connection.execute(
            text(f"SELECT {SCHEMA}.lifecycle_initial_state(:k, :v)"), {"k": key, "v": version}
        ).scalar_one() == CANDIDATE.initial_state
        assert connection.execute(
            text(f"SELECT {SCHEMA}.lifecycle_edge_exists(:k, :v, 'one', 'two')"),
            {"k": key, "v": version},
        ).scalar_one() is True


#: A machine that is deliberately left as a **draft** in the session's database, forever.
#:
#: There is no way to remove one -- the definition tables refuse ``DELETE`` for every role,
#: which is the point of the immutability trigger -- so a draft installed for a test is a
#: draft the database keeps. That is fine and is itself worth having: it is a standing
#: example of a definition that exists and is not consumable, and the tests below assert
#: exactly that about it.
DRAFT = replace(CANDIDATE, machine_key="test_unpublished")


def test_an_instance_cannot_be_created_of_an_unpublished_machine(
    owner_engine, application_engine, principal_a, lifecycle_definitions
):
    """The consumer that matters most, asserted through the ordinary entry point.

    The machine is complete -- every state, every edge -- and simply not published. It reads
    to ``create_lifecycle_instance`` exactly as a machine that was never registered does,
    which is what "only complete definitions are consumable" has to mean at the boundary a
    caller actually touches.
    """
    from firmbatch.control_plane.db import auth
    from firmbatch.control_plane.db.lifecycle import create_lifecycle_instance

    with owner_engine.connect() as connection:
        if not connection.execute(
            text(
                f"SELECT count(*) FROM {SCHEMA}.lifecycle_machines "
                "WHERE machine_key = :k AND version = :v"
            ),
            {"k": DRAFT.machine_key, "v": DRAFT.version},
        ).scalar_one():
            yield_partial(connection, DRAFT)
            for source, target in DRAFT.transitions:
                _insert_edge(connection, DRAFT, source, target)
            connection.commit()

    with pytest.raises(LifecycleDefinitionError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            create_lifecycle_instance(
                session, machine_key=DRAFT.machine_key, machine_version=DRAFT.version
            )
    assert "no such lifecycle machine version is registered" in str(exc.value)

    # And it is still a draft afterwards: nothing about being asked for publishes it.
    with owner_engine.connect() as connection:
        assert (DRAFT.machine_key, DRAFT.version) not in registered_lifecycle_machines(connection)


def test_registration_refuses_an_autocommit_connection(environment):
    """Under AUTOCOMMIT each statement is durable on its own.

    A registration that failed at its fourth statement would leave three committed rows
    behind -- a machine with some of its states -- which no rollback could take back.
    Refused before anything is written.
    """
    handle = create_disposable_database(environment)
    try:
        engine = migrate.create_migration_engine(handle.migration_url)
        try:
            with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
                with pytest.raises(LifecycleDefinitionError) as exc:
                    register_lifecycle_definition(connection, CANDIDATE)
                assert "AUTOCOMMIT" in str(exc.value)
                assert connection.execute(
                    text(f"SELECT count(*) FROM {SCHEMA}.lifecycle_machines")
                ).scalar_one() == 0
        finally:
            engine.dispose()
    finally:
        drop_disposable_database(handle)


def test_publication_refuses_a_definition_assembled_across_transactions(environment):
    """The database's own check, and the one that actually holds.

    Every row of the definition must carry *this* transaction's ``xmin``. A machine whose
    states committed in one transaction and whose edges committed in another was, for a
    while, a publishable definition that no single rollback could take back -- so publication
    refuses it however it got there, including through an AUTOCOMMIT connection that got
    past the Python check.
    """
    handle = create_disposable_database(environment)
    try:
        engine = migrate.create_migration_engine(handle.migration_url)
        try:
            with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
                _insert_machine(connection, CANDIDATE)
                for state in CANDIDATE.states:
                    _insert_state(
                        connection,
                        CANDIDATE,
                        state,
                        initial=state == CANDIDATE.initial_state,
                        terminal=state in set(CANDIDATE.terminal_states),
                    )
                with pytest.raises(DBAPIError) as exc:
                    connection.execute(
                        text(f"SELECT {SCHEMA}.publish_lifecycle_machine(:k, :v)"),
                        {"k": CANDIDATE.machine_key, "v": CANDIDATE.version},
                    )
                assert "registered and published in one transaction" in str(exc.value)
                # And the draft is still a draft: nothing consumes it.
                assert registered_lifecycle_machines(connection) == ()
        finally:
            engine.dispose()
    finally:
        drop_disposable_database(handle)


def test_a_failed_registration_leaves_nothing_behind(environment):
    """The rollback case, on its own database, checked after the transaction ends.

    The definition is refused at its last statement -- publication, because no state was
    marked initial -- and the whole transaction goes back. What is asserted is that the
    database afterwards has no trace of it, published or otherwise.
    """
    handle = create_disposable_database(environment)
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, _expected):
            _insert_machine(connection, CANDIDATE)
            for state in CANDIDATE.states:
                _insert_state(connection, CANDIDATE, state)  # no initial state
            with pytest.raises(DBAPIError):
                connection.execute(
                    text(f"SELECT {SCHEMA}.publish_lifecycle_machine(:k, :v)"),
                    {"k": CANDIDATE.machine_key, "v": CANDIDATE.version},
                )
            connection.rollback()

            assert registered_lifecycle_machines(connection) == ()
            assert connection.execute(
                text(f"SELECT count(*) FROM {SCHEMA}.lifecycle_machines")
            ).scalar_one() == 0
            assert connection.execute(
                text(f"SELECT count(*) FROM {SCHEMA}.lifecycle_states")
            ).scalar_one() == 0
    finally:
        drop_disposable_database(handle)


def test_a_registered_machine_is_published_by_the_registrar(owner_engine, lifecycle_definitions):
    """The control: the supported path leaves a published machine, not a draft.

    Scoped to the machines the fixture registered, because a draft installed by the test
    above is also in this table -- and its being unpublished is the property that test
    exists for.
    """
    with owner_engine.connect() as connection:
        rows = {
            (row.machine_key, row.version): row.published
            for row in connection.execute(
                text(
                    f"SELECT machine_key, version, published_at IS NOT NULL AS published "
                    f"FROM {SCHEMA}.lifecycle_machines"
                )
            ).all()
        }
    assert lifecycle_definitions, "the fixture registered nothing"
    for key in lifecycle_definitions:
        assert rows[key] is True, key


# ------------------------- publication is a boundary, not a path (review finding 4)
#
# The rules used to live inside ``publish_lifecycle_machine()``, and a function is a path
# rather than a boundary: they applied to callers who chose to come through it. The schema
# owner -- the only identity that can reach these tables at all -- could publish an arbitrary
# graph with a plain ``UPDATE``, and every consumer would then resolve it.
#
# They live in the ``BEFORE UPDATE`` trigger now, which is on the one place a row's
# publication column can change. These tests go at that boundary directly, with hand-written
# SQL, so what they establish is a property of the *table* rather than of the supported path.


def _draft_machine(connection, definition, *, initial=True, edges=True) -> None:
    """Assemble a machine in this transaction, up to but not including publication."""
    _insert_machine(connection, definition)
    for state in definition.states:
        _insert_state(
            connection,
            definition,
            state,
            initial=initial and state == definition.initial_state,
            terminal=state in definition.terminal_states,
        )
    if edges:
        for source, target in definition.transitions:
            _insert_edge(connection, definition, source, target)


def _publish_directly(connection, definition, *, when="now()") -> None:
    connection.execute(
        text(
            f"UPDATE {SCHEMA}.lifecycle_machines SET published_at = {when} "
            "WHERE machine_key = :k AND version = :v"
        ),
        {"k": definition.machine_key, "v": definition.version},
    )


def test_a_machine_cannot_be_inserted_already_published(owner_engine, lifecycle_definitions):
    """**The door beside the boundary.**

    Every publication rule is attached to the update that publishes, so a row that arrived
    *already* published would never have been validated at all: no states, no edges, no
    initial state, and every consumer resolving it. Refused at insert.
    """
    with owner_transaction(owner_engine) as connection:
        with pytest.raises(DBAPIError) as exc:
            connection.execute(
                text(
                    f"INSERT INTO {SCHEMA}.lifecycle_machines "
                    "(machine_key, version, read_scope, create_scope, transition_scope, published_at) "
                    "VALUES (:k, :v, :r, :c, :t, now())"
                ),
                {
                    "k": CANDIDATE.machine_key,
                    "v": CANDIDATE.version,
                    "r": CANDIDATE.read_scope,
                    "c": CANDIDATE.create_scope,
                    "t": CANDIDATE.transition_scope,
                },
            )
    assert "inserted unpublished" in str(exc.value)


def test_a_direct_update_is_refused_by_the_same_whole_graph_check_the_function_uses(
    owner_engine, lifecycle_definitions
):
    """A hand-written ``UPDATE`` publishing an incomplete graph is refused.

    No initial state, so the definition is not complete -- and the check that says so is the
    one the supported function used to own. The control below shows the refusal is the
    validation working rather than the update being blocked outright.
    """
    with owner_transaction(owner_engine) as connection:
        _draft_machine(connection, CANDIDATE, initial=False)
        with pytest.raises(DBAPIError) as exc:
            _publish_directly(connection, CANDIDATE)
    assert "exactly one initial state" in str(exc.value)


def test_a_direct_update_publishes_a_complete_graph_assembled_in_one_transaction(
    owner_engine, lifecycle_definitions
):
    """The control for the test above, and the other half of "the same validation".

    A boundary that refused every direct update would prove nothing about the rules; it
    would prove that the path was closed. This one is accepted, by exactly the checks the
    function used to make.
    """
    with owner_transaction(owner_engine) as connection:
        _draft_machine(connection, CANDIDATE)
        _publish_directly(connection, CANDIDATE)
        assert connection.execute(
            text(
                f"SELECT published_at IS NOT NULL FROM {SCHEMA}.lifecycle_machines "
                "WHERE machine_key = :k AND version = :v"
            ),
            {"k": CANDIDATE.machine_key, "v": CANDIDATE.version},
        ).scalar_one() is True


def test_a_direct_update_cannot_publish_a_graph_assembled_across_transactions(environment):
    """The ``xmin`` rule, on the direct path rather than through the function.

    A committed draft is a definition whose pieces became durable independently, so a failure
    during registration could not have taken them back. Publishing one is refused however it
    is attempted -- which is also the second half of the publication race below: a child row
    another transaction committed carries that transaction's id and is refused here.
    """
    handle = create_disposable_database(environment)
    try:
        engine = migrate.create_migration_engine(handle.migration_url)
        try:
            with engine.connect() as connection:
                _draft_machine(connection, CANDIDATE)
                connection.commit()
            with engine.connect() as connection:
                with pytest.raises(DBAPIError) as exc:
                    _publish_directly(connection, CANDIDATE)
                assert "registered and published in one transaction" in str(exc.value)
                connection.rollback()
                assert registered_lifecycle_machines(connection) == ()
        finally:
            engine.dispose()
    finally:
        drop_disposable_database(handle)


def test_the_publication_instant_is_the_servers_and_not_the_callers(
    owner_engine, lifecycle_definitions
):
    """A caller that could date a publication could date it into the past or the future.

    ``published_at`` is what every consumer tests, so it is overwritten with
    ``clock_timestamp()`` on the way through the trigger rather than taken from the
    statement.
    """
    with owner_transaction(owner_engine) as connection:
        _draft_machine(connection, CANDIDATE)
        _publish_directly(connection, CANDIDATE, when="TIMESTAMPTZ '1999-01-01 00:00:00+00'")
        published = connection.execute(
            text(
                f"SELECT published_at FROM {SCHEMA}.lifecycle_machines "
                "WHERE machine_key = :k AND version = :v"
            ),
            {"k": CANDIDATE.machine_key, "v": CANDIDATE.version},
        ).scalar_one()
        assert published.year > 2000, published


def test_publication_takes_the_machine_row_lock_before_it_looks_at_the_graph(owner_engine):
    """Asserted on the function and the trigger bodies, because the *order* is the property.

    Reading the publication column without a lock is not deciding on it: a concurrent state
    or edge insert can commit between the read and the decision. Both sides take
    ``FOR UPDATE`` on the machine row -- the one lockable object in this design, so there is
    one order and nothing to deadlock against -- and both take it before they inspect
    anything.
    """
    with owner_engine.connect() as connection:
        bodies = {
            row.proname: row.prosrc
            for row in connection.execute(
                text(
                    "SELECT p.proname, p.prosrc FROM pg_catalog.pg_proc p "
                    "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = :s AND p.proname = ANY(:names)"
                ),
                {
                    "s": SCHEMA,
                    "names": [
                        "publish_lifecycle_machine",
                        "lifecycle_machines_before_update",
                        "lifecycle_definition_rows_before_insert",
                    ],
                },
            ).all()
        }
    for name, body in bodies.items():
        assert "FOR UPDATE" in body, name
        assert f"{SCHEMA}.lifecycle_machines" in body, name
    # And the child trigger locks the machine *before* it reads the publication column.
    child = bodies["lifecycle_definition_rows_before_insert"]
    assert child.index("FOR UPDATE") < child.index("IF v_published IS NOT NULL")


def test_an_edge_insert_fires_the_publication_trigger_before_the_terminal_check(owner_engine):
    """Trigger firing order is by name, and this one has to hold the lock first.

    PostgreSQL fires ``BEFORE`` row triggers in name order.
    ``lifecycle_transition_edges_only_before_publication`` sorts before
    ``lifecycle_transition_edges_source_not_terminal``, so the machine lock is taken before
    anything else reads a definition row -- and before the composite foreign keys, which are
    ``AFTER`` triggers and run later still.
    """
    with owner_engine.connect() as connection:
        names = [
            row[0]
            for row in connection.execute(
                text(
                    "SELECT g.tgname FROM pg_catalog.pg_trigger g "
                    "JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid "
                    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = :s AND c.relname = 'lifecycle_transition_edges' "
                    "AND NOT g.tgisinternal ORDER BY g.tgname"
                ),
                {"s": SCHEMA},
            ).all()
        ]
    assert names.index("lifecycle_transition_edges_only_before_publication") < names.index(
        "lifecycle_transition_edges_source_not_terminal"
    )


@pytest.mark.parametrize("table", ["lifecycle_states", "lifecycle_transition_edges"])
def test_a_definition_row_can_never_be_updated_or_deleted_so_it_cannot_race(
    owner_engine, lifecycle_definitions, table
):
    """The other two child mutations the review asked about, and why they need no lock.

    An ``UPDATE`` or a ``DELETE`` of a state or an edge is refused unconditionally, before
    and after publication alike, for every writer including the schema owner. So there is no
    interleaving in which one of them races a publication: there is no interleaving in which
    one of them happens at all. That is also why "an update moving a row between machine
    parents must lock both parents in a deterministic order" has nothing to implement here --
    no update reaches a row to move.
    """
    for statement in (
        f"UPDATE {SCHEMA}.{table} SET machine_version = machine_version",
        f"DELETE FROM {SCHEMA}.{table}",
    ):
        with owner_transaction(owner_engine) as connection:
            with pytest.raises(DBAPIError) as exc:
                connection.execute(text(statement))
        assert "immutable" in str(exc.value), statement
