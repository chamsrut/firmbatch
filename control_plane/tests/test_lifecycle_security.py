"""What arbitrary runtime SQL cannot do to a lifecycle, and why each route is closed.

``test_protected_auth_state.py`` established the pattern for Milestone 2.3: a
``SECURITY DEFINER`` function is either hardened on every axis or it is a standing privilege
escalation, and each axis is asserted separately from the catalogue rather than from the
migration source. Milestone 2.4 adds twenty-two functions and four protected relations to
that same boundary -- and, since its third correction pass, a fourth role: the **lifecycle
writer**, which owns the two entry points so that they execute as it, and which nobody can
``SET ROLE`` to. ``test_lifecycle_writer.py`` owns that role's properties; this module
asserts the same function-boundary properties over the new objects and then goes after the
routes a lifecycle specifically opens:

* **choosing the required capability.** The scope an instance takes is protected data. A
  caller cannot name one, cannot lower one, and cannot make the policies read a different
  one.
* **bypassing the graph.** The internal readers and the trigger functions are executable by
  nobody, and the entry points do not accept a "skip the check" of any shape.
* **forging the actor or the tenant.** Neither is a parameter, and the insert policy
  re-derives both.
* **carrying state across a connection.** A lifecycle is a row, not session state, so pooled
  connections and reused ``Session`` objects have nothing to leak -- asserted rather than
  assumed.

Everything here runs as the ordinary application role against the real server, because a
property asserted from the owner connection is a property nobody is defending against.
"""

from __future__ import annotations

import json
import re
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from firmbatch.control_plane.db import auth, roles
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.lifecycle import (
    LifecycleConflict,
    lifecycle_instance,
    transition_lifecycle_instance,
)
from firmbatch.control_plane.db.models import PROTECTED_TABLES
from firmbatch.control_plane.security.authorization import Scope

from .conftest import TEST_RESTRICTED, TEST_WORKFLOW

LIFECYCLE_FUNCTION_NAMES = tuple(name for name, _signature in roles.ALL_LIFECYCLE_FUNCTIONS)


def _functions(owner_engine) -> dict:
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                """
                SELECT p.proname,
                       pg_get_userbyid(p.proowner) AS owner,
                       p.prosecdef,
                       coalesce(array_to_string(p.proconfig, ','), '') AS config,
                       coalesce(array_to_string(p.proacl, ','), '') AS acl,
                       p.prosrc
                FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = :schema AND p.proname = ANY(:names)
                """
            ),
            {"schema": SCHEMA, "names": list(LIFECYCLE_FUNCTION_NAMES)},
        ).mappings().all()
    return {row["proname"]: row for row in rows}


def _grantees(acl: str) -> set[str]:
    return {entry.split("=", 1)[0] or "PUBLIC" for entry in acl.split(",") if entry}


# ----------------------------------------------------------------- the function boundary


def test_every_lifecycle_function_exists_and_is_owned_by_the_schema_owner_or_the_writer(
    owner_engine, disposable_database
):
    """The manifest in ``db/roles.py`` is what the grants are driven from.

    The two entry points are owned by the lifecycle writer -- that is what makes them execute
    as it, and what every lifecycle-derived guard checks for. Everything else is the schema
    owner's. No function is owned by a runtime role, which could ``CREATE OR REPLACE`` it --
    and these decide who may move what.
    """
    functions = _functions(owner_engine)
    missing = [name for name in LIFECYCLE_FUNCTION_NAMES if name not in functions]
    assert missing == [], missing
    writer_owned = {name for name, _signature in roles.LIFECYCLE_WRITER_FUNCTIONS}
    assert writer_owned == {"create_lifecycle_instance", "transition_lifecycle_instance"}
    for name in LIFECYCLE_FUNCTION_NAMES:
        expected = (
            disposable_database.lifecycle_writer_role
            if name in writer_owned
            else disposable_database.owner_role
        )
        assert functions[name]["owner"] == expected, name
        assert functions[name]["owner"] not in (
            disposable_database.application_role,
            disposable_database.provisioning_role,
        ), name


def test_every_lifecycle_function_pins_a_safe_search_path(owner_engine):
    """Without it, a definer function resolves unqualified names through the caller's path."""
    functions = _functions(owner_engine)
    for name in LIFECYCLE_FUNCTION_NAMES:
        config = functions[name]["config"]
        assert "search_path=pg_catalog" in config.replace(" ", ""), f"{name}: {config!r}"


def test_public_holds_execute_on_no_lifecycle_function(owner_engine):
    """PostgreSQL grants ``EXECUTE`` to ``PUBLIC`` by default; nothing here inherits it."""
    functions = _functions(owner_engine)
    for name in LIFECYCLE_FUNCTION_NAMES:
        acl = functions[name]["acl"]
        assert acl != "", f"{name}: an empty ACL means PostgreSQL's default, which is PUBLIC"
        assert "PUBLIC" not in _grantees(acl), f"{name}: {acl}"


def test_the_definition_readers_and_triggers_are_executable_by_nobody(
    owner_engine, disposable_database
):
    """The internal functions no runtime role may call.

    The three readers, because a role that could call them could enumerate every registered
    machine, its states, its edges and the capability each requires. The trigger functions,
    because PostgreSQL does not check ``EXECUTE`` when firing a trigger, so a grant would
    only make them callable as ordinary functions -- which nothing needs.

    The lifecycle writer is the one exception, and it is not a runtime role: the entry
    points execute as it, so it holds ``EXECUTE`` on exactly the helpers their bodies, their
    triggers and the policies they meet call -- and on no trigger function and not on
    publication.
    """
    functions = _functions(owner_engine)
    writer_helpers = {name for name, _signature in roles.LIFECYCLE_WRITER_HELPER_FUNCTIONS}
    for name, _signature in roles.INTERNAL_LIFECYCLE_FUNCTIONS:
        grantees = _grantees(functions[name]["acl"])
        permitted = {disposable_database.owner_role}
        if name in writer_helpers:
            permitted.add(disposable_database.lifecycle_writer_role)
        assert grantees <= permitted, f"{name} is executable by {grantees}"
    assert "publish_lifecycle_machine" not in writer_helpers
    assert not any(name.endswith(("_before_insert", "_before_update", "_immutable",
                                  "_check_source", "_is_derived", "_guard", "_is_authorized"))
                   for name in writer_helpers), writer_helpers


def test_the_lifecycle_entry_points_are_granted_to_the_application_role_only(
    owner_engine, disposable_database
):
    """And **not** to provisioning, which receives no lifecycle authority of any kind.

    This is the first asymmetry between the two runtime roles in this schema, and it is
    deliberate: provisioning creates a tenant and mints its first credential.

    The two entry points are owned by the lifecycle writer, so their ACL names the writer
    as owner and the application role as the one grantee -- written by the writer, because
    the schema owner can neither grant nor revoke on a function it does not own.
    """
    functions = _functions(owner_engine)
    for name, _signature in roles.LIFECYCLE_WRITER_FUNCTIONS:
        grantees = _grantees(functions[name]["acl"])
        assert grantees == {
            disposable_database.lifecycle_writer_role,
            disposable_database.application_role,
        }, f"{name} is executable by {grantees}"
        assert disposable_database.provisioning_role not in grantees, name
        assert disposable_database.owner_role not in grantees, name
    for name, _signature in roles.APPLICATION_LIFECYCLE_FUNCTIONS:
        grantees = _grantees(functions[name]["acl"])
        assert disposable_database.application_role in grantees, name
        assert disposable_database.provisioning_role not in grantees, name
        assert grantees <= {
            disposable_database.owner_role,
            disposable_database.application_role,
            disposable_database.lifecycle_writer_role,
        }, f"{name} is executable by {grantees}"


def test_no_lifecycle_function_builds_a_statement_or_resolves_an_object_by_name(owner_engine):
    """The two shapes that turn a definer function into an injection surface."""
    forbidden = (
        "execute format",
        "execute '",
        'execute "',
        "quote_ident",
        "format(",
        "to_regclass",
        "to_regprocedure",
        "::regclass",
        "::regprocedure",
    )
    functions = _functions(owner_engine)
    for name in LIFECYCLE_FUNCTION_NAMES:
        body = functions[name]["prosrc"].lower()
        for fragment in forbidden:
            assert fragment not in body, f"{name}: body contains {fragment!r}"


def test_every_lifecycle_reference_in_every_body_is_schema_qualified(owner_engine):
    """An unqualified name resolves through ``search_path``, which is why it is pinned.

    Belt and braces: with the path pinned to ``pg_catalog`` a bare ``lifecycle_states``
    would fail rather than resolve -- but it would fail at *call* time, in the middle of a
    transition, which is the worst place to discover it.
    """
    functions = _functions(owner_engine)
    interesting = (
        "lifecycle_machines",
        "lifecycle_states",
        "lifecycle_transition_edges",
        "lifecycle_instances",
        "lifecycle_transitions",
        "lifecycle_required_scope",
        "lifecycle_initial_state",
        "lifecycle_state_is_terminal",
        "lifecycle_edge_exists",
        "append_audit_event",
        "auth_context",
    )
    for name in LIFECYCLE_FUNCTION_NAMES:
        body = functions[name]["prosrc"]
        for token in interesting:
            pattern = re.compile(rf"(?<![\w.])({SCHEMA}\.)?{token}(?![\w])")
            for match in pattern.finditer(body):
                assert match.group(1) is not None, (
                    f"{name}: unqualified reference to {token!r} near "
                    f"{body[max(0, match.start() - 40):match.end() + 20]!r}"
                )


def test_the_security_type_of_every_lifecycle_function_is_what_was_decided(owner_engine):
    """Stated as data, so a change of security type is a deliberate edit rather than a diff.

    The four readers and the two entry points are ``SECURITY DEFINER`` because they read the
    protected definition or write protected tenant state. The five trigger functions are
    **not**: a trigger runs as whoever is writing, and the only writers are the owner and
    the definer functions above, so definer rights would buy nothing and would make the
    trigger callable as a privileged function if it were ever granted.
    """
    expected = {
        "lifecycle_required_scope": True,
        "lifecycle_initial_state": True,
        "lifecycle_state_is_terminal": True,
        "lifecycle_edge_exists": True,
        "create_lifecycle_instance": True,
        "transition_lifecycle_instance": True,
        # Publication runs as the owner because only the owner can call it -- it is granted
        # to nobody -- so definer rights would add nothing it does not already have.
        "publish_lifecycle_machine": False,
        # The three internal helpers of the transition boundary. **Invoker rights, on
        # purpose**: each is called only from inside a definer function, where the current
        # user is already the schema owner, and each is granted to nobody. Definer rights
        # would buy nothing there and would make them privileged the day somebody granted
        # one by mistake -- which matters most for lifecycle_replay_claim, whose whole job
        # is to read framework rows *as the caller sees them* so that row security still
        # decides what a replay may return.
        "lifecycle_request_fingerprint": False,
        "lifecycle_replay_claim": False,
        "append_lifecycle_audit_event": False,
        "lifecycle_definition_is_immutable": False,
        "lifecycle_machines_before_insert": False,
        "lifecycle_machines_before_update": False,
        "lifecycle_definition_rows_before_insert": False,
        "lifecycle_edges_check_source": False,
        "lifecycle_instances_before_insert": False,
        "lifecycle_instances_before_update": False,
        "lifecycle_transitions_before_insert": False,
        "lifecycle_framework_tag_is_derived": False,
        "lifecycle_claim_provenance_guard": False,
        # The writer's identity is read from pg_catalog, which every role can read, so a
        # definer version would add nothing but a privileged function to grant by mistake;
        # and the outbox-link guard is a trigger that must run as the inserting role, so
        # its claim lookup is bounded by that role's own row-security view.
        "lifecycle_writer_role": False,
        "outbox_events_link_is_authorized": False,
    }
    assert set(expected) == set(LIFECYCLE_FUNCTION_NAMES)
    functions = _functions(owner_engine)
    for name, definer in expected.items():
        assert functions[name]["prosecdef"] is definer, name


# ------------------------------------------------------------- what runtime SQL cannot do


def test_the_application_role_cannot_call_the_internal_readers(
    application_engine, principal_a, lifecycle_definitions
):
    """Not even to ask an innocuous question about a global machine.

    An enumerable definition is a definition an attacker can plan against: which states
    exist, which edges exist, and which capability each requires.
    """
    probes = (
        f"SELECT {SCHEMA}.lifecycle_initial_state('test_workflow', 1)",
        f"SELECT {SCHEMA}.lifecycle_state_is_terminal('test_workflow', 1, 'closed')",
        f"SELECT {SCHEMA}.lifecycle_edge_exists('test_workflow', 1, 'draft', 'closed')",
        f"SELECT {SCHEMA}.publish_lifecycle_machine('test_workflow', 1)",
    )
    for statement in probes:
        with pytest.raises(ProgrammingError) as exc:
            with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
                session.execute(text(statement))
        assert "permission denied" in str(exc.value).lower(), statement


def test_the_application_role_cannot_call_the_trigger_functions(application_engine, principal_a):
    for name, _signature in roles.INTERNAL_LIFECYCLE_FUNCTIONS:
        if not name.endswith(
            ("_before_insert", "_before_update", "_immutable", "_check_source", "_is_authorized")
        ):
            continue
        with pytest.raises(ProgrammingError) as exc:
            with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
                session.execute(text(f"SELECT {SCHEMA}.{name}()"))
        assert "permission denied" in str(exc.value).lower(), name


@pytest.mark.parametrize("table", sorted({"lifecycle_machines", "lifecycle_states", "lifecycle_transition_edges"}))
def test_the_definition_tables_are_in_the_protected_catalogue(table):
    """One inventory, so the ACL sanitiser, the principal check and the tests agree.

    A protected relation that had to be remembered separately in each of those places is a
    protected relation that stops being protected in one of them.
    """
    assert table in PROTECTED_TABLES


def test_a_runtime_role_cannot_discover_which_machines_exist(application_engine, principal_a):
    """Not by reading, not by counting, and not by asking about one it already knows."""
    for statement in (
        f"SELECT count(*) FROM {SCHEMA}.lifecycle_machines",
        f"SELECT machine_key FROM {SCHEMA}.lifecycle_machines LIMIT 1",
        f"SELECT count(*) FROM {SCHEMA}.lifecycle_states WHERE machine_key = 'test_workflow'",
        f"SELECT count(*) FROM {SCHEMA}.lifecycle_transition_edges",
    ):
        with pytest.raises(ProgrammingError) as exc:
            with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
                session.execute(text(statement))
        assert "permission denied" in str(exc.value).lower(), statement


def test_the_required_scope_reader_answers_and_confers_nothing(
    application_engine, principal_a, lifecycle_definitions
):
    """It **is** callable by the application role, and that is deliberate rather than a gap.

    Every policy on both tenant-owned lifecycle tables calls it, and a policy is evaluated
    with the querying role's privileges -- so a role without ``EXECUTE`` could not read its
    own instances at all. What it discloses is which capability a global, immutable machine
    version requires: a fact about the closed scope catalogue, not about any tenant. And
    knowing the answer confers nothing, because the caller still has to *hold* the scope.
    """
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert session.execute(
            text(f"SELECT {SCHEMA}.lifecycle_required_scope('test_workflow', 1, 'transition')")
        ).scalar_one() == Scope.WORKSPACE_WRITE.value
        # An unknown machine, version or capability answers NULL, which coalesces to a
        # refusal in every policy that reads it.
        for arguments in (
            "'no_such_machine', 1, 'transition'",
            "'test_workflow', 99, 'transition'",
            "'test_workflow', 1, 'invented'",
        ):
            assert session.execute(
                text(f"SELECT {SCHEMA}.lifecycle_required_scope({arguments})")
            ).scalar_one() is None, arguments


def test_knowing_the_required_scope_does_not_grant_it(
    application_engine, new_principal, issue_credential, lifecycle_definitions
):
    """The reader is not an oracle worth having: the answer is public and the capability is not."""
    owner = new_principal("scope-reader")
    narrow = issue_credential(owner, [Scope.WORKSPACE_READ, Scope.MUTATION_EXECUTE])
    with auth.authenticated_transaction(application_engine, narrow.credential) as session:
        required = session.execute(
            text(f"SELECT {SCHEMA}.lifecycle_required_scope(:k, :v, 'create')"),
            {"k": TEST_RESTRICTED.machine_key, "v": TEST_RESTRICTED.version},
        ).scalar_one()
        assert required == Scope.CREDENTIAL_MANAGE.value
        # And asserting it changes nothing: scopes come from the credential.
        assert session.execute(
            text(f"SELECT {SCHEMA}.auth_has_scope(:s)"), {"s": required}
        ).scalar_one() is False


def test_setting_a_setting_named_after_a_scope_grants_nothing(
    application_engine, new_principal, issue_credential, new_instance
):
    """The Milestone 2.3 property, re-asserted on the Milestone 2.4 surface.

    A caller cannot manufacture a capability by writing one anywhere it can write.
    """
    owner = new_principal("forged-scope")
    position = new_instance(owner)
    narrow = issue_credential(owner, [Scope.WORKSPACE_READ, Scope.MUTATION_EXECUTE])

    from firmbatch.control_plane.security.authorization import AuthorizationError

    with pytest.raises(AuthorizationError):
        with auth.authenticated_transaction(application_engine, narrow.credential) as session:
            session.execute(text("SELECT set_config('app.scopes', 'workspace:write', true)"))
            session.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(owner.id)})
            transition_lifecycle_instance(
                session,
                instance_id=position.id,
                expected_state="draft",
                expected_revision=0,
                target_state="active",
            )


def test_a_runtime_role_cannot_register_a_machine_of_its_own(
    application_engine, principal_a, lifecycle_definitions
):
    """The whole escalation, attempted end to end.

    A machine requiring only ``workspace:read`` whose graph permits everything would be a
    complete bypass of every authorization decision this kernel makes -- for every tenant at
    once, since definitions are global.
    """
    from firmbatch.control_plane.db.lifecycle import register_lifecycle_definition

    from .conftest import TEST_CYCLIC

    with pytest.raises(ProgrammingError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            register_lifecycle_definition(session.connection(), TEST_CYCLIC)
    assert "permission denied" in str(exc.value).lower()


def test_a_runtime_role_cannot_add_an_edge_to_an_existing_machine(
    application_engine, principal_a, lifecycle_definitions
):
    """The narrower and more tempting version: one row, and ``draft -> closed`` is legal."""
    with pytest.raises(ProgrammingError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.lifecycle_transition_edges "
                    "(machine_key, machine_version, from_state, to_state) "
                    "VALUES ('test_workflow', 1, 'draft', 'closed')"
                )
            )
    assert "permission denied" in str(exc.value).lower()


def test_a_runtime_role_cannot_unmark_a_terminal_state(
    application_engine, principal_a, lifecycle_definitions
):
    with pytest.raises(ProgrammingError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(f"UPDATE {SCHEMA}.lifecycle_states SET is_terminal = false")
            )
    assert "permission denied" in str(exc.value).lower()


def test_the_transition_function_cannot_be_pointed_at_another_tenant(
    application_engine, principal_a, principal_b, new_instance
):
    """Raw SQL, straight at the function, with the victim's instance id.

    There is no tenant parameter to supply, and the resolve is scoped to the context -- so
    the only thing a caller can vary is the instance id, and an id it does not own resolves
    to nothing.
    """
    victim = new_instance(principal_b)
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"SELECT {SCHEMA}.transition_lifecycle_instance("
                    ":i, 'draft', 0, 'active', NULL, NULL, NULL)"
                ),
                {"i": victim.id},
            )
    assert "not in the expected state at the expected revision" in str(exc.value)

    with auth.authenticated_transaction(application_engine, principal_b.credential) as session:
        assert lifecycle_instance(session, victim.id).revision == 0


def test_the_create_function_cannot_be_pointed_at_another_tenant(
    application_engine, principal_a, principal_b, workflow
):
    """There is no tenant argument at all, so an instance lands where the credential is."""
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        created = session.execute(
            text(f"SELECT instance_id FROM {SCHEMA}.create_lifecycle_instance(:k, :v)"),
            {"k": workflow.machine_key, "v": workflow.version},
        ).scalar_one()

    with auth.authenticated_transaction(application_engine, principal_b.credential) as session:
        assert lifecycle_instance(session, created) is None
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert lifecycle_instance(session, created).tenant_id == principal_a.id


def test_the_instance_update_policy_is_not_reachable_without_the_function(
    raw_application_connection, principal_a
):
    """No ``UPDATE`` privilege at all, so the policy is never even consulted.

    Two independent refusals, in the right order: the privilege system says no first, and
    the policy would say no after it. Neither is load-bearing alone.
    """
    with pytest.raises(ProgrammingError) as exc:
        raw_application_connection.execute(
            text(f"UPDATE {SCHEMA}.lifecycle_instances SET current_state = 'closed'")
        )
    assert "permission denied" in str(exc.value).lower()


# --------------------------------------------------------------- no state on a connection


def test_a_lifecycle_leaves_nothing_on_a_pooled_connection(
    single_connection_engine, principal_a, principal_b, workflow
):
    """One physical connection, two tenants, in sequence.

    A lifecycle is a row and not session state, so there is nothing here to leak -- and that
    is asserted rather than assumed, on a pool of exactly one, which is the only arrangement
    in which a leak would be visible.
    """
    from firmbatch.control_plane.db.lifecycle import create_lifecycle_instance

    with auth.authenticated_transaction(single_connection_engine, principal_a.credential) as session:
        first = create_lifecycle_instance(
            session, machine_key=workflow.machine_key, machine_version=workflow.version
        )
    with auth.authenticated_transaction(single_connection_engine, principal_b.credential) as session:
        assert lifecycle_instance(session, first.id) is None
        second = create_lifecycle_instance(
            session, machine_key=workflow.machine_key, machine_version=workflow.version
        )
        assert second.id != first.id
    with auth.authenticated_transaction(single_connection_engine, principal_a.credential) as session:
        assert lifecycle_instance(session, second.id) is None
        assert lifecycle_instance(session, first.id) is not None


def test_a_reused_session_does_not_serve_the_previous_tenants_instance(
    application_engine, principal_a, principal_b, new_instance
):
    """The identity map is dropped on a change of context, which this re-asserts here.

    ``session.get()`` answers from the identity map without going to the database, so a
    reused ``Session`` is the one place a policy is not consulted at all.
    """
    from sqlalchemy.orm import Session

    from firmbatch.control_plane.db.models import LifecycleInstance

    position = new_instance(principal_a)
    session = db_engine._install_session_guards(Session(bind=application_engine, expire_on_commit=False))
    try:
        with session.begin():
            auth.bind_authenticated_context(session, principal_a.credential)
            assert session.get(LifecycleInstance, position.id) is not None
        with session.begin():
            auth.bind_authenticated_context(session, principal_b.credential)
            assert session.get(LifecycleInstance, position.id) is None
    finally:
        session.close()


def test_an_unauthenticated_transaction_reaches_no_lifecycle_row(application_engine, principal_a, new_instance):
    position = new_instance(principal_a)
    with db_engine.transaction(application_engine) as session:
        assert lifecycle_instance(session, position.id) is None
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.lifecycle_instances")
        ).scalar_one() == 0
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.lifecycle_transitions")
        ).scalar_one() == 0


def test_a_read_only_transaction_is_refused_before_anything_lifecycle_happens(
    application_engine, principal_a
):
    """The Milestone 2.3 writable-primary boundary, unchanged and reached first.

    Acquiring an authenticated context writes one row of protected transaction state, so a
    lifecycle operation on a read-only transaction never gets as far as being a lifecycle
    operation -- it is refused at the bind, with the deliberate diagnostic.
    """
    from firmbatch.control_plane.db.engine import WritablePrimaryRequiredError

    engine = application_engine.execution_options(postgresql_readonly=True)
    with pytest.raises(WritablePrimaryRequiredError) as exc:
        with auth.authenticated_transaction(engine, principal_a.credential) as session:
            session.execute(text("SELECT 1"))
    assert "read-only" in str(exc.value)
    assert "primary-only at this milestone" in str(exc.value)


def test_a_transition_refusal_carries_no_credential_or_connection_material(
    application_engine, principal_a, new_instance
):
    """Every refusal, walked over the whole ``__cause__``/``__context__`` graph.

    ``raise ... from None`` suppresses a printed traceback without detaching anything, and a
    ``DBAPIError`` renders the failing statement *and its parameters* -- which here are the
    caller's reason and details document.
    """
    from .conftest import exception_chain

    position = new_instance(principal_a)
    secret = principal_a.credential.reveal()
    with pytest.raises(LifecycleConflict) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            transition_lifecycle_instance(
                session,
                instance_id=uuid.uuid4(),
                expected_state="draft",
                expected_revision=0,
                target_state="active",
                reason="a note that should not travel",
            )
    rendered = exception_chain(exc.value)
    assert secret not in rendered
    assert "a note that should not travel" not in rendered
    assert "postgresql" not in rendered.lower()
    assert exc.value.__cause__ is None and exc.value.__context__ is None
    assert position.revision == 0


def test_an_unexpected_database_error_does_not_repeat_the_details_document(
    application_engine, principal_a
):
    """The catch-all branch of the translator, exercised on a real unexpected failure.

    A non-existent instance id of the wrong *type* produces a database error this module did
    not anticipate; what matters is that the reason and the details do not travel with it.
    """
    from firmbatch.control_plane.db.lifecycle import LifecycleError

    with pytest.raises((LifecycleError, DBAPIError)) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"SELECT {SCHEMA}.transition_lifecycle_instance("
                    ":i, 'draft', 0, 'active', :r, CAST(:d AS jsonb))"
                ),
                {"i": str(uuid.uuid4()), "r": "a reason", "d": '{"note": "a value"}'},
            )
    # Whichever error shape it takes, the conflict message is the one that reaches a caller
    # through the supported path -- and that path is tested above. Here the point is only
    # that the raw path fails rather than succeeding.
    assert exc.value is not None


@pytest.fixture()
def owner_grant(owner_engine):
    """Grant something on the disposable database as its owner, and take it back.

    As the **owner**, not the cluster admin: the admin's connection is to the maintenance
    database, where the ``firmbatch`` schema does not exist. Cleanup is explicit and runs in
    ``finally``, because an ACL entry that outlived a failing test would change the answer
    for every test that ran afterwards -- which is exactly the state these tests detect.
    """
    granted: list[str] = []

    def _grant(statement: str) -> None:
        with owner_engine.connect() as connection:
            connection.execute(text(statement))
            connection.commit()
        granted.append(statement)

    try:
        yield _grant
    finally:
        for statement in reversed(granted):
            undo = statement.replace("GRANT ", "REVOKE ", 1).replace(" TO ", " FROM ", 1)
            with owner_engine.connect() as connection:
                connection.execute(text(undo))
                connection.commit()


def _refused_at_connect(disposable_database):
    from firmbatch.control_plane.config import PrivilegedPrincipalError

    engine = db_engine.create_application_engine(
        disposable_database.application_url, pool_size=1, max_overflow=0
    )
    try:
        with pytest.raises(PrivilegedPrincipalError) as exc:
            with engine.connect():
                pass
        return str(exc.value)
    finally:
        engine.dispose()


def test_the_protected_lifecycle_tables_disqualify_a_privileged_runtime_connection(
    disposable_database, owner_grant
):
    """A grant on a definition table refuses the connection at connect time.

    Same boundary as ``auth_bindings``: the principal check walks one catalogue, so a
    relation added to ``PROTECTED_TABLES`` is covered without a special case. Measured here
    on ``lifecycle_transition_edges``, which is the one whose contents decide what every
    tenant's instances may do.
    """
    owner_grant(
        f'GRANT SELECT ON TABLE {SCHEMA}.lifecycle_transition_edges '
        f'TO "{disposable_database.application_role}"'
    )
    assert "lifecycle_transition_edges" in _refused_at_connect(disposable_database)


def test_a_column_grant_on_a_definition_table_disqualifies_too(disposable_database, owner_grant):
    """The column half of the same boundary, which relation ACLs do not report.

    A role holding only column privileges never appears in ``pg_class.relacl``, so the
    relation check sees nothing -- and ``UPDATE (is_terminal)`` would be enough to make a
    finished job movable again for every tenant running that machine.
    """
    owner_grant(
        f'GRANT UPDATE (is_terminal) ON TABLE {SCHEMA}.lifecycle_states '
        f'TO "{disposable_database.application_role}"'
    )
    assert "lifecycle_states" in _refused_at_connect(disposable_database)


def test_the_ordinary_application_principal_reaches_no_lifecycle_definition(disposable_database):
    """The control. Without it, both refusals above could be a check that refuses always."""
    from firmbatch.control_plane.db.principal import inspect_principal

    engine = db_engine.create_application_engine(
        disposable_database.application_url, pool_size=1, max_overflow=0
    )
    try:
        with engine.connect() as connection:
            report = inspect_principal(connection.connection.cursor())
        assert report.is_safe, report
        for name in report.privileged_objects:
            assert "lifecycle" not in name, name
        for name in report.privileged_columns:
            assert "lifecycle" not in name, name
    finally:
        engine.dispose()


# --------------------- mutation:execute is not a lifecycle capability (finding 2)
#
# ``mutation:execute`` is the capability to claim an idempotency key and append an outbox
# event. It was never permission to read what somebody else's lifecycle did -- and it was:
# a claim's ``result`` carries the instance id, the states and the revisions, and an
# event's ``attributes`` carry the same. A credential holding only the framework capability
# could read the whole trajectory of a machine it holds no capability for, and could replay
# a claim it should never have seen.
#
# The correction is a tag written by the database and consulted by row-level security. These
# use **two credentials in one tenant** -- one entitled for the machine, one holding only
# the framework capability -- because a cross-tenant test would pass on the Milestone 2.1
# boundary and prove nothing about this one.


def _framework_pair(new_principal, issue_credential):
    """One tenant, two credentials: entitled for ``test_workflow``, and framework-only."""
    owner = new_principal("framework-boundary")
    entitled = issue_credential(
        owner, [Scope.WORKSPACE_READ, Scope.WORKSPACE_WRITE, Scope.MUTATION_EXECUTE]
    )
    framework_only = issue_credential(owner, [Scope.MUTATION_EXECUTE])
    return entitled, framework_only


def _claimed_move(application_engine, principal):
    """Create an instance and move it once, under an idempotency claim."""
    from firmbatch.control_plane.db.lifecycle import (
        create_lifecycle_instance,
        execute_idempotent_lifecycle_transition,
    )

    with auth.authenticated_transaction(application_engine, principal.credential) as session:
        position = create_lifecycle_instance(
            session, machine_key=TEST_WORKFLOW.machine_key, machine_version=TEST_WORKFLOW.version
        )
    with auth.authenticated_transaction(application_engine, principal.credential) as session:
        outcome = execute_idempotent_lifecycle_transition(
            session,
            idempotency_key=f"fb-{uuid.uuid4().hex}",
            instance_id=position.id,
            expected_state=position.current_state,
            expected_revision=position.revision,
            target_state="active",
        )
    return position, outcome


def test_the_framework_capability_alone_reads_no_lifecycle_claim_or_event(
    application_engine, new_principal, issue_credential, lifecycle_definitions
):
    """Same tenant, and the framework-only credential sees neither row.

    Row-level security is what does this: the claim and the event are tagged with the
    machine, and a tagged row's read policy requires that machine's declared read scope. So
    it holds for a caller composing its own ``SELECT``, which a Python check could not.
    """
    entitled, framework_only = _framework_pair(new_principal, issue_credential)
    position, outcome = _claimed_move(application_engine, entitled)

    with auth.authenticated_transaction(application_engine, entitled.credential) as session:
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.idempotency_records WHERE id = :i"),
            {"i": outcome.record_id},
        ).scalar_one() == 1
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.outbox_events WHERE id = :i"),
            {"i": outcome.event_id},
        ).scalar_one() == 1

    with auth.authenticated_transaction(application_engine, framework_only.credential) as session:
        # Not by id, not in bulk, and not through the ORM read either.
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.idempotency_records WHERE id = :i"),
            {"i": outcome.record_id},
        ).scalar_one() == 0
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.outbox_events WHERE id = :i"),
            {"i": outcome.event_id},
        ).scalar_one() == 0
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.idempotency_records")
        ).scalar_one() == 0
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.outbox_events")
        ).scalar_one() == 0
        assert lifecycle_instance(session, position.id) is None


def test_moving_an_instance_requires_the_machines_read_capability_too(
    application_engine, new_principal, issue_credential, lifecycle_definitions
):
    """A consequence of the boundary, asserted rather than discovered.

    The transition function resolves the instance with an ordinary ``SELECT``, and row
    security is ``FORCE``d -- so the resolve is subject to the machine's **read** policy even
    though the function runs as the schema owner. A credential holding the machine's
    transition capability and not its read capability therefore cannot move an instance: the
    row it names is not there as far as the function is concerned, and it gets the ordinary
    conflict.

    That is the right answer rather than a gap. You cannot move what you cannot see, and the
    alternative -- a resolve that bypassed row security -- would be a read path around the
    isolation boundary inside the one function that writes state.

    A machine that wants "may move, may not read" therefore declares the *same* scope for
    both. The two are separate fields because a machine may want reading to be **wider**
    than moving, which this arrangement supports.
    """
    from firmbatch.control_plane.db.lifecycle import execute_idempotent_lifecycle_transition

    owner = new_principal("move-needs-read")
    entitled = issue_credential(
        owner, [Scope.WORKSPACE_READ, Scope.WORKSPACE_WRITE, Scope.MUTATION_EXECUTE]
    )
    write_only = issue_credential(owner, [Scope.WORKSPACE_WRITE, Scope.MUTATION_EXECUTE])
    position, _outcome = _claimed_move(application_engine, entitled)

    with pytest.raises(LifecycleConflict):
        with auth.authenticated_transaction(application_engine, write_only.credential) as session:
            execute_idempotent_lifecycle_transition(
                session,
                idempotency_key=f"mv-{uuid.uuid4().hex}",
                instance_id=position.id,
                expected_state="active",
                expected_revision=1,
                target_state="paused",
            )

    with auth.authenticated_transaction(application_engine, entitled.credential) as session:
        assert lifecycle_instance(session, position.id).revision == 1


def test_a_key_hidden_behind_another_machine_does_not_collide_at_all(
    application_engine, new_principal, issue_credential, lifecycle_definitions
):
    """**The write-side existence oracle, closed by separating the namespaces.**

    An idempotency key used to be scoped by ``(tenant, operation, key)`` with one operation
    name for every machine, so one tenant's two machines shared a key space. That made the
    claim index answer a question it had no business answering: present a key already taken
    by a machine you cannot read, and the insert failed -- so "this key is taken" was
    readable for rows the read policies hide. Renaming the error would not have helped;
    success versus failure was the oracle.

    The operation is now derived as ``lifecycle.transition.<machine>.v<version>`` from the
    machine the *instance* pins, so the two machines are in different uniqueness domains and
    the key does not collide. This asserts the property the reviewer asked for directly: the
    authorized request behaves **identically** whether or not a hidden claim is holding the
    same textual key.
    """
    from firmbatch.control_plane.db.lifecycle import (
        create_lifecycle_instance,
        execute_idempotent_lifecycle_transition,
        lifecycle_transition_operation,
    )

    owner = new_principal("cross-machine-key")
    restricted = issue_credential(
        owner, [Scope.AUDIT_READ, Scope.CREDENTIAL_MANAGE, Scope.MUTATION_EXECUTE]
    )
    workflow = issue_credential(
        owner, [Scope.WORKSPACE_READ, Scope.WORKSPACE_WRITE, Scope.MUTATION_EXECUTE]
    )
    shared_key = f"xm-{uuid.uuid4().hex}"
    unused_key = f"xm-{uuid.uuid4().hex}"

    # Claimed by a machine the second credential cannot read.
    with auth.authenticated_transaction(application_engine, restricted.credential) as session:
        hidden = create_lifecycle_instance(
            session,
            machine_key=TEST_RESTRICTED.machine_key,
            machine_version=TEST_RESTRICTED.version,
        )
    with auth.authenticated_transaction(application_engine, restricted.credential) as session:
        hidden_outcome = execute_idempotent_lifecycle_transition(
            session,
            idempotency_key=shared_key,
            instance_id=hidden.id,
            expected_state=hidden.current_state,
            expected_revision=hidden.revision,
            target_state="settled",
        )

    # The used key and an unused one, on two equivalent authorized requests. If the hidden
    # claim were reachable, exactly one of these two would fail -- which is the oracle.
    outcomes = []
    for key in (shared_key, unused_key):
        with auth.authenticated_transaction(application_engine, workflow.credential) as session:
            mine = create_lifecycle_instance(
                session,
                machine_key=TEST_WORKFLOW.machine_key,
                machine_version=TEST_WORKFLOW.version,
            )
        with auth.authenticated_transaction(application_engine, workflow.credential) as session:
            outcomes.append(
                (
                    mine,
                    execute_idempotent_lifecycle_transition(
                        session,
                        idempotency_key=key,
                        instance_id=mine.id,
                        expected_state=mine.current_state,
                        expected_revision=mine.revision,
                        target_state="active",
                    ),
                )
            )

    for instance, outcome in outcomes:
        assert outcome.replayed is False
        assert outcome.result["lifecycle_instance_id"] == str(instance.id)
        with auth.authenticated_transaction(application_engine, workflow.credential) as session:
            assert lifecycle_instance(session, instance.id).revision == 1

    # The hidden claim is untouched, and it is in a different operation namespace -- which
    # is the mechanism, stated so that a future change to the naming has to face it.
    assert lifecycle_transition_operation(
        TEST_RESTRICTED.machine_key, TEST_RESTRICTED.version
    ) != lifecycle_transition_operation(TEST_WORKFLOW.machine_key, TEST_WORKFLOW.version)
    with auth.authenticated_transaction(application_engine, restricted.credential) as session:
        assert lifecycle_instance(session, hidden.id).revision == 1
    assert hidden_outcome.replayed is False


def test_a_key_taken_within_one_authorized_machine_still_conflicts(
    application_engine, new_principal, issue_credential, lifecycle_definitions
):
    """Separating the namespaces must not separate away the property that matters.

    Within one machine a caller *is* authorized for, reusing a key for a different request is
    still the established conflicting-key-reuse outcome. Two instances of ``test_workflow``,
    one key: the second request is a different one, and it is refused rather than replayed.
    """
    from firmbatch.control_plane.db.idempotency import IdempotencyConflict
    from firmbatch.control_plane.db.lifecycle import (
        create_lifecycle_instance,
        execute_idempotent_lifecycle_transition,
    )

    owner = new_principal("same-machine-key")
    credential = issue_credential(
        owner, [Scope.WORKSPACE_READ, Scope.WORKSPACE_WRITE, Scope.MUTATION_EXECUTE]
    )
    key = f"sm-{uuid.uuid4().hex}"

    made = []
    for _ in range(2):
        with auth.authenticated_transaction(application_engine, credential.credential) as session:
            made.append(
                create_lifecycle_instance(
                    session,
                    machine_key=TEST_WORKFLOW.machine_key,
                    machine_version=TEST_WORKFLOW.version,
                )
            )
    first, second = made

    with auth.authenticated_transaction(application_engine, credential.credential) as session:
        execute_idempotent_lifecycle_transition(
            session,
            idempotency_key=key,
            instance_id=first.id,
            expected_state=first.current_state,
            expected_revision=first.revision,
            target_state="active",
        )

    with pytest.raises(IdempotencyConflict) as exc:
        with auth.authenticated_transaction(application_engine, credential.credential) as session:
            execute_idempotent_lifecycle_transition(
                session,
                idempotency_key=key,
                instance_id=second.id,
                expected_state=second.current_state,
                expected_revision=second.revision,
                target_state="active",
            )
    rendered = str(exc.value)
    # It says the key was reused and nothing about what it was reused from.
    assert "different request" in rendered
    for leaked in (str(first.id), "to_revision", "transition_id"):
        assert leaked not in rendered, leaked

    with auth.authenticated_transaction(application_engine, credential.credential) as session:
        assert lifecycle_instance(session, first.id).revision == 1
        assert lifecycle_instance(session, second.id).revision == 0

def test_the_framework_capability_alone_cannot_replay_a_lifecycle_claim(
    application_engine, new_principal, issue_credential, lifecycle_definitions
):
    """The weakest credential reaches nothing at all, and leaks nothing on the way.

    A context holding only ``mutation:execute`` cannot read the instance and cannot read the
    claim, so it gets the ordinary conflict -- the same one an invented identifier produces.
    What matters here is what the refusal does **not** carry: none of the winner's stored
    result.
    """
    from firmbatch.control_plane.db.lifecycle import execute_idempotent_lifecycle_transition

    entitled, framework_only = _framework_pair(new_principal, issue_credential)
    position, outcome = _claimed_move(application_engine, entitled)
    key = _key_of(application_engine, entitled, outcome.record_id)

    with pytest.raises(LifecycleConflict) as exc:
        with auth.authenticated_transaction(
            application_engine, framework_only.credential
        ) as session:
            execute_idempotent_lifecycle_transition(
                session,
                idempotency_key=key,
                instance_id=position.id,
                expected_state="active",
                expected_revision=1,
                target_state="paused",
            )
    rendered = str(exc.value)
    for leaked in ("to_revision", "transition_id", str(position.id), str(outcome.record_id)):
        assert leaked not in rendered, leaked

    with auth.authenticated_transaction(application_engine, entitled.credential) as session:
        assert lifecycle_instance(session, position.id).revision == 1


def _key_of(application_engine, principal, record_id):
    with auth.authenticated_transaction(application_engine, principal.credential) as session:
        return session.execute(
            text(f"SELECT idempotency_key FROM {SCHEMA}.idempotency_records WHERE id = :i"),
            {"i": record_id},
        ).scalar_one()


def test_a_generic_mutation_stays_readable_with_the_framework_capability_alone(
    application_engine, new_principal, issue_credential
):
    """The control, and the requirement that generic Milestone 2.2 behaviour is unchanged.

    An untagged claim and an untagged event are exactly what they were: readable by any
    context holding ``mutation:execute``. Without this the tag could have been a blanket
    tightening of M2.2 wearing a lifecycle name.
    """
    from firmbatch.control_plane.db.idempotency import (
        MutationOutcome,
        OutboxEventSpec,
        execute_idempotent_mutation,
    )
    from firmbatch.control_plane.db.repositories import WorkspaceRepository

    owner = new_principal("generic-mutation")
    writer = issue_credential(
        owner, [Scope.WORKSPACE_READ, Scope.WORKSPACE_WRITE, Scope.MUTATION_EXECUTE]
    )
    framework_only = issue_credential(owner, [Scope.MUTATION_EXECUTE])

    def mutate(unit_of_work):
        workspace = WorkspaceRepository(unit_of_work).create(slug="generic-ws", name="Generic")
        return MutationOutcome(
            result={"workspace_id": workspace.id},
            event=OutboxEventSpec(
                event_type="workspace.created",
                aggregate_type="workspace",
                aggregate_id=workspace.id,
            ),
        )

    with auth.authenticated_transaction(application_engine, writer.credential) as session:
        outcome = execute_idempotent_mutation(
            session,
            operation="workspace.create",
            idempotency_key=f"gen-{uuid.uuid4().hex}",
            request_identity={"workspace_slug": "generic-ws"},
            mutate=mutate,
        )

    with auth.authenticated_transaction(application_engine, framework_only.credential) as session:
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.idempotency_records WHERE id = :i"),
            {"i": outcome.record_id},
        ).scalar_one() == 1
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.outbox_events WHERE id = :i"),
            {"i": outcome.event_id},
        ).scalar_one() == 1
        tag = session.execute(
            text(
                f"SELECT lifecycle_machine_key FROM {SCHEMA}.idempotency_records WHERE id = :i"
            ),
            {"i": outcome.record_id},
        ).scalar_one()
        assert tag is None, "a generic mutation must not be tagged with a machine"


@pytest.mark.parametrize("table", ["idempotency_records", "outbox_events"])
def test_the_lifecycle_tag_is_derived_and_cannot_be_supplied(
    application_engine, principal_a, table, lifecycle_definitions
):
    """The tag is written by the lifecycle writer alone, which is what makes the policy mean something.

    A caller that could set it could tag its own row with a machine it may read; a caller
    that could clear it could untag a real one so that reading it needed no machine
    capability. Either way the read policy would decide nothing.
    """
    columns = {
        "idempotency_records": (
            "tenant_id, operation, idempotency_key, request_fingerprint, "
            "lifecycle_machine_key, lifecycle_machine_version"
        ),
        "outbox_events": (
            "tenant_id, event_type, aggregate_type, aggregate_id, "
            "lifecycle_machine_key, lifecycle_machine_version"
        ),
    }[table]
    values = {
        "idempotency_records": (
            ":t, 'lifecycle.transition', 'forged-key-000001', :f, :k, 1"
        ),
        "outbox_events": (":t, 'a.b', 'thing', gen_random_uuid(), :k, 1"),
    }[table]

    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(f"INSERT INTO {SCHEMA}.{table} ({columns}) VALUES ({values})"),
                {"t": principal_a.id, "f": "0" * 64, "k": TEST_WORKFLOW.machine_key},
            )
    # Since the Milestone 2.4 correction the refusal comes one layer earlier than the
    # trigger: the application role holds no ``INSERT`` privilege on the tag columns at all,
    # so naming one is a permission error before any row is composed. The trigger is still
    # there and is asserted below -- it is what would answer if a privilege were ever
    # granted by accident, and it is what binds a future definer function owned by somebody
    # else.
    assert "permission denied" in str(exc.value).lower()


@pytest.mark.parametrize("table", ["idempotency_records", "outbox_events", "audit_events"])
def test_the_lifecycle_tag_trigger_is_present_on_every_tagged_table(owner_engine, table):
    """The second answer, asserted from the catalogue rather than from a refusal.

    The privilege refusal above is the first answer and the one a caller actually meets.
    This is the one that keeps holding if a later migration grants the column by accident,
    and the one that binds a writer the privilege system does not bound -- a definer function
    owned by somebody other than the schema owner.
    """
    with owner_engine.connect() as connection:
        assert connection.execute(
            text(
                "SELECT count(*) FROM pg_catalog.pg_trigger g "
                "JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid "
                "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = :s AND c.relname = :t AND NOT g.tgisinternal "
                "AND g.tgname = :g"
            ),
            {"s": SCHEMA, "t": table, "g": f"{table}_lifecycle_tag_is_derived"},
        ).scalar_one() == 1


@pytest.mark.parametrize("table", ["idempotency_records", "outbox_events", "audit_events"])
def test_no_runtime_role_holds_a_column_privilege_on_the_lifecycle_tag(
    owner_engine, disposable_database, table
):
    """The column half of the boundary, checked the way Milestone 2.3 checks protected state.

    A column grant does not appear in ``pg_class.relacl`` at all, so a check that read only
    relation privileges would see nothing -- which is the defect the third M2.3 correction
    pass found on ``auth_transaction_context``.

    Since Milestone 2.4 these tables *do* carry column ACLs, deliberately: the application
    role's ``INSERT`` is column-level so that the row's identifier is not among the columns
    it may name. So this asks the narrower question it always meant to ask -- **no runtime
    role holds a privilege on the two tag columns** -- and the identifier is checked with it,
    because the two answers rest on the same grant. The one grantee those columns have is
    the lifecycle writer, ``INSERT`` only: it is the identity that writes the tag, and the
    identity nobody can become.
    """
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT a.attname, pg_catalog.pg_get_userbyid(acl.grantee), acl.privilege_type "
                "FROM pg_catalog.pg_attribute a "
                "JOIN pg_catalog.pg_class c ON c.oid = a.attrelid "
                "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                "CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl "
                "WHERE n.nspname = :s AND c.relname = :t AND a.attnum > 0 "
                "AND NOT a.attisdropped "
                "AND a.attname IN ('lifecycle_machine_key', 'lifecycle_machine_version', 'id')"
            ),
            {"s": SCHEMA, "t": table},
        ).all()
    assert {(grantee, privilege) for _column, grantee, privilege in rows} == {
        (disposable_database.lifecycle_writer_role, "INSERT")
    }, rows


def test_a_reachable_role_holding_the_lifecycle_definition_is_refused(
    disposable_database, owner_grant
):
    """The reachable-role half: a grant one ``SET ROLE`` away is still a grant.

    ``has_table_privilege`` follows inherited privilege, so a membership granted
    ``INHERIT FALSE, SET TRUE`` answers "no" while a single ``SET ROLE`` reaches everything.
    Milestone 2.3's principal check enumerates every reachable role for exactly this, and
    the lifecycle definition tables are in the same catalogue -- so this needs no new
    machinery, only the assertion that it is covered.
    """
    from firmbatch.control_plane.db.principal import inspect_principal

    owner_grant(
        f'GRANT SELECT ON TABLE {SCHEMA}.lifecycle_machines '
        f'TO "{disposable_database.application_role}"'
    )
    engine = db_engine.create_application_engine(
        disposable_database.application_url, pool_size=1, max_overflow=0, validate_principal=False
    )
    try:
        with engine.connect() as connection:
            report = inspect_principal(connection.connection.cursor())
        assert not report.is_safe
        assert any("lifecycle_machines" in entry for entry in report.privileged_objects), (
            report.privileged_objects
        )
    finally:
        engine.dispose()


# --------------- the audit trail is not a way round the machine (review finding 3)
#
# ``audit:read`` is the capability to read the trail. It was never meant to be permission to
# read what somebody else's *lifecycle* did -- and it was: an audit row for a lifecycle
# action carries the instance id in ``resource_id``, and the machine, the states, the
# revisions and the transition id in ``details``. A credential holding ``mutation:execute``
# and ``audit:read`` could read the whole trajectory of a machine it holds no capability for.
#
# Same correction as the two framework tables, one milestone late: the row is tagged by the
# database, and a tagged row's ``SELECT`` policy additionally requires the machine's declared
# read scope. These use **two credentials in one tenant**, because a cross-tenant test would
# pass on the Milestone 2.1 boundary and prove nothing about this one.


def _audit_pair(new_principal, issue_credential):
    """One tenant, two credentials: entitled for ``test_workflow``, and audit-only."""
    owner = new_principal("audit-boundary")
    entitled = issue_credential(
        owner,
        [Scope.WORKSPACE_READ, Scope.WORKSPACE_WRITE, Scope.MUTATION_EXECUTE, Scope.AUDIT_READ],
    )
    audit_only = issue_credential(owner, [Scope.MUTATION_EXECUTE, Scope.AUDIT_READ])
    return entitled, audit_only


def _audit_rows(engine, principal):
    from firmbatch.control_plane.db.audit import audit_events

    with auth.authenticated_transaction(engine, principal.credential) as session:
        return list(audit_events(session, limit=500))


def test_a_credential_without_the_machines_read_scope_sees_no_lifecycle_audit_row(
    application_engine, new_principal, issue_credential, lifecycle_definitions
):
    """**The two-credential regression.** Same tenant, both hold ``audit:read``.

    One holds the machine's read scope and sees the lifecycle rows; the other does not and
    sees neither the rows nor the identifiers they carry. Row-level security is what does it,
    so it holds for a caller composing its own ``SELECT`` -- which a Python check could not.
    """
    from firmbatch.control_plane.db.lifecycle import (
        create_lifecycle_instance,
        execute_idempotent_lifecycle_transition,
    )

    entitled, audit_only = _audit_pair(new_principal, issue_credential)

    with auth.authenticated_transaction(application_engine, entitled.credential) as session:
        position = create_lifecycle_instance(
            session, machine_key=TEST_WORKFLOW.machine_key, machine_version=TEST_WORKFLOW.version
        )
    with auth.authenticated_transaction(application_engine, entitled.credential) as session:
        outcome = execute_idempotent_lifecycle_transition(
            session,
            idempotency_key=f"au-{uuid.uuid4().hex}",
            instance_id=position.id,
            expected_state=position.current_state,
            expected_revision=position.revision,
            target_state="active",
        )

    # The entitled credential reads them, which is what makes the refusal below meaningful.
    mine = _audit_rows(application_engine, entitled)
    lifecycle_actions = {
        row.action for row in mine if row.action.startswith("lifecycle.")
    }
    assert lifecycle_actions == {"lifecycle.instance_created", "lifecycle.transitioned"}
    assert any(row.resource_id == position.id for row in mine)

    # The audit-only credential sees no lifecycle row at all, and nothing that names one.
    theirs = _audit_rows(application_engine, audit_only)
    assert [row for row in theirs if row.action.startswith("lifecycle.")] == []
    for row in theirs:
        assert row.resource_id != position.id
        rendered = json.dumps(row.details, default=str)
        for leaked in (
            str(position.id),
            str(outcome.result["transition_id"]),
            TEST_WORKFLOW.machine_key,
            "to_revision",
        ):
            assert leaked not in rendered, (row.action, leaked)


def test_the_audit_row_is_hidden_by_the_policy_and_not_by_the_reader(
    application_engine, new_principal, issue_credential, lifecycle_definitions
):
    """Raw SQL, straight at the table, asking for exactly the columns that carry the leak.

    The Python reader could have been the thing filtering. It is not: the policy is, so a
    caller writing its own ``SELECT`` gets the same answer.
    """
    from firmbatch.control_plane.db.lifecycle import create_lifecycle_instance

    entitled, audit_only = _audit_pair(new_principal, issue_credential)
    with auth.authenticated_transaction(application_engine, entitled.credential) as session:
        position = create_lifecycle_instance(
            session, machine_key=TEST_WORKFLOW.machine_key, machine_version=TEST_WORKFLOW.version
        )

    statement = text(
        f"SELECT resource_id, details, lifecycle_machine_key FROM {SCHEMA}.audit_events "
        "WHERE resource_id = :i"
    )
    with auth.authenticated_transaction(application_engine, entitled.credential) as session:
        assert session.execute(statement, {"i": position.id}).all() != []
    with auth.authenticated_transaction(application_engine, audit_only.credential) as session:
        assert session.execute(statement, {"i": position.id}).all() == []


def test_generic_audit_reading_is_exactly_what_it_was(
    application_engine, new_principal, issue_credential, lifecycle_definitions
):
    """The other half: an untagged audit row is unaffected by any of this.

    Both credentials hold ``audit:read``, neither holds a machine capability for the action
    below, and both read it -- because it belongs to no machine and the tag is NULL.
    """
    from firmbatch.control_plane.db.audit import AuditEventSpec, append_audit_event

    entitled, audit_only = _audit_pair(new_principal, issue_credential)
    marker = uuid.uuid4()
    with auth.authenticated_transaction(application_engine, audit_only.credential) as session:
        append_audit_event(
            session,
            AuditEventSpec(
                action="workspace.create",
                outcome="succeeded",
                resource_type="workspace",
                resource_id=marker,
            ),
        )

    for principal in (entitled, audit_only):
        rows = _audit_rows(application_engine, principal)
        assert any(row.resource_id == marker for row in rows), principal


def test_the_generic_append_cannot_write_an_untagged_lifecycle_action(
    application_engine, new_principal, issue_credential, lifecycle_definitions
):
    """Forging is closed as well as reading.

    ``append_audit_event`` is the generic path and it never sets the tag, so a
    ``lifecycle.`` action written through it violates the reserved-namespace constraint. A
    caller therefore cannot manufacture a lifecycle-looking audit row that is readable with
    ``audit:read`` alone -- which would have made the policy above decide nothing.
    """
    from firmbatch.control_plane.db.audit import AuditError, AuditEventSpec, append_audit_event

    _entitled, audit_only = _audit_pair(new_principal, issue_credential)

    # Raw SQL, straight at the hardened append function, so the constraint that refuses it is
    # visible rather than translated.
    with pytest.raises(DBAPIError) as raw:
        with auth.authenticated_transaction(application_engine, audit_only.credential) as session:
            session.execute(
                text(
                    f"SELECT {SCHEMA}.append_audit_event("
                    "'lifecycle.transitioned', 'succeeded', 'lifecycle_instance', "
                    "gen_random_uuid(), NULL, '{}'::jsonb)"
                )
            )
    assert "lifecycle_namespace_reserved" in str(raw.value)

    # And through the Python boundary, which refuses it too and -- correctly -- does not
    # repeat the database's explanation, because the failing statement carries the caller's
    # details document as a parameter.
    with pytest.raises(AuditError):
        with auth.authenticated_transaction(application_engine, audit_only.credential) as session:
            append_audit_event(
                session,
                AuditEventSpec(
                    action="lifecycle.transitioned",
                    outcome="succeeded",
                    resource_type="lifecycle_instance",
                    resource_id=uuid.uuid4(),
                ),
            )


def test_the_audit_read_policy_was_replaced_and_not_added_beside(owner_engine):
    """Two policies for one command combine with ``OR``, so the weaker one would decide.

    Exactly one ``SELECT`` policy on ``audit_events``, and it names the machine's read scope
    as well as ``audit:read``.
    """
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT policyname, qual FROM pg_policies "
                "WHERE schemaname = :s AND tablename = 'audit_events' AND cmd = 'SELECT'"
            ),
            {"s": SCHEMA},
        ).all()
    assert len(rows) == 1, [row[0] for row in rows]
    predicate = rows[0][1]
    assert "audit:read" in predicate
    assert "lifecycle_required_scope" in predicate
    assert "lifecycle_machine_key" in predicate


@pytest.mark.parametrize("role_kind", ["application", "provisioning"])
def test_no_runtime_role_can_execute_the_lifecycle_audit_append(
    disposable_database, application_engine, provisioning_engine, principal_a, role_kind
):
    """The one writer permitted to tag an audit row is executable by nobody.

    A role that could call it could tag a row of its own -- or write a ``lifecycle.`` action
    about an instance it invented, which is the forgery the namespace constraint exists to
    stop.
    """
    engine = application_engine if role_kind == "application" else provisioning_engine
    with pytest.raises(ProgrammingError) as exc:
        with auth.authenticated_transaction(engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"SELECT {SCHEMA}.append_lifecycle_audit_event("
                    "'lifecycle.transitioned', 'succeeded', 'lifecycle_instance', "
                    "gen_random_uuid(), '{}'::jsonb, :m, 1)"
                ),
                {"m": TEST_WORKFLOW.machine_key},
            )
    assert "permission denied" in str(exc.value).lower()


# ------------- a chosen identifier is refused before any index (review finding 5)
#
# A caller that could name a row's primary key could submit one it had guessed or read
# elsewhere and learn from the uniqueness conflict whether it exists -- an existence oracle
# over rows the read policies hide. The application role's ``INSERT`` is column-level now and
# the identifier is not among the columns, so the refusal is a permission error at
# permission-check time: naming an id that exists and naming one that does not fail
# **identically**, and neither reaches an index.


@pytest.mark.parametrize("table", ["idempotency_records", "outbox_events"])
def test_an_existing_and_an_absent_chosen_identifier_fail_identically(
    application_engine, owner_engine, new_principal, issue_credential, lifecycle_definitions, table
):
    """``INSERT ... ON CONFLICT`` with a hidden row's id, and with one that does not exist.

    The hidden row is a lifecycle claim (and its event) belonging to a machine this
    credential holds no capability for, so the read policies do not show it. If a chosen
    identifier could reach the unique index, the two statements below would fail differently
    -- and the difference would be the answer to "does this row exist?".
    """
    from firmbatch.control_plane.db.lifecycle import (
        create_lifecycle_instance,
        execute_idempotent_lifecycle_transition,
    )

    owner = new_principal("identifier-oracle")
    restricted = issue_credential(
        owner, [Scope.AUDIT_READ, Scope.CREDENTIAL_MANAGE, Scope.MUTATION_EXECUTE]
    )
    probe = issue_credential(
        owner, [Scope.WORKSPACE_READ, Scope.WORKSPACE_WRITE, Scope.MUTATION_EXECUTE]
    )

    with auth.authenticated_transaction(application_engine, restricted.credential) as session:
        hidden = create_lifecycle_instance(
            session,
            machine_key=TEST_RESTRICTED.machine_key,
            machine_version=TEST_RESTRICTED.version,
        )
    with auth.authenticated_transaction(application_engine, restricted.credential) as session:
        outcome = execute_idempotent_lifecycle_transition(
            session,
            idempotency_key=f"io-{uuid.uuid4().hex}",
            instance_id=hidden.id,
            expected_state=hidden.current_state,
            expected_revision=hidden.revision,
            target_state="settled",
        )
    existing = outcome.record_id if table == "idempotency_records" else outcome.event_id
    absent = uuid.uuid4()

    # The probe cannot see either row, which is what makes this an oracle question.
    with auth.authenticated_transaction(application_engine, probe.credential) as session:
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.{table} WHERE id = :i"), {"i": existing}
        ).scalar_one() == 0

    statement = {
        "idempotency_records": (
            f"INSERT INTO {SCHEMA}.idempotency_records "
            "(id, tenant_id, operation, idempotency_key, request_fingerprint, status, result) "
            "VALUES (:i, :t, 'job.advance', :k, :f, 'completed', '{}'::jsonb) "
            "ON CONFLICT (id) DO NOTHING"
        ),
        "outbox_events": (
            f"INSERT INTO {SCHEMA}.outbox_events "
            "(id, tenant_id, event_type, aggregate_type, aggregate_id) "
            "VALUES (:i, :t, 'job.advanced', 'job', gen_random_uuid()) "
            "ON CONFLICT (id) DO NOTHING"
        ),
    }[table]

    rendered = []
    for identifier in (existing, absent):
        with pytest.raises(DBAPIError) as exc:
            with auth.authenticated_transaction(
                application_engine, probe.credential
            ) as session:
                session.execute(
                    text(statement),
                    {
                        "i": identifier,
                        "t": owner.id,
                        "k": f"io-{uuid.uuid4().hex}",
                        "f": "0" * 64,
                    },
                )
        rendered.append(str(exc.value).split("[SQL:")[0].strip())

    assert rendered[0] == rendered[1], rendered
    assert "permission denied" in rendered[0].lower()


@pytest.mark.parametrize("table", ["idempotency_records", "outbox_events"])
def test_the_ordinary_insert_without_an_identifier_still_works(
    application_engine, principal_a, table
):
    """The control. Without it the test above could be passing because nothing may be written.

    The application role writes these rows every time a mutation is claimed; what it may not
    do is choose the identifier.
    """
    statement = {
        "idempotency_records": (
            f"INSERT INTO {SCHEMA}.idempotency_records "
            "(tenant_id, operation, idempotency_key, request_fingerprint, status, result) "
            "VALUES (:t, 'job.advance', :k, :f, 'completed', '{}'::jsonb) RETURNING id"
        ),
        "outbox_events": (
            f"INSERT INTO {SCHEMA}.outbox_events "
            "(tenant_id, event_type, aggregate_type, aggregate_id) "
            "VALUES (:t, 'job.advanced', 'job', gen_random_uuid()) RETURNING id"
        ),
    }[table]
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert session.execute(
            text(statement),
            {"t": principal_a.id, "k": f"ok-{uuid.uuid4().hex}", "f": "0" * 64},
        ).scalar_one() is not None


@pytest.mark.parametrize(
    ("table", "namespaced"),
    (
        ("idempotency_records", True),
        ("outbox_events", False),
        ("audit_events", True),
    ),
)
def test_the_lifecycle_tag_is_all_or_none_and_names_a_real_machine(
    owner_engine, table, namespaced
):
    """Every new authorization field is complete or absent, and points at something real.

    A half-written tag would make a row look untagged to the read policy while still naming a
    machine; a tag pointing at a machine that does not exist would make the policy's scope
    lookup return NULL, which coalesces to a refusal and would hide the row from everybody.
    Both are inexpressible rather than merely unlikely.

    The reserved-namespace constraint is the other direction, on the two tables that have a
    name to reserve: the ``lifecycle.`` prefix and the tag imply each other, so a generic
    writer -- which cannot set the tag -- cannot write in the namespace either.
    """
    expected = {
        f"ck_{table}_lifecycle_tag_complete",
        f"fk_{table}_lifecycle_machine_lifecycle_machines",
    }
    if namespaced:
        expected.add(f"ck_{table}_lifecycle_namespace_reserved")

    with owner_engine.connect() as connection:
        present = {
            name
            for (name,) in connection.execute(
                text(
                    "SELECT c.conname FROM pg_catalog.pg_constraint c "
                    "JOIN pg_catalog.pg_class t ON t.oid = c.conrelid "
                    "JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace "
                    "WHERE n.nspname = :s AND t.relname = :t"
                ),
                {"s": SCHEMA, "t": table},
            ).all()
        }
    assert expected <= present, sorted(expected - present)


def test_every_provenance_column_is_not_null(owner_engine):
    """All-or-none, in the strongest form available: none of it is optional.

    A replay resolves the whole chain, so a provenance row with a missing link would be a row
    the replay could not verify and would therefore refuse -- which is a worse failure than
    not being able to write one.
    """
    with owner_engine.connect() as connection:
        nullable = [
            name
            for (name,) in connection.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = :s AND table_name = 'lifecycle_claim_provenance' "
                    "AND is_nullable = 'YES'"
                ),
                {"s": SCHEMA},
            ).all()
        ]
    assert nullable == []
