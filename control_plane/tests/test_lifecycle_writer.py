"""The lifecycle writer: a dedicated identity, and the only one that may write lifecycle-derived rows.

The third M2.4 review found that ownership of the schema was standing in for authorship of
a transition. The guards on the machine tags and on ``lifecycle_claim_provenance`` checked
``current_user = schema owner``, and the two entry points are ``SECURITY DEFINER`` -- so
they passed; but so did the schema owner's own ``INSERT``, and so did any other
``SECURITY DEFINER`` function the schema owner happened to own. Direct owner SQL could
insert a tagged claim, a tagged event and a provenance row matching an earlier transition,
and the replay accepted the forged association.

The correction is a fourth role. The **lifecycle writer** is ``NOLOGIN``, carries no
credential and no privileged attribute, is a member of nothing, can be reached by nobody
through ``SET ROLE``, and owns exactly two objects: the two entry points, which therefore
*execute as it*. Every lifecycle-derived guard now asks ``current_user`` to be that role, so
"written by the lifecycle boundary" is a fact about the executing identity. The schema owner
is refused with everybody else. Only a superuser -- or an administrator deliberately altering
roles, functions or triggers -- sits outside that, and that limitation is retained on purpose.

Who the writer is comes from the catalogue: ``firmbatch.lifecycle_writer_role()`` names the
owner of both entry points, provided that owner is not the schema owner and cannot log in.
No GUC, transaction variable, temporary object, token, query text or trigger depth is
consulted anywhere in the chain.

The one way a test reaches the writer's identity is the accepted limitation exercised
deliberately: the trusted bootstrap administrator grants the owner a ``SET``-only membership
for one block and revokes it after (``conftest.acting_as_lifecycle_writer``). That is used to
prove the guards pass **for the writer** and for nobody else -- a refusal-only test could not
tell a guard that refuses always from one that recognises the writer -- and to construct the
rows the replay must refuse.
"""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from firmbatch.control_plane import migrate
from firmbatch.control_plane.db import auth, roles
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.lifecycle import (
    LifecycleProvenanceError,
    execute_idempotent_lifecycle_transition,
    lifecycle_instance,
    lifecycle_transition_operation,
    transition_lifecycle_instance,
)
from firmbatch.control_plane.testing import bootstrap
from firmbatch.control_plane.testing.bootstrap import (
    create_disposable_database,
    drop_disposable_database,
    wire_handle_roles,
)

from .conftest import TEST_WORKFLOW, acting_as_lifecycle_writer

_PROVENANCE_INSERT = text(
    f"INSERT INTO {SCHEMA}.lifecycle_claim_provenance "
    "(idempotency_record_id, tenant_id, lifecycle_transition_id, lifecycle_instance_id, "
    "machine_key, machine_version, from_revision, to_revision, outbox_event_id) "
    "VALUES (:r, :t, :x, :i, :m, :v, :fr, :tr, :e)"
)

_TAGGED_CLAIM_INSERT = text(
    f"INSERT INTO {SCHEMA}.idempotency_records "
    "(tenant_id, operation, idempotency_key, request_fingerprint, status, result, "
    "lifecycle_machine_key, lifecycle_machine_version) "
    "VALUES (:t, :o, :k, :f, 'completed', CAST(:r AS jsonb), :m, :v) RETURNING id"
)

_TAGGED_EVENT_INSERT = text(
    f"INSERT INTO {SCHEMA}.outbox_events "
    "(tenant_id, event_type, aggregate_type, aggregate_id, attributes, "
    "lifecycle_machine_key, lifecycle_machine_version) "
    "VALUES (:t, 'test_workflow.transitioned', 'test_workflow', :a, '{}'::jsonb, :m, :v)"
)

_TAGGED_AUDIT_INSERT = text(
    f"INSERT INTO {SCHEMA}.audit_events "
    "(tenant_id, actor_kind, actor_principal_id, actor_binding_id, action, outcome, "
    "resource_type, resource_id, details, lifecycle_machine_key, lifecycle_machine_version) "
    "VALUES (:t, 'credential', :p, :b, 'lifecycle.transitioned', 'succeeded', "
    "'lifecycle_instance', :a, '{}'::jsonb, :m, :v)"
)


def _bind(connection, principal) -> None:
    connection.execute(
        text(f"SELECT {SCHEMA}.bind_authenticated_context(:c)"),
        {"c": principal.credential.reveal()},
    )


def _refusal(exc) -> tuple[str | None, str]:
    orig = getattr(exc.value, "orig", None)
    return getattr(orig, "sqlstate", None), str(exc.value).split("[SQL:")[0].strip()


def _unlinked_move(engine, principal, position, target="active"):
    """A transition through the internal form: a real history row and a real event, no claim."""
    with auth.authenticated_transaction(engine, principal.credential) as session:
        return transition_lifecycle_instance(
            session,
            instance_id=position.id,
            expected_state=position.current_state,
            expected_revision=position.revision,
            target_state=target,
        )


def _tagged_claim_without_provenance(disposable_database, principal, position, key) -> uuid.UUID:
    """A claim only the writer can write: in the reserved namespace, tagged, no provenance."""
    result = {
        "lifecycle_instance_id": str(position.id),
        "machine_key": TEST_WORKFLOW.machine_key,
        "machine_version": TEST_WORKFLOW.version,
        "from_state": position.current_state,
        "to_state": "active",
        "from_revision": position.revision,
        "to_revision": position.revision + 1,
        "transition_id": str(uuid.uuid4()),
    }
    with acting_as_lifecycle_writer(disposable_database, bind_as=principal) as connection:
        record_id = connection.execute(
            _TAGGED_CLAIM_INSERT,
            {
                "t": principal.id,
                "o": lifecycle_transition_operation(TEST_WORKFLOW.machine_key, TEST_WORKFLOW.version),
                "k": key,
                "f": "0" * 64,
                "r": json.dumps(result),
                "m": TEST_WORKFLOW.machine_key,
                "v": TEST_WORKFLOW.version,
            },
        ).scalar_one()
        connection.commit()
    return record_id


def _valid_provenance_parameters(disposable_database, application_engine, principal, new_instance):
    """A provenance row every constraint would accept: the identity is the only thing wrong.

    The claim is a lifecycle claim with no provenance of its own (writer-constructed, since
    nobody else can), the transition and the event come from a genuine **unlinked** move,
    so neither carries provenance either; the tenant, the machine and the revisions agree.
    """
    position = new_instance(principal)
    moved = _unlinked_move(application_engine, principal, position)
    claimant = new_instance(principal)
    record_id = _tagged_claim_without_provenance(
        disposable_database, principal, claimant, f"vp-{uuid.uuid4().hex}"
    )
    return {
        "r": record_id,
        "t": principal.id,
        "x": moved.transition_id,
        "i": position.id,
        "m": TEST_WORKFLOW.machine_key,
        "v": TEST_WORKFLOW.version,
        "fr": moved.from_revision,
        "tr": moved.to_revision,
        "e": moved.event_id,
    }


# ---------------------------------------------- 1. the schema owner's direct INSERT


def test_a_valid_provenance_row_is_refused_to_the_schema_owner(
    disposable_database, owner_engine, application_engine, principal_a, new_instance
):
    """**The reviewer's attack, executable, and closed.**

    Every foreign key is satisfied, every uniqueness constraint would pass, the tenant and
    the machine agree, and the writer is bound as the tenant. The schema owner is refused
    all the same, by the guard, on identity -- and the same row written by the lifecycle
    writer is accepted, which is what proves the refusal was about the identity and not
    about the row.
    """
    parameters = _valid_provenance_parameters(
        disposable_database, application_engine, principal_a, new_instance
    )
    with owner_engine.connect() as connection:
        _bind(connection, principal_a)
        with pytest.raises(DBAPIError) as exc:
            connection.execute(_PROVENANCE_INSERT, parameters)
        connection.rollback()
        enabled = connection.execute(
            text(
                "SELECT g.tgenabled FROM pg_catalog.pg_trigger g "
                "JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid "
                "WHERE c.relname = 'lifecycle_claim_provenance' "
                "AND g.tgname = 'lifecycle_claim_provenance_derived'"
            )
        ).scalar_one()
    assert enabled == "O", "the guard trigger is not enabled, so the refusal proves nothing"
    state, message = _refusal(exc)
    assert state == "42501"
    assert "written by the transition boundary" in message
    assert "schema owner included" in message

    # The positive control: the identical row, written by the writer, is accepted.
    with acting_as_lifecycle_writer(disposable_database, bind_as=principal_a) as connection:
        connection.execute(_PROVENANCE_INSERT, parameters)
        connection.commit()
    with owner_engine.connect() as connection:
        assert connection.execute(
            text(
                f"SELECT count(*) FROM {SCHEMA}.lifecycle_claim_provenance "
                "WHERE idempotency_record_id = :r"
            ),
            {"r": parameters["r"]},
        ).scalar_one() == 1


# ------------------------------------- 2. the two runtime roles' direct INSERTs


@pytest.mark.parametrize("role_kind", ["application", "provisioning"])
def test_the_runtime_roles_are_refused_provenance_by_the_privilege_system(
    application_engine, provisioning_engine, principal_a, new_instance, role_kind
):
    """No grant, so the refusal is the privilege system's, one layer before the guard."""
    engine = application_engine if role_kind == "application" else provisioning_engine
    position = new_instance(principal_a)
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(engine, principal_a.credential) as session:
            session.execute(
                _PROVENANCE_INSERT,
                {
                    "r": uuid.uuid4(),
                    "t": principal_a.id,
                    "x": uuid.uuid4(),
                    "i": position.id,
                    "m": TEST_WORKFLOW.machine_key,
                    "v": TEST_WORKFLOW.version,
                    "fr": 0,
                    "tr": 1,
                    "e": uuid.uuid4(),
                },
            )
    assert "permission denied" in str(exc.value).lower()


# ------------------------------------- 3. an unrelated owner-owned definer function


def test_an_unrelated_owner_definer_function_is_refused_too(
    disposable_database, owner_engine, application_engine, principal_a, new_instance
):
    """A second ``SECURITY DEFINER`` function owned by the schema owner runs as the schema owner.

    Under the previous check that was enough to write provenance; it is not the lifecycle
    writer, so it is refused now -- called by the owner, and called by the application role
    after being granted, because who calls a definer function does not change who it runs
    as. Created and dropped inside the test so the shared database is left as it was.
    """
    parameters = _valid_provenance_parameters(
        disposable_database, application_engine, principal_a, new_instance
    )
    forge = text(
        f"SELECT {SCHEMA}.forge_lifecycle_provenance(:r, :t, :x, :i, :m, :v, :fr, :tr, :e)"
    )
    with owner_engine.connect() as connection:
        connection.execute(
            text(
                f"CREATE FUNCTION {SCHEMA}.forge_lifecycle_provenance("
                "p_r uuid, p_t uuid, p_x uuid, p_i uuid, p_m text, p_v integer, "
                "p_fr integer, p_tr integer, p_e uuid) RETURNS void "
                "LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $f$ "
                f"BEGIN INSERT INTO {SCHEMA}.lifecycle_claim_provenance "
                "(idempotency_record_id, tenant_id, lifecycle_transition_id, "
                "lifecycle_instance_id, machine_key, machine_version, from_revision, "
                "to_revision, outbox_event_id) "
                "VALUES (p_r, p_t, p_x, p_i, p_m, p_v, p_fr, p_tr, p_e); END $f$"
            )
        )
        connection.execute(
            text(
                f"GRANT EXECUTE ON FUNCTION {SCHEMA}.forge_lifecycle_provenance("
                "uuid, uuid, uuid, uuid, text, integer, integer, integer, uuid) "
                f'TO "{disposable_database.application_role}"'
            )
        )
        connection.commit()
    try:
        with owner_engine.connect() as connection:
            _bind(connection, principal_a)
            with pytest.raises(DBAPIError) as as_owner:
                connection.execute(forge, parameters)
            connection.rollback()
        with pytest.raises(DBAPIError) as as_application:
            with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
                session.execute(forge, parameters)
        for exc in (as_owner, as_application):
            state, message = _refusal(exc)
            assert state == "42501", message
            assert "written by the transition boundary" in message
        with owner_engine.connect() as connection:
            assert connection.execute(
                text(
                    f"SELECT count(*) FROM {SCHEMA}.lifecycle_claim_provenance "
                    "WHERE idempotency_record_id = :r"
                ),
                {"r": parameters["r"]},
            ).scalar_one() == 0
    finally:
        with owner_engine.connect() as connection:
            connection.execute(
                text(
                    f"DROP FUNCTION {SCHEMA}.forge_lifecycle_provenance("
                    "uuid, uuid, uuid, uuid, text, integer, integer, integer, uuid)"
                )
            )
            connection.commit()


# ------------------------------------------------- 4. nobody can SET ROLE to the writer


def test_no_role_can_set_role_to_the_writer(
    disposable_database, owner_engine, raw_application_connection, provisioning_engine
):
    """The schema owner included: the temporary membership the bootstrap took is gone."""
    statement = text(f'SET ROLE "{disposable_database.lifecycle_writer_role}"')
    with pytest.raises(ProgrammingError) as exc:
        raw_application_connection.execute(statement)
    assert "permission denied to set role" in str(exc.value)
    raw_application_connection.rollback()

    provisioning = provisioning_engine.execution_options(isolation_level="AUTOCOMMIT")
    with provisioning.connect() as connection:
        with pytest.raises(ProgrammingError) as exc:
            connection.execute(statement)
        assert "permission denied to set role" in str(exc.value)

    with owner_engine.connect() as connection:
        with pytest.raises(ProgrammingError) as exc:
            connection.execute(statement)
        assert "permission denied to set role" in str(exc.value)
        connection.rollback()


# ---------------------------------------------- 5. no membership path reaches the writer


def test_no_membership_path_reaches_the_writer(disposable_database, owner_engine, admin_engine):
    """Read from ``pg_auth_members`` rather than inferred, and walked transitively.

    The only row that may name the writer is the bootstrap administrator's own creator row,
    which a ``CREATEROLE`` administrator receives with ``ADMIN OPTION`` and nothing else
    (a superuser administrator receives none). That row is the accepted trusted-administrator
    reach; it carries neither ``SET`` nor ``INHERIT``, and nothing the per-run roles can
    reach leads to the writer by any path.
    """
    writer = disposable_database.lifecycle_writer_role
    with admin_engine.connect() as connection:
        administrator = connection.execute(text("SELECT current_user")).scalar_one()
        rows = connection.execute(
            text(
                "SELECT pg_catalog.pg_get_userbyid(m.member), m.admin_option, m.inherit_option, "
                "       m.set_option "
                "FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid "
                "WHERE r.rolname = :w"
            ),
            {"w": writer},
        ).all()
    for member, admin_option, inherit_option, set_option in rows:
        assert member == administrator, rows
        assert admin_option is True and inherit_option is False and set_option is False, rows

    with owner_engine.connect() as connection:
        for role in (
            disposable_database.owner_role,
            disposable_database.application_role,
            disposable_database.provisioning_role,
        ):
            for privilege in ("MEMBER", "USAGE", "SET"):
                assert connection.execute(
                    text("SELECT pg_catalog.pg_has_role(:role, :writer, :privilege)"),
                    {"role": role, "writer": writer, "privilege": privilege},
                ).scalar_one() is False, (role, privilege)
        # And the writer itself is a member of nothing.
        assert connection.execute(
            text(
                "SELECT count(*) FROM pg_catalog.pg_auth_members m "
                "JOIN pg_catalog.pg_roles r ON r.oid = m.member WHERE r.rolname = :w"
            ),
            {"w": writer},
        ).scalar_one() == 0


# ----------------------------------------------------- 6. the writer's role profile


def test_the_writer_is_nologin_nobypassrls_and_carries_no_privileged_attribute(
    disposable_database, owner_engine
):
    with owner_engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, "
                "       rolreplication, rolinherit "
                "FROM pg_catalog.pg_roles WHERE rolname = :w"
            ),
            {"w": disposable_database.lifecycle_writer_role},
        ).one()
    assert tuple(row) == (False, False, False, False, False, False, False), row
    with owner_engine.connect() as connection:
        inventory = roles.lifecycle_writer_inventory(
            connection, disposable_database.lifecycle_writer_role
        )
    assert inventory.attributes == {
        name: expected for name, expected in roles.LIFECYCLE_WRITER_ATTRIBUTES
    }


# --------------------------------------- 7. the application role, through the entry point


def test_the_application_role_moves_an_instance_through_the_genuine_entry_point(
    disposable_database, application_engine, principal_a, new_instance
):
    """The whole protected boundary, end to end, and the identity it executed as."""
    position = new_instance(principal_a)
    key = f"gw-{uuid.uuid4().hex}"
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert session.execute(
            text(f"SELECT {SCHEMA}.lifecycle_writer_role()")
        ).scalar_one() == disposable_database.lifecycle_writer_role
        outcome = execute_idempotent_lifecycle_transition(
            session,
            idempotency_key=key,
            instance_id=position.id,
            expected_state=position.current_state,
            expected_revision=position.revision,
            target_state="active",
        )
    assert outcome.replayed is False
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert lifecycle_instance(session, position.id).revision == 1
        # And an identical retry replays, through the provenance the writer wrote.
        again = execute_idempotent_lifecycle_transition(
            session,
            idempotency_key=key,
            instance_id=position.id,
            expected_state="draft",
            expected_revision=0,
            target_state="active",
        )
    assert again.replayed is True
    assert again.record_id == outcome.record_id


# --------------------------------------------- 8. exactly one of each, from the catalogue


def test_a_genuine_transition_writes_exactly_one_claim_event_audit_history_and_provenance_row(
    owner_engine, application_engine, principal_a, new_instance
):
    position = new_instance(principal_a)
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        outcome = execute_idempotent_lifecycle_transition(
            session,
            idempotency_key=f"one-{uuid.uuid4().hex}",
            instance_id=position.id,
            expected_state=position.current_state,
            expected_revision=position.revision,
            target_state="active",
        )
    with auth.authenticated_transaction(owner_engine, principal_a.credential) as session:
        counts = {
            "claims": session.execute(
                text(f"SELECT count(*) FROM {SCHEMA}.idempotency_records WHERE id = :r"),
                {"r": outcome.record_id},
            ).scalar_one(),
            "events": session.execute(
                text(f"SELECT count(*) FROM {SCHEMA}.outbox_events WHERE idempotency_record_id = :r"),
                {"r": outcome.record_id},
            ).scalar_one(),
            "audit": session.execute(
                text(
                    f"SELECT count(*) FROM {SCHEMA}.audit_events "
                    "WHERE resource_id = :i AND action = 'lifecycle.transitioned'"
                ),
                {"i": position.id},
            ).scalar_one(),
            "history": session.execute(
                text(
                    f"SELECT count(*) FROM {SCHEMA}.lifecycle_transitions "
                    "WHERE lifecycle_instance_id = :i"
                ),
                {"i": position.id},
            ).scalar_one(),
            "provenance": session.execute(
                text(
                    f"SELECT count(*) FROM {SCHEMA}.lifecycle_claim_provenance "
                    "WHERE idempotency_record_id = :r"
                ),
                {"r": outcome.record_id},
            ).scalar_one(),
        }
    assert counts == {"claims": 1, "events": 1, "audit": 1, "history": 1, "provenance": 1}, counts


# ---------------------------- 9. owner-tagged construction cannot become replayable


def test_direct_owner_tagged_construction_is_refused_and_cannot_become_replayable(
    disposable_database, owner_engine, application_engine, principal_a, new_instance
):
    """Three tagged rows the owner used to be able to write, and the replay that never follows.

    A tagged claim, a tagged event and a tagged audit row are each refused to the schema
    owner by the tag guard, on identity. And a tagged claim that *does* exist without its
    provenance -- constructible only by the writer -- is refused by the replay rather than
    handed back, so there is no arrangement in which owner-written rows replay.
    """
    position = new_instance(principal_a)
    operation = lifecycle_transition_operation(TEST_WORKFLOW.machine_key, TEST_WORKFLOW.version)
    attempts = {
        "claim": (
            _TAGGED_CLAIM_INSERT,
            {
                "t": principal_a.id,
                "o": operation,
                "k": f"ow-{uuid.uuid4().hex}",
                "f": "0" * 64,
                "r": "{}",
                "m": TEST_WORKFLOW.machine_key,
                "v": TEST_WORKFLOW.version,
            },
        ),
        "event": (
            _TAGGED_EVENT_INSERT,
            {"t": principal_a.id, "a": position.id, "m": TEST_WORKFLOW.machine_key, "v": TEST_WORKFLOW.version},
        ),
        "audit": (
            _TAGGED_AUDIT_INSERT,
            {
                "t": principal_a.id,
                "p": principal_a.principal_id,
                "b": principal_a.binding_id,
                "a": position.id,
                "m": TEST_WORKFLOW.machine_key,
                "v": TEST_WORKFLOW.version,
            },
        ),
    }
    with owner_engine.connect() as connection:
        for label, (statement, parameters) in attempts.items():
            _bind(connection, principal_a)
            with pytest.raises(DBAPIError) as exc:
                connection.execute(statement, parameters)
            connection.rollback()
            state, message = _refusal(exc)
            assert state == "42501", (label, message)
            assert "derived, not supplied" in message, label
            assert "schema owner included" in message, label

    key = f"ow-{uuid.uuid4().hex}"
    _tagged_claim_without_provenance(disposable_database, principal_a, position, key)
    with pytest.raises(LifecycleProvenanceError):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            execute_idempotent_lifecycle_transition(
                session,
                idempotency_key=key,
                instance_id=position.id,
                expected_state="draft",
                expected_revision=0,
                target_state="active",
            )
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert lifecycle_instance(session, position.id).revision == 0


# -------------------------- 10. downgrade, reconciliation, re-upgrade, and no leak


def _inventory(connection, handle):
    return roles.lifecycle_writer_inventory(connection, handle.lifecycle_writer_role)


def _shared_dependencies(connection, role: str) -> int:
    """``pg_shdepend`` rows naming ``role`` in this database: ownerships and grants alike."""
    return connection.execute(
        text(
            "SELECT count(*) FROM pg_catalog.pg_shdepend d "
            "WHERE d.refclassid = 'pg_catalog.pg_authid'::regclass "
            "  AND d.refobjid = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :role) "
            "  AND d.dbid = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())"
        ),
        {"role": role},
    ).scalar_one()


def test_downgrade_reconciliation_and_reupgrade_leave_no_role_or_ownership_leak(
    environment, admin_engine
):
    """0004 -> 0003 -> wire -> 0004 -> wire, and the writer is exactly what it was.

    At ``0003`` the writer owns nothing and holds nothing in the database -- not a grant on
    the schema, not on a table, not on a function -- so ``pg_shdepend`` carries no row for
    it, and reconciling the wiring at that revision keeps it that way. Coming back up
    restores the exact authority boundary: the same two owned objects, the same grants,
    the same executable set, recognised again. And at the end, down again, the
    administrator can ``DROP ROLE`` it: the proof that no dependency survives.
    """
    handle = create_disposable_database(environment)
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            at_head = _inventory(connection, handle)
            assert at_head.recognised
            assert len(at_head.owned_objects) == 2
            assert _shared_dependencies(connection, handle.lifecycle_writer_role) > 0

            migrate.downgrade_to(connection, roles.M2_3_REVISION, expected=expected)
            connection.commit()
            downgraded = _inventory(connection, handle)
            assert downgraded.owned_objects == ()
            assert downgraded.schema_privileges == frozenset()
            assert downgraded.table_privileges == {}
            assert downgraded.column_privileges == {}
            assert downgraded.executable_functions == frozenset()
            assert downgraded.recognised is False
            assert _shared_dependencies(connection, handle.lifecycle_writer_role) == 0

            # Reconciling at 0003 is a no-op that verifies rather than a failure.
            wire_handle_roles(connection, handle)
            connection.commit()
            assert _inventory(connection, handle) == downgraded

            migrate.upgrade_to_head(connection, expected=expected)
            connection.commit()
            # Freshly re-created, the entry points are the schema owner's again and the
            # writer is recognised by nothing -- until the wiring runs.
            assert _inventory(connection, handle).recognised is False
            wire_handle_roles(connection, handle)
            connection.commit()
            restored = _inventory(connection, handle)
            assert restored == at_head, (restored, at_head)

            migrate.downgrade_to(connection, roles.M2_3_REVISION, expected=expected)
            connection.commit()
            assert _shared_dependencies(connection, handle.lifecycle_writer_role) == 0

        with admin_engine.connect() as connection:
            connection.execute(text(f'DROP ROLE "{handle.lifecycle_writer_role}"'))
            assert connection.execute(
                text("SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname = :w"),
                {"w": handle.lifecycle_writer_role},
            ).scalar_one() == 0
    finally:
        drop_disposable_database(handle)


def test_a_failure_while_installing_the_writer_leaks_no_role(environment, monkeypatch):
    """The last wiring step fails, and every object -- the writer included -- is gone."""
    seen: dict[str, str] = {}
    real = bootstrap.roles.install_lifecycle_writer

    def explode(connection, writer_role, application_role):
        seen["writer"] = writer_role
        seen["owner"] = connection.execute(text("SELECT current_user")).scalar_one()
        raise RuntimeError("the writer installation failed on purpose")

    monkeypatch.setattr(bootstrap.roles, "install_lifecycle_writer", explode)
    with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
        bootstrap.create_disposable_database(environment)
    assert real is not explode
    assert "have been removed" in str(exc.value)
    assert seen["writer"].startswith("firmbatch_test_lcw_")

    admin = bootstrap._admin_engine(bootstrap.config.load_test_admin_url(environment))
    try:
        with admin.connect() as connection:
            for role in (seen["writer"], seen["owner"]):
                assert connection.execute(
                    text("SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname = :r"),
                    {"r": role},
                ).scalar_one() == 0, f"{role} was left behind"
    finally:
        admin.dispose()


# ------------------------------------------------- the grant and ownership matrix


def test_the_writer_holds_exactly_the_planned_authority_and_nothing_else(
    disposable_database, owner_engine
):
    """The ownership and grant matrix, read from the catalogue and compared to the plan.

    Two functions owned; ``USAGE`` on the schema; ``SELECT`` on the five tables the bodies
    and the replay read; column-level ``INSERT`` and ``UPDATE`` on exactly the columns the
    bodies write; ``EXECUTE`` on exactly the helpers the bodies, their triggers and the
    policies call plus the two entry points it owns; and no membership carrying ``SET`` or
    ``INHERIT``.
    """
    plan = roles.REVISION_PLANS[roles.M2_4_REVISION]
    with owner_engine.connect() as connection:
        inventory = roles.lifecycle_writer_inventory(
            connection, disposable_database.lifecycle_writer_role
        )
        owned = set(
            connection.execute(
                text(
                    "SELECT p.proname FROM pg_catalog.pg_proc p "
                    "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = :s AND p.proowner = "
                    "(SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :w)"
                ),
                {"s": SCHEMA, "w": disposable_database.lifecycle_writer_role},
            ).scalars()
        )
        expected_executable = set()
        for name, signature in plan.lifecycle_writer_helper_functions + plan.lifecycle_writer_functions:
            expected_executable.add(
                connection.execute(
                    text("SELECT pg_catalog.to_regprocedure(:f)::pg_catalog.oid"),
                    {"f": f"{SCHEMA}.{name}({signature})"},
                ).scalar_one()
            )
        executable = set(
            connection.execute(
                text(
                    "SELECT p.oid FROM pg_catalog.pg_proc p "
                    "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = :s AND pg_catalog.has_function_privilege(:w, p.oid, 'EXECUTE')"
                ),
                {"s": SCHEMA, "w": disposable_database.lifecycle_writer_role},
            ).scalars()
        )

    assert inventory.recognised
    assert owned == {name for name, _signature in plan.lifecycle_writer_functions}
    assert owned == {"create_lifecycle_instance", "transition_lifecycle_instance"}
    assert all(entry.startswith("function ") for entry in inventory.owned_objects)
    assert inventory.schema_privileges == {"USAGE"}
    assert inventory.table_privileges == {
        table: frozenset(privileges.replace(" ", "").split(","))
        for table, privileges in plan.lifecycle_writer_grants
    }
    expected_columns: dict[tuple[str, str], set[str]] = {}
    for table, privilege, columns in plan.lifecycle_writer_column_grants:
        for column in columns:
            expected_columns.setdefault((table, column), set()).add(privilege)
    assert inventory.column_privileges == {
        key: frozenset(value) for key, value in expected_columns.items()
    }
    assert executable == expected_executable
    for _grantor, _member, _admin, inherit, set_option in inventory.memberships:
        assert not inherit and not set_option
    # Nothing on the protected credential registry, the context relation, the definition
    # tables, the tenants or the workspaces -- by omission from the plan, asserted here.
    assert not (set(inventory.table_privileges) & {
        "auth_bindings", "auth_transaction_context", "lifecycle_machines", "lifecycle_states",
        "lifecycle_transition_edges", "tenants", "workspaces",
    })


def test_the_generic_writer_cannot_acquire_the_writers_authority_indirectly(
    disposable_database, owner_engine, application_engine, principal_a
):
    """Every helper the writer may call and the application may not is refused to the application.

    The application role reaches the two entry points, ``lifecycle_required_scope`` and
    ``lifecycle_writer_role`` -- and nothing else the writer holds. Asserted with
    ``has_function_privilege``, which follows inherited privilege, and by calling the two
    helpers whose names most invite it.
    """
    plan = roles.REVISION_PLANS[roles.M2_4_REVISION]
    permitted = {name for name, _signature in plan.application_functions}
    permitted |= {name for name, _signature in plan.common_functions}
    permitted |= {name for name, _signature in plan.lifecycle_writer_functions}
    with owner_engine.connect() as connection:
        for name, signature in plan.lifecycle_writer_helper_functions:
            held = connection.execute(
                text("SELECT pg_catalog.has_function_privilege(:role, :f, 'EXECUTE')"),
                {"role": disposable_database.application_role, "f": f"{SCHEMA}.{name}({signature})"},
            ).scalar_one()
            assert held is (name in permitted), name
    for statement in (
        f"SELECT {SCHEMA}.append_lifecycle_audit_event('lifecycle.transitioned', 'succeeded', "
        "'lifecycle_instance', gen_random_uuid(), '{}'::jsonb, 'test_workflow', 1)",
        f"SELECT * FROM {SCHEMA}.lifecycle_replay_claim('lifecycle.transition.test_workflow.v1', "
        "'some-key-0001', 'test_workflow', 1, repeat('0', 64))",
    ):
        with pytest.raises(ProgrammingError) as exc:
            with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
                session.execute(text(statement))
        assert "permission denied" in str(exc.value).lower(), statement


def test_the_identity_function_fails_closed_when_an_entry_point_is_not_the_writers(environment):
    """Replace one entry point with a schema-owner stub and every guard refuses.

    The writer is recognised only while it owns *both* entry points. A schema owner that
    drops one and recreates it -- a deliberate DDL act, and the one the trusted-administrator
    limitation is about -- does not become the writer; it makes there be no writer, and the
    remaining genuine entry point refuses too because its tagged writes are no longer
    recognised. The failure direction is closed rather than open.
    """
    from firmbatch.control_plane.db import engine as db_engine
    from firmbatch.control_plane.db.lifecycle import (
        create_lifecycle_instance,
        register_lifecycle_definition,
    )
    from firmbatch.control_plane.security.authorization import AuthorizationError

    from .conftest import DEFAULT_SCOPES, _new_principal

    handle = create_disposable_database(environment)
    try:
        owner = migrate.create_migration_engine(handle.migration_url)
        provisioning = db_engine.create_application_engine(handle.provisioning_url, pool_size=2)
        application = db_engine.create_application_engine(handle.application_url)
        try:
            with owner.connect() as connection:
                register_lifecycle_definition(connection, TEST_WORKFLOW)
                connection.commit()
            principal = _new_principal(provisioning, "stub", DEFAULT_SCOPES)
            with auth.authenticated_transaction(application, principal.credential) as session:
                position = create_lifecycle_instance(
                    session, machine_key=TEST_WORKFLOW.machine_key, machine_version=TEST_WORKFLOW.version
                )

            with owner.connect() as connection:
                connection.execute(text(f"DROP FUNCTION {SCHEMA}.create_lifecycle_instance(text, integer)"))
                connection.execute(
                    text(
                        f"CREATE FUNCTION {SCHEMA}.create_lifecycle_instance(p_k text, p_v integer) "
                        "RETURNS TABLE (instance_id uuid, initial_state text, event_id uuid) "
                        "LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog "
                        "AS $f$ SELECT NULL::uuid, NULL::text, NULL::uuid $f$"
                    )
                )
                connection.commit()
                assert connection.execute(
                    text(f"SELECT {SCHEMA}.lifecycle_writer_role()")
                ).scalar_one() is None

            with pytest.raises(AuthorizationError) as exc:
                with auth.authenticated_transaction(application, principal.credential) as session:
                    transition_lifecycle_instance(
                        session,
                        instance_id=position.id,
                        expected_state=position.current_state,
                        expected_revision=position.revision,
                        target_state="active",
                    )
            assert "derived, not supplied" in str(exc.value)
            with auth.authenticated_transaction(application, principal.credential) as session:
                assert lifecycle_instance(session, position.id).revision == 0
        finally:
            application.dispose()
            provisioning.dispose()
            owner.dispose()
    finally:
        drop_disposable_database(handle)
