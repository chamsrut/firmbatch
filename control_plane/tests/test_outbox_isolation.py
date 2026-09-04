"""The M2.2 tables inherit the isolation boundary, and add append-only to it.

``test_tenant_isolation.py`` establishes the boundary on the spine. Two new tenant-owned
tables do not inherit that by being written in the same style -- they inherit it by
carrying the same forced policies, the same fail-closed behaviour without context, and
grants that were extended rather than widened. This module asserts all three, from the
restricted application role, against real PostgreSQL.

It also asserts the property the spine has no equivalent of: a committed outbox event is
immutable. That is enforced twice, and both halves are tested separately, because they
fail in different directions and each covers what the other cannot:

* the application role holds no ``UPDATE`` or ``DELETE`` privilege, so it gets an error;
* the tables carry no ``UPDATE`` or ``DELETE`` policy, so any role that somehow held the
  privilege -- including the owner, since row security is ``FORCE``d -- reaches no row.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.idempotency import (
    MutationOutcome,
    OutboxEventSpec,
    append_outbox_event,
    execute_idempotent_mutation,
    outbox_events,
)
from firmbatch.control_plane.db.models import (
    APPEND_ONLY_TABLES,
    IdempotencyRecord,
    OutboxEvent,
    Workspace,
)
from firmbatch.control_plane.db.repositories import WorkspaceRepository

OPERATION = "workspace.create"


def _key() -> str:
    return f"iso-{uuid.uuid4().hex}"


def _claim(engine, tenant_id, slug: str):
    """Commit one idempotent mutation and return (record_id, event_id)."""

    def mutate(unit_of_work):
        workspace = WorkspaceRepository(unit_of_work).create(slug=slug, name=slug.replace("-", " "))
        return MutationOutcome(
            result={"workspace_id": workspace.id},
            event=OutboxEventSpec(
                event_type="workspace.created",
                aggregate_type="workspace",
                aggregate_id=workspace.id,
                attributes={"slug": slug},
            ),
        )

    with db_engine.tenant_transaction(engine, tenant_id) as session:
        outcome = execute_idempotent_mutation(
            session,
            operation=OPERATION,
            idempotency_key=_key(),
            request_identity={"workspace_slug": slug},
            mutate=mutate,
        )
    return outcome.record_id, outcome.event_id


# ------------------------------------------------------------------------ fail closed


def test_without_tenant_context_neither_table_is_readable(application_engine, tenant_a):
    _claim(application_engine, tenant_a, "closed-read")
    with db_engine.transaction(application_engine) as session:
        assert session.scalars(select(IdempotencyRecord)).all() == []
        assert session.scalars(select(OutboxEvent)).all() == []


@pytest.mark.parametrize("table", sorted(APPEND_ONLY_TABLES))
def test_without_tenant_context_an_append_is_rejected(application_engine, tenant_a, table):
    """The INSERT policy's predicate is NULL with no context, so the write is refused."""
    statements = {
        "idempotency_records": (
            f"INSERT INTO {SCHEMA}.idempotency_records "
            "(tenant_id, operation, idempotency_key, request_fingerprint, result) "
            "VALUES (:t, 'workspace.create', 'no-context-key-1', :f, '{}'::jsonb)"
        ),
        "outbox_events": (
            f"INSERT INTO {SCHEMA}.outbox_events "
            "(tenant_id, idempotency_record_id, event_type, aggregate_type, aggregate_id) "
            "VALUES (:t, :r, 'workspace.created', 'workspace', :a)"
        ),
    }
    record_id, _ = _claim(application_engine, tenant_a, f"closed-append-{table[:6]}")
    with pytest.raises(DBAPIError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(
                text(statements[table]),
                {"t": tenant_a, "f": "0" * 64, "r": record_id, "a": uuid.uuid4()},
            )
    assert "row-level security" in str(exc.value).lower()


def test_tenant_a_cannot_read_tenant_b_claims_or_events(application_engine, tenant_a, tenant_b):
    b_record, b_event = _claim(application_engine, tenant_b, "beta-private")

    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        assert session.scalars(select(IdempotencyRecord)).all() == []
        assert session.scalars(select(OutboxEvent)).all() == []
        assert session.get(IdempotencyRecord, b_record) is None
        assert session.get(OutboxEvent, b_event) is None
        assert session.scalar(select(func.count()).select_from(OutboxEvent)) == 0


def test_tenant_a_cannot_append_into_tenant_b(application_engine, tenant_a, tenant_b):
    """The WITH CHECK half: a row may not be written outside the writing tenant's scope."""
    b_record, _ = _claim(application_engine, tenant_b, "beta-target")

    with pytest.raises(DBAPIError) as exc:
        with db_engine.tenant_transaction(application_engine, tenant_a) as session:
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.idempotency_records "
                    "(tenant_id, operation, idempotency_key, request_fingerprint, result) "
                    "VALUES (:t, 'workspace.create', 'stolen-key-1234', :f, '{}'::jsonb)"
                ),
                {"t": tenant_b, "f": "1" * 64},
            )
    assert "row-level security" in str(exc.value).lower()

    with pytest.raises(DBAPIError) as exc:
        with db_engine.tenant_transaction(application_engine, tenant_a) as session:
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.outbox_events "
                    "(tenant_id, idempotency_record_id, event_type, aggregate_type, aggregate_id) "
                    "VALUES (:t, :r, 'workspace.created', 'workspace', :a)"
                ),
                {"t": tenant_b, "r": b_record, "a": uuid.uuid4()},
            )
    assert "row-level security" in str(exc.value).lower()


def test_an_event_cannot_be_attached_to_another_tenants_claim(application_engine, tenant_a, tenant_b):
    """The composite foreign key, which referential integrity checks with RLS bypassed.

    A single-column ``REFERENCES idempotency_records(id)`` would have accepted this: the
    check runs with row security off, so tenant B's claim id is perfectly valid there.
    Referencing ``(id, tenant_id)`` is what makes tenant consistency a database fact.
    """
    b_record, _ = _claim(application_engine, tenant_b, "beta-anchor")
    a_record, _ = _claim(application_engine, tenant_a, "alpha-anchor")

    with pytest.raises(IntegrityError) as exc:
        with db_engine.tenant_transaction(application_engine, tenant_a) as session:
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.outbox_events "
                    "(tenant_id, idempotency_record_id, event_type, aggregate_type, aggregate_id) "
                    "VALUES (:t, :r, 'workspace.created', 'workspace', :a)"
                ),
                {"t": tenant_a, "r": b_record, "a": uuid.uuid4()},
            )
    assert "foreign key" in str(exc.value).lower()
    assert a_record != b_record


def test_one_claim_may_not_carry_two_events(application_engine, tenant_a):
    """**At most one** linked event per claim -- which is all a unique constraint can say.

    It cannot require that a claim has an event; that the primitive writes exactly one,
    atomically with the claim, is proved in ``test_idempotency.py`` by counting committed
    rows.
    """
    record_id, _ = _claim(application_engine, tenant_a, "alpha-single-event")

    with pytest.raises(IntegrityError) as exc:
        with db_engine.tenant_transaction(application_engine, tenant_a) as session:
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.outbox_events "
                    "(tenant_id, idempotency_record_id, event_type, aggregate_type, aggregate_id) "
                    "VALUES (:t, :r, 'workspace.renamed', 'workspace', :a)"
                ),
                {"t": tenant_a, "r": record_id, "a": uuid.uuid4()},
            )
    assert "uq_outbox_events_tenant_id_idempotency_record_id" in str(exc.value)


# ------------------------------------------------------------------------ append only


@pytest.mark.parametrize("table", sorted(APPEND_ONLY_TABLES))
def test_the_application_role_cannot_update_or_delete(raw_application_connection, table):
    """No privilege, so the attempt is an error rather than a quiet no-op."""
    for statement in (
        f"UPDATE {SCHEMA}.{table} SET tenant_id = tenant_id",
        f"DELETE FROM {SCHEMA}.{table}",
    ):
        with pytest.raises(ProgrammingError) as exc:
            raw_application_connection.execute(text(statement))
        assert "permission denied" in str(exc.value).lower()


def test_a_committed_event_cannot_be_rewritten_through_the_orm(application_engine, tenant_a):
    _claim(application_engine, tenant_a, "alpha-immutable")

    with pytest.raises(ProgrammingError):
        with db_engine.tenant_transaction(application_engine, tenant_a) as session:
            session.execute(update(OutboxEvent).values(event_type="workspace.rewritten"))

    with pytest.raises(ProgrammingError):
        with db_engine.tenant_transaction(application_engine, tenant_a) as session:
            session.execute(delete(OutboxEvent))

    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        event = session.scalars(select(OutboxEvent)).one()
        assert event.event_type == "workspace.created"


def test_even_a_privileged_role_reaches_no_row_to_update_or_delete(owner_engine, application_engine, tenant_a):
    """The half a grant cannot buy.

    The owner holds every privilege on these tables and is still subject to the policies,
    because row security is ``FORCE``d -- and there is no ``UPDATE`` or ``DELETE`` policy
    for it to be subject to. So the statement is permitted and matches nothing. That is
    what makes append-only a property of the schema rather than of today's grant list.
    """
    _claim(application_engine, tenant_a, "alpha-owner-proof")

    with db_engine.tenant_transaction(owner_engine, tenant_a) as session:
        # The owner really can see the rows, so a zero rowcount below is the policy and
        # not an empty table.
        assert session.scalar(select(func.count()).select_from(OutboxEvent)) == 1
        assert session.scalar(select(func.count()).select_from(IdempotencyRecord)) == 1
        # Raw SQL, so what is measured is PostgreSQL's row count and not an ORM
        # synchronisation strategy's idea of one.
        for statement in (
            f"UPDATE {SCHEMA}.outbox_events SET event_type = 'workspace.forced'",
            f"DELETE FROM {SCHEMA}.outbox_events",
            f"UPDATE {SCHEMA}.idempotency_records SET status = 'completed'",
            f"DELETE FROM {SCHEMA}.idempotency_records",
        ):
            assert session.execute(text(statement)).rowcount == 0, statement

    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        assert session.scalars(select(OutboxEvent)).one().event_type == "workspace.created"


def test_a_stored_result_cannot_be_revised(application_engine, tenant_a):
    """A completed claim is final; a retry replays what was committed, not what was edited."""
    _claim(application_engine, tenant_a, "alpha-final")
    with pytest.raises(ProgrammingError) as exc:
        with db_engine.tenant_transaction(application_engine, tenant_a) as session:
            session.execute(update(IdempotencyRecord).values(result={"workspace_id": str(uuid.uuid4())}))
    assert "permission denied" in str(exc.value).lower()


# ----------------------------------------------------------------------------- grants


def _privileges(owner_engine, role: str, table: str) -> set[str]:
    with owner_engine.connect() as connection:
        return set(
            connection.execute(
                text(
                    "SELECT privilege_type FROM information_schema.role_table_grants "
                    "WHERE table_schema = :schema AND table_name = :table AND grantee = :role"
                ),
                {"schema": SCHEMA, "table": table, "role": role},
            ).scalars()
        )


@pytest.mark.parametrize("table", sorted(APPEND_ONLY_TABLES))
def test_the_application_role_holds_exactly_select_and_insert(owner_engine, disposable_database, table):
    assert _privileges(owner_engine, disposable_database.application_role, table) == {"SELECT", "INSERT"}


@pytest.mark.parametrize("table", sorted(APPEND_ONLY_TABLES))
def test_the_provisioning_role_gained_nothing(owner_engine, disposable_database, table):
    """M2.2 extends the application role's reach. It must not extend provisioning's.

    Provisioning creates tenants. It has no business reading another role's idempotency
    keys, and no business seeing the events they produced.
    """
    assert _privileges(owner_engine, disposable_database.provisioning_role, table) == set()


@pytest.mark.parametrize("table", sorted(APPEND_ONLY_TABLES))
def test_the_provisioning_role_is_refused_at_the_database(provisioning_engine, tenant_a, table):
    with pytest.raises(ProgrammingError) as exc:
        with db_engine.tenant_transaction(provisioning_engine, tenant_a) as session:
            session.execute(text(f"SELECT * FROM {SCHEMA}.{table}"))
    assert "permission denied" in str(exc.value).lower()


@pytest.mark.parametrize("table", sorted(APPEND_ONLY_TABLES))
def test_public_holds_nothing_on_either_table(owner_engine, table):
    """Nothing is inherited from a PostgreSQL default; PUBLIC is revoked explicitly."""
    assert _privileges(owner_engine, "PUBLIC", table) == set()


def test_neither_runtime_role_gained_a_privileged_attribute(owner_engine, disposable_database):
    """The M2.2 grants are table grants. No role attribute changed, and none may.

    Ownership, DDL, ``SUPERUSER``, ``BYPASSRLS``, ``REPLICATION``, ``CREATEDB`` and
    ``CREATEROLE`` are each a complete bypass of the boundary the new tables sit behind.
    """
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                """
                SELECT rolname, rolsuper, rolbypassrls, rolreplication, rolcreatedb, rolcreaterole
                FROM pg_roles WHERE rolname = ANY(:roles)
                """
            ),
            {"roles": [disposable_database.application_role, disposable_database.provisioning_role]},
        ).all()
        owners = dict(
            connection.execute(
                text("SELECT tablename, tableowner FROM pg_tables WHERE schemaname = :schema"),
                {"schema": SCHEMA},
            ).all()
        )
    assert len(rows) == 2
    for row in rows:
        assert row[1:] == (False, False, False, False, False), row[0]
    for table in APPEND_ONLY_TABLES:
        assert owners[table] not in (
            disposable_database.application_role,
            disposable_database.provisioning_role,
        ), table
        assert owners[table] == disposable_database.owner_role


@pytest.mark.parametrize("table", sorted(APPEND_ONLY_TABLES))
def test_row_security_is_enabled_and_forced_on_the_new_tables(owner_engine, table):
    with owner_engine.connect() as connection:
        enabled, forced = connection.execute(
            text(
                "SELECT c.relrowsecurity, c.relforcerowsecurity FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = :schema AND c.relname = :table"
            ),
            {"schema": SCHEMA, "table": table},
        ).one()
    assert enabled, f"{table}: row-level security is not enabled"
    assert forced, f"{table}: row-level security is not FORCEd, so the owner is exempt"


@pytest.mark.parametrize("table", sorted(APPEND_ONLY_TABLES))
def test_the_application_role_cannot_disable_the_new_policies(raw_application_connection, table):
    for statement in (
        f"ALTER TABLE {SCHEMA}.{table} NO FORCE ROW LEVEL SECURITY",
        f"ALTER TABLE {SCHEMA}.{table} DISABLE ROW LEVEL SECURITY",
        f"DROP POLICY {table}_tenant_read ON {SCHEMA}.{table}",
    ):
        with pytest.raises(ProgrammingError) as exc:
            raw_application_connection.execute(text(statement))
        message = str(exc.value).lower()
        assert "must be owner" in message or "permission denied" in message


# ------------------------------------------------- the outbox is not only for the API


def _rename_workspace_internally(engine, tenant_id, workspace_id, new_name: str):
    """An internal, tenant-scoped state change that appends its own event.

    This is the shape every later authoritative transition has -- controller, reconciler,
    validator, lifecycle. There is no caller, no HTTP request, and no idempotency key to
    scope one by, so the event's causation link is NULL.
    """
    with db_engine.tenant_transaction(engine, tenant_id) as session:
        session.execute(
            update(Workspace).where(Workspace.id == workspace_id).values(name=new_name)
        )
        return append_outbox_event(
            session,
            OutboxEventSpec(
                event_type="workspace.renamed",
                aggregate_type="workspace",
                aggregate_id=workspace_id,
                attributes={"reason": "internal_reconciliation"},
            ),
        )


def test_an_internal_state_change_can_append_an_event_without_an_idempotency_record(
    application_engine, tenant_a
):
    """The outbox belongs to every authoritative state transition, not only to the API.

    Requiring a claim per event would mean manufacturing an idempotency record for each
    internal transition -- rows nobody can ever retry against, in the table that exists to
    record retries. The link is optional instead.
    """
    _claim(application_engine, tenant_a, "alpha-internal")
    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        workspace_id = WorkspaceRepository(session).get_by_slug("alpha-internal").id

    event_id = _rename_workspace_internally(application_engine, tenant_a, workspace_id, "Renamed Internally")

    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        events = {e.id: e for e in outbox_events(session)}
        assert len(events) == 2, "the claim's event and the internal one"
        internal = events[event_id]
        assert internal.idempotency_record_id is None
        assert internal.event_type == "workspace.renamed"
        assert internal.tenant_id == tenant_a
        assert internal.attributes == {"reason": "internal_reconciliation"}
        # No claim was manufactured for it.
        assert session.scalar(select(func.count()).select_from(IdempotencyRecord)) == 1
        assert WorkspaceRepository(session).get(workspace_id).name == "Renamed Internally"


def test_two_internal_events_do_not_collide_on_the_null_link(application_engine, tenant_a):
    """PostgreSQL treats NULLs as distinct, so unlinked events do not fight the constraint."""
    _claim(application_engine, tenant_a, "alpha-two-internal")
    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        workspace_id = WorkspaceRepository(session).get_by_slug("alpha-two-internal").id

    first = _rename_workspace_internally(application_engine, tenant_a, workspace_id, "First Rename")
    second = _rename_workspace_internally(application_engine, tenant_a, workspace_id, "Second Rename")
    assert first != second

    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        unlinked = [e for e in outbox_events(session) if e.idempotency_record_id is None]
        assert len(unlinked) == 2


def test_a_rolled_back_internal_change_takes_its_event_with_it(application_engine, tenant_a):
    """Atomicity, in the direction that matters: neither half survives alone."""
    _claim(application_engine, tenant_a, "alpha-atomic")
    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        workspace_id = WorkspaceRepository(session).get_by_slug("alpha-atomic").id
        original = WorkspaceRepository(session).get(workspace_id).name

    with pytest.raises(RuntimeError):
        with db_engine.tenant_transaction(application_engine, tenant_a) as session:
            session.execute(
                update(Workspace).where(Workspace.id == workspace_id).values(name="Never Committed")
            )
            append_outbox_event(
                session,
                OutboxEventSpec(
                    event_type="workspace.renamed",
                    aggregate_type="workspace",
                    aggregate_id=workspace_id,
                    attributes={"reason": "internal_reconciliation"},
                ),
            )
            raise RuntimeError("the process dies here, before COMMIT")

    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        assert WorkspaceRepository(session).get(workspace_id).name == original
        assert [e.idempotency_record_id for e in outbox_events(session)] != [None]
        assert all(e.idempotency_record_id is not None for e in outbox_events(session))


def test_appending_an_event_without_tenant_context_is_refused(application_engine):
    with pytest.raises(db_engine.TenantContextError):
        with db_engine.transaction(application_engine) as session:
            append_outbox_event(
                session,
                OutboxEventSpec(
                    event_type="workspace.renamed",
                    aggregate_type="workspace",
                    aggregate_id=uuid.uuid4(),
                ),
            )


def test_an_internal_event_is_still_tenant_scoped(application_engine, tenant_a, tenant_b):
    """Decoupling the link does not decouple the tenant."""
    _claim(application_engine, tenant_a, "alpha-scoped")
    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        workspace_id = WorkspaceRepository(session).get_by_slug("alpha-scoped").id
    _rename_workspace_internally(application_engine, tenant_a, workspace_id, "Scoped Rename")

    with db_engine.tenant_transaction(application_engine, tenant_b) as session:
        assert outbox_events(session) == []
