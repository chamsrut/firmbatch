"""The append-only tables inherit the isolation boundary, and add immutability to it.

``test_tenant_isolation.py`` establishes the boundary on the spine. Tenant-owned tables do
not inherit that by being written in the same style -- they inherit it by carrying the
same forced policies, the same fail-closed behaviour without an authenticated context, and
grants that were extended rather than widened. This module asserts all three, from the
restricted application role, against real PostgreSQL.

Every parametrised test here walks ``APPEND_ONLY_TABLES``, so Milestone 2.3's
``audit_events`` is covered by the same assertions the M2.2 tables are, and a fourth
append-only table added later would be too. That is deliberate: the properties are
properties of the *category*, and a test that named its tables individually would silently
stop covering the newest one.

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

from firmbatch.control_plane.db import auth
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


def _claim(engine, principal, slug: str):
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

    with auth.authenticated_transaction(engine, principal.credential) as session:
        outcome = execute_idempotent_mutation(
            session,
            operation=OPERATION,
            idempotency_key=_key(),
            request_identity={"workspace_slug": slug},
            mutate=mutate,
        )
    return outcome.record_id, outcome.event_id


# ------------------------------------------------------------------------ fail closed


def test_without_tenant_context_neither_table_is_readable(application_engine, principal_a):
    _claim(application_engine, principal_a, "closed-read")
    with db_engine.transaction(application_engine) as session:
        assert session.scalars(select(IdempotencyRecord)).all() == []
        assert session.scalars(select(OutboxEvent)).all() == []


#: What each runtime role holds on each append-only table, and why.
#:
#: The two Milestone 2.2 tables take ``SELECT, INSERT`` for the application role: it claims
#: idempotency keys and appends outbox events, and never revises either.
#:
#: The audit trail takes ``SELECT`` and **not** ``INSERT``, which is the Milestone 2.3
#: correction. Appending goes through ``firmbatch.append_audit_event()``, a hardened
#: ``SECURITY DEFINER`` function that applies the whole bounded-metadata policy to the row
#: it is about to write. An ``INSERT`` privilege here would make that policy advisory: the
#: table's check constraints bound a details document's size and shape and say nothing at
#: all about its content, so a role holding ``INSERT`` could write a bearer credential into
#: the trail simply by composing the statement itself.
APPLICATION_PRIVILEGES = {
    "idempotency_records": {"SELECT", "INSERT"},
    "outbox_events": {"SELECT", "INSERT"},
    "audit_events": {"SELECT"},
}

#: Nothing at all for provisioning. Not on the M2.2 tables -- it creates tenants and has no
#: business reading another role's idempotency keys or the events they produced -- and not
#: on the audit trail either: it records what it did through the same hardened function,
#: and it cannot read the trail back because reading it is the ``audit:read`` capability
#: and a provisioning context does not carry one.
PROVISIONING_PRIVILEGES = {
    "idempotency_records": set(),
    "outbox_events": set(),
    "audit_events": set(),
}

#: The append-only tables a runtime role can attempt an ``INSERT`` on at all, with a
#: statement that would succeed if the policy allowed it.
#:
#: ``audit_events`` is deliberately absent, and its absence is a stronger property than an
#: entry would be: no runtime role holds ``INSERT`` on the trail, so a context-less append
#: does not reach the policy -- it is refused one layer earlier, by the privilege system.
#: The policy is still there and still evaluated, and ``test_audit_events.py`` exercises it
#: from the owner connection, which is the only identity that can now reach it.
DIRECT_APPENDS = {
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


def test_every_append_only_table_is_either_insertable_or_privilege_protected():
    """The split above is data, so this is what keeps it honest.

    Each append-only table is in exactly one of two states: the application role may
    attempt an ``INSERT`` and the policy refuses it, or the application role may not
    attempt one at all. A table that fell out of both would be silently untested.
    """
    covered = set(DIRECT_APPENDS)
    protected = {table for table, held in APPLICATION_PRIVILEGES.items() if "INSERT" not in held}
    assert covered | protected == set(APPEND_ONLY_TABLES)
    assert covered & protected == set()


@pytest.mark.parametrize("table", sorted(DIRECT_APPENDS))
def test_without_tenant_context_an_append_is_rejected(application_engine, principal_a, table):
    """The INSERT policy's predicate is NULL with no context, so the write is refused."""
    record_id, _ = _claim(application_engine, principal_a, f"closed-append-{table.replace('_', '-')}")
    with pytest.raises(DBAPIError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(
                text(DIRECT_APPENDS[table]),
                {"t": principal_a.id, "f": "0" * 64, "r": record_id, "a": uuid.uuid4()},
            )
    assert "row-level security" in str(exc.value).lower()


@pytest.mark.parametrize(
    "table", sorted(t for t, held in APPLICATION_PRIVILEGES.items() if "INSERT" not in held)
)
def test_an_append_only_table_without_an_insert_grant_refuses_earlier(
    application_engine, principal_a, table
):
    """With a valid context, and still refused -- by privilege rather than by policy.

    The counterpart to the test above. There is no context that makes this succeed, which
    is what "the hardened function is the only way in" means in the privilege system.
    """
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.{table} (action, outcome, resource_type) "
                    "VALUES ('a.b', 'succeeded', 'thing')"
                )
            )
    assert "permission denied" in str(exc.value).lower()


def test_tenant_a_cannot_read_tenant_b_claims_or_events(application_engine, principal_a, principal_b):
    b_record, b_event = _claim(application_engine, principal_b, "beta-private")

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert session.scalars(select(IdempotencyRecord)).all() == []
        assert session.scalars(select(OutboxEvent)).all() == []
        assert session.get(IdempotencyRecord, b_record) is None
        assert session.get(OutboxEvent, b_event) is None
        assert session.scalar(select(func.count()).select_from(OutboxEvent)) == 0


def test_tenant_a_cannot_append_into_tenant_b(application_engine, principal_a, principal_b):
    """The WITH CHECK half: a row may not be written outside the writing tenant's scope."""
    b_record, _ = _claim(application_engine, principal_b, "beta-target")

    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.idempotency_records "
                    "(tenant_id, operation, idempotency_key, request_fingerprint, result) "
                    "VALUES (:t, 'workspace.create', 'stolen-key-1234', :f, '{}'::jsonb)"
                ),
                {"t": principal_b.id, "f": "1" * 64},
            )
    assert "row-level security" in str(exc.value).lower()

    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.outbox_events "
                    "(tenant_id, idempotency_record_id, event_type, aggregate_type, aggregate_id) "
                    "VALUES (:t, :r, 'workspace.created', 'workspace', :a)"
                ),
                {"t": principal_b.id, "r": b_record, "a": uuid.uuid4()},
            )
    assert "row-level security" in str(exc.value).lower()


def test_an_event_cannot_be_attached_to_another_tenants_claim(application_engine, principal_a, principal_b):
    """The composite foreign key, which referential integrity checks with RLS bypassed.

    A single-column ``REFERENCES idempotency_records(id)`` would have accepted this: the
    check runs with row security off, so tenant B's claim id is perfectly valid there.
    Referencing ``(id, tenant_id)`` is what makes tenant consistency a database fact.
    """
    b_record, _ = _claim(application_engine, principal_b, "beta-anchor")
    a_record, _ = _claim(application_engine, principal_a, "alpha-anchor")

    with pytest.raises(IntegrityError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.outbox_events "
                    "(tenant_id, idempotency_record_id, event_type, aggregate_type, aggregate_id) "
                    "VALUES (:t, :r, 'workspace.created', 'workspace', :a)"
                ),
                {"t": principal_a.id, "r": b_record, "a": uuid.uuid4()},
            )
    assert "foreign key" in str(exc.value).lower()
    assert a_record != b_record


def test_one_claim_may_not_carry_two_events(application_engine, principal_a):
    """**At most one** linked event per claim -- which is all a unique constraint can say.

    It cannot require that a claim has an event; that the primitive writes exactly one,
    atomically with the claim, is proved in ``test_idempotency.py`` by counting committed
    rows.
    """
    record_id, _ = _claim(application_engine, principal_a, "alpha-single-event")

    with pytest.raises(IntegrityError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.outbox_events "
                    "(tenant_id, idempotency_record_id, event_type, aggregate_type, aggregate_id) "
                    "VALUES (:t, :r, 'workspace.renamed', 'workspace', :a)"
                ),
                {"t": principal_a.id, "r": record_id, "a": uuid.uuid4()},
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


def test_a_committed_event_cannot_be_rewritten_through_the_orm(application_engine, principal_a):
    _claim(application_engine, principal_a, "alpha-immutable")

    with pytest.raises(ProgrammingError):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(update(OutboxEvent).values(event_type="workspace.rewritten"))

    with pytest.raises(ProgrammingError):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(delete(OutboxEvent))

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        event = session.scalars(select(OutboxEvent)).one()
        assert event.event_type == "workspace.created"


def test_even_a_privileged_role_reaches_no_row_to_update_or_delete(owner_engine, application_engine, principal_a):
    """The half a grant cannot buy.

    The owner holds every privilege on these tables and is still subject to the policies,
    because row security is ``FORCE``d -- and there is no ``UPDATE`` or ``DELETE`` policy
    for it to be subject to. So the statement is permitted and matches nothing. That is
    what makes append-only a property of the schema rather than of today's grant list.
    """
    _claim(application_engine, principal_a, "alpha-owner-proof")

    with auth.authenticated_transaction(owner_engine, principal_a.credential) as session:
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

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert session.scalars(select(OutboxEvent)).one().event_type == "workspace.created"


def test_a_stored_result_cannot_be_revised(application_engine, principal_a):
    """A completed claim is final; a retry replays what was committed, not what was edited."""
    _claim(application_engine, principal_a, "alpha-final")
    with pytest.raises(ProgrammingError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
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
def test_the_application_role_holds_exactly_its_allowlist(owner_engine, disposable_database, table):
    assert set(APPLICATION_PRIVILEGES) == set(APPEND_ONLY_TABLES), (
        "an append-only table was added without deciding what the application may do with it"
    )
    assert _privileges(owner_engine, disposable_database.application_role, table) == (
        APPLICATION_PRIVILEGES[table]
    )


@pytest.mark.parametrize("table", sorted(APPEND_ONLY_TABLES))
def test_the_provisioning_role_holds_only_what_it_must(owner_engine, disposable_database, table):
    """These grants extend the application role's reach. They must not extend provisioning's.

    Since the Milestone 2.3 correction the answer is "nothing, on any of them".
    Provisioning appends to the audit trail through ``firmbatch.append_audit_event()`` like
    everybody else, so it needs no table privilege in order to leave a trail and holds
    none.
    """
    assert set(PROVISIONING_PRIVILEGES) == set(APPEND_ONLY_TABLES), (
        "an append-only table was added without deciding what provisioning may do with it"
    )
    assert _privileges(owner_engine, disposable_database.provisioning_role, table) == (
        PROVISIONING_PRIVILEGES[table]
    )


@pytest.mark.parametrize("table", sorted(APPEND_ONLY_TABLES))
def test_the_provisioning_role_cannot_read_any_of_them(provisioning_engine, principal_a, table):
    """Including the audit trail, where it may append and may not look."""
    with pytest.raises(ProgrammingError) as exc:
        with auth.authenticated_transaction(provisioning_engine, principal_a.credential) as session:
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
        f"DROP POLICY {table}_authenticated_read ON {SCHEMA}.{table}",
    ):
        with pytest.raises(ProgrammingError) as exc:
            raw_application_connection.execute(text(statement))
        message = str(exc.value).lower()
        assert "must be owner" in message or "permission denied" in message


# ------------------------------------------------- the outbox is not only for the API


def _rename_workspace_internally(engine, principal, workspace_id, new_name: str):
    """An internal, tenant-scoped state change that appends its own event.

    This is the shape every later authoritative transition has -- controller, reconciler,
    validator, lifecycle. There is no caller, no HTTP request, and no idempotency key to
    scope one by, so the event's causation link is NULL.
    """
    with auth.authenticated_transaction(engine, principal.credential) as session:
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
    application_engine, principal_a
):
    """The outbox belongs to every authoritative state transition, not only to the API.

    Requiring a claim per event would mean manufacturing an idempotency record for each
    internal transition -- rows nobody can ever retry against, in the table that exists to
    record retries. The link is optional instead.
    """
    _claim(application_engine, principal_a, "alpha-internal")
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        workspace_id = WorkspaceRepository(session).get_by_slug("alpha-internal").id

    event_id = _rename_workspace_internally(application_engine, principal_a, workspace_id, "Renamed Internally")

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        events = {e.id: e for e in outbox_events(session)}
        assert len(events) == 2, "the claim's event and the internal one"
        internal = events[event_id]
        assert internal.idempotency_record_id is None
        assert internal.event_type == "workspace.renamed"
        assert internal.tenant_id == principal_a.id
        assert internal.attributes == {"reason": "internal_reconciliation"}
        # No claim was manufactured for it.
        assert session.scalar(select(func.count()).select_from(IdempotencyRecord)) == 1
        assert WorkspaceRepository(session).get(workspace_id).name == "Renamed Internally"


def test_two_internal_events_do_not_collide_on_the_null_link(application_engine, principal_a):
    """PostgreSQL treats NULLs as distinct, so unlinked events do not fight the constraint."""
    _claim(application_engine, principal_a, "alpha-two-internal")
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        workspace_id = WorkspaceRepository(session).get_by_slug("alpha-two-internal").id

    first = _rename_workspace_internally(application_engine, principal_a, workspace_id, "First Rename")
    second = _rename_workspace_internally(application_engine, principal_a, workspace_id, "Second Rename")
    assert first != second

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        unlinked = [e for e in outbox_events(session) if e.idempotency_record_id is None]
        assert len(unlinked) == 2


def test_a_rolled_back_internal_change_takes_its_event_with_it(application_engine, principal_a):
    """Atomicity, in the direction that matters: neither half survives alone."""
    _claim(application_engine, principal_a, "alpha-atomic")
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        workspace_id = WorkspaceRepository(session).get_by_slug("alpha-atomic").id
        original = WorkspaceRepository(session).get(workspace_id).name

    with pytest.raises(RuntimeError):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
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

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert WorkspaceRepository(session).get(workspace_id).name == original
        assert [e.idempotency_record_id for e in outbox_events(session)] != [None]
        assert all(e.idempotency_record_id is not None for e in outbox_events(session))


def test_appending_an_event_without_an_authenticated_context_is_refused(application_engine):
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


def test_an_internal_event_is_still_tenant_scoped(application_engine, principal_a, principal_b):
    """Decoupling the link does not decouple the tenant."""
    _claim(application_engine, principal_a, "alpha-scoped")
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        workspace_id = WorkspaceRepository(session).get_by_slug("alpha-scoped").id
    _rename_workspace_internally(application_engine, principal_a, workspace_id, "Scoped Rename")

    with auth.authenticated_transaction(application_engine, principal_b.credential) as session:
        assert outbox_events(session) == []
