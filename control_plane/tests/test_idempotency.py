"""The idempotent-mutation primitive, against real PostgreSQL.

The Milestone 2 gate is two halves: cross-tenant access fails closed (M2.1, and extended
to the new tables in ``test_outbox_isolation.py``) and **duplicate mutations produce one
contractual effect**. This module is the second half.

Every test drives ``db/idempotency.py`` through the restricted application role and a
real transaction, and counts what is actually in the database afterwards -- the workspace
rows, the idempotency records and the outbox events -- rather than trusting the value the
primitive returned. A primitive that reported a replay while writing a second row would
pass a test that only read its return value.

The contractual effect used throughout is a workspace, because it is the only tenant-owned
business table that exists. Nothing here builds job, quote or billing tables; those are
later milestones.

On what the metadata tests do and do not establish: they show that the primitive persists
a digest and bounded metadata, and that the obvious payload- and credential-shaped fields
are refused **before** the mutation runs. They do not establish that customer payload
cannot reach PostgreSQL -- ``TEXT`` and ``JSONB`` hold text. That data-flow proof is
Milestone 5's.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.idempotency import (
    IdempotencyConflict,
    IdempotencyError,
    IsolationLevelError,
    MetadataPolicyError,
    MutationContractError,
    MutationOutcome,
    MutationUnitOfWork,
    OutboxEventSpec,
    canonical_json,
    execute_idempotent_mutation,
    outbox_events,
    request_fingerprint,
    validated_metadata,
)
from firmbatch.control_plane.db.models import IdempotencyRecord, OutboxEvent, Workspace
from firmbatch.control_plane.db.repositories import WorkspaceRepository

OPERATION = "workspace.create"

#: A request identity of the shape M2.2 is for: identifiers, counts, and references to
#: objects that live in S3. The bytes themselves never appear.
MANIFEST_IDENTITY = {
    "workspace_slug": "alpha-manifest",
    "input_manifest_id": "01HQ8Z0000000000000000000A",
    "input_manifest_digest": "sha256:" + "ab" * 28,
    "output_object_key": "tenants/alpha/jobs/01HQ8Z/outputs/",
    "artifact_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "request_count": 4000,
}


def _key(label: str = "k") -> str:
    return f"{label}-{uuid.uuid4().hex}"


class _Recorder:
    """A mutation wrapper that counts how many times it was actually invoked.

    Several tests below assert **zero** invocations: a malformed operation, a malformed
    key, or a request identity carrying payload-shaped material must be refused before any
    business change is attempted, not after.
    """

    def __init__(self, slug: str, *, fail_after: bool = False, body=None):
        self.slug = slug
        self.fail_after = fail_after
        self.body = body
        self.calls = 0

    def __call__(self, unit_of_work):
        self.calls += 1
        if self.body is not None:
            return self.body(unit_of_work)
        workspace = WorkspaceRepository(unit_of_work).create(
            slug=self.slug, name=self.slug.replace("-", " ")
        )
        if self.fail_after:
            raise RuntimeError("deliberate failure after the business mutation")
        return MutationOutcome(
            result={"workspace_id": workspace.id, "slug": workspace.slug},
            event=OutboxEventSpec(
                event_type="workspace.created",
                aggregate_type="workspace",
                aggregate_id=workspace.id,
                attributes={"slug": workspace.slug},
            ),
        )


def _create_workspace(slug: str, *, fail_after: bool = False) -> _Recorder:
    return _Recorder(slug, fail_after=fail_after)


def _run(engine, tenant_id, *, key: str, identity: dict, mutate, operation: str = OPERATION):
    with db_engine.tenant_transaction(engine, tenant_id) as session:
        return execute_idempotent_mutation(
            session,
            operation=operation,
            idempotency_key=key,
            request_identity=identity,
            mutate=mutate,
        )


def _counts(engine, tenant_id) -> dict[str, int]:
    """What this tenant can actually see, read back on its own transaction."""
    with db_engine.tenant_transaction(engine, tenant_id) as session:
        return {
            "workspaces": session.scalar(select(func.count()).select_from(Workspace)),
            "records": session.scalar(select(func.count()).select_from(IdempotencyRecord)),
            "events": session.scalar(select(func.count()).select_from(OutboxEvent)),
        }


# ------------------------------------------------------------------ the replay contract


def test_an_identical_retry_returns_the_stored_result(application_engine, tenant_a):
    key = _key()

    first = _run(application_engine, tenant_a, key=key, identity=MANIFEST_IDENTITY, mutate=_create_workspace("alpha-one"))
    second = _run(application_engine, tenant_a, key=key, identity=MANIFEST_IDENTITY, mutate=_create_workspace("alpha-one"))

    assert first.replayed is False
    assert second.replayed is True
    assert second.result == first.result
    assert second.record_id == first.record_id
    assert second.event_id == first.event_id
    assert uuid.UUID(second.result["workspace_id"])


def test_an_identical_retry_makes_exactly_one_contractual_effect(application_engine, tenant_a):
    """The count, not the return value. One workspace, one claim, one event."""
    key = _key()
    mutate = _create_workspace("alpha-once")

    for _ in range(4):
        _run(application_engine, tenant_a, key=key, identity=MANIFEST_IDENTITY, mutate=mutate)

    assert _counts(application_engine, tenant_a) == {"workspaces": 1, "records": 1, "events": 1}
    assert mutate.calls == 1, "a replay must not reach the mutation at all"


def test_the_second_call_never_runs_the_mutation(application_engine, tenant_a):
    """A replay must not reach the mutation -- not merely undo it afterwards."""
    mutate = _create_workspace("alpha-counted")
    key = _key()
    _run(application_engine, tenant_a, key=key, identity=MANIFEST_IDENTITY, mutate=mutate)
    _run(application_engine, tenant_a, key=key, identity=MANIFEST_IDENTITY, mutate=mutate)

    assert mutate.calls == 1


def test_the_primitive_writes_exactly_one_linked_event(application_engine, tenant_a):
    """Exactly one, atomically -- which is a property of the primitive, not of a constraint.

    The unique constraint on ``(tenant_id, idempotency_record_id)`` bounds duplicates; it
    cannot require that a committed claim has an event. So the claim and its event are
    counted here, together, after a real commit.
    """
    key = _key()
    result = _run(
        application_engine, tenant_a, key=key, identity=MANIFEST_IDENTITY, mutate=_create_workspace("alpha-evented")
    )

    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        events = outbox_events(session)
        assert len(events) == 1
        event = events[0]
        assert event.id == result.event_id
        assert event.event_type == "workspace.created"
        assert event.aggregate_type == "workspace"
        assert str(event.aggregate_id) == result.result["workspace_id"]
        assert event.attributes == {"slug": "alpha-evented"}
        assert event.tenant_id == tenant_a
        # The event is attributable to the claim it committed with.
        assert event.idempotency_record_id == result.record_id
        # And the claim exists, in the same committed state.
        assert session.scalars(select(IdempotencyRecord)).one().id == result.record_id


def test_the_claim_records_a_digest_and_not_the_request(application_engine, tenant_a):
    key = _key()
    identity = dict(MANIFEST_IDENTITY, workspace_slug="alpha-digest")
    _run(application_engine, tenant_a, key=key, identity=identity, mutate=_create_workspace("alpha-digest"))

    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        record = session.scalars(select(IdempotencyRecord)).one()
        assert record.request_fingerprint == request_fingerprint(
            tenant_id=tenant_a, operation=OPERATION, request_identity=identity
        )
        assert len(record.request_fingerprint) == 64
        assert record.status == "completed"
        # The identity itself is hashed and discarded; the row keeps the digest only.
        assert "input_manifest_id" not in canonical_json(record.result)
        assert identity["input_manifest_id"] not in canonical_json(record.result)


# ----------------------------------------------------------------- conflicting reuse


def test_reusing_a_key_with_a_different_request_is_rejected(application_engine, tenant_a):
    key = _key()
    _run(
        application_engine,
        tenant_a,
        key=key,
        identity=dict(MANIFEST_IDENTITY, workspace_slug="alpha-first"),
        mutate=_create_workspace("alpha-first"),
    )

    second = _create_workspace("alpha-second")
    with pytest.raises(IdempotencyConflict) as exc:
        _run(
            application_engine,
            tenant_a,
            key=key,
            identity=dict(MANIFEST_IDENTITY, workspace_slug="alpha-second"),
            mutate=second,
        )
    assert key in str(exc.value)
    assert second.calls == 0, "a conflicting reuse must be refused before the mutation runs"

    # And the conflicting call changed nothing.
    assert _counts(application_engine, tenant_a) == {"workspaces": 1, "records": 1, "events": 1}
    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        assert [w.slug for w in WorkspaceRepository(session).list()] == ["alpha-first"]


def test_the_same_key_under_a_different_operation_is_a_different_claim(application_engine, tenant_a):
    """Keys are scoped by operation as well as tenant, so this is not a conflict."""
    key = _key()
    _run(
        application_engine,
        tenant_a,
        key=key,
        identity=dict(MANIFEST_IDENTITY, workspace_slug="alpha-op-one"),
        mutate=_create_workspace("alpha-op-one"),
    )
    second = _run(
        application_engine,
        tenant_a,
        key=key,
        identity=dict(MANIFEST_IDENTITY, workspace_slug="alpha-op-two"),
        mutate=_create_workspace("alpha-op-two"),
        operation="workspace.provision",
    )

    assert second.replayed is False
    assert _counts(application_engine, tenant_a) == {"workspaces": 2, "records": 2, "events": 2}


def test_a_key_is_independent_between_tenants(application_engine, tenant_a, tenant_b):
    """The same key, the same operation, the same identity, in two tenants: two effects."""
    key = _key()

    a = _run(application_engine, tenant_a, key=key, identity=MANIFEST_IDENTITY, mutate=_create_workspace("shared-key-ws"))
    b = _run(application_engine, tenant_b, key=key, identity=MANIFEST_IDENTITY, mutate=_create_workspace("shared-key-ws"))

    assert a.replayed is False and b.replayed is False
    assert a.record_id != b.record_id
    assert a.result["workspace_id"] != b.result["workspace_id"]
    assert _counts(application_engine, tenant_a) == {"workspaces": 1, "records": 1, "events": 1}
    assert _counts(application_engine, tenant_b) == {"workspaces": 1, "records": 1, "events": 1}


def test_the_fingerprint_is_scoped_to_its_tenant_and_operation(tenant_a, tenant_b):
    identity = {"workspace_slug": "same"}
    base = request_fingerprint(tenant_id=tenant_a, operation=OPERATION, request_identity=identity)
    assert base == request_fingerprint(tenant_id=tenant_a, operation=OPERATION, request_identity=identity)
    assert base != request_fingerprint(tenant_id=tenant_b, operation=OPERATION, request_identity=identity)
    assert base != request_fingerprint(tenant_id=tenant_a, operation="workspace.provision", request_identity=identity)
    # Key order is not part of the identity.
    assert request_fingerprint(
        tenant_id=tenant_a, operation=OPERATION, request_identity={"a": 1, "b": 2}
    ) == request_fingerprint(tenant_id=tenant_a, operation=OPERATION, request_identity={"b": 2, "a": 1})


# --------------------------------------------------------------------------- rollback


def test_a_failure_inside_the_mutation_leaves_nothing_behind(application_engine, tenant_a):
    with pytest.raises(RuntimeError):
        _run(
            application_engine,
            tenant_a,
            key=_key(),
            identity=MANIFEST_IDENTITY,
            mutate=_create_workspace("alpha-doomed", fail_after=True),
        )

    assert _counts(application_engine, tenant_a) == {"workspaces": 0, "records": 0, "events": 0}


def test_a_failure_after_the_primitive_returns_rolls_the_whole_thing_back(application_engine, tenant_a):
    """The caller owns the commit, so a caller that dies before it leaves no claim."""
    with pytest.raises(RuntimeError):
        with db_engine.tenant_transaction(application_engine, tenant_a) as session:
            execute_idempotent_mutation(
                session,
                operation=OPERATION,
                idempotency_key=_key(),
                request_identity=MANIFEST_IDENTITY,
                mutate=_create_workspace("alpha-uncommitted"),
            )
            raise RuntimeError("the process dies here, before COMMIT")

    assert _counts(application_engine, tenant_a) == {"workspaces": 0, "records": 0, "events": 0}


def test_a_rolled_back_claim_does_not_block_the_retry(application_engine, tenant_a):
    """No durable 'in progress' row, so the retry is an ordinary first attempt.

    This is the property that makes it safe not to have written a recovery system: there
    is no half-finished record for one to interpret.
    """
    key = _key()
    with pytest.raises(RuntimeError):
        with db_engine.tenant_transaction(application_engine, tenant_a) as session:
            execute_idempotent_mutation(
                session,
                operation=OPERATION,
                idempotency_key=key,
                request_identity=MANIFEST_IDENTITY,
                mutate=_create_workspace("alpha-retried"),
            )
            raise RuntimeError("crash before COMMIT")

    result = _run(
        application_engine, tenant_a, key=key, identity=MANIFEST_IDENTITY, mutate=_create_workspace("alpha-retried")
    )
    assert result.replayed is False
    assert _counts(application_engine, tenant_a) == {"workspaces": 1, "records": 1, "events": 1}


def test_a_refused_result_leaves_nothing_behind(application_engine, tenant_a):
    """The metadata policy refuses before COMMIT, so the mutation goes back with it."""

    def body(unit_of_work):
        workspace = WorkspaceRepository(unit_of_work).create(slug="alpha-leaky", name="Alpha Leaky")
        return MutationOutcome(
            result={"api_key": "sk-live-not-allowed"},
            event=OutboxEventSpec(
                event_type="workspace.created", aggregate_type="workspace", aggregate_id=workspace.id
            ),
        )

    with pytest.raises(MetadataPolicyError):
        _run(application_engine, tenant_a, key=_key(), identity=MANIFEST_IDENTITY, mutate=_Recorder("x", body=body))

    assert _counts(application_engine, tenant_a) == {"workspaces": 0, "records": 0, "events": 0}


def test_a_business_constraint_violation_is_the_callers_error(application_engine, tenant_a):
    """A duplicate slug under a *fresh* key is not a lost race, and must not look like one."""
    _run(
        application_engine,
        tenant_a,
        key=_key(),
        identity=MANIFEST_IDENTITY,
        mutate=_create_workspace("alpha-taken"),
    )
    with pytest.raises(IntegrityError) as exc:
        _run(
            application_engine,
            tenant_a,
            key=_key(),
            identity=MANIFEST_IDENTITY,
            mutate=_create_workspace("alpha-taken"),
        )
    assert "uq_workspaces_tenant_id_slug" in str(exc.value)
    assert _counts(application_engine, tenant_a) == {"workspaces": 1, "records": 1, "events": 1}


# ---------------------------------------------------------------- the mutation contract


def test_a_mutation_cannot_commit_the_outer_transaction(application_engine, tenant_a):
    """The merge blocker.

    ``Session.commit()`` in SQLAlchemy 2.x commits the **outermost** transaction even
    inside an open ``begin_nested()`` SAVEPOINT. A callback holding the real Session could
    therefore persist its business row before the claim and the event were written. The
    callback is given a unit of work that has no ``commit`` at all, so the attempt is
    refused and the business row goes back with the transaction.
    """

    def body(unit_of_work):
        WorkspaceRepository(unit_of_work).create(slug="alpha-committer", name="Alpha Committer")
        unit_of_work.commit()  # must be refused
        raise AssertionError("unreachable: the unit of work must refuse commit()")

    mutate = _Recorder("alpha-committer", body=body)
    with pytest.raises(MutationContractError) as exc:
        _run(application_engine, tenant_a, key=_key(), identity=MANIFEST_IDENTITY, mutate=mutate)

    assert "commit" in str(exc.value)
    assert mutate.calls == 1
    assert _counts(application_engine, tenant_a) == {"workspaces": 0, "records": 0, "events": 0}


def test_a_mutation_that_rolls_back_fails_cleanly_and_leaves_nothing(application_engine, tenant_a):
    def body(unit_of_work):
        WorkspaceRepository(unit_of_work).create(slug="alpha-rollback", name="Alpha Rollback")
        unit_of_work.rollback()  # must be refused
        raise AssertionError("unreachable: the unit of work must refuse rollback()")

    with pytest.raises(MutationContractError) as exc:
        _run(
            application_engine,
            tenant_a,
            key=_key(),
            identity=MANIFEST_IDENTITY,
            mutate=_Recorder("alpha-rollback", body=body),
        )

    assert "rollback" in str(exc.value)
    assert _counts(application_engine, tenant_a) == {"workspaces": 0, "records": 0, "events": 0}


@pytest.mark.parametrize(
    "operation",
    ["commit", "rollback", "close", "begin", "begin_nested", "connection", "get_bind", "expunge_all"],
)
def test_the_unit_of_work_refuses_every_transaction_control_operation(operation):
    """One list, asserted, so a forwarding refactor cannot quietly re-expose one."""
    unit_of_work = MutationUnitOfWork(object())
    with pytest.raises(MutationContractError) as exc:
        getattr(unit_of_work, operation)()
    assert operation in str(exc.value)
    assert "rollback-safe transactional DML" in str(exc.value)


def test_the_transaction_boundary_survives_the_callback(application_engine, tenant_a):
    """The primitive re-checks its own boundary after the callback returns.

    The unit of work removes the reflex path out; this check catches an escape by any
    other route, and turns it into a raised error instead of a claim recorded for a
    mutation that already committed.
    """
    observed = {}

    def body(unit_of_work):
        workspace = WorkspaceRepository(unit_of_work).create(slug="alpha-intact", name="Alpha Intact")
        return MutationOutcome(
            result={"workspace_id": workspace.id},
            event=OutboxEventSpec(
                event_type="workspace.created", aggregate_type="workspace", aggregate_id=workspace.id
            ),
        )

    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        observed["outer"] = session.get_transaction()
        execute_idempotent_mutation(
            session,
            operation=OPERATION,
            idempotency_key=_key(),
            request_identity=MANIFEST_IDENTITY,
            mutate=_Recorder("alpha-intact", body=body),
        )
        # Same outer transaction, and the savepoint has been released rather than left open.
        assert session.get_transaction() is observed["outer"]
        assert session.get_nested_transaction() is None

    assert _counts(application_engine, tenant_a) == {"workspaces": 1, "records": 1, "events": 1}


def test_an_escape_around_the_unit_of_work_is_detected_and_refused(application_engine, tenant_a):
    """The commit is refused **before** it happens, not noticed after it.

    ``object_session(row)`` hands a callback the real ``Session``, and
    ``Session.commit()`` commits the *outermost* transaction even from inside the
    primitive's SAVEPOINT. Detecting that afterwards would be worthless: the business row
    would already be committed with no claim and no event, and a later retry would collide
    with a row nothing explains. So a ``before_commit`` listener scoped to the callback
    refuses first -- ahead of the flush a commit performs -- and **nothing is written**.
    """
    from sqlalchemy.orm import object_session

    def body(unit_of_work):
        workspace = WorkspaceRepository(unit_of_work).create(slug="alpha-escape", name="Alpha Escape")
        object_session(workspace).commit()
        raise AssertionError("unreachable: the commit guard must refuse before the commit")

    with pytest.raises(MutationContractError) as exc:
        _run(
            application_engine,
            tenant_a,
            key=_key(),
            identity=MANIFEST_IDENTITY,
            mutate=_Recorder("alpha-escape", body=body),
        )
    assert "a mutation may not commit" in str(exc.value)

    # Nothing survives. Not the workspace, not a claim, not an event -- which is the whole
    # point: a partial commit is the state this primitive exists to make impossible.
    assert _counts(application_engine, tenant_a) == {"workspaces": 0, "records": 0, "events": 0}


def test_the_commit_guard_is_removed_before_the_caller_commits(application_engine, tenant_a):
    """The guard is scoped to the callback, and its removal is proved by the commit.

    Two commits follow every successful mutation and both are legitimate: the primitive
    releases its own SAVEPOINT (which dispatches ``before_commit``, because the transaction
    is nested), and then ``tenant_transaction`` commits the real one. A listener left
    attached would refuse one of them and nothing would persist, so the rows below are the
    proof that it was removed.
    """
    key = _key()
    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        result = execute_idempotent_mutation(
            session,
            operation=OPERATION,
            idempotency_key=key,
            request_identity=MANIFEST_IDENTITY,
            mutate=_create_workspace("alpha-guard-removed"),
        )
        # The SAVEPOINT has already been released at this point, so its before_commit has
        # fired and was not refused.
        assert session.get_nested_transaction() is None

    # And the outer commit went through.
    assert _counts(application_engine, tenant_a) == {"workspaces": 1, "records": 1, "events": 1}

    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        record = session.scalars(select(IdempotencyRecord)).one()
        event = session.scalars(select(OutboxEvent)).one()
        assert record.id == result.record_id
        assert event.id == result.event_id
        assert event.idempotency_record_id == record.id
        assert [w.slug for w in WorkspaceRepository(session).list()] == ["alpha-guard-removed"]

    # The session is not left in a state that refuses later work either: a second,
    # different operation commits normally on the same engine.
    second = _run(
        application_engine,
        tenant_a,
        key=_key(),
        identity=dict(MANIFEST_IDENTITY, workspace_slug="alpha-guard-second"),
        mutate=_create_workspace("alpha-guard-second"),
    )
    assert second.replayed is False
    assert _counts(application_engine, tenant_a) == {"workspaces": 2, "records": 2, "events": 2}


def test_pending_orm_state_at_entry_is_rejected(application_engine, tenant_a):
    """``begin_nested()`` flushes pending state *before* it opens the SAVEPOINT.

    A row the caller added and did not flush would therefore be written outside the
    boundary the primitive rolls back to, and would survive a lost race that discards
    everything else. Rejecting at entry is what keeps the rollback guarantee from
    depending on what the caller happened to leave behind.
    """
    mutate = _create_workspace("alpha-clean")
    with pytest.raises(MutationContractError) as exc:
        with db_engine.tenant_transaction(application_engine, tenant_a) as session:
            session.add(Workspace(tenant_id=tenant_a, slug="alpha-pending", name="Alpha Pending"))
            execute_idempotent_mutation(
                session,
                operation=OPERATION,
                idempotency_key=_key(),
                request_identity=MANIFEST_IDENTITY,
                mutate=mutate,
            )
    assert "unflushed ORM state" in str(exc.value)
    assert mutate.calls == 0, "the mutation must not run once the session is known to be dirty"
    assert _counts(application_engine, tenant_a) == {"workspaces": 0, "records": 0, "events": 0}


def test_a_write_flushed_before_the_primitive_is_outside_its_savepoint(application_engine, tenant_a):
    """The limit of the entry check, recorded so it is not mistaken for coverage.

    The pending-state check sees ``session.new``/``dirty``/``deleted``. A write the caller
    has already **flushed** is none of those, so the primitive cannot detect it, and it
    sits in the caller's outer transaction *outside* the SAVEPOINT the primitive rolls back
    to. If a lost race discarded the mutation, that earlier write would remain.

    The rule that closes this is a contract rather than a check, and it is stated in
    ``db/idempotency.py``: every business write belonging to the operation goes inside
    ``mutate``, and the primitive is called before any DML for that operation.

    What the outer transaction *does* still cover is the ordinary failure below -- the
    caller dies before ``COMMIT`` and both writes go back together, because they share one
    transaction even though they do not share the savepoint.
    """
    with pytest.raises(RuntimeError):
        with db_engine.tenant_transaction(application_engine, tenant_a) as session:
            session.add(Workspace(tenant_id=tenant_a, slug="alpha-flushed", name="Alpha Flushed"))
            session.flush()
            execute_idempotent_mutation(
                session,
                operation=OPERATION,
                idempotency_key=_key(),
                request_identity=MANIFEST_IDENTITY,
                mutate=_create_workspace("alpha-second-ws"),
            )
            raise RuntimeError("crash before COMMIT")

    assert _counts(application_engine, tenant_a) == {"workspaces": 0, "records": 0, "events": 0}


# ------------------------------------------------------------------------ fail closed


def test_without_tenant_context_an_idempotent_mutation_is_refused(application_engine):
    mutate = _create_workspace("no-context")
    with pytest.raises(db_engine.TenantContextError) as exc:
        with db_engine.transaction(application_engine) as session:
            execute_idempotent_mutation(
                session,
                operation=OPERATION,
                idempotency_key=_key(),
                request_identity=MANIFEST_IDENTITY,
                mutate=mutate,
            )
    assert "tenant context" in str(exc.value)
    assert mutate.calls == 0


def test_the_database_also_refuses_a_claim_written_without_context(application_engine, tenant_a):
    """Two layers, and the database is the one that counts.

    The primitive refuses in Python; this is the same write going straight to PostgreSQL
    with no context, which the INSERT policy rejects because its predicate is NULL.
    """
    with pytest.raises(DBAPIError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.idempotency_records "
                    "(tenant_id, operation, idempotency_key, request_fingerprint, result) "
                    "VALUES (:t, 'workspace.create', 'orphan-key-12345', :f, '{}'::jsonb)"
                ),
                {"t": tenant_a, "f": "0" * 64},
            )
    assert "row-level security" in str(exc.value).lower()


def test_outside_a_transaction_it_is_refused(application_engine):
    from sqlalchemy.orm import Session

    session = Session(bind=application_engine)
    mutate = _create_workspace("never")
    try:
        with pytest.raises(db_engine.TenantContextError):
            execute_idempotent_mutation(
                session,
                operation=OPERATION,
                idempotency_key=_key(),
                request_identity={},
                mutate=mutate,
            )
    finally:
        session.close()
    assert mutate.calls == 0


def test_a_stricter_isolation_level_is_refused_rather_than_mishandled(application_engine, tenant_a):
    """Recovering from a lost race means re-reading a just-committed row.

    Only READ COMMITTED takes a fresh snapshot per statement. Under REPEATABLE READ the
    re-read would return nothing and the caller would be told the key is free when it is
    not, so the level is checked and the wrong one is refused.
    """
    strict = application_engine.execution_options(isolation_level="REPEATABLE READ")
    mutate = _create_workspace("alpha-strict")
    with pytest.raises(IsolationLevelError) as exc:
        _run(strict, tenant_a, key=_key(), identity=MANIFEST_IDENTITY, mutate=mutate)
    assert "repeatable read" in str(exc.value).lower()
    assert mutate.calls == 0
    assert _counts(application_engine, tenant_a) == {"workspaces": 0, "records": 0, "events": 0}


# ------------------------------------------------------- input validation before mutation


@pytest.mark.parametrize(
    "bad_key",
    [
        "",
        "short",
        "has spaces in it",
        "x" * 201,
        "semi;colon;injection",
        # fullmatch, not match: '$' would otherwise accept a trailing newline, and the
        # PostgreSQL check constraint (whose '~' is not newline-sensitive) would then
        # reject at INSERT time what Python had already let past the mutation.
        "valid-key-1234\n",
        "valid-key-1234\nsecond-line",
    ],
)
def test_a_malformed_idempotency_key_is_refused_before_the_mutation(application_engine, tenant_a, bad_key):
    mutate = _create_workspace("alpha-badkey")
    with pytest.raises(IdempotencyError):
        _run(application_engine, tenant_a, key=bad_key, identity=MANIFEST_IDENTITY, mutate=mutate)
    assert mutate.calls == 0
    assert _counts(application_engine, tenant_a) == {"workspaces": 0, "records": 0, "events": 0}


@pytest.mark.parametrize(
    "bad_operation",
    ["", "Not A Valid Operation", "nodots", "workspace.", ".create", "workspace.create\n", "workspace.CREATE"],
)
def test_a_malformed_operation_is_refused_before_the_mutation(application_engine, tenant_a, bad_operation):
    """Validated in Python now, so a bad name cannot produce an unrecorded business change.

    The old behaviour ran the mutation and let the check constraint refuse the claim
    afterwards. The transaction rolled back, so nothing was lost -- but the mutation had
    already executed, which is exactly the ordering this correction is about.
    """
    mutate = _create_workspace("alpha-badop")
    with pytest.raises(IdempotencyError):
        _run(
            application_engine,
            tenant_a,
            key=_key(),
            identity=MANIFEST_IDENTITY,
            mutate=mutate,
            operation=bad_operation,
        )
    assert mutate.calls == 0
    assert _counts(application_engine, tenant_a) == {"workspaces": 0, "records": 0, "events": 0}


def test_the_database_still_refuses_a_malformed_operation(application_engine, tenant_a):
    """Defense in depth: the check constraint holds for a writer that bypasses Python."""
    with pytest.raises(IntegrityError) as exc:
        with db_engine.tenant_transaction(application_engine, tenant_a) as session:
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.idempotency_records "
                    "(tenant_id, operation, idempotency_key, request_fingerprint, result) "
                    "VALUES (:t, 'Not A Valid Operation', 'bypass-key-1234', :f, '{}'::jsonb)"
                ),
                {"t": tenant_a, "f": "0" * 64},
            )
    assert "ck_idempotency_records_operation_format" in str(exc.value)


def test_a_mutation_that_returns_the_wrong_type_is_refused(application_engine, tenant_a):
    with pytest.raises(IdempotencyError):
        _run(
            application_engine,
            tenant_a,
            key=_key(),
            identity=MANIFEST_IDENTITY,
            mutate=_Recorder("x", body=lambda unit_of_work: {"result": {}}),
        )
    assert _counts(application_engine, tenant_a) == {"workspaces": 0, "records": 0, "events": 0}


# ------------------------------------------------------------------- metadata policy


@pytest.mark.parametrize(
    "value",
    [
        {"password": "hunter2"},
        {"api_key": "sk-live-0000"},
        {"authorization": "Bearer abc"},
        {"payload": "the customer's bytes"},
        {"prompt": "write me a sonnet"},
        {"output": "the model's answer"},
        {"content": "..."},
        {"private_key": "-----BEGIN"},
        {"messages": "chat history"},
        {"database_url": "postgresql://user:pw@host/db"},
    ],
)
def test_keys_that_name_content_or_a_credential_are_refused(value):
    with pytest.raises(MetadataPolicyError) as exc:
        validated_metadata(value, where="the request identity")
    assert "names content or a credential" in str(exc.value)


@pytest.mark.parametrize(
    "key",
    [
        # The exact names the old substring rule wrongly rejected. These are references
        # to objects that live in S3, which is precisely what belongs here.
        "input_manifest_id",
        "output_object_key",
        "artifact_digest",
        "input_manifest_digest",
        "output_prefix",
        "content_type",
        "token_count",
        "input_token_count",
        "message_count",
        "body_digest",
    ],
)
def test_reference_shaped_keys_are_accepted(key):
    """The denylist matches whole names, not substrings.

    A substring rule rejected ``input_manifest_id`` and ``output_object_key`` -- the
    metadata this table exists to hold -- while doing nothing about a payload spelled
    under another name. Names are matched whole for that reason.
    """
    assert validated_metadata({key: "reference-value"}, where="the request identity") == {
        key: "reference-value"
    }


def test_payload_shaped_material_is_rejected_before_the_mutation_runs(application_engine, tenant_a):
    """The ordering matters, not only the refusal.

    The request identity is validated at entry, so a caller that passes a raw prompt or an
    API key gets an error with no business change attempted -- rather than a mutation that
    ran and was rolled back.
    """
    for identity in (
        {"prompt": "summarise this document", "workspace_slug": "alpha"},
        {"api_key": "sk-live-" + "9" * 40},
        {"payload": "x" * 100},
        {"input_manifest_id": b"\x00\x01binary"},
    ):
        mutate = _create_workspace("alpha-rejected")
        with pytest.raises(MetadataPolicyError):
            _run(application_engine, tenant_a, key=_key(), identity=identity, mutate=mutate)
        assert mutate.calls == 0, f"{identity!r} must be refused before the mutation runs"

    assert _counts(application_engine, tenant_a) == {"workspaces": 0, "records": 0, "events": 0}


@pytest.mark.parametrize(
    "value",
    [
        {"nested": {"still": "an object"}},
        {"long": "x" * 257},
        {"CapitalKey": 1},
        {"has space": 1},
        {"trailing_newline_key\n": 1},
        {"many": ["a"] * 17},
        {f"k{i}": i for i in range(33)},
        {"binary": b"bytes"},
        {"binary": bytearray(b"bytes")},
        {"ratio": float("nan")},
        {"ratio": float("inf")},
        {"when": object()},
    ],
)
def test_metadata_that_is_not_bounded_metadata_is_refused(value):
    with pytest.raises(MetadataPolicyError):
        validated_metadata(value, where="the mutation result")


def test_metadata_that_is_bounded_metadata_is_accepted():
    accepted = validated_metadata(
        {
            "workspace_id": uuid.UUID("00000000-0000-0000-0000-000000000001"),
            "created": True,
            "shard_count": 12,
            "ratio": 0.5,
            "missing": None,
            "slugs": ["one", "two"],
            "input_manifest_id": "01HQ8Z0000000000000000000A",
        },
        where="the mutation result",
    )
    assert accepted["workspace_id"] == "00000000-0000-0000-0000-000000000001"
    assert accepted["slugs"] == ["one", "two"]
    assert accepted["input_manifest_id"] == "01HQ8Z0000000000000000000A"


def test_an_oversized_metadata_document_is_refused():
    with pytest.raises(MetadataPolicyError) as exc:
        validated_metadata({f"field_{i}": "x" * 200 for i in range(20)}, where="the mutation result")
    assert "bytes" in str(exc.value)


def test_only_a_digest_of_the_request_identity_is_persisted(application_engine, tenant_a):
    """What M2.2 actually proves about the payload plane, stated as narrowly as it holds.

    The identity is bounded metadata -- object references and counts -- and none of its
    values reaches a row: the claim keeps a SHA-256 digest and the result keeps what the
    mutation chose to record. This is **not** a proof that payload cannot reach
    PostgreSQL; ``TEXT`` and ``JSONB`` hold text, and the bounds and deny rules are
    defense in depth. The data-flow proof belongs to Milestone 5.
    """
    # Marked values, none of which the mutation records, so finding one in a row would
    # mean the identity itself had been persisted rather than hashed.
    marker = uuid.uuid4().hex
    identity = {
        "input_manifest_id": f"MANIFESTMARKER{marker}",
        "input_manifest_digest": f"DIGESTMARKER{marker}",
        "output_object_key": f"KEYMARKER{marker}",
    }
    _run(application_engine, tenant_a, key=_key(), identity=identity, mutate=_create_workspace("alpha-private"))

    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        stored = "".join(
            session.scalars(text(f"SELECT row_to_json(t)::text FROM {SCHEMA}.idempotency_records t")).all()
        ) + "".join(
            session.scalars(text(f"SELECT row_to_json(t)::text FROM {SCHEMA}.outbox_events t")).all()
        )
        fingerprint = session.scalars(select(IdempotencyRecord.request_fingerprint)).one()

    assert stored, "nothing was stored, so this test would pass vacuously"
    assert fingerprint in stored
    for value in identity.values():
        assert value not in stored, f"{value!r} from the request identity reached a row"
    assert marker not in stored


def test_the_application_role_cannot_widen_the_bounds_it_was_given(raw_application_connection):
    """The check constraints are the owner's, not the application's, to relax."""
    with pytest.raises(ProgrammingError) as exc:
        raw_application_connection.execute(
            text(f"ALTER TABLE {SCHEMA}.idempotency_records DROP CONSTRAINT ck_idempotency_records_result_bounded")
        )
    message = str(exc.value).lower()
    assert "must be owner" in message or "permission denied" in message
