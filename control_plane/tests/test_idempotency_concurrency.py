"""Two callers, one key, one effect -- proved by contention, not by argument.

The single-threaded tests in ``test_idempotency.py`` show that a *sequential* retry
replays. That is the easy half. The claim Milestone 2 actually needs is that two callers
racing on one key still produce one committed effect and one linked outbox event, and a
sequential test cannot demonstrate it: it never reaches the window where both callers
have decided the key is free.

Note the shape of the claim, because it is narrower than "one caller runs the mutation".
Both callers **execute**; the loser's mutation is rolled back to a SAVEPOINT and it then
replays the winner's result. What is asserted below is that exactly one mutation
*commits*, which is why every test counts committed rows rather than callback
invocations.

So the tests here force that window open and hold it. One caller claims the key and is
paused before its ``COMMIT``; the second is released and blocks; a third connection
watches ``pg_stat_activity`` until it can see that the second caller really is waiting on
a lock, and only then is the first allowed to commit. If the block is never observed the
test **fails** rather than passing on an interleaving that proved nothing.

The mechanism under test is the unique index and PostgreSQL's transaction semantics.
Nothing here holds a lock in Python -- an in-process mutex would stop meaning anything
the moment a second control-plane process started, which is the deployment this system
is for.
"""

from __future__ import annotations

import threading
import time
import uuid

import pytest
from sqlalchemy import func, select, text

from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.idempotency import (
    IdempotencyConflict,
    MutationOutcome,
    OutboxEventSpec,
    execute_idempotent_mutation,
)
from firmbatch.control_plane.db.models import IdempotencyRecord, OutboxEvent, Workspace
from firmbatch.control_plane.db.repositories import WorkspaceRepository

OPERATION = "workspace.create"

#: Generous. A local PostgreSQL reports a waiting backend in milliseconds; this is long
#: enough that a loaded machine does not turn a real property into a flaky one.
BLOCK_TIMEOUT_SECONDS = 20.0


def _key() -> str:
    return f"race-{uuid.uuid4().hex}"


def _counts(engine, tenant_id) -> dict[str, int]:
    with db_engine.tenant_transaction(engine, tenant_id) as session:
        return {
            "workspaces": session.scalar(select(func.count()).select_from(Workspace)),
            "records": session.scalar(select(func.count()).select_from(IdempotencyRecord)),
            "events": session.scalar(select(func.count()).select_from(OutboxEvent)),
        }


def _mutation(slug: str):
    def mutate(unit_of_work):
        workspace = WorkspaceRepository(unit_of_work).create(slug=slug, name=slug.replace("-", " "))
        return MutationOutcome(
            result={"workspace_id": workspace.id, "slug": workspace.slug},
            event=OutboxEventSpec(
                event_type="workspace.created",
                aggregate_type="workspace",
                aggregate_id=workspace.id,
                attributes={"slug": workspace.slug},
            ),
        )

    return mutate


def _caller(engine, tenant_id, *, key, request_identity, mutate, into, label, before=None, after=None):
    """One idempotent mutation on its own thread, with hooks either side of the primitive.

    ``after`` runs **inside** the transaction, after the claim has been written and before
    ``COMMIT``. That is the pause that holds the race window open: the claim row exists,
    uncommitted, so the next caller to reach the same key blocks on the index.
    """

    def run():
        try:
            if before is not None:
                before()
            with db_engine.tenant_transaction(engine, tenant_id) as session:
                outcome = execute_idempotent_mutation(
                    session,
                    operation=OPERATION,
                    idempotency_key=key,
                    request_identity=request_identity,
                    mutate=mutate,
                )
                if after is not None:
                    after()
                into[label] = outcome
        except BaseException as exc:  # re-raised in the main thread, where it is visible
            into[label] = exc

    return threading.Thread(target=run, name=label, daemon=True)


def _wait_for_a_blocked_backend(engine) -> bool:
    """True once another backend on this database is waiting on a lock.

    ``pg_stat_activity`` shows wait state for sessions belonging to a role the caller has
    the privileges of; every connection here authenticates as the same application role,
    so the watcher can see the waiter without any additional privilege.
    """
    deadline = time.monotonic() + BLOCK_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        with engine.connect() as connection:
            waiting = connection.execute(
                text(
                    """
                    SELECT count(*) FROM pg_stat_activity
                    WHERE datname = current_database()
                      AND pid <> pg_backend_pid()
                      AND state = 'active'
                      AND wait_event_type = 'Lock'
                    """
                )
            ).scalar()
        if waiting:
            return True
        time.sleep(0.05)
    return False


def _unwrap(value):
    if isinstance(value, BaseException):
        raise value
    return value


def _join(threads) -> None:
    for thread in threads:
        thread.join(timeout=BLOCK_TIMEOUT_SECONDS * 2)
        assert not thread.is_alive(), f"{thread.name} did not finish"


def _race(engine, *, winner, loser, results) -> bool:
    """Start the winner, hold it uncommitted, release the loser, wait for it to block.

    Returns whether the loser was actually observed waiting on a lock.
    """
    winner.start()
    assert results["claimed"].wait(timeout=BLOCK_TIMEOUT_SECONDS), "the first caller never claimed the key"
    loser.start()
    observed = _wait_for_a_blocked_backend(engine)
    results["release"].set()
    _join((winner, loser))
    return observed


def _choreography() -> dict:
    """The two events the winner thread waits on, plus somewhere to put results."""
    claimed, release = threading.Event(), threading.Event()
    return {"claimed": claimed, "release": release}


def _hold_after_claim(state: dict):
    def after():
        state["claimed"].set()
        state["release"].wait(timeout=BLOCK_TIMEOUT_SECONDS)

    return after


def test_two_concurrent_callers_produce_one_effect_and_one_event(application_engine, tenant_a):
    key, request_identity = _key(), {"workspace_slug": "raced-workspace"}
    results = _choreography()

    winner = _caller(
        application_engine,
        tenant_a,
        key=key,
        request_identity=request_identity,
        mutate=_mutation("raced-workspace"),
        into=results,
        label="winner",
        after=_hold_after_claim(results),
    )
    loser = _caller(
        application_engine,
        tenant_a,
        key=key,
        request_identity=request_identity,
        mutate=_mutation("raced-workspace"),
        into=results,
        label="loser",
    )

    observed_block = _race(application_engine, winner=winner, loser=loser, results=results)
    assert observed_block, (
        "no backend was ever observed waiting on a lock, so the contended path was not exercised"
    )

    first = _unwrap(results["winner"])
    second = _unwrap(results["loser"])

    assert first.replayed is False
    assert second.replayed is True, "the caller that lost the race must replay, not fail"
    assert second.record_id == first.record_id
    assert second.event_id == first.event_id
    assert second.result == first.result

    assert _counts(application_engine, tenant_a) == {"workspaces": 1, "records": 1, "events": 1}


def test_a_concurrent_conflicting_reuse_is_rejected(application_engine, tenant_a):
    """Losing the race does not turn a conflicting reuse into a replay.

    Here the two callers write *different* workspaces, so the loser reaches the claim
    index itself rather than tripping over a business constraint first -- which is what
    makes this the direct test of the claim index as the serializer. It then re-reads the
    winner's row, finds a different fingerprint, and refuses.
    """
    key = _key()
    results = _choreography()

    winner = _caller(
        application_engine,
        tenant_a,
        key=key,
        request_identity={"workspace_slug": "settled-workspace"},
        mutate=_mutation("settled-workspace"),
        into=results,
        label="winner",
        after=_hold_after_claim(results),
    )
    loser = _caller(
        application_engine,
        tenant_a,
        key=key,
        request_identity={"workspace_slug": "other-workspace"},
        mutate=_mutation("other-workspace"),
        into=results,
        label="loser",
    )

    observed_block = _race(application_engine, winner=winner, loser=loser, results=results)
    assert observed_block, "the loser never blocked on the claim index"

    assert _unwrap(results["winner"]).replayed is False
    assert isinstance(results["loser"], IdempotencyConflict), results["loser"]

    # The refused caller's workspace went back with its transaction.
    assert _counts(application_engine, tenant_a) == {"workspaces": 1, "records": 1, "events": 1}
    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        assert [w.slug for w in WorkspaceRepository(session).list()] == ["settled-workspace"]


def test_a_field_of_callers_still_produces_one_effect(application_engine, tenant_a):
    """The same property with no choreography at all, under whatever order happens.

    Four threads released together. Whichever interleaving occurs -- contended, or so
    sequential that the later callers take the plain replay path -- the committed state
    is one workspace, one claim and one event.
    """
    key, request_identity = _key(), {"workspace_slug": "crowded-workspace"}
    results: dict[str, object] = {}
    start = threading.Barrier(4)

    threads = [
        _caller(
            application_engine,
            tenant_a,
            key=key,
            request_identity=request_identity,
            mutate=_mutation("crowded-workspace"),
            into=results,
            label=f"caller-{i}",
            # Before the transaction, so a caller that takes the fast replay path has
            # already passed the barrier and cannot leave the others waiting on it.
            before=lambda: start.wait(timeout=BLOCK_TIMEOUT_SECONDS),
        )
        for i in range(4)
    ]
    for thread in threads:
        thread.start()
    _join(threads)

    outcomes = [_unwrap(results[f"caller-{i}"]) for i in range(4)]
    assert sum(1 for o in outcomes if not o.replayed) == 1, "exactly one mutation may commit"
    assert len({o.record_id for o in outcomes}) == 1
    assert len({o.event_id for o in outcomes}) == 1
    assert _counts(application_engine, tenant_a) == {"workspaces": 1, "records": 1, "events": 1}


def test_concurrent_callers_in_different_tenants_do_not_collide(application_engine, tenant_a, tenant_b):
    """The same key in two tenants is two claims, even simultaneously.

    A globally scoped key would make one of these callers replay the other tenant's
    result -- which is a cross-tenant read wearing a helpful name.
    """
    key, request_identity = _key(), {"workspace_slug": "parallel-workspace"}
    results: dict[str, object] = {}
    start = threading.Barrier(2)

    threads = [
        _caller(
            application_engine,
            tenant,
            key=key,
            request_identity=request_identity,
            mutate=_mutation("parallel-workspace"),
            into=results,
            label=label,
            before=lambda: start.wait(timeout=BLOCK_TIMEOUT_SECONDS),
        )
        for tenant, label in ((tenant_a, "alpha"), (tenant_b, "beta"))
    ]
    for thread in threads:
        thread.start()
    _join(threads)

    alpha = _unwrap(results["alpha"])
    beta = _unwrap(results["beta"])
    assert alpha.replayed is False and beta.replayed is False
    assert alpha.record_id != beta.record_id
    assert alpha.result["workspace_id"] != beta.result["workspace_id"]
    assert _counts(application_engine, tenant_a) == {"workspaces": 1, "records": 1, "events": 1}
    assert _counts(application_engine, tenant_b) == {"workspaces": 1, "records": 1, "events": 1}


@pytest.mark.parametrize("repeat", range(3))
def test_the_race_result_is_stable_across_repeats(application_engine, tenant_a, repeat):
    """A concurrency property that only holds sometimes is not a property.

    Cheap enough to run more than once, and a lost effect or a second event would show up
    here rather than in production.
    """
    key, request_identity = _key(), {"workspace_slug": f"repeated-workspace-{repeat}"}
    results: dict[str, object] = {}
    start = threading.Barrier(2)

    threads = [
        _caller(
            application_engine,
            tenant_a,
            key=key,
            request_identity=request_identity,
            mutate=_mutation(f"repeated-workspace-{repeat}"),
            into=results,
            label=f"caller-{i}",
            before=lambda: start.wait(timeout=BLOCK_TIMEOUT_SECONDS),
        )
        for i in range(2)
    ]
    for thread in threads:
        thread.start()
    _join(threads)

    outcomes = [_unwrap(results[f"caller-{i}"]) for i in range(2)]
    assert sum(1 for o in outcomes if not o.replayed) == 1
    assert _counts(application_engine, tenant_a) == {"workspaces": 1, "records": 1, "events": 1}
