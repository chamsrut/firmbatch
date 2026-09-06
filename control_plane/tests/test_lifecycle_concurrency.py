"""Two callers, one instance, one revision -- proved by contention, not by argument.

``test_lifecycle_transitions.py`` shows that a *sequential* stale revision is refused. That
is the easy half. The claim Milestone 2.4 actually needs is that two callers who read the
same instance at the same revision, and then both decide to move it, produce **one** move
between them -- and a sequential test cannot demonstrate it, because it never reaches the
window where both callers have decided.

So the tests here force that window open and hold it. One caller performs its transition and
is paused before ``COMMIT``; the second is released and blocks on the instance's row lock; a
third connection watches ``pg_stat_activity`` until it can see that the second really is
waiting; only then is the first allowed to commit. If the block is never observed the test
**fails** rather than passing on an interleaving that proved nothing.

The mechanism is worth naming precisely, because two different controls meet here and only
one of them is doing this job:

* an **idempotency key** bounds retries of one request. Two callers using *different* keys
  are two different requests and do not serialise on the claim index at all;
* the **revision** bounds concurrent requests. The conditional ``UPDATE`` takes the
  instance's row lock; the second caller blocks there, and when the first commits it
  re-evaluates its own predicate against the row that now exists, matches nothing, and
  conflicts.

Neither substitutes for the other, and the tests below use different keys precisely so that
it is the revision, and not the claim index, that is under test.

Nothing here holds a lock in Python. An in-process mutex would stop meaning anything the
moment a second control-plane process started, which is the deployment this system is for.
"""

from __future__ import annotations

import ast
import pathlib
import threading
import time
import uuid

import pytest
from sqlalchemy import func, select, text

from firmbatch.control_plane import migrate
from firmbatch.control_plane.db import auth, lifecycle
from firmbatch.control_plane.db.audit import audit_events
from firmbatch.control_plane.db.lifecycle import (
    TRANSITIONED_ACTION,
    LifecycleConflict,
    execute_idempotent_lifecycle_transition,
    lifecycle_history,
    lifecycle_instance,
    transition_lifecycle_instance,
)
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.idempotency import IdempotencyConflict
from firmbatch.control_plane.db.models import IdempotencyRecord, OutboxEvent

from .conftest import TEST_CYCLIC

OPERATION = "lifecycle.transition"

#: Generous. A local PostgreSQL reports a waiting backend in milliseconds; this is long
#: enough that a loaded machine does not turn a real property into a flaky one.
BLOCK_TIMEOUT_SECONDS = 20.0


def _key() -> str:
    return f"race-{uuid.uuid4().hex}"


def _counts(engine, principal, instance_id) -> dict[str, int]:
    with auth.authenticated_transaction(engine, principal.credential) as session:
        instance = lifecycle_instance(session, instance_id)
        return {
            "state": instance.current_state,
            "revision": instance.revision,
            "history": len(lifecycle_history(session, instance_id)),
            "moves": len([e for e in audit_events(session) if e.action == TRANSITIONED_ACTION]),
            # Transition events only. Creating the instance commits a ``.created`` event of
            # its own, so "events about this instance" is no longer "moves".
            "events": session.scalar(
                select(func.count()).select_from(OutboxEvent).where(
                    OutboxEvent.aggregate_id == instance_id,
                    OutboxEvent.event_type.like("%.transitioned"),
                )
            ),
            "claims": session.scalar(select(func.count()).select_from(IdempotencyRecord)),
        }


def _caller(engine, principal, *, position, target, key, into, label, before=None, after=None):
    """One transition on its own thread, with hooks either side of the primitive.

    ``after`` runs **inside** the transaction, after the instance has been updated and
    before ``COMMIT``. That is the pause that holds the race window open: the row is locked
    and uncommitted, so the next caller to reach it blocks.
    """

    def run():
        try:
            if before is not None:
                before()
            with auth.authenticated_transaction(engine, principal.credential) as session:
                if key is None:
                    outcome = transition_lifecycle_instance(
                        session,
                        instance_id=position.id,
                        expected_state=position.current_state,
                        expected_revision=position.revision,
                        target_state=target,
                    )
                else:
                    outcome = execute_idempotent_lifecycle_transition(
                        session,
                        idempotency_key=key,
                        instance_id=position.id,
                        expected_state=position.current_state,
                        expected_revision=position.revision,
                        target_state=target,
                    )
                if after is not None:
                    after()
                into[label] = outcome
        except BaseException as exc:  # re-raised in the main thread, where it is visible
            into[label] = exc

    return threading.Thread(target=run, name=label, daemon=True)


def _wait_for_a_blocked_backend(engine) -> bool:
    """True once another backend on this database is waiting on a lock."""
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


def _choreography() -> dict:
    claimed, release = threading.Event(), threading.Event()
    return {"claimed": claimed, "release": release}


def _hold_after_move(state: dict):
    def after():
        state["claimed"].set()
        state["release"].wait(timeout=BLOCK_TIMEOUT_SECONDS)

    return after


def _race(engine, *, winner, loser, results) -> bool:
    winner.start()
    assert results["claimed"].wait(timeout=BLOCK_TIMEOUT_SECONDS), "the first caller never moved"
    loser.start()
    observed = _wait_for_a_blocked_backend(engine)
    results["release"].set()
    _join((winner, loser))
    return observed


# ------------------------------------------------------------------------ the contended path


def test_two_callers_from_one_revision_produce_one_move(
    application_engine, principal_a, new_instance
):
    """The core property, with the contention observed rather than hoped for.

    Different idempotency keys, so the claim index is **not** what serialises them: the two
    are different requests and each is entitled to its own claim. What stops the second is
    the revision, on the instance row it is trying to move.
    """
    position = new_instance(principal_a)
    results = _choreography()

    winner = _caller(
        application_engine,
        principal_a,
        position=position,
        target="active",
        key=_key(),
        into=results,
        label="winner",
        after=_hold_after_move(results),
    )
    loser = _caller(
        application_engine,
        principal_a,
        position=position,
        target="cancelled",
        key=_key(),
        into=results,
        label="loser",
    )

    observed = _race(application_engine, winner=winner, loser=loser, results=results)
    assert observed, "no backend was ever observed waiting on a lock, so the contended path was not exercised"

    _unwrap(results["winner"])
    assert isinstance(results["loser"], LifecycleConflict), results["loser"]

    # Deterministic relative to the winner: the state is the winner's target, at revision 1.
    counts = _counts(application_engine, principal_a, position.id)
    assert counts["state"] == "active"
    assert counts["revision"] == 1
    assert counts["history"] == 1
    assert counts["moves"] == 1
    assert counts["events"] == 1
    # And the loser's claim went back with its transaction, so its key is free again.
    assert counts["claims"] == 1


def test_the_loser_gets_a_conflict_and_not_a_deadlock(
    application_engine, principal_a, new_instance
):
    """A deadlock would be a different bug wearing the same shape.

    Two callers moving one row in one order cannot deadlock -- there is one lock and they
    take it in the same sequence -- and asserting it is what would catch a future version
    that took a second lock somewhere else.
    """
    position = new_instance(principal_a)
    results = _choreography()

    winner = _caller(
        application_engine,
        principal_a,
        position=position,
        target="active",
        key=_key(),
        into=results,
        label="winner",
        after=_hold_after_move(results),
    )
    loser = _caller(
        application_engine,
        principal_a,
        position=position,
        target="active",
        key=_key(),
        into=results,
        label="loser",
    )
    assert _race(application_engine, winner=winner, loser=loser, results=results)

    failure = results["loser"]
    assert isinstance(failure, LifecycleConflict)
    rendered = repr(failure) + str(failure)
    assert "deadlock" not in rendered.lower()
    assert getattr(failure, "__cause__", None) is None
    assert getattr(failure, "__context__", None) is None


def test_nothing_in_the_module_retries_a_conflict():
    """A retry loop would hide exactly what these tests exist to observe.

    A conflict means the caller's revision is stale. Retrying with the same revision either
    fails identically forever or -- if the state happens to come back around a cycle --
    applies a move the caller never decided on.

    The idempotent path **does** recover from a lost race, and the distinction is the whole
    of this test: it re-reads the winning claim and returns what that claim recorded. It
    never calls the transition again. So the assertion is not "no exception handler does
    anything" -- one of them reads a row -- but the two things that would make it a retry: a
    loop anywhere in the module, and a call to ``_apply_transition`` from inside a handler.
    """
    tree = ast.parse(pathlib.Path(lifecycle.__file__).read_text())
    for node in ast.walk(tree):
        assert not isinstance(node, (ast.While, ast.AsyncFor)), "db/lifecycle.py loops"

    def calls_the_transition(body) -> bool:
        for node in body:
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    name = getattr(inner.func, "id", None) or getattr(inner.func, "attr", None)
                    if name == "_apply_transition":
                        return True
        return False

    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                assert not calls_the_transition(handler.body), (
                    "an exception handler re-invokes the transition, which is a retry"
                )


@pytest.mark.parametrize("repeat", range(5))
def test_the_race_result_is_stable_across_repeats(
    application_engine, principal_a, new_instance, repeat
):
    """A concurrency property that only holds sometimes is not a property.

    Run without choreography, so whatever interleaving the machine produces is the one under
    test -- contended or sequential, the committed state is one move.
    """
    position = new_instance(principal_a)
    results: dict[str, object] = {}
    start = threading.Barrier(2)

    threads = [
        _caller(
            application_engine,
            principal_a,
            position=position,
            target=target,
            key=_key(),
            into=results,
            label=label,
            before=lambda: start.wait(timeout=BLOCK_TIMEOUT_SECONDS),
        )
        for target, label in (("active", "first"), ("cancelled", "second"))
    ]
    for thread in threads:
        thread.start()
    _join(threads)

    outcomes = [results["first"], results["second"]]
    conflicts = [o for o in outcomes if isinstance(o, LifecycleConflict)]
    succeeded = [o for o in outcomes if not isinstance(o, BaseException)]
    assert len(conflicts) == 1, outcomes
    assert len(succeeded) == 1, outcomes

    counts = _counts(application_engine, principal_a, position.id)
    assert counts["revision"] == 1
    assert counts["history"] == 1
    assert counts["moves"] == 1
    assert counts["events"] == 1
    assert counts["state"] in ("active", "cancelled")


def test_a_field_of_callers_still_produces_one_move(application_engine, principal_a, new_instance):
    """Four threads from one revision. One wins; the other three conflict."""
    position = new_instance(principal_a)
    results: dict[str, object] = {}
    start = threading.Barrier(4)

    threads = [
        _caller(
            application_engine,
            principal_a,
            position=position,
            target="active",
            key=_key(),
            into=results,
            label=f"caller-{index}",
            before=lambda: start.wait(timeout=BLOCK_TIMEOUT_SECONDS),
        )
        for index in range(4)
    ]
    for thread in threads:
        thread.start()
    _join(threads)

    outcomes = [results[f"caller-{index}"] for index in range(4)]
    assert sum(1 for o in outcomes if isinstance(o, LifecycleConflict)) == 3, outcomes
    assert sum(1 for o in outcomes if not isinstance(o, BaseException)) == 1, outcomes

    counts = _counts(application_engine, principal_a, position.id)
    assert (counts["state"], counts["revision"]) == ("active", 1)
    assert counts["history"] == 1 and counts["moves"] == 1 and counts["events"] == 1


def test_the_unlinked_form_races_the_same_way(application_engine, principal_a, new_instance):
    """No idempotency key at all, so the revision is unambiguously the only control."""
    position = new_instance(principal_a)
    results = _choreography()

    winner = _caller(
        application_engine,
        principal_a,
        position=position,
        target="active",
        key=None,
        into=results,
        label="winner",
        after=_hold_after_move(results),
    )
    loser = _caller(
        application_engine,
        principal_a,
        position=position,
        target="cancelled",
        key=None,
        into=results,
        label="loser",
    )
    assert _race(application_engine, winner=winner, loser=loser, results=results)

    assert _unwrap(results["winner"]).to_revision == 1
    assert isinstance(results["loser"], LifecycleConflict)
    counts = _counts(application_engine, principal_a, position.id)
    assert (counts["state"], counts["revision"], counts["history"]) == ("active", 1, 1)
    assert counts["claims"] == 0, "the unlinked form writes no idempotency claim"


def test_concurrent_moves_of_different_instances_do_not_collide(
    application_engine, principal_a, new_instance
):
    """The lock is on the instance, not on the machine or the tenant.

    Two instances of the same machine in the same tenant move independently, which is what
    stops one tenant's throughput being one transition at a time.
    """
    first = new_instance(principal_a)
    second = new_instance(principal_a)
    results: dict[str, object] = {}
    start = threading.Barrier(2)

    threads = [
        _caller(
            application_engine,
            principal_a,
            position=position,
            target="active",
            key=_key(),
            into=results,
            label=label,
            before=lambda: start.wait(timeout=BLOCK_TIMEOUT_SECONDS),
        )
        for position, label in ((first, "first"), (second, "second"))
    ]
    for thread in threads:
        thread.start()
    _join(threads)

    _unwrap(results["first"])
    _unwrap(results["second"])
    for position in (first, second):
        counts = _counts(application_engine, principal_a, position.id)
        assert (counts["state"], counts["revision"], counts["history"]) == ("active", 1, 1)


def test_concurrent_callers_in_different_tenants_do_not_collide(
    application_engine, principal_a, principal_b, new_instance
):
    """Two tenants, two instances, one key value -- and no interaction of any kind."""
    key = _key()
    first = new_instance(principal_a)
    second = new_instance(principal_b)
    results: dict[str, object] = {}
    start = threading.Barrier(2)

    threads = [
        _caller(
            application_engine,
            principal,
            position=position,
            target="active",
            key=key,
            into=results,
            label=label,
            before=lambda: start.wait(timeout=BLOCK_TIMEOUT_SECONDS),
        )
        for principal, position, label in (
            (principal_a, first, "alpha"),
            (principal_b, second, "beta"),
        )
    ]
    for thread in threads:
        thread.start()
    _join(threads)

    for principal, position, label in (
        (principal_a, first, "alpha"),
        (principal_b, second, "beta"),
    ):
        outcome = _unwrap(results[label])
        assert outcome.replayed is False
        counts = _counts(application_engine, principal, position.id)
        assert (counts["state"], counts["revision"], counts["history"]) == ("active", 1, 1)


# ------------------- identical concurrent requests replay (review finding 3)
#
# Two callers making the *same* request -- same tenant, operation, key, identity and
# fingerprint -- are one request retried, not two requests competing. Whichever loses must
# return the original result rather than an error: an HTTP client that retried on a timeout
# and got a conflict would have no way to tell "you already did this" from "somebody else
# moved it", and the correct action differs completely between the two.
#
# There are two ways to lose and the recovery is the same for both. A caller can lose on the
# **claim index**, when the winner's claim commits first; or on the **instance row lock**,
# when the winner's conditional update commits first and the loser's predicate then matches
# nothing. Both roll the attempt back, re-read the claim, and replay it.


def test_identical_concurrent_requests_both_return_the_original_result(
    application_engine, principal_a, new_instance
):
    """The same key, the same move, two callers, and the contention held open.

    The winner is paused after its move and before ``COMMIT``, so the loser is inside the
    window with the claim uncommitted. It blocks, the winner commits, and the loser finds a
    claim whose fingerprint matches its own -- and returns what that claim recorded.
    """
    position = new_instance(principal_a)
    key = _key()
    results = _choreography()

    winner = _caller(
        application_engine,
        principal_a,
        position=position,
        target="active",
        key=key,
        into=results,
        label="winner",
        after=_hold_after_move(results),
    )
    loser = _caller(
        application_engine,
        principal_a,
        position=position,
        target="active",
        key=key,
        into=results,
        label="loser",
    )

    observed = _race(application_engine, winner=winner, loser=loser, results=results)
    assert observed, "the contended path was not exercised"

    first = _unwrap(results["winner"])
    second = _unwrap(results["loser"])
    assert first.replayed is False
    assert second.replayed is True, "an identical concurrent request must replay, not fail"
    assert second.record_id == first.record_id
    assert second.event_id == first.event_id
    assert second.result == first.result

    counts = _counts(application_engine, principal_a, position.id)
    assert counts["state"] == "active"
    assert counts["revision"] == 1
    assert counts["history"] == 1
    assert counts["moves"] == 1
    assert counts["events"] == 1
    assert counts["claims"] == 1


@pytest.mark.parametrize("repeat", range(5))
def test_identical_concurrent_requests_replay_under_any_interleaving(
    application_engine, principal_a, new_instance, repeat
):
    """No choreography: whichever order the machine produces, one move and two results.

    Run repeatedly because a recovery that only works when the loser arrives after the
    winner's commit is not a recovery -- the two orders take different branches inside the
    primitive, and both have to end in a replay.
    """
    position = new_instance(principal_a)
    key = _key()
    results: dict[str, object] = {}
    start = threading.Barrier(2)

    threads = [
        _caller(
            application_engine,
            principal_a,
            position=position,
            target="active",
            key=key,
            into=results,
            label=label,
            before=lambda: start.wait(timeout=BLOCK_TIMEOUT_SECONDS),
        )
        for label in ("first", "second")
    ]
    for thread in threads:
        thread.start()
    _join(threads)

    outcomes = [_unwrap(results["first"]), _unwrap(results["second"])]
    assert sum(1 for o in outcomes if not o.replayed) == 1, outcomes
    assert sum(1 for o in outcomes if o.replayed) == 1, outcomes
    assert outcomes[0].record_id == outcomes[1].record_id
    assert outcomes[0].result == outcomes[1].result

    counts = _counts(application_engine, principal_a, position.id)
    assert (counts["revision"], counts["history"], counts["moves"], counts["events"]) == (
        1,
        1,
        1,
        1,
    )
    assert counts["claims"] == 1


def test_the_same_key_with_a_different_fingerprint_is_refused_not_replayed(
    application_engine, principal_a, new_instance
):
    """Concurrently, and the recovery must not turn a conflicting reuse into a replay.

    The two callers agree on the key and disagree on the move, so their fingerprints differ.
    The loser finds the winner's claim, compares fingerprints, and refuses -- which is the
    one case where finding a claim must *not* mean returning its result.
    """
    position = new_instance(principal_a)
    key = _key()
    results = _choreography()

    winner = _caller(
        application_engine,
        principal_a,
        position=position,
        target="active",
        key=key,
        into=results,
        label="winner",
        after=_hold_after_move(results),
    )
    loser = _caller(
        application_engine,
        principal_a,
        position=position,
        target="cancelled",
        key=key,
        into=results,
        label="loser",
    )

    assert _race(application_engine, winner=winner, loser=loser, results=results)
    assert _unwrap(results["winner"]).replayed is False
    assert isinstance(results["loser"], IdempotencyConflict), results["loser"]

    counts = _counts(application_engine, principal_a, position.id)
    assert (counts["state"], counts["revision"], counts["claims"]) == ("active", 1, 1)
    assert (counts["history"], counts["moves"], counts["events"]) == (1, 1, 1)


def test_a_genuine_stale_request_keeps_its_conflict(
    application_engine, principal_a, new_instance
):
    """No winning claim exists, so there is nothing to replay and the refusal stands.

    This is the boundary of the recovery. The instance moved -- under a *different* key --
    so this caller's request really is out of date, and quietly handing it somebody else's
    stored result would report success for a move it did not make.
    """
    position = new_instance(principal_a)
    moved = _unwrap(
        _run_once(application_engine, principal_a, position, "active", _key())
    )
    assert moved.replayed is False

    with pytest.raises(LifecycleConflict):
        _run_once(application_engine, principal_a, position, "cancelled", _key())

    counts = _counts(application_engine, principal_a, position.id)
    assert (counts["state"], counts["revision"], counts["claims"]) == ("active", 1, 1)


def test_a_cross_tenant_identifier_is_not_turned_into_a_replay(
    application_engine, principal_a, principal_b, new_instance
):
    """The other thing the recovery must not do: reach across the isolation boundary.

    Tenant B holds a claim under this exact operation and key. Tenant A presents the same
    key for an instance it does not own; the re-read is tenant-scoped, finds nothing, and
    the conflict stands.
    """
    theirs = new_instance(principal_b)
    key = _key()
    _unwrap(_run_once(application_engine, principal_b, theirs, "active", key))

    mine = new_instance(principal_a)
    with pytest.raises(LifecycleConflict):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            execute_idempotent_lifecycle_transition(
                session,
                idempotency_key=key,
                instance_id=theirs.id,
                expected_state="draft",
                expected_revision=0,
                target_state="active",
            )

    assert _counts(application_engine, principal_b, theirs.id)["revision"] == 1
    assert _counts(application_engine, principal_a, mine.id)["revision"] == 0


def _run_once(engine, principal, position, target, key):
    """One idempotent transition, inline, returning the outcome or raising."""
    with auth.authenticated_transaction(engine, principal.credential) as session:
        return execute_idempotent_lifecycle_transition(
            session,
            idempotency_key=key,
            instance_id=position.id,
            expected_state=position.current_state,
            expected_revision=position.revision,
            target_state=target,
        )



# ------------------- publication against the graph it publishes (review finding 4)
#
# The first version read the publication column without a lock, so
#
#     T1: insert an edge; sees the machine unpublished; proceeds
#     T2: publish; validates a graph that does not contain T1's edge; commits
#     T1: commits
#
# left a *published* machine carrying an edge nothing had validated. Reading a value is not
# deciding on it when somebody else may change it in between.
#
# Both sides now take ``FOR UPDATE`` on the machine row before they inspect anything, and
# that is the one lockable object in this design -- so there is one lock order and nothing to
# deadlock against. These tests force the window open the same way the transition races above
# do: one connection holds, a third watches ``pg_stat_activity`` until it can see the other
# really waiting, and the test **fails** if the block is never observed.
#
# The lock is belt to the ``xmin`` rule's braces, and the tests say which is doing what. See
# ``test_a_publication_and_a_child_insert_have_no_reachable_interleaving`` for why the
# original scenario is not merely refused but unreachable while that rule stands.

_RACE_STATES = ("one", "two", "three")


@pytest.fixture()
def owner_engines(disposable_database):
    """Three independent owner engines, because the migration engine pools **one**.

    A publication race needs a holder, a waiter and a watcher at the same instant, and
    ``migrate.create_migration_engine`` deliberately pools ``pool_size=1, max_overflow=1`` --
    a large pool of owner connections is a standing privilege nobody needs. Sharing one
    engine here would make the watcher queue behind the two it is supposed to be watching,
    which reads as "the block was never observed" and is really "the test could not look".
    """
    engines = [
        migrate.create_migration_engine(disposable_database.migration_url) for _ in range(3)
    ]
    try:
        yield engines
    finally:
        for engine in engines:
            engine.dispose()


def _race_machine_key() -> str:
    return f"test_race_{uuid.uuid4().hex[:12]}"


def _committed_draft(engine, key: str) -> str:
    """A machine and its states, committed and deliberately **not** published.

    Reachable state: it is what a registration that committed part-way would leave. Nothing
    consumes it -- every reader requires publication -- and it cannot be published either,
    because its rows carry another transaction's id. What it is good for is holding a lock
    that two connections can both name.
    """
    with engine.connect() as connection:
        connection.execute(
            text(
                f"INSERT INTO {SCHEMA}.lifecycle_machines "
                "(machine_key, version, read_scope, create_scope, transition_scope) "
                "VALUES (:k, 1, 'workspace:read', 'workspace:write', 'workspace:write')"
            ),
            {"k": key},
        )
        for index, state in enumerate(_RACE_STATES):
            connection.execute(
                text(
                    f"INSERT INTO {SCHEMA}.lifecycle_states "
                    "(machine_key, machine_version, state, is_initial, is_terminal) "
                    "VALUES (:k, 1, :s, :i, false)"
                ),
                {"k": key, "s": state, "i": index == 0},
            )
        connection.commit()
    return key


def _holder(engine, *, key: str, state: dict, statement: str, params: dict, label: str, into: dict):
    """A thread that runs one statement, signals, waits, and then rolls back."""

    def run():
        try:
            with engine.connect() as connection:
                connection.execute(text(statement), params)
                state["claimed"].set()
                state["release"].wait(timeout=BLOCK_TIMEOUT_SECONDS)
                if state.get("commit"):
                    connection.commit()
                else:
                    connection.rollback()
            into[label] = "done"
        except BaseException as exc:
            state["claimed"].set()
            into[label] = exc

    return threading.Thread(target=run, name=label, daemon=True)


def _blocked(engine, *, statement: str, params: dict, label: str, into: dict):
    """A thread that runs one statement, which is expected to block, and then rolls back."""

    def run():
        try:
            with engine.connect() as connection:
                connection.execute(text(statement), params)
                connection.rollback()
            into[label] = "done"
        except BaseException as exc:
            into[label] = exc

    return threading.Thread(target=run, name=label, daemon=True)


_LOCK_MACHINE = (
    f"SELECT machine_key FROM {SCHEMA}.lifecycle_machines "
    "WHERE machine_key = :k AND version = 1 FOR UPDATE"
)
_INSERT_RACE_STATE = (
    f"INSERT INTO {SCHEMA}.lifecycle_states "
    "(machine_key, machine_version, state, is_initial, is_terminal) "
    "VALUES (:k, 1, :s, false, false)"
)
_INSERT_RACE_EDGE = (
    f"INSERT INTO {SCHEMA}.lifecycle_transition_edges "
    "(machine_key, machine_version, from_state, to_state) VALUES (:k, 1, :f, :t)"
)
_PUBLISH_RACE_MACHINE = (
    f"UPDATE {SCHEMA}.lifecycle_machines SET published_at = now() "
    "WHERE machine_key = :k AND version = 1"
)


@pytest.mark.parametrize(
    ("what", "statement", "params"),
    (
        ("state", _INSERT_RACE_STATE, {"s": "four"}),
        ("edge", _INSERT_RACE_EDGE, {"f": "one", "t": "two"}),
    ),
)
def test_a_child_insert_blocks_on_the_lock_a_publication_holds(
    owner_engines, lifecycle_definitions, what, statement, params
):
    """**The lock is real, and an edge takes it on the machine rather than on a state.**

    The holder takes the same ``FOR UPDATE`` on the machine row that publication takes before
    it looks at any child. The insert then waits -- observed on ``pg_stat_activity``, so the
    test fails rather than passing on an interleaving that proved nothing -- which is what
    makes "read the publication column after acquiring the lock" a decision rather than a
    glance.

    Locking the *state* rows an edge refers to would not do this: an edge's parent is the
    machine, and a state row is not something publication takes a lock on.
    """
    watcher, first, second = owner_engines
    key = _committed_draft(watcher, _race_machine_key())
    state = _choreography()
    results: dict = {}

    holder = _holder(
        first,
        key=key,
        state=state,
        statement=_LOCK_MACHINE,
        params={"k": key},
        label="holder",
        into=results,
    )
    child = _blocked(
        second,
        statement=statement,
        params={"k": key, **params},
        label="child",
        into=results,
    )

    holder.start()
    assert state["claimed"].wait(timeout=BLOCK_TIMEOUT_SECONDS), "the holder never took the lock"
    _unwrap(results.get("holder", "pending"))
    child.start()
    observed = _wait_for_a_blocked_backend(watcher)
    state["release"].set()
    _join((holder, child))

    assert observed, f"the {what} insert never blocked, so the lock is not conflicting"
    _unwrap(results["holder"])
    _unwrap(results["child"])


def test_a_publication_waits_for_an_in_flight_child_insert(
    owner_engines, lifecycle_definitions
):
    """The other order: the child holds the machine lock and the publication waits for it.

    And when it gets the lock it refuses, because the rows it would be publishing were
    written by transactions other than its own. That refusal is the ``xmin`` rule rather than
    the lock -- the lock is what makes the *order* deterministic, so the publication decides
    against a graph that has stopped changing rather than against one mid-flight.
    """
    watcher, first, second = owner_engines
    key = _committed_draft(watcher, _race_machine_key())
    state = _choreography()
    state["commit"] = True
    results: dict = {}

    child = _holder(
        first,
        key=key,
        state=state,
        statement=_INSERT_RACE_STATE,
        params={"k": key, "s": "four"},
        label="child",
        into=results,
    )
    publication = _blocked(
        second,
        statement=_PUBLISH_RACE_MACHINE,
        params={"k": key},
        label="publication",
        into=results,
    )

    child.start()
    assert state["claimed"].wait(timeout=BLOCK_TIMEOUT_SECONDS), "the child never inserted"
    publication.start()
    observed = _wait_for_a_blocked_backend(watcher)
    state["release"].set()
    _join((child, publication))

    assert observed, "the publication never blocked, so it did not take the machine lock"
    _unwrap(results["child"])
    failure = results["publication"]
    assert isinstance(failure, BaseException)
    assert "registered and published in one transaction" in str(failure)

    with watcher.connect() as connection:
        assert connection.execute(
            text(
                f"SELECT published_at IS NULL FROM {SCHEMA}.lifecycle_machines "
                "WHERE machine_key = :k AND version = 1"
            ),
            {"k": key},
        ).scalar_one() is True


def test_a_child_that_waited_on_a_published_machine_is_refused(
    owner_engines, lifecycle_definitions
):
    """**Publication won: the child re-reads after the wait and refuses.**

    The holder takes the machine lock on a machine that is already published -- the state
    publication leaves behind -- and the child waits for it. When the child gets the lock it
    reads the publication column again, and the answer is no. Without the lock it could have
    read that column before the flag was set and proceeded on a stale answer.
    """
    watcher, first, second = owner_engines
    key = TEST_CYCLIC.machine_key
    state = _choreography()
    results: dict = {}

    holder = _holder(
        first,
        key=key,
        state=state,
        statement=_LOCK_MACHINE,
        params={"k": key},
        label="holder",
        into=results,
    )
    child = _blocked(
        second,
        statement=_INSERT_RACE_STATE,
        params={"k": key, "s": "sneaked_in"},
        label="child",
        into=results,
    )

    holder.start()
    assert state["claimed"].wait(timeout=BLOCK_TIMEOUT_SECONDS), "the holder never took the lock"
    child.start()
    observed = _wait_for_a_blocked_backend(watcher)
    state["release"].set()
    _join((holder, child))

    assert observed, "the child never blocked on the published machine's lock"
    _unwrap(results["holder"])
    failure = results["child"]
    assert isinstance(failure, BaseException)
    assert "published lifecycle machine version cannot gain" in str(failure)

    # And the published graph is exactly what publication validated.
    with watcher.connect() as connection:
        assert connection.execute(
            text(
                f"SELECT count(*) FROM {SCHEMA}.lifecycle_states "
                "WHERE machine_key = :k AND state = 'sneaked_in'"
            ),
            {"k": key},
        ).scalar_one() == 0


def test_a_publication_and_a_child_insert_have_no_reachable_interleaving(
    owner_engines, lifecycle_definitions
):
    """Why the original scenario is unreachable and not merely refused, stated as a test.

    The bad interleaving needs two transactions to touch one definition while one of them
    publishes. Both halves of that are closed, and by different rules:

    * a machine created in an *uncommitted* transaction is invisible to any other connection,
      so a concurrent child insert cannot even name it -- it gets the "no such machine
      version" refusal, having found nothing to lock;
    * a machine that **is** committed cannot be published at all, because publication
      requires every row of the definition to carry this transaction's id.

    So while the same-transaction rule stands there is no execution in which a publication
    validates a graph that another transaction then adds to. The lock is what makes that true
    for the window where the two rules hand over to each other, and this is the reason it is
    belt rather than braces.
    """
    watcher, first, second = owner_engines
    key = _race_machine_key()
    state = _choreography()
    results: dict = {}

    creator = _holder(
        first,
        key=key,
        state=state,
        statement=(
            f"INSERT INTO {SCHEMA}.lifecycle_machines "
            "(machine_key, version, read_scope, create_scope, transition_scope) "
            "VALUES (:k, 1, 'workspace:read', 'workspace:write', 'workspace:write')"
        ),
        params={"k": key},
        label="creator",
        into=results,
    )
    intruder = _blocked(
        second,
        statement=_INSERT_RACE_STATE,
        params={"k": key, "s": "four"},
        label="intruder",
        into=results,
    )

    creator.start()
    assert state["claimed"].wait(timeout=BLOCK_TIMEOUT_SECONDS), "the creator never inserted"
    intruder.start()
    _join((intruder,))
    state["release"].set()
    _join((creator,))

    _unwrap(results["creator"])
    failure = results["intruder"]
    assert isinstance(failure, BaseException)
    assert "no such lifecycle machine version" in str(failure)


def test_concurrent_child_inserts_and_a_publication_attempt_do_not_deadlock(
    owner_engines, lifecycle_definitions
):
    """One lockable object and one order, so there is nothing to deadlock against.

    Five child inserts and a publication attempt, all on one machine, started together. Every
    one of them takes ``FOR UPDATE`` on the same machine row first, so they serialise in
    whatever order the server chooses; none of them takes a second lock, so none of them can
    be waiting on another while another waits on it.
    """
    watcher, first, second = owner_engines
    key = _committed_draft(watcher, _race_machine_key())
    results: dict = {}
    engines = (first, second)
    threads = [
        _blocked(
            engines[index % 2],
            statement=_INSERT_RACE_STATE,
            params={"k": key, "s": f"extra_{index}"},
            label=f"child-{index}",
            into=results,
        )
        for index in range(5)
    ]
    threads.append(
        _blocked(
            second,
            statement=_PUBLISH_RACE_MACHINE,
            params={"k": key},
            label="publication",
            into=results,
        )
    )
    for thread in threads:
        thread.start()
    _join(threads)

    for label, outcome in results.items():
        if isinstance(outcome, BaseException):
            assert "deadlock" not in str(outcome).lower(), f"{label}: {outcome}"
    # Every child rolled back and the publication was refused, so the graph is untouched.
    with watcher.connect() as connection:
        assert connection.execute(
            text(
                f"SELECT count(*) FROM {SCHEMA}.lifecycle_states WHERE machine_key = :k"
            ),
            {"k": key},
        ).scalar_one() == len(_RACE_STATES)
        assert connection.execute(
            text(
                f"SELECT published_at IS NULL FROM {SCHEMA}.lifecycle_machines "
                "WHERE machine_key = :k AND version = 1"
            ),
            {"k": key},
        ).scalar_one() is True
