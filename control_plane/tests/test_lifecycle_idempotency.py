"""A transition claimed once per key: composition with Milestone 2.2, not a second copy.

``execute_idempotent_lifecycle_transition`` reuses Milestone 2.2's **table**, its unique
index, its record type and its conflict semantics, and none of its Python. The claim, the
replay, the fingerprint, the recovery from a lost race and the one **linked** outbox event
are all written by ``firmbatch.transition_lifecycle_instance()`` -- the same database call
the unlinked form makes, told one idempotency key. Nothing about the transition is decided
twice, and nothing about the claim is decided outside the database.

Everything a caller says about idempotency is that one key. The operation name is derived
from the machine the instance pins, the request fingerprint from the arguments the call
executed, and the claim is tied to the transition it stands for by a protected provenance
row -- because a replay that trusted a machine tag alone would hand back whatever ``result``
a row happened to carry.

This module asserts what that composition buys, and -- as importantly -- that it buys it
without weakening either half:

* an identical retry returns the stored result and the instance does **not** move again;
* a conflicting reuse of the key is rejected, and moves nothing;
* one successful call leaves one revision, one history row, one audit event and one linked
  outbox intent;
* a replay leaves none of them a second time;
* a failure before commit leaves no claim, so the retry takes the ordinary first path.

The two controls do different jobs and the tests keep them apart. An **idempotency key**
bounds retries of one request: the same key, the same move, twice. A **revision** bounds
concurrent requests: two callers, two keys, one revision. ``test_lifecycle_concurrency.py``
owns the second; this module owns the first.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import replace

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from firmbatch.control_plane.db import auth
from firmbatch.control_plane.db.audit import audit_events
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.idempotency import IdempotencyConflict
from firmbatch.control_plane.db.lifecycle import (
    TRANSITIONED_ACTION,
    LifecycleConflict,
    LifecycleProvenanceError,
    LifecycleTransitionNotAllowed,
    execute_idempotent_lifecycle_transition,
    lifecycle_history,
    lifecycle_instance,
    lifecycle_transition_operation,
)
from firmbatch.control_plane.db.models import IdempotencyRecord, OutboxEvent

from .conftest import TEST_WORKFLOW, acting_as_lifecycle_writer


def _key() -> str:
    return f"lc-{uuid.uuid4().hex}"


def _claim(engine, principal, position, target, key, **kwargs):
    with auth.authenticated_transaction(engine, principal.credential) as session:
        return execute_idempotent_lifecycle_transition(
            session,
            idempotency_key=key,
            instance_id=position.id,
            expected_state=position.current_state,
            expected_revision=position.revision,
            target_state=target,
            **kwargs,
        )


def _state(engine, principal, instance_id):
    with auth.authenticated_transaction(engine, principal.credential) as session:
        row = lifecycle_instance(session, instance_id)
        return row.current_state, row.revision


def _counts(engine, principal, instance_id) -> dict[str, int]:
    with auth.authenticated_transaction(engine, principal.credential) as session:
        return {
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


# ------------------------------------------------------------------------ one of each


def test_one_idempotent_transition_makes_exactly_one_of_each_record(
    application_engine, principal_a, new_instance
):
    position = new_instance(principal_a)
    outcome = _claim(application_engine, principal_a, position, "active", _key())

    assert outcome.replayed is False
    assert outcome.result["to_state"] == "active"
    assert outcome.result["to_revision"] == 1
    assert _state(application_engine, principal_a, position.id) == ("active", 1)
    assert _counts(application_engine, principal_a, position.id) == {
        "history": 1,
        "moves": 1,
        "events": 1,
        "claims": 1,
    }


def test_the_outbox_event_is_linked_to_the_claim(application_engine, principal_a, new_instance):
    """The difference between the two supported shapes, and the only difference.

    The unlinked form commits an event with ``idempotency_record_id`` NULL; this one commits
    the same event linked to the claim, which is what lets a dispatcher and an operator tell
    "the API asked for this" from "the controller decided this".
    """
    position = new_instance(principal_a)
    outcome = _claim(application_engine, principal_a, position, "active", _key())

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        event = session.get(OutboxEvent, outcome.event_id)
        assert event.idempotency_record_id == outcome.record_id
        assert event.event_type.endswith(".transitioned")
        assert event.attributes["to_revision"] == 1


# ------------------------------------------------------------------------------ replay


def test_an_identical_retry_returns_the_stored_result_and_moves_nothing(
    application_engine, principal_a, new_instance
):
    """The property the whole mechanism exists for, stated as the instance's revision.

    A retry that moved the instance a second time would be a duplicate contractual effect
    wearing a helpful name -- and for a lifecycle it is the worst kind, because the second
    move is usually legal.
    """
    position = new_instance(principal_a)
    key = _key()

    first = _claim(application_engine, principal_a, position, "active", key)
    second = _claim(application_engine, principal_a, position, "active", key)

    assert first.replayed is False
    assert second.replayed is True
    assert second.record_id == first.record_id
    assert second.event_id == first.event_id
    assert second.result == first.result
    assert _state(application_engine, principal_a, position.id) == ("active", 1)


def test_a_replay_appends_no_history_audit_or_outbox_row(
    application_engine, principal_a, new_instance
):
    position = new_instance(principal_a)
    key = _key()
    _claim(application_engine, principal_a, position, "active", key)
    before = _counts(application_engine, principal_a, position.id)

    for _ in range(3):
        assert _claim(application_engine, principal_a, position, "active", key).replayed is True

    assert _counts(application_engine, principal_a, position.id) == before
    assert before == {"history": 1, "moves": 1, "events": 1, "claims": 1}


def test_a_replay_works_even_once_the_instance_has_moved_on(
    application_engine, principal_a, new_instance
):
    """The retry never reaches the database function, so a stale revision cannot refuse it.

    This is the case that separates "idempotent" from "conditional". The original request is
    long superseded -- the instance is two moves further on -- and the retry still returns
    what the original did, because a retry asks *what happened to my request*, not *may I do
    this now*.
    """
    position = new_instance(principal_a)
    key = _key()
    first = _claim(application_engine, principal_a, position, "active", key)

    moved = first.result
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        from firmbatch.control_plane.db.lifecycle import transition_lifecycle_instance

        transition_lifecycle_instance(
            session,
            instance_id=position.id,
            expected_state="active",
            expected_revision=1,
            target_state="paused",
        )

    replay = _claim(application_engine, principal_a, position, "active", key)
    assert replay.replayed is True
    assert replay.result == moved
    assert _state(application_engine, principal_a, position.id) == ("paused", 2)


# --------------------------------------------------------------------------- conflict


def test_reusing_a_key_for_a_different_move_is_rejected(
    application_engine, principal_a, new_instance
):
    """The request identity is the move, so "the same key" means "the same move"."""
    position = new_instance(principal_a)
    key = _key()
    _claim(application_engine, principal_a, position, "active", key)

    with pytest.raises(IdempotencyConflict):
        _claim(application_engine, principal_a, position, "cancelled", key)
    assert _state(application_engine, principal_a, position.id) == ("active", 1)


def test_reusing_a_key_for_a_different_instance_is_rejected(
    application_engine, principal_a, new_instance
):
    first = new_instance(principal_a)
    second = new_instance(principal_a)
    key = _key()
    _claim(application_engine, principal_a, first, "active", key)

    with pytest.raises(IdempotencyConflict):
        _claim(application_engine, principal_a, second, "active", key)
    assert _state(application_engine, principal_a, second.id) == ("draft", 0)


def test_reusing_a_key_from_a_different_revision_is_rejected(
    application_engine, principal_a, new_instance
):
    """The expected revision is part of the request identity, and has to be.

    Without it, "move to active, from revision 0" and "move to active, from revision 1"
    would fingerprint identically, and the second would be handed the first's stored result
    -- a replay of a request the caller is not making.
    """
    position = new_instance(principal_a)
    key = _key()
    _claim(application_engine, principal_a, position, "active", key)

    moved = replace(position, current_state="active", revision=1)
    with pytest.raises(IdempotencyConflict):
        _claim(application_engine, principal_a, moved, "paused", key)
    assert _state(application_engine, principal_a, position.id) == ("active", 1)


def test_the_same_key_is_independent_between_tenants(
    application_engine, principal_a, principal_b, new_instance
):
    key = _key()
    first = new_instance(principal_a)
    second = new_instance(principal_b)

    assert _claim(application_engine, principal_a, first, "active", key).replayed is False
    assert _claim(application_engine, principal_b, second, "active", key).replayed is False
    assert _state(application_engine, principal_a, first.id) == ("active", 1)
    assert _state(application_engine, principal_b, second.id) == ("active", 1)


# ------------------------------------------------------------------- failure leaves nothing


def test_a_refused_transition_leaves_no_claim_blocking_the_retry(
    application_engine, principal_a, new_instance
):
    """The claim commits with the move or not at all, so a refusal does not burn a key.

    A durable half-claim would need a recovery system to interpret it, and Milestone 2.2
    deliberately builds none -- which is only sound if a failed attempt leaves no row.
    """
    position = new_instance(principal_a)
    key = _key()

    with pytest.raises(LifecycleTransitionNotAllowed):
        _claim(application_engine, principal_a, position, "closed", key)

    assert _counts(application_engine, principal_a, position.id) == {
        "history": 0,
        "moves": 0,
        "events": 0,
        "claims": 0,
    }
    # And the same key now works for a legal move.
    outcome = _claim(application_engine, principal_a, position, "active", key)
    assert outcome.replayed is False
    assert _state(application_engine, principal_a, position.id) == ("active", 1)


def test_a_conflicting_transition_leaves_no_claim(application_engine, principal_a, new_instance):
    position = new_instance(principal_a)
    key = _key()

    with pytest.raises(LifecycleConflict):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            execute_idempotent_lifecycle_transition(
                session,
                idempotency_key=key,
                instance_id=position.id,
                expected_state="draft",
                expected_revision=9,
                target_state="active",
            )

    assert _counts(application_engine, principal_a, position.id)["claims"] == 0


def test_a_failure_after_the_primitive_returns_rolls_the_whole_thing_back(
    application_engine, principal_a, new_instance
):
    """Seven effects, one transaction: the claim, the event, and the five the move makes."""
    position = new_instance(principal_a)
    key = _key()

    class Deliberate(RuntimeError):
        pass

    with pytest.raises(Deliberate):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            execute_idempotent_lifecycle_transition(
                session,
                idempotency_key=key,
                instance_id=position.id,
                expected_state="draft",
                expected_revision=0,
                target_state="active",
            )
            raise Deliberate("the caller failed after the claim")

    assert _state(application_engine, principal_a, position.id) == ("draft", 0)
    assert _counts(application_engine, principal_a, position.id) == {
        "history": 0,
        "moves": 0,
        "events": 0,
        "claims": 0,
    }
    # The key is free, so the retry takes the ordinary first-attempt path.
    assert _claim(application_engine, principal_a, position, "active", key).replayed is False


def test_the_claim_and_the_move_commit_together(application_engine, principal_a, new_instance):
    """Counted after a real commit, because that is the only instant both are durable."""
    position = new_instance(principal_a)
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        execute_idempotent_lifecycle_transition(
            session,
            idempotency_key=_key(),
            instance_id=position.id,
            expected_state="draft",
            expected_revision=0,
            target_state="active",
        )
        # Nothing is durable yet: another transaction cannot see either.
        with auth.authenticated_transaction(application_engine, principal_a.credential) as other:
            assert lifecycle_instance(other, position.id).revision == 0
            assert other.scalar(select(func.count()).select_from(IdempotencyRecord)) == 0

    assert _state(application_engine, principal_a, position.id) == ("active", 1)
    assert _counts(application_engine, principal_a, position.id)["claims"] == 1


def test_a_malformed_key_is_refused_before_the_move(
    application_engine, principal_a, new_instance
):
    """There is no operation to malform any more, so the key is the whole of the surface.

    The operation a lifecycle claim is made under is derived inside the database from the
    machine the instance pins, and no parameter carries it. What is left for a caller to get
    wrong is the key, and it is refused in Python and again in the database before anything
    moves.
    """
    from firmbatch.control_plane.db.idempotency import IdempotencyError

    position = new_instance(principal_a)
    for key in ("short", "has spaces in it", "x" * 201):
        with pytest.raises(IdempotencyError):
            with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
                execute_idempotent_lifecycle_transition(
                    session,
                    idempotency_key=key,
                    instance_id=position.id,
                    expected_state="draft",
                    expected_revision=0,
                    target_state="active",
                )
    assert _state(application_engine, principal_a, position.id) == ("draft", 0)


def test_the_idempotent_form_takes_no_operation_or_fingerprint_argument(application_engine):
    """**Asserted from the signature**, because their absence is the correction.

    While Python passed an operation name and a request fingerprint into the database, both
    were values a caller could choose -- and a fingerprint a caller chooses can bind a claim
    to a request that was never made. Both are derived inside
    ``firmbatch.transition_lifecycle_instance()`` now, and this is what stops one quietly
    coming back.
    """
    import inspect

    parameters = set(
        inspect.signature(execute_idempotent_lifecycle_transition).parameters
    )
    assert "operation" not in parameters
    assert "request_fingerprint" not in parameters
    assert "fingerprint" not in parameters
    assert "idempotency_key" in parameters


def test_the_wrapper_validates_before_it_claims_a_key(application_engine, principal_a, new_instance):
    """A malformed instance id or revision must not burn a key on its way to being refused."""
    from firmbatch.control_plane.db.lifecycle import LifecycleError

    key = _key()
    position = new_instance(principal_a)
    with pytest.raises(LifecycleError):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            execute_idempotent_lifecycle_transition(
                session,
                idempotency_key=key,
                instance_id="not-a-uuid",
                expected_state="draft",
                expected_revision=0,
                target_state="active",
            )
    assert _counts(application_engine, principal_a, position.id)["claims"] == 0
    assert _claim(application_engine, principal_a, position, "active", key).replayed is False


# ------------------ a replay is backed by a transition (review finding 1)
#
# A machine tag says which machine a framework row belongs to. It does **not** say which
# transition a claim stands for, and a replay that trusted the tag alone would hand back
# whatever ``result`` a row happened to carry -- so a fabricated claim with a plausible
# lifecycle result would have replayed as a transition that never happened.
#
# ``firmbatch.lifecycle_claim_provenance`` is the link: written only by the transition
# boundary, immutable afterwards for everybody including the owner, every column a composite
# foreign key into a row that transition wrote. A replay resolves the whole chain and refuses
# anything that does not agree with itself.


def _bind(connection, principal) -> None:
    """Give an owner connection the tenant's authenticated context.

    Row security is ``FORCE``d, so the schema owner is subject to the same insert policies as
    anybody else and cannot write a tenant-scoped row without a context. Since the third
    M2.4 correction the schema owner cannot write a *tagged* row or a provenance row at all
    -- those guards ask for the lifecycle writer -- so the tests that need such rows use
    ``acting_as_lifecycle_writer`` and use this only to show the owner's own attempt refused.
    """
    connection.execute(
        text(f"SELECT {SCHEMA}.bind_authenticated_context(:c)"),
        {"c": principal.credential.reveal()},
    )


def _provenance_rows(owner_engine, record_id=None) -> list[dict]:
    clause = "WHERE idempotency_record_id = :r" if record_id is not None else ""
    with owner_engine.connect() as connection:
        return [
            dict(row)
            for row in connection.execute(
                text(f"SELECT * FROM {SCHEMA}.lifecycle_claim_provenance {clause}"),
                {"r": record_id} if record_id is not None else {},
            ).mappings()
        ]


def test_one_claimed_transition_writes_exactly_one_provenance_row(
    application_engine, owner_engine, principal_a, new_instance
):
    """And every column of it agrees with the transition, the instance and the event."""
    position = new_instance(principal_a)
    outcome = _claim(application_engine, principal_a, position, "active", _key())

    rows = _provenance_rows(owner_engine, outcome.record_id)
    assert len(rows) == 1
    row = rows[0]
    assert row["tenant_id"] == principal_a.id
    assert row["lifecycle_instance_id"] == position.id
    assert row["machine_key"] == TEST_WORKFLOW.machine_key
    assert row["machine_version"] == TEST_WORKFLOW.version
    assert row["from_revision"] == 0
    assert row["to_revision"] == 1
    assert row["outbox_event_id"] == outcome.event_id
    assert str(row["lifecycle_transition_id"]) == outcome.result["transition_id"]


def test_the_unlinked_form_writes_no_provenance_because_it_claims_nothing(
    application_engine, owner_engine, principal_a, new_instance
):
    """The control: provenance exists for claims, and the internal form makes none."""
    from firmbatch.control_plane.db.lifecycle import transition_lifecycle_instance

    position = new_instance(principal_a)
    before = len(_provenance_rows(owner_engine))
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        transition_lifecycle_instance(
            session,
            instance_id=position.id,
            expected_state=position.current_state,
            expected_revision=position.revision,
            target_state="active",
        )
    assert len(_provenance_rows(owner_engine)) == before


def test_a_fabricated_generic_claim_and_event_never_replay_as_a_transition(
    application_engine, principal_a, new_instance
):
    """**The reviewer's regression, executable.**

    The application role writes an ordinary Milestone 2.2 claim -- its own operation, its own
    key -- whose ``result`` is a complete, plausible lifecycle result naming a real instance
    and claiming it reached revision 99, plus an outbox event linked to it. Everything about
    the row is legitimate as a *generic* claim; nothing about it is a lifecycle transition.

    The lifecycle API is then asked for that key. It does not replay: it derives its own
    operation from the machine the instance pins, finds no claim there, does the real move,
    and returns what the real move produced. The fabricated result reaches nobody.
    """
    position = new_instance(principal_a)
    key = _key()
    fabricated = {
        "lifecycle_instance_id": str(position.id),
        "machine_key": TEST_WORKFLOW.machine_key,
        "machine_version": TEST_WORKFLOW.version,
        "from_state": "draft",
        "to_state": "closed",
        "from_revision": 98,
        "to_revision": 99,
        "transition_id": str(uuid.uuid4()),
    }
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        record_id = session.execute(
            text(
                f"INSERT INTO {SCHEMA}.idempotency_records "
                "(tenant_id, operation, idempotency_key, request_fingerprint, status, result) "
                "VALUES (:t, 'job.advance', :k, :f, 'completed', CAST(:r AS jsonb)) RETURNING id"
            ),
            {
                "t": principal_a.id,
                "k": key,
                "f": "0" * 64,
                "r": json.dumps(fabricated),
            },
        ).scalar_one()
        session.execute(
            text(
                f"INSERT INTO {SCHEMA}.outbox_events "
                "(tenant_id, idempotency_record_id, event_type, aggregate_type, aggregate_id, "
                "attributes) VALUES (:t, :r, 'job.advanced', 'job', :a, CAST(:x AS jsonb))"
            ),
            {
                "t": principal_a.id,
                "r": record_id,
                "a": position.id,
                "x": json.dumps(fabricated),
            },
        )

    outcome = _claim(application_engine, principal_a, position, "active", key)

    assert outcome.replayed is False
    assert outcome.record_id != record_id
    assert outcome.result["to_revision"] == 1
    assert outcome.result["to_state"] == "active"
    assert outcome.result["transition_id"] != fabricated["transition_id"]
    # The instance went where the real move sent it, and nowhere near revision 99.
    assert _state(application_engine, principal_a, position.id) == ("active", 1)


def test_a_fabricated_generic_claim_cannot_stop_a_real_move_either(
    application_engine, principal_a, new_instance
):
    """The other half of the same regression: with a stale expectation it still conflicts.

    A fabricated claim must neither be replayed *nor* be able to make a genuine request
    succeed by standing in for it. Here the request is stale, so the answer is the ordinary
    conflict -- and the instance is untouched.
    """
    position = new_instance(principal_a)
    key = _key()
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        session.execute(
            text(
                f"INSERT INTO {SCHEMA}.idempotency_records "
                "(tenant_id, operation, idempotency_key, request_fingerprint, status, result) "
                "VALUES (:t, 'job.advance', :k, :f, 'completed', CAST(:r AS jsonb))"
            ),
            {
                "t": principal_a.id,
                "k": key,
                "f": "0" * 64,
                "r": json.dumps({"to_revision": 99, "to_state": "closed"}),
            },
        )

    with pytest.raises(LifecycleConflict):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            execute_idempotent_lifecycle_transition(
                session,
                idempotency_key=key,
                instance_id=position.id,
                expected_state="draft",
                expected_revision=7,
                target_state="active",
            )
    assert _state(application_engine, principal_a, position.id) == ("draft", 0)


def test_a_generic_writer_cannot_create_a_claim_in_the_reserved_namespace(
    application_engine, principal_a, lifecycle_definitions
):
    """The namespace is closed at the database, not by convention.

    ``lifecycle.`` on a claim's operation is tied to the machine tag by a check constraint,
    and only the schema owner may write that tag -- and the application role holds no column
    privilege on it at all. So both spellings fail: untagged violates the constraint, tagged
    is refused before the row is composed.
    """
    operation = lifecycle_transition_operation(TEST_WORKFLOW.machine_key, TEST_WORKFLOW.version)
    with pytest.raises(DBAPIError) as untagged:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.idempotency_records "
                    "(tenant_id, operation, idempotency_key, request_fingerprint, status, result) "
                    "VALUES (:t, :o, :k, :f, 'completed', '{}'::jsonb)"
                ),
                {"t": principal_a.id, "o": operation, "k": _key(), "f": "0" * 64},
            )
    assert "lifecycle_namespace_reserved" in str(untagged.value)

    with pytest.raises(DBAPIError) as tagged:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.idempotency_records "
                    "(tenant_id, operation, idempotency_key, request_fingerprint, status, result, "
                    "lifecycle_machine_key, lifecycle_machine_version) "
                    "VALUES (:t, :o, :k, :f, 'completed', '{}'::jsonb, :m, 1)"
                ),
                {
                    "t": principal_a.id,
                    "o": operation,
                    "k": _key(),
                    "f": "0" * 64,
                    "m": TEST_WORKFLOW.machine_key,
                },
            )
    assert "permission denied" in str(tagged.value).lower()


def test_a_generic_claim_and_a_lifecycle_claim_may_share_a_textual_key(
    application_engine, principal_a, new_instance
):
    """Separated domains, so one key means two different things and neither shadows the other."""
    from firmbatch.control_plane.db.idempotency import (
        MutationOutcome,
        OutboxEventSpec,
        execute_idempotent_mutation,
    )

    position = new_instance(principal_a)
    key = _key()

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        generic = execute_idempotent_mutation(
            session,
            operation="workspace.create",
            idempotency_key=key,
            request_identity={"slug": "shared-key"},
            mutate=lambda _uow: MutationOutcome(
                result={"ok": True},
                event=OutboxEventSpec(
                    event_type="workspace.created",
                    aggregate_type="workspace",
                    aggregate_id=uuid.uuid4(),
                ),
            ),
        )

    lifecycle_outcome = _claim(application_engine, principal_a, position, "active", key)

    assert generic.record_id != lifecycle_outcome.record_id
    assert generic.result == {"ok": True}
    assert lifecycle_outcome.result["to_revision"] == 1
    assert _state(application_engine, principal_a, position.id) == ("active", 1)


def test_a_replay_requires_its_provenance_and_refuses_without_it(
    application_engine, owner_engine, disposable_database, principal_a, new_instance
):
    """Delete the link and the claim stops being replayable -- it does not become free.

    The provenance table refuses ``DELETE`` for every role including the owner, so this is
    done on a copy of the situation rather than on the real row: a claim in the reserved
    namespace, tagged, with a plausible result and **no** provenance. That is the state a
    bug inside the writer would leave, and the replay refuses it rather than handing back
    what it says.

    Only the lifecycle writer can write that row now -- the schema owner's own attempt is
    refused first, and asserted -- so the row is constructed by the trusted administrator
    acting as the writer, which is the accepted limitation and the only route there is.
    """
    position = new_instance(principal_a)
    key = _key()
    operation = lifecycle_transition_operation(TEST_WORKFLOW.machine_key, TEST_WORKFLOW.version)
    result = {
        "lifecycle_instance_id": str(position.id),
        "machine_key": TEST_WORKFLOW.machine_key,
        "machine_version": TEST_WORKFLOW.version,
        "from_state": "draft",
        "to_state": "active",
        "from_revision": 0,
        "to_revision": 1,
        "transition_id": str(uuid.uuid4()),
    }
    tagged_claim = text(
        f"INSERT INTO {SCHEMA}.idempotency_records "
        "(tenant_id, operation, idempotency_key, request_fingerprint, status, result, "
        "lifecycle_machine_key, lifecycle_machine_version) "
        "VALUES (:t, :o, :k, :f, 'completed', CAST(:r AS jsonb), :m, :v)"
    )
    parameters = {
        "t": principal_a.id,
        "o": operation,
        "k": key,
        "f": "0" * 64,
        "r": json.dumps(result),
        "m": TEST_WORKFLOW.machine_key,
        "v": TEST_WORKFLOW.version,
    }
    # The schema owner, bound as the tenant, is refused: the tag is the writer's to set.
    with owner_engine.connect() as connection:
        _bind(connection, principal_a)
        with pytest.raises(DBAPIError) as refused:
            connection.execute(tagged_claim, parameters)
        connection.rollback()
    assert "derived, not supplied" in str(refused.value)
    # The writer can write it, and does -- with no provenance.
    with acting_as_lifecycle_writer(disposable_database, bind_as=principal_a) as connection:
        connection.execute(tagged_claim, parameters)
        connection.commit()

    with pytest.raises(LifecycleProvenanceError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            execute_idempotent_lifecycle_transition(
                session,
                idempotency_key=key,
                instance_id=position.id,
                expected_state="draft",
                expected_revision=0,
                target_state="active",
            )
    assert "no verifiable lifecycle transition" in str(exc.value)
    assert _state(application_engine, principal_a, position.id) == ("draft", 0)


def test_a_replay_refuses_provenance_that_points_at_another_instances_transition(
    application_engine, disposable_database, principal_a, new_instance
):
    """A mismatched association is not a replay either.

    Every individual row here is genuine: a real claim, a real transition, a real event. The
    *relationship* is not -- the provenance says this claim stands for a transition of a
    different instance -- and the replay insists on the relationship rather than on the rows.

    The other instance is moved through the **unlinked** form, so its transition has no
    provenance of its own and the uniqueness constraint below is not what refuses this. The
    rows are written by the trusted administrator acting as the lifecycle writer, because
    since the third correction nothing else -- the schema owner included -- may write them.
    """
    from firmbatch.control_plane.db.lifecycle import transition_lifecycle_instance

    mine = new_instance(principal_a)
    other = new_instance(principal_a)
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        elsewhere = transition_lifecycle_instance(
            session,
            instance_id=other.id,
            expected_state=other.current_state,
            expected_revision=other.revision,
            target_state="active",
        )

    key = _key()
    operation = lifecycle_transition_operation(TEST_WORKFLOW.machine_key, TEST_WORKFLOW.version)
    result = {
        "lifecycle_instance_id": str(mine.id),
        "machine_key": TEST_WORKFLOW.machine_key,
        "machine_version": TEST_WORKFLOW.version,
        "from_state": "draft",
        "to_state": "active",
        "from_revision": 0,
        "to_revision": 1,
        "transition_id": str(elsewhere.transition_id),
    }
    with acting_as_lifecycle_writer(disposable_database, bind_as=principal_a) as connection:
        record_id = connection.execute(
            text(
                f"INSERT INTO {SCHEMA}.idempotency_records "
                "(tenant_id, operation, idempotency_key, request_fingerprint, status, result, "
                "lifecycle_machine_key, lifecycle_machine_version) "
                "VALUES (:t, :o, :k, :f, 'completed', CAST(:r AS jsonb), :m, :v) RETURNING id"
            ),
            {
                "t": principal_a.id,
                "o": operation,
                "k": key,
                "f": "0" * 64,
                "r": json.dumps(result),
                "m": TEST_WORKFLOW.machine_key,
                "v": TEST_WORKFLOW.version,
            },
        ).scalar_one()
        connection.execute(
            text(
                f"INSERT INTO {SCHEMA}.lifecycle_claim_provenance "
                "(idempotency_record_id, tenant_id, lifecycle_transition_id, "
                "lifecycle_instance_id, machine_key, machine_version, from_revision, "
                "to_revision, outbox_event_id) "
                "VALUES (:r, :t, :x, :i, :m, :v, 0, 1, :e)"
            ),
            {
                "r": record_id,
                "t": principal_a.id,
                # The transition really happened -- to the *other* instance.
                "x": elsewhere.transition_id,
                "i": mine.id,
                "m": TEST_WORKFLOW.machine_key,
                "v": TEST_WORKFLOW.version,
                "e": elsewhere.event_id,
            },
        )
        connection.commit()

    with pytest.raises(LifecycleProvenanceError):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            execute_idempotent_lifecycle_transition(
                session,
                idempotency_key=key,
                instance_id=mine.id,
                expected_state="draft",
                expected_revision=0,
                target_state="active",
            )
    assert _state(application_engine, principal_a, mine.id) == ("draft", 0)


def test_two_claims_cannot_stand_for_one_transition(
    application_engine, disposable_database, principal_a, new_instance
):
    """One provenance row per transition and one per event, in the other direction.

    A second claim pointed at a transition that already has one is refused by a unique
    constraint rather than by a check somebody has to remember to make -- so "this move was
    claimed once" is a property of the schema. Attempted as the lifecycle writer itself,
    which is the only identity that gets as far as the constraint.
    """
    position = new_instance(principal_a)
    outcome = _claim(application_engine, principal_a, position, "active", _key())

    with acting_as_lifecycle_writer(disposable_database, bind_as=principal_a) as connection:
        record_id = connection.execute(
            text(
                f"INSERT INTO {SCHEMA}.idempotency_records "
                "(tenant_id, operation, idempotency_key, request_fingerprint, status, result, "
                "lifecycle_machine_key, lifecycle_machine_version) "
                "VALUES (:t, :o, :k, :f, 'completed', '{}'::jsonb, :m, :v) RETURNING id"
            ),
            {
                "t": principal_a.id,
                "o": lifecycle_transition_operation(
                    TEST_WORKFLOW.machine_key, TEST_WORKFLOW.version
                ),
                "k": _key(),
                "f": "0" * 64,
                "m": TEST_WORKFLOW.machine_key,
                "v": TEST_WORKFLOW.version,
            },
        ).scalar_one()
        with pytest.raises(DBAPIError) as exc:
            connection.execute(
                text(
                    f"INSERT INTO {SCHEMA}.lifecycle_claim_provenance "
                    "(idempotency_record_id, tenant_id, lifecycle_transition_id, "
                    "lifecycle_instance_id, machine_key, machine_version, from_revision, "
                    "to_revision, outbox_event_id) "
                    "VALUES (:r, :t, CAST(:x AS uuid), :i, :m, :v, 0, 1, :e)"
                ),
                {
                    "r": record_id,
                    "t": principal_a.id,
                    "x": outcome.result["transition_id"],
                    "i": position.id,
                    "m": TEST_WORKFLOW.machine_key,
                    "v": TEST_WORKFLOW.version,
                    "e": outcome.event_id,
                },
            )
        connection.rollback()
    assert "uq_lifecycle_claim_provenance_transition_id" in str(exc.value)


def test_provenance_cannot_be_written_or_revised_even_by_the_owner(
    application_engine, owner_engine, principal_a, new_instance
):
    """Written by the transition boundary and by nothing else; never edited afterwards.

    The insert guard names the lifecycle writer because the transition function executes as
    the writer, and the update and delete refusals name nobody: a link that could be
    re-pointed after the fact would prove nothing about the claim it was written for. The
    owner's own insert attempt is ``test_lifecycle_writer.py``'s to refuse.
    """
    position = new_instance(principal_a)
    outcome = _claim(application_engine, principal_a, position, "active", _key())

    with owner_engine.connect() as connection:
        for statement in (
            f"UPDATE {SCHEMA}.lifecycle_claim_provenance SET to_revision = to_revision",
            f"DELETE FROM {SCHEMA}.lifecycle_claim_provenance",
        ):
            with pytest.raises(DBAPIError) as exc:
                connection.execute(text(statement))
            connection.rollback()
            assert "provenance is immutable" in str(exc.value), statement

    # And the row is still there, unchanged.
    rows = _provenance_rows(owner_engine, outcome.record_id)
    assert len(rows) == 1 and rows[0]["to_revision"] == 1


def test_the_application_role_cannot_insert_provenance_at_all(
    application_engine, principal_a, new_instance
):
    """No grant, so the refusal is the privilege system's rather than a predicate's."""
    position = new_instance(principal_a)
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.lifecycle_claim_provenance "
                    "(idempotency_record_id, tenant_id, lifecycle_transition_id, "
                    "lifecycle_instance_id, machine_key, machine_version, from_revision, "
                    "to_revision, outbox_event_id) "
                    "VALUES (gen_random_uuid(), :t, gen_random_uuid(), :i, :m, 1, 0, 1, "
                    "gen_random_uuid())"
                ),
                {"t": principal_a.id, "i": position.id, "m": TEST_WORKFLOW.machine_key},
            )
    assert "permission denied" in str(exc.value).lower()


# ---------------- the fingerprint is the database's (review finding 2)
#
# It used to arrive as a parameter, computed in Python. That made it a caller-controlled
# value in exactly the place a caller must not control one: move instance A while storing a
# fingerprint computed for a request about B, and the next genuine request for B replays A.
#
# There is no parameter to supply now. PostgreSQL is the canonical implementation and the
# only one -- Python computes no lifecycle fingerprint at all -- so there is no parity to
# prove and no second copy to drift.


def test_raw_sql_cannot_bind_a_claim_to_a_request_it_did_not_make(
    application_engine, principal_a, new_instance
):
    """**The reviewer's A/B scenario, as close to it as the signature now permits.**

    Raw SQL moves instance A under key K -- there is no fingerprint argument to supply, so
    the best a caller can do is claim the key for A and hope. A later genuine request for
    instance **B** with the same key is then not a replay: the fingerprint the database
    derived for A does not match the one it derives for B, so B is refused as a conflicting
    reuse and B does not move.
    """
    first = new_instance(principal_a)
    second = new_instance(principal_a)
    key = _key()

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        session.execute(
            text(
                f"SELECT * FROM {SCHEMA}.transition_lifecycle_instance("
                ":i, 'draft', 0, 'active', NULL, NULL, :k)"
            ),
            {"i": first.id, "k": key},
        )

    with pytest.raises(IdempotencyConflict):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            execute_idempotent_lifecycle_transition(
                session,
                idempotency_key=key,
                instance_id=second.id,
                expected_state="draft",
                expected_revision=0,
                target_state="active",
            )

    assert _state(application_engine, principal_a, first.id) == ("active", 1)
    assert _state(application_engine, principal_a, second.id) == ("draft", 0)


def test_the_raw_sql_call_takes_no_fingerprint_argument_at_all(
    application_engine, principal_a, new_instance
):
    """The strongest form of the property: there is nothing to supply.

    Passing an eighth argument is not a fingerprint that is ignored -- it is a function that
    does not exist.
    """
    position = new_instance(principal_a)
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"SELECT * FROM {SCHEMA}.transition_lifecycle_instance("
                    ":i, 'draft', 0, 'active', NULL, NULL, :k, :f)"
                ),
                {"i": position.id, "k": _key(), "f": "0" * 64},
            )
    assert "does not exist" in str(exc.value)
    assert _state(application_engine, principal_a, position.id) == ("draft", 0)


def _fingerprint(owner_engine, **overrides) -> str:
    arguments = {
        "tenant": uuid.UUID("00000000-0000-0000-0000-000000000001"),
        "operation": "lifecycle.transition.test_workflow.v1",
        "instance": uuid.UUID("00000000-0000-0000-0000-000000000002"),
        "machine_key": "test_workflow",
        "machine_version": 1,
        "expected_state": "draft",
        "expected_revision": 0,
        "target_state": "active",
        "reason": None,
        "details": "{}",
    }
    arguments.update(overrides)
    with owner_engine.connect() as connection:
        return connection.execute(
            text(
                f"SELECT {SCHEMA}.lifecycle_request_fingerprint("
                ":tenant, :operation, :instance, :machine_key, "
                "CAST(:machine_version AS integer), :expected_state, "
                "CAST(:expected_revision AS integer), :target_state, "
                "CAST(:reason AS text), CAST(:details AS jsonb))"
            ),
            arguments,
        ).scalar_one()


def test_the_database_fingerprint_is_a_sha256_hex_digest(owner_engine):
    value = _fingerprint(owner_engine)
    assert len(value) == 64
    assert set(value) <= set("0123456789abcdef")


@pytest.mark.parametrize(
    ("what", "left", "right"),
    (
        # Object key order: ``jsonb`` normalises it, so two spellings of one document are
        # one document and hash alike.
        ("object key order", '{"a": 1, "b": 2}', '{"b": 2, "a": 1}'),
        # Whitespace and duplicate keys, for the same reason.
        ("whitespace", '{"a":1}', '{ "a" : 1 }'),
        ("duplicate keys", '{"a": 1, "a": 1}', '{"a": 1}'),
        # Numbers: ``1e2`` and ``100`` are the same jsonb number.
        ("number spelling", '{"n": 1e2}', '{"n": 100}'),
        # Unicode: an escape and the character itself are the same string.
        ("unicode escapes", '{"s": "\\u00e9"}', '{"s": "é"}'),
    ),
)
def test_the_fingerprint_is_stable_across_equivalent_metadata(owner_engine, what, left, right):
    """``jsonb`` is what makes the descriptor canonical rather than merely deterministic.

    Two spellings of one document must not look like two different requests, or an identical
    retry would be refused as a conflicting reuse depending on how its client serialised the
    details.
    """
    assert _fingerprint(owner_engine, details=left) == _fingerprint(owner_engine, details=right), what


@pytest.mark.parametrize(
    ("what", "overrides"),
    (
        ("tenant", {"tenant": uuid.UUID("00000000-0000-0000-0000-0000000000ff")}),
        ("operation", {"operation": "lifecycle.transition.test_workflow.v2"}),
        ("instance", {"instance": uuid.UUID("00000000-0000-0000-0000-0000000000fe")}),
        ("machine key", {"machine_key": "test_cyclic"}),
        ("machine version", {"machine_version": 2}),
        ("expected state", {"expected_state": "active"}),
        ("expected revision", {"expected_revision": 1}),
        ("target state", {"target_state": "closed"}),
        ("reason", {"reason": "because"}),
        ("details", {"details": '{"a": 1}'}),
        ("a null detail value", {"details": '{"a": null}'}),
    ),
)
def test_every_part_of_the_request_changes_the_fingerprint(owner_engine, what, overrides):
    """Every field the review named is in the descriptor, asserted one at a time.

    A field that did not change the digest would be a field two different requests could
    disagree on while replaying each other.
    """
    assert _fingerprint(owner_engine) != _fingerprint(owner_engine, **overrides), what


def test_a_null_reason_is_a_value_and_not_an_omission(owner_engine):
    """NULL becomes ``null`` in the descriptor rather than disappearing from it.

    If it disappeared, a request with no reason and a request whose reason happened to be
    absent from the object would be the same digest -- which is fine here and would not be
    fine the day another optional field is added. Stated now, while it costs one assertion.
    """
    assert _fingerprint(owner_engine, reason=None) != _fingerprint(owner_engine, reason="")


def test_python_computes_no_lifecycle_fingerprint(owner_engine):
    """PostgreSQL is the canonical implementation, so there is no second one to keep in step.

    Asserted from the source rather than from behaviour: a Python fingerprint that agreed
    today would be a fingerprint somebody could pass tomorrow.
    """
    import pathlib

    from firmbatch.control_plane.db import lifecycle as lifecycle_module

    source = pathlib.Path(lifecycle_module.__file__).read_text()
    assert "hashlib" not in source
    assert "request_fingerprint" not in source
