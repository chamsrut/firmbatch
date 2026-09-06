"""A generic outbox writer proves its claim link before any constraint sees it.

The third M2.4 review found the last write-side existence oracle. ``idempotency_record_id``
is a column the application role may name -- the Milestone 2.2 primitive links each event
to the claim it wrote -- and, left to the constraints, naming it answered a question the
read policies refuse: a **hidden lifecycle claim's** id produced a uniqueness violation on
the one-event-per-claim index (the transition had already linked its event), an absent id
produced a foreign-key violation, and the foreign key is checked with row security bypassed
so the hidden row was found. Two different errors -- or, with ``ON CONFLICT DO NOTHING``,
silent success versus an error -- for two ids the caller could not read either of.

The correction is a ``BEFORE INSERT`` trigger on ``outbox_events`` that runs **before** the
tuple is formed, so before the unique index, before the ``ON CONFLICT`` arbiter, and before
the referential-integrity trigger. For anybody but the lifecycle writer it requires the link
to name a claim this authenticated context may read -- the lookup runs as the invoker under
``FORCE`` row security, so visibility is the read policy's decision -- in the row's own
tenant, untagged, and outside the reserved namespace. Every failure is one message from one
raise site. The lifecycle writer passes, because it is the boundary that links a lifecycle
claim to the event it wrote in the same call.

Everything here runs as the ordinary application role against the real server, because a
property asserted from the owner connection is a property nobody is defending against.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from firmbatch.control_plane.db import auth
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.idempotency import (
    OUTBOX_LINK_SQLSTATE,
    MutationOutcome,
    OutboxEventSpec,
    OutboxLinkRefused,
    append_outbox_event,
    execute_idempotent_mutation,
)
from firmbatch.control_plane.db.lifecycle import (
    create_lifecycle_instance,
    execute_idempotent_lifecycle_transition,
    lifecycle_instance,
)
from firmbatch.control_plane.db.models import OutboxEvent
from firmbatch.control_plane.db.repositories import WorkspaceRepository
from firmbatch.control_plane.security.authorization import Scope

from .conftest import TEST_RESTRICTED, TEST_WORKFLOW

#: The one-event-per-claim index, which is the *established* conflict for an authorized
#: claim that already carries its event -- and must stay that.
ONE_EVENT_PER_CLAIM = "uq_outbox_events_tenant_id_idempotency_record_id"

#: A raw link, written the way the Milestone 2.2 primitive writes one: no identifier, every
#: other column the application role may name.
_LINK = text(
    f"INSERT INTO {SCHEMA}.outbox_events "
    "(tenant_id, idempotency_record_id, event_type, aggregate_type, aggregate_id) "
    "VALUES (:t, :r, 'workspace.renamed', 'workspace', :a)"
)

#: The same link through ``ON CONFLICT DO NOTHING`` on the one-event-per-claim index. Left
#: to the constraints, this shape is the *cleaner* oracle: a hidden claim's id hits the
#: arbiter and the statement **succeeds** with zero rows, while an absent id fails the
#: foreign key.
_LINK_ON_CONFLICT = text(
    f"INSERT INTO {SCHEMA}.outbox_events "
    "(tenant_id, idempotency_record_id, event_type, aggregate_type, aggregate_id) "
    "VALUES (:t, :r, 'workspace.renamed', 'workspace', :a) "
    "ON CONFLICT (tenant_id, idempotency_record_id) DO NOTHING"
)


def _refusal(exc) -> tuple[str, str]:
    """The SQLSTATE and the server's message, without the statement psycopg appends."""
    error = exc.value
    orig = getattr(error, "orig", None)
    return getattr(orig, "sqlstate", None), str(error).split("[SQL:")[0].strip()


def _pair(new_principal, issue_credential):
    """One tenant, two credentials: one for ``test_restricted``, one for ``test_workflow``.

    The second cannot read the first's machine, so a claim the first makes is a **hidden**
    row to the second -- in the same tenant, which is the boundary under test. A cross-tenant
    pair would pass on the Milestone 2.1 boundary and prove nothing about this one.
    """
    tenant = new_principal("outbox-link")
    restricted = issue_credential(
        tenant, [Scope.AUDIT_READ, Scope.CREDENTIAL_MANAGE, Scope.MUTATION_EXECUTE]
    )
    probe = issue_credential(
        tenant, [Scope.WORKSPACE_READ, Scope.WORKSPACE_WRITE, Scope.MUTATION_EXECUTE]
    )
    return tenant, restricted, probe


def _hidden_lifecycle_claim(engine, restricted):
    """A claimed transition of a machine the probe cannot read: its claim id and event id."""
    with auth.authenticated_transaction(engine, restricted.credential) as session:
        hidden = create_lifecycle_instance(
            session,
            machine_key=TEST_RESTRICTED.machine_key,
            machine_version=TEST_RESTRICTED.version,
        )
    with auth.authenticated_transaction(engine, restricted.credential) as session:
        outcome = execute_idempotent_lifecycle_transition(
            session,
            idempotency_key=f"hl-{uuid.uuid4().hex}",
            instance_id=hidden.id,
            expected_state=hidden.current_state,
            expected_revision=hidden.revision,
            target_state="settled",
        )
    return outcome.record_id, outcome.event_id


def _unlinked_generic_claim(engine, principal) -> uuid.UUID:
    """A generic Milestone 2.2 claim with **no** event yet, written the way the role may."""
    with auth.authenticated_transaction(engine, principal.credential) as session:
        return session.execute(
            text(
                f"INSERT INTO {SCHEMA}.idempotency_records "
                "(tenant_id, operation, idempotency_key, request_fingerprint, status, result) "
                "VALUES (:t, 'workspace.rename', :k, :f, 'completed', '{}'::jsonb) RETURNING id"
            ),
            {"t": principal.id, "k": f"ug-{uuid.uuid4().hex}", "f": "0" * 64},
        ).scalar_one()


def _linked_generic_claim(engine, principal, slug: str) -> uuid.UUID:
    """A generic claim made by the primitive, so it already carries its one event."""

    def mutate(unit_of_work):
        workspace = WorkspaceRepository(unit_of_work).create(slug=slug, name=slug)
        return MutationOutcome(
            result={"workspace_id": workspace.id},
            event=OutboxEventSpec(
                event_type="workspace.created", aggregate_type="workspace", aggregate_id=workspace.id
            ),
        )

    with auth.authenticated_transaction(engine, principal.credential) as session:
        return execute_idempotent_mutation(
            session,
            operation="workspace.create",
            idempotency_key=f"lg-{uuid.uuid4().hex}",
            request_identity={"workspace_slug": slug},
            mutate=mutate,
        ).record_id


def _attempt_link(engine, principal, statement, record_id, tenant_id=None):
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(engine, principal.credential) as session:
            session.execute(
                statement,
                {"t": tenant_id or principal.id, "r": record_id, "a": uuid.uuid4()},
            )
    return exc


# ------------------------------------------------- 1. hidden versus absent, identically


def test_a_hidden_lifecycle_claim_and_an_absent_uuid_are_refused_identically(
    application_engine, new_principal, issue_credential, lifecycle_definitions
):
    """**The reviewer's attack, executable, and closed.**

    Same tenant, same credential, same statement, two ids: one belongs to a lifecycle claim
    this credential cannot read, one belongs to nothing. Before the correction the first hit
    the one-event-per-claim index and the second hit the foreign key; the two errors were
    the answer. Now both are the same custom refusal, raised before either constraint, and
    neither error names a constraint at all.
    """
    tenant, restricted, probe = _pair(new_principal, issue_credential)
    hidden_record, _hidden_event = _hidden_lifecycle_claim(application_engine, restricted)
    absent = uuid.uuid4()

    # The probe really cannot see the hidden claim, which is what makes this an oracle.
    with auth.authenticated_transaction(application_engine, probe.credential) as session:
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.idempotency_records WHERE id = :i"),
            {"i": hidden_record},
        ).scalar_one() == 0

    refusals = [
        _refusal(_attempt_link(application_engine, probe, _LINK, identifier))
        for identifier in (hidden_record, absent)
    ]
    assert refusals[0] == refusals[1], refusals
    state, message = refusals[0]
    assert state == OUTBOX_LINK_SQLSTATE
    assert "generic idempotency claim this context may read" in message
    for constraint in ("foreign key", ONE_EVENT_PER_CLAIM, "violates"):
        assert constraint not in message.lower(), message

    # And through the supported Python path, which translates it -- identically too.
    rendered = []
    for identifier in (hidden_record, absent):
        with pytest.raises(OutboxLinkRefused) as exc:
            with auth.authenticated_transaction(application_engine, probe.credential) as session:
                append_outbox_event(
                    session,
                    OutboxEventSpec(
                        event_type="workspace.renamed",
                        aggregate_type="workspace",
                        aggregate_id=uuid.uuid4(),
                    ),
                    idempotency_record_id=identifier,
                )
        assert exc.value.__cause__ is None and exc.value.__context__ is None
        rendered.append(str(exc.value))
    assert rendered[0] == rendered[1]
    assert str(hidden_record) not in rendered[0]


# ---------------------------------------------- 2. the same comparison, ON CONFLICT


def test_the_on_conflict_form_is_refused_identically_too(
    application_engine, new_principal, issue_credential, lifecycle_definitions
):
    """``INSERT ... ON CONFLICT DO NOTHING`` is the cleaner oracle, and it is closed too.

    Left to the constraints, a hidden claim's id reaches the arbiter and the statement
    **succeeds** with zero rows, while an absent id fails the foreign key. A ``BEFORE
    INSERT`` trigger fires before the arbiter is consulted, so both are the same refusal
    and neither succeeds.
    """
    tenant, restricted, probe = _pair(new_principal, issue_credential)
    hidden_record, _hidden_event = _hidden_lifecycle_claim(application_engine, restricted)

    refusals = [
        _refusal(_attempt_link(application_engine, probe, _LINK_ON_CONFLICT, identifier))
        for identifier in (hidden_record, uuid.uuid4())
    ]
    assert refusals[0] == refusals[1], refusals
    assert refusals[0][0] == OUTBOX_LINK_SQLSTATE

    # Nothing was written by either attempt.
    with auth.authenticated_transaction(application_engine, probe.credential) as session:
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.outbox_events WHERE event_type = 'workspace.renamed'")
        ).scalar_one() == 0


# --------------------------------------------- 3. an authorized generic link succeeds


def test_an_authorized_generic_claim_can_be_linked(application_engine, principal_a):
    """The control, in both spellings: raw SQL and the supported primitive.

    Without it every refusal above could be a trigger that refuses everything. An unlinked
    generic claim of this tenant, readable by this credential, takes exactly one event.
    """
    raw_claim = _unlinked_generic_claim(application_engine, principal_a)
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        session.execute(_LINK, {"t": principal_a.id, "r": raw_claim, "a": uuid.uuid4()})

    python_claim = _unlinked_generic_claim(application_engine, principal_a)
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        event_id = append_outbox_event(
            session,
            OutboxEventSpec(
                event_type="workspace.renamed", aggregate_type="workspace", aggregate_id=uuid.uuid4()
            ),
            idempotency_record_id=python_claim,
        )

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        linked = {
            event.idempotency_record_id: event
            for event in session.query(OutboxEvent).filter(
                OutboxEvent.idempotency_record_id.in_([raw_claim, python_claim])
            )
        }
        assert set(linked) == {raw_claim, python_claim}
        assert linked[python_claim].id == event_id
        assert linked[python_claim].lifecycle_machine_key is None


# ---------------------------------- 4. an already-linked authorized claim conflicts


def test_an_authorized_generic_claim_already_linked_conflicts_as_before(
    application_engine, principal_a
):
    """The Milestone 2.2 property, preserved rather than replaced.

    A claim this credential may read, in its own tenant, that already carries its event:
    the guard passes, and the one-event-per-claim index refuses -- by name, exactly as it
    always did. The refusal is the established conflict and **not** the link refusal.
    """
    claim = _linked_generic_claim(application_engine, principal_a, f"linked-{uuid.uuid4().hex[:8]}")

    with pytest.raises(IntegrityError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(_LINK, {"t": principal_a.id, "r": claim, "a": uuid.uuid4()})
    state, message = _refusal(exc)
    assert state == "23505"
    assert ONE_EVENT_PER_CLAIM in message
    assert "generic idempotency claim this context may read" not in message


# ------------------------------- 5. a lifecycle claim the writer can read, still refused


def test_a_generic_writer_cannot_link_a_lifecycle_claim_even_one_it_can_read(
    application_engine, principal_a, new_instance
):
    """Knowing the UUID -- and being entitled to read the claim -- buys nothing.

    This credential made the claimed transition, so the claim is visible to it and it holds
    the id legitimately. A second event linked to that claim is refused all the same, with
    the link refusal and **not** the one-event-per-claim conflict: a lifecycle claim is the
    lifecycle writer's to link, and it linked it already. The refusal is identical to the
    one an absent id gets, so even the entitled caller learns nothing from the shape.
    """
    position = new_instance(principal_a)
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        outcome = execute_idempotent_lifecycle_transition(
            session,
            idempotency_key=f"own-{uuid.uuid4().hex}",
            instance_id=position.id,
            expected_state=position.current_state,
            expected_revision=position.revision,
            target_state="active",
        )
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.idempotency_records WHERE id = :i"),
            {"i": outcome.record_id},
        ).scalar_one() == 1, "the claim must be readable here, or this proves nothing"

    mine = _refusal(_attempt_link(application_engine, principal_a, _LINK, outcome.record_id))
    absent = _refusal(_attempt_link(application_engine, principal_a, _LINK, uuid.uuid4()))
    assert mine == absent
    assert mine[0] == OUTBOX_LINK_SQLSTATE
    assert ONE_EVENT_PER_CLAIM not in mine[1]

    # The transition's own linked event is untouched, and still the only one.
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.outbox_events WHERE idempotency_record_id = :r"),
            {"r": outcome.record_id},
        ).scalar_one() == 1
        assert lifecycle_instance(session, position.id).revision == 1


# ------------------------------------ 6. cross-tenant and wrong identity, like absent


def test_cross_tenant_and_wrong_identity_links_fail_like_absent_claims(
    application_engine, principal_a, principal_b, new_principal, issue_credential
):
    """Three wrong links, one refusal, and it is the absent-claim refusal.

    * tenant B's unlinked generic claim, named by tenant A;
    * tenant A's own unlinked claim, on a row that names tenant B;
    * tenant A's own unlinked claim, linked by a credential in tenant A that does not hold
      ``mutation:execute`` -- the current authenticated authorization is what decides
      visibility, and without the capability the claim is not there.
    """
    theirs = _unlinked_generic_claim(application_engine, principal_b)
    mine = _unlinked_generic_claim(application_engine, principal_a)
    tenant = new_principal("wrong-identity")
    # The same tenant as ``tenant``'s owner credential, holding no framework capability.
    unentitled = issue_credential(tenant, [Scope.WORKSPACE_READ, Scope.WORKSPACE_WRITE])
    theirs_in_tenant = _unlinked_generic_claim(application_engine, tenant)

    baseline = _refusal(_attempt_link(application_engine, principal_a, _LINK, uuid.uuid4()))
    assert baseline[0] == OUTBOX_LINK_SQLSTATE

    cross_tenant = _refusal(_attempt_link(application_engine, principal_a, _LINK, theirs))
    wrong_row_tenant = _refusal(
        _attempt_link(application_engine, principal_a, _LINK, mine, tenant_id=principal_b.id)
    )
    wrong_identity = _refusal(
        _attempt_link(application_engine, unentitled, _LINK, theirs_in_tenant)
    )
    assert cross_tenant == baseline, cross_tenant
    assert wrong_row_tenant == baseline, wrong_row_tenant
    assert wrong_identity == baseline, wrong_identity

    # None of the three claims gained an event.
    for principal, claim in ((principal_b, theirs), (principal_a, mine), (tenant, theirs_in_tenant)):
        with auth.authenticated_transaction(application_engine, principal.credential) as session:
            assert session.execute(
                text(f"SELECT count(*) FROM {SCHEMA}.outbox_events WHERE idempotency_record_id = :r"),
                {"r": claim},
            ).scalar_one() == 0


# ---------------------------------------- 7. the lifecycle boundary still links atomically


def test_a_lifecycle_transition_still_links_its_event_atomically(
    application_engine, owner_engine, principal_a, new_instance
):
    """The writer passes the guard, and the link it writes is exactly one and all-or-nothing.

    The claimed transition commits one claim, one event linked to it and one provenance
    row naming both; a caller that fails after the call commits none of them, so there is
    no arrangement with a claim and no event or an event and no claim.
    """
    position = new_instance(principal_a)
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        outcome = execute_idempotent_lifecycle_transition(
            session,
            idempotency_key=f"at-{uuid.uuid4().hex}",
            instance_id=position.id,
            expected_state=position.current_state,
            expected_revision=position.revision,
            target_state="active",
        )
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        events = session.query(OutboxEvent).filter(
            OutboxEvent.idempotency_record_id == outcome.record_id
        ).all()
        assert [event.id for event in events] == [outcome.event_id]
        assert events[0].lifecycle_machine_key == TEST_WORKFLOW.machine_key
    with owner_engine.connect() as connection:
        assert connection.execute(
            text(
                f"SELECT outbox_event_id FROM {SCHEMA}.lifecycle_claim_provenance "
                "WHERE idempotency_record_id = :r"
            ),
            {"r": outcome.record_id},
        ).scalar_one() == outcome.event_id

    second = new_instance(principal_a)
    key = f"at-{uuid.uuid4().hex}"
    with pytest.raises(RuntimeError):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            execute_idempotent_lifecycle_transition(
                session,
                idempotency_key=key,
                instance_id=second.id,
                expected_state=second.current_state,
                expected_revision=second.revision,
                target_state="active",
            )
            raise RuntimeError("the process dies here, before COMMIT")
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.idempotency_records WHERE idempotency_key = :k"),
            {"k": key},
        ).scalar_one() == 0
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.outbox_events WHERE aggregate_id = :i"),
            {"i": second.id},
        ).scalar_one() == 1, "only the creation event; the discarded move left none"
        assert lifecycle_instance(session, second.id).revision == 0


# -------------------------------------------------------- the guard, from the catalogue


def test_the_link_guard_is_a_before_insert_row_trigger_run_as_the_invoker(owner_engine):
    """Asserted from the catalogue, so the ordering argument is a fact and not a comment.

    ``BEFORE`` and ``FOR EACH ROW``, so it runs before the tuple is formed -- before the
    unique index, the ``ON CONFLICT`` arbiter and the ``AFTER``-trigger foreign key.
    ``SECURITY INVOKER``, so its lookup of the claim runs under the inserting role's own
    row-security view rather than bypassing it through a definer.
    """
    with owner_engine.connect() as connection:
        tgtype, secdef, config = connection.execute(
            text(
                "SELECT g.tgtype, p.prosecdef, coalesce(array_to_string(p.proconfig, ','), '') "
                "FROM pg_catalog.pg_trigger g "
                "JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid "
                "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                "JOIN pg_catalog.pg_proc p ON p.oid = g.tgfoid "
                "WHERE n.nspname = :s AND c.relname = 'outbox_events' "
                "AND g.tgname = 'outbox_events_link_is_authorized' AND NOT g.tgisinternal"
            ),
            {"s": SCHEMA},
        ).one()
    # tgtype bits: 1 = FOR EACH ROW, 2 = BEFORE, 4 = INSERT.
    assert tgtype & 1, "not a row trigger"
    assert tgtype & 2, "not a BEFORE trigger"
    assert tgtype & 4, "not an INSERT trigger"
    assert secdef is False
    assert "search_path=pg_catalog" in config.replace(" ", "")


def test_an_absent_link_never_reaches_the_foreign_key(application_engine, principal_a):
    """The SQLSTATE says which layer refused: the guard, not referential integrity."""
    state, _message = _refusal(_attempt_link(application_engine, principal_a, _LINK, uuid.uuid4()))
    assert state == OUTBOX_LINK_SQLSTATE
    assert state != "23503", "the foreign key answered, so the guard did not run first"
