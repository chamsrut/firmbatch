"""The audit trail: derived actors, bounded details, immutable rows, tenant-scoped reads.

The trail answers one question -- who did what, for which tenant, when, and under which
request -- and the value of the answer depends entirely on nobody being able to write a
false one. So the tests here are mostly about what a caller *cannot* do: attribute an
action to another tenant, to another principal, to another binding, or to another time;
change a record after the fact; or read somebody else's.

Two things it deliberately is not, and both are asserted rather than described. It is not
the outbox -- the two are separate tables with separate primitives, because one records
intent to tell somebody and the other records who acted. And it is not a tamper-evident
log: there is no hash chain and no external delivery, because the canonical architecture
asks for audit events and building either of those here would be machinery invented ahead
of a requirement. What makes these rows trustworthy today is narrower and checkable, and
it is what this module checks.
"""

from __future__ import annotations

import json
import uuid
from contextlib import contextmanager
from datetime import timedelta

import pytest
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

from firmbatch.control_plane.tests.conftest import exception_chain as _exception_chain
from firmbatch.control_plane.db import audit, auth
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.metadata import MetadataPolicyError, validated_metadata
from firmbatch.control_plane.db.models import AUDIT_OUTCOMES, AuditEvent
from firmbatch.control_plane.db.repositories import TenantRepository, WorkspaceRepository
from firmbatch.control_plane.security.secrets import (
    WHITESPACE_CODE_POINTS as _WHITESPACE_CODE_POINTS,
)
from firmbatch.control_plane.security.secrets import (
    KeyBackend,
    KeyReference,
    Secret,
    generate_bearer_credential,
    looks_like_secret,
)

SPEC = audit.AuditEventSpec

#: Actions the fixtures themselves record. Creating a tenant mints its first credential,
#: and ``register_auth_binding`` audits -- which is the integration this milestone asked
#: for, and which means a freshly provisioned tenant's trail is not empty. Filtering them
#: out here keeps every assertion below about the event the test wrote, without any test
#: having to know how many rows the fixture left. :func:`_all_events` is for the tests
#: whose subject *is* the lifecycle record.
FIXTURE_ACTIONS = {"auth.binding_registered", "auth.binding_revoked"}


def _append(engine, principal, **kwargs):
    with auth.authenticated_transaction(engine, principal.credential) as session:
        return audit.append_audit_event(session, SPEC(**kwargs))


@contextmanager
def _owner_with_context(owner_engine, principal, actor_kind="credential", scopes=("audit:read",)):
    """An owner connection carrying a forged authenticated context. Always rolled back.

    Since no runtime role holds ``INSERT`` on ``audit_events``, the layers under the grant
    -- the insert policy and the check constraints -- can no longer be reached by a runtime
    role at all. They are still there and still load-bearing, so they are exercised from
    the one identity that *can* reach them: the schema owner, which holds the table's
    inherent rights and owns ``auth_context_begin`` besides.

    That makes these tests stronger than the ones they replace rather than weaker. The old
    version asserted "the application role cannot attribute an action to another tenant";
    this asserts it of the **schema owner**, under ``FORCE ROW LEVEL SECURITY``, with a
    context it wrote itself.
    """
    connection = owner_engine.connect()
    try:
        connection.execute(
            text(
                f"SELECT {SCHEMA}.auth_context_begin("
                "CAST(:b AS uuid), CAST(:t AS uuid), CAST(:p AS uuid), :k, CAST(:s AS text[]))"
            ),
            {
                "b": principal.binding_id if actor_kind == "credential" else None,
                "t": principal.id,
                "p": principal.principal_id if actor_kind == "credential" else None,
                "k": actor_kind,
                "s": list(scopes),
            },
        )
        yield connection
    finally:
        connection.rollback()
        connection.close()


def _all_events(engine, principal):
    with auth.authenticated_transaction(engine, principal.credential) as session:
        return {e.id: e for e in audit.audit_events(session)}


def _events(engine, principal):
    return {
        event_id: event
        for event_id, event in _all_events(engine, principal).items()
        if event.action not in FIXTURE_ACTIONS
    }


# ------------------------------------------------------------------ what it records


def test_an_event_records_the_whole_question_it_exists_to_answer(application_engine, principal_a):
    resource = uuid.uuid4()
    correlation = uuid.uuid4()
    event_id = _append(
        application_engine,
        principal_a,
        action="workspace.create",
        resource_type="workspace",
        resource_id=resource,
        correlation_id=correlation,
        details={"slug": "production", "member_count": 3},
    )

    event = _events(application_engine, principal_a)[event_id]
    # Who acted, and for whom -- neither of which the caller supplied.
    assert event.tenant_id == principal_a.id
    assert event.actor_kind == "credential"
    assert event.actor_principal_id == principal_a.principal_id
    assert event.actor_binding_id == principal_a.binding_id
    # What was done, to what, and under which request.
    assert event.action == "workspace.create"
    assert event.outcome == "succeeded"
    assert event.resource_type == "workspace"
    assert event.resource_id == resource
    assert event.correlation_id == correlation
    assert event.details == {"slug": "production", "member_count": 3}
    # When, from the server.
    assert event.occurred_at is not None and event.occurred_at.tzinfo is not None


def test_an_attempted_and_a_denied_action_are_recordable(application_engine, principal_a):
    """A trail that only records successes cannot answer the question it exists for."""
    recorded = {}
    for outcome in AUDIT_OUTCOMES:
        recorded[outcome] = _append(
            application_engine,
            principal_a,
            action="workspace.create",
            resource_type="workspace",
            outcome=outcome,
        )
    events = _events(application_engine, principal_a)
    assert {events[i].outcome for i in recorded.values()} == set(AUDIT_OUTCOMES)


def test_an_unknown_outcome_is_refused(application_engine, principal_a):
    with pytest.raises(audit.AuditError) as exc:
        _append(application_engine, principal_a, action="a.b", resource_type="thing", outcome="maybe")
    assert "closed" in str(exc.value)


@pytest.mark.parametrize(
    "action, resource_type",
    [("nodots", "workspace"), ("Workspace.Create", "workspace"), ("a.b", "Workspace"), ("a.b", "with space")],
)
def test_a_malformed_action_or_resource_type_is_refused_before_the_row(
    application_engine, principal_a, action, resource_type
):
    with pytest.raises(audit.AuditError):
        _append(application_engine, principal_a, action=action, resource_type=resource_type)
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == 1


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO {schema}.audit_events (action, outcome, resource_type) "
        "VALUES ('a.b', 'succeeded', 'workspace')",
        "UPDATE {schema}.audit_events SET action = 'x.y'",
        "DELETE FROM {schema}.audit_events",
        "TRUNCATE {schema}.audit_events",
    ],
)
def test_no_runtime_role_can_write_the_trail_except_through_the_function(
    application_engine, principal_a, statement
):
    """The correction that makes the metadata policy a property rather than a courtesy.

    While the application role held ``INSERT``, ``db/metadata.py`` was a boundary a caller
    could walk around by writing the ``INSERT`` itself: the table's check constraints bound
    a details document's size and shape and said nothing whatsoever about its content, so a
    bearer credential under an innocuous key was refused by Python and accepted by
    PostgreSQL. The privilege is gone, and ``firmbatch.append_audit_event`` -- which applies
    every rule again, inside the database -- is now the only way in.
    """
    with pytest.raises(ProgrammingError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(text(statement.format(schema=SCHEMA)))
    assert "permission denied" in str(exc.value).lower()


def test_the_database_refuses_a_malformed_action_under_raw_sql(application_engine, principal_a):
    """Called directly, bypassing ``db/audit.py`` entirely. The rule holds and does not echo."""
    bad = "Not A Valid Action"
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"SELECT {SCHEMA}.append_audit_event(:a, 'succeeded', 'workspace', "
                    "NULL, NULL, NULL)"
                ),
                {"a": bad},
            )
    server_message = str(exc.value.orig)
    assert "dotted lowercase name" in server_message
    # The server's own message names the rule and not the value. (SQLAlchemy renders the
    # caller's own bound parameters into the wrapper exception; that is the caller's
    # statement and the caller's data, and no error Firmbatch raises does it -- see
    # test_a_refused_append_carries_nothing_from_the_document.)
    assert bad not in server_message


def test_the_check_constraint_is_still_the_backstop_under_the_function(owner_engine, principal_a):
    """Defense in depth: the constraint holds even for the identity that can reach it.

    The application role can no longer write the row that would test this, so it is tested
    from the schema owner. If the constraint were ever dropped, the function above would
    still refuse -- and this is what says the second layer has not quietly gone away.
    """
    with _owner_with_context(owner_engine, principal_a) as connection:
        with pytest.raises(IntegrityError) as exc:
            connection.execute(
                text(
                    f"INSERT INTO {SCHEMA}.audit_events (action, outcome, resource_type) "
                    "VALUES ('Not A Valid Action', 'succeeded', 'workspace')"
                )
            )
        assert "ck_audit_events_action_format" in str(exc.value)


def test_a_provisioning_action_records_a_provisioning_actor(provisioning_engine, application_engine):
    """The one actor with no credential, and the trail says so rather than inventing one.

    Read back through the *application* role: provisioning holds ``INSERT`` and not
    ``SELECT`` on the trail, so it records what it did and cannot read it back -- which is
    itself the shape the grants were chosen for.
    """
    slug = f"audited-{uuid.uuid4().hex[:10]}"
    with auth.provisioning_transaction(provisioning_engine) as session:
        tenant = TenantRepository(session).create(slug=slug, name="Audited")
        issued = auth.register_auth_binding(session, principal_id=uuid.uuid4(), scopes=["audit:read"])
        tenant_id = tenant.id

    with auth.authenticated_transaction(application_engine, issued.credential) as session:
        events = audit.audit_events(session)

    assert [e.action for e in events] == ["auth.binding_registered"]
    event = events[0]
    assert event.tenant_id == tenant_id
    assert event.actor_kind == "provisioning"
    assert event.actor_principal_id is None
    assert event.actor_binding_id is None


# ---------------------------------------------------------------- derived, not supplied


def test_the_function_has_no_parameter_for_any_derived_column(owner_engine):
    """The strongest form of "a caller cannot supply it": there is nowhere to put it.

    ``firmbatch.append_audit_event`` takes the action, the outcome, the resource type, the
    resource id, the correlation id and the details. It does not take a tenant, an actor
    kind, a principal, a binding or a timestamp, so a caller cannot name one correctly or
    incorrectly, and the database has nothing to reconcile.
    """
    with owner_engine.connect() as connection:
        arguments = connection.execute(
            text(
                "SELECT pg_get_function_arguments(p.oid) FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = :s AND p.proname = 'append_audit_event'"
            ),
            {"s": SCHEMA},
        ).scalar_one()
    for forbidden in ("tenant", "actor", "principal", "binding", "occurred", "timestamptz"):
        assert forbidden not in arguments, (forbidden, arguments)


@pytest.mark.parametrize(
    "columns, values",
    [
        ("tenant_id", ":other_tenant"),
        ("actor_principal_id", ":other_principal"),
        ("actor_binding_id", ":other_binding"),
        ("actor_kind, actor_principal_id, actor_binding_id", "'provisioning', NULL, NULL"),
    ],
)
def test_not_even_the_owner_can_attribute_an_action_to_somebody_else(
    owner_engine, principal_a, principal_b, issue_credential, columns, values
):
    """The insert policy compares every derived column against the context, and refuses.

    Run as the **schema owner**, because ``FORCE ROW LEVEL SECURITY`` binds the owner too
    and because no runtime role can reach this table with an ``INSERT`` any more. The
    owner holds a context here that it wrote itself with ``auth_context_begin`` -- so this
    is the most privileged writer this database has, attempting the forgery with the
    mechanism's own tools, and being refused by the policy.
    """
    other_binding = issue_credential(principal_a, []).binding_id
    with _owner_with_context(owner_engine, principal_a) as connection:
        with pytest.raises(DBAPIError) as exc:
            connection.execute(
                text(
                    f"INSERT INTO {SCHEMA}.audit_events "
                    f"({columns}, action, outcome, resource_type) "
                    f"VALUES ({values}, 'workspace.create', 'succeeded', 'workspace')"
                ),
                {
                    "other_tenant": principal_b.id,
                    "other_principal": principal_b.principal_id,
                    "other_binding": other_binding,
                },
            )
        assert "row-level security" in str(exc.value).lower()


def test_a_supplied_timestamp_is_discarded_rather_than_stored(owner_engine, principal_a):
    """``occurred_at`` is written by a ``BEFORE INSERT`` trigger, so a supplied one is ignored.

    The first version of this compared the column against ``now()`` in the insert policy.
    That refused an *explicit* wrong value and missed the interesting case entirely: a
    caller does not have to supply anything to backdate an event, it only has to open its
    transaction early, because ``now()`` is transaction-*start* time and the default would
    then be an hour old with the policy agreeing. Both halves are covered here.
    """
    supplied = []
    recorded = []
    for offset in ("- interval '1 day'", "+ interval '1 day'"):
        # As the owner: no runtime role can name this column any more, because no runtime
        # role can write this table at all. The trigger is what makes the value
        # unsuppliable, and the trigger binds every writer including this one.
        with _owner_with_context(owner_engine, principal_a) as connection:
            connection.execute(
                text(
                    f"INSERT INTO {SCHEMA}.audit_events (action, outcome, resource_type, occurred_at) "
                    f"VALUES ('workspace.create', 'succeeded', 'workspace', now() {offset})"
                )
            )
            supplied.append(connection.execute(text(f"SELECT now() {offset}")).scalar())
            recorded.append(
                connection.execute(
                    text(
                        f"SELECT occurred_at FROM {SCHEMA}.audit_events "
                        "WHERE action = 'workspace.create' ORDER BY occurred_at DESC LIMIT 1"
                    )
                ).scalar()
            )

    assert len(recorded) == 2
    for stored, asked_for in zip(sorted(recorded), sorted(supplied)):
        assert stored != asked_for
    # Both landed within the run rather than a day either side of it.
    assert max(recorded) - min(recorded) < timedelta(minutes=1)


def test_an_event_cannot_be_dated_from_the_transactions_start(application_engine, principal_a):
    """The case a ``now()`` comparison could never have caught.

    The transaction opens, time passes, and the event is inserted. ``now()`` still reports
    the opening instant; ``clock_timestamp()`` reports the insert. The trigger uses the
    second, so the recorded time is when the event happened rather than when its
    transaction began -- and a caller cannot lengthen that gap into a backdate.
    """
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        started = session.execute(text("SELECT now()")).scalar()
        session.execute(text("SELECT pg_sleep(0.1)"))
        event_id = audit.append_audit_event(session, SPEC(action="a.b", resource_type="thing"))

    event = _events(application_engine, principal_a)[event_id]
    assert event.occurred_at > started, (
        "the event was dated from the transaction's start, so a long transaction backdates it"
    )
    assert event.occurred_at - started < timedelta(minutes=1)


def test_the_primitive_offers_no_way_to_name_an_actor(application_engine, principal_a):
    """There is no parameter to get wrong, which is stronger than one that is checked."""
    for field in ("tenant_id", "actor_principal_id", "actor_binding_id", "actor_kind", "occurred_at"):
        with pytest.raises(TypeError):
            SPEC(action="a.b", resource_type="thing", **{field: uuid.uuid4()})


def test_an_unauthenticated_transaction_cannot_append(application_engine):
    with pytest.raises(auth.AuthenticationError):
        with db_engine.transaction(application_engine) as session:
            audit.append_audit_event(session, SPEC(action="a.b", resource_type="thing"))


def test_appending_outside_a_transaction_is_refused(application_engine):
    from sqlalchemy.orm import Session

    session = Session(bind=application_engine)
    try:
        with pytest.raises(audit.AuditError):
            audit.append_audit_event(session, SPEC(action="a.b", resource_type="thing"))
    finally:
        session.close()


# --------------------------------------------------------------------------- isolation


def test_one_tenant_cannot_read_anothers_trail(application_engine, principal_a, principal_b):
    mine = _append(application_engine, principal_a, action="workspace.create", resource_type="workspace")
    theirs = _append(application_engine, principal_b, action="workspace.create", resource_type="workspace")

    assert set(_events(application_engine, principal_a)) == {mine}
    assert set(_events(application_engine, principal_b)) == {theirs}

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert session.get(AuditEvent, theirs) is None
        # Its own two: the fixture's binding registration, and the one written above.
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == 2


def test_the_actor_reference_is_composite_and_therefore_tenant_consistent(owner_engine):
    """Referential integrity runs with row security bypassed, so the reference is composite.

    A single-column ``REFERENCES auth_bindings(id)`` would accept a binding from another
    tenant as a perfectly valid actor, because the check that enforces it does not see the
    policies. Referencing ``(id, tenant_id)`` makes tenant consistency a database fact.

    Asserted on the schema rather than by attempting the row, and that is worth saying
    plainly: **there is no connection from which the attempt can be made.** The insert
    policy refuses a mismatched actor before the foreign key is consulted, and it refuses
    the owner too, because row security is ``FORCE``d. The constraint is the backstop for
    a future writer that arrives some other way -- a superuser, a later migration -- and
    what can be checked about a backstop nothing can currently reach is that it is there
    and points where it should.
    """
    from sqlalchemy import inspect

    fks = {
        fk["name"]: fk
        for fk in inspect(owner_engine).get_foreign_keys("audit_events", schema=SCHEMA)
    }
    composite = fks["fk_audit_events_actor_binding_id_tenant_id"]
    assert composite["constrained_columns"] == ["actor_binding_id", "tenant_id"]
    assert composite["referred_columns"] == ["id", "tenant_id"]
    assert composite["referred_table"] == "auth_bindings"
    assert composite["referred_schema"] == SCHEMA
    assert not any(
        fk["constrained_columns"] == ["actor_binding_id"] for fk in fks.values()
    ), "a single-column actor reference would reach across tenants"


# ------------------------------------------------------------------------ immutability


def test_a_committed_event_cannot_be_changed_by_the_application_role(application_engine, principal_a):
    _append(application_engine, principal_a, action="workspace.create", resource_type="workspace")

    with pytest.raises(ProgrammingError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(update(AuditEvent).values(outcome="failed"))
    assert "permission denied" in str(exc.value).lower()

    with pytest.raises(ProgrammingError):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(delete(AuditEvent))

    assert [e.outcome for e in _all_events(application_engine, principal_a).values()] == [
        "succeeded",
        "succeeded",
    ]


def test_even_the_owner_reaches_no_row_to_change(owner_engine, application_engine, principal_a):
    """The half a grant cannot buy: no ``UPDATE`` or ``DELETE`` policy exists at all."""
    _append(application_engine, principal_a, action="workspace.create", resource_type="workspace")

    with auth.authenticated_transaction(owner_engine, principal_a.credential) as session:
        # The owner really can see the rows, so a zero rowcount below is the policy and
        # not an empty table.
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == 2
        for statement in (
            f"UPDATE {SCHEMA}.audit_events SET outcome = 'failed'",
            f"DELETE FROM {SCHEMA}.audit_events",
        ):
            assert session.execute(text(statement)).rowcount == 0, statement

    assert [e.outcome for e in _events(application_engine, principal_a).values()] == ["succeeded"]


# ------------------------------------------------------------------------- atomicity


def test_a_rolled_back_action_takes_its_audit_record_with_it(application_engine, principal_a):
    """An audit row that outlived its action would assert something that did not happen."""
    with pytest.raises(RuntimeError):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            workspace = WorkspaceRepository(session).create(slug="doomed", name="Doomed")
            audit.append_audit_event(
                session,
                SPEC(action="workspace.create", resource_type="workspace", resource_id=workspace.id),
            )
            raise RuntimeError("the process dies here, before COMMIT")

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert WorkspaceRepository(session).list() == []
    assert _events(application_engine, principal_a) == {}


def test_the_record_commits_with_the_action_and_not_before(application_engine, principal_a):
    """The other direction: nothing is durable until the caller commits, and then both are."""
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        workspace = WorkspaceRepository(session).create(slug="together", name="Together")
        audit.append_audit_event(
            session,
            SPEC(action="workspace.create", resource_type="workspace", resource_id=workspace.id),
        )
        # Still uncommitted; another transaction sees neither.
        assert _events(application_engine, principal_a) == {}

    events = list(_events(application_engine, principal_a).values())
    assert len(events) == 1
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert [w.slug for w in WorkspaceRepository(session).list()] == ["together"]
    assert events[0].resource_id is not None


def test_appending_does_not_commit_the_callers_transaction(application_engine, principal_a):
    """It writes inside the transaction it was given, and owns none of the boundary."""
    with pytest.raises(RuntimeError):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            audit.append_audit_event(session, SPEC(action="a.b", resource_type="thing"))
            assert session.in_transaction()
            raise RuntimeError("unwinding on purpose")
    assert _events(application_engine, principal_a) == {}


# ---------------------------------------------------------------------- bounded details


def test_details_are_bounded_metadata(application_engine, principal_a):
    """The same policy as every other jsonb column in this schema, for the same reasons."""
    for bad in (
        {"nested": {"a": 1}},
        {"blob": b"\x00\x01"},
        {"long": "x" * 300},
        {"Bad Key": 1},
        {f"field_{i}": i for i in range(40)},
        {"list_too_long": list(range(40))},
    ):
        with pytest.raises(MetadataPolicyError):
            _append(application_engine, principal_a, action="a.b", resource_type="thing", details=bad)
    assert _events(application_engine, principal_a) == {}


def test_details_may_not_name_content_or_a_credential(application_engine, principal_a):
    for key in ("payload", "prompt", "api_key", "password", "authorization"):
        with pytest.raises(MetadataPolicyError) as exc:
            _append(
                application_engine, principal_a, action="a.b", resource_type="thing", details={key: "x"}
            )
        assert "content or a credential" in str(exc.value)


def test_reference_shaped_keys_are_accepted(application_engine, principal_a):
    """The vocabulary the trail exists to hold must stay usable."""
    event_id = _append(
        application_engine,
        principal_a,
        action="job.submitted",
        resource_type="job",
        details={
            "input_manifest_id": str(uuid.uuid4()),
            "output_object_key": "tenant/abc/attempt/1/out.jsonl",
            "artifact_digest": "sha256:" + "0" * 64,
            "request_count": 4000,
        },
    )
    assert event_id in _events(application_engine, principal_a)


@pytest.mark.parametrize(
    "value",
    [
        "fbk_" + "A" * 43,
        "-----BEGIN RSA PRIVATE KEY-----",
        "Bearer abcdefghijklmnop",
        "postgresql://user:hunter2@db.example.com:5432/prod",
        "AKIAIOSFODNN7EXAMPLE",
        "api_key=abc123",
    ],
)
def test_a_secret_shaped_value_is_refused_before_the_row(application_engine, principal_a, value):
    """Under an innocuous key, so the key denylist cannot be what catches it.

    Defense in depth and not a proof -- a credential in a format nobody anticipated passes
    every one of these. What it stops is the mistake somebody makes on the way to a
    deadline, at the boundary where they get a usable error.
    """
    with pytest.raises(MetadataPolicyError) as exc:
        _append(
            application_engine, principal_a, action="a.b", resource_type="thing", details={"note": value}
        )
    assert "looks like" in str(exc.value)
    # And the refusal does not carry the value it refused, which matters most for a short
    # secret where even a length is a clue.
    assert value not in str(exc.value)
    assert _events(application_engine, principal_a) == {}


def test_a_secret_object_cannot_be_smuggled_into_details(application_engine, principal_a):
    """A ``Secret`` is not a scalar, and the refusal renders its type and not its value."""
    secret = generate_bearer_credential()
    for value in (secret, KeyReference(KeyBackend.AWS_KMS, "alias/firmbatch")):
        with pytest.raises(MetadataPolicyError) as exc:
            _append(
                application_engine,
                principal_a,
                action="a.b",
                resource_type="thing",
                details={"note": value},
            )
        assert secret.reveal() not in str(exc.value)


def test_the_database_bounds_the_details_column_too(owner_engine, principal_a):
    """The check constraints, still there under the function that now refuses first.

    Written as the schema owner through a legitimate context, so the derived columns
    satisfy the policy and the constraint is what refuses the row -- which is the layer
    under test. A runtime role cannot reach this any more, and that is the point of the
    layer above it; this is what says the layer below has not been quietly removed.
    """
    for value, constraint in (
        ('"a string, not an object"', "ck_audit_events_details_object"),
        ('{"note": "' + "x" * 5000 + '"}', "ck_audit_events_details_bounded"),
    ):
        with _owner_with_context(owner_engine, principal_a) as connection:
            with pytest.raises(IntegrityError) as exc:
                connection.execute(
                    text(
                        f"INSERT INTO {SCHEMA}.audit_events "
                        "(action, outcome, resource_type, details) "
                        "VALUES ('a.b', 'succeeded', 'thing', CAST(:d AS jsonb))"
                    ),
                    {"d": value},
                )
            assert constraint in str(exc.value)


# --------------------------------------------------------- distinct from the outbox


def test_audit_events_and_outbox_events_are_different_records(application_engine, principal_a):
    """One records who acted; the other records intent to tell somebody. Neither implies
    the other, and an integration that collapsed them would lose both questions."""
    from firmbatch.control_plane.db.idempotency import OutboxEventSpec, append_outbox_event, outbox_events

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        workspace = WorkspaceRepository(session).create(slug="both", name="Both")
        audit_id = audit.append_audit_event(
            session,
            SPEC(action="workspace.create", resource_type="workspace", resource_id=workspace.id),
        )
        outbox_id = append_outbox_event(
            session,
            OutboxEventSpec(
                event_type="workspace.created", aggregate_type="workspace", aggregate_id=workspace.id
            ),
        )
    assert audit_id != outbox_id

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        trail = [e for e in audit.audit_events(session) if e.action not in FIXTURE_ACTIONS]
        outbox = outbox_events(session)
        assert [e.action for e in trail] == ["workspace.create"]
        assert [e.event_type for e in outbox] == ["workspace.created"]
        # An audit event carries an actor; an outbox event does not, and does not need one.
        assert trail[0].actor_binding_id == principal_a.binding_id
        assert not hasattr(outbox[0], "actor_binding_id")
        assert len(outbox) == 1


def test_an_internal_transition_appends_an_outbox_event_and_no_audit_record(
    application_engine, principal_a
):
    """The asymmetry, stated as a test: not every state change has an actor."""
    from firmbatch.control_plane.db.idempotency import OutboxEventSpec, append_outbox_event

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        workspace = WorkspaceRepository(session).create(slug="internal", name="Internal")
        append_outbox_event(
            session,
            OutboxEventSpec(
                event_type="workspace.reconciled", aggregate_type="workspace", aggregate_id=workspace.id
            ),
        )

    assert _events(application_engine, principal_a) == {}


def test_the_trail_is_ordered_oldest_first(application_engine, principal_a):
    ids = [
        _append(application_engine, principal_a, action=f"thing.step_{i}", resource_type="thing")
        for i in range(3)
    ]
    recorded = _events(application_engine, principal_a)
    assert set(recorded) == set(ids)
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        ordered = audit.audit_events(session)
    assert [e.occurred_at for e in ordered] == sorted(e.occurred_at for e in ordered)


def test_there_is_no_hash_chain_column(owner_engine):
    """Asserted so that "we decided not to" and "we forgot" are different states.

    A tamper-evident chain is not what the canonical architecture asks for, and one built
    here would be machinery invented ahead of a requirement -- with a verifier nobody runs
    and a repair story nobody has written. If a later milestone needs one, it arrives as a
    decision, and this test is what has to be deleted to make room for it.
    """
    with owner_engine.connect() as connection:
        columns = set(
            connection.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = :s AND table_name = 'audit_events'"
                ),
                {"s": SCHEMA},
            ).scalars()
        )
    assert not any(name in columns for name in ("previous_hash", "hash", "chain_hash", "signature"))
    assert not any(name in columns for name in ("delivered_at", "dispatched_at", "delivery_state"))


def test_a_secret_never_renders_itself_in_an_audit_failure(application_engine, principal_a):
    """The refusal path is a place a secret could leak, so it is tested as one."""
    secret = Secret("fbk_" + "B" * 43)
    with pytest.raises(MetadataPolicyError) as exc:
        _append(
            application_engine,
            principal_a,
            action="a.b",
            resource_type="thing",
            details={"note": secret.reveal()},
        )
    rendered = str(exc.value)
    assert secret.reveal() not in rendered
    assert "B" * 20 not in rendered


# --------------------------------------------- validation errors never echo (finding 7)

#: The same inputs the reference tests use, plus the shapes that only matter as *keys*.
ECHO_PROBES = (
    "fbk_" + "A" * 43,
    "postgresql://firmbatch:hunter2@db.internal:5432/prod",
    "AKIAIOSFODNN7EXAMPLE",
    "Bearer eyJhbGciOiJIUzI1NiJ9.e30.abc",
    "-----BEGIN RSA PRIVATE KEY-----",
)


def _chain(error: BaseException) -> str:
    """Every rendering an exception and its whole cause/context chain can produce."""
    seen = []
    current: BaseException | None = error
    while current is not None and len(seen) < 20:
        seen.append(f"{current!r} {current!s}")
        current = current.__cause__ or current.__context__
    return " || ".join(seen)


@pytest.mark.parametrize("probe", ECHO_PROBES)
def test_a_rejected_metadata_key_is_never_echoed(application_engine, principal_a, probe):
    """The finding, exactly: the format check used to quote the key it refused.

    A credential used as a metadata key is refused -- and the refusal is where it used to
    end up, in an exception, a traceback and a retained CI log. The error now names the
    position and the rule.
    """
    with pytest.raises(MetadataPolicyError) as exc:
        _append(
            application_engine, principal_a, action="a.b", resource_type="thing", details={probe: 1}
        )
    chain = _chain(exc.value)
    assert probe not in chain
    assert probe[:8] not in chain
    assert "entry 0" in chain, "the refusal must still say *which* entry was wrong"


@pytest.mark.parametrize("probe", ECHO_PROBES)
def test_a_rejected_metadata_value_is_never_echoed(application_engine, principal_a, probe):
    with pytest.raises(MetadataPolicyError) as exc:
        _append(
            application_engine,
            principal_a,
            action="a.b",
            resource_type="thing",
            details={"note": probe},
        )
    chain = _chain(exc.value)
    assert probe not in chain
    assert probe[:8] not in chain


def test_a_rejected_value_inside_a_list_is_located_and_not_echoed(application_engine, principal_a):
    probe = "fbk_" + "D" * 43
    with pytest.raises(MetadataPolicyError) as exc:
        _append(
            application_engine,
            principal_a,
            action="a.b",
            resource_type="thing",
            details={"ids": ["one", "two", probe]},
        )
    chain = _chain(exc.value)
    assert probe not in chain
    assert "entry 0, item 2" in chain


def test_an_oversized_value_does_not_report_its_length(application_engine, principal_a):
    """A length is a small leak in general and most of a short secret in particular."""
    probe = "x" * 900
    with pytest.raises(MetadataPolicyError) as exc:
        _append(
            application_engine,
            principal_a,
            action="a.b",
            resource_type="thing",
            details={"note": probe},
        )
    chain = _chain(exc.value)
    assert probe not in chain
    assert "900" not in chain
    assert "256" in chain, "the limit is useful and is not the caller's data"


@pytest.mark.parametrize("probe", ECHO_PROBES)
def test_a_rejected_action_or_resource_type_is_never_echoed(application_engine, principal_a, probe):
    """Actions are caller-supplied text too, and the check used to quote them."""
    for kwargs in (
        {"action": probe, "resource_type": "thing"},
        {"action": "a.b", "resource_type": probe},
    ):
        with pytest.raises(audit.AuditError) as exc:
            _append(application_engine, principal_a, **kwargs)
        chain = _chain(exc.value)
        assert probe not in chain
        assert probe[:8] not in chain


def test_a_short_malformed_key_is_refused_without_being_repeated(application_engine, principal_a):
    """The short-secret half of the rule, where it can actually be tested.

    A short password used as a *key* is refused for being malformed rather than for looking
    like a secret -- no rule can tell ``hunter2!`` from a typo. What matters is that the
    refusal does not quote it, because for a short value the quote is the whole secret.
    """
    for probe in ("hunter2!", "s3cr3t!", "Pw"):
        with pytest.raises(MetadataPolicyError) as exc:
            _append(
                application_engine,
                principal_a,
                action="a.b",
                resource_type="thing",
                details={probe: 1},
            )
        chain = _chain(exc.value)
        assert probe not in chain
        assert probe[:2] not in chain


# ------------------------------------- the metadata policy, in both places at once
#
# ``db/metadata.py`` applies the bounded-metadata policy at the boundary so a caller gets a
# usable error. ``firmbatch.audit_require_acceptable_details`` applies it inside the
# database so that it holds when the caller writes the SQL itself. Two implementations of
# one rule is exactly the arrangement that drifts, so the corpus below is walked by both
# and the two must agree on every entry.
#
# The corpus is not a sample of what somebody thought of. It is organised by *rule*, so a
# rule with no example is visible as a gap rather than absent.

ACCEPTED_DETAILS = {
    "empty": {},
    "scalars": {"count": 3, "ratio": 1.5, "ok": True, "absent": None, "note": "a short note"},
    "reference_keys": {
        "input_manifest_id": "m-1",
        "output_object_key": "s3://bucket/key",
        "artifact_digest": "sha256:" + "0" * 64,
    },
    "an_array_of_scalars": {"tags": ["a", "b", "c"]},
    "the_longest_allowed_string": {"note": "x" * 256},
    "the_largest_allowed_array": {"tags": [str(i) for i in range(16)]},
    "the_most_allowed_keys": {f"k{i}": i for i in range(32)},
    # A word that a shape rule would love to reject and must not: it is a perfectly good
    # identifier, and refusing it would make the policy about vocabulary rather than shape.
    "an_awkward_but_valid_key": {"password_rotated_at": "2026-09-05"},
    # Ordinary Unicode letters. The whitespace fold rewrites separators and nothing else,
    # so a note in another script is metadata like any other and must stay storable --
    # "reject anything non-ASCII" would have been a cheaper fix and the wrong one.
    "unicode_letters": {"note": "Grüße, naïve café — 日本語, русский"},
    "unicode_letters_in_an_array": {"tags": ["élève", "中文", "αβγ"]},
    # A no-break space in text that is not secret-shaped: folding it to a space changes
    # which separator class it is in and must not, on its own, refuse the document.
    "a_no_break_space_in_ordinary_text": {"note": "two\u00a0words"},
    # The stated limitation, asserted as behaviour rather than left in prose. A Unicode
    # homoglyph of a marker is recognised by NEITHER implementation, because the fold is
    # ASCII and these characters are not ASCII. That is the deliberate trade: a Unicode
    # fold cannot be reproduced by PostgreSQL's translate(), so keeping one would make
    # the boundary a caller can bypass stricter than the boundary that actually holds.
    # These entries exist so the limitation is a test somebody has to change on purpose,
    # not a sentence somebody can forget. See ADR 0006 decision 8c.
    "a_long_s_homoglyph_marker_a_stated_limitation": {"note": "\u017Fecret=x"},
    "a_kelvin_sign_homoglyph_marker_a_stated_limitation": {"note": "api\u212Aey=x"},
    # Ordinary words in scripts with their own casing rules stay storable.
    "turkish_words": {"note": "\u0130stanbul ve \u0131smail"},
}

#: Every code point ``security/secrets.WHITESPACE_CODE_POINTS`` folds, as characters.
#: Imported from the module rather than written out, so a widened set cannot leave this
#: corpus behind, and rendered by escape below because these characters are invisible.
WHITESPACE_CHARACTERS: tuple[str, ...] = tuple(
    chr(code) for code in _WHITESPACE_CODE_POINTS
)

#: Two shapes that are separator-sensitive, as templates over one whitespace character.
#: The first is the reported `` `` + ``Bearer example``; the second the reported
#: ``token`` + `` `` + ``=example``. Both were refused by Python and **accepted by
#: PostgreSQL** before the fold, on the half of the policy that holds when a runtime role
#: writes the call itself.
SEPARATOR_SENSITIVE_TEMPLATES: tuple[tuple[str, str], ...] = (
    ("before_bearer", "{ws}Bearer example"),
    ("around_assignment", "token{ws}={ws}example"),
    ("before_basic", "{ws}Basic dXNlcjpwYXNz"),
    ("uppercase_marker", "PASSWORD{ws}={ws}swordfish"),
    ("lowercase_marker", "secret{ws}:{ws}swordfish"),
    ("mixed_case_marker", "Api_Key{ws}={ws}swordfish"),
)

REJECTED_DETAILS = {
    "a_denied_key": {"password": "anything"},
    "another_denied_key": {"payload": "anything"},
    "a_secret_shaped_key": {"fbk_" + "A" * 43: 1},
    "an_uppercase_key": {"Note": 1},
    "a_key_with_a_space": {"a key": 1},
    "a_key_that_is_too_long": {"k" * 64: 1},
    "too_many_keys": {f"k{i}": i for i in range(33)},
    "a_nested_object": {"note": {"deeper": 1}},
    "a_nested_array": {"tags": [["a"]]},
    "an_object_in_an_array": {"tags": [{"a": 1}]},
    "an_array_that_is_too_long": {"tags": [str(i) for i in range(17)]},
    "a_string_that_is_too_long": {"note": "x" * 257},
    "a_bearer_credential": {"note": "fbk_" + "A" * 43},
    "a_credential_bearing_url": {"note": "postgresql://user:hunter2@localhost/db"},
    "an_authorization_header": {"note": "Bearer abcdefghijklmnopqrstuvwxyz"},
    "an_aws_access_key": {"note": "AKIAIOSFODNN7EXAMPLE"},
    "a_pem_block": {"note": "-----BEGIN RSA PRIVATE KEY-----"},
    "an_assignment": {"note": "api_key=abcdefghijklmnop"},
    "a_string_in_an_array": {"tags": ["fine", "fbk_" + "A" * 43]},
    "a_document_over_the_size_bound": {f"k{i}": "y" * 200 for i in range(20)},
    # The two values the review reported. Python's ``\s`` matched U+00A0 and PostgreSQL's
    # ``[[:space:]]`` did not, so each of these was refused at the boundary and stored by
    # the database -- and the database is the half that holds when a runtime role writes
    # ``append_audit_event`` itself.
    "a_no_break_space_before_bearer": {"note": "\u00a0Bearer example"},
    "a_no_break_space_around_an_assignment": {"note": "token\u00a0=\u00a0example"},
    # And the same trick moved into the key, which is checked by the same rule.
    "a_secret_shaped_key_using_a_no_break_space": {"token\u00a0=\u00a0example": 1},
    # ASCII case variation. ``re.IGNORECASE`` caught these and ``~*`` caught them too,
    # so they were never the bypass -- they are here because the explicit ASCII fold is
    # what carries them now, and a fold that lost an ordinary uppercase marker while
    # fixing the homoglyph disagreement would be a worse trade than the one made.
    "an_uppercase_marker_as_a_value": {"note": "SECRET=swordfish"},
    "a_mixed_case_marker_as_a_value": {"note": "ToKeN: swordfish"},
    "an_uppercase_marker_as_a_key": {"APIKEY=swordfish": 1},
    "a_mixed_case_marker_as_a_key": {"Api_Key=swordfish": 1},
    "an_uppercase_bearer_header": {"note": "BEARER abcdefghijklmnop"},
    "a_mixed_case_pem_block": {"note": "-----BeGiN Ec PrIvAtE kEy-----"},
    "a_lowercase_aws_access_key": {"note": "akiaiosfodnn7example"},
    # A non-ASCII letter is a word boundary under the explicit ASCII rule, so the
    # marker after it is recognised -- by both implementations, which is the point.
    "a_marker_behind_a_dotless_i": {"note": "\u0131token=swordfish"},
}


def test_the_corpus_covers_every_rule_the_policy_states():
    """A corpus is only worth what it covers, so the coverage is asserted rather than hoped.

    Each rule the policy states has at least one rejected example, and the accepted side
    carries the boundary values -- the longest allowed string, the largest allowed array,
    the most allowed keys -- because an off-by-one in a bound is refused metadata that
    should have been stored, which is a bug nobody notices until a trail is missing a row.
    """
    assert {"the_longest_allowed_string", "the_largest_allowed_array", "the_most_allowed_keys"} <= set(
        ACCEPTED_DETAILS
    )
    for rule in ("denied_key", "nested", "too_long", "too_many", "secret", "bearer", "size_bound"):
        assert any(rule in name for name in REJECTED_DETAILS), rule
    # The two normalisation steps, on both sides of the boundary, and the limitation.
    for rule in ("no_break_space", "uppercase_marker", "mixed_case_marker"):
        assert any(rule in name for name in REJECTED_DETAILS), rule
    for rule in ("homoglyph", "unicode_letters", "turkish"):
        assert any(rule in name for name in ACCEPTED_DETAILS), rule


@pytest.mark.parametrize("name", sorted(ACCEPTED_DETAILS))
def test_python_and_postgresql_both_accept_the_accepted_corpus(
    application_engine, principal_a, name
):
    details = ACCEPTED_DETAILS[name]
    validated = validated_metadata(details, where="the corpus")
    event_id = _append(
        application_engine, principal_a, action="a.b", resource_type="thing", details=details
    )
    stored = _events(application_engine, principal_a)[event_id]
    assert stored.details == validated


@pytest.mark.parametrize("name", sorted(REJECTED_DETAILS))
def test_python_and_postgresql_both_reject_the_rejected_corpus(
    application_engine, principal_a, name
):
    """Both, on the same document, and the database one reached by raw SQL.

    The Python half is the boundary a caller meets. The PostgreSQL half is the one that
    holds when there is no Python -- and since no runtime role holds ``INSERT`` on the
    trail, ``firmbatch.append_audit_event`` is the only way a row gets written at all.
    """
    details = REJECTED_DETAILS[name]
    with pytest.raises(MetadataPolicyError):
        validated_metadata(details, where="the corpus")

    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"SELECT {SCHEMA}.append_audit_event('a.b', 'succeeded', 'thing', "
                    "NULL, NULL, CAST(:d AS jsonb))"
                ),
                {"d": json.dumps(details)},
            )
    assert "firmbatch:" in str(exc.value.orig)
    assert _events(application_engine, principal_a) == {}


@pytest.mark.parametrize("name", sorted(REJECTED_DETAILS))
def test_the_databases_refusal_never_quotes_the_document(application_engine, principal_a, name):
    """The refusal names the rule and the position. It does not name the content.

    Checked on the **server's own message**, because that is the part Firmbatch writes.
    SQLAlchemy renders the caller's bound parameters into the wrapper exception when the
    caller composed the statement, which is the caller's own data on the caller's own
    statement -- and no error raised by ``db/audit.py`` does it, which
    ``test_a_refused_append_carries_nothing_from_the_document`` is what checks.
    """
    details = REJECTED_DETAILS[name]
    interesting = [
        str(value)
        for value in list(details.keys()) + list(details.values())
        if isinstance(value, str) and len(value) > 8
    ]
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"SELECT {SCHEMA}.append_audit_event('a.b', 'succeeded', 'thing', "
                    "NULL, NULL, CAST(:d AS jsonb))"
                ),
                {"d": json.dumps(details)},
            )
    message = str(exc.value.orig)
    for value in interesting:
        assert value not in message, (name, value)


def test_a_refused_append_carries_nothing_from_the_document(application_engine, principal_a):
    """The boundary refuses first, and its refusal quotes nothing."""
    leaked = "fbk_" + "C" * 43
    with pytest.raises(MetadataPolicyError) as exc:
        _append(
            application_engine,
            principal_a,
            action="a.b",
            resource_type="thing",
            details={"note": leaked},
        )
    chain = _exception_chain(exc.value)
    assert leaked not in chain, chain


def test_the_database_refusal_reaches_python_carrying_nothing_either(
    application_engine, principal_a, monkeypatch
):
    """With the Python boundary removed, so the database is what refuses.

    The two layers agree on every document (the corpus above is what says so), which means
    the second layer's error path cannot be reached through the ordinary call. It is
    reached here by disabling the first, because that path has its own promise to keep: the
    statement carries the caller's whole details document as a bound parameter, and a
    ``DBAPIError`` renders its parameters. If ``db/audit.py`` let that exception travel --
    as ``__cause__``, as ``__context__``, or by quoting its text -- the refusal would
    reattach exactly the document it exists to keep out of a log.

    ``raise ... from None`` alone would not be enough. It sets ``__suppress_context__``,
    which stops a *printed* traceback showing the original; it does not detach it. The
    error is built inside the handler and raised outside it, and this walks the whole graph
    to say so.
    """
    leaked = "fbk_" + "E" * 43
    monkeypatch.setattr(audit, "validated_metadata", lambda value, where: dict(value))

    with pytest.raises(audit.AuditError) as exc:
        _append(
            application_engine,
            principal_a,
            action="a.b",
            resource_type="thing",
            details={"note": leaked},
        )
    assert "looks like a Firmbatch bearer credential" in str(exc.value)
    chain = _exception_chain(exc.value)
    assert leaked not in chain, chain
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None


def test_an_unanticipated_database_error_repeats_no_database_text_at_all(
    application_engine, principal_a, monkeypatch
):
    """The other half: a failure this module did not anticipate says so and stops there.

    An unexpected error can render the failing row, and the failing row here is the
    caller's metadata document. So an unanticipated SQLSTATE produces a message with no
    database text in it -- the code and nothing else.
    """
    leaked = "fbk_" + "F" * 43
    monkeypatch.setattr(audit, "validated_metadata", lambda value, where: dict(value))
    # A statement with an argument too many, so the database refuses it with a SQLSTATE
    # this module does not anticipate -- while still carrying the details document as a
    # bound parameter, which is the part that must not come back.
    monkeypatch.setattr(
        audit,
        "_APPEND_STATEMENT",
        text(f"SELECT {SCHEMA}.append_audit_event(:action, :outcome, :resource_type, "
             "CAST(:resource_id AS uuid), CAST(:correlation_id AS uuid), "
             "CAST(:details AS jsonb), NULL)"),
    )
    with pytest.raises(audit.AuditError) as exc:
        _append(
            application_engine,
            principal_a,
            action="a.b",
            resource_type="thing",
            details={"note": leaked},
        )
    assert "deliberately not repeated here" in str(exc.value)
    chain = _exception_chain(exc.value)
    assert leaked not in chain, chain


def test_the_shape_recogniser_agrees_in_both_languages(owner_engine):
    """``firmbatch.secret_shape`` and ``looks_like_secret`` name the same shapes.

    Two regular-expression dialects -- Python's ``re`` and PostgreSQL's ARE -- so the
    patterns are not identical text and cannot be compared by reading them. What can be
    compared is the answer, on the corpus above plus the values a rule must *not* fire on.
    """
    from firmbatch.control_plane.security.secrets import looks_like_secret

    samples = [
        "fbk_" + "A" * 43,
        "-----BEGIN RSA PRIVATE KEY-----",
        "Bearer abcdefghijklmnop",
        "basic dXNlcjpwYXNz",
        "postgresql://user:hunter2@localhost/db",
        "AKIAIOSFODNN7EXAMPLE",
        "ASIAIOSFODNN7EXAMPLE",
        "api_key=abcdefghijklmnop",
        "PASSWORD: swordfish",
        # And the ones nothing may fire on.
        "a perfectly ordinary note",
        "sha256:" + "0" * 64,
        "s3://bucket/key",
        "workspace_slug",
        "password_rotated_at",
        "hunter2",
        "",
    ]
    with owner_engine.connect() as connection:
        for sample in samples:
            in_sql = connection.execute(
                text(f"SELECT {SCHEMA}.secret_shape(:v)"), {"v": sample}
            ).scalar()
            in_python = looks_like_secret(sample)
            assert in_sql == in_python, (sample, in_sql, in_python)


# ------------------------------------- whitespace, which the two dialects disagreed about
#
# Python's ``\s`` and PostgreSQL's ``[[:space:]]`` are different sets, and the second is
# decided by the server's ``lc_ctype``. Measured on this server before the fix: U+0085,
# U+00A0, U+2007 and U+202F are whitespace to Python and are not whitespace to
# PostgreSQL. So ``" Bearer example"`` and ``"token =example"`` were refused by
# ``validated_metadata`` and **accepted** by the database -- and no runtime role holds
# INSERT on the trail, so ``firmbatch.append_audit_event`` is the only way a row is
# written and its check is the one that has to hold.
#
# The correction is to stop asking either dialect what whitespace is: both fold an
# explicitly enumerated set to an ASCII space before matching. The tests below walk that
# whole set rather than the two reported examples, because a fix verified only against
# the two reported examples is a fix that covers two code points.


def test_the_declared_whitespace_set_is_exactly_what_python_treats_as_whitespace():
    """The enumeration is the contract, so it is checked against ``\\s`` itself.

    If a future Python widened ``\\s``, an unenumerated code point would be whitespace to
    ``looks_like_secret``'s *callers'* intuition and not to the fold -- and, worse, the
    fold would no longer be the complete bridge between the two implementations. That
    would be a silent reopening of exactly this gap, so it fails here instead.
    """
    import re as _re

    matched = {code for code in range(0x110000) if _re.match(r"\s", chr(code))}
    assert set(_WHITESPACE_CODE_POINTS) == matched
    # And the code points the review named explicitly, so the list cannot be trimmed.
    named = {
        0x0085, 0x00A0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
        *range(0x2000, 0x200B),
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20,
    }
    assert named <= set(_WHITESPACE_CODE_POINTS)


def test_the_migration_carries_the_identical_code_point_list():
    """Two copies, one equality test -- the same arrangement as the ACL sanitiser.

    A migration is a historical record and must not import application code, so the list is
    duplicated. The behavioural test below would catch a *missing* code point, because an
    unfolded separator no longer matches `` `` in either pattern; this catches a
    reordered or duplicated one too, and it says which list is wrong rather than which
    sample failed.
    """
    import importlib.util
    import pathlib

    from firmbatch.control_plane.db import models as models_module

    path = (
        pathlib.Path(models_module.__file__).parent
        / "migrations"
        / "versions"
        / "0003_auth_context_and_audit.py"
    )
    spec = importlib.util.spec_from_file_location("firmbatch_migration_0003_whitespace", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    assert tuple(migration.WHITESPACE_CODE_POINTS) == tuple(_WHITESPACE_CODE_POINTS)
    # And the rendered literals agree with the list, one replacement space per code point.
    assert migration._whitespace_replacement_literal() == "'" + " " * len(
        _WHITESPACE_CODE_POINTS
    ) + "'"
    assert migration._whitespace_literal() == "U&'" + "".join(
        f"\\{code:04X}" for code in _WHITESPACE_CODE_POINTS
    ) + "'"


@pytest.mark.parametrize("code", _WHITESPACE_CODE_POINTS, ids=lambda c: f"U+{c:04X}")
def test_python_and_postgresql_agree_on_every_declared_whitespace_code_point(owner_engine, code):
    """Every code point in the declared set, in every separator-sensitive shape.

    Both implementations are asked for the *name* of the shape, not merely for a verdict:
    agreeing that something is a secret while disagreeing about which kind would still be
    two rules rather than one.
    """
    character = chr(code)
    with owner_engine.connect() as connection:
        for label, template in SEPARATOR_SENSITIVE_TEMPLATES:
            sample = template.format(ws=character)
            in_sql = connection.execute(
                text(f"SELECT {SCHEMA}.secret_shape(:v)"), {"v": sample}
            ).scalar()
            in_python = looks_like_secret(sample)
            assert in_sql == in_python, (label, hex(code), in_sql, in_python)
            assert in_python is not None, (label, hex(code))


@pytest.mark.parametrize("code", _WHITESPACE_CODE_POINTS, ids=lambda c: f"U+{c:04X}")
def test_an_ordinary_note_separated_by_any_declared_whitespace_stays_valid(owner_engine, code):
    """The control. Folding a separator must not turn ordinary prose into a secret."""
    sample = f"two{chr(code)}ordinary{chr(code)}words"
    with owner_engine.connect() as connection:
        in_sql = connection.execute(
            text(f"SELECT {SCHEMA}.secret_shape(:v)"), {"v": sample}
        ).scalar()
    assert in_sql is None
    assert looks_like_secret(sample) is None


@pytest.mark.parametrize(
    "sample",
    [
        "Grüße, naïve café",
        "日本語のノート",
        "русский текст",
        "αβγδε",
        "sha256:" + "0" * 64,
        "workspace_slug",
        "password_rotated_at",
    ],
)
def test_ordinary_unicode_is_not_whitespace_and_stays_valid(owner_engine, sample):
    """Non-whitespace Unicode is untouched by the fold, in both implementations.

    "Reject everything non-ASCII" would have closed the gap and refused a legitimate note
    in most of the world's scripts. The fold rewrites separators only, and this is what
    says so.
    """
    with owner_engine.connect() as connection:
        in_sql = connection.execute(
            text(f"SELECT {SCHEMA}.secret_shape(:v)"), {"v": sample}
        ).scalar()
    assert in_sql is None
    assert looks_like_secret(sample) is None


@pytest.mark.parametrize("code", (0x0085, 0x00A0, 0x2007, 0x202F))
def test_the_reported_bypasses_are_refused_by_the_database_itself(
    application_engine, principal_a, code
):
    """The exploit, through raw SQL, on the half that has no Python in front of it.

    ``append_audit_event`` is the only way any role writes an audit row, so this is the
    check that decides whether the value can be stored -- and before the fold it accepted
    both of these.
    """
    character = chr(code)
    for sample in (f"{character}Bearer example", f"token{character}=example"):
        with pytest.raises(DBAPIError) as exc:
            with auth.authenticated_transaction(
                application_engine, principal_a.credential
            ) as session:
                session.execute(
                    text(
                        f"SELECT {SCHEMA}.append_audit_event('a.b', 'succeeded', 'thing', "
                        "NULL, NULL, CAST(:d AS jsonb))"
                    ),
                    {"d": json.dumps({"note": sample})},
                )
        assert "firmbatch:" in str(exc.value.orig)
        # And the refusal does not repeat the value it refused, which is the whole reason
        # the shape test runs before the format test.
        assert sample not in str(exc.value.orig)
    assert _events(application_engine, principal_a) == {}


@pytest.mark.parametrize("code", (0x0085, 0x00A0, 0x2007, 0x202F))
def test_the_python_refusal_of_a_folded_bypass_carries_no_cause_and_no_value(code):
    """The boundary half: refused, and refused without echoing anything.

    ``exception_chain`` walks ``__cause__`` and ``__context__`` as well as ``str`` --
    ``raise ... from None`` suppresses a printed traceback and does not detach a chain, so
    the graph is what has to be empty of the value.
    """
    character = chr(code)
    for sample in (f"{character}Bearer example", f"token{character}=example"):
        with pytest.raises(MetadataPolicyError) as exc:
            validated_metadata({"note": sample}, where="the corpus")
        chain = _exception_chain(exc.value)
        assert sample not in chain, chain
        assert "Bearer" not in chain
        assert "example" not in chain
        assert exc.value.__cause__ is None
        assert exc.value.__context__ is None


# --------------------------------------------------------- outcomes are never echoed


@pytest.mark.parametrize(
    "hostile",
    [
        "fbk_" + "A" * 43,
        "Bearer abcdefghijklmnop",
        "postgresql://user:hunter2@localhost/db",
        "AKIAIOSFODNN7EXAMPLE",
        "hunter2",
        "zq7",
        "SUCCEEDED",
        "probably fine",
    ],
)
def test_an_invalid_outcome_is_never_repeated_back(application_engine, principal_a, hostile):
    """The outcome is caller-supplied text from a closed set, so it gets the same rule.

    Including the values no pattern recognises. "It did not look like a credential" is not
    a reason to interpolate unvetted input into an exception that travels into a traceback
    and a retained log.
    """
    with pytest.raises(audit.AuditError) as exc:
        _append(
            application_engine, principal_a, action="a.b", resource_type="thing", outcome=hostile
        )
    chain = _exception_chain(exc.value)
    assert hostile not in chain, chain


def test_the_database_refuses_an_invalid_outcome_without_echoing_it(
    application_engine, principal_a
):
    """And under raw SQL, where Python's check is not in the way."""
    hostile = "fbk_" + "D" * 43
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"SELECT {SCHEMA}.append_audit_event('a.b', :o, 'thing', NULL, NULL, NULL)"
                ),
                {"o": hostile},
            )
    message = str(exc.value.orig)
    assert "not one of the four" in message
    assert hostile not in message


# ------------------------------------ ASCII case, which the two dialects also disagreed on
#
# The whitespace section above closed one locale-dependent construct. This closes the
# other. Measured on this server, on the pre-fix patterns:
#
#     U+017F + "ecret=x"      Python: refused    PostgreSQL: STORED
#     "api" + U+212A + "ey=x" Python: refused    PostgreSQL: STORED
#
# ``re.IGNORECASE`` is Unicode case folding; ``~*`` is locale case folding. Both are gone.
# Values are folded A-Z to a-z explicitly -- by ``str.translate`` here and by
# ``translate()`` there -- and the patterns are lowercase and case-sensitive.
#
# The parity claim is now structural rather than sampled: the *pattern text itself* is
# identical in both places, and the first test below compares it character for character.
# The corpus tests are still worth their runtime, because identical text matched by two
# different regular-expression engines is one assumption further than identical answers.

ASCII_CASE_MARKERS = ("secret", "password", "token", "api_key", "apikey", "api-key")


def _ascii_case_variants(word: str) -> tuple[str, ...]:
    return (
        word,
        word.upper(),
        word[:1].upper() + word[1:],
        "".join(c.upper() if i % 2 else c for i, c in enumerate(word)),
    )


def test_the_migration_carries_the_identical_pattern_text():
    """Not "equivalent patterns" -- the same characters, compared.

    Before this correction the two lists were a Python dialect and a PostgreSQL dialect of
    the same intent: ``\\b`` against ``\\y``, an inline ``(?i)`` against the ``~*``
    operator, ``\\s`` against ``[[:space:]]``. Every one of those pairings turned out to
    mean something slightly different, and a reader comparing them could not see it.

    Now the normalisation happens before matching and the patterns contain nothing either
    engine has to look up, so the text can simply be the same text -- and this is what says
    it still is. A migration must not import application code, so the copy stays; what does
    not stay is the licence to let it drift.
    """
    import importlib.util
    import pathlib

    from firmbatch.control_plane.db import models as models_module
    from firmbatch.control_plane.security import secrets as secrets_module

    path = (
        pathlib.Path(models_module.__file__).parent
        / "migrations"
        / "versions"
        / "0003_auth_context_and_audit.py"
    )
    spec = importlib.util.spec_from_file_location("firmbatch_migration_0003_patterns", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    assert tuple(migration.SECRET_SHAPES) == tuple(secrets_module.SECRET_SHAPE_PATTERNS)
    assert migration.ASCII_UPPERCASE == secrets_module.ASCII_UPPERCASE
    assert migration.ASCII_LOWERCASE == secrets_module.ASCII_LOWERCASE
    assert (
        migration.ASCII_WORD_BOUNDARY_BEFORE == secrets_module.ASCII_WORD_BOUNDARY_BEFORE
    )
    assert migration.ASCII_WORD_BOUNDARY_AFTER == secrets_module.ASCII_WORD_BOUNDARY_AFTER

    # And the rendered function carries no case-insensitive operator and no
    # locale-sensitive case conversion, which is the property the pattern equality
    # rests on. Read with the ``--`` comments stripped: the body explains itself at
    # length and the explanation names the very operators the assertion looks for, so a
    # test that read the comments would be measuring the prose.
    executable = '\n'.join(
        line.split("--", 1)[0] for line in migration._SECRET_SHAPE.splitlines()
    )
    assert "~*" not in executable
    assert "lower(" not in executable and "upper(" not in executable
    assert "citext" not in executable
    # The two folds really are there, in the stated order.
    assert executable.index("translate") < executable.index(migration.ASCII_UPPERCASE)
    assert executable.count("translate") == 2


#: Values whose *shape verdict* must be identical in both implementations. Organised by the
#: rule each one exercises, so a rule with no example is visible as a gap.
CASE_FOLD_CORPUS: tuple[str, ...] = (
    # ASCII case variation of every marker, in both separators.
    *(
        f"{variant}{separator}swordfish"
        for marker in ASCII_CASE_MARKERS
        for variant in _ascii_case_variants(marker)
        for separator in ("=", ":")
    ),
    # ASCII case variation of both authorization schemes.
    *(
        f"{variant} abcdefghijklmnop"
        for word in ("bearer", "basic")
        for variant in _ascii_case_variants(word)
    ),
    # The other four shapes, in both cases.
    "FBK_" + "a" * 43,
    "fbk_" + "A" * 43,
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----begin rsa private key-----",
    "-----BeGiN Ec PrIvAtE kEy-----",
    "AKIAIOSFODNN7EXAMPLE",
    "akiaiosfodnn7example",
    "AsIaIOSFODNN7EXAMPLE",
    "POSTGRESQL://u:p@h/db",
    "postgresql://u:p@h/db",
    # The two reported homoglyphs, which must now be answered the same way by both --
    # and the answer is "not recognised", which is the stated limitation.
    "\u017Fecret=x",
    "\u017FECRET=x",
    "api\u212Aey=x",
    "API\u212AEY=x",
    # Turkish dotted and dotless i, and ordinary words in other scripts.
    "\u0131token=x",
    "\u0130token=x",
    "\u0130d_token=x",
    "\u0130stanbul",
    "\u0131smail",
    "Grüße, naïve café",
    "日本語",
    "русский",
    "αβγ",
    # And the values nothing may fire on, in mixed case.
    "A Perfectly Ordinary Note",
    "SHA256:" + "0" * 64,
    "S3://bucket/KEY",
    "Workspace_Slug",
    "Password_Rotated_At",
    "Input_Manifest_Id",
    "",
)


def test_the_case_fold_corpus_covers_every_rule_it_should():
    """A corpus is worth what it covers, so the coverage is asserted rather than hoped."""
    joined = "\n".join(CASE_FOLD_CORPUS)
    assert "\u017F" in joined, "the long-s homoglyph is missing"
    assert "\u212A" in joined, "the Kelvin-sign homoglyph is missing"
    assert "\u0130" in joined and "\u0131" in joined, "Turkish dotted/dotless i is missing"
    # Every marker, in all four ASCII case variants.
    for marker in ASCII_CASE_MARKERS:
        for variant in _ascii_case_variants(marker):
            assert any(entry.startswith(variant) for entry in CASE_FOLD_CORPUS), variant
    # At least one sample per shape name, so no rule is unexercised.
    from firmbatch.control_plane.security.secrets import SECRET_SHAPE_PATTERNS

    named = {looks_like_secret(entry) for entry in CASE_FOLD_CORPUS}
    for name, _ in SECRET_SHAPE_PATTERNS:
        assert name in named, name
    assert None in named, "the corpus has no sample that must be accepted"


@pytest.mark.parametrize("value", CASE_FOLD_CORPUS, ids=lambda v: repr(v)[:48])
def test_python_and_postgresql_name_the_same_shape_for_every_case_fold_sample(
    owner_engine, value
):
    """The verdict *and* which shape it is, on every entry.

    Agreeing that something is a secret while disagreeing about which kind would still be
    two rules rather than one.
    """
    with owner_engine.connect() as connection:
        in_sql = connection.execute(
            text(f"SELECT {SCHEMA}.secret_shape(:v)"), {"v": value}
        ).scalar()
    assert in_sql == looks_like_secret(value), (repr(value), in_sql, looks_like_secret(value))


@pytest.mark.parametrize("code", _WHITESPACE_CODE_POINTS, ids=lambda c: f"U+{c:04X}")
def test_case_variation_and_every_declared_whitespace_agree_together(owner_engine, code):
    """The two folds interact, so they are tested interacting.

    Each whitespace code point carrying a case-varied marker across it: the pipeline has to
    apply both steps for these to be recognised, and both implementations have to apply them
    in the same order.
    """
    character = chr(code)
    samples = [
        f"{character}BeArEr example",
        f"{character}BASIC dXNlcjpwYXNz",
        f"ToKeN{character}={character}example",
        f"PASSWORD{character}:{character}example",
        f"Api_Key{character}={character}example",
        f"two{character}Ordinary{character}Words",
    ]
    with owner_engine.connect() as connection:
        for sample in samples:
            in_sql = connection.execute(
                text(f"SELECT {SCHEMA}.secret_shape(:v)"), {"v": sample}
            ).scalar()
            in_python = looks_like_secret(sample)
            assert in_sql == in_python, (hex(code), repr(sample), in_sql, in_python)
    # And the control in the same breath: ordinary words do not become a secret because
    # one of them was capitalised.
    assert looks_like_secret(f"two{character}Ordinary{character}Words") is None


@pytest.mark.parametrize(
    "marker", ["SECRET", "Password", "ToKeN", "APIKEY", "Api_Key", "API-KEY"]
)
def test_a_case_varied_marker_is_refused_by_the_database_itself(
    application_engine, principal_a, marker
):
    """Through raw SQL, on the half with no Python in front of it.

    ``append_audit_event`` is the only way any role writes an audit row, so this is the
    check that decides whether the value can be stored -- as a **value** and as a **key**,
    because the same rule runs on both.
    """
    value_document = {"note": f"{marker}=swordfish"}
    key_document = {f"{marker}=swordfish": 1}
    for document in (value_document, key_document):
        with pytest.raises(DBAPIError) as exc:
            with auth.authenticated_transaction(
                application_engine, principal_a.credential
            ) as session:
                session.execute(
                    text(
                        f"SELECT {SCHEMA}.append_audit_event('a.b', 'succeeded', 'thing', "
                        "NULL, NULL, CAST(:d AS jsonb))"
                    ),
                    {"d": json.dumps(document)},
                )
        message = str(exc.value.orig)
        assert "firmbatch:" in message
        # And the refusal does not repeat what it refused, in any case variant.
        assert marker not in message
        assert "swordfish" not in message
    assert _events(application_engine, principal_a) == {}


@pytest.mark.parametrize(
    "marker", ["SECRET", "Password", "ToKeN", "APIKEY", "Api_Key", "API-KEY"]
)
def test_the_python_refusal_of_a_case_varied_marker_carries_no_value_and_no_chain(marker):
    """The boundary half: refused, and refused without echoing anything.

    ``exception_chain`` walks ``__cause__`` and ``__context__`` as well as ``str`` and
    ``args``, because ``raise ... from None`` suppresses a printed traceback and does not
    detach the chain.
    """
    for document in ({"note": f"{marker}=swordfish"}, {f"{marker}=swordfish": 1}):
        with pytest.raises(MetadataPolicyError) as exc:
            validated_metadata(document, where="the corpus")
        chain = _exception_chain(exc.value)
        assert marker not in chain, chain
        assert "swordfish" not in chain, chain
        assert exc.value.__cause__ is None
        assert exc.value.__context__ is None
