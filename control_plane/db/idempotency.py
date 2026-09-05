"""One idempotent mutation, one committed effect, one linked outbox event.

This is the Milestone 2.2 primitive. A caller hands it an operation name, a caller-chosen
idempotency key, the **request identity** the key was chosen for, and a function that
performs the authoritative database mutation. Inside the caller's **single** transaction
it:

1. validates the operation, the key and the request identity **before** anything runs;
2. requires a tenant context, and refuses without one;
3. fingerprints the request identity deterministically;
4. replays the stored result if the key has already been claimed for the same identity;
5. **rejects** the key if it was claimed for a different one;
6. otherwise runs the mutation once, records the claim with a metadata-only result, and
   appends exactly one outbox event linked to that claim.

The business state, the completed idempotency record and the outbox event are written on
one transaction and become visible together at ``COMMIT``. Nothing durable exists before
that instant, which is the property that makes the failure story short: a process that
dies at any point before ``COMMIT`` leaves no row anywhere, so the retry that follows
takes the ordinary first-attempt path. There is deliberately no ``in_progress`` record --
a durable half-claim needs a recovery system to interpret it, and this milestone does not
build one.

The mutation contract
---------------------

``mutate`` is **not** given the caller's ``Session``. It is given a
:class:`MutationUnitOfWork`, which forwards the ORM operations a mutation legitimately
needs -- ``add``, ``flush``, ``execute``, ``get``, ``scalars`` -- and refuses the ones
that would take the transaction away from the primitive: ``commit``, ``rollback``,
``close``, ``begin``, ``begin_nested``, ``connection``, ``get_bind``.

That refusal is load-bearing rather than tidy. ``Session.commit()`` in SQLAlchemy 2.x
commits the **outermost** transaction even while a ``begin_nested()`` SAVEPOINT is open,
so a callback holding the real Session could commit its business row before the claim and
the event were written -- producing exactly the duplicate effect this module exists to
prevent, and leaving a later retry to collide with a row that no claim explains.

The unit of work does not close that on its own, because the real ``Session`` is one
``object_session(some_mapped_row)`` away. So for the duration of the callback -- and only
for that duration -- a ``before_commit`` listener is attached to the real Session and
**refuses the commit before it happens**. ``before_commit`` is dispatched ahead of the
flush a commit performs, so nothing is written and nothing is committed. The listener is
removed in a ``finally`` before the primitive releases its own SAVEPOINT and long before
the caller commits the real transaction; nothing stays attached to a session that outlives
the call.

A post-hoc check cannot do this job, and is not claimed to: nothing in Python can
un-commit. What ``_require_intact_boundary`` adds after the callback is **secondary
detection** of a boundary destroyed some other way -- a rollback reached through the real
Session, most obviously -- where there is no atomicity left to preserve anyway.

**What a mutation may do:** rollback-safe transactional DML through the unit of work, and
nothing else. No provider calls, no email, no spending, no session or connection commits,
no session-scoped locks (``pg_advisory_lock``; the transaction-scoped variants are
released by the rollback, the session-scoped ones are not), no writes to files or queues,
no external HTTP. A losing concurrent caller's mutation **is executed and then rolled
back**, so any effect that a ``ROLLBACK`` does not undo will have happened for a
transaction that never committed. Effects that must outlive the transaction go into the
outbox and are performed by a later dispatcher.

Like everything else in this repository, this is an accident-prevention guardrail for an
aligned caller, not a sandbox. The scoped pre-commit guard closes the known escape -- the
one a contributor reaches by reflex, ``Session.commit()`` on the session behind a mapped
row. It does **not** bound arbitrary Python: a callback that opens its own engine or
connection, drops to the DBAPI, or issues ``COMMIT`` as raw SQL is outside this
transaction and outside anything this module can see.

**All business writes for the operation must therefore happen inside ``mutate``, and the
primitive must be called before any DML for that operation.** A write the caller already
flushed in the outer transaction is not inside the primitive's SAVEPOINT and is not rolled
back when a lost race discards the mutation; it is covered only by the caller's own
transaction. That case is invisible here by construction -- ``session.new``,
``session.dirty`` and ``session.deleted`` describe *pending* state, and a flushed write is
no longer pending -- so it is a contract, not a check.

What this does **not** claim
----------------------------

**Not exactly-once external delivery.** The outbox records durable intent. No dispatcher
exists; when one does, it may deliver **at least once**, and a consumer must tolerate
duplicates. What is proved here is narrower: one committed database effect and one linked
outbox event per (tenant, operation, key).

**Not "every claim has an event", by constraint.** The unique constraint on
``(tenant_id, idempotency_record_id)`` enforces **at most one** linked event per claim; it
cannot enforce that one exists. That the primitive writes exactly one, atomically with the
claim, is proved by its PostgreSQL tests rather than asserted by the schema.

**Not a guarantee that ``mutate`` runs once per call.** It runs at most once per
*committed* transaction. Two callers racing on one key both begin work; the loser's
mutation is rolled back to a ``SAVEPOINT`` and it then replays the winner's stored result.

Concurrency
-----------

The control is the unique index on ``(tenant_id, operation, idempotency_key)`` and
PostgreSQL's own transaction semantics -- not a lock in this process, which would stop
being a guarantee the moment a second control-plane process started. Two transactions
claiming one key serialise on that index: the second blocks until the first commits and
then sees a unique violation, which this module recovers from by rolling back its
savepoint and re-reading the winner's row.

That recovery depends on ``READ COMMITTED``, where each statement takes a fresh snapshot
and so the re-read sees the row that just committed. Under ``REPEATABLE READ`` or
``SERIALIZABLE`` the re-read would run against the transaction's older snapshot and find
nothing, which is a wrong answer rather than a slow one -- so the isolation level is
checked and anything else is refused rather than quietly mishandled.

Request identity, and the limit of what this proves
---------------------------------------------------

Target-architecture invariant 3 says customer payload bytes never pass through the API
process or PostgreSQL. **Milestone 2.2 does not prove that**, and nothing here should be
read as proving it: the presigned S3 payload path, and the data-flow argument that goes
with it, are Milestone 5.

What M2.2 proves is the narrower thing it can: **the primitive persists only a digest and
bounded metadata.** The value a caller passes as ``request_identity`` is not a request
body -- it is the bounded metadata that identifies a request: identifiers, counts,
digests, and references to objects that live elsewhere (``input_manifest_id``,
``output_object_key``, ``artifact_digest``). It is validated *before* the mutation runs,
hashed, and discarded; only the digest reaches a row.

The validation is a curated **exact-name** denylist plus size and shape bounds. Both are
defense in depth and **neither is a proof**: ``TEXT`` and ``JSONB`` hold text, so an
encoded or textual payload can be stored in them, a 256-character string can be content,
and the absence of a ``bytea`` column makes storing bytes inconvenient rather than
impossible. The rules stop the obvious mistake at the boundary where a caller gets a
usable error. The check constraints in migration ``0002`` are the backstop for a writer
that bypasses this module.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from sqlalchemy import event, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..security.authorization import Scope
from ..security.secrets import looks_like_secret
from .auth import require_authenticated_context
from .engine import TenantContextError
# Re-exported, in the ``name as name`` form that says so: the metadata policy moved to
# ``db/metadata.py`` at Milestone 2.3 so the audit trail could hold itself to the same
# rule, and every caller that imported one of these from here keeps working.
from .metadata import DENIED_METADATA_KEYS as DENIED_METADATA_KEYS
from .metadata import MAX_METADATA_DOCUMENT_BYTES as MAX_METADATA_DOCUMENT_BYTES
from .metadata import MAX_METADATA_KEYS as MAX_METADATA_KEYS
from .metadata import MAX_METADATA_SEQUENCE_LENGTH as MAX_METADATA_SEQUENCE_LENGTH
from .metadata import MAX_METADATA_STRING_LENGTH as MAX_METADATA_STRING_LENGTH
from .metadata import METADATA_KEY_REGEX as METADATA_KEY_REGEX
from .metadata import MetadataPolicyError as MetadataPolicyError
from .metadata import canonical_json, validated_metadata
from .models import (
    DOTTED_NAME_REGEX,
    IDEMPOTENCY_KEY_REGEX,
    IDEMPOTENCY_STATUS_COMPLETED,
    SIMPLE_NAME_REGEX,
    IdempotencyRecord,
    OutboxEvent,
)

#: The unique constraint a losing concurrent claim violates. Matched by name so that an
#: integrity error raised by the caller's *own* mutation -- a duplicate workspace slug,
#: say -- is re-raised rather than mistaken for a lost race and silently swallowed.
CLAIM_CONSTRAINT = "uq_idempotency_records_tenant_id_operation_idempotency_key"

#: The isolation level the recovery path above is correct under, and the PostgreSQL
#: default. Anything else is refused.
REQUIRED_ISOLATION_LEVEL = "read committed"

#: The metadata policy for every bounded ``jsonb`` column in this schema lives in
#: ``db/metadata.py``. It was extracted at Milestone 2.3 so that the audit trail could hold
#: itself to exactly the same rule; every public name is re-exported here, so callers that
#: imported it from this module are unaffected.
#:
#: See that module for what is refused and, more importantly, for what none of it proves.

#: What a mutation may reach through its unit of work.
_FORWARDED_OPERATIONS = (
    "add",
    "add_all",
    "delete",
    "merge",
    "flush",
    "execute",
    "scalars",
    "scalar",
    "get",
    "refresh",
    "expire",
    "is_modified",
)

#: What it may not, and why each one matters. ``commit`` is the merge blocker: in
#: SQLAlchemy 2.x it commits the OUTERMOST transaction even inside a ``begin_nested()``
#: SAVEPOINT, so a callback could persist its business row without the claim or the event.
_REFUSED_OPERATIONS = {
    "commit": "it commits the outermost transaction even inside a SAVEPOINT, which would persist "
    "the business change without its idempotency claim or its outbox event",
    "rollback": "it discards the whole transaction, including the claim the primitive is about to "
    "write; the primitive owns the transaction boundary",
    "close": "it ends the session the primitive is mid-transaction on",
    "begin": "the transaction is already open and belongs to the caller",
    "begin_nested": "the primitive's SAVEPOINT is what bounds this mutation; a second one nested "
    "inside it would change what a rollback undoes",
    "connection": "a raw connection can issue COMMIT directly",
    "get_bind": "the Engine leads to connections outside this transaction",
    "get_transaction": "the transaction boundary is the primitive's, not the mutation's",
    "get_nested_transaction": "the SAVEPOINT boundary is the primitive's, not the mutation's",
    "expunge_all": "it would detach rows the primitive still has to flush",
    "invalidate": "it discards the connection under the open transaction",
    "bulk_save_objects": "the legacy bulk API bypasses the unit of work's flush accounting",
    "bulk_insert_mappings": "the legacy bulk API bypasses the unit of work's flush accounting",
    "bulk_update_mappings": "the legacy bulk API bypasses the unit of work's flush accounting",
}


class IdempotencyError(RuntimeError):
    """Base class for every refusal this module makes."""


class IdempotencyConflict(IdempotencyError):
    """The key exists for this tenant and operation, claimed for a different request."""


class IsolationLevelError(IdempotencyError):
    """The transaction is not ``READ COMMITTED``, which the recovery path requires."""


class MutationContractError(IdempotencyError):
    """A mutation tried to leave the transaction boundary the primitive holds."""


# --------------------------------------------------------------------------- unit of work


def _refusal(name: str, reason: str):
    def refuse(self, *_args, **_kwargs):
        raise MutationContractError(
            f"a mutation may not call {name}(): {reason}. A mutation performs rollback-safe "
            "transactional DML through this unit of work and nothing else -- no provider calls, "
            "no email, no spending, no session-scoped locks, and no transaction control. Anything "
            "that must outlive the transaction belongs in the outbox event."
        )

    refuse.__name__ = name
    refuse.__qualname__ = f"MutationUnitOfWork.{name}"
    return refuse


class MutationUnitOfWork:
    """The handle a mutation is given instead of the caller's ``Session``.

    Forwards the ORM operations a mutation legitimately needs and refuses the ones that
    would take the transaction away from the primitive. It duck-types as a ``Session`` for
    the repositories in this package, so ``WorkspaceRepository(unit_of_work)`` works
    unchanged.

    Accident prevention, not a sandbox -- see the module docstring. The private reference
    is name-mangled so that reaching the real session is at least a deliberate act.
    """

    def __init__(self, session: Session) -> None:
        self.__session = session

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return "MutationUnitOfWork(<the primitive's transaction>)"


def _install_unit_of_work_surface() -> None:
    """Build the forwarding and refusing methods once, at import."""
    for name in _FORWARDED_OPERATIONS:

        def forward(self, *args, _name=name, **kwargs):
            return getattr(self._MutationUnitOfWork__session, _name)(*args, **kwargs)

        forward.__name__ = name
        forward.__qualname__ = f"MutationUnitOfWork.{name}"
        setattr(MutationUnitOfWork, name, forward)

    for name, reason in _REFUSED_OPERATIONS.items():
        setattr(MutationUnitOfWork, name, _refusal(name, reason))


_install_unit_of_work_surface()


# --------------------------------------------------------------------------- value types


@dataclass(frozen=True)
class OutboxEventSpec:
    """The event a state change commits alongside itself.

    ``aggregate_id`` names what the event is about. It is not a foreign key: the referent
    is polymorphic, and one foreign key per aggregate kind would couple the outbox to
    every table the product will ever have.
    """

    event_type: str
    aggregate_type: str
    aggregate_id: uuid.UUID
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MutationOutcome:
    """What a mutation function returns: the replayable result, and the event."""

    #: Metadata only. This is exactly what a later identical retry gets back, so it has
    #: to be enough for the caller and no more than that.
    result: Mapping[str, Any]
    event: OutboxEventSpec


@dataclass(frozen=True)
class IdempotentResult:
    """What the primitive returns, on a first execution and on a replay alike."""

    record_id: uuid.UUID
    event_id: uuid.UUID
    result: dict[str, Any]
    #: ``True`` when the mutation was not run because the key had already been claimed.
    replayed: bool


#: A mutation runs inside the caller's transaction and returns what to record.
Mutation = Callable[[MutationUnitOfWork], MutationOutcome]


# --------------------------------------------------------------------- fingerprinting


def request_fingerprint(*, tenant_id: uuid.UUID, operation: str, request_identity: Mapping[str, Any]) -> str:
    """The SHA-256 digest stored in place of the request identity.

    Tenant and operation are folded in as domain separation. They already scope the
    lookup, so this changes no outcome; it means a digest carries its scope with it and
    cannot be compared across one.
    """
    material = canonical_json(
        {"tenant": str(tenant_id), "operation": operation, "request_identity": dict(request_identity)}
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- preconditions


def _require_open_transaction(session: Session, function: str) -> None:
    if not session.in_transaction():
        raise TenantContextError(
            f"{function} requires an open transaction: the state change, the claim and the event "
            "only mean anything if they commit together."
        )


def _require_valid_name(value: Any, *, pattern: str, what: str, example: str) -> None:
    """Validate one caller-supplied name without repeating it back.

    Shape first, then format. The value is not echoed: an operation name is caller-supplied
    text, and a refusal that quoted it would put whatever was pasted there into an
    exception and from there into a log.
    """
    shape = looks_like_secret(value)
    if shape is not None:
        raise IdempotencyError(
            f"the {what} looks like {shape}. It names an operation; it is not a place for a "
            "secret, and the value is deliberately not repeated here."
        )
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise IdempotencyError(
            f"the {what} is not acceptable; it must match {pattern} (for example {example!r}). "
            "Checked here, before the mutation runs, so a malformed name cannot produce a "
            "business change that the claim then fails to record. The value is deliberately not "
            "repeated."
        )


def _require_valid_key(idempotency_key: Any) -> None:
    """Validate the caller-chosen key, and refuse one that carries a secret shape.

    The key format -- letters, digits and ``._:@=+-`` -- happily accepts a Firmbatch bearer
    credential, and the key is **stored verbatim**. So the shape test is not cosmetic here:
    it is what stops a caller that reached for the nearest unique-looking string from
    writing a live credential into a column, and it runs before the format test so a
    rejected one is never quoted back.
    """
    shape = looks_like_secret(idempotency_key)
    if shape is not None:
        raise IdempotencyError(
            f"the idempotency key looks like {shape}. Keys are stored verbatim, so one must be an "
            "identifier chosen for this request and nothing else. The value is deliberately not "
            "repeated here."
        )
    if not isinstance(idempotency_key, str) or not re.fullmatch(IDEMPOTENCY_KEY_REGEX, idempotency_key):
        raise IdempotencyError(
            "the idempotency key is not acceptable. Keys are 8 to 200 characters of letters, "
            "digits and '._:@=+-'; they are stored verbatim, so they are identifiers and not a "
            "place to put anything else. Matched with fullmatch, so a trailing newline is refused "
            "rather than passed through by '$'. The value is deliberately not repeated."
        )


def _require_clean_session(session: Session) -> None:
    """Refuse *pending* ORM state at entry.

    ``Session.begin_nested()`` **flushes** whatever is pending before it emits the
    ``SAVEPOINT``, so a row the caller added and did not flush would be written *outside*
    the boundary this primitive rolls back to -- and would survive a lost race that
    discards everything else. Rejecting is the honest fix: the alternative is a primitive
    whose rollback guarantee quietly depends on what the caller happened to leave behind.

    **This covers pending state only, and cannot cover more.** A write the caller already
    flushed is no longer in ``session.new``/``dirty``/``deleted``, so nothing here can see
    it; it sits in the caller's outer transaction, outside this SAVEPOINT, and a lost race
    that rolls the mutation back leaves it in place. The rule that closes that is a
    contract rather than a check: every business write belonging to the operation goes
    inside ``mutate``, and the primitive is called before any DML for that operation.
    """
    pending = {
        "new": tuple(session.new),
        "dirty": tuple(session.dirty),
        "deleted": tuple(session.deleted),
    }
    outstanding = {kind: rows for kind, rows in pending.items() if rows}
    if outstanding:
        summary = "; ".join(f"{len(rows)} {kind}" for kind, rows in outstanding.items())
        raise MutationContractError(
            f"the session has unflushed ORM state at entry ({summary}). begin_nested() flushes "
            "pending state before it opens the SAVEPOINT, so those rows would be written outside "
            "the boundary this primitive rolls back to and would survive a lost race. Flush and "
            "commit them first, or perform them inside the mutation."
        )


def _require_read_committed(session: Session) -> None:
    level = session.execute(text("SELECT current_setting('transaction_isolation')")).scalar()
    if (level or "").lower() != REQUIRED_ISOLATION_LEVEL:
        raise IsolationLevelError(
            f"this transaction is {level!r}, and an idempotent mutation requires "
            f"{REQUIRED_ISOLATION_LEVEL!r}. Recovering from a lost race means re-reading the row the "
            "winner just committed, and only READ COMMITTED takes a fresh snapshot per statement; "
            "under a stricter level that read would return nothing and the caller would be told the "
            "key is free when it is not."
        )


def _tenant_context(session: Session) -> uuid.UUID:
    """The tenant this transaction authenticated as, and the capability to use it.

    Milestone 2.3 changed where this comes from and not what it means. It used to read a
    setting the caller had set; it now reads the authenticated context, so a caller that
    has not presented a credential is refused here and would be refused by the policies
    anyway.

    ``mutation:execute`` is checked in Python as well as by the policies because a missing
    capability should name itself. It is the minimal framework capability: it permits
    claiming a key and appending the event that goes with it, and says nothing about any
    customer resource.
    """
    try:
        context = require_authenticated_context(session)
    except Exception as exc:
        raise TenantContextError(
            "an authenticated context is required: outbox events and idempotency keys are "
            "tenant-scoped, and without one the row-level security policies would reject the write "
            f"anyway. Use authenticated_transaction(). ({exc})"
        ) from None
    context.require_scope(Scope.MUTATION_EXECUTE)
    return context.tenant_id


@contextmanager
def _refuse_commits_during(session: Session):
    """Refuse any commit reached from inside the mutation, **before** it can happen.

    The unit of work has no ``commit``, but the real ``Session`` is one
    ``object_session(some_mapped_row)`` away, and ``Session.commit()`` commits the
    *outermost* transaction even from inside an open SAVEPOINT. Detecting that afterwards
    is worthless: by then the business row is committed without its claim or its event,
    which is the partial state this whole module exists to make impossible, and a later
    retry collides with a surviving row that no claim explains.

    So the refusal happens *before* the commit. ``before_commit`` is dispatched at the top
    of ``SessionTransaction._prepare_impl``, ahead of the flush that a commit performs, so
    raising here means nothing is flushed and nothing is committed.

    The listener is attached to this one ``Session`` for exactly the duration of the
    callback and removed in a ``finally``. That matters twice over: the primitive releases
    its own SAVEPOINT with ``nested.commit()``, which dispatches ``before_commit`` because
    the transaction is nested, and the caller then commits the real transaction. Both are
    legitimate and both happen after the guard is gone. Nothing is left attached to a
    session that outlives this call.
    """

    def refuse(_session) -> None:
        raise MutationContractError(
            "a mutation may not commit: it reached the underlying Session -- through "
            "object_session() or another route the unit of work does not cover -- and called "
            "commit(). Session.commit() commits the OUTERMOST transaction even from inside the "
            "primitive's SAVEPOINT, which would leave the business change committed without its "
            "idempotency claim or its outbox event, and a later retry colliding with a row that "
            "no claim explains. A mutation performs rollback-safe transactional DML through the "
            "unit of work and nothing else; the caller owns the commit."
        )

    event.listen(session, "before_commit", refuse)
    try:
        yield
    finally:
        event.remove(session, "before_commit", refuse)


def _require_intact_boundary(session: Session, *, outer, nested) -> None:
    """Secondary defense: the transaction and the SAVEPOINT are still the ones we opened.

    The pre-commit guard above is what *prevents* the known escape. This catches what is
    left -- a rollback reached through the real ``Session``, or any other destruction of
    the boundary -- and it is a **detection**, not a preservation of atomicity: for a
    rollback there is nothing to preserve, since the rollback already discarded the work.

    It deliberately does not claim to turn a commit into a non-commit. Nothing in Python
    can un-commit, which is precisely why the guard runs before the commit rather than
    after it.
    """
    problems = []
    if not session.in_transaction():
        problems.append("the transaction is no longer open")
    elif session.get_transaction() is not outer:
        problems.append("the outer transaction was replaced")
    if session.get_nested_transaction() is not nested or not nested.is_active:
        problems.append("the SAVEPOINT this mutation ran inside is gone")
    if problems:
        raise MutationContractError(
            "the mutation left the primitive's transaction boundary: "
            + "; and ".join(problems)
            + ". A mutation performs rollback-safe transactional DML and nothing else; it must not "
            "commit, roll back, or open transactions of its own."
        )


# ------------------------------------------------------------------------ the outbox


def append_outbox_event(
    session: Session,
    event: OutboxEventSpec,
    *,
    idempotency_record_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Append one outbox event inside the caller's open transaction. Returns its id.

    The outbox belongs to **every** authoritative state transition, not only to API
    mutations: the controller, the reconciler, the validator and the lifecycle machines of
    later milestones all need to commit an event with the state change that caused it, and
    none of them has an API idempotency key. So ``idempotency_record_id`` is an optional
    causation link. When it is supplied the composite foreign key holds the event and the
    claim in the same tenant, and the unique constraint allows at most one linked event per
    claim; when it is ``NULL`` the foreign key does not apply (a ``MATCH SIMPLE`` composite
    reference is satisfied when any column is NULL) and the unique constraint does not
    collide, because PostgreSQL treats NULLs as distinct.

    This does not commit. It is the caller's transaction that makes the event durable,
    together with the state change it describes or not at all.
    """
    _require_open_transaction(session, "append_outbox_event")
    _require_valid_name(
        event.event_type, pattern=DOTTED_NAME_REGEX, what="outbox event type", example="workspace.created"
    )
    _require_valid_name(
        event.aggregate_type, pattern=SIMPLE_NAME_REGEX, what="outbox aggregate type", example="workspace"
    )
    tenant_id = _tenant_context(session)
    attributes = validated_metadata(event.attributes, where="the outbox event's attributes")

    row = OutboxEvent(
        tenant_id=tenant_id,
        idempotency_record_id=idempotency_record_id,
        event_type=event.event_type,
        aggregate_type=event.aggregate_type,
        aggregate_id=event.aggregate_id,
        attributes=attributes,
    )
    session.add(row)
    session.flush()
    return row.id


def outbox_events(session: Session, *, limit: int = 100) -> Sequence[OutboxEvent]:
    """This tenant's events, oldest first. The read a dispatcher would make.

    No dispatcher exists -- Milestone 6 owns delivery -- but the ordering a later one
    needs is a property of the schema, so it is stated here rather than rediscovered.
    """
    return list(
        session.scalars(
            select(OutboxEvent).order_by(OutboxEvent.occurred_at, OutboxEvent.id).limit(limit)
        )
    )


# ------------------------------------------------------------------------- the primitive


def _claim_conflict(exc: IntegrityError) -> bool:
    """True only for a unique violation on the idempotency claim index."""
    original = getattr(exc, "orig", None)
    constraint = getattr(getattr(original, "diag", None), "constraint_name", None)
    if constraint is not None:
        return constraint == CLAIM_CONSTRAINT
    # No structured diagnostics (a non-psycopg driver, or a wrapped error). Fall back to
    # the constraint name in the message, which PostgreSQL always includes.
    return CLAIM_CONSTRAINT in str(exc)


def _load_record(session: Session, *, operation: str, idempotency_key: str) -> IdempotencyRecord | None:
    """The claim for this key, if this tenant has one.

    No ``WHERE tenant_id = ...``: row-level security is the filter, and a reader can
    check that claim by noticing there is no filter here to get wrong.
    """
    return session.scalars(
        select(IdempotencyRecord).where(
            IdempotencyRecord.operation == operation,
            IdempotencyRecord.idempotency_key == idempotency_key,
        )
    ).one_or_none()


def _event_id_for(session: Session, record_id: uuid.UUID) -> uuid.UUID:
    """The one event linked to this claim.

    ``.one()`` on purpose: the unique constraint bounds this at one, and the primitive
    always writes one, so zero here would mean a claim committed without its event -- the
    exact failure the atomicity tests exist to rule out.
    """
    return session.scalars(
        select(OutboxEvent.id).where(OutboxEvent.idempotency_record_id == record_id)
    ).one()


def _replay(
    session: Session, record: IdempotencyRecord, *, fingerprint: str, operation: str, idempotency_key: str
) -> IdempotentResult:
    if record.request_fingerprint != fingerprint:
        raise IdempotencyConflict(
            f"idempotency key {idempotency_key!r} was already used for operation {operation!r} with a "
            "different request. Reusing a key for a changed request is a caller bug -- retry the "
            "original request with this key, or use a new key for the new one."
        )
    return IdempotentResult(
        record_id=record.id,
        event_id=_event_id_for(session, record.id),
        result=dict(record.result),
        replayed=True,
    )


def execute_idempotent_mutation(
    session: Session,
    *,
    operation: str,
    idempotency_key: str,
    request_identity: Mapping[str, Any],
    mutate: Mutation,
) -> IdempotentResult:
    """Commit ``mutate``'s effect at most once per ``(tenant, operation, key)``.

    Runs entirely inside ``session``'s existing transaction and commits nothing itself:
    the caller's ``authenticated_transaction`` block is what makes the state change, the claim
    and the event durable, together or not at all.

    ``mutate`` is called with a :class:`MutationUnitOfWork`, not with ``session``. See the
    module docstring for the contract it has to keep.

    Raises :class:`IdempotencyConflict` if the key was claimed for a different request,
    :class:`MetadataPolicyError` if the identity, result or event is not bounded metadata,
    :class:`MutationContractError` if the session is not clean at entry or the mutation
    leaves the transaction boundary, and
    :class:`~firmbatch.control_plane.db.engine.TenantContextError` with no tenant context.
    """
    # Everything a caller supplies is checked before the mutation runs, so a malformed
    # operation, key or identity cannot produce a business change that the claim then
    # fails to record.
    _require_open_transaction(session, "execute_idempotent_mutation")
    _require_valid_name(operation, pattern=DOTTED_NAME_REGEX, what="operation", example="workspace.create")
    _require_valid_key(idempotency_key)
    _require_clean_session(session)
    identity = validated_metadata(request_identity, where="the request identity")

    _require_read_committed(session)
    tenant_id = _tenant_context(session)
    fingerprint = request_fingerprint(tenant_id=tenant_id, operation=operation, request_identity=identity)

    existing = _load_record(session, operation=operation, idempotency_key=idempotency_key)
    if existing is not None:
        return _replay(
            session, existing, fingerprint=fingerprint, operation=operation, idempotency_key=idempotency_key
        )

    # Everything below is one savepoint, so that losing the race to another claim of this
    # key rolls back this caller's mutation as well as its own insert. Without that, the
    # loser's business row would survive its failed claim and there would be two effects.
    outer = session.get_transaction()
    nested = session.begin_nested()
    try:
        # The guard is scoped to the callback and nothing else: the primitive's own
        # nested.commit() below releases the SAVEPOINT, and the caller's commit follows,
        # and both dispatch before_commit. Neither may be refused.
        with _refuse_commits_during(session):
            outcome = mutate(MutationUnitOfWork(session))
        _require_intact_boundary(session, outer=outer, nested=nested)
        if not isinstance(outcome, MutationOutcome):
            raise IdempotencyError(
                f"the mutation returned {type(outcome).__name__}; it must return a MutationOutcome "
                "carrying the replayable result and the outbox event to commit with it."
            )
        result = validated_metadata(outcome.result, where="the mutation result")
        session.flush()

        record = IdempotencyRecord(
            tenant_id=tenant_id,
            operation=operation,
            idempotency_key=idempotency_key,
            request_fingerprint=fingerprint,
            status=IDEMPOTENCY_STATUS_COMPLETED,
            result=result,
        )
        session.add(record)
        session.flush()

        event_id = append_outbox_event(session, outcome.event, idempotency_record_id=record.id)

        # Read out before the savepoint is released: releasing empties the identity map
        # (see db/engine.py), which detaches these instances.
        claimed = IdempotentResult(record_id=record.id, event_id=event_id, result=result, replayed=False)
        nested.commit()
        return claimed
    except IntegrityError as exc:
        nested.rollback()
        # The question is not which index raised, it is whether this key is now taken.
        # A losing racer blocks on whichever unique index it reaches first -- the claim
        # index, or one belonging to its own mutation, since a duplicate request usually
        # violates a business constraint before it ever gets to the claim. Both mean the
        # same thing: somebody else committed this operation, and our savepoint rollback
        # has already taken our attempt at it back out.
        winner = _load_record(session, operation=operation, idempotency_key=idempotency_key)
        if winner is None:
            if _claim_conflict(exc):  # pragma: no cover - _require_read_committed precedes it
                raise IdempotencyError(
                    f"claim of {idempotency_key!r} for {operation!r} conflicted with a row that is "
                    "not there on re-read. That is only possible outside READ COMMITTED."
                ) from exc
            # The key is still free, so this was the caller's own constraint. Theirs.
            raise
        return _replay(
            session, winner, fingerprint=fingerprint, operation=operation, idempotency_key=idempotency_key
        )
    except BaseException:
        # Anything else -- the mutation raised, the metadata was refused, the boundary was
        # broken -- leaves nothing behind. The savepoint rollback is not strictly required,
        # since the caller's transaction is about to roll back too, but it keeps the
        # session usable for a caller that wants to handle the error and carry on.
        if nested.is_active:
            nested.rollback()
        raise
