"""The audit trail: who did what, for which tenant, when, and under what request.

One typed primitive, :func:`append_audit_event`, and one read, :func:`audit_events`. Both
run inside the caller's transaction and neither commits: an audit record that survived a
rolled-back action would be a record of something that did not happen, and one that was
lost when the action committed would be worse.

What an audit event answers
---------------------------

* **Who acted** -- ``actor_kind``, ``actor_principal_id`` and ``actor_binding_id``, taken
  from the authenticated context by column default and re-checked by the insert policy.
  The caller cannot supply any of them, and a caller that names one anyway is refused
  rather than silently corrected.
* **For which tenant** -- ``tenant_id``, from the same place, for the same reason.
* **What was attempted or completed** -- ``action`` and ``outcome``. ``attempted`` and
  ``denied`` are first-class outcomes: a trail that records only successes cannot answer
  the question it exists for.
* **Against what** -- ``resource_type`` and an optional ``resource_id``, optional because
  a refused creation has no resource yet.
* **When** -- ``occurred_at``, written by a ``BEFORE INSERT`` trigger from
  ``clock_timestamp()``, which overwrites whatever arrives. So there is no value a caller
  can supply and none it can preserve.

  ``clock_timestamp()`` and not ``now()``, which is transaction-*start* time: a caller that
  opened its transaction an hour before inserting could otherwise date the event an hour
  into the past **without supplying anything at all**, which no policy comparing against
  ``now()`` would notice, because it would be comparing the backdated value against the
  same backdated clock.
* **Under which request** -- ``correlation_id``, which is the one caller-supplied field
  here. Correlation is the caller's fact about its own request; it carries no authority
  and nothing is decided from it.

Distinct from the outbox, and worth keeping distinct
----------------------------------------------------

An **outbox event** is intent to tell somebody that state changed: addressed outward, read
one day by a dispatcher, its content chosen by the state machine that emitted it. An
**audit event** is a record of who did what: addressed inward, dispatched to nobody, its
actor and tenant not chosen by anyone. Neither is derivable from the other -- an action
that changes no state still belongs in the trail, and an internal transition with no actor
still belongs in the outbox -- so they are two tables and two primitives.

One way in
----------

**No runtime role holds ``INSERT`` on ``firmbatch.audit_events``.** Appending goes through
``firmbatch.append_audit_event()``, a hardened ``SECURITY DEFINER`` function, and this
module calls it rather than composing an ``INSERT``.

That is the correction that makes the metadata policy below a property rather than a
courtesy. While the application role held ``INSERT``, this module was a boundary a caller
could walk around by writing the statement itself -- and the table's check constraints
bound a details document's *size and shape* and said nothing whatever about its content, so
a bearer credential under an innocuous key was refused here and accepted by PostgreSQL. The
function applies every rule again, inside the database, against the values it is about to
write.

The function has **no parameter** for the tenant, the actor kind, the principal, the
binding or the timestamp, so there is nothing derived for a caller to supply correctly or
incorrectly. The insert policy still evaluates -- row security is ``FORCE``d and a definer
function runs as the owner, whom ``FORCE`` binds too -- so the derivation is checked twice.

Immutability
------------

Append-only three times over now: no runtime role holds ``INSERT``, ``UPDATE`` or
``DELETE``, and the table carries no ``UPDATE`` or ``DELETE`` policy at all, so those
commands reach no row even for the owner under ``FORCE``.

There is deliberately **no hash chain and no external audit delivery**. The canonical
architecture asks for audit events; a tamper-evident log and an audit shipper are neither
required by it nor buildable honestly at this milestone, and inventing either here would
be machinery ahead of a requirement. What makes these rows trustworthy today is narrower
and checkable: nobody can change one, and nobody can write one about another tenant or
another actor.

What may go in ``details``
--------------------------

The same bounded-metadata policy as every other ``jsonb`` column in this schema
(``db/metadata.py``): identifiers, counts, digests, and references. Payload- and
credential-shaped material is refused **before** the row is written, including values that
carry a recognisable secret shape -- and the refusal names the shape rather than the
value, so that catching a secret in the audit trail does not put it in the exception text
instead.

Applied twice, by two implementations of one rule: here, so a caller gets a usable error at
the boundary, and in ``firmbatch.audit_require_acceptable_details``, so the rule holds when
the caller writes the SQL. Two implementations is the arrangement that drifts, so
``tests/test_audit_events.py`` walks a shared corpus of accepted and rejected documents
through both and requires them to agree on every one.

Like everything else here, that is defense in depth and not a proof. No rule can establish
that a string is not content.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from ..security.secrets import looks_like_secret
from .auth import require_authenticated_context
from .base import SCHEMA
from .metadata import canonical_json, validated_metadata
from .models import AUDIT_OUTCOMES, DOTTED_NAME_REGEX, SIMPLE_NAME_REGEX, AuditEvent

#: The outcome to record when a caller does not say. ``succeeded`` rather than
#: ``attempted``: the ordinary call site appends after the work is done, and a default
#: that quietly recorded every completed action as merely attempted would make the
#: distinction useless.
DEFAULT_OUTCOME = "succeeded"

#: The one statement that writes an audit row. Not an ``INSERT``: no runtime role holds
#: ``INSERT`` on ``firmbatch.audit_events``, so this hardened ``SECURITY DEFINER`` function
#: is the only path in, and every rule ``db/metadata.py`` applies at the boundary is
#: applied again inside it against the values about to be written.
_APPEND_STATEMENT = text(
    f"SELECT {SCHEMA}.append_audit_event("
    ":action, :outcome, :resource_type, CAST(:resource_id AS uuid), "
    "CAST(:correlation_id AS uuid), CAST(:details AS jsonb))"
)

#: SQLSTATEs the append function raises, matched on the code because a message is prose.
_INSUFFICIENT_PRIVILEGE = "42501"
_INVALID_PARAMETER_VALUE = "22023"


class AuditError(RuntimeError):
    """An audit event could not be recorded as described."""


def _translate(error: DBAPIError) -> Exception:
    """The database's refusal, as the Python error that means the same thing.

    Only the server's own primary message travels, and only for the two SQLSTATEs this
    module raises deliberately -- those messages are written in migration ``0003`` and
    name the rule and the position, never the value. Anything unanticipated becomes a
    message with **no** database text at all: an unexpected error can render the failing
    row, and the failing row here is the caller's metadata document.
    """
    orig = getattr(error, "orig", None)
    state = getattr(orig, "sqlstate", None)
    if state in (_INVALID_PARAMETER_VALUE, _INSUFFICIENT_PRIVILEGE):
        return AuditError(str(orig).strip() or "the audit event was refused")
    return AuditError(
        "the audit event could not be written, and the database's explanation is deliberately "
        f"not repeated here: the failing statement carries the caller's details document as a "
        f"parameter. SQLSTATE {state!r}."
    )


@dataclass(frozen=True)
class AuditEventSpec:
    """What a caller may say about an action. Everything else is derived.

    There is no tenant, no principal, no binding and no timestamp here, and that absence
    is the design: those are facts about *who is acting and when*, and a caller that could
    state them could state them wrongly.
    """

    #: Dotted lowercase -- ``workspace.create``, ``auth.binding_registered``.
    action: str
    #: Undotted lowercase -- ``workspace``, ``binding``.
    resource_type: str
    outcome: str = DEFAULT_OUTCOME
    resource_id: uuid.UUID | None = None
    correlation_id: uuid.UUID | None = None
    details: Mapping[str, Any] = field(default_factory=dict)


def _require_name(value: Any, *, pattern: str, what: str, example: str) -> None:
    """Validate one caller-supplied name without repeating it back.

    Shape first, then format, and neither echoes. An action or a resource type is
    caller-supplied text like any other, so a credential pasted into one would otherwise be
    quoted by the check that refused it -- into an exception, a traceback, and a retained
    log.
    """
    shape = looks_like_secret(value)
    if shape is not None:
        raise AuditError(
            f"the audit {what} looks like {shape}. An action names what was done; it is not a "
            "place for a secret, and the value is deliberately not repeated here."
        )
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise AuditError(
            f"the audit {what} is not acceptable; it must match {pattern} (for example "
            f"{example!r}). Checked here so that a malformed name is refused before the row rather "
            "than by a check constraint after it. The value is deliberately not repeated."
        )


def _require_outcome(value: Any) -> None:
    """Validate the outcome without repeating it back.

    Shape first, then membership, and neither echoes. An outcome is caller-supplied text
    like an action name: the closed set is what makes the trail searchable, and quoting a
    rejected value into the exception is how a credential pasted into the wrong argument
    reaches a traceback.
    """
    shape = looks_like_secret(value)
    if shape is not None:
        raise AuditError(
            f"the audit outcome looks like {shape}. An outcome is one of four fixed words; the "
            "value is deliberately not repeated here."
        )
    if value not in AUDIT_OUTCOMES:
        raise AuditError(
            f"the audit outcome is not one of {list(AUDIT_OUTCOMES)}. The set is closed: an outcome "
            "nobody can enumerate is an outcome nobody can search for. The rejected value is "
            "deliberately not repeated."
        )


def _require_optional_uuid(value: Any, *, what: str) -> uuid.UUID | None:
    if value is None or isinstance(value, uuid.UUID):
        return value
    raise AuditError(f"an audit {what} is a UUID or None; got {type(value).__name__}")


def append_audit_event(session: Session, event: AuditEventSpec) -> uuid.UUID:
    """Append one audit event inside the caller's open transaction. Returns its id.

    Commits nothing. The event becomes durable with the action it describes, or not at
    all: an audit row that outlived a rolled-back action would assert something false.

    Requires an authenticated context and **no scope beyond one**. That is deliberate and
    it has a cost worth naming: a credential with no scopes at all can append audit rows
    in its own tenant. The alternative -- an ``audit:append`` capability -- is a credential
    that can act without leaving a trail, which is the one outcome an audit trail exists
    to prevent. Reading the trail is the privileged half, and that is ``audit:read``.

    The insert carries no ``RETURNING`` clause, which is why the id is generated here.
    PostgreSQL applies ``SELECT`` policies to ``INSERT ... RETURNING``, so an ORM insert
    would require ``audit:read`` to append -- reintroducing exactly the coupling the
    paragraph above rejects. What the identifier has to be is *immutable*, and append-only
    is what makes it so.

    ``occurred_at`` is not passed and could not usefully be: the ``BEFORE INSERT`` trigger
    overwrites it with ``clock_timestamp()`` on every row.
    """
    if not session.in_transaction():
        raise AuditError(
            "append_audit_event requires an open transaction: an audit record means nothing unless "
            "it commits with the action it describes."
        )

    _require_name(
        event.action, pattern=DOTTED_NAME_REGEX, what="action", example="workspace.create"
    )
    _require_name(
        event.resource_type, pattern=SIMPLE_NAME_REGEX, what="resource type", example="workspace"
    )
    _require_outcome(event.outcome)
    resource_id = _require_optional_uuid(event.resource_id, what="resource id")
    correlation_id = _require_optional_uuid(event.correlation_id, what="correlation id")
    details = validated_metadata(event.details, where="the audit event's details")

    # Refused here rather than by the policy, so the caller is told which capability is
    # missing -- and so an unauthenticated caller does not get a check-constraint
    # violation on a NULL tenant instead of an explanation.
    require_authenticated_context(session)

    # tenant_id, actor_kind, actor_principal_id, actor_binding_id and occurred_at are not
    # arguments of the function below, so there is no value this module could supply for
    # any of them and nothing for the database to have to reconcile. The id comes back as
    # the function's result rather than through RETURNING, because PostgreSQL applies
    # SELECT policies to INSERT ... RETURNING and appending must not require audit:read.
    failure: Exception | None = None
    try:
        return session.execute(
            _APPEND_STATEMENT,
            {
                "action": event.action,
                "outcome": event.outcome,
                "resource_type": event.resource_type,
                "resource_id": resource_id,
                "correlation_id": correlation_id,
                "details": canonical_json(details),
            },
        ).scalar_one()
    except DBAPIError as error:
        failure = _translate(error)
    # Outside the handler, so nothing is attached as ``__cause__`` or ``__context__``. The
    # statement above carries the caller's details as a bound parameter and a ``DBAPIError``
    # renders its parameters, so letting the psycopg exception travel with this one would
    # re-attach exactly the document the refusal exists to keep out of a log.
    raise failure from None


def audit_events(session: Session, *, limit: int = 100) -> Sequence[AuditEvent]:
    """This tenant's audit trail, oldest first. Requires ``audit:read``.

    No ``WHERE tenant_id = ...``: row-level security is the filter, and a reader can check
    that claim by noticing there is no filter here to get wrong. A context without
    ``audit:read`` sees an empty trail rather than an error, because that is what a policy
    does -- :func:`~firmbatch.control_plane.security.authorization.require_scope` is what
    a caller uses when it wants the missing capability named.
    """
    return list(
        session.scalars(
            select(AuditEvent).order_by(AuditEvent.occurred_at, AuditEvent.id).limit(limit)
        )
    )
