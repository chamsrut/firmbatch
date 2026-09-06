"""The lifecycle kernel: versioned machines, persisted instances, race-safe transitions.

Milestone 2.4, and the last declared slice of Milestone 2. It answers one question and
deliberately no others: **where has this thing got to, and how did it get there** -- for a
thing whose legal moves were decided in advance, by us, and written down as data.

Three parts, and the boundary between them is the design:

* a **definition** -- one immutable ``(machine_key, version)`` with its states, its edges
  and the scope its instances require. Registered by the schema owner, never by the
  runtime. See :func:`register_lifecycle_definition`.
* an **instance** -- one tenant-owned row saying which machine version it is running,
  which state it is in, and at which revision. Created by
  :func:`create_lifecycle_instance`.
* a **transition** -- one conditional move, recorded once. :func:`transition_lifecycle_instance`.

What this is not
----------------

Not a workflow engine, and not on its way to becoming one. There is no customer-editable
graph, no expression language, no scripting hook, no timers, no compensation, no retry
policy and no scheduler. A machine is data we author in a migration; the runtime may move
an instance along an edge that already exists and may do nothing else with it. A general
workflow product would have to answer "what may a customer's graph do?", and every honest
answer to that is a sandbox.

It also carries **no domain**. There is no job here, no window offer, no attempt, no lease:
those tables are Milestones 5 and 6, and they will point at an instance of the machine that
describes them. The target architecture's job lifecycle (section 5.1) and window-offer
machine (section 12.1) are the two definitions those milestones will register; this
milestone registers **none**, because a graph seeded ahead of the rows it describes is a
product decision taken by a foundation.

The transition, precisely
-------------------------

``firmbatch.transition_lifecycle_instance()`` performs, in the caller's transaction:

1. requires ``mutation:execute``, because the move commits durable framework records;
2. resolves the instance **inside the authenticated tenant** -- so another tenant's
   instance is simply not there;
3. derives the required capability from the machine version the instance pinned, which is
   protected data the caller cannot write and does not name;
4. compares **both** the expected state and the expected revision to the persisted row, and
   only then asks the graph whether the target is a declared edge and the source is not
   terminal;
5. performs **one conditional ``UPDATE``** whose predicate carries the tenant, the
   instance, the machine version, the expected state and the expected revision, and
   increments the revision by one;
6. appends exactly one row of transition history, with the actor taken from the
   authenticated context;
7. appends exactly one audit event, from the same context, **tagged** with the machine so
   that reading it needs that machine's read scope and not only ``audit:read``;
8. writes the idempotency claim, if one was asked for, under an operation name and a
   request fingerprint it **derived**;
9. appends exactly one outbox intent, linked to that claim when there is one;
10. writes the protected provenance row that ties the claim to this transition, this
    instance, these revisions and that event.

A zero-row update is a :class:`LifecycleConflict`, and it is the **same** conflict whether
the instance was stale, was never there, or belongs to somebody else. That identity is
deliberate: a refusal that distinguished them would answer "does this id exist in another
tenant", which is the question tenant isolation exists to refuse. Step 4 is part of it: a
caller whose revision is stale never gets a *graph* diagnosis, so the refusal says nothing
about a row it did not correctly describe.

There is no read-then-write. Steps 2 to 4 are diagnosis -- they decide which error a caller
gets and nothing about whether the write happens. Step 5's predicate decides that, against
the row as it is at the instant of the write.

And underneath all of it, a ``BEFORE UPDATE`` trigger requires that ``(old, new)`` be a
declared edge, that the source not be terminal, and that the revision advance by exactly
one -- for **every** writer, including the schema owner. The function's own edge check is
a courtesy that gives the caller a good error; the trigger is the property.

Every artifact, or none
-----------------------

**All ten of those happen inside one database call, and that is the point.** While the
outbox intent was appended in Python after the call returned, an application role executing
arbitrary SQL could invoke the function and simply not append one -- a committed state
change, history row and audit event with nothing announcing the change. Neither of the two
Python entry points appends anything now: there is no caller and no ordering that produces
a subset.

The two supported shapes differ only in whether a claim is written:

* :func:`transition_lifecycle_instance` -- the internal transition. One **unlinked** event,
  which is the case ADR 0005 built the optional causation link for: a controller, a
  reconciler or a validator committing an event with the state change that caused it.
* :func:`execute_idempotent_lifecycle_transition` -- the API transition. The same call, told
  one idempotency key, so the claim, one **linked** event and the provenance that ties them
  are written by it. An outbox row is append-only, so it could not be linked afterwards; and
  a claim's result is not known until the move has happened. That ordering is why this path
  does not go through ``execute_idempotent_mutation``, which writes its claim *after* the
  mutation it wraps.

A caller supplies no claim identifier, no operation name, no request fingerprint and no
event content. The claim is created by the database, in the authenticated tenant, under an
operation derived from the machine the instance pins, with a fingerprint derived from the
arguments that ran and a result computed from what they did.

Reading a lifecycle's framework records
---------------------------------------

``mutation:execute`` is the capability to claim a key and append an event, and ``audit:read``
is the capability to read the trail. Neither was ever permission to read what somebody else's
lifecycle did -- and a claim's ``result``, an event's ``attributes`` and an audit row's
``resource_id`` and ``details`` all carry the instance, the states and the revisions.

So all three framework rows are **tagged** with the machine they belong to, by the database,
and reading a tagged row additionally requires that machine's declared read scope. Row-level
security enforces it, so it holds for a caller composing its own ``SELECT``. Untagged rows --
every generic Milestone 2.2 mutation and every non-lifecycle audit action -- are unaffected.

The ``lifecycle.`` operation and action namespaces are **reserved** in the same movement: a
check constraint ties the prefix to the tag, and only the lifecycle writer may write the tag.
So the generic primitive cannot create a claim that collides with a lifecycle one, cannot use
the claim index to ask whether a lifecycle key is taken, and cannot write an untagged audit
row that looks like a lifecycle one.

Who the lifecycle writer is
---------------------------

A dedicated ``NOLOGIN`` role, created by the wiring layer, that owns the two
``SECURITY DEFINER`` entry points and nothing else -- so the entry points *execute as it*,
and every lifecycle-derived guard (the machine tags, ``lifecycle_claim_provenance``, the
linking of an outbox event to a lifecycle claim) requires ``current_user`` to be it. The
schema owner is refused along with everybody else: its direct DML and any definer function
it owns run as the schema owner, not as the writer. ``firmbatch.lifecycle_writer_role()``
reads which role that is from the catalogue -- the owner of both entry points, provided it
is not the schema owner and cannot log in -- and answers NULL until the wiring has run, so
the guards fail closed on an unwired database. Nobody can ``SET ROLE`` to it, and
``db/roles.py`` gives it the minimum the two bodies need. See ADR 0007 decision 8h.

A replay, and what it rests on
------------------------------

A replay hands back what a claim recorded, so the question "may this row be replayed as a
lifecycle transition?" must not be answered by the row itself. The machine tag does not
answer it: it says which machine a row belongs to, not which move it records.

``firmbatch.lifecycle_claim_provenance`` is the answer -- a protected relation, written only
by the transition function executing as the lifecycle writer, immutable afterwards for
everybody including the owner, whose every column is a composite foreign key into a row that
transition wrote. A replay resolves
the whole chain (claim, provenance, transition, instance, event), insists that every link
agrees with every other, and insists that the stored result describes the transition the
provenance names. A claim without that chain is **refused**, never replayed.

What this does not claim
------------------------

**Not exactly-once external delivery.** Unchanged from Milestone 2.2: the outbox records
durable intent, no dispatcher exists, and when one does it will deliver at least once.

**Not protection from the schema owner's DDL.** The definition triggers, the derived-tag
and provenance guards, the outbox-link guard and the row policies bind ordinary DML
including the owner's -- since the third correction pass the owner's DML and its own definer
functions are refused every lifecycle-derived write, because the guards ask for the
lifecycle writer and the owner is not it. They do not bind a superuser, and they do not
bind an owner who first disables a trigger, redefines a guard, or sets
``session_replication_role``. Those are deliberate, DDL-shaped acts by a role this design
already trusts with the definitions themselves; see ADR 0006 on the migration owner.

**Not retention.** Nothing here deletes an instance or a history row, and no policy would
let it: both tables carry no ``DELETE`` policy at all. Retention is a decision no milestone
has taken.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from sqlalchemy import Connection, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from ..security.authorization import (
    LIFECYCLE_ELIGIBLE_SCOPES,
    AuthorizationError,
    Scope,
)
from ..security.secrets import looks_like_secret
from .auth import require_authenticated_context
from .base import SCHEMA

# The Milestone 2.2 machinery this module composes with. The *table*, the unique index, the
# fingerprint, the record type and the conflict semantics are all M2.2's; what is not reused
# is ``execute_idempotent_mutation``'s control flow, and ``execute_idempotent_lifecycle_transition``
# says at length why. The private names are imported deliberately rather than re-spelled:
# two copies of "what is a valid idempotency key" is how one of them stops being right.
from .idempotency import (
    IdempotencyConflict,
    IdempotentResult,
    _require_clean_session,
    _require_read_committed,
    _require_valid_key,
)
from .metadata import canonical_json, validated_metadata
from .models import (
    LIFECYCLE_NAME_REGEX,
    MAX_LIFECYCLE_REASON_LENGTH,
    MAX_LIFECYCLE_STATES,
    MAX_LIFECYCLE_TRANSITIONS,
    LifecycleInstance,
    LifecycleTransition,
)

#: The SQLSTATEs migration ``0004`` raises, mirrored here because this module translates
#: them. Matched on the code rather than on the message: a message is prose and can be
#: improved, a SQLSTATE is a contract.
#:
#: A user-defined class rather than a borrowed standard one, and the borrowing is what that
#: avoids. ``23514`` (check violation) would arrive as an ``IntegrityError``, which
#: ``db/idempotency.py`` catches and re-reads as a possibly-lost idempotency race;
#: ``40001`` (serialization failure) is the code every retry helper in every framework
#: retries automatically, and a lifecycle conflict is precisely the thing that must not be
#: retried without re-reading the instance first.
LIFECYCLE_CONFLICT_SQLSTATE = "FB001"
LIFECYCLE_NOT_ALLOWED_SQLSTATE = "FB002"
LIFECYCLE_DEFINITION_SQLSTATE = "FB003"
#: The key was claimed for a different request. Translated to the Milestone 2.2
#: :class:`~firmbatch.control_plane.db.idempotency.IdempotencyConflict`, because it is the
#: same outcome and a caller should not have to learn a second name for it.
LIFECYCLE_KEY_REUSE_SQLSTATE = "FB004"
#: A claim in the reserved lifecycle namespace with no verifiable transition behind it.
LIFECYCLE_PROVENANCE_SQLSTATE = "FB005"

_INSUFFICIENT_PRIVILEGE = "42501"
_INVALID_PARAMETER_VALUE = "22023"

#: The operation namespace lifecycle claims live in, mirrored from migration ``0004``.
#:
#: A caller never supplies an operation name. The database derives
#: ``lifecycle.transition.<machine_key>.v<version>`` from the machine the *instance* pins,
#: and a check constraint plus the derived-tag trigger make the whole ``lifecycle.``
#: namespace unwritable by the generic Milestone 2.2 primitive -- so a generic claim can
#: neither collide with a lifecycle claim nor use the unique index to ask whether one
#: exists. Named here so a test and a reader can find it.
LIFECYCLE_NAMESPACE_PREFIX = "lifecycle."
LIFECYCLE_TRANSITION_OPERATION_PREFIX = "lifecycle.transition."


def lifecycle_transition_operation(machine_key: str, machine_version: int) -> str:
    """The operation name the database derives for one machine version.

    A convenience for readers and tests. **Nothing in the write path calls it**: the value
    that reaches a row is computed inside
    ``firmbatch.transition_lifecycle_instance()`` from the machine the instance pins, and
    there is no parameter through which this one could be substituted for it.
    """
    return f"{LIFECYCLE_TRANSITION_OPERATION_PREFIX}{machine_key}.v{machine_version}"

#: The one thing a conflict ever says. Written here as a constant rather than taken from
#: the database's message, because psycopg renders a plpgsql exception's ``CONTEXT`` -- and
#: that names the *line number* of the ``RAISE``, which is a branch identifier. The database
#: side is one raise site for the same reason; this is the other half of the same property.
LIFECYCLE_CONFLICT_MESSAGE = (
    "the lifecycle instance is not in the expected state at the expected revision. It may "
    "have moved since it was read, it may never have existed, or it may belong to another "
    "tenant -- the three are deliberately indistinguishable, because a refusal that told "
    "them apart would answer whether an identifier exists outside this tenant. Re-read the "
    "instance and decide again; a blind retry carries the same stale revision."
)

_STATE_PATTERN = re.compile(LIFECYCLE_NAME_REGEX)

#: The audit actions the database writes. Named here so a caller can find the trail, and
#: asserted against the function bodies by the tests.
INSTANCE_CREATED_ACTION = "lifecycle.instance_created"
TRANSITIONED_ACTION = "lifecycle.transitioned"

#: What an accepted transition announces. Deliberately neutral: ``<machine>.transitioned``
#: rather than ``<machine>.<new state>``, because a domain event vocabulary is Milestone 5
#: and 6 work and a foundation that claimed ``job.completed`` would have taken that name
#: before the milestone that owns it could.
TRANSITIONED_EVENT_SUFFIX = "transitioned"


class LifecycleError(RuntimeError):
    """Base class for every refusal this module makes."""


class LifecycleConflict(LifecycleError):
    """The instance is not in the expected state at the expected revision.

    One error for four situations, on purpose: the instance moved since it was read, the
    instance does not exist, the instance belongs to another tenant, or another caller won
    a race for the same revision. Distinguishing them would make the refusal an existence
    oracle across the isolation boundary, which is the one thing a conflict must not be.

    A caller that means to proceed anyway must **re-read the instance** and decide again.
    It must not simply retry: the revision it holds is stale by definition, and a blind
    retry either fails identically forever or -- if the state happened to come back around
    -- applies a move the caller never actually decided on.
    """


class LifecycleTransitionNotAllowed(LifecycleError):
    """The requested move is not an edge of this instance's machine version.

    Distinct from a conflict, and the distinction is actionable: a conflict says "somebody
    else got there first, look again", and this says "no version of this machine has ever
    permitted that move". Terminal states arrive here too -- a terminal state has no
    outgoing edge by definition.
    """


class LifecycleProvenanceError(LifecycleError):
    """A claim in the lifecycle namespace has no verifiable transition behind it.

    A replay returns what a claim recorded, so it has to be backed by the protected link
    between that claim, the transition it stands for, the instance, the revisions and the
    outbox event -- and a machine tag is not that link: it says which machine a row belongs
    to, not which move it records.

    Not an outcome an ordinary caller can produce. Only the lifecycle writer can write a row
    in the reserved namespace, and the one function that does writes the provenance in the
    same statement sequence. It exists so that a claim which somehow lacks its provenance is
    **refused** rather than replayed as a transition that may never have happened.
    """


class LifecycleDefinitionError(LifecycleError):
    """A machine definition is missing, malformed, or already registered.

    Kept separate from :class:`LifecycleConflict` because the two are different failures
    with different owners: a conflict is ordinary concurrency and belongs to the caller, and
    this is a deployment or migration problem and belongs to whoever registered the machine.

    Machines are **global**, so nothing here reveals anything about any tenant -- which is
    why this one may say what went wrong while a conflict may not.
    """


# --------------------------------------------------------------------------- value types


@dataclass(frozen=True)
class LifecycleDefinition:
    """One immutable machine version, as the registrar takes it.

    A plain description with no behaviour. The graph rules it must satisfy are in
    :func:`validated_lifecycle_definition`, and every one of them is enforced again by the
    schema -- so this type is a convenience for whoever writes a definition, not the thing
    that makes a definition safe.
    """

    machine_key: str
    version: int
    #: The one state every instance starts in.
    initial_state: str
    #: The explicit state set, including the initial and terminal ones. Explicit rather than
    #: derived from the edges, because a state with no edges is a legitimate part of a graph
    #: and deriving the set would make it unrepresentable.
    states: tuple[str, ...]
    #: States the machine stops in. A terminal state may have no outgoing edge.
    terminal_states: tuple[str, ...] = ()
    #: The allowed moves, as ``(from, to)``. Cycles are permitted, including self-edges:
    #: ``offered -> accepted -> revoked -> offered`` is a real machine, and a kernel that
    #: assumed acyclicity would have to be argued with by every domain that needs one.
    transitions: tuple[tuple[str, str], ...] = ()
    #: The capability an instance of this version requires, for each of the three
    #: operations. Only a scope that already exists in the closed catalogue, and never
    #: ``tenant:provision``; see ``security/authorization.LIFECYCLE_ELIGIBLE_SCOPES``.
    read_scope: str = Scope.WORKSPACE_READ.value
    create_scope: str = Scope.WORKSPACE_WRITE.value
    transition_scope: str = Scope.WORKSPACE_WRITE.value


@dataclass(frozen=True)
class LifecyclePosition:
    """Where an instance is: the machine it runs, the state it is in, and its revision."""

    id: uuid.UUID
    machine_key: str
    machine_version: int
    current_state: str
    revision: int
    #: The outbox intent creating the instance committed. Never ``None`` from
    #: :func:`create_lifecycle_instance`: the database call writes it, so there is no
    #: ordering in which a caller gets an instance and no event.
    event_id: uuid.UUID | None = None


@dataclass(frozen=True)
class AppliedTransition:
    """One accepted move, and every artifact the database wrote with it."""

    transition_id: uuid.UUID
    instance_id: uuid.UUID
    machine_key: str
    machine_version: int
    from_state: str
    to_state: str
    from_revision: int
    to_revision: int
    #: The outbox intent the move committed. Always present -- the database call that
    #: changes the state is the one that writes it.
    event_id: uuid.UUID | None = None
    #: The idempotency claim the move committed, when one was asked for. ``None`` for the
    #: internal form, whose event is unlinked.
    record_id: uuid.UUID | None = None
    #: What a later identical retry replays, computed by the database from what it did.
    result: "dict[str, Any]" = field(default_factory=dict)
    #: The operation the claim was made under, **derived by the database** from the machine
    #: this instance pins. ``None`` for the internal form, which claims nothing.
    operation: str | None = None
    #: ``True`` when this call did not move anything: the key had already been claimed for
    #: this exact request, and what came back is what that claim recorded.
    replayed: bool = False

    def position(self) -> LifecyclePosition:
        return LifecyclePosition(
            id=self.instance_id,
            machine_key=self.machine_key,
            machine_version=self.machine_version,
            current_state=self.to_state,
            revision=self.to_revision,
        )


# ---------------------------------------------------------------------- non-echoing checks


def _refuse(message: str) -> None:
    """Raise a definition refusal that names the rule and never the value.

    Raised directly rather than from inside an ``except`` block, so nothing is attached as
    ``__cause__`` or ``__context__`` carrying what was refused.
    """
    raise LifecycleDefinitionError(message)


def _at(index: int) -> str:
    return f"position {index}"


def _require_name(value: Any, *, what: str, where: str = "") -> None:
    """Shape first, then format, and neither echoes.

    The shape test is not decoration here. The identifier grammar a state name has to
    satisfy -- lowercase letters, digits and underscores, up to 63 characters -- happily
    accepts an all-lowercase Firmbatch bearer credential, and a state name reaches a
    ``jsonb`` audit document and a stored history row. So a credential pasted where a state
    belongs would otherwise be caught by nothing here and quoted by the check that refused
    it.
    """
    located = f" at {where}" if where else ""
    shape = looks_like_secret(value)
    if shape is not None:
        _refuse(
            f"the {what}{located} looks like {shape}. It names a position in a state machine; "
            "the value is deliberately not repeated here."
        )
    if not isinstance(value, str) or not _STATE_PATTERN.fullmatch(value):
        _refuse(
            f"the {what}{located} is not a lowercase identifier of at most 63 characters "
            f"({LIFECYCLE_NAME_REGEX}). The value is deliberately not repeated."
        )


def _require_scope_value(value: Any, *, what: str) -> str:
    shape = looks_like_secret(value)
    if shape is not None:
        _refuse(
            f"the {what} looks like {shape}. It names a capability from a closed catalogue; "
            "the value is deliberately not repeated here."
        )
    if not isinstance(value, str):
        _refuse(f"the {what} is {type(value).__name__}, not a scope name")
    if value not in LIFECYCLE_ELIGIBLE_SCOPES:
        _refuse(
            f"the {what} is not a scope a lifecycle machine may require. Eligible: "
            f"{list(LIFECYCLE_ELIGIBLE_SCOPES)}. tenant:provision is excluded deliberately -- it "
            "cannot be placed on any credential, so a machine gated on it would be unreachable "
            "rather than protected. The rejected value is deliberately not repeated."
        )
    return value


def validated_lifecycle_definition(definition: LifecycleDefinition) -> LifecycleDefinition:
    """Check one machine definition, or refuse it without repeating what it said.

    The rules, and the reason each one is a rule:

    * **known states.** Every endpoint of every edge, and the initial state, must be in the
      declared state set. Enforced again by foreign keys, which bind every writer.
    * **exactly one initial state.** :attr:`LifecycleDefinition.initial_state` is singular
      by construction here, and a partial unique index makes "at most one" a database fact.
    * **unique states and unique edges.** A duplicate is a definition somebody wrote twice
      and meant once; the primary keys refuse it too.
    * **no outgoing edge from a terminal state.** The one graph rule beyond "the states are
      known". A terminal state is the definition's statement that the machine stops there,
      so an edge out of one is a contradiction inside a single definition rather than a
      policy this kernel is imposing.
    * **eligible scopes.** Only a capability the closed catalogue already has, and never the
      bootstrap-only ``tenant:provision``.
    * **bounds.** At most :data:`~firmbatch.control_plane.db.models.MAX_LIFECYCLE_STATES`
      states and :data:`~firmbatch.control_plane.db.models.MAX_LIFECYCLE_TRANSITIONS` edges.
      Not a security property -- the protected tables are -- but a definition is data, and
      every policy evaluation reads it.

    Three rules it deliberately does **not** impose, because none of them is a product
    requirement and each would have to be argued with later:

    * **acyclicity.** Cycles are legitimate machines. Self-edges are permitted too: a move
      that changes only the revision is a real thing to want, and forbidding it would be a
      rule nobody asked for.
    * **reachability.** A state no edge leads to is odd and is not wrong; a definition may
      be built up across versions.
    * **an outgoing edge from every non-terminal state.** A dead end that is not marked
      terminal is a definition mistake this kernel is not entitled to diagnose.
    """
    if not isinstance(definition, LifecycleDefinition):
        _refuse(f"a lifecycle definition is a LifecycleDefinition, not {type(definition).__name__}")

    _require_name(definition.machine_key, what="lifecycle machine key")
    if isinstance(definition.version, bool) or not isinstance(definition.version, int):
        _refuse("a lifecycle machine version is an integer")
    if definition.version < 1:
        _refuse("a lifecycle machine version is a positive integer, counting from 1")

    states = tuple(definition.states)
    if not states:
        _refuse("a lifecycle machine declares at least one state; the state set is explicit")
    if len(states) > MAX_LIFECYCLE_STATES:
        _refuse(
            f"a lifecycle machine declares {len(states)} states, over the {MAX_LIFECYCLE_STATES} "
            "allowed. A machine that needs more than that is a machine that should be several."
        )
    for index, state in enumerate(states):
        _require_name(state, what="lifecycle state name", where=_at(index))
    if len(set(states)) != len(states):
        _refuse("the lifecycle state set repeats a state; the rejected names are not repeated here")

    known = set(states)
    _require_name(definition.initial_state, what="lifecycle initial state")
    if definition.initial_state not in known:
        _refuse("the lifecycle initial state is not in the declared state set")

    terminal = tuple(definition.terminal_states)
    for index, state in enumerate(terminal):
        _require_name(state, what="lifecycle terminal state", where=_at(index))
        if state not in known:
            _refuse(f"the lifecycle terminal state at {_at(index)} is not in the declared state set")
    if len(set(terminal)) != len(terminal):
        _refuse("the lifecycle terminal state set repeats a state")

    transitions = tuple(definition.transitions)
    if len(transitions) > MAX_LIFECYCLE_TRANSITIONS:
        _refuse(
            f"a lifecycle machine declares {len(transitions)} edges, over the "
            f"{MAX_LIFECYCLE_TRANSITIONS} allowed"
        )
    terminal_set = set(terminal)
    seen: set[tuple[str, str]] = set()
    for index, edge in enumerate(transitions):
        if not isinstance(edge, (tuple, list)) or len(edge) != 2:
            _refuse(f"the lifecycle edge at {_at(index)} is not a (from, to) pair")
        source, target = edge
        _require_name(source, what="lifecycle edge source", where=_at(index))
        _require_name(target, what="lifecycle edge target", where=_at(index))
        if source not in known:
            _refuse(f"the lifecycle edge at {_at(index)} starts from a state that is not declared")
        if target not in known:
            _refuse(f"the lifecycle edge at {_at(index)} ends at a state that is not declared")
        if source in terminal_set:
            _refuse(
                f"the lifecycle edge at {_at(index)} leaves a terminal state. A terminal state is "
                "the definition's statement that the machine stops there."
            )
        if (source, target) in seen:
            _refuse(f"the lifecycle edge at {_at(index)} is declared twice")
        seen.add((source, target))

    return LifecycleDefinition(
        machine_key=definition.machine_key,
        version=definition.version,
        initial_state=definition.initial_state,
        states=states,
        terminal_states=terminal,
        transitions=tuple(tuple(edge) for edge in transitions),
        read_scope=_require_scope_value(definition.read_scope, what="lifecycle read scope"),
        create_scope=_require_scope_value(definition.create_scope, what="lifecycle create scope"),
        transition_scope=_require_scope_value(
            definition.transition_scope, what="lifecycle transition scope"
        ),
    )


# ------------------------------------------------------------------ registration (owner)


_INSERT_MACHINE = text(
    f"""
    INSERT INTO {SCHEMA}.lifecycle_machines
        (machine_key, version, read_scope, create_scope, transition_scope)
    VALUES (:machine_key, :version, :read_scope, :create_scope, :transition_scope)
    ON CONFLICT (machine_key, version) DO NOTHING
    RETURNING machine_key
    """
)

_INSERT_STATE = text(
    f"""
    INSERT INTO {SCHEMA}.lifecycle_states
        (machine_key, machine_version, state, is_initial, is_terminal)
    VALUES (:machine_key, :version, :state, :is_initial, :is_terminal)
    """
)

_INSERT_EDGE = text(
    f"""
    INSERT INTO {SCHEMA}.lifecycle_transition_edges
        (machine_key, machine_version, from_state, to_state)
    VALUES (:machine_key, :version, :from_state, :to_state)
    """
)

_PUBLISH_MACHINE = text(
    f"SELECT {SCHEMA}.publish_lifecycle_machine(:machine_key, CAST(:version AS integer))"
)

_REGISTERED_MACHINES = text(
    f"SELECT machine_key, version, published_at IS NOT NULL AS published "
    f"FROM {SCHEMA}.lifecycle_machines ORDER BY machine_key, version"
)


def _refuse_autocommit_registration(connection: Connection) -> None:
    """Refuse a registration on a connection that commits every statement on its own.

    Read from the driver, before anything is written. Under AUTOCOMMIT each statement of a
    definition is durable by itself, so a registration that failed at its fourth statement
    would leave three committed rows behind -- a machine with some of its states, which no
    rollback could take back.

    Deliberately **not** ``connection.in_transaction()`` at this point: SQLAlchemy autobegins
    on the first statement, so before one has run that answer is ``False`` for a perfectly
    ordinary connection and says nothing. It is asserted after the first insert instead, and
    the property is established for real by
    :func:`~firmbatch.control_plane.db.lifecycle.register_lifecycle_definition`'s last
    statement: ``firmbatch.publish_lifecycle_machine`` requires every row of the definition
    to carry *this* transaction's ``xmin``, so a definition assembled across transactions
    cannot be published however it got there.
    """
    dbapi = getattr(getattr(connection, "connection", None), "dbapi_connection", None)
    if getattr(dbapi, "autocommit", False):
        _refuse(
            "registering a lifecycle machine requires a real transaction, and this connection is "
            "in AUTOCOMMIT. A definition is several statements; under AUTOCOMMIT each of them is "
            "durable on its own, so a failure part-way through would leave a partial machine that "
            "no rollback could remove."
        )


def _require_open_registration_transaction(connection: Connection) -> None:
    """Assert, after the first statement, that one transaction is open and holding it."""
    if not connection.in_transaction():
        _refuse(
            "registering a lifecycle machine requires an open transaction: the machine, its "
            "states, its edges and its publication become durable together or not at all."
        )


def register_lifecycle_definition(
    connection: Connection, definition: LifecycleDefinition
) -> LifecycleDefinition:
    """Register one machine version. **Runs as the schema owner, and only as the owner.**

    Takes a :class:`~sqlalchemy.engine.Connection` rather than a ``Session``, and the type
    is the cheapest way to say what this is: an owner-run admin action, like the grants in
    ``db/roles.py``. No runtime or provisioning role holds any privilege on the three
    definition tables, so a runtime caller reaching this gets ``permission denied`` from
    PostgreSQL rather than a half-registered machine.

    Deliberately **outside Alembic**, for the same reason role wiring is: which definitions
    a deployment needs is a property of which milestones it runs, not of the schema. A
    later milestone registers the job and window-offer machines alongside the domain tables
    that use them.

    Does not commit. The caller's transaction is what makes the definition durable -- all of
    it or none of it, which matters because a machine with states and no edges is a machine
    that cannot be left.

    **Draft, then publish.** The machine row is inserted unpublished, then its states, then
    its edges, and the **last** statement is
    ``firmbatch.publish_lifecycle_machine()``, which checks the whole graph and sets
    ``published_at``. Nothing consumes an unpublished machine: every reader the policies,
    the triggers and the entry points go through requires publication. So a registration
    that fails at any point has produced nothing usable even before the transaction rolls
    back, and a *concurrent* reader never sees a half-built graph at any instant.

    That ordering is also what makes "exactly one initial state" checkable at all. The
    partial unique index bounds it at one and cannot require that one exists -- the same
    limit the Milestone 2.2 outbox link has -- so existence is checked where the definition
    is declared complete.

    Re-registering an existing ``(machine_key, version)`` is refused rather than merged: a
    registered version is immutable, and a change is a new version. The refusal comes from
    ``ON CONFLICT DO NOTHING`` returning nothing rather than from a prior existence check,
    so there is no window between the two for a concurrent registrar to fit through.
    """
    checked = validated_lifecycle_definition(definition)
    terminal = set(checked.terminal_states)
    _refuse_autocommit_registration(connection)

    claimed = connection.execute(
        _INSERT_MACHINE,
        {
            "machine_key": checked.machine_key,
            "version": checked.version,
            "read_scope": checked.read_scope,
            "create_scope": checked.create_scope,
            "transition_scope": checked.transition_scope,
        },
    ).scalar_one_or_none()
    # Now that a statement has run, SQLAlchemy has autobegun and this answer means
    # something: one transaction is open and will carry the rest of the registration.
    _require_open_registration_transaction(connection)
    if claimed is None:
        _refuse(
            "that lifecycle machine version is already registered. A registered version is "
            "immutable -- every existing instance and every history row is interpreted against "
            "it -- so a change is a new version rather than a revision of this one."
        )

    for state in checked.states:
        connection.execute(
            _INSERT_STATE,
            {
                "machine_key": checked.machine_key,
                "version": checked.version,
                "state": state,
                "is_initial": state == checked.initial_state,
                "is_terminal": state in terminal,
            },
        )
    for source, target in checked.transitions:
        connection.execute(
            _INSERT_EDGE,
            {
                "machine_key": checked.machine_key,
                "version": checked.version,
                "from_state": source,
                "to_state": target,
            },
        )

    # Last, and in this transaction. Until this returns the machine is a draft that no
    # reader will resolve; after it, the graph is sealed in every direction -- no state or
    # edge may be added, and none may be revised or removed.
    connection.execute(
        _PUBLISH_MACHINE, {"machine_key": checked.machine_key, "version": checked.version}
    )
    return checked


def registered_lifecycle_machines(connection: Connection) -> tuple[tuple[str, int], ...]:
    """Every **published** ``(machine_key, version)``. Owner-only, like registration.

    Exists so that "this migration seeds no machine" is a claim a test can check rather
    than a sentence in a docstring. Unpublished rows are excluded because an unpublished
    machine is not a registered machine -- nothing can create an instance of one, and no
    policy will resolve a capability for one.
    """
    return tuple(
        (row.machine_key, row.version)
        for row in connection.execute(_REGISTERED_MACHINES)
        if row.published
    )


# ------------------------------------------------------------------------- the primitives


_CREATE_STATEMENT = text(
    f"SELECT instance_id, initial_state, event_id FROM {SCHEMA}.create_lifecycle_instance("
    ":machine_key, CAST(:machine_version AS integer))"
)

#: The function's output columns carry an ``o_`` prefix because an ``OUT`` parameter is an
#: ordinary plpgsql variable, and one named ``machine_key`` makes every reference to the
#: ``lifecycle_instances`` column of that name ambiguous inside the function body. They are
#: aliased back here, in the one statement that calls it, so the prefix does not leak into
#: this module or into anything that reads a row from it.
_TRANSITION_STATEMENT = text(
    "SELECT o_transition_id AS transition_id, o_machine_key AS machine_key, "
    "o_machine_version AS machine_version, o_from_revision AS from_revision, "
    "o_to_revision AS to_revision, o_event_id AS event_id, o_record_id AS record_id, "
    "o_result AS result, o_operation AS operation, o_replayed AS replayed "
    f"FROM {SCHEMA}.transition_lifecycle_instance("
    "CAST(:instance_id AS uuid), :expected_state, CAST(:expected_revision AS integer), "
    ":target_state, CAST(:reason AS text), CAST(:details AS jsonb), "
    "CAST(:idempotency_key AS text))"
)


def _translate(error: DBAPIError) -> Exception:
    """The database's refusal, as the Python error that means the same thing.

    Only the server's own primary message travels, and only for the SQLSTATEs migration
    ``0004`` raises deliberately -- those messages are written there, and each names the
    rule and never the value. Anything unanticipated becomes a message with **no** database
    text at all: an unexpected ``DBAPIError`` renders the failing statement *and its
    parameters*, and the parameters here are the caller's reason and details document.
    """
    orig = getattr(error, "orig", None)
    state = getattr(orig, "sqlstate", None)
    message = str(orig).strip()
    if state == LIFECYCLE_CONFLICT_SQLSTATE:
        # **The database's own text is deliberately dropped here**, and this is the one
        # translation that drops it. psycopg renders a plpgsql exception's ``CONTEXT``,
        # which names the function and the line number that raised -- and a line number is a
        # branch identifier. A conflict has to be one refusal, so it is written here as one
        # constant rather than assembled from whatever the server happened to say.
        return LifecycleConflict(LIFECYCLE_CONFLICT_MESSAGE)
    if state == LIFECYCLE_NOT_ALLOWED_SQLSTATE:
        return LifecycleTransitionNotAllowed(
            message or "that lifecycle transition is not an edge of this machine version"
        )
    if state == LIFECYCLE_DEFINITION_SQLSTATE:
        return LifecycleDefinitionError(message or "the lifecycle machine definition is unusable")
    if state == LIFECYCLE_KEY_REUSE_SQLSTATE:
        # The Milestone 2.2 outcome, under the Milestone 2.2 name. The fingerprint
        # comparison moved into the database -- it is derived there now, from the request
        # that ran -- but what the caller is told, and what it should do about it, is
        # unchanged.
        return IdempotencyConflict(
            "that idempotency key was already used for this lifecycle machine with a different "
            "request. Reusing a key for a changed request is a caller bug -- retry the original "
            "request with this key, or use a new key for the new one. Nothing about the existing "
            "request is disclosed here."
        )
    if state == LIFECYCLE_PROVENANCE_SQLSTATE:
        return LifecycleProvenanceError(
            message or "that idempotency key is claimed by a record with no verifiable lifecycle "
            "transition behind it"
        )
    if state == _INSUFFICIENT_PRIVILEGE:
        return AuthorizationError(message or "this context is not permitted to do that")
    if state == _INVALID_PARAMETER_VALUE:
        return LifecycleError(message or "the lifecycle request was refused")
    return LifecycleError(
        "the lifecycle operation could not be performed, and the database's explanation is "
        "deliberately not repeated here: the failing statement carries the caller's reason and "
        f"details document as parameters. SQLSTATE {state!r}."
    )


def _execute(session, statement, params):
    """Run one lifecycle statement and translate a refusal, attaching nothing.

    The raise happens **after** the ``except`` block rather than inside it. Inside a
    handler Python attaches the exception being handled as ``__context__``; ``raise ... from
    None`` suppresses that in a printed traceback without detaching it, so anything that
    walks the chain still finds the psycopg error and the parameters it renders.

    ``IntegrityError`` is deliberately **not** translated. It is what a lost claim race
    looks like -- a unique violation on the Milestone 2.2 claim index -- and
    :func:`execute_idempotent_lifecycle_transition` recovers from it by re-reading the
    winner, exactly as the Milestone 2.2 primitive does. Turning it into a
    ``LifecycleError`` here would take that recovery away.
    """
    failure: Exception | None = None
    try:
        return session.execute(statement, params)
    except IntegrityError:
        raise
    except DBAPIError as error:
        failure = _translate(error)
    raise failure from None


def _require_open_transaction(session, function: str) -> None:
    if not session.in_transaction():
        raise LifecycleError(
            f"{function} requires an open transaction: the state change, its history row, its "
            "audit event and its outbox intent only mean anything if they commit together."
        )


def _require_reason(reason: Any) -> str | None:
    """Bounded, metadata-only, and never echoed.

    A reason is the one free-text field this milestone has. It is short, it is refused if
    it carries a recognisable secret shape, and neither the value nor its length appears in
    a refusal -- a length is a small leak on its own and most of what is missing for a short
    secret.
    """
    if reason is None:
        return None
    shape = looks_like_secret(reason)
    if shape is not None:
        raise LifecycleError(
            f"the lifecycle transition reason looks like {shape}. A reason is a short note about "
            "why a move was made; the value is deliberately not repeated here."
        )
    if not isinstance(reason, str):
        raise LifecycleError(
            f"a lifecycle transition reason is a string or None; got {type(reason).__name__}"
        )
    if not 1 <= len(reason) <= MAX_LIFECYCLE_REASON_LENGTH:
        raise LifecycleError(
            f"a lifecycle transition reason is between 1 and {MAX_LIFECYCLE_REASON_LENGTH} "
            "characters. The value and its length are deliberately not repeated."
        )
    return reason


def _require_uuid(value: Any, *, what: str) -> uuid.UUID:
    if not isinstance(value, uuid.UUID):
        raise LifecycleError(f"a {what} is a UUID; got {type(value).__name__}")
    return value


def _require_revision(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LifecycleError(
            f"the expected lifecycle revision is an integer; got {type(value).__name__}"
        )
    if value < 0:
        raise LifecycleError("the expected lifecycle revision is not negative; instances start at 0")
    return value


def create_lifecycle_instance(
    session: Session, *, machine_key: str, machine_version: int
) -> LifecyclePosition:
    """Create one instance of one machine version, in this transaction's tenant.

    There is no ``tenant_id`` parameter and no ``initial_state`` parameter, and both
    absences are the design. The tenant is whatever the transaction authenticated as; the
    starting state is whatever the machine version declares, written by a ``BEFORE INSERT``
    trigger that binds every writer -- so an instance cannot be created half-way through
    its own lifecycle even by the schema owner.

    Requires the machine version's declared **create** capability, read from the protected
    definition rather than named by the caller, **and** ``mutation:execute`` -- because
    creating an instance commits a durable outbox intent alongside it, and appending one is
    what that capability is.

    The instance row, its audit event and its outbox intent are written by the one database
    call, so there is no ordering in which a caller gets the instance and skips the rest.

    Commits nothing.
    """
    _require_open_transaction(session, "create_lifecycle_instance")
    _require_name(machine_key, what="lifecycle machine key")
    if isinstance(machine_version, bool) or not isinstance(machine_version, int):
        raise LifecycleError("a lifecycle machine version is an integer")
    if machine_version < 1:
        raise LifecycleError("a lifecycle machine version is a positive integer")
    # Refused here as well as in the database, so an unauthenticated caller is told which
    # step it skipped rather than being handed a policy violation several frames later.
    require_authenticated_context(session)

    row = _execute(
        session,
        _CREATE_STATEMENT,
        {"machine_key": machine_key, "machine_version": machine_version},
    ).one()
    return LifecyclePosition(
        id=row.instance_id,
        machine_key=machine_key,
        machine_version=machine_version,
        current_state=row.initial_state,
        revision=0,
        event_id=row.event_id,
    )


def _apply_transition(
    session,
    *,
    instance_id: uuid.UUID,
    expected_state: str,
    expected_revision: int,
    target_state: str,
    reason: str | None,
    details: Mapping[str, Any] | None,
    idempotency_key: str | None = None,
) -> AppliedTransition:
    """The one move. Everything public here goes through this and nothing else.

    Validates in Python first -- so a malformed value never reaches a statement the server
    could log -- and then hands the whole decision to
    ``firmbatch.transition_lifecycle_instance()``, which makes it again against the row as
    it is at the instant of the write, and which writes **every** artifact the move owes:
    the state change, the history row, the audit event, the outbox intent, the idempotency
    claim when there is one, and the provenance row that ties that claim to this transition.

    ``idempotency_key`` is the **whole** of what a caller says about idempotency. The
    operation name and the request fingerprint used to be passed too, and both are now
    derived inside the database: the operation from the machine the instance pins, the
    fingerprint from the arguments the call actually executed. A caller that could supply
    either could bind a claim to a request it never made.
    """
    _require_open_transaction(session, "transition_lifecycle_instance")
    instance = _require_uuid(instance_id, what="lifecycle instance id")
    revision = _require_revision(expected_revision)
    _require_name(expected_state, what="expected lifecycle state")
    _require_name(target_state, what="target lifecycle state")
    checked_reason = _require_reason(reason)
    checked_details = validated_metadata(details or {}, where="the lifecycle transition's details")
    require_authenticated_context(session)

    row = _execute(
        session,
        _TRANSITION_STATEMENT,
        {
            "instance_id": instance,
            "expected_state": expected_state,
            "expected_revision": revision,
            "target_state": target_state,
            "reason": checked_reason,
            "details": canonical_json(checked_details),
            "idempotency_key": idempotency_key,
        },
    ).one()
    result = dict(row.result)
    return AppliedTransition(
        transition_id=row.transition_id,
        instance_id=instance,
        machine_key=row.machine_key,
        machine_version=row.machine_version,
        # On a replay these come from the claim the database verified rather than from the
        # arguments: a replayed call moved nothing, so what it describes is the transition
        # that did.
        from_state=result.get("from_state", expected_state),
        to_state=result.get("to_state", target_state),
        from_revision=row.from_revision,
        to_revision=row.to_revision,
        event_id=row.event_id,
        record_id=row.record_id,
        result=result,
        operation=row.operation,
        replayed=bool(row.replayed),
    )


def transition_lifecycle_instance(
    session: Session,
    *,
    instance_id: uuid.UUID,
    expected_state: str,
    expected_revision: int,
    target_state: str,
    reason: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> AppliedTransition:
    """Move one instance along one declared edge, or refuse. **The transition primitive.**

    The internal-transition form: the database call commits one **unlinked** outbox event,
    which is exactly the case ADR 0005 built the optional causation link for -- a
    controller, a reconciler or a validator committing an event with the state change that
    caused it, with no caller-supplied idempotency key to link it to. For the API form,
    where an identical retry must replay rather than move the instance again, use
    :func:`execute_idempotent_lifecycle_transition`.

    **This function appends nothing itself**, and that is the correction rather than an
    implementation detail. While the outbox event was written here, after the database call
    returned, an application role executing arbitrary SQL could call the database function
    and simply not append one: a committed state change, history row and audit event with
    nothing announcing the change. Every artifact is now written by the one call that
    changes the state, so there is no caller and no ordering that produces a subset.

    Commits nothing itself. The caller's transaction is what makes the state change, the
    history row, the audit event and the outbox intent durable -- together or not at all.

    Raises :class:`LifecycleConflict` if the instance is not in ``expected_state`` at
    ``expected_revision`` (which is also what an absent or another tenant's instance
    produces, indistinguishably), :class:`LifecycleTransitionNotAllowed` if the move is not
    an edge of this machine version or the instance is already terminal,
    :class:`~firmbatch.control_plane.security.authorization.AuthorizationError` if the
    context does not hold the machine's transition capability or ``mutation:execute``, and
    :class:`~firmbatch.control_plane.db.metadata.MetadataPolicyError` if the details are not
    bounded metadata.
    """
    return _apply_transition(
        session,
        instance_id=instance_id,
        expected_state=expected_state,
        expected_revision=expected_revision,
        target_state=target_state,
        reason=reason,
        details=details,
    )


def execute_idempotent_lifecycle_transition(
    session: Session,
    *,
    idempotency_key: str,
    instance_id: uuid.UUID,
    expected_state: str,
    expected_revision: int,
    target_state: str,
    reason: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> IdempotentResult:
    """The API form: the same move, claimed once per ``(tenant, machine version, key)``.

    Uses the Milestone 2.2 **table**, index, record type and semantics -- and not its
    ``execute_idempotent_mutation`` control flow, and not, any longer, any of its Python.
    **The whole of lifecycle idempotency happens inside
    ``firmbatch.transition_lifecycle_instance()``**, and that is deliberate rather than
    convenient: it is the smallest authority boundary the property fits inside.

    What moved into the database, and why each one had to:

    * **The operation name.** It is derived as
      ``lifecycle.transition.<machine_key>.v<version>`` from the machine the *instance*
      pins, so a caller cannot choose which uniqueness domain its key lands in and two
      machines never share one. The whole ``lifecycle.`` namespace is closed to the generic
      Milestone 2.2 primitive by a check constraint tied to the owner-only machine tag, so a
      generic claim can neither collide with a lifecycle claim nor use the unique index to
      ask whether one exists.
    * **The request fingerprint.** It is computed from the arguments the call actually
      executed -- the authenticated tenant, the derived operation, the instance, the machine
      version it pins, the expectation, the target, and the validated reason and details.
      While Python computed it and passed it in, it was a caller-controlled value in exactly
      the place a caller must not control one: a raw-SQL caller could move instance A while
      storing a fingerprint computed for a request about B, and the next genuine request for
      B would replay A's result. PostgreSQL is now the only implementation, so there is no
      parity to prove and no second copy to drift.
    * **The replay lookup, and the recovery from a lost race.** Both re-read the claim
      through the protected provenance relation, so a replay is backed by an actual
      transition rather than by a row that carries a plausible ``result``.

    What this buys, unchanged from before:

    * an identical retry returns the stored result and does **not** move the instance again;
    * reusing the key for a different request raises
      :class:`~firmbatch.control_plane.db.idempotency.IdempotencyConflict`;
    * one successful call leaves one revision, one history row, one audit event, one linked
      outbox intent, one claim and one provenance row;
    * **two identical requests running concurrently both return the original result.** The
      loser -- whether it lost on the claim index or on the instance's row lock -- has its
      whole attempt rolled back by the function's own subtransaction, re-reads the winner's
      claim, and replays it;
    * two *different* keys racing from the same revision still produce one move and one
      conflict: they are different requests, and there is no winning claim to find.

    The two controls do different jobs and neither substitutes for the other. An idempotency
    key bounds *retries of one request*; the revision bounds *concurrent requests*.

    There is no ``operation`` parameter, and its absence is the point. Everything else a
    caller passes is the move itself.
    """
    _require_open_transaction(session, "execute_idempotent_lifecycle_transition")
    # The Milestone 2.2 key validator, reused rather than re-spelled: a malformed key is
    # refused before anything is read or written, and the refusal never repeats it. The
    # database applies the same rule again, which is what makes it hold for raw SQL.
    _require_valid_key(idempotency_key)
    # begin_nested() no longer appears on this path -- the savepoint is the database
    # function's own subtransaction -- but the reason for refusing pending ORM state is
    # unchanged: ``session.execute`` autoflushes, so a row the caller left pending would be
    # written into the outer transaction and would survive a lost race that discards
    # everything the function did.
    _require_clean_session(session)
    # Recovering from a lost race means re-reading the row the winner just committed, and
    # only READ COMMITTED takes a fresh snapshot per statement. Checked here for a good
    # error and again inside the function, which is where the recovery actually is.
    _require_read_committed(session)

    applied = _apply_transition(
        session,
        instance_id=instance_id,
        expected_state=expected_state,
        expected_revision=expected_revision,
        target_state=target_state,
        reason=reason,
        details=details,
        idempotency_key=idempotency_key,
    )
    return IdempotentResult(
        record_id=applied.record_id,
        event_id=applied.event_id,
        result=applied.result,
        replayed=applied.replayed,
    )


# ------------------------------------------------------------------------------- reading


def lifecycle_instance(session: Session, instance_id: uuid.UUID) -> LifecycleInstance | None:
    """One instance, or ``None`` for anything this context cannot see.

    No ``WHERE tenant_id = ...``: row-level security is the filter, and a reader can check
    that claim by noticing there is no filter here to get wrong. Another tenant's instance
    and a context without the machine's read capability both produce ``None`` rather than
    an error, because that is what a policy does.
    """
    return session.get(LifecycleInstance, instance_id)


def lifecycle_history(
    session: Session, instance_id: uuid.UUID, *, limit: int = 100
) -> Sequence[LifecycleTransition]:
    """One instance's transitions, oldest first, ordered by revision.

    By ``to_revision`` and not by ``occurred_at``: the revision is the total order the
    machine itself defines, and two rows written in the same microsecond would be
    indistinguishable by clock. The unique constraint on
    ``(tenant_id, lifecycle_instance_id, to_revision)`` is what makes that order complete.
    """
    return list(
        session.scalars(
            select(LifecycleTransition)
            .where(LifecycleTransition.lifecycle_instance_id == instance_id)
            .order_by(LifecycleTransition.to_revision)
            .limit(limit)
        )
    )
