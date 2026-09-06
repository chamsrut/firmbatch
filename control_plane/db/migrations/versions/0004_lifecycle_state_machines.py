"""Persisted, versioned lifecycle state machines whose transitions cannot race.

Revision ID: 0004_lifecycle_state_machines
Revises: 0003_auth_context_and_audit
Create Date: 2026-09-05

The fourth v1 migration, and the last declared slice of Milestone 2. It adds a **lifecycle
kernel**: the smallest thing that can say "this row is in this state, it got there by a
declared move, and two callers cannot both move it".

What it is not
--------------

It is not a workflow product. There is no customer-editable DSL, no expression language, no
scripting hook, no scheduler and no compensation model. A machine is four kinds of row --
a version, its states, its edges, and the scopes it requires -- and the only thing the
runtime may do with one is move an instance along an edge that already exists.

It is also **empty**. This migration registers **no machine**: the job lifecycle of target
architecture section 5.1 and the window-offer machine of section 12.1 are Milestone 5 and 6
work, and their definitions land with the domain tables they describe. Seeding a
demonstration machine here would put a graph nobody had reviewed as a product decision into
every production database, and the roadmap does not ask for one. Tests register explicitly
test-only definitions into their own disposable database, through the owner.

The four things it does establish
---------------------------------

1. **A definition is protected, global and immutable.** ``lifecycle_machines``,
   ``lifecycle_states`` and ``lifecycle_transition_edges`` carry no grant for any runtime
   or provisioning role, and a ``BEFORE UPDATE OR DELETE`` trigger refuses a change even
   for the owner. A machine version is one graph for every tenant -- explicitly global, in
   the sense target architecture section 3.1 uses for the certification registry -- and a
   change to it is a **new version**, so an instance created under version 3 keeps meaning
   what it meant.

2. **An instance is tenant-owned and starts where its machine says.** ``tenant_id`` comes
   from the authenticated context and from nowhere else; the initial state and revision
   zero are written by a ``BEFORE INSERT`` trigger, so a direct writer cannot start an
   instance half-way through its own lifecycle.

3. **A transition is a compare-and-swap, and the graph is enforced underneath it.**
   ``firmbatch.transition_lifecycle_instance()`` performs one conditional ``UPDATE`` whose
   predicate names the tenant, the instance, the machine version, the expected state **and**
   the expected revision. Zero rows updated is a conflict -- and it is the *same* conflict
   whether the instance is stale, missing, or another tenant's, so the refusal is not an
   existence oracle. Underneath it, a ``BEFORE UPDATE`` trigger requires that
   ``(old state, new state)`` be a declared edge, that the source not be terminal, and that
   the revision advance by exactly one. That trigger binds every writer, so an illegal move
   is impossible rather than merely refused.

4. **The history cannot record a move the machine does not have.**
   ``lifecycle_transitions`` references the *edge* table on
   ``(machine_key, machine_version, from_state, to_state)``, and the instance on
   ``(id, tenant_id, machine_key, machine_version)``. Referential integrity is checked with
   row security bypassed, so both hold for the owner and for any future role: an invalid
   edge, a cross-tenant reference and a cross-machine reference are all inexpressible.

Where the authorization comes from
----------------------------------

Not from the caller. A machine version declares the scope its instances require to be read,
created and moved, and every policy reads it through
``firmbatch.lifecycle_required_scope()`` -- a ``SECURITY DEFINER`` reader over the protected
definition. So "who may move this" is a property of the machine, stored where the runtime
cannot write it, and the runtime never states a required capability at all. The definition
may name only a scope that already exists (``security/authorization.LIFECYCLE_ELIGIBLE_SCOPES``),
enforced by a check constraint: there is no ``lifecycle:*`` wildcard and this migration adds
no scope.

Who may write a lifecycle-derived row
-------------------------------------

Only the **lifecycle writer**: a dedicated ``NOLOGIN`` role that owns the two
``SECURITY DEFINER`` entry points and nothing else, so that "this row was written by the
lifecycle boundary" is a fact about ``current_user`` rather than a convention. The machine
tags on the three framework tables, the provenance relation, and the linking of an outbox
event to a lifecycle claim are each refused to every other identity -- the application role,
the provisioning role, **and the schema owner**, whose direct DML and whose own definer
functions used to pass a ``current_user = schema owner`` check and could therefore forge the
association a replay rests on.

The migration cannot name that role: role names differ per environment and per disposable
test database, so the wiring layer (``db/roles.py``) creates it and hands it the entry points.
What the migration does instead is define **how the writer is recognised**:
``firmbatch.lifecycle_writer_role()`` reads the owner of the entry points from the catalogue
and answers with that role only if it owns *both*, is not the schema owner, and holds none of
``LOGIN``, ``SUPERUSER``, ``BYPASSRLS``, ``CREATEROLE``, ``CREATEDB`` or ``REPLICATION``.
Until the wiring has run, that is NULL and every guard fails closed. No caller-settable GUC,
transaction variable, temporary object, token, query text or trigger depth is consulted: the
identity is the executing role, and the executing role is what ``SECURITY DEFINER`` sets.

The generic Milestone 2.2 outbox path is bounded the same way from the other side. A caller
that could supply ``idempotency_record_id`` used to reach the foreign key and the
one-event-per-claim index with a hidden lifecycle claim's id -- a uniqueness violation for a
claim that exists, a foreign-key violation for one that does not, and the difference was an
existence oracle over rows the read policies hide. A ``BEFORE INSERT`` trigger now proves,
**before either constraint is evaluated**, that a generic writer's link names a claim this
authenticated context may read, in its own tenant, untagged and outside the reserved
namespace -- and refuses everything else with one message.

Hand-written like ``0001`` to ``0003``: ``op.create_table`` cannot emit RLS DDL, function
definitions, triggers or policies. ``tests/test_migrations.py`` asserts with
``compare_metadata`` that what this file builds still matches ``db/models.py``.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP, UUID

revision: str = "0004_lifecycle_state_machines"
down_revision: str | None = "0003_auth_context_and_audit"
branch_labels: str | None = None
depends_on: str | None = None

SCHEMA = "firmbatch"

# Mirrors db/models.py and security/authorization.py. The migration cannot import them --
# a migration that follows the models stops being a record of what was applied -- so the
# constants are duplicated and tests/test_migrations.py asserts the duplicate has not
# drifted.
SIMPLE_NAME_REGEX = r"^[a-z][a-z0-9_]{0,62}$"
LIFECYCLE_NAME_REGEX = SIMPLE_NAME_REGEX
MAX_METADATA_BYTES = 4096
MAX_LIFECYCLE_REASON_LENGTH = 200

#: The Milestone 2.2 idempotency vocabulary, mirrored because the transition function now
#: writes the claim itself. It has to: the outbox event must carry the claim's id, an
#: outbox row is append-only so the link cannot be added afterwards, and the claim's result
#: is not known until the move has happened -- so claim and event have to be written by the
#: same call, in that order, inside the one statement sequence that also moves the instance.
DOTTED_NAME_REGEX = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$"
IDEMPOTENCY_KEY_REGEX = r"^[A-Za-z0-9._:@=+-]{8,200}$"
FINGERPRINT_REGEX = r"^[0-9a-f]{64}$"
IDEMPOTENCY_STATUS_COMPLETED = "completed"

#: **The reserved lifecycle namespace**, and it is reserved in the database rather than by
#: convention.
#:
#: An idempotency claim's operation and an audit event's action both start with this prefix
#: exactly when the row belongs to a lifecycle machine, and only trusted database code can
#: write such a row: a check constraint ties the prefix to the derived machine tag, and the
#: tag trigger below refuses that tag to every writer but the schema owner. So a generic
#: Milestone 2.2 mutation cannot create a claim in this namespace, cannot collide with one,
#: and cannot use a uniqueness conflict to ask whether one exists.
#:
#: The operation a lifecycle transition claims under is
#: ``lifecycle.transition.<machine_key>.v<version>``, derived inside the database from the
#: machine the *instance* pins. Two consequences, both wanted: a caller has no say in it,
#: and two machines never share a uniqueness domain -- so a key taken for a machine this
#: context cannot read is in a namespace this context never reaches.
LIFECYCLE_NAMESPACE_PREFIX = "lifecycle."
LIFECYCLE_TRANSITION_OPERATION_PREFIX = "lifecycle.transition."

#: The scopes a machine definition may require. Every known scope except
#: ``tenant:provision``, which is acquired from ``begin_tenant_provisioning()`` and cannot
#: be placed on any credential -- so a machine gated on it would be unreachable rather than
#: protected. Mirrors ``security/authorization.LIFECYCLE_ELIGIBLE_SCOPES``.
LIFECYCLE_ELIGIBLE_SCOPES = (
    "audit:read",
    "credential:manage",
    "mutation:execute",
    "tenant:read",
    "workspace:read",
    "workspace:write",
)

AUDIT_ACTOR_KINDS = ("credential", "provisioning")

#: The three outcomes this kernel raises, as SQLSTATEs, because a SQLSTATE is a contract and
#: a message is prose. They are in a user-defined class rather than borrowed from the
#: standard ones, and the borrowing is what that avoids: ``23514`` would have been caught by
#: ``db/idempotency.py``'s ``IntegrityError`` handler and re-read as a lost idempotency
#: race, and ``40001`` would have invited a retry loop around a conflict that must never be
#: retried blindly. PostgreSQL accepts any five-character alphanumeric code; class ``FB`` is
#: not one the standard defines. Mirrored in ``db/lifecycle.py``, which translates them.
LIFECYCLE_CONFLICT_SQLSTATE = "FB001"
LIFECYCLE_NOT_ALLOWED_SQLSTATE = "FB002"
LIFECYCLE_DEFINITION_SQLSTATE = "FB003"
#: A key already claimed for a *different* request. Its own code because it maps onto the
#: Milestone 2.2 ``IdempotencyConflict``, which is a caller-actionable outcome rather than a
#: lifecycle refusal, and because the fingerprint comparison now happens in the database.
LIFECYCLE_KEY_REUSE_SQLSTATE = "FB004"
#: A claim in the reserved lifecycle namespace whose provenance does not check out. Not
#: reachable by an ordinary caller -- only the lifecycle writer can write such a row, and
#: the transition function writes the provenance with it -- so this is the code for "the
#: relationship a replay depends on is not there", and it never replays.
LIFECYCLE_PROVENANCE_SQLSTATE = "FB005"
#: A generic outbox writer asked to link an event to a claim it may not link: absent, in
#: another tenant, unreadable by this context, or a lifecycle claim. One code and one
#: message for all of those, raised **before** the foreign key and the one-event-per-claim
#: index are evaluated, so that neither constraint can answer whether a hidden claim exists.
#: Mirrored in ``db/idempotency.py``, which translates it.
OUTBOX_LINK_SQLSTATE = "FB006"

#: The one message a conflict ever carries. Deliberately identical for a stale state, a
#: stale revision, an instance that does not exist, and an instance in another tenant: the
#: four are indistinguishable from outside, so the refusal cannot be used to ask whether a
#: given id exists somewhere else.
LIFECYCLE_CONFLICT_MESSAGE = (
    "firmbatch: the lifecycle instance is not in the expected state at the expected revision"
)

_UUID = UUID(as_uuid=True)
_TIMESTAMPTZ = TIMESTAMP(timezone=True)
_JSONB = JSONB(none_as_null=True)

_TENANT = f"{SCHEMA}.auth_tenant_id()"


def _metadata_checks(column: str) -> list[sa.CheckConstraint]:
    """Bare names: Alembic applies the ``ck_%(table_name)s_%(constraint_name)s``
    convention from ``db/base.py``."""
    return [
        sa.CheckConstraint(f"jsonb_typeof({column}) = 'object'", name=f"{column}_object"),
        sa.CheckConstraint(
            f"octet_length({column}::text) <= {MAX_METADATA_BYTES}", name=f"{column}_bounded"
        ),
    ]


def _quoted_list(values) -> str:
    return ", ".join(f"'{value}'" for value in values)


def _required_scope(capability: str) -> str:
    """The policy fragment that asks the *definition* which capability a row takes.

    Every policy on both tenant-owned lifecycle tables is written in terms of this, so the
    required scope is read from protected data on every evaluation and is never something a
    caller stated. An unknown machine, an unknown capability or a missing definition yields
    NULL, and ``auth_has_scope(NULL)`` coalesces to false -- so the failure direction is
    "denied" rather than "unconstrained".
    """
    return (
        f"{SCHEMA}.auth_has_scope("
        f"{SCHEMA}.lifecycle_required_scope(machine_key, machine_version, '{capability}'))"
    )


#: table -> (command, policy suffix, using, with check). A command absent from a table's
#: list has **no** policy, which under FORCE ROW LEVEL SECURITY means it reaches no row for
#: any role, the owner included.
POLICIES: "dict[str, tuple[tuple[str, str, str | None, str | None], ...]]" = {
    "lifecycle_instances": (
        ("SELECT", "read", f"tenant_id = {_TENANT} AND {_required_scope('read')}", None),
        ("INSERT", "append", None, f"tenant_id = {_TENANT} AND {_required_scope('create')}"),
        # The conditional update the transition primitive performs. It runs as the schema
        # owner inside a SECURITY DEFINER function, and row security is FORCEd, so this
        # policy is evaluated for it too -- which is why the tenant and the scope are
        # checked twice: once by the function, once here, on the row being written.
        (
            "UPDATE",
            "amend",
            f"tenant_id = {_TENANT} AND {_required_scope('transition')}",
            f"tenant_id = {_TENANT} AND {_required_scope('transition')}",
        ),
        # No DELETE policy. Removing an instance is not a runtime operation at this
        # milestone, and retention is a decision no milestone has taken yet.
    ),
    "lifecycle_transitions": (
        ("SELECT", "read", f"tenant_id = {_TENANT} AND {_required_scope('read')}", None),
        # Every derived column must agree with the authenticated context, exactly as on the
        # audit trail: a caller that names another tenant, another principal or another
        # binding is refused rather than silently corrected.
        #
        # ``occurred_at`` is deliberately not compared. A BEFORE INSERT trigger overwrites
        # it with clock_timestamp(), and WITH CHECK runs after BEFORE triggers, so there is
        # nothing left for a policy to check.
        (
            "INSERT",
            "append",
            None,
            " AND ".join(
                (
                    f"tenant_id = {_TENANT}",
                    f"actor_kind = {SCHEMA}.auth_actor_kind()",
                    f"actor_principal_id IS NOT DISTINCT FROM {SCHEMA}.auth_principal_id()",
                    f"actor_binding_id IS NOT DISTINCT FROM {SCHEMA}.auth_binding_id()",
                    _required_scope("transition"),
                )
            ),
        ),
        # No UPDATE and no DELETE policy: the history is append-only for every role.
    ),
}

#: The Milestone 2.2 framework tables get their **read** policy replaced.
#:
#: ``mutation:execute`` is the capability to claim a key and append an event. It was never
#: meant to be permission to *read* what somebody else's lifecycle did -- and until this
#: correction it was: a claim's ``result`` carries the instance id, the states and the
#: revisions, and an outbox event's ``attributes`` carry the same, so a credential holding
#: only the framework capability could read the whole trajectory of a machine it has no
#: capability for.
#:
#: So a framework row that belongs to a lifecycle machine is **tagged** with that machine by
#: trusted database code (see the tag trigger below), and reading a tagged row additionally
#: requires the machine's declared read scope. An untagged row -- every generic Milestone 2.2
#: mutation -- is unaffected, which is what keeps that behaviour exactly as it was.
_FRAMEWORK_TAG_READABLE = (
    "(lifecycle_machine_key IS NULL OR "
    f"{SCHEMA}.auth_has_scope({SCHEMA}.lifecycle_required_scope("
    "lifecycle_machine_key, lifecycle_machine_version, 'read')))"
)

#: The three framework tables whose read policy is replaced. ``audit_events`` is here for
#: exactly the same reason as the other two and it was missed the first time: an audit row
#: for a lifecycle action carries the instance id in ``resource_id`` and the machine, the
#: states, the revisions and the transition id in ``details``, so ``audit:read`` alone read
#: the whole trajectory of a machine the credential holds no capability for. Reading the
#: trail is still ``audit:read``; reading a *lifecycle* row additionally needs the machine's
#: declared read scope. Untagged rows -- every non-lifecycle action -- are unaffected.
FRAMEWORK_READ_POLICIES: "dict[str, str]" = {
    "idempotency_records": (
        f"tenant_id = {_TENANT} AND {SCHEMA}.auth_has_scope('mutation:execute') "
        f"AND {_FRAMEWORK_TAG_READABLE}"
    ),
    "outbox_events": (
        f"tenant_id = {_TENANT} AND {SCHEMA}.auth_has_scope('mutation:execute') "
        f"AND {_FRAMEWORK_TAG_READABLE}"
    ),
    "audit_events": (
        f"tenant_id = {_TENANT} AND {SCHEMA}.auth_has_scope('audit:read') "
        f"AND {_FRAMEWORK_TAG_READABLE}"
    ),
}

#: What migration ``0003`` wrote, so the downgrade restores it exactly.
_LEGACY_FRAMEWORK_READ_POLICIES: "dict[str, str]" = {
    "idempotency_records": f"tenant_id = {_TENANT} AND {SCHEMA}.auth_has_scope('mutation:execute')",
    "outbox_events": f"tenant_id = {_TENANT} AND {SCHEMA}.auth_has_scope('mutation:execute')",
    "audit_events": f"tenant_id = {_TENANT} AND {SCHEMA}.auth_has_scope('audit:read')",
}

#: The three tables that gain the derived lifecycle tag, and the column whose reserved
#: namespace is tied to it. ``operation`` for a claim, ``action`` for an audit row; the
#: outbox has no reserved namespace of its own because an event's ``event_type`` is
#: ``<machine_key>.transitioned`` and machine keys are not ours to reserve.
FRAMEWORK_TAGGED_TABLES: "tuple[tuple[str, str | None], ...]" = (
    ("idempotency_records", "operation"),
    ("outbox_events", None),
    ("audit_events", "action"),
)

#: Every function this migration creates, with its argument signature and its audience, so
#: that the grants, the downgrade and the tests all work from one list.
#:
#: ``application`` rather than ``runtime``: the provisioning role receives **no** lifecycle
#: authority. It exists to create a tenant and mint that tenant's first credential; moving a
#: job through its lifecycle is not a provisioning act, and no documented requirement asks
#: for one.
#:
#: ``writer``: the two mutation entry points. Created here owned by the schema owner, like
#: everything else a migration creates, and **handed to the lifecycle writer role by the
#: wiring layer** -- the migration cannot name a role. Their ``EXECUTE`` grant to the
#: application role is then the writer's to give, and ``db/roles.py`` gives it.
FUNCTIONS = (
    ("lifecycle_required_scope", "text, integer, text", "application"),
    # Reads the catalogue and answers which role, if any, is the lifecycle writer. Granted
    # to the application role because the outbox-link trigger below calls it while running
    # as whoever inserted the row, and that is the application role for a generic event.
    # What it discloses is a role name that pg_proc and pg_roles already show to every
    # role, and knowing the name confers nothing: nobody can SET ROLE to it.
    ("lifecycle_writer_role", "", "application"),
    ("create_lifecycle_instance", "text, integer", "writer"),
    # Seven parameters, not nine. The operation name and the request fingerprint used to be
    # among them and are now **derived here**: the operation from the machine the instance
    # pins, the fingerprint from the arguments this call actually executed. A caller that
    # could supply either could bind a claim to a request it did not make.
    (
        "transition_lifecycle_instance",
        "uuid, text, integer, text, text, jsonb, text",
        "writer",
    ),
    ("lifecycle_initial_state", "text, integer", "internal"),
    ("lifecycle_state_is_terminal", "text, integer, text", "internal"),
    ("lifecycle_edge_exists", "text, integer, text, text", "internal"),
    ("lifecycle_request_fingerprint", "uuid, text, uuid, text, integer, text, integer, text, text, jsonb", "internal"),
    ("lifecycle_replay_claim", "text, text, text, integer, text", "internal"),
    ("append_lifecycle_audit_event", "text, text, text, uuid, jsonb, text, integer", "internal"),
    ("publish_lifecycle_machine", "text, integer", "internal"),
    ("lifecycle_definition_is_immutable", "", "internal"),
    ("lifecycle_machines_before_insert", "", "internal"),
    ("lifecycle_machines_before_update", "", "internal"),
    ("lifecycle_definition_rows_before_insert", "", "internal"),
    ("lifecycle_edges_check_source", "", "internal"),
    ("lifecycle_instances_before_insert", "", "internal"),
    ("lifecycle_instances_before_update", "", "internal"),
    ("lifecycle_transitions_before_insert", "", "internal"),
    ("lifecycle_framework_tag_is_derived", "", "internal"),
    ("lifecycle_claim_provenance_guard", "", "internal"),
    ("outbox_events_link_is_authorized", "", "internal"),
    # The ownership-aware ACL sanitiser, as a function: see the access-control hygiene
    # section. Dropped last by the downgrade, with the rest.
    ("sanitize_schema_privileges", "", "internal"),
)


# --------------------------------------------------------------------- definition readers
#
# Three tiny ``SECURITY DEFINER`` readers over the protected definition. They exist so that
# the policies, the triggers and the two entry points all ask the same question of the same
# rows, and so that the *only* thing anybody can learn from the definition through them is
# the answer to that question. Each pins ``search_path``, qualifies every reference, builds
# no statement, and looks nothing up by a name it was told to trust.
#
# **Every one of them requires ``published_at IS NOT NULL``.** A definition is built up over
# several statements -- the machine, then its states, then its edges -- and between the first
# and the last it is a partial graph: no initial state yet, or states with no edges. Nothing
# may consume that. Publication is the single statement that makes a definition visible to
# these readers, and it is the last thing registration does. So an unpublished machine has
# no required scope, no initial state, no terminal states and no edges, from every consumer's
# point of view, and a registration that fails part-way leaves nothing usable behind even
# before the transaction rolls back.

_LIFECYCLE_REQUIRED_SCOPE = f"""
CREATE FUNCTION {SCHEMA}.lifecycle_required_scope(
    p_machine_key text,
    p_machine_version integer,
    p_capability text
) RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    -- The capability is a literal at every call site -- three policies and two entry
    -- points -- and never a value that reached the database from a caller. An unrecognised
    -- one returns NULL, which auth_has_scope coalesces to false, so the failure direction
    -- is denial.
    SELECT CASE p_capability
               WHEN 'read' THEN m.read_scope
               WHEN 'create' THEN m.create_scope
               WHEN 'transition' THEN m.transition_scope
           END
    FROM {SCHEMA}.lifecycle_machines m
    WHERE m.machine_key = p_machine_key
      AND m.version = p_machine_version
      AND m.published_at IS NOT NULL
$function$
"""

_LIFECYCLE_INITIAL_STATE = f"""
CREATE FUNCTION {SCHEMA}.lifecycle_initial_state(
    p_machine_key text,
    p_machine_version integer
) RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT s.state
    FROM {SCHEMA}.lifecycle_states s
    JOIN {SCHEMA}.lifecycle_machines m
      ON m.machine_key = s.machine_key AND m.version = s.machine_version
    WHERE s.machine_key = p_machine_key
      AND s.machine_version = p_machine_version
      AND s.is_initial
      AND m.published_at IS NOT NULL
$function$
"""

_LIFECYCLE_STATE_IS_TERMINAL = f"""
CREATE FUNCTION {SCHEMA}.lifecycle_state_is_terminal(
    p_machine_key text,
    p_machine_version integer,
    p_state text
) RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT COALESCE(
        (SELECT s.is_terminal
         FROM {SCHEMA}.lifecycle_states s
         JOIN {SCHEMA}.lifecycle_machines m
           ON m.machine_key = s.machine_key AND m.version = s.machine_version
         WHERE s.machine_key = p_machine_key
           AND s.machine_version = p_machine_version
           AND s.state = p_state
           AND m.published_at IS NOT NULL),
        false
    )
$function$
"""

_LIFECYCLE_EDGE_EXISTS = f"""
CREATE FUNCTION {SCHEMA}.lifecycle_edge_exists(
    p_machine_key text,
    p_machine_version integer,
    p_from_state text,
    p_to_state text
) RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (
        SELECT 1
        FROM {SCHEMA}.lifecycle_transition_edges e
        JOIN {SCHEMA}.lifecycle_machines m
          ON m.machine_key = e.machine_key AND m.version = e.machine_version
        WHERE e.machine_key = p_machine_key
          AND e.machine_version = p_machine_version
          AND e.from_state = p_from_state
          AND e.to_state = p_to_state
          AND m.published_at IS NOT NULL
    )
$function$
"""


# ------------------------------------------------------------------------- publication
#
# A definition is assembled over several statements and is only usable once, at the end,
# it is **published**. That boundary is what makes "only complete definitions are
# consumable" a fact rather than a convention: every consumer reads through the four
# readers above, and every one of them requires ``published_at IS NOT NULL``.
#
# Publication also re-validates the whole graph. The individual constraints -- the state
# foreign keys, the partial unique index, the terminal-source trigger, the eligible-scope
# checks -- each hold at the instant of their own row's insert; what none of them can say is
# "this machine, taken as a whole, is complete". *At least one initial state* is exactly
# such a property: a unique index bounds duplicates and cannot require existence, the same
# limit the Milestone 2.2 outbox link has.

_PUBLISH_LIFECYCLE_MACHINE = f"""
CREATE FUNCTION {SCHEMA}.publish_lifecycle_machine(
    p_machine_key text,
    p_machine_version integer
) RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    v_published timestamptz;
BEGIN
    -- Executable by nobody: publication is part of registration, and registration is an
    -- owner action. Inside the owner's transaction the privilege is implicit.
    --
    -- **This function validates nothing.** Every rule lives in the ``BEFORE UPDATE``
    -- trigger below, and that is the correction: while the rules lived here, they applied
    -- only to callers who chose to come through here, and a plain owner-written UPDATE
    -- setting the publication column published an arbitrary graph. What is left here is
    -- the two errors that need a nicer message than a trigger can give, and the lock.
    --
    -- **The lock, before anything looks at the graph.** ``FOR UPDATE`` on the machine row
    -- is the one lock this whole design takes, and every mutation of a state or an edge
    -- takes the same one first. So a concurrent edge insert either holds it -- and this
    -- waits, then sees the row that insert's transaction left -- or does not, and waits
    -- for us. There is exactly one lockable object and one order, so there is nothing to
    -- deadlock against.
    SELECT m.published_at INTO v_published
    FROM {SCHEMA}.lifecycle_machines m
    WHERE m.machine_key = p_machine_key AND m.version = p_machine_version
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'firmbatch: there is no such lifecycle machine version to publish'
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                  DETAIL = 'publication is the last step of registration, in the same transaction '
                           'that created the machine';
    END IF;
    IF v_published IS NOT NULL THEN
        RAISE EXCEPTION 'firmbatch: that lifecycle machine version is already published'
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                  DETAIL = 'a published version is sealed; a change is a new version';
    END IF;

    -- The trigger derives the timestamp, so what is written here is a placeholder that
    -- says "publish": any non-NULL value produces the same row.
    UPDATE {SCHEMA}.lifecycle_machines
    SET published_at = pg_catalog.clock_timestamp()
    WHERE machine_key = p_machine_key AND version = p_machine_version;
END;
$function$
"""


# ------------------------------------------------------------------------------ triggers

_LIFECYCLE_DEFINITION_IS_IMMUTABLE = f"""
CREATE FUNCTION {SCHEMA}.lifecycle_definition_is_immutable() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    -- Immutability that binds the owner too, which no grant can express. A registered
    -- version is what every existing instance and every history row is interpreted
    -- against; revising one in place would silently change the meaning of rows already
    -- written, which is the failure an append-only history exists to rule out.
    --
    -- **What this does not claim.** A trigger binds ordinary DML, including the schema
    -- owner's. It does not bind a superuser, and it does not bind an owner who first runs
    -- ``ALTER TABLE ... DISABLE TRIGGER`` or ``SET session_replication_role = replica``.
    -- Both of those are DDL-shaped, deliberate acts by a role this design already trusts
    -- with the definitions themselves -- see ADR 0006 on the migration owner. What the
    -- trigger buys is that no *accident* and no ordinary statement can revise a published
    -- definition.
    RAISE EXCEPTION 'firmbatch: a registered lifecycle machine version is immutable'
        USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
              DETAIL = 'a change to a machine is a new version; registered rows are never '
                       'revised or removed, because existing instances are interpreted against them';
END;
$function$
"""

_LIFECYCLE_MACHINES_BEFORE_INSERT = f"""
CREATE FUNCTION {SCHEMA}.lifecycle_machines_before_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    -- A machine is born a **draft**. Without this, the whole publication boundary had a
    -- door beside it: an INSERT that carried a non-NULL publication column produced a
    -- published machine with no states, no edges and no validation of any kind, because
    -- the validation is attached to the *update* that publishes.
    IF NEW.published_at IS NOT NULL THEN
        RAISE EXCEPTION 'firmbatch: a lifecycle machine version is inserted unpublished'
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                  DETAIL = 'publication is a separate step that validates the finished graph; a row '
                           'that arrived published would never have been validated at all';
    END IF;
    NEW.created_at := pg_catalog.clock_timestamp();
    RETURN NEW;
END;
$function$
"""

#: **Every publication rule, on the boundary every publication crosses.**
#:
#: These checks used to live in ``publish_lifecycle_machine()``, and that was the defect: a
#: function is a path, not a boundary. The schema owner -- who is the only identity that can
#: reach these tables at all, and who is trusted with the definitions -- could publish an
#: arbitrary graph with a plain ``UPDATE``, and every consumer would then resolve it. A
#: ``BEFORE UPDATE`` trigger is on the one place a row's ``published_at`` can change, so the
#: supported function and a hand-written ``UPDATE`` now run identically.
#:
#: **And it takes the lock before it looks.** The ``SELECT ... FOR UPDATE`` re-reads this
#: machine row under a lock that every state and edge mutation also takes, so a child insert
#: that is mid-flight either committed before we looked (and is included in the checks below)
#: or has not started (and will find us published, and refuse). The row is already locked by
#: the UPDATE that fired this trigger, so the statement never waits on itself.
_LIFECYCLE_MACHINES_BEFORE_UPDATE = f"""
CREATE FUNCTION {SCHEMA}.lifecycle_machines_before_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    v_current xid;
    v_xmin xid;
    v_states integer;
    v_initial integer;
    v_foreign integer;
BEGIN
    -- Exactly one update is legal on a machine row, ever: the one that publishes it. Every
    -- other column must be unchanged, the row must be moving from unpublished to published,
    -- and a published row may not be touched again -- so there is no unpublishing and no
    -- editing of published metadata.
    IF OLD.published_at IS NOT NULL
       OR NEW.published_at IS NULL
       OR NEW.machine_key IS DISTINCT FROM OLD.machine_key
       OR NEW.version IS DISTINCT FROM OLD.version
       OR NEW.read_scope IS DISTINCT FROM OLD.read_scope
       OR NEW.create_scope IS DISTINCT FROM OLD.create_scope
       OR NEW.transition_scope IS DISTINCT FROM OLD.transition_scope
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
    THEN
        RAISE EXCEPTION 'firmbatch: the only legal update to a lifecycle machine is its publication'
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                  DETAIL = 'a published version cannot be unpublished, edited or republished; a '
                           'change to a machine is a new version';
    END IF;

    -- The publication instant is the server's, not the caller's. A caller that could supply
    -- it could date a definition into the past or the future, and ``published_at`` is what
    -- every consumer tests.
    NEW.published_at := pg_catalog.clock_timestamp();

    v_current := pg_catalog.pg_current_xact_id()::pg_catalog.xid;

    -- The lock, before the graph is inspected. See the note above this function.
    SELECT m.xmin INTO v_xmin
    FROM {SCHEMA}.lifecycle_machines m
    WHERE m.machine_key = OLD.machine_key AND m.version = OLD.version
    FOR UPDATE;

    -- ------------------------------------------------- one transaction, or none at all
    --
    -- Every row of the definition must have been written by **this** transaction. That is
    -- what refuses an AUTOCOMMIT registration, and more generally any registration whose
    -- pieces became durable independently: a machine whose states committed in one
    -- transaction and whose edges committed in another was, for a while, a publishable
    -- definition that no single rollback could take back.
    --
    -- ``xmin`` is the transaction that inserted the row, and ``pg_current_xact_id()`` is
    -- this one. Under AUTOCOMMIT the earlier inserts carry a different id, so this refuses
    -- -- measured against a real server rather than reasoned about.
    --
    -- It is also the other half of the race: a state or an edge that another transaction
    -- committed while we waited for the lock carries that transaction's id and is refused
    -- here, so the loser of the race is publication rather than the graph.
    IF v_xmin <> v_current THEN
        RAISE EXCEPTION 'firmbatch: a lifecycle machine is registered and published in one transaction'
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                  DETAIL = 'the machine row was committed by an earlier transaction, so a failure '
                           'during registration could not have taken it back';
    END IF;
    SELECT pg_catalog.count(*) INTO v_foreign
    FROM {SCHEMA}.lifecycle_states s
    WHERE s.machine_key = OLD.machine_key AND s.machine_version = OLD.version
      AND s.xmin <> v_current;
    IF v_foreign > 0 THEN
        RAISE EXCEPTION 'firmbatch: a lifecycle machine is registered and published in one transaction'
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                  DETAIL = 'one or more state rows were committed by an earlier transaction';
    END IF;
    SELECT pg_catalog.count(*) INTO v_foreign
    FROM {SCHEMA}.lifecycle_transition_edges e
    WHERE e.machine_key = OLD.machine_key AND e.machine_version = OLD.version
      AND e.xmin <> v_current;
    IF v_foreign > 0 THEN
        RAISE EXCEPTION 'firmbatch: a lifecycle machine is registered and published in one transaction'
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                  DETAIL = 'one or more edge rows were committed by an earlier transaction';
    END IF;

    -- --------------------------------------------------------- the whole-graph checks
    SELECT pg_catalog.count(*),
           pg_catalog.count(*) FILTER (WHERE s.is_initial)
    INTO v_states, v_initial
    FROM {SCHEMA}.lifecycle_states s
    WHERE s.machine_key = OLD.machine_key AND s.machine_version = OLD.version;

    IF v_states = 0 THEN
        RAISE EXCEPTION 'firmbatch: a lifecycle machine version declares at least one state'
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}';
    END IF;
    IF v_initial <> 1 THEN
        RAISE EXCEPTION 'firmbatch: a lifecycle machine version has exactly one initial state, not %',
            v_initial
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                  DETAIL = 'the partial unique index bounds this at one and cannot require that one '
                           'exists; publication is where existence is checked';
    END IF;

    -- Every edge endpoint is a declared state. The composite foreign keys already refuse
    -- an undeclared one at insert; asserted again here because publication is the place
    -- that says the definition is complete, and a completeness check that trusted an
    -- earlier statement would be a completeness check with a hole in it.
    SELECT pg_catalog.count(*) INTO v_foreign
    FROM {SCHEMA}.lifecycle_transition_edges e
    WHERE e.machine_key = OLD.machine_key AND e.machine_version = OLD.version
      AND (NOT EXISTS (
              SELECT 1 FROM {SCHEMA}.lifecycle_states s
              WHERE s.machine_key = e.machine_key AND s.machine_version = e.machine_version
                AND s.state = e.from_state)
           OR NOT EXISTS (
              SELECT 1 FROM {SCHEMA}.lifecycle_states s
              WHERE s.machine_key = e.machine_key AND s.machine_version = e.machine_version
                AND s.state = e.to_state));
    IF v_foreign > 0 THEN
        RAISE EXCEPTION 'firmbatch: a lifecycle edge names a state this machine version does not declare'
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                  DETAIL = 'the offending names are deliberately not shown';
    END IF;

    -- No outgoing edge from a terminal state. The insert trigger refuses one when the edge
    -- arrives after the state; this catches the other order, where the state is marked
    -- terminal after its edges were written.
    SELECT pg_catalog.count(*) INTO v_foreign
    FROM {SCHEMA}.lifecycle_transition_edges e
    JOIN {SCHEMA}.lifecycle_states s
      ON s.machine_key = e.machine_key AND s.machine_version = e.machine_version
     AND s.state = e.from_state
    WHERE e.machine_key = OLD.machine_key AND e.machine_version = OLD.version
      AND s.is_terminal;
    IF v_foreign > 0 THEN
        RAISE EXCEPTION 'firmbatch: a terminal lifecycle state may not have an outgoing edge'
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                  DETAIL = 'the offending names are deliberately not shown';
    END IF;

    -- The three declared scopes are in the eligible set. Check constraints already refuse
    -- an ineligible one; the same reason as above applies.
    IF NOT (NEW.read_scope = ANY (ARRAY[{_quoted_list(LIFECYCLE_ELIGIBLE_SCOPES)}]::text[])
            AND NEW.create_scope = ANY (ARRAY[{_quoted_list(LIFECYCLE_ELIGIBLE_SCOPES)}]::text[])
            AND NEW.transition_scope = ANY (ARRAY[{_quoted_list(LIFECYCLE_ELIGIBLE_SCOPES)}]::text[]))
    THEN
        RAISE EXCEPTION 'firmbatch: a lifecycle machine requires a scope that is not eligible'
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                  DETAIL = 'the rejected value is deliberately not shown';
    END IF;

    RETURN NEW;
END;
$function$
"""

#: **Serialised against publication, and that is the whole of the second half of this fix.**
#:
#: The first version read ``published_at`` without a lock, so the sequence
#:
#:     T1: insert an edge; sees published_at IS NULL; proceeds
#:     T2: publish; validates a graph that does not yet contain T1's edge; commits
#:     T1: commits
#:
#: left a *published* machine with an edge nothing had ever validated. Reading a value is
#: not deciding on it when somebody else may change it in between.
#:
#: So this takes ``FOR UPDATE`` on the machine row -- the same lock publication takes, before
#: publication looks at any child -- and reads ``published_at`` from the row the lock gives
#: it back. Under ``READ COMMITTED`` a locking read that waits then re-reads the row version
#: the winner committed, so if publication won, this sees it and refuses; and if this won,
#: publication waits and then refuses on the ``xmin`` check, because a child committed by
#: another transaction is exactly what "one transaction, or none at all" excludes.
#:
#: **The lock is taken on the machine, by both children.** Locking the *state* rows an edge
#: refers to would not do: an edge's parent is the machine, publication validates the whole
#: machine, and a state row is not a thing publication takes a lock on. One lockable object,
#: one order, no deadlock.
#:
#: On edges this trigger fires before ``lifecycle_transition_edges_source_not_terminal``:
#: PostgreSQL fires ``BEFORE`` row triggers in name order, and
#: ``..._only_before_publication`` sorts before ``..._source_not_terminal``. So the lock is
#: held before anything else reads a definition row -- and before the composite foreign keys,
#: which are ``AFTER`` triggers and run later still.
_LIFECYCLE_DEFINITION_ROWS_BEFORE_INSERT = f"""
CREATE FUNCTION {SCHEMA}.lifecycle_definition_rows_before_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    v_published timestamptz;
    v_found boolean;
BEGIN
    -- A state or an edge may only be added to a machine that has not been published. After
    -- publication the graph is sealed in every direction: no insert here, and no update or
    -- delete through the immutability trigger.
    SELECT true, m.published_at INTO v_found, v_published
    FROM {SCHEMA}.lifecycle_machines m
    WHERE m.machine_key = NEW.machine_key AND m.version = NEW.machine_version
    FOR UPDATE;

    IF NOT COALESCE(v_found, false) THEN
        -- No machine row to lock, so nothing here can serialise against a publication. The
        -- composite foreign key refuses this row a moment later; saying so now is a better
        -- error than a constraint name.
        RAISE EXCEPTION 'firmbatch: there is no such lifecycle machine version to add a state or an edge to'
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                  DETAIL = 'a definition is a machine row, then its states, then its edges, then its '
                           'publication -- in that order and in one transaction';
    END IF;
    IF v_published IS NOT NULL THEN
        RAISE EXCEPTION 'firmbatch: a published lifecycle machine version cannot gain a state or an edge'
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                  DETAIL = 'a change to a machine is a new version; the published graph is sealed';
    END IF;
    RETURN NEW;
END;
$function$
"""

#: **Who the lifecycle writer is, read from the catalogue and from nowhere else.**
#:
#: The identity every lifecycle-derived write is checked against. It is the role that owns
#: **both** mutation entry points -- and only if that role is not the schema owner, and
#: cannot log in, and holds none of the attributes that would let it reach anything on its
#: own. Nothing about it is supplied: not a setting, not a transaction variable, not a token,
#: not the text of the statement, not the trigger depth. ``SECURITY DEFINER`` makes the
#: executing role the function's owner, and this asks the catalogue who that owner is.
#:
#: Fails closed in every direction. Before the wiring layer has handed the entry points to
#: the writer they are owned by the schema owner and this returns NULL, so every guard
#: below refuses; if one entry point were replaced by a function owned by somebody else, the
#: two would have different owners and this returns NULL; if the writer were ever given
#: ``LOGIN`` or ``BYPASSRLS``, this returns NULL. ``count(*)`` is compared against the total
#: number of functions carrying either name, so a third overload owned by anybody at all
#: also produces NULL rather than a majority.
#:
#: ``SECURITY INVOKER``, deliberately: it reads only ``pg_catalog``, which every role can
#: read, and a definer version would add nothing but a privileged function to grant by
#: mistake. ``STABLE`` because the catalogue does not change inside a statement.
_LIFECYCLE_WRITER_ROLE = f"""
CREATE FUNCTION {SCHEMA}.lifecycle_writer_role() RETURNS name
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    WITH entry_points AS (
        SELECT p.proname, p.prosecdef, p.proowner, n.nspowner
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = '{SCHEMA}'
          AND p.proname IN ('create_lifecycle_instance', 'transition_lifecycle_instance')
    )
    SELECT r.rolname
    FROM entry_points e
    JOIN pg_catalog.pg_roles r ON r.oid = e.proowner
    GROUP BY r.rolname, r.rolcanlogin, r.rolsuper, r.rolbypassrls,
             r.rolcreaterole, r.rolcreatedb, r.rolreplication
    HAVING pg_catalog.count(*) = (SELECT pg_catalog.count(*) FROM entry_points)
       AND pg_catalog.count(DISTINCT e.proname) = 2
       AND pg_catalog.bool_and(e.prosecdef)
       AND pg_catalog.bool_and(e.proowner <> e.nspowner)
       AND NOT r.rolcanlogin
       AND NOT r.rolsuper
       AND NOT r.rolbypassrls
       AND NOT r.rolcreaterole
       AND NOT r.rolcreatedb
       AND NOT r.rolreplication
$function$
"""

#: The Milestone 2.2 framework tables carry two derived columns naming the lifecycle machine
#: a row belongs to, and this is what makes them **derived** rather than **supplied**.
#:
#: They are written by the two lifecycle entry points, which are ``SECURITY DEFINER`` and
#: owned by the lifecycle writer, so they execute as that role. Any other writer -- the
#: application role composing its own ``INSERT``, the generic Milestone 2.2 primitive, the
#: schema owner's direct DML, a definer function the schema owner wrote -- may leave them
#: NULL and may not set them. A caller that could set them could tag its own row with a
#: machine it may read, or untag a row so that reading it needs no machine capability, and
#: the read policy that consults them would decide nothing.
#:
#: The check used to be ``current_user = schema owner``, and that was the defect: the schema
#: owner's ordinary ``INSERT`` and any ``SECURITY DEFINER`` function it happened to own could
#: tag a row, so ownership of the schema was standing in for authorship of the transition.
_LIFECYCLE_FRAMEWORK_TAG_IS_DERIVED = f"""
CREATE FUNCTION {SCHEMA}.lifecycle_framework_tag_is_derived() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF NEW.lifecycle_machine_key IS NULL AND NEW.lifecycle_machine_version IS NULL THEN
        RETURN NEW;
    END IF;

    IF current_user IS DISTINCT FROM {SCHEMA}.lifecycle_writer_role() THEN
        RAISE EXCEPTION 'firmbatch: the lifecycle tag on a framework row is derived, not supplied'
            USING ERRCODE = 'insufficient_privilege',
                  DETAIL = 'it is written by the lifecycle entry points, which execute as the '
                           'dedicated lifecycle writer role; no other identity, the schema owner '
                           'included, may set it -- leave it null';
    END IF;
    RETURN NEW;
END;
$function$
"""

#: The provenance relation is written by the transition entry point and by nothing else.
#:
#: No runtime role holds a privilege on it, which is the first answer; this is the second,
#: and it is the one that keeps holding if a later migration grants something by accident.
#: ``INSERT`` is refused to every identity but the lifecycle writer -- the entry point is
#: ``SECURITY DEFINER`` and owned by that role, so it *is* that role while it runs -- and
#: ``UPDATE`` and ``DELETE`` are refused to everybody, because a replay is only worth
#: anything if the relationship it rests on cannot be edited after the fact.
#:
#: **The schema owner is refused too**, and that is the correction. While the check was
#: ``current_user = schema owner``, direct owner SQL could insert a tagged claim, a tagged
#: event and a provenance row that matched an earlier transition, and the replay accepted the
#: forged association; a second owner-owned definer function had the same authority. Owning
#: the schema is not having produced the transition.
#:
#: And the claim the row names has to be a lifecycle claim of the same tenant and the same
#: machine, as this context sees it, so that provenance can only ever describe a tagged
#: claim: that is what lets the outbox-link guard treat "untagged" as "has no provenance"
#: without holding a privilege on this relation.
_LIFECYCLE_CLAIM_PROVENANCE_GUARD = f"""
CREATE FUNCTION {SCHEMA}.lifecycle_claim_provenance_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    v_claim_is_lifecycle boolean;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'firmbatch: lifecycle claim provenance is immutable'
            USING ERRCODE = '{LIFECYCLE_PROVENANCE_SQLSTATE}',
                  DETAIL = 'it records which transition, instance, revisions and event one claim '
                           'stands for; a replay that could be re-pointed would prove nothing';
    END IF;

    IF current_user IS DISTINCT FROM {SCHEMA}.lifecycle_writer_role() THEN
        RAISE EXCEPTION 'firmbatch: lifecycle claim provenance is written by the transition boundary'
            USING ERRCODE = 'insufficient_privilege',
                  DETAIL = 'it is written by transition_lifecycle_instance(), which executes as the '
                           'dedicated lifecycle writer role, in the same statement sequence that '
                           'produced the transition; no other identity, the schema owner included, '
                           'may write it';
    END IF;

    SELECT true INTO v_claim_is_lifecycle
    FROM {SCHEMA}.idempotency_records r
    WHERE r.id = NEW.idempotency_record_id
      AND r.tenant_id = NEW.tenant_id
      AND r.lifecycle_machine_key = NEW.machine_key
      AND r.lifecycle_machine_version = NEW.machine_version
      AND pg_catalog.starts_with(r.operation, '{LIFECYCLE_NAMESPACE_PREFIX}');
    IF NOT COALESCE(v_claim_is_lifecycle, false) THEN
        RAISE EXCEPTION 'firmbatch: lifecycle claim provenance names a claim that is not a lifecycle claim of this machine'
            USING ERRCODE = '{LIFECYCLE_PROVENANCE_SQLSTATE}',
                  DETAIL = 'the claim is absent, is in another tenant, is untagged, or is tagged with '
                           'another machine; the cases are deliberately indistinguishable';
    END IF;

    NEW.created_at := pg_catalog.clock_timestamp();
    RETURN NEW;
END;
$function$
"""

#: **A generic outbox writer proves its link before any constraint sees it.**
#:
#: ``idempotency_record_id`` is a column the application role may name -- the Milestone 2.2
#: primitive links each event to the claim it wrote. Left to the constraints, that column
#: was an existence oracle: a hidden lifecycle claim's id produced a uniqueness violation on
#: the one-event-per-claim index (the transition already linked its event), an absent id
#: produced a foreign-key violation, and the foreign key is checked with row security
#: bypassed so the hidden row was found. Success versus one error versus another was the
#: answer to "does this claim exist", for rows the read policies hide.
#:
#: This runs first. ``BEFORE INSERT`` row triggers fire before the tuple is formed, so
#: before the unique index is consulted -- including the ``ON CONFLICT`` arbiter -- and long
#: before the referential-integrity trigger, which is an ``AFTER`` trigger. Two identities:
#:
#: * the **lifecycle writer** is the transition boundary linking the claim it just wrote, and
#:   passes: the claim is tagged, the event is tagged, and the provenance guard ties them;
#: * **anybody else** is a generic writer, and its link must name a claim this authenticated
#:   context may read -- the ``SELECT`` below runs as the invoker under ``FORCE`` row
#:   security, so the read policy decides visibility and nothing here bypasses it -- in the
#:   row's own tenant, untagged, and outside the reserved namespace. Untagged is what makes
#:   "has no provenance" true without reading the provenance relation, which no runtime role
#:   may reach: the provenance guard refuses a row for an untagged claim.
#:
#: **One raise site and one message** for every way the check can fail. PostgreSQL puts the
#: plpgsql line number in the CONTEXT of an exception, so two raise sites would be two
#: distinguishable refusals; and a hidden claim, an absent claim, another tenant's claim and
#: a lifecycle claim this context *can* read all have to look the same from outside.
_OUTBOX_EVENTS_LINK_IS_AUTHORIZED = f"""
CREATE FUNCTION {SCHEMA}.outbox_events_link_is_authorized() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    v_tenant_id uuid;
    v_operation text;
    v_machine_key text;
    v_linkable boolean;
BEGIN
    IF NEW.idempotency_record_id IS NULL THEN
        RETURN NEW;
    END IF;
    IF current_user IS NOT DISTINCT FROM {SCHEMA}.lifecycle_writer_role() THEN
        RETURN NEW;
    END IF;

    SELECT r.tenant_id, r.operation, r.lifecycle_machine_key
    INTO v_tenant_id, v_operation, v_machine_key
    FROM {SCHEMA}.idempotency_records r
    WHERE r.id = NEW.idempotency_record_id;

    v_linkable := FOUND
        AND v_tenant_id IS NOT DISTINCT FROM NEW.tenant_id
        AND v_tenant_id IS NOT DISTINCT FROM {SCHEMA}.auth_tenant_id()
        AND v_machine_key IS NULL
        AND NOT pg_catalog.starts_with(v_operation, '{LIFECYCLE_NAMESPACE_PREFIX}');

    IF NOT COALESCE(v_linkable, false) THEN
        RAISE EXCEPTION 'firmbatch: an outbox event may only be linked to a generic idempotency claim this context may read'
            USING ERRCODE = '{OUTBOX_LINK_SQLSTATE}',
                  DETAIL = 'the claim is absent, belongs to another tenant, is not readable by this '
                           'authenticated context, or belongs to a lifecycle machine; the cases are '
                           'deliberately indistinguishable';
    END IF;
    RETURN NEW;
END;
$function$
"""

#: **The canonical request descriptor, and PostgreSQL is where it is canonical.**
#:
#: The fingerprint used to arrive as a parameter, computed in Python. That made it a
#: caller-controlled value in exactly the place a caller must not control one: a raw-SQL
#: caller could move instance A while storing the fingerprint of a request for instance B,
#: and the next genuine request for B would then replay A's result.
#:
#: There is now no parameter to supply. The descriptor is built here from the arguments the
#: call actually executed -- the authenticated tenant, the derived operation, the instance,
#: the machine version the instance *pins*, the expectation, the target, and the validated
#: reason and details -- and hashed here. Python computes no lifecycle fingerprint at all,
#: so there is no second implementation to keep in step and no parity to prove.
#:
#: ``jsonb`` is what makes it canonical rather than merely deterministic: object keys are
#: stored in a normalised order and duplicates collapse at parse time, so the text form of a
#: descriptor does not depend on how it was written. NULL becomes ``null`` rather than
#: disappearing, so an absent reason is a value and not an omission.
_LIFECYCLE_REQUEST_FINGERPRINT = f"""
CREATE FUNCTION {SCHEMA}.lifecycle_request_fingerprint(
    p_tenant_id uuid,
    p_operation text,
    p_instance_id uuid,
    p_machine_key text,
    p_machine_version integer,
    p_expected_state text,
    p_expected_revision integer,
    p_target_state text,
    p_reason text,
    p_details jsonb
) RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.encode(
        pg_catalog.sha256(
            pg_catalog.convert_to(
                pg_catalog.jsonb_build_object(
                    'tenant', p_tenant_id,
                    'operation', p_operation,
                    'lifecycle_instance_id', p_instance_id,
                    'machine_key', p_machine_key,
                    'machine_version', p_machine_version,
                    'expected_state', p_expected_state,
                    'expected_revision', p_expected_revision,
                    'target_state', p_target_state,
                    'reason', p_reason,
                    'details', COALESCE(p_details, '{{}}'::jsonb)
                )::pg_catalog.text,
                'UTF8'
            )
        ),
        'hex'
    )
$function$
"""

#: One claim, verified end to end, or nothing.
#:
#: **Non-NULL machine tags are not provenance.** The tag says which machine a framework row
#: belongs to and is what the read policies consult; it says nothing about *which transition*
#: a claim stands for. So a replay resolves the whole chain -- claim, provenance, transition,
#: instance, event -- insists that every link agrees with every other, and additionally
#: insists that the stored result describes the transition the provenance names and that the
#: instance actually reached the revision that transition produced.
#:
#: Reads the framework tables as the caller sees them: row security is ``FORCE``d, this
#: runs inside a definer function owned by the lifecycle writer, and the writer owns none of
#: the tables and holds no ``BYPASSRLS`` -- so the policies still evaluate against the
#: caller's context. A claim this context may not read is a claim it cannot be handed -- but
#: by the time this is called the context has already been authorised for the machine the
#: *instance* pins, and the operation namespace is derived from that machine, so there is no
#: readable-elsewhere claim in this namespace to be refused by.
_LIFECYCLE_REPLAY_CLAIM = f"""
CREATE FUNCTION {SCHEMA}.lifecycle_replay_claim(
    p_operation text,
    p_idempotency_key text,
    p_machine_key text,
    p_machine_version integer,
    p_fingerprint text
) RETURNS TABLE (o_record_id uuid, o_event_id uuid, o_result jsonb)
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    v_claim_id uuid;
    v_stored_fingerprint text;
    v_record_id uuid;
    v_event_id uuid;
    v_result jsonb;
BEGIN
    SELECT r.id, r.request_fingerprint INTO v_claim_id, v_stored_fingerprint
    FROM {SCHEMA}.idempotency_records r
    WHERE r.operation = p_operation
      AND r.idempotency_key = p_idempotency_key;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT r.id, p.outbox_event_id, r.result
    INTO v_record_id, v_event_id, v_result
    FROM {SCHEMA}.idempotency_records r
    JOIN {SCHEMA}.lifecycle_claim_provenance p
      ON p.idempotency_record_id = r.id AND p.tenant_id = r.tenant_id
    JOIN {SCHEMA}.lifecycle_transitions t
      ON t.id = p.lifecycle_transition_id AND t.tenant_id = p.tenant_id
    JOIN {SCHEMA}.lifecycle_instances i
      ON i.id = p.lifecycle_instance_id AND i.tenant_id = p.tenant_id
    JOIN {SCHEMA}.outbox_events e
      ON e.id = p.outbox_event_id AND e.tenant_id = p.tenant_id
    WHERE r.id = v_claim_id
      -- the claim is tagged with the machine the provenance names, and that machine is the
      -- one this request resolved
      AND r.lifecycle_machine_key = p.machine_key
      AND r.lifecycle_machine_version = p.machine_version
      AND p.machine_key = p_machine_key
      AND p.machine_version = p_machine_version
      -- the transition is of that machine, that instance, those revisions
      AND t.lifecycle_instance_id = p.lifecycle_instance_id
      AND t.machine_key = p.machine_key
      AND t.machine_version = p.machine_version
      AND t.from_revision = p.from_revision
      AND t.to_revision = p.to_revision
      -- the event is the one linked to this claim, and is tagged with the same machine
      AND e.idempotency_record_id = r.id
      AND e.lifecycle_machine_key = p.machine_key
      AND e.lifecycle_machine_version = p.machine_version
      -- the instance really did reach the revision the transition produced
      AND i.machine_key = p.machine_key
      AND i.machine_version = p.machine_version
      AND i.revision >= p.to_revision
      -- and the stored result describes that transition rather than some other one
      AND r.result -> 'transition_id' = pg_catalog.to_jsonb(t.id)
      AND r.result -> 'lifecycle_instance_id' = pg_catalog.to_jsonb(p.lifecycle_instance_id)
      AND r.result -> 'machine_key' = pg_catalog.to_jsonb(p.machine_key)
      AND r.result -> 'machine_version' = pg_catalog.to_jsonb(p.machine_version)
      AND r.result -> 'from_state' = pg_catalog.to_jsonb(t.from_state)
      AND r.result -> 'to_state' = pg_catalog.to_jsonb(t.to_state)
      AND r.result -> 'from_revision' = pg_catalog.to_jsonb(t.from_revision)
      AND r.result -> 'to_revision' = pg_catalog.to_jsonb(t.to_revision);

    IF NOT FOUND THEN
        RAISE EXCEPTION 'firmbatch: that idempotency key is claimed by a record with no verifiable lifecycle transition behind it'
            USING ERRCODE = '{LIFECYCLE_PROVENANCE_SQLSTATE}',
                  DETAIL = 'a lifecycle replay returns what a transition recorded, so it requires the '
                           'protected link between the claim, the transition, the instance and the '
                           'event; a machine tag alone is not that link';
    END IF;

    -- The fingerprint comparison is the whole of "the same request", and it happens here
    -- against a value this database derived rather than one anybody supplied.
    IF v_stored_fingerprint IS DISTINCT FROM p_fingerprint THEN
        RAISE EXCEPTION 'firmbatch: that idempotency key was already used for a different lifecycle request'
            USING ERRCODE = '{LIFECYCLE_KEY_REUSE_SQLSTATE}',
                  DETAIL = 'retry the original request with this key, or use a new key for the new '
                           'one; nothing about the existing request is shown';
    END IF;

    o_record_id := v_record_id;
    o_event_id := v_event_id;
    o_result := v_result;
    RETURN NEXT;
END;
$function$
"""

#: The audit append the lifecycle entry points use, and the only writer that may tag a row.
#:
#: ``append_audit_event`` cannot do this job: it is the generic path, it is granted to both
#: runtime roles, and giving it a tag parameter would give every caller one. So the lifecycle
#: kernel gets its own internal append, executable by nobody, called from the two definer
#: entry points -- which is what makes "an audit row in the ``lifecycle.`` namespace is
#: tagged, and a tagged row was written by the lifecycle boundary" a fact rather than a
#: convention. The check constraint on ``audit_events`` ties the two together in the other
#: direction: a ``lifecycle.`` action with no tag is refused, so the generic function cannot
#: write an untagged row that looks like one.
_APPEND_LIFECYCLE_AUDIT_EVENT = f"""
CREATE FUNCTION {SCHEMA}.append_lifecycle_audit_event(
    p_action text,
    p_outcome text,
    p_resource_type text,
    p_resource_id uuid,
    p_details jsonb,
    p_machine_key text,
    p_machine_version integer
) RETURNS uuid
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    v_context {SCHEMA}.auth_context_row;
    v_id uuid;
BEGIN
    v_context := {SCHEMA}.auth_context();
    IF v_context.tenant_id IS NULL THEN
        RAISE EXCEPTION 'firmbatch: appending an audit event requires an authenticated context'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- The action is a literal at both call sites, so the shape and format checks the
    -- generic append makes for caller-supplied text have nothing to catch here. The
    -- metadata policy still applies: a details document is assembled from a caller's
    -- machine key and state names.
    PERFORM {SCHEMA}.audit_require_acceptable_details(p_details);

    v_id := pg_catalog.gen_random_uuid();
    INSERT INTO {SCHEMA}.audit_events (
        id, tenant_id, actor_kind, actor_principal_id, actor_binding_id,
        action, outcome, resource_type, resource_id, correlation_id, details,
        lifecycle_machine_key, lifecycle_machine_version
    )
    VALUES (
        v_id, v_context.tenant_id, v_context.actor_kind, v_context.principal_id, v_context.binding_id,
        p_action, p_outcome, p_resource_type, p_resource_id, NULL,
        COALESCE(p_details, '{{}}'::jsonb),
        p_machine_key, p_machine_version
    );
    RETURN v_id;
END;
$function$
"""

_LIFECYCLE_EDGES_CHECK_SOURCE = f"""
CREATE FUNCTION {SCHEMA}.lifecycle_edges_check_source() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    -- The one graph rule this kernel imposes beyond "the states are known". A terminal
    -- state is the definition's statement that the machine stops there; an outgoing edge
    -- from one is a contradiction inside a single definition rather than a policy choice.
    --
    -- Deliberately **no acyclicity rule**: a cycle is a legitimate machine (offered ->
    -- accepted -> revoked -> offered), and a kernel that assumed otherwise would have to be
    -- argued with by every domain that needs one.
    --
    -- Reads the state table **directly** rather than through
    -- the publication-aware terminal reader. That reader requires publication, which is exactly
    -- right for a consumer and exactly wrong here: an edge is inserted while the machine is
    -- still a draft, so a publication-aware reader would answer "not terminal" for every
    -- state and this trigger would never fire. Publication re-checks the same rule over the
    -- finished graph, which is what catches the other order -- a state marked terminal after
    -- its edges were written.
    IF COALESCE(
        (SELECT s.is_terminal
         FROM {SCHEMA}.lifecycle_states s
         WHERE s.machine_key = NEW.machine_key
           AND s.machine_version = NEW.machine_version
           AND s.state = NEW.from_state),
        false
    ) THEN
        RAISE EXCEPTION 'firmbatch: a terminal lifecycle state may not have an outgoing edge'
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                  DETAIL = 'the state is marked terminal, so the machine stops there; the offending '
                           'names are deliberately not shown';
    END IF;
    RETURN NEW;
END;
$function$
"""

_LIFECYCLE_INSTANCES_BEFORE_INSERT = f"""
CREATE FUNCTION {SCHEMA}.lifecycle_instances_before_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    v_initial text;
BEGIN
    -- Where an instance starts is the machine's decision, not the writer's. Enforced here
    -- rather than only in create_lifecycle_instance() so that it binds the owner and any
    -- future writer: a direct INSERT naming 'completed' would otherwise create a job that
    -- had never run.
    v_initial := {SCHEMA}.lifecycle_initial_state(NEW.machine_key, NEW.machine_version);
    IF v_initial IS NULL THEN
        RAISE EXCEPTION 'firmbatch: this lifecycle machine version has no initial state'
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                  DETAIL = 'a machine version is registered with exactly one initial state; this one '
                           'has none, so no instance of it can be created';
    END IF;
    IF NEW.current_state IS DISTINCT FROM v_initial THEN
        RAISE EXCEPTION 'firmbatch: a lifecycle instance starts in its machine''s initial state'
            USING ERRCODE = '{LIFECYCLE_NOT_ALLOWED_SQLSTATE}',
                  DETAIL = 'the requested starting state is not the initial state of this machine '
                           'version; the offending value is deliberately not shown';
    END IF;
    -- Revision zero and both timestamps are server facts. A caller that could supply them
    -- could supply a revision that a later compare-and-swap would accept, or a created_at
    -- from its own clock.
    NEW.revision := 0;
    NEW.created_at := pg_catalog.clock_timestamp();
    NEW.updated_at := NEW.created_at;
    RETURN NEW;
END;
$function$
"""

_LIFECYCLE_INSTANCES_BEFORE_UPDATE = f"""
CREATE FUNCTION {SCHEMA}.lifecycle_instances_before_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    -- **The graph, enforced under every writer.** transition_lifecycle_instance() checks
    -- the edge before it writes, and that check is a courtesy to the caller: this one is
    -- the property. It sees OLD and NEW together, which no row-level-security policy can,
    -- and it therefore holds for the owner, for a future definer function, and for
    -- anything a later migration adds.
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.machine_key IS DISTINCT FROM OLD.machine_key
       OR NEW.machine_version IS DISTINCT FROM OLD.machine_version
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
    THEN
        RAISE EXCEPTION 'firmbatch: a lifecycle instance''s identity and machine are immutable'
            USING ERRCODE = '{LIFECYCLE_NOT_ALLOWED_SQLSTATE}',
                  DETAIL = 'id, tenant, machine key, machine version and creation time are fixed '
                           'when the instance is created';
    END IF;
    IF NEW.revision IS DISTINCT FROM OLD.revision + 1 THEN
        RAISE EXCEPTION 'firmbatch: a lifecycle revision advances by exactly one'
            USING ERRCODE = '{LIFECYCLE_NOT_ALLOWED_SQLSTATE}',
                  DETAIL = 'the revision is the compare-and-swap token; skipping or reusing one '
                           'would make two writers'' expectations agree when they should not';
    END IF;
    IF {SCHEMA}.lifecycle_state_is_terminal(OLD.machine_key, OLD.machine_version, OLD.current_state) THEN
        RAISE EXCEPTION 'firmbatch: a terminal lifecycle state cannot be left'
            USING ERRCODE = '{LIFECYCLE_NOT_ALLOWED_SQLSTATE}',
                  DETAIL = 'the machine stops in this state; the offending values are deliberately '
                           'not shown';
    END IF;
    IF NOT {SCHEMA}.lifecycle_edge_exists(
        OLD.machine_key, OLD.machine_version, OLD.current_state, NEW.current_state
    ) THEN
        RAISE EXCEPTION 'firmbatch: that lifecycle transition is not an edge of this machine version'
            USING ERRCODE = '{LIFECYCLE_NOT_ALLOWED_SQLSTATE}',
                  DETAIL = 'the machine declares its allowed moves and this is not one of them; the '
                           'offending values are deliberately not shown';
    END IF;
    -- Server wall-clock, overwritten unconditionally, for the reason audit_events'
    -- occurred_at is: now() is transaction-start time, so a caller that opened its
    -- transaction early could otherwise date a move into the past by supplying nothing.
    NEW.updated_at := pg_catalog.clock_timestamp();
    RETURN NEW;
END;
$function$
"""

_LIFECYCLE_TRANSITIONS_BEFORE_INSERT = f"""
CREATE FUNCTION {SCHEMA}.lifecycle_transitions_before_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    NEW.occurred_at := pg_catalog.clock_timestamp();
    RETURN NEW;
END;
$function$
"""


# ------------------------------------------------------------------------- entry points

_CREATE_LIFECYCLE_INSTANCE = f"""
CREATE FUNCTION {SCHEMA}.create_lifecycle_instance(
    p_machine_key text,
    p_machine_version integer
) RETURNS TABLE (instance_id uuid, initial_state text, event_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_context {SCHEMA}.auth_context_row;
    v_scope text;
    v_initial text;
    v_id uuid;
    v_event_id uuid;
    v_shape text;
BEGIN
    v_context := {SCHEMA}.auth_context();
    -- The tenant is NOT an argument, here or anywhere in this migration. It is whatever
    -- the transaction authenticated as, so an instance cannot be created into a tenant the
    -- caller does not already hold.
    IF v_context.tenant_id IS NULL THEN
        RAISE EXCEPTION 'firmbatch: creating a lifecycle instance requires an authenticated context'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Shape before format, and neither echoes. A machine key is caller-supplied text like
    -- any other, and the identifier grammar below happily accepts an all-lowercase bearer
    -- credential -- so a credential pasted here would be quoted by the check that refused
    -- it, into an exception, a traceback and a retained log.
    v_shape := {SCHEMA}.secret_shape(p_machine_key);
    IF v_shape IS NOT NULL THEN
        RAISE EXCEPTION 'firmbatch: the lifecycle machine key looks like %', v_shape
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the value is deliberately not shown';
    END IF;
    IF p_machine_key IS NULL OR p_machine_key !~ '{LIFECYCLE_NAME_REGEX}' THEN
        RAISE EXCEPTION 'firmbatch: the lifecycle machine key is not a lowercase identifier'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the value is deliberately not shown';
    END IF;
    IF p_machine_version IS NULL OR p_machine_version < 1 THEN
        RAISE EXCEPTION 'firmbatch: a lifecycle machine version is a positive integer'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- The required capability is read from the protected definition, never supplied. A
    -- machine version that does not exist yields NULL here and is refused as a definition
    -- error: machines are global, so this reveals nothing about any tenant.
    v_scope := {SCHEMA}.lifecycle_required_scope(p_machine_key, p_machine_version, 'create');
    IF v_scope IS NULL THEN
        RAISE EXCEPTION 'firmbatch: no such lifecycle machine version is registered'
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                  DETAIL = 'machine definitions are global and immutable; register one as the schema '
                           'owner before creating instances of it';
    END IF;
    IF NOT COALESCE(v_scope = ANY (v_context.scopes), false) THEN
        RAISE EXCEPTION 'firmbatch: creating an instance of this lifecycle machine is not permitted'
            USING ERRCODE = 'insufficient_privilege',
                  DETAIL = 'the machine version declares which capability its instances require, and '
                           'this context does not hold it';
    END IF;
    -- **Both capabilities, checked here.** Creating an instance commits an outbox intent,
    -- and appending one is what ``mutation:execute`` is. Checking it inside the function is
    -- what makes it hold for a caller writing raw SQL: the insert policy on outbox_events
    -- would refuse anyway, but a refusal from a policy several statements later is a worse
    -- answer than a refusal that names the capability.
    IF NOT COALESCE('mutation:execute' = ANY (v_context.scopes), false) THEN
        RAISE EXCEPTION 'firmbatch: creating a lifecycle instance requires the mutation:execute scope'
            USING ERRCODE = 'insufficient_privilege',
                  DETAIL = 'it commits a durable outbox intent alongside the instance, and appending '
                           'one is what that capability is';
    END IF;

    v_initial := {SCHEMA}.lifecycle_initial_state(p_machine_key, p_machine_version);
    IF v_initial IS NULL THEN
        RAISE EXCEPTION 'firmbatch: this lifecycle machine version has no initial state'
            USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                  DETAIL = 'a machine version is registered with exactly one initial state';
    END IF;

    -- Generated here rather than returned by the INSERT: PostgreSQL applies SELECT
    -- policies to INSERT ... RETURNING, so a RETURNING clause would make creating an
    -- instance require the machine's *read* scope as well as its create scope.
    v_id := pg_catalog.gen_random_uuid();
    INSERT INTO {SCHEMA}.lifecycle_instances
        (id, tenant_id, machine_key, machine_version, current_state)
    VALUES (v_id, v_context.tenant_id, p_machine_key, p_machine_version, v_initial);

    -- One audit event, from the context, inside the caller's transaction. Written here
    -- rather than in Python so that it holds for a caller that writes the SQL itself:
    -- creating durable tenant state without a record of who did it is the outcome the
    -- trail exists to prevent.
    --
    -- Through the lifecycle append rather than the generic one, and that is what makes the
    -- audit row *tagged*: an audit event for a lifecycle action carries the instance id in
    -- ``resource_id`` and the machine, the state and (for a transition) the revisions in
    -- ``details``, so ``audit:read`` alone read the trajectory of a machine the credential
    -- holds no capability for. A tagged row's read policy additionally requires that
    -- machine's declared read scope.
    PERFORM {SCHEMA}.append_lifecycle_audit_event(
        'lifecycle.instance_created',
        'succeeded',
        'lifecycle_instance',
        v_id,
        pg_catalog.jsonb_build_object(
            'machine_key', p_machine_key,
            'machine_version', p_machine_version,
            'initial_state', v_initial
        ),
        p_machine_key,
        p_machine_version
    );

    -- And one outbox intent, written **here** rather than in Python. That is the whole of
    -- the correction: while the event was appended by the caller after this function
    -- returned, an application role executing arbitrary SQL could call this function and
    -- simply not append one -- a durable lifecycle row with nothing announcing it. There is
    -- now no way to change lifecycle state without every artifact, because the one call
    -- that changes it writes them all.
    v_event_id := pg_catalog.gen_random_uuid();
    INSERT INTO {SCHEMA}.outbox_events (
        id, tenant_id, idempotency_record_id, event_type, aggregate_type, aggregate_id,
        attributes, lifecycle_machine_key, lifecycle_machine_version
    )
    VALUES (
        v_event_id, v_context.tenant_id, NULL,
        p_machine_key || '.created', p_machine_key, v_id,
        pg_catalog.jsonb_build_object(
            'machine_version', p_machine_version,
            'initial_state', v_initial
        ),
        p_machine_key, p_machine_version
    );

    -- All three, because the caller cannot read the rows back: creating an instance
    -- requires the machine's *create* capability and reading one requires its *read*
    -- capability, and a caller that holds only the first would otherwise be handed an id
    -- and no way to learn where the instance starts or what was announced about it.
    instance_id := v_id;
    initial_state := v_initial;
    event_id := v_event_id;
    RETURN NEXT;
END;
$function$
"""

_TRANSITION_LIFECYCLE_INSTANCE = f"""
CREATE FUNCTION {SCHEMA}.transition_lifecycle_instance(
    p_instance_id uuid,
    p_expected_state text,
    p_expected_revision integer,
    p_target_state text,
    p_reason text,
    p_details jsonb,
    -- **The whole of the caller's say in idempotency: one key, or NULL.**
    --
    -- The operation name and the request fingerprint used to be parameters too, and both
    -- are now derived here. The operation is ``lifecycle.transition.<machine>.v<version>``,
    -- built from the machine the *instance* pins -- so a caller cannot choose which
    -- uniqueness domain its key lands in, and two machines never share one. The fingerprint
    -- is computed from the arguments this call actually executed -- so a caller cannot bind
    -- a claim to a request it did not make, which is what a raw-SQL caller could do while
    -- it supplied one: move instance A, store the fingerprint of a request for B, and let
    -- the next genuine request for B replay A.
    p_idempotency_key text
) RETURNS TABLE (
    -- Prefixed, and the prefix is load-bearing rather than a style. An ``OUT`` parameter is
    -- an ordinary plpgsql variable, so a column named ``machine_key`` in
    -- ``lifecycle_instances`` and an output named ``machine_key`` make every reference to
    -- it ambiguous -- SQLSTATE 42702, raised at *runtime* from inside the UPDATE below,
    -- where it would have read as an unexplained database failure rather than as a naming
    -- collision. ``db/lifecycle.py`` aliases these back to their plain names in the one
    -- statement that calls this function.
    o_transition_id uuid,
    o_machine_key text,
    o_machine_version integer,
    o_from_revision integer,
    o_to_revision integer,
    o_event_id uuid,
    o_record_id uuid,
    o_result jsonb,
    o_operation text,
    o_replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_context {SCHEMA}.auth_context_row;
    v_machine_key text;
    v_machine_version integer;
    v_current_state text;
    v_current_revision integer;
    v_scope text;
    v_updated integer;
    v_to_revision integer;
    v_transition_id uuid;
    v_event_id uuid;
    v_record_id uuid;
    v_result jsonb;
    v_claiming boolean;
    v_operation text;
    v_fingerprint text;
    v_details jsonb;
    v_shape text;
    v_replay record;
    v_constraint text;
BEGIN
    v_context := {SCHEMA}.auth_context();
    IF v_context.tenant_id IS NULL THEN
        RAISE EXCEPTION 'firmbatch: transitioning a lifecycle instance requires an authenticated context'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- **Both capabilities, inside the database.** The machine's transition scope is checked
    -- below, once the instance has told us which machine it runs; ``mutation:execute`` is
    -- checked here because every transition commits an idempotency claim, an outbox intent,
    -- or both, and appending those is what that capability is. Checking it in the function
    -- rather than only in Python is what makes it hold for a caller writing raw SQL.
    IF NOT COALESCE('mutation:execute' = ANY (v_context.scopes), false) THEN
        RAISE EXCEPTION 'firmbatch: transitioning a lifecycle instance requires the mutation:execute scope'
            USING ERRCODE = 'insufficient_privilege',
                  DETAIL = 'a transition commits a durable outbox intent, and appending one is what '
                           'that capability is';
    END IF;

    -- ------------------------------------------------------------------ validate first
    --
    -- Everything the caller supplied is checked before anything is read or written, so a
    -- malformed value cannot produce a partial effect. Shape before format throughout, and
    -- no refusal repeats what it refused.
    IF p_instance_id IS NULL THEN
        RAISE EXCEPTION 'firmbatch: a lifecycle transition names the instance it moves'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_expected_revision IS NULL OR p_expected_revision < 0 THEN
        RAISE EXCEPTION 'firmbatch: the expected lifecycle revision is a non-negative integer'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    v_shape := {SCHEMA}.secret_shape(p_expected_state);
    IF v_shape IS NULL THEN
        v_shape := {SCHEMA}.secret_shape(p_target_state);
    END IF;
    IF v_shape IS NOT NULL THEN
        RAISE EXCEPTION 'firmbatch: a lifecycle state name looks like %', v_shape
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'a state names a position in a machine; the value is deliberately not shown';
    END IF;
    IF p_expected_state IS NULL OR p_expected_state !~ '{LIFECYCLE_NAME_REGEX}'
       OR p_target_state IS NULL OR p_target_state !~ '{LIFECYCLE_NAME_REGEX}'
    THEN
        RAISE EXCEPTION 'firmbatch: a lifecycle state name is a lowercase identifier'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the offending value is deliberately not shown';
    END IF;

    IF p_reason IS NOT NULL THEN
        v_shape := {SCHEMA}.secret_shape(p_reason);
        IF v_shape IS NOT NULL THEN
            RAISE EXCEPTION 'firmbatch: the lifecycle transition reason looks like %', v_shape
                USING ERRCODE = 'invalid_parameter_value',
                      DETAIL = 'a reason is a short metadata-only note; the value is not shown';
        END IF;
        IF pg_catalog.length(p_reason) < 1
           OR pg_catalog.length(p_reason) > {MAX_LIFECYCLE_REASON_LENGTH}
        THEN
            RAISE EXCEPTION 'firmbatch: the lifecycle transition reason is longer than the % allowed',
                {MAX_LIFECYCLE_REASON_LENGTH}
                USING ERRCODE = 'invalid_parameter_value',
                      DETAIL = 'the value and its length are deliberately not shown';
        END IF;
    END IF;
    -- The one bounded-metadata policy, shared rather than copied. Its refusals name the
    -- rule and the position and never the content, which is what makes it safe to apply to
    -- a document the caller supplied.
    PERFORM {SCHEMA}.audit_require_acceptable_details(p_details);
    -- Normalised once, here, and used for the history row, the fingerprint and the audit
    -- document alike. A fingerprint computed over one shape and a row written in another
    -- would make an identical retry look like a different request.
    v_details := COALESCE(p_details, '{{}}'::jsonb);

    -- ------------------------------------------------------------------ the claim, if any
    v_claiming := p_idempotency_key IS NOT NULL;
    IF v_claiming THEN
        v_shape := {SCHEMA}.secret_shape(p_idempotency_key);
        IF v_shape IS NOT NULL THEN
            RAISE EXCEPTION 'firmbatch: an idempotency key looks like %', v_shape
                USING ERRCODE = 'invalid_parameter_value',
                      DETAIL = 'a key is stored verbatim; the value is deliberately not shown';
        END IF;
        IF p_idempotency_key !~ '{IDEMPOTENCY_KEY_REGEX}' THEN
            RAISE EXCEPTION 'firmbatch: the idempotency key is not acceptable'
                USING ERRCODE = 'invalid_parameter_value',
                      DETAIL = 'the offending value is deliberately not shown';
        END IF;
        -- The recovery below re-reads a row a concurrent winner has just committed, and
        -- only READ COMMITTED takes a fresh snapshot per statement. Enforced here rather
        -- than only in Python, because the recovery is here.
        PERFORM {SCHEMA}.auth_require_read_committed();
    END IF;

    -- --------------------------------------------------------------- resolve, in tenant
    --
    -- Scoped to the authenticated tenant, so an instance belonging to another tenant is
    -- simply not found -- and "not found" produces the same conflict a stale revision
    -- does. That identity is the point: the refusal must not answer "does this id exist
    -- somewhere else".
    --
    -- Row security is FORCEd and this function runs as the schema owner, so the instance
    -- read policy evaluates here too: an instance whose machine's *read* scope this context
    -- does not hold is not found either, indistinguishably.
    SELECT i.machine_key, i.machine_version, i.current_state, i.revision
    INTO v_machine_key, v_machine_version, v_current_state, v_current_revision
    FROM {SCHEMA}.lifecycle_instances i
    WHERE i.id = p_instance_id
      AND i.tenant_id = v_context.tenant_id;

    IF FOUND THEN
        -- The capability comes from the machine version this instance pinned, which is
        -- protected data. There is no parameter through which a caller could name one.
        v_scope := {SCHEMA}.lifecycle_required_scope(
            v_machine_key, v_machine_version, 'transition'
        );
        IF v_scope IS NULL THEN
            RAISE EXCEPTION 'firmbatch: this lifecycle instance pins a machine version that is not registered'
                USING ERRCODE = '{LIFECYCLE_DEFINITION_SQLSTATE}',
                      DETAIL = 'the definition a persisted instance refers to is missing, which is a '
                               'schema problem rather than a stale transition';
        END IF;
        IF NOT COALESCE(v_scope = ANY (v_context.scopes), false) THEN
            RAISE EXCEPTION 'firmbatch: transitioning this lifecycle machine is not permitted'
                USING ERRCODE = 'insufficient_privilege',
                      DETAIL = 'the machine version declares which capability its instances require, '
                               'and this context does not hold it';
        END IF;

        -- ------------------------------------------ the derived operation and fingerprint
        --
        -- **After authorisation on the machine this request actually names, and before any
        -- claim is looked up.** That order is what stops a claim being an existence oracle:
        -- a context that cannot reach this machine never gets as far as asking whether a key
        -- is taken in its namespace -- and the namespace is per-machine, so a key taken for
        -- a machine this context cannot read is not in a namespace it can reach at all.
        IF v_claiming THEN
            v_operation := '{LIFECYCLE_TRANSITION_OPERATION_PREFIX}'
                           || v_machine_key || '.v' || v_machine_version::text;
            v_fingerprint := {SCHEMA}.lifecycle_request_fingerprint(
                v_context.tenant_id, v_operation, p_instance_id,
                v_machine_key, v_machine_version,
                p_expected_state, p_expected_revision, p_target_state,
                p_reason, v_details
            );
            SELECT * INTO v_replay FROM {SCHEMA}.lifecycle_replay_claim(
                v_operation, p_idempotency_key, v_machine_key, v_machine_version, v_fingerprint
            );
            IF FOUND THEN
                o_transition_id := (v_replay.o_result ->> 'transition_id')::uuid;
                o_machine_key := v_machine_key;
                o_machine_version := v_machine_version;
                o_from_revision := (v_replay.o_result ->> 'from_revision')::integer;
                o_to_revision := (v_replay.o_result ->> 'to_revision')::integer;
                o_event_id := v_replay.o_event_id;
                o_record_id := v_replay.o_record_id;
                o_result := v_replay.o_result;
                o_operation := v_operation;
                o_replayed := true;
                RETURN NEXT;
                RETURN;
            END IF;
        END IF;

        -- -------------------------------------------- the whole expectation, before graph
        --
        -- **Both** the expected state and the expected revision are compared to the
        -- persisted row before any graph question is asked, and a mismatch in either falls
        -- through to the one conflict below. The order is not cosmetic; each half of it was
        -- measured.
        --
        -- With the graph checked first, a caller that lost a race and re-read *after* the
        -- winner committed asked "is my target an edge from the state the winner left?" --
        -- and for ``draft -> active`` raced against itself, the answer was "no, active ->
        -- active is not an edge". An ordinary lost race reported an invalid transition.
        --
        -- With only the *state* compared first, the same thing happened one step further
        -- on: a caller holding a stale revision, whose state happened to have come back
        -- around a cycle, was told its instance was terminal or its edge was invalid --
        -- which is a diagnosis about the *current* row given to a caller whose request was
        -- simply out of date, and which tells that caller something about a state it did
        -- not ask about. Comparing both first means the graph is only ever asked about a
        -- row the caller has correctly described.
        --
        -- After this check the persisted state and revision are the caller's, so the graph
        -- question below is asked of the persisted row either way.
        IF v_current_state IS DISTINCT FROM p_expected_state
           OR v_current_revision IS DISTINCT FROM p_expected_revision
        THEN
            v_updated := 0;
        ELSE
            IF {SCHEMA}.lifecycle_state_is_terminal(
                v_machine_key, v_machine_version, v_current_state
            ) THEN
                RAISE EXCEPTION 'firmbatch: this lifecycle instance is in a terminal state'
                    USING ERRCODE = '{LIFECYCLE_NOT_ALLOWED_SQLSTATE}',
                          DETAIL = 'the machine stops here; the offending values are deliberately '
                                   'not shown';
            END IF;
            IF NOT {SCHEMA}.lifecycle_edge_exists(
                v_machine_key, v_machine_version, v_current_state, p_target_state
            ) THEN
                RAISE EXCEPTION 'firmbatch: that lifecycle transition is not an edge of this machine version'
                    USING ERRCODE = '{LIFECYCLE_NOT_ALLOWED_SQLSTATE}',
                          DETAIL = 'the machine declares its allowed moves and this is not one of '
                                   'them; the offending values are deliberately not shown';
            END IF;

            -- ----------------------------------------------------- the compare-and-swap
            --
            -- One statement. The predicate carries the tenant, the instance, the machine
            -- version, the expected state and the expected revision, so the check and the
            -- write are the same operation and there is no window between them for a second
            -- caller to fit through. Two callers holding the same revision serialise on the
            -- row lock; the second re-evaluates this predicate against the row the first
            -- committed, matches nothing, and is told so.
            --
            -- **Not a read followed by an unconditional UPDATE.** Everything above is
            -- diagnosis: it decides which error a caller gets and nothing about whether the
            -- write happens. The predicate here is what decides that, against the row as it
            -- is at the instant of the write -- which is why the expected state appears in
            -- both places rather than only in the one that produced a nicer message.
            UPDATE {SCHEMA}.lifecycle_instances
            SET current_state = p_target_state,
                revision = revision + 1
            WHERE id = p_instance_id
              AND tenant_id = v_context.tenant_id
              AND machine_key = v_machine_key
              AND machine_version = v_machine_version
              AND current_state = p_expected_state
              AND revision = p_expected_revision
            RETURNING revision INTO v_to_revision;

            GET DIAGNOSTICS v_updated = ROW_COUNT;
        END IF;
    ELSE
        -- Not found, and it falls through to the **same** raise below rather than raising
        -- here. Two raise sites would have been two different errors: PostgreSQL puts the
        -- plpgsql line number in the CONTEXT of every exception, so a caller could read off
        -- which branch refused it and learn whether an id it does not own is real. Measured
        -- against a real server before this was written -- the messages were identical and
        -- the CONTEXT lines were not.
        v_updated := 0;
    END IF;

    IF v_updated = 0 THEN
        -- **The lost identical race.** The winner's conditional UPDATE held this instance's
        -- row lock until it committed, so by the time this one matched nothing the winner's
        -- claim is committed too -- and under READ COMMITTED the statement below takes a
        -- fresh snapshot and sees it. An identical request replays; a different one gets the
        -- conflicting-reuse refusal; and a genuinely stale request, a cross-tenant id or a
        -- wrong-identity attempt finds no claim at all and keeps the conflict it earned.
        IF v_claiming AND v_machine_key IS NOT NULL THEN
            SELECT * INTO v_replay FROM {SCHEMA}.lifecycle_replay_claim(
                v_operation, p_idempotency_key, v_machine_key, v_machine_version, v_fingerprint
            );
            IF FOUND THEN
                o_transition_id := (v_replay.o_result ->> 'transition_id')::uuid;
                o_machine_key := v_machine_key;
                o_machine_version := v_machine_version;
                o_from_revision := (v_replay.o_result ->> 'from_revision')::integer;
                o_to_revision := (v_replay.o_result ->> 'to_revision')::integer;
                o_event_id := v_replay.o_event_id;
                o_record_id := v_replay.o_record_id;
                o_result := v_replay.o_result;
                o_operation := v_operation;
                o_replayed := true;
                RETURN NEXT;
                RETURN;
            END IF;
        END IF;
        RAISE EXCEPTION '%', '{LIFECYCLE_CONFLICT_MESSAGE}'
            USING ERRCODE = '{LIFECYCLE_CONFLICT_SQLSTATE}',
                  DETAIL = 'the instance is missing, is in another tenant, or has moved since it was '
                           'read; the three are deliberately indistinguishable';
    END IF;

    -- ------------------------------------------------------------------- the history row
    --
    -- Same transaction, so the move and the record of it commit together or not at all.
    -- The actor is not a parameter: it is written from the authenticated context and
    -- re-checked by the insert policy.
    v_transition_id := pg_catalog.gen_random_uuid();
    INSERT INTO {SCHEMA}.lifecycle_transitions (
        id, tenant_id, lifecycle_instance_id, machine_key, machine_version,
        from_state, to_state, from_revision, to_revision,
        actor_kind, actor_principal_id, actor_binding_id, reason, details
    )
    VALUES (
        v_transition_id, v_context.tenant_id, p_instance_id, v_machine_key, v_machine_version,
        p_expected_state, p_target_state, p_expected_revision, v_to_revision,
        v_context.actor_kind, v_context.principal_id, v_context.binding_id,
        p_reason, v_details
    );

    -- And one audit event, for the same reason create_lifecycle_instance() writes one: a
    -- state change with no record of who made it is the outcome the trail exists to
    -- prevent, and a caller writing raw SQL must not be able to avoid leaving one. Tagged,
    -- so reading it needs the machine's read scope and not only ``audit:read``.
    PERFORM {SCHEMA}.append_lifecycle_audit_event(
        'lifecycle.transitioned',
        'succeeded',
        'lifecycle_instance',
        p_instance_id,
        pg_catalog.jsonb_build_object(
            'machine_key', v_machine_key,
            'machine_version', v_machine_version,
            'from_state', p_expected_state,
            'to_state', p_target_state,
            'from_revision', p_expected_revision,
            'to_revision', v_to_revision,
            'transition_id', v_transition_id
        ),
        v_machine_key,
        v_machine_version
    );

    -- ---------------------------------------------------------- the claim, then the event
    --
    -- The result is computed **here**, from what this function just did, rather than taken
    -- from a caller. It is what a later identical retry gets back, so a caller that could
    -- supply it could make a retry return something the transition never produced.
    v_result := pg_catalog.jsonb_build_object(
        'lifecycle_instance_id', p_instance_id,
        'machine_key', v_machine_key,
        'machine_version', v_machine_version,
        'from_state', p_expected_state,
        'to_state', p_target_state,
        'from_revision', p_expected_revision,
        'to_revision', v_to_revision,
        'transition_id', v_transition_id
    );

    IF v_claiming THEN
        -- The tenant is the authenticated one, the operation is derived from the machine
        -- and the fingerprint from the request, so there is nothing here a caller chose
        -- except the key itself. A key already taken raises a unique violation on
        -- ``uq_idempotency_records_tenant_id_operation_idempotency_key``, and the handler
        -- at the end of this function recovers from it exactly as the lost row-lock race
        -- above does.
        v_record_id := pg_catalog.gen_random_uuid();
        INSERT INTO {SCHEMA}.idempotency_records (
            id, tenant_id, operation, idempotency_key, request_fingerprint, status, result,
            lifecycle_machine_key, lifecycle_machine_version
        )
        VALUES (
            v_record_id, v_context.tenant_id, v_operation, p_idempotency_key,
            v_fingerprint, '{IDEMPOTENCY_STATUS_COMPLETED}', v_result,
            v_machine_key, v_machine_version
        );
    END IF;

    -- **The outbox intent, written here rather than by the caller.** While this was
    -- appended in Python after the function returned, an application role executing
    -- arbitrary SQL could call the function and simply not append one -- a committed state
    -- change, a history row and an audit event with nothing announcing the change. There is
    -- now no call that moves an instance without writing every artifact, and no artifact
    -- that can be omitted by choosing a different caller.
    --
    -- The tag columns are what make the claim, the event and the audit row readable only by
    -- a context that holds the machine's read capability; they are settable by the lifecycle
    -- writer alone, and this function executes as the writer because the writer owns it.
    -- The outbox-link guard passes this insert for the same reason: the writer is the one
    -- identity that may link an event to a lifecycle claim.
    v_event_id := pg_catalog.gen_random_uuid();
    INSERT INTO {SCHEMA}.outbox_events (
        id, tenant_id, idempotency_record_id, event_type, aggregate_type, aggregate_id,
        attributes, lifecycle_machine_key, lifecycle_machine_version
    )
    VALUES (
        v_event_id, v_context.tenant_id, v_record_id,
        v_machine_key || '.transitioned', v_machine_key, p_instance_id,
        pg_catalog.jsonb_build_object(
            'machine_version', v_machine_version,
            'from_state', p_expected_state,
            'to_state', p_target_state,
            'from_revision', p_expected_revision,
            'to_revision', v_to_revision,
            'transition_id', v_transition_id
        ),
        v_machine_key, v_machine_version
    );

    -- -------------------------------------------------------------------- the provenance
    --
    -- **What makes a replay a replay of something.** A machine tag says which machine a
    -- claim belongs to; it does not say which transition the claim stands for, and a replay
    -- that trusted the tag alone would hand back whatever ``result`` a row happened to
    -- carry. This row is the link. It is written by this function and by nothing else, no
    -- role holds a privilege on the table, and a trigger refuses every UPDATE and DELETE
    -- including the owner's. Every column is a foreign key into a row this call just wrote,
    -- so the relationship cannot dangle.
    IF v_claiming THEN
        INSERT INTO {SCHEMA}.lifecycle_claim_provenance (
            idempotency_record_id, tenant_id, lifecycle_transition_id, lifecycle_instance_id,
            machine_key, machine_version, from_revision, to_revision, outbox_event_id
        )
        VALUES (
            v_record_id, v_context.tenant_id, v_transition_id, p_instance_id,
            v_machine_key, v_machine_version, p_expected_revision, v_to_revision, v_event_id
        );
    END IF;

    o_transition_id := v_transition_id;
    o_machine_key := v_machine_key;
    o_machine_version := v_machine_version;
    o_from_revision := p_expected_revision;
    o_to_revision := v_to_revision;
    o_event_id := v_event_id;
    o_record_id := v_record_id;
    o_result := v_result;
    o_operation := v_operation;
    o_replayed := false;
    RETURN NEXT;

EXCEPTION
    WHEN unique_violation THEN
        -- **The other way to lose an identical race**: the winner's claim committed while
        -- this call was still working, so the claim insert above collided on the Milestone
        -- 2.2 index. plpgsql's exception block is a subtransaction, so reaching this handler
        -- has already rolled back everything this call wrote -- the move included -- which
        -- is the recovery the Python savepoint used to provide, one layer lower and out of
        -- any caller's reach.
        --
        -- Only that one index. A unique violation from anywhere else -- the history's
        -- ``(tenant, instance, to_revision)``, the outbox's one-event-per-claim -- means
        -- something this recovery has no business interpreting, and is re-raised.
        GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
        IF NOT v_claiming
           OR v_constraint IS DISTINCT FROM 'uq_idempotency_records_tenant_id_operation_idempotency_key'
        THEN
            RAISE;
        END IF;
        SELECT * INTO v_replay FROM {SCHEMA}.lifecycle_replay_claim(
            v_operation, p_idempotency_key, v_machine_key, v_machine_version, v_fingerprint
        );
        IF NOT FOUND THEN
            -- The index said the key is taken and the re-read says it is not. Under READ
            -- COMMITTED that cannot happen -- which is why the isolation level is required
            -- above rather than hoped for.
            RAISE EXCEPTION 'firmbatch: an idempotency claim conflicted with a row that is not there on re-read'
                USING ERRCODE = '{LIFECYCLE_PROVENANCE_SQLSTATE}',
                      DETAIL = 'only possible outside READ COMMITTED, which this function refuses';
        END IF;
        o_transition_id := (v_replay.o_result ->> 'transition_id')::uuid;
        o_machine_key := v_machine_key;
        o_machine_version := v_machine_version;
        o_from_revision := (v_replay.o_result ->> 'from_revision')::integer;
        o_to_revision := (v_replay.o_result ->> 'to_revision')::integer;
        o_event_id := v_replay.o_event_id;
        o_record_id := v_replay.o_record_id;
        o_result := v_replay.o_result;
        o_operation := v_operation;
        o_replayed := true;
        RETURN NEXT;
END;
$function$
"""


# --------------------------------------------------------------- access-control hygiene
#
# **The ownership-aware sanitiser, installed as a function.** A character-for-character copy
# of ``db/roles.py``'s ``SCHEMA_ACL_SANITIZER_BODY``: a migration must not import application
# code, because one that follows the application stops being a record of what was applied,
# so the text is duplicated and a test compares the two live copies. Migration ``0003``
# carries the original text, without the ownership predicate, and is history -- it is not
# edited to suit the objects this migration introduces.
#
# Why a function rather than the anonymous block ``0003`` ran: this migration introduces a
# role that owns two functions in the schema, and the schema owner cannot ``REVOKE`` on a
# function it does not own, so from here on the sanitiser a database needs is the
# ownership-aware one -- and a *later* migration should call it rather than carry a fourth
# copy. It is created before the final sanitisation below and executed by it, revokes
# ``PUBLIC``'s default ``EXECUTE`` from itself in passing, is granted to nobody, and is
# dropped by the downgrade after every writer-owned function and every writer grant is gone,
# so a ``0003`` database has exactly what ``0003`` installed.
#
# Read the commentary in ``db/roles.py`` for why revoking from ``PUBLIC`` is not stating the
# access control, why column ACLs need their own pass, and why the two function loops touch
# only functions the schema owner owns.
_SANITIZE_SCHEMA_ACL_BODY = f"""
DECLARE
    entry record;
BEGIN
    EXECUTE 'REVOKE ALL ON SCHEMA {SCHEMA} FROM PUBLIC';
    FOR entry IN
        SELECT pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_namespace n
        CROSS JOIN LATERAL pg_catalog.aclexplode(n.nspacl) acl
        WHERE n.nspname = '{SCHEMA}'
          AND acl.grantee <> 0
          AND acl.grantee <> n.nspowner
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON SCHEMA {SCHEMA} FROM %I', entry.grantee);
    END LOOP;

    FOR entry IN
        SELECT c.oid::pg_catalog.regclass AS obj,
               CASE WHEN c.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END AS kind,
               c.relowner
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = '{SCHEMA}' AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON %s %s FROM PUBLIC', entry.kind, entry.obj);
    END LOOP;

    FOR entry IN
        SELECT c.oid::pg_catalog.regclass AS obj,
               CASE WHEN c.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END AS kind,
               pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) acl
        WHERE n.nspname = '{SCHEMA}'
          AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
          AND acl.grantee <> 0
          AND acl.grantee <> c.relowner
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL ON %s %s FROM %I', entry.kind, entry.obj, entry.grantee
        );
    END LOOP;

    FOR entry IN
        SELECT DISTINCT c.oid::pg_catalog.regclass AS obj,
               a.attname AS column_name
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
        CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
        WHERE n.nspname = '{SCHEMA}'
          AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND a.attnum > 0
          AND NOT a.attisdropped
          AND acl.grantee = 0
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL (%I) ON TABLE %s FROM PUBLIC', entry.column_name, entry.obj
        );
    END LOOP;

    FOR entry IN
        SELECT DISTINCT c.oid::pg_catalog.regclass AS obj,
               a.attname AS column_name,
               pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
        CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
        WHERE n.nspname = '{SCHEMA}'
          AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND a.attnum > 0
          AND NOT a.attisdropped
          AND acl.grantee <> 0
          AND acl.grantee <> c.relowner
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL (%I) ON TABLE %s FROM %I',
            entry.column_name, entry.obj, entry.grantee
        );
    END LOOP;

    FOR entry IN
        SELECT p.oid::pg_catalog.regprocedure AS obj
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = '{SCHEMA}'
          AND p.proowner = n.nspowner
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', entry.obj);
    END LOOP;

    FOR entry IN
        SELECT p.oid::pg_catalog.regprocedure AS obj,
               pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl
        WHERE n.nspname = '{SCHEMA}'
          AND p.proowner = n.nspowner
          AND acl.grantee <> 0
          AND acl.grantee <> p.proowner
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM %I', entry.obj, entry.grantee);
    END LOOP;

    FOR entry IN
        SELECT t.oid::pg_catalog.regtype AS obj
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = '{SCHEMA}' AND t.typtype IN ('c', 'd', 'e', 'r')
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON TYPE %s FROM PUBLIC', entry.obj);
    END LOOP;

    FOR entry IN
        SELECT t.oid::pg_catalog.regtype AS obj,
               pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(t.typacl) acl
        WHERE n.nspname = '{SCHEMA}'
          AND t.typtype IN ('c', 'd', 'e', 'r')
          AND acl.grantee <> 0
          AND acl.grantee <> t.typowner
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON TYPE %s FROM %I', entry.obj, entry.grantee);
    END LOOP;
END;
"""

_SANITIZE_SCHEMA_PRIVILEGES = f"""
CREATE FUNCTION {SCHEMA}.sanitize_schema_privileges() RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
{_SANITIZE_SCHEMA_ACL_BODY}
$function$
"""


def _policy_name(table: str, suffix: str) -> str:
    return f"{table}_authenticated_{suffix}"


def upgrade() -> None:
    # --- the protected, global definition ---------------------------------------------
    op.create_table(
        "lifecycle_machines",
        sa.Column("machine_key", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("read_scope", sa.Text(), nullable=False),
        sa.Column("create_scope", sa.Text(), nullable=False),
        sa.Column("transition_scope", sa.Text(), nullable=False),
        sa.Column("created_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("now()")),
        # NULL until the definition is complete. Every consumer reads through the four
        # publication-aware readers, so an unpublished machine has no required scope, no
        # initial state and no edges as far as anything that uses one is concerned.
        sa.Column("published_at", _TIMESTAMPTZ, nullable=True),
        sa.PrimaryKeyConstraint("machine_key", "version", name="pk_lifecycle_machines"),
        sa.CheckConstraint(f"machine_key ~ '{LIFECYCLE_NAME_REGEX}'", name="machine_key_format"),
        sa.CheckConstraint("version >= 1", name="version_positive"),
        sa.CheckConstraint(
            f"read_scope IN ({_quoted_list(LIFECYCLE_ELIGIBLE_SCOPES)})", name="read_scope_eligible"
        ),
        sa.CheckConstraint(
            f"create_scope IN ({_quoted_list(LIFECYCLE_ELIGIBLE_SCOPES)})", name="create_scope_eligible"
        ),
        sa.CheckConstraint(
            f"transition_scope IN ({_quoted_list(LIFECYCLE_ELIGIBLE_SCOPES)})",
            name="transition_scope_eligible",
        ),
        schema=SCHEMA,
    )

    op.create_table(
        "lifecycle_states",
        sa.Column("machine_key", sa.Text(), nullable=False),
        sa.Column("machine_version", sa.Integer(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("is_initial", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_terminal", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.PrimaryKeyConstraint("machine_key", "machine_version", "state", name="pk_lifecycle_states"),
        sa.ForeignKeyConstraint(
            ["machine_key", "machine_version"],
            [f"{SCHEMA}.lifecycle_machines.machine_key", f"{SCHEMA}.lifecycle_machines.version"],
            name="fk_lifecycle_states_machine_lifecycle_machines",
        ),
        sa.CheckConstraint(f"state ~ '{LIFECYCLE_NAME_REGEX}'", name="state_format"),
        schema=SCHEMA,
    )
    # Exactly one initial state per machine version, as a database fact. A partial unique
    # index rather than a trigger: two concurrent registrations of the same version would
    # each see no initial state and each insert one, and only an index refuses that.
    op.create_index(
        "uq_lifecycle_states_one_initial_per_version",
        "lifecycle_states",
        ["machine_key", "machine_version"],
        unique=True,
        postgresql_where=sa.text("is_initial"),
        schema=SCHEMA,
    )

    op.create_table(
        "lifecycle_transition_edges",
        sa.Column("machine_key", sa.Text(), nullable=False),
        sa.Column("machine_version", sa.Integer(), nullable=False),
        sa.Column("from_state", sa.Text(), nullable=False),
        sa.Column("to_state", sa.Text(), nullable=False),
        # The whole edge is the key, so an edge cannot be duplicated.
        sa.PrimaryKeyConstraint(
            "machine_key", "machine_version", "from_state", "to_state",
            name="pk_lifecycle_transition_edges",
        ),
        sa.ForeignKeyConstraint(
            ["machine_key", "machine_version", "from_state"],
            [
                f"{SCHEMA}.lifecycle_states.machine_key",
                f"{SCHEMA}.lifecycle_states.machine_version",
                f"{SCHEMA}.lifecycle_states.state",
            ],
            name="fk_lifecycle_transition_edges_from_lifecycle_states",
        ),
        sa.ForeignKeyConstraint(
            ["machine_key", "machine_version", "to_state"],
            [
                f"{SCHEMA}.lifecycle_states.machine_key",
                f"{SCHEMA}.lifecycle_states.machine_version",
                f"{SCHEMA}.lifecycle_states.state",
            ],
            name="fk_lifecycle_transition_edges_to_lifecycle_states",
        ),
        schema=SCHEMA,
    )

    # --- the readers and the triggers --------------------------------------------------
    #
    # Before the tenant-owned tables, because their triggers and policies call these.
    op.execute(_LIFECYCLE_REQUIRED_SCOPE)
    op.execute(_LIFECYCLE_INITIAL_STATE)
    op.execute(_LIFECYCLE_STATE_IS_TERMINAL)
    op.execute(_LIFECYCLE_EDGE_EXISTS)
    op.execute(_LIFECYCLE_REQUEST_FINGERPRINT)
    op.execute(_LIFECYCLE_REPLAY_CLAIM)
    op.execute(_APPEND_LIFECYCLE_AUDIT_EVENT)
    op.execute(_PUBLISH_LIFECYCLE_MACHINE)
    op.execute(_LIFECYCLE_DEFINITION_IS_IMMUTABLE)
    op.execute(_LIFECYCLE_MACHINES_BEFORE_INSERT)
    op.execute(_LIFECYCLE_MACHINES_BEFORE_UPDATE)
    op.execute(_LIFECYCLE_DEFINITION_ROWS_BEFORE_INSERT)
    op.execute(_LIFECYCLE_EDGES_CHECK_SOURCE)
    op.execute(_LIFECYCLE_INSTANCES_BEFORE_INSERT)
    op.execute(_LIFECYCLE_INSTANCES_BEFORE_UPDATE)
    op.execute(_LIFECYCLE_TRANSITIONS_BEFORE_INSERT)
    # The writer's identity, before the three guards that ask for it.
    op.execute(_LIFECYCLE_WRITER_ROLE)
    op.execute(_LIFECYCLE_FRAMEWORK_TAG_IS_DERIVED)
    op.execute(_LIFECYCLE_CLAIM_PROVENANCE_GUARD)
    op.execute(_OUTBOX_EVENTS_LINK_IS_AUTHORIZED)

    # Sealing, in three directions. A state or an edge may never be updated or deleted,
    # and may only be inserted before publication. A machine row may never be deleted and
    # has exactly one legal update -- its publication -- so it gets its own trigger rather
    # than the blanket refusal.
    for table in ("lifecycle_states", "lifecycle_transition_edges"):
        op.execute(
            f"""
            CREATE TRIGGER {table}_immutable
            BEFORE UPDATE OR DELETE ON {SCHEMA}.{table}
            FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.lifecycle_definition_is_immutable()
            """
        )
        op.execute(
            f"""
            CREATE TRIGGER {table}_only_before_publication
            BEFORE INSERT ON {SCHEMA}.{table}
            FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.lifecycle_definition_rows_before_insert()
            """
        )
    op.execute(
        f"""
        CREATE TRIGGER lifecycle_machines_immutable
        BEFORE DELETE ON {SCHEMA}.lifecycle_machines
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.lifecycle_definition_is_immutable()
        """
    )
    # A machine is born a draft. Without this the publication boundary had a door beside
    # it: an INSERT carrying published_at produced a published machine that no validation
    # had ever seen, because the validation is attached to the update that publishes.
    op.execute(
        f"""
        CREATE TRIGGER lifecycle_machines_draft_on_insert
        BEFORE INSERT ON {SCHEMA}.lifecycle_machines
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.lifecycle_machines_before_insert()
        """
    )
    # And every publication rule, on the one boundary a publication crosses -- so a
    # hand-written UPDATE runs exactly what publish_lifecycle_machine() runs.
    op.execute(
        f"""
        CREATE TRIGGER lifecycle_machines_publication_only
        BEFORE UPDATE ON {SCHEMA}.lifecycle_machines
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.lifecycle_machines_before_update()
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER lifecycle_transition_edges_source_not_terminal
        BEFORE INSERT ON {SCHEMA}.lifecycle_transition_edges
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.lifecycle_edges_check_source()
        """
    )

    # --- the tenant-owned instance -----------------------------------------------------
    op.create_table(
        "lifecycle_instances",
        sa.Column("id", _UUID, nullable=False, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", _UUID, nullable=False),
        sa.Column("machine_key", sa.Text(), nullable=False),
        sa.Column("machine_version", sa.Integer(), nullable=False),
        sa.Column("current_state", sa.Text(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("now()")),
        # Both defaults are formalities: the BEFORE triggers overwrite them on every row.
        # They are kept so the columns have one if a trigger is ever dropped by mistake,
        # and so NOT NULL never fires in place of an explanation.
        sa.Column("updated_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_lifecycle_instances"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            [f"{SCHEMA}.tenants.id"],
            name="fk_lifecycle_instances_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        # The state is one this machine version declares. Referential integrity is checked
        # with row security bypassed, so this binds every writer including the owner.
        sa.ForeignKeyConstraint(
            ["machine_key", "machine_version", "current_state"],
            [
                f"{SCHEMA}.lifecycle_states.machine_key",
                f"{SCHEMA}.lifecycle_states.machine_version",
                f"{SCHEMA}.lifecycle_states.state",
            ],
            name="fk_lifecycle_instances_state_lifecycle_states",
        ),
        sa.UniqueConstraint("id", "tenant_id", name="uq_lifecycle_instances_id_tenant_id"),
        sa.UniqueConstraint(
            "id", "tenant_id", "machine_key", "machine_version",
            name="uq_lifecycle_instances_id_tenant_id_machine_key_version",
        ),
        sa.CheckConstraint("revision >= 0", name="revision_not_negative"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_lifecycle_instances_tenant_id_machine_key",
        "lifecycle_instances",
        ["tenant_id", "machine_key"],
        schema=SCHEMA,
    )
    op.execute(
        f"""
        CREATE TRIGGER lifecycle_instances_start_at_the_initial_state
        BEFORE INSERT ON {SCHEMA}.lifecycle_instances
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.lifecycle_instances_before_insert()
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER lifecycle_instances_follow_the_graph
        BEFORE UPDATE ON {SCHEMA}.lifecycle_instances
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.lifecycle_instances_before_update()
        """
    )
    op.execute(f"ALTER TABLE {SCHEMA}.lifecycle_instances ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {SCHEMA}.lifecycle_instances FORCE ROW LEVEL SECURITY")

    # --- the tenant-owned, append-only history -----------------------------------------
    op.create_table(
        "lifecycle_transitions",
        sa.Column("id", _UUID, nullable=False, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", _UUID, nullable=False),
        sa.Column("lifecycle_instance_id", _UUID, nullable=False),
        sa.Column("machine_key", sa.Text(), nullable=False),
        sa.Column("machine_version", sa.Integer(), nullable=False),
        sa.Column("from_state", sa.Text(), nullable=False),
        sa.Column("to_state", sa.Text(), nullable=False),
        sa.Column("from_revision", sa.Integer(), nullable=False),
        sa.Column("to_revision", sa.Integer(), nullable=False),
        sa.Column("actor_kind", sa.Text(), nullable=False),
        sa.Column("actor_principal_id", _UUID, nullable=True),
        sa.Column("actor_binding_id", _UUID, nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("details", _JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column(
            "occurred_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("clock_timestamp()")
        ),
        sa.PrimaryKeyConstraint("id", name="pk_lifecycle_transitions"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            [f"{SCHEMA}.tenants.id"],
            name="fk_lifecycle_transitions_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        # Tenant AND machine consistency, structurally.
        sa.ForeignKeyConstraint(
            ["lifecycle_instance_id", "tenant_id", "machine_key", "machine_version"],
            [
                f"{SCHEMA}.lifecycle_instances.id",
                f"{SCHEMA}.lifecycle_instances.tenant_id",
                f"{SCHEMA}.lifecycle_instances.machine_key",
                f"{SCHEMA}.lifecycle_instances.machine_version",
            ],
            name="fk_lifecycle_transitions_instance_lifecycle_instances",
            ondelete="CASCADE",
        ),
        # The graph, in the history: a move that is not a declared edge cannot be recorded
        # as having been taken, by any writer.
        sa.ForeignKeyConstraint(
            ["machine_key", "machine_version", "from_state", "to_state"],
            [
                f"{SCHEMA}.lifecycle_transition_edges.machine_key",
                f"{SCHEMA}.lifecycle_transition_edges.machine_version",
                f"{SCHEMA}.lifecycle_transition_edges.from_state",
                f"{SCHEMA}.lifecycle_transition_edges.to_state",
            ],
            name="fk_lifecycle_transitions_edge_lifecycle_transition_edges",
        ),
        sa.ForeignKeyConstraint(
            ["actor_binding_id", "tenant_id"],
            [f"{SCHEMA}.auth_bindings.id", f"{SCHEMA}.auth_bindings.tenant_id"],
            name="fk_lifecycle_transitions_actor_binding_auth_bindings",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "tenant_id", "lifecycle_instance_id", "to_revision",
            name="uq_lifecycle_transitions_tenant_id_instance_id_to_revision",
        ),
        sa.UniqueConstraint("id", "tenant_id", name="uq_lifecycle_transitions_id_tenant_id"),
        sa.CheckConstraint("from_revision >= 0", name="from_revision_not_negative"),
        sa.CheckConstraint("to_revision = from_revision + 1", name="revision_advances_by_one"),
        sa.CheckConstraint(
            f"actor_kind IN ({_quoted_list(AUDIT_ACTOR_KINDS)})", name="actor_kind_known"
        ),
        sa.CheckConstraint(
            "(actor_kind = 'credential' AND actor_principal_id IS NOT NULL AND actor_binding_id IS NOT NULL)"
            " OR (actor_kind = 'provisioning' AND actor_principal_id IS NULL AND actor_binding_id IS NULL)",
            name="actor_shape",
        ),
        sa.CheckConstraint(
            f"reason IS NULL OR length(reason) BETWEEN 1 AND {MAX_LIFECYCLE_REASON_LENGTH}",
            name="reason_bounded",
        ),
        *_metadata_checks("details"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_lifecycle_transitions_tenant_id_occurred_at",
        "lifecycle_transitions",
        ["tenant_id", "occurred_at"],
        schema=SCHEMA,
    )
    op.execute(
        f"""
        CREATE TRIGGER lifecycle_transitions_occurred_at
        BEFORE INSERT ON {SCHEMA}.lifecycle_transitions
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.lifecycle_transitions_before_insert()
        """
    )
    op.execute(f"ALTER TABLE {SCHEMA}.lifecycle_transitions ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {SCHEMA}.lifecycle_transitions FORCE ROW LEVEL SECURITY")

    # --- the Milestone 2.2 framework tables gain a derived lifecycle tag -----------------
    #
    # ``mutation:execute`` is the capability to claim a key and append an event. It was
    # never permission to read what somebody else's lifecycle did -- and it was: a claim's
    # ``result`` carries the instance id, the states and the revisions, and an event's
    # ``attributes`` carry the same. A credential holding only the framework capability
    # could read the whole trajectory of a machine it holds no capability for.
    #
    # The correction is a tag, written only by the two lifecycle entry points (which execute
    # as the lifecycle writer role that owns them), refused to every other writer by a
    # trigger, and consulted by the read policy. It is deliberately a *column* rather than a
    # Python check: the boundary has to hold for a caller composing its own SELECT.
    for table, namespaced_column in FRAMEWORK_TAGGED_TABLES:
        op.add_column(
            table,
            sa.Column("lifecycle_machine_key", sa.Text(), nullable=True),
            schema=SCHEMA,
        )
        op.add_column(
            table,
            sa.Column("lifecycle_machine_version", sa.Integer(), nullable=True),
            schema=SCHEMA,
        )
        op.create_check_constraint(
            "lifecycle_tag_complete",
            table,
            "(lifecycle_machine_key IS NULL) = (lifecycle_machine_version IS NULL)",
            schema=SCHEMA,
        )
        # The tag names a real machine version, so it cannot point at a graph that does not
        # exist and the read policy's scope lookup always has something to find.
        op.create_foreign_key(
            f"fk_{table}_lifecycle_machine_lifecycle_machines",
            table,
            "lifecycle_machines",
            ["lifecycle_machine_key", "lifecycle_machine_version"],
            ["machine_key", "version"],
            source_schema=SCHEMA,
            referent_schema=SCHEMA,
        )
        op.execute(
            f"""
            CREATE TRIGGER {table}_lifecycle_tag_is_derived
            BEFORE INSERT ON {SCHEMA}.{table}
            FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.lifecycle_framework_tag_is_derived()
            """
        )
        if namespaced_column is None:
            continue
        # **The reserved namespace, tied to the derived tag in both directions.**
        #
        # A claim's operation and an audit row's action start with ``lifecycle.`` exactly
        # when the row carries a machine tag. Only the schema owner can write that tag, so
        # a generic Milestone 2.2 writer cannot create a row in the namespace at all: with
        # no tag it fails this constraint, and with one it fails the trigger above -- and
        # it has no column privilege on the tag either.
        #
        # That is what separates the two uniqueness domains. A generic claim can never
        # collide with a lifecycle claim, so it cannot use the claim index to ask whether a
        # lifecycle key is taken. And because the lifecycle operation carries the machine
        # key and version, two machines never share a domain either.
        op.create_check_constraint(
            "lifecycle_namespace_reserved",
            table,
            f"pg_catalog.starts_with({namespaced_column}, '{LIFECYCLE_NAMESPACE_PREFIX}') "
            "= (lifecycle_machine_key IS NOT NULL)",
            schema=SCHEMA,
        )

    # **The outbox link is proved before any constraint sees it.** A generic writer may name
    # ``idempotency_record_id``; what it may not do is learn from the foreign key or from the
    # one-event-per-claim index whether a claim the read policies hide exists. This fires
    # before the tuple is formed -- ahead of the unique index, the ON CONFLICT arbiter and
    # the AFTER-trigger foreign key -- and refuses every unlinkable claim with one message.
    # Named so it sorts after the tag trigger; both refuse independently, so the order is
    # legibility rather than a requirement.
    op.execute(
        f"""
        CREATE TRIGGER outbox_events_link_is_authorized
        BEFORE INSERT ON {SCHEMA}.outbox_events
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.outbox_events_link_is_authorized()
        """
    )

    # The composite key the provenance relation references. ``outbox_events`` had no
    # ``(id, tenant_id)`` unique constraint because nothing referenced it before; foreign
    # keys are checked with row security bypassed, so a single-column reference would reach
    # across tenants.
    op.create_unique_constraint(
        "uq_outbox_events_id_tenant_id", "outbox_events", ["id", "tenant_id"], schema=SCHEMA
    )

    # --- the protected provenance relation ----------------------------------------------
    #
    # **A lifecycle replay has to be backed by a lifecycle transition, and this is the
    # backing.** The machine tag above says which machine a claim belongs to; it does not
    # say which transition it stands for, and a replay that trusted the tag alone would hand
    # back whatever a row's ``result`` happened to say. This relation is the link, every
    # column of it is a foreign key, and the replay path insists on the whole chain.
    #
    # Protected in the same way the definition tables are: **no runtime role holds any
    # privilege on it** -- the wiring layer grants the lifecycle writer, and only the
    # lifecycle writer, ``SELECT`` and ``INSERT`` -- so "a generic writer cannot forge
    # provenance" is a privilege fact rather than a predicate that has to be right. The guard
    # trigger is the second answer, for the day a later migration grants something by
    # accident, and it also refuses UPDATE and DELETE to everybody including the owner.
    #
    # No row-level security, and deliberately: RLS bounds what a *granted* role may reach,
    # and no role is granted anything here. The rows it carries are tenant-scoped, and every
    # path that reads one joins it to ``idempotency_records``, ``lifecycle_transitions``,
    # ``lifecycle_instances`` and ``outbox_events``, all four of which are FORCE-RLS tables
    # -- so the tenant filter is applied by the rows this one is verified against.
    op.create_table(
        "lifecycle_claim_provenance",
        sa.Column("idempotency_record_id", _UUID, nullable=False),
        sa.Column("tenant_id", _UUID, nullable=False),
        sa.Column("lifecycle_transition_id", _UUID, nullable=False),
        sa.Column("lifecycle_instance_id", _UUID, nullable=False),
        sa.Column("machine_key", sa.Text(), nullable=False),
        sa.Column("machine_version", sa.Integer(), nullable=False),
        sa.Column("from_revision", sa.Integer(), nullable=False),
        sa.Column("to_revision", sa.Integer(), nullable=False),
        sa.Column("outbox_event_id", _UUID, nullable=False),
        sa.Column(
            "created_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("clock_timestamp()")
        ),
        # One provenance row per claim: the claim is the identity, so a second row for one
        # claim is inexpressible rather than refused.
        sa.PrimaryKeyConstraint("idempotency_record_id", name="pk_lifecycle_claim_provenance"),
        sa.ForeignKeyConstraint(
            ["idempotency_record_id", "tenant_id"],
            [f"{SCHEMA}.idempotency_records.id", f"{SCHEMA}.idempotency_records.tenant_id"],
            name="fk_lifecycle_claim_provenance_record_idempotency_records",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["lifecycle_transition_id", "tenant_id"],
            [f"{SCHEMA}.lifecycle_transitions.id", f"{SCHEMA}.lifecycle_transitions.tenant_id"],
            name="fk_lifecycle_claim_provenance_transition_lifecycle_transitions",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["lifecycle_instance_id", "tenant_id", "machine_key", "machine_version"],
            [
                f"{SCHEMA}.lifecycle_instances.id",
                f"{SCHEMA}.lifecycle_instances.tenant_id",
                f"{SCHEMA}.lifecycle_instances.machine_key",
                f"{SCHEMA}.lifecycle_instances.machine_version",
            ],
            name="fk_lifecycle_claim_provenance_instance_lifecycle_instances",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["outbox_event_id", "tenant_id"],
            [f"{SCHEMA}.outbox_events.id", f"{SCHEMA}.outbox_events.tenant_id"],
            name="fk_lifecycle_claim_provenance_event_outbox_events",
            ondelete="CASCADE",
        ),
        # One claim per transition and one claim per event, in the other direction.
        sa.UniqueConstraint(
            "lifecycle_transition_id", name="uq_lifecycle_claim_provenance_transition_id"
        ),
        sa.UniqueConstraint("outbox_event_id", name="uq_lifecycle_claim_provenance_event_id"),
        sa.CheckConstraint("from_revision >= 0", name="from_revision_not_negative"),
        sa.CheckConstraint("to_revision = from_revision + 1", name="revision_advances_by_one"),
        schema=SCHEMA,
    )
    op.execute(
        f"""
        CREATE TRIGGER lifecycle_claim_provenance_derived
        BEFORE INSERT OR UPDATE OR DELETE ON {SCHEMA}.lifecycle_claim_provenance
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.lifecycle_claim_provenance_guard()
        """
    )

    # And the read policy that consults it. Dropped and recreated rather than added beside
    # the old one: two policies for one command are combined with OR, so leaving 0003's in
    # place would mean the weaker one still decided.
    for table, predicate in FRAMEWORK_READ_POLICIES.items():
        op.execute(f"DROP POLICY {_policy_name(table, 'read')} ON {SCHEMA}.{table}")
        op.execute(
            f"CREATE POLICY {_policy_name(table, 'read')} ON {SCHEMA}.{table}\n"
            f"FOR SELECT\nTO PUBLIC\nUSING ({predicate})"
        )

    # --- the entry points ---------------------------------------------------------------
    #
    # After the tables they write into, so the reader meets them in the order they depend on
    # one another. plpgsql resolves names at execution, so this is legibility rather than a
    # requirement -- which is exactly why it is worth keeping honest.
    op.execute(_CREATE_LIFECYCLE_INSTANCE)
    op.execute(_TRANSITION_LIFECYCLE_INSTANCE)

    # --- policies ------------------------------------------------------------------------
    for table, policies in POLICIES.items():
        for command, suffix, using, with_check in policies:
            clauses = [f"CREATE POLICY {_policy_name(table, suffix)} ON {SCHEMA}.{table}"]
            clauses.append(f"FOR {command}")
            clauses.append("TO PUBLIC")
            if using is not None:
                clauses.append(f"USING ({using})")
            if with_check is not None:
                clauses.append(f"WITH CHECK ({with_check})")
            op.execute("\n".join(clauses))

    # --- and state the access control rather than inheriting it --------------------------
    #
    # Same reason as migration 0003, and it applies again because this migration creates
    # six more tables and twenty more functions: ALTER DEFAULT PRIVILEGES FOR ROLE <owner>
    # is applied by the *creator* at the instant each object is created, so a grant can
    # already be on lifecycle_machines before the next statement here runs, and revoking
    # from PUBLIC never touches it.
    #
    # The same body as db/roles.py's SCHEMA_ACL_SANITIZER_BODY, installed as a function and
    # called, rather than run as the anonymous block 0003 ran: from this revision on the
    # schema holds functions the owner does not own, and the sanitiser has to know that. A
    # migration must not import application code -- one that follows the models stops being
    # a record of what was applied -- so the copy is the price and a test is what stops it
    # drifting.
    op.execute(_SANITIZE_SCHEMA_PRIVILEGES)
    op.execute(f"SELECT {SCHEMA}.sanitize_schema_privileges()")


#: The identifier grammar a role name has to satisfy before the downgrade will quote it into
#: a ``REVOKE``. The name comes from the catalogue rather than from a caller, and every
#: role this repository creates matches; anything else is refused rather than interpolated.
_ROLE_NAME_REGEX = r"^[a-z_][a-z0-9_]{0,62}$"


def _writer_privileges_to_revoke(connection, writer: str) -> list[str]:
    """Every ``REVOKE`` that leaves ``writer`` holding nothing in this schema.

    Enumerated from the catalogue, like the sanitiser, rather than from a list this file
    would have to keep in step with ``db/roles.py``: the schema itself, every relation and
    every column, every function, and every type whose ACL names the writer. Run after the
    writer's own functions are gone, so everything left is the schema owner's to revoke.
    """
    import re as _re

    from sqlalchemy import text as _text

    if not _re.match(_ROLE_NAME_REGEX, writer):
        raise RuntimeError(
            "the lifecycle writer's role name does not match the identifier grammar this "
            "downgrade is willing to quote; revoke its privileges by hand and re-run"
        )
    quoted = '"' + writer.replace('"', '""') + '"'
    statements: list[str] = []
    if connection.execute(
        _text(
            "SELECT count(*) FROM pg_catalog.pg_namespace n "
            "CROSS JOIN LATERAL pg_catalog.aclexplode(n.nspacl) acl "
            "WHERE n.nspname = :schema AND acl.grantee = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :writer)"
        ),
        {"schema": SCHEMA, "writer": writer},
    ).scalar_one():
        statements.append(f"REVOKE ALL ON SCHEMA {SCHEMA} FROM {quoted}")
    for kind, obj in connection.execute(
        _text(
            "SELECT DISTINCT CASE WHEN c.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END, "
            "       c.oid::pg_catalog.regclass::text "
            "FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "LEFT JOIN pg_catalog.pg_attribute a "
            "  ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped "
            "CROSS JOIN LATERAL pg_catalog.aclexplode("
            "  COALESCE(c.relacl, '{}'::aclitem[]) || COALESCE(a.attacl, '{}'::aclitem[])) acl "
            "WHERE n.nspname = :schema "
            "  AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') "
            "  AND acl.grantee = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :writer) "
            "ORDER BY 2"
        ),
        {"schema": SCHEMA, "writer": writer},
    ).all():
        statements.append(f"REVOKE ALL ON {kind} {obj} FROM {quoted}")
    for (obj,) in connection.execute(
        _text(
            "SELECT p.oid::pg_catalog.regprocedure::text "
            "FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
            "CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl "
            "WHERE n.nspname = :schema AND acl.grantee = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :writer) "
            "ORDER BY 1"
        ),
        {"schema": SCHEMA, "writer": writer},
    ).all():
        statements.append(f"REVOKE ALL ON FUNCTION {obj} FROM {quoted}")
    for (obj,) in connection.execute(
        _text(
            "SELECT t.oid::pg_catalog.regtype::text "
            "FROM pg_catalog.pg_type t "
            "JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace "
            "CROSS JOIN LATERAL pg_catalog.aclexplode(t.typacl) acl "
            "WHERE n.nspname = :schema AND t.typtype IN ('c', 'd', 'e', 'r') "
            "  AND acl.grantee = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :writer) "
            "ORDER BY 1"
        ),
        {"schema": SCHEMA, "writer": writer},
    ).all():
        statements.append(f"REVOKE ALL ON TYPE {obj} FROM {quoted}")
    return statements


def downgrade() -> None:
    """Back to the Milestone 2.3 shape exactly.

    Ordered by dependency: policies before the tables they are attached to, the tenant-owned
    tables before the definition they reference, and the functions last because the triggers
    and policies above call them.

    **And it leaves the lifecycle writer holding nothing.** The wiring layer, not this file,
    created that role and granted it the writer's privileges -- but which role it is can be
    read from the catalogue while the entry points still exist, so the downgrade reads it
    first, drops everything (the schema owner may drop a function another role owns in its
    schema), and then revokes every remaining grant the writer holds. Afterwards the role
    owns nothing and holds nothing in this database, which is what makes ``DROP ROLE``
    possible and what "no ownership dependency survives a downgrade" means.
    """
    from sqlalchemy import text as _text

    connection = op.get_bind()
    writer = connection.execute(_text(f"SELECT {SCHEMA}.lifecycle_writer_role()")).scalar()

    for table, policies in POLICIES.items():
        for _command, suffix, _using, _with_check in policies:
            op.execute(f"DROP POLICY IF EXISTS {_policy_name(table, suffix)} ON {SCHEMA}.{table}")

    # --- give the framework tables back the shape 0003 left them in ---------------------
    #
    # The read policy first, because it names the tag columns; then the trigger, the
    # constraints and the columns. A downgrade that dropped the columns while a policy still
    # referenced them would fail, and one that left the policy behind would leave a database
    # nothing could read.
    for table, predicate in _LEGACY_FRAMEWORK_READ_POLICIES.items():
        op.execute(f"DROP POLICY IF EXISTS {_policy_name(table, 'read')} ON {SCHEMA}.{table}")
        op.execute(
            f"CREATE POLICY {_policy_name(table, 'read')} ON {SCHEMA}.{table}\n"
            f"FOR SELECT\nTO PUBLIC\nUSING ({predicate})"
        )
    # The provenance relation, before the four tables it references.
    op.drop_table("lifecycle_claim_provenance", schema=SCHEMA)
    # The outbox-link guard lives on a table 0003 keeps, so it is dropped explicitly rather
    # than with a table.
    op.execute(f"DROP TRIGGER outbox_events_link_is_authorized ON {SCHEMA}.outbox_events")
    op.execute(
        f"ALTER TABLE {SCHEMA}.outbox_events DROP CONSTRAINT uq_outbox_events_id_tenant_id"
    )

    for table, namespaced_column in FRAMEWORK_TAGGED_TABLES:
        op.execute(f"DROP TRIGGER {table}_lifecycle_tag_is_derived ON {SCHEMA}.{table}")
        # Raw ``ALTER TABLE`` with the exact names rather than ``op.drop_constraint``, which
        # re-applies ``db/base.py``'s naming convention to whatever it is handed -- so a name
        # that is already conventional comes back doubled
        # (``ck_idempotency_records_ck_idempotency_records_...``) and the drop fails on a
        # constraint that does not exist. Found on the first downgrade after the tag columns
        # were added.
        if namespaced_column is not None:
            op.execute(
                f"ALTER TABLE {SCHEMA}.{table} "
                f"DROP CONSTRAINT ck_{table}_lifecycle_namespace_reserved"
            )
        op.execute(
            f"ALTER TABLE {SCHEMA}.{table} "
            f"DROP CONSTRAINT fk_{table}_lifecycle_machine_lifecycle_machines"
        )
        op.execute(
            f"ALTER TABLE {SCHEMA}.{table} DROP CONSTRAINT ck_{table}_lifecycle_tag_complete"
        )
        op.drop_column(table, "lifecycle_machine_version", schema=SCHEMA)
        op.drop_column(table, "lifecycle_machine_key", schema=SCHEMA)

    op.drop_index(
        "ix_lifecycle_transitions_tenant_id_occurred_at",
        table_name="lifecycle_transitions",
        schema=SCHEMA,
    )
    op.drop_table("lifecycle_transitions", schema=SCHEMA)

    op.drop_index(
        "ix_lifecycle_instances_tenant_id_machine_key",
        table_name="lifecycle_instances",
        schema=SCHEMA,
    )
    op.drop_table("lifecycle_instances", schema=SCHEMA)

    op.drop_table("lifecycle_transition_edges", schema=SCHEMA)
    op.drop_index(
        "uq_lifecycle_states_one_initial_per_version", table_name="lifecycle_states", schema=SCHEMA
    )
    op.drop_table("lifecycle_states", schema=SCHEMA)
    op.drop_table("lifecycle_machines", schema=SCHEMA)

    # The two writer-owned entry points go with the rest, and so does the ownership-aware
    # sanitiser: a 0003 database has no sanitiser object, because 0003 ran its sanitiser as
    # an anonymous block. The schema owner may drop a function another role owns inside its
    # own schema, and that is the whole of the writer's ownership dependency.
    for name, signature, _audience in FUNCTIONS:
        op.execute(f"DROP FUNCTION {SCHEMA}.{name}({signature})")

    # --- and the writer holds nothing on what 0003 keeps --------------------------------
    #
    # Its grants on the 0004 tables and functions went with those objects. What remains are
    # the ones the wiring layer gave it on the schema and on the Milestone 2.2 and 2.3
    # objects the entry points read and write -- and those are the schema owner's to revoke.
    if writer is not None:
        for statement in _writer_privileges_to_revoke(connection, writer):
            op.execute(statement)
