"""The tenant/workspace spine, the M2.2 idempotency and outbox tables, M2.3's
authentication registry and audit trail, and M2.4's lifecycle kernel.

Eleven tables. Seven are tenant-scoped and under forced row-level security; four are
**protected**, which is a different and stronger thing: no role but the schema owner holds
any privilege on them at all, and the only way in is a hardened ``SECURITY DEFINER``
function. They exist to carry the isolation and authorization boundary that every later
milestone's tables inherit, not to model the product: there are no accounts, memberships,
jobs, quotes, or ledgers here, and adding one before its milestone would be
later-milestone work.

Conventions established here and binding on every tenant-owned table that follows
(target architecture 3.1 and invariant 2):

* **UUID primary keys**, defaulted server-side with ``gen_random_uuid()`` so a row
  inserted from ``psql`` obeys the same rule as one inserted through the ORM.
* **Timezone-aware timestamps.** ``timestamptz`` everywhere; a naive timestamp in a
  system whose product is a deadline is a defect waiting for a daylight-saving boundary.
* **An explicit ``tenant_id``** on every tenant-owned row, with a real foreign key.
* **Tenant-local uniqueness.** A workspace slug is unique *within* its tenant. A global
  unique index would leak the existence of another tenant's names through a constraint
  violation, and would let the first tenant to claim ``production`` deny it to everyone.
* **A composite ``(id, tenant_id)`` unique key** on every tenant-owned table. PostgreSQL
  performs referential-integrity checks with row security bypassed, so a plain
  ``REFERENCES workspaces(id)`` on a future child table would happily point across
  tenants. Child tables added in M2.2 onward carry their own ``tenant_id`` and reference
  ``(workspace_id, tenant_id)`` against this key, which makes tenant consistency a
  database fact rather than a code review. ``outbox_events`` is the first table to use
  it, against ``idempotency_records``.

M2.2 adds two more, and one further convention with them:

* **Append-only means append-only in the schema, not in a comment.** Neither
  ``idempotency_records`` nor ``outbox_events`` carries an ``UPDATE`` or ``DELETE``
  policy at all, so no role -- including the table owner, because row security is
  ``FORCE``d -- can reach an existing row with either command. See
  :data:`APPEND_ONLY_TABLES` and migration ``0002``.
* **Bounded metadata, and a digest instead of a request.** Both tables hold small
  ``jsonb`` objects and neither has a binary column; the request an idempotency key was
  claimed for is stored as a SHA-256 digest rather than as its content.
  ``db/idempotency.py`` enforces the shape on the way in and the check constraints here
  are the backstop for a writer that bypasses it.

  What that establishes is that **the schema persists a digest and bounded metadata** --
  not that customer payload bytes cannot reach PostgreSQL. ``TEXT`` and ``JSONB`` hold
  text, so an encoded or textual payload fits in them, and the absence of a ``bytea``
  column makes storing bytes inconvenient rather than impossible. The data-flow proof
  that payload never enters the API process (target architecture invariant 3) is
  Milestone 5's presigned S3 path, and is not claimed here.

M2.3 adds two more, and with them the convention that matters most:

* **Tenant context is not a column value the caller supplies; it is what the database
  says the caller authenticated as.** The isolation predicates no longer read a
  caller-settable ``app.tenant_id`` setting. They read
  ``firmbatch.auth_tenant_id()``, which returns the tenant recorded in a protected
  transaction-local context that only a valid credential can write. Migration ``0003``
  replaces every policy and drops the old helper.
* **``auth_bindings`` is protected rather than policed.** A policy constrains a role that
  holds privileges; this table grants none, to anybody, so there is nothing for a policy
  to constrain. It is therefore absent from :data:`TENANT_SCOPED_TABLES` and present in
  ``security.authorization.PROTECTED_TABLES`` -- two different mechanisms, named
  differently on purpose.
* **``audit_events`` derives its tenant and its actor from the authenticated context**,
  by column default *and* by policy check, so a caller cannot write an event attributing
  an action to somebody else. It is append-only in the same two ways the M2.2 tables are.

M2.4 adds five, and the convention they carry is the last one this milestone needs:

* **A state machine is data, and the data is protected and versioned.**
  ``lifecycle_machines``, ``lifecycle_states`` and ``lifecycle_transition_edges`` hold one
  immutable graph per ``(machine_key, version)``. They are **global**, not tenant-owned --
  one machine version is the same graph for every tenant, like the target architecture's
  explicitly global certification registry (section 3.1) -- and they are **protected**: no
  runtime or provisioning role holds any privilege on them, and a row trigger refuses
  ``UPDATE`` and ``DELETE`` even for the owner, so a change is a new version rather than a
  rewrite of history.
* **A persisted instance cannot be in a state its machine does not have, and cannot move
  along an edge its machine does not have.** ``lifecycle_instances`` references
  ``(machine_key, machine_version, current_state)`` against the state set, and
  ``lifecycle_transitions`` references ``(machine_key, machine_version, from_state,
  to_state)`` against the **edge** set -- so an invalid transition is not merely refused by
  a function, it cannot be recorded. Both are foreign keys, which PostgreSQL checks with
  row security bypassed, so they hold for every writer.
* **Every reference across tenant-owned lifecycle rows is composite.**
  ``lifecycle_transitions`` references ``lifecycle_instances`` on
  ``(id, tenant_id, machine_key, machine_version)``, so neither a cross-tenant nor a
  cross-machine fabrication is expressible.
* **The history is append-only and its revision pair is unique.**
  ``UNIQUE (tenant_id, lifecycle_instance_id, to_revision)`` is what makes "one row per
  revision" a database fact; the ``SELECT``/``INSERT``-only policy set is what makes a
  committed row unchangeable, as for the M2.2 and M2.3 tables.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    FetchedValue,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..security.authorization import KNOWN_SCOPES, LIFECYCLE_ELIGIBLE_SCOPES, MAX_SCOPES_PER_BINDING
from ..security.authorization import PROTECTED_TABLES as _CATALOGUE_PROTECTED_TABLES
from .base import SCHEMA, Base

#: Lowercase DNS-safe slugs. Slugs appear in URLs and object-store keys, so the shape is
#: constrained in the database rather than trusted from the caller.
SLUG_REGEX = r"^[a-z0-9]([a-z0-9-]{0,60}[a-z0-9])?$"

#: Dotted lowercase names -- ``workspace.create``, ``workspace.created``. Used for both
#: the operation an idempotency key is scoped to and the type of an outbox event.
DOTTED_NAME_REGEX = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$"

#: An undotted lowercase name -- ``workspace``. What an outbox event is about.
SIMPLE_NAME_REGEX = r"^[a-z][a-z0-9_]{0,62}$"

#: The shape a caller-supplied idempotency key may take. Bounded and printable: the key
#: is stored verbatim, so it is not a place to put anything but an identifier.
IDEMPOTENCY_KEY_REGEX = r"^[A-Za-z0-9._:@=+-]{8,200}$"

#: A hex SHA-256 digest, which is all that is kept of a request.
FINGERPRINT_REGEX = r"^[0-9a-f]{64}$"

#: The one durable status an idempotency record may have. There is deliberately no
#: ``in_progress`` value: a claim that does not reach ``COMMIT`` is rolled back with the
#: mutation and the event it belonged to, so no recovery system is needed to interpret a
#: half-finished row. Keeping the column, constrained to one value, means a future
#: two-phase design has to change the schema in the open rather than start writing a new
#: value into a column that already accepts anything.
IDEMPOTENCY_STATUS_COMPLETED = "completed"

#: Upper bound on a stored ``jsonb`` document, in bytes of its text rendering. Small on
#: purpose: these columns carry identifiers and counts, never content.
MAX_METADATA_BYTES = 4096

#: A hex SHA-256 digest again, this time of a bearer credential. The same shape as a
#: request fingerprint and a different meaning, so it has its own name: this one is the
#: **only** thing PostgreSQL ever holds of a credential, and it is computed by the
#: database (see migration ``0003``), never by the application.
CREDENTIAL_FINGERPRINT_REGEX = FINGERPRINT_REGEX

#: ``domain:action``. The closed catalogue of values lives in
#: ``security/authorization.py``; this is the shape the column enforces underneath it, so
#: that a malformed scope is refused even by a writer that reached the table another way.
SCOPE_REGEX = r"^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$"

#: What an audit event says happened to the action it records. A closed set: "attempted"
#: and "denied" are as important as "succeeded", because an audit trail that only records
#: successes cannot answer the question it exists for.
AUDIT_OUTCOMES: tuple[str, ...] = ("attempted", "succeeded", "failed", "denied")

#: A machine key and a state name are both undotted lowercase identifiers -- the same shape
#: as an outbox aggregate type, and for the same reason: they end up inside a dotted event
#: type (``<machine_key>.transitioned``) and inside an audit action, both of which are
#: dotted lowercase names. Named separately from :data:`SIMPLE_NAME_REGEX` so that a later
#: change to one is not silently a change to the other, and asserted equal by the tests.
LIFECYCLE_NAME_REGEX = SIMPLE_NAME_REGEX

#: Bounds on one machine definition. Not a security property -- the closed scope catalogue
#: and the protected tables are -- but a definition is data, and unbounded data in a table
#: every policy predicate reads is a cost nobody chose. A machine that needs more than this
#: is a machine that should be several.
MAX_LIFECYCLE_STATES = 64
MAX_LIFECYCLE_TRANSITIONS = 512

#: A transition reason is bounded free text: a short, metadata-only note about *why*.
#: It is not a place for content, and the same secret-shape rule that guards metadata
#: values guards it -- in Python and again in PostgreSQL.
MAX_LIFECYCLE_REASON_LENGTH = 200

#: What kind of identity acted. ``credential`` is a bearer credential resolved through
#: ``firmbatch.bind_authenticated_context``; ``provisioning`` is the internal path that
#: creates a tenant, which by construction has no credential yet -- see
#: ``firmbatch.begin_tenant_provisioning()``.
AUDIT_ACTOR_KINDS: tuple[str, ...] = ("credential", "provisioning")

_UUID_PK = UUID(as_uuid=True)
_TIMESTAMPTZ = TIMESTAMP(timezone=True)
_JSONB = JSONB(none_as_null=True)


def _metadata_constraints(column: str, prefix: str) -> tuple[CheckConstraint, ...]:
    """The two checks every metadata column carries: an object, and a bounded one."""
    return (
        CheckConstraint(f"jsonb_typeof({column}) = 'object'", name=f"{prefix}_object"),
        CheckConstraint(f"octet_length({column}::text) <= {MAX_METADATA_BYTES}", name=f"{prefix}_bounded"),
    )


class Tenant(Base):
    """The top-level isolation scope. Everything tenant-owned points here."""

    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    slug: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))

    __table_args__ = (
        # Tenant slugs ARE global: a tenant slug is the outermost namespace, so there is
        # no enclosing scope to make it local to.
        UniqueConstraint("slug", name="uq_tenants_slug"),
        CheckConstraint(f"slug ~ '{SLUG_REGEX}'", name="slug_format"),
        CheckConstraint("length(name) between 1 and 200", name="name_length"),
    )


class Workspace(Base):
    """A tenant-owned container. The first row that proves the isolation boundary."""

    __tablename__ = "workspaces"

    id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        _UUID_PK,
        # Schema-qualified. An unqualified target is resolved through whatever
        # search_path the caller arrived with, which is precisely what the pinned
        # schema exists to remove.
        ForeignKey(f"{SCHEMA}.tenants.id", ondelete="CASCADE", name="fk_workspaces_tenant_id_tenants"),
        nullable=False,
    )
    slug: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))

    __table_args__ = (
        # Tenant-local, not global. Two tenants may both own a workspace called
        # "production" and neither can detect the other through a constraint error.
        UniqueConstraint("tenant_id", "slug", name="uq_workspaces_tenant_id_slug"),
        UniqueConstraint("tenant_id", "name", name="uq_workspaces_tenant_id_name"),
        # The composite key future child tables reference; see the module docstring.
        UniqueConstraint("id", "tenant_id", name="uq_workspaces_id_tenant_id"),
        CheckConstraint(f"slug ~ '{SLUG_REGEX}'", name="slug_format"),
        CheckConstraint("length(name) between 1 and 200", name="name_length"),
        Index("ix_workspaces_tenant_id", "tenant_id"),
    )


class IdempotencyRecord(Base):
    """One committed claim of an idempotency key, with the result a retry replays.

    Scoped by ``(tenant_id, operation, idempotency_key)`` and never globally. A global
    key space would let one tenant's key collide with -- or probe for -- another's, and
    would make "the same key" mean something across an isolation boundary that exists
    precisely so that it does not.

    ``request_fingerprint`` is a SHA-256 digest of the canonical request. Storing the
    digest rather than the request is what lets a conflicting reuse be rejected without
    the request itself, which may reference customer payload, ever reaching PostgreSQL.

    A row appears only at ``COMMIT``, together with the business mutation and the outbox
    event it belongs to. Nothing updates or deletes one; see :data:`APPEND_ONLY_TABLES`.
    """

    __tablename__ = "idempotency_records"

    id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        _UUID_PK,
        ForeignKey(f"{SCHEMA}.tenants.id", ondelete="CASCADE", name="fk_idempotency_records_tenant_id_tenants"),
        nullable=False,
    )
    #: What the key is scoped to, alongside the tenant. Two different operations may use
    #: the same key without one replaying the other's result.
    operation: Mapped[str] = mapped_column(Text, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(Text, nullable=False)
    request_fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text(f"'{IDEMPOTENCY_STATUS_COMPLETED}'"))
    #: Metadata only: identifiers and counts describing what the mutation did. Never the
    #: request, never a payload, never a credential.
    result: Mapped[dict[str, Any]] = mapped_column(_JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))
    #: **The lifecycle tag, and it is derived rather than supplied.**
    #:
    #: NULL for every generic Milestone 2.2 mutation, which is what leaves that behaviour
    #: exactly as it was. Set by the two lifecycle entry points in migration ``0004``, which
    #: are ``SECURITY DEFINER`` and therefore run as the schema owner; a
    #: ``BEFORE INSERT`` trigger refuses a non-NULL value from any other writer.
    #:
    #: It exists because ``mutation:execute`` is the capability to *claim a key and append
    #: an event*, and was never meant to be permission to read what somebody else's
    #: lifecycle did. A tagged row's ``SELECT`` policy additionally requires the machine
    #: version's declared read scope, so the framework capability alone no longer reads a
    #: machine's states, revisions and identifiers out of the records the framework keeps.
    #: ``FetchedValue()`` rather than a real server default, and it is what keeps this
    #: column out of every ORM ``INSERT``: SQLAlchemy omits a column it believes the
    #: database supplies. The application role holds no ``INSERT`` privilege on it, so an
    #: ORM write that named it -- which is what a plain nullable column produces, as an
    #: explicit NULL -- would be refused outright. A caller that deliberately assigns the
    #: attribute still emits it, and is still refused; that is the intended answer.
    lifecycle_machine_key: Mapped[str | None] = mapped_column(
        Text, nullable=True, server_default=FetchedValue()
    )
    lifecycle_machine_version: Mapped[int | None] = mapped_column(
        Integer, nullable=True, server_default=FetchedValue()
    )

    __table_args__ = (
        # THE concurrency control. Two transactions claiming one key serialise on this
        # index: the second blocks until the first commits and then sees a unique
        # violation, which is what makes "one committed effect" a database fact rather
        # than a property of an in-process lock that only holds inside one process.
        UniqueConstraint(
            "tenant_id", "operation", "idempotency_key", name="uq_idempotency_records_tenant_id_operation_idempotency_key"
        ),
        # The composite key outbox_events references, because FK checks bypass RLS.
        UniqueConstraint("id", "tenant_id", name="uq_idempotency_records_id_tenant_id"),
        CheckConstraint(f"operation ~ '{DOTTED_NAME_REGEX}'", name="operation_format"),
        CheckConstraint(f"idempotency_key ~ '{IDEMPOTENCY_KEY_REGEX}'", name="idempotency_key_format"),
        CheckConstraint(f"request_fingerprint ~ '{FINGERPRINT_REGEX}'", name="request_fingerprint_format"),
        CheckConstraint(f"status = '{IDEMPOTENCY_STATUS_COMPLETED}'", name="status_completed"),
        *_metadata_constraints("result", "result"),
        # Both or neither, so a half-written tag cannot make a row look untagged
        # to the read policy while still naming a machine.
        CheckConstraint(
            "(lifecycle_machine_key IS NULL) = (lifecycle_machine_version IS NULL)",
            name="lifecycle_tag_complete",
        ),
        # The tag names a real machine version, so the read policy's scope lookup
        # always has something to find.
        ForeignKeyConstraint(
            ["lifecycle_machine_key", "lifecycle_machine_version"],
            [f"{SCHEMA}.lifecycle_machines.machine_key", f"{SCHEMA}.lifecycle_machines.version"],
            name="fk_idempotency_records_lifecycle_machine_lifecycle_machines",
        ),
        # **The reserved lifecycle namespace, tied to the derived tag in both directions.**
        #
        # An operation starts with ``lifecycle.`` exactly when the row carries a machine
        # tag, and only the schema owner can write that tag. So a generic Milestone 2.2
        # writer cannot create a claim in the namespace at all -- untagged it fails this
        # constraint, tagged it fails the trigger -- and therefore cannot collide with a
        # lifecycle claim or use the unique index to ask whether one exists. The lifecycle
        # operation carries the machine key and version, so two machines do not share a
        # uniqueness domain either.
        CheckConstraint(
            "pg_catalog.starts_with(operation, 'lifecycle.') "
            "= (lifecycle_machine_key IS NOT NULL)",
            name="lifecycle_namespace_reserved",
        ),
        # No ix_idempotency_records_tenant_id: the unique constraint above already leads
        # with tenant_id, so a second index on it would be dead weight.
    )


class OutboxEvent(Base):
    """One durable intent, committed with the state change that caused it.

    The outbox records that something happened, not that anybody was told. A dispatcher
    is Milestone 6 work and does not exist; when it does, it may deliver **at least
    once**, and its delivery state belongs in a separate table so that the event content
    here stays immutable.

    Bounded metadata, and enforced as such: an event names what it is about
    (``aggregate_type``, ``aggregate_id``) and carries a small ``attributes`` object of
    identifiers, counts, digests and references to objects that live elsewhere.

    Written by :func:`~firmbatch.control_plane.db.idempotency.append_outbox_event`, which
    every authoritative state transition can call -- with an idempotency claim behind it,
    or without one.

    There is deliberately no monotonic sequence column. A cluster-wide sequence is shared
    across tenants, so the gaps in one tenant's numbers measure another tenant's write
    volume -- the same leak that makes workspace slugs tenant-local here. A dispatcher
    orders by ``(occurred_at, id)`` within the tenant it is reading.
    """

    __tablename__ = "outbox_events"

    id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        _UUID_PK,
        ForeignKey(f"{SCHEMA}.tenants.id", ondelete="CASCADE", name="fk_outbox_events_tenant_id_tenants"),
        nullable=False,
    )
    #: An **optional causation link** to the API idempotency claim this event was
    #: committed with, when there was one.
    #:
    #: Nullable because the outbox belongs to every authoritative state transition, not
    #: only to API mutations. The controller, the reconciler, the validator and the
    #: lifecycle machines of later milestones all commit an event with the state change
    #: that caused it, and none of them has a caller-supplied idempotency key; requiring
    #: one would mean manufacturing a fake claim per internal transition, which would put
    #: rows nobody can retry against into the table that exists to record retries.
    idempotency_record_id: Mapped[uuid.UUID | None] = mapped_column(_UUID_PK, nullable=True)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    #: What the event is about. Deliberately not a foreign key: the referent is
    #: polymorphic, and an FK per aggregate kind would couple the outbox to every table
    #: the product will ever have.
    aggregate_type: Mapped[str] = mapped_column(Text, nullable=False)
    aggregate_id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(_JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    occurred_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))
    #: **The lifecycle tag, and it is derived rather than supplied.**
    #:
    #: NULL for every generic Milestone 2.2 mutation, which is what leaves that behaviour
    #: exactly as it was. Set by the two lifecycle entry points in migration ``0004``, which
    #: are ``SECURITY DEFINER`` and therefore run as the schema owner; a
    #: ``BEFORE INSERT`` trigger refuses a non-NULL value from any other writer.
    #:
    #: It exists because ``mutation:execute`` is the capability to *claim a key and append
    #: an event*, and was never meant to be permission to read what somebody else's
    #: lifecycle did. A tagged row's ``SELECT`` policy additionally requires the machine
    #: version's declared read scope, so the framework capability alone no longer reads a
    #: machine's states, revisions and identifiers out of the records the framework keeps.
    #: ``FetchedValue()`` rather than a real server default, and it is what keeps this
    #: column out of every ORM ``INSERT``: SQLAlchemy omits a column it believes the
    #: database supplies. The application role holds no ``INSERT`` privilege on it, so an
    #: ORM write that named it -- which is what a plain nullable column produces, as an
    #: explicit NULL -- would be refused outright. A caller that deliberately assigns the
    #: attribute still emits it, and is still refused; that is the intended answer.
    lifecycle_machine_key: Mapped[str | None] = mapped_column(
        Text, nullable=True, server_default=FetchedValue()
    )
    lifecycle_machine_version: Mapped[int | None] = mapped_column(
        Integer, nullable=True, server_default=FetchedValue()
    )

    __table_args__ = (
        # Tenant-consistent by construction *when the link is present*: the referenced
        # claim must belong to the same tenant as the event, and PostgreSQL checks
        # referential integrity with row security bypassed, so a plain
        # REFERENCES idempotency_records(id) would happily point across tenants.
        # A composite MATCH SIMPLE reference is satisfied when any column is NULL, so an
        # unlinked event is exempt rather than dangling.
        ForeignKeyConstraint(
            ["idempotency_record_id", "tenant_id"],
            [f"{SCHEMA}.idempotency_records.id", f"{SCHEMA}.idempotency_records.tenant_id"],
            name="fk_outbox_events_idempotency_record_id_tenant_id",
            ondelete="CASCADE",
        ),
        # **At most one** linked event per claim. It cannot say that every claim has one --
        # a unique constraint bounds duplicates, it does not require existence -- so
        # "the primitive writes exactly one, atomically" is proved by the tests in
        # tests/test_idempotency.py rather than asserted here. PostgreSQL treats NULLs as
        # distinct by default, so events with no claim do not collide with each other.
        UniqueConstraint("tenant_id", "idempotency_record_id", name="uq_outbox_events_tenant_id_idempotency_record_id"),
        CheckConstraint(f"event_type ~ '{DOTTED_NAME_REGEX}'", name="event_type_format"),
        CheckConstraint(f"aggregate_type ~ '{SIMPLE_NAME_REGEX}'", name="aggregate_type_format"),
        *_metadata_constraints("attributes", "attributes"),
        # Both or neither, so a half-written tag cannot make a row look untagged
        # to the read policy while still naming a machine.
        CheckConstraint(
            "(lifecycle_machine_key IS NULL) = (lifecycle_machine_version IS NULL)",
            name="lifecycle_tag_complete",
        ),
        # The tag names a real machine version, so the read policy's scope lookup
        # always has something to find.
        ForeignKeyConstraint(
            ["lifecycle_machine_key", "lifecycle_machine_version"],
            [f"{SCHEMA}.lifecycle_machines.machine_key", f"{SCHEMA}.lifecycle_machines.version"],
            name="fk_outbox_events_lifecycle_machine_lifecycle_machines",
        ),
        # The composite key ``lifecycle_claim_provenance`` references. Foreign keys are
        # checked with row security bypassed, so a single-column reference to ``id`` would
        # reach across tenants.
        UniqueConstraint("id", "tenant_id", name="uq_outbox_events_id_tenant_id"),
        # For a future dispatcher's "oldest first, within my tenant" read.
        Index("ix_outbox_events_tenant_id_occurred_at", "tenant_id", "occurred_at"),
    )


class AuthBinding(Base):
    """One authentication binding: a credential fingerprint, and what it authorises.

    **This table is protected, not policed.** No role but the schema owner holds any
    privilege on it -- not the application role, not the provisioning role, not PUBLIC --
    so there is no query any runtime connection can run against it, with or without a
    tenant context. It carries no row-level security policy for that reason: a policy
    bounds what a role with privileges may reach, and here no role has any.

    The only ways in are the ``SECURITY DEFINER`` functions migration ``0003`` creates:
    ``register_auth_binding`` (writes one, in the tenant of the current context),
    ``revoke_auth_binding`` (marks one revoked, in the tenant of the current context) and
    ``bind_authenticated_context`` (reads one by fingerprint, and returns nothing about
    it except the context it establishes). None of them takes a tenant, a binding id, a
    fingerprint or a scope from the caller as the thing that selects a row: the first two
    derive the tenant from the context, and the third selects on a digest of the secret
    the caller presented.

    ``fingerprint`` is a hex SHA-256 digest computed **in PostgreSQL**. The credential
    itself is never stored, never returned, and never logged by this package. The digest
    is globally unique rather than tenant-unique: the fingerprint space is global, a
    cross-tenant collision would be a SHA-256 collision, and nothing can observe the
    constraint anyway because nothing can query the table.

    ``scopes`` is bounded by a check constraint against the closed catalogue in
    ``security/authorization.py``, so an unknown capability cannot be stored and then
    become meaningful when somebody later adds a policy for it.
    """

    __tablename__ = "auth_bindings"

    id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        _UUID_PK,
        ForeignKey(f"{SCHEMA}.tenants.id", ondelete="CASCADE", name="fk_auth_bindings_tenant_id_tenants"),
        nullable=False,
    )
    #: The identity acting through this credential. Milestone 3 gives principals their own
    #: table (users, service identities, memberships); until then it is an opaque
    #: identifier the credential carries, which is what audit needs to answer "who".
    principal_id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, nullable=False)
    fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    scopes: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))
    #: ``NULL`` means "does not expire". An expired binding fails closed at bind time.
    expires_at: Mapped[datetime | None] = mapped_column(_TIMESTAMPTZ, nullable=True)
    #: Set by ``revoke_auth_binding``. Revocation is a state, not a deletion: a deleted
    #: binding would take the audit trail's foreign key with it.
    revoked_at: Mapped[datetime | None] = mapped_column(_TIMESTAMPTZ, nullable=True)

    __table_args__ = (
        UniqueConstraint("fingerprint", name="uq_auth_bindings_fingerprint"),
        UniqueConstraint("id", "tenant_id", name="uq_auth_bindings_id_tenant_id"),
        CheckConstraint(f"fingerprint ~ '{CREDENTIAL_FINGERPRINT_REGEX}'", name="fingerprint_format"),
        # One dimension, no NULL elements, bounded, and every element in the catalogue.
        CheckConstraint("array_ndims(scopes) = 1", name="scopes_one_dimension"),
        CheckConstraint(f"cardinality(scopes) <= {MAX_SCOPES_PER_BINDING}", name="scopes_bounded"),
        CheckConstraint("array_position(scopes, NULL) IS NULL", name="scopes_not_null"),
        CheckConstraint(
            "scopes <@ ARRAY[" + ", ".join(f"'{scope}'" for scope in KNOWN_SCOPES) + "]::text[]",
            name="scopes_known",
        ),
        CheckConstraint(
            "expires_at IS NULL OR expires_at > created_at", name="expiry_after_creation"
        ),
        Index("ix_auth_bindings_tenant_id", "tenant_id"),
    )


class AuditEvent(Base):
    """One durable record of something a principal did, or tried to do, in one tenant.

    Distinct from an outbox event, and the distinction is worth keeping sharp because the
    two look similar and answer different questions. An **outbox event** is intent to tell
    somebody that state changed; it is addressed outward, a dispatcher will one day read
    it, and its content is chosen by the state machine that emitted it. An **audit event**
    is a record of *who did what*; it is addressed inward, nothing dispatches it, and its
    actor and tenant are not chosen by anyone -- they are taken from the authenticated
    context by column default and re-checked by the insert policy.

    Neither is derivable from the other. An action that changes no state still belongs in
    the audit trail (a denied attempt, most obviously), and an internal state transition
    with no actor still belongs in the outbox.

    Append-only in the same two independent ways as the M2.2 tables: no ``UPDATE`` or
    ``DELETE`` privilege for any runtime role, and no ``UPDATE`` or ``DELETE`` policy at
    all, so those commands reach no row even for the owner under ``FORCE``.

    There is deliberately **no hash chain and no external delivery**. The canonical
    architecture asks for audit events, not for a tamper-evident log or an audit shipper,
    and building either here would be machinery invented ahead of a requirement. What
    makes these rows trustworthy at this milestone is that no role can change one and no
    role can write one about another tenant or another actor.
    """

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    #: Derived, not supplied. The server default reads the authenticated context, and the
    #: insert policy refuses any value that disagrees with it -- so a caller that sets the
    #: column explicitly is refused rather than silently corrected.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        _UUID_PK,
        ForeignKey(f"{SCHEMA}.tenants.id", ondelete="CASCADE", name="fk_audit_events_tenant_id_tenants"),
        nullable=False,
        server_default=text(f"{SCHEMA}.auth_tenant_id()"),
    )
    actor_kind: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text(f"{SCHEMA}.auth_actor_kind()")
    )
    actor_principal_id: Mapped[uuid.UUID | None] = mapped_column(
        _UUID_PK, nullable=True, server_default=text(f"{SCHEMA}.auth_principal_id()")
    )
    actor_binding_id: Mapped[uuid.UUID | None] = mapped_column(
        _UUID_PK, nullable=True, server_default=text(f"{SCHEMA}.auth_binding_id()")
    )
    #: What was done -- ``workspace.create``, ``auth.binding_registered``.
    action: Mapped[str] = mapped_column(Text, nullable=False)
    #: Whether it was attempted, completed, failed, or refused.
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    resource_type: Mapped[str] = mapped_column(Text, nullable=False)
    #: ``NULL`` where the action has no resource yet -- a refused creation, for instance.
    resource_id: Mapped[uuid.UUID | None] = mapped_column(_UUID_PK, nullable=True)
    #: The request or correlation this action belonged to. Caller-supplied, because
    #: correlation is the caller's fact about its own request; it carries no authority and
    #: nothing is decided from it.
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(_UUID_PK, nullable=True)
    #: **The lifecycle tag, derived and not supplied**, exactly as on the two Milestone 2.2
    #: framework tables -- and here for the same reason, which was missed the first time. An
    #: audit row for a lifecycle action carries the instance id in ``resource_id`` and the
    #: machine, the states, the revisions and the transition id in ``details``, so
    #: ``audit:read`` alone read the whole trajectory of a machine the credential holds no
    #: capability for. A tagged row's ``SELECT`` policy additionally requires that machine
    #: version's declared read scope; an untagged row -- every non-lifecycle action -- is
    #: unaffected.
    #: ``FetchedValue()`` rather than a real server default, and it is what keeps this
    #: column out of every ORM ``INSERT``: SQLAlchemy omits a column it believes the
    #: database supplies. The application role holds no ``INSERT`` privilege on it, so an
    #: ORM write that named it -- which is what a plain nullable column produces, as an
    #: explicit NULL -- would be refused outright. A caller that deliberately assigns the
    #: attribute still emits it, and is still refused; that is the intended answer.
    lifecycle_machine_key: Mapped[str | None] = mapped_column(
        Text, nullable=True, server_default=FetchedValue()
    )
    lifecycle_machine_version: Mapped[int | None] = mapped_column(
        Integer, nullable=True, server_default=FetchedValue()
    )
    #: Bounded metadata, validated before the insert. Never a payload, never a credential.
    details: Mapped[dict[str, Any]] = mapped_column(_JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    #: Server-generated, by a ``BEFORE INSERT`` trigger that overwrites whatever arrives
    #: with ``clock_timestamp()``. Not ``now()``, which is transaction-*start* time: a
    #: caller that opened its transaction an hour ago could otherwise date an event an hour
    #: into the past without supplying anything at all. And a trigger rather than a
    #: default, because a default only applies when the column is omitted.
    occurred_at: Mapped[datetime] = mapped_column(
        _TIMESTAMPTZ, nullable=False, server_default=text("clock_timestamp()")
    )

    __table_args__ = (
        # The actor is a real binding in this tenant, or there is no binding at all
        # (the provisioning path). Composite, because referential integrity is checked
        # with row security bypassed and a single-column reference would reach across
        # tenants. MATCH SIMPLE exempts the NULL case rather than dangling on it.
        ForeignKeyConstraint(
            ["actor_binding_id", "tenant_id"],
            [f"{SCHEMA}.auth_bindings.id", f"{SCHEMA}.auth_bindings.tenant_id"],
            name="fk_audit_events_actor_binding_id_tenant_id",
            ondelete="CASCADE",
        ),
        UniqueConstraint("id", "tenant_id", name="uq_audit_events_id_tenant_id"),
        CheckConstraint(f"action ~ '{DOTTED_NAME_REGEX}'", name="action_format"),
        CheckConstraint(f"resource_type ~ '{SIMPLE_NAME_REGEX}'", name="resource_type_format"),
        CheckConstraint(
            "outcome IN (" + ", ".join(f"'{value}'" for value in AUDIT_OUTCOMES) + ")",
            name="outcome_known",
        ),
        CheckConstraint(
            "actor_kind IN (" + ", ".join(f"'{value}'" for value in AUDIT_ACTOR_KINDS) + ")",
            name="actor_kind_known",
        ),
        # A credential actor has both identifiers; a provisioning actor has neither. A
        # half-filled actor would be a record nobody could interpret.
        CheckConstraint(
            "(actor_kind = 'credential' AND actor_principal_id IS NOT NULL AND actor_binding_id IS NOT NULL)"
            " OR (actor_kind = 'provisioning' AND actor_principal_id IS NULL AND actor_binding_id IS NULL)",
            name="actor_shape",
        ),
        *_metadata_constraints("details", "details"),
        # Both or neither, so a half-written tag cannot make a row look untagged to the
        # read policy while still naming a machine.
        CheckConstraint(
            "(lifecycle_machine_key IS NULL) = (lifecycle_machine_version IS NULL)",
            name="lifecycle_tag_complete",
        ),
        ForeignKeyConstraint(
            ["lifecycle_machine_key", "lifecycle_machine_version"],
            [f"{SCHEMA}.lifecycle_machines.machine_key", f"{SCHEMA}.lifecycle_machines.version"],
            name="fk_audit_events_lifecycle_machine_lifecycle_machines",
        ),
        # The reserved namespace again, on ``action`` this time. ``append_audit_event`` --
        # the generic path, granted to both runtime roles -- never sets the tag, so a
        # ``lifecycle.`` action written through it is refused here: a caller cannot forge an
        # untagged audit row that looks like a lifecycle one and is therefore readable with
        # ``audit:read`` alone. The lifecycle kernel has its own internal append, executable
        # by nobody, which is what sets the tag.
        CheckConstraint(
            "pg_catalog.starts_with(action, 'lifecycle.') "
            "= (lifecycle_machine_key IS NOT NULL)",
            name="lifecycle_namespace_reserved",
        ),
        Index("ix_audit_events_tenant_id_occurred_at", "tenant_id", "occurred_at"),
    )


class LifecycleMachine(Base):
    """One immutable, versioned state-machine definition. **Global, and protected.**

    Global because a machine version is one graph, not one graph per tenant: two tenants
    running ``job`` version 3 are running the same 3. The target architecture already draws
    this line -- "every tenant-owned authoritative row carries ``tenant_id``; shared
    provider and certification records are explicitly global" (section 3.1) -- and a
    definition is a shared record in exactly that sense.

    Protected because the required scopes live here. A role that could write this row could
    lower the capability its own instances demand, which is a privilege escalation dressed
    as a configuration change. No runtime or provisioning role holds any privilege on it,
    and a ``BEFORE UPDATE OR DELETE`` trigger refuses a change even for the owner: a
    registered version is immutable, and a change is a new version. That is what keeps
    ``lifecycle_transitions`` a readable history rather than a set of rows whose meaning
    quietly changed underneath them.

    Registration is an **owner-run admin action**, like ``db/roles.py``'s grants: outside
    Alembic, because the definitions a deployment needs are a property of which milestones
    it runs rather than of the schema. M2.4 registers **none** -- the job and window-offer
    machines belong to Milestones 5 and 6, alongside the domain tables they describe.
    """

    __tablename__ = "lifecycle_machines"

    machine_key: Mapped[str] = mapped_column(Text, primary_key=True)
    #: Positive and monotonic per key. There is no "latest" pointer, deliberately: an
    #: instance pins its version at creation, and a reader that wants the newest one asks
    #: for the newest one rather than being handed a moving answer.
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: The scope an instance of this version requires to be read, created, and moved. Read
    #: back by ``firmbatch.lifecycle_required_scope()``, which every policy on
    #: ``lifecycle_instances`` and ``lifecycle_transitions`` calls -- so the capability is
    #: derived from protected data and is never something a caller states.
    read_scope: Mapped[str] = mapped_column(Text, nullable=False)
    create_scope: Mapped[str] = mapped_column(Text, nullable=False)
    transition_scope: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))
    #: NULL until the definition is complete and sealed.
    #:
    #: A machine is assembled over several statements -- the row, then its states, then
    #: its edges -- and between the first and the last it is a partial graph. Every
    #: consumer goes through a reader that requires this column, so a partial definition
    #: has no required scope, no initial state and no edges as far as anything that uses
    #: one is concerned. ``firmbatch.publish_lifecycle_machine()`` sets it, as the last
    #: statement of registration and in the same transaction, after checking the whole
    #: graph; a trigger permits that one update and no other, so there is no
    #: unpublishing and no editing of a published machine.
    published_at: Mapped[datetime | None] = mapped_column(_TIMESTAMPTZ, nullable=True)

    __table_args__ = (
        CheckConstraint(f"machine_key ~ '{LIFECYCLE_NAME_REGEX}'", name="machine_key_format"),
        CheckConstraint("version >= 1", name="version_positive"),
        # Only a scope that already exists, and never the bootstrap-only one. See
        # security/authorization.LIFECYCLE_ELIGIBLE_SCOPES for why tenant:provision is out.
        *(
            CheckConstraint(
                f"{column} IN (" + ", ".join(f"'{scope}'" for scope in LIFECYCLE_ELIGIBLE_SCOPES) + ")",
                name=f"{column}_eligible",
            )
            for column in ("read_scope", "create_scope", "transition_scope")
        ),
    )


class LifecycleState(Base):
    """One state of one machine version, with its initial and terminal markers.

    The state set is explicit rather than implied by the edges: a state with no edges at
    all is a legitimate part of a graph, and deriving the set from the edges would make it
    unrepresentable. ``lifecycle_instances`` references this table, so an instance cannot
    hold a state its machine version does not declare -- checked by PostgreSQL with row
    security bypassed, which is what makes it hold for every writer rather than for the
    ones that went through the function.

    **Exactly one initial state** is a database fact: the partial unique index below
    permits one row per machine version with ``is_initial``. That a version has *at least*
    one is enforced at registration and by ``firmbatch.create_lifecycle_instance()``, which
    refuses a version whose initial state it cannot find -- a unique index bounds
    duplicates and cannot require existence, exactly as the M2.2 outbox link cannot.
    """

    __tablename__ = "lifecycle_states"

    machine_key: Mapped[str] = mapped_column(Text, primary_key=True)
    machine_version: Mapped[int] = mapped_column(Integer, primary_key=True)
    state: Mapped[str] = mapped_column(Text, primary_key=True)
    is_initial: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    #: A terminal state has no outgoing edge, enforced when an edge is inserted. It is a
    #: marker rather than a derived property so that "this machine is finished here" is
    #: something the definition *says*, and so a state that simply has no edges yet cannot
    #: be mistaken for one.
    is_terminal: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))

    __table_args__ = (
        ForeignKeyConstraint(
            ["machine_key", "machine_version"],
            [f"{SCHEMA}.lifecycle_machines.machine_key", f"{SCHEMA}.lifecycle_machines.version"],
            name="fk_lifecycle_states_machine_lifecycle_machines",
        ),
        CheckConstraint(f"state ~ '{LIFECYCLE_NAME_REGEX}'", name="state_format"),
        # One initial state per machine version, in the schema rather than in a comment.
        Index(
            "uq_lifecycle_states_one_initial_per_version",
            "machine_key",
            "machine_version",
            unique=True,
            postgresql_where=text("is_initial"),
        ),
    )


class LifecycleTransitionEdge(Base):
    """One allowed move of one machine version. The graph, as rows.

    Both endpoints reference :class:`LifecycleState`, so an edge cannot name a state the
    version does not have. The primary key is the whole edge, so an edge cannot be
    duplicated. And a ``BEFORE INSERT`` trigger refuses an edge whose source is terminal,
    which is the one graph rule this milestone imposes beyond "the states are known".

    Deliberately **no acyclicity rule**. A cycle is a legitimate machine -- a window offer
    that is revoked and re-offered, a shard that is re-leased -- and a kernel that assumed
    otherwise would have to be argued with by every domain that needs one.
    """

    __tablename__ = "lifecycle_transition_edges"

    machine_key: Mapped[str] = mapped_column(Text, primary_key=True)
    machine_version: Mapped[int] = mapped_column(Integer, primary_key=True)
    from_state: Mapped[str] = mapped_column(Text, primary_key=True)
    to_state: Mapped[str] = mapped_column(Text, primary_key=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["machine_key", "machine_version", "from_state"],
            [
                f"{SCHEMA}.lifecycle_states.machine_key",
                f"{SCHEMA}.lifecycle_states.machine_version",
                f"{SCHEMA}.lifecycle_states.state",
            ],
            name="fk_lifecycle_transition_edges_from_lifecycle_states",
        ),
        ForeignKeyConstraint(
            ["machine_key", "machine_version", "to_state"],
            [
                f"{SCHEMA}.lifecycle_states.machine_key",
                f"{SCHEMA}.lifecycle_states.machine_version",
                f"{SCHEMA}.lifecycle_states.state",
            ],
            name="fk_lifecycle_transition_edges_to_lifecycle_states",
        ),
    )


class LifecycleInstance(Base):
    """One tenant-owned instance of one pinned machine version.

    Deliberately carries no domain columns. There is no job here, no window offer, no
    attempt: those are Milestone 5 and 6 tables, and they will point at an instance of the
    machine that describes them rather than inheriting from it. What this row is, and all
    it is, is *where this thing has got to* -- a state, a revision, and the machine version
    that decides what either means.

    ``revision`` is the compare-and-swap token. It starts at zero, is incremented by
    exactly one on every accepted transition, and is what a caller presents alongside the
    state it believes it is moving from. Two callers holding the same revision are two
    callers who read the same row; exactly one of them can be right, and PostgreSQL is what
    decides which -- the conditional ``UPDATE`` in
    ``firmbatch.transition_lifecycle_instance()`` carries both in its predicate.

    Immutability is enforced by a ``BEFORE UPDATE`` trigger rather than left to the
    function: ``id``, ``tenant_id``, ``machine_key``, ``machine_version`` and ``created_at``
    cannot change, the revision must increase by exactly one, the source state must not be
    terminal, and ``(old state, new state)`` must be a declared edge. That holds for the
    owner and for any future writer, not only for callers that went through the function.
    """

    __tablename__ = "lifecycle_instances"

    id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        _UUID_PK,
        ForeignKey(f"{SCHEMA}.tenants.id", ondelete="CASCADE", name="fk_lifecycle_instances_tenant_id_tenants"),
        nullable=False,
    )
    machine_key: Mapped[str] = mapped_column(Text, nullable=False)
    machine_version: Mapped[int] = mapped_column(Integer, nullable=False)
    current_state: Mapped[str] = mapped_column(Text, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    created_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))
    #: Server-generated on every write by a ``BEFORE`` trigger, like ``audit_events``'
    #: ``occurred_at`` and for the same reason: a caller that could supply it could supply
    #: a wrong one, and one that opened its transaction early could keep a stale one.
    updated_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))

    __table_args__ = (
        # The state is one this machine version declares. Checked with row security
        # bypassed, so it binds every writer including the owner.
        ForeignKeyConstraint(
            ["machine_key", "machine_version", "current_state"],
            [
                f"{SCHEMA}.lifecycle_states.machine_key",
                f"{SCHEMA}.lifecycle_states.machine_version",
                f"{SCHEMA}.lifecycle_states.state",
            ],
            name="fk_lifecycle_instances_state_lifecycle_states",
        ),
        # The composite key a future child table references, because FK checks bypass RLS.
        UniqueConstraint("id", "tenant_id", name="uq_lifecycle_instances_id_tenant_id"),
        # And the one lifecycle_transitions references, which additionally pins the machine
        # -- so a history row cannot claim an instance is running a machine it is not.
        UniqueConstraint(
            "id",
            "tenant_id",
            "machine_key",
            "machine_version",
            name="uq_lifecycle_instances_id_tenant_id_machine_key_version",
        ),
        CheckConstraint("revision >= 0", name="revision_not_negative"),
        Index("ix_lifecycle_instances_tenant_id_machine_key", "tenant_id", "machine_key"),
    )


class LifecycleTransition(Base):
    """One accepted move, recorded once and never revised.

    Append-only in the same two independent ways as every other append-only table here: no
    runtime role holds ``INSERT``, ``UPDATE`` or ``DELETE`` on it, and it carries no
    ``UPDATE`` or ``DELETE`` policy at all, so those commands reach no row even for the
    owner under ``FORCE``.

    The actor is derived, exactly as an audit event's is: ``actor_kind``,
    ``actor_principal_id`` and ``actor_binding_id`` are written by
    ``firmbatch.transition_lifecycle_instance()`` from the authenticated context, and the
    function has no parameter for any of them.

    Distinct from an audit event, and both are written. A transition row is the machine's
    own history -- the thing a later milestone reconstructs a job's timeline from, keyed by
    revision so it is totally ordered within an instance. An audit event is the record that
    *somebody did this*, in the one trail that answers that question across every kind of
    action. Neither is derivable from the other: the trail does not carry a revision, and
    the history does not carry the denied attempts.
    """

    __tablename__ = "lifecycle_transitions"

    id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        _UUID_PK,
        ForeignKey(f"{SCHEMA}.tenants.id", ondelete="CASCADE", name="fk_lifecycle_transitions_tenant_id_tenants"),
        nullable=False,
    )
    lifecycle_instance_id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, nullable=False)
    machine_key: Mapped[str] = mapped_column(Text, nullable=False)
    machine_version: Mapped[int] = mapped_column(Integer, nullable=False)
    from_state: Mapped[str] = mapped_column(Text, nullable=False)
    to_state: Mapped[str] = mapped_column(Text, nullable=False)
    from_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    to_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    actor_kind: Mapped[str] = mapped_column(Text, nullable=False)
    actor_principal_id: Mapped[uuid.UUID | None] = mapped_column(_UUID_PK, nullable=True)
    actor_binding_id: Mapped[uuid.UUID | None] = mapped_column(_UUID_PK, nullable=True)
    #: Optional, bounded, metadata-only. Why this move was made, in a sentence -- never
    #: what was moved.
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(_JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    occurred_at: Mapped[datetime] = mapped_column(
        _TIMESTAMPTZ, nullable=False, server_default=text("clock_timestamp()")
    )

    __table_args__ = (
        # Tenant AND machine consistency, structurally. A single-column reference to the
        # instance would be satisfied by another tenant's row, because referential
        # integrity is checked with row security bypassed.
        ForeignKeyConstraint(
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
        # **The graph, in the history.** An edge that does not exist cannot be recorded as
        # having been taken -- so "invalid transitions leave no history" is a referential
        # fact and not only a property of the function that refuses them.
        ForeignKeyConstraint(
            ["machine_key", "machine_version", "from_state", "to_state"],
            [
                f"{SCHEMA}.lifecycle_transition_edges.machine_key",
                f"{SCHEMA}.lifecycle_transition_edges.machine_version",
                f"{SCHEMA}.lifecycle_transition_edges.from_state",
                f"{SCHEMA}.lifecycle_transition_edges.to_state",
            ],
            name="fk_lifecycle_transitions_edge_lifecycle_transition_edges",
        ),
        # The actor is a binding in this tenant, or there is none (the provisioning path).
        ForeignKeyConstraint(
            ["actor_binding_id", "tenant_id"],
            [f"{SCHEMA}.auth_bindings.id", f"{SCHEMA}.auth_bindings.tenant_id"],
            name="fk_lifecycle_transitions_actor_binding_auth_bindings",
            ondelete="CASCADE",
        ),
        # One row per revision of an instance. This is the half that makes the history a
        # total order rather than a bag: two rows claiming to be revision 4 would be two
        # accounts of the same moment.
        UniqueConstraint(
            "tenant_id",
            "lifecycle_instance_id",
            "to_revision",
            name="uq_lifecycle_transitions_tenant_id_instance_id_to_revision",
        ),
        UniqueConstraint("id", "tenant_id", name="uq_lifecycle_transitions_id_tenant_id"),
        CheckConstraint("from_revision >= 0", name="from_revision_not_negative"),
        CheckConstraint("to_revision = from_revision + 1", name="revision_advances_by_one"),
        CheckConstraint(
            "actor_kind IN (" + ", ".join(f"'{value}'" for value in AUDIT_ACTOR_KINDS) + ")",
            name="actor_kind_known",
        ),
        CheckConstraint(
            "(actor_kind = 'credential' AND actor_principal_id IS NOT NULL AND actor_binding_id IS NOT NULL)"
            " OR (actor_kind = 'provisioning' AND actor_principal_id IS NULL AND actor_binding_id IS NULL)",
            name="actor_shape",
        ),
        CheckConstraint(
            f"reason IS NULL OR length(reason) BETWEEN 1 AND {MAX_LIFECYCLE_REASON_LENGTH}",
            name="reason_bounded",
        ),
        *_metadata_constraints("details", "details"),
        Index("ix_lifecycle_transitions_tenant_id_occurred_at", "tenant_id", "occurred_at"),
    )


class LifecycleClaimProvenance(Base):
    """What ties one idempotency claim to the transition it stands for. **Protected.**

    A replay hands back the ``result`` a claim stored, so the question "may this row be
    replayed as a lifecycle transition?" has to have an answer that does not come from the
    row itself. The machine tag on ``idempotency_records`` is not that answer: it says which
    machine a row belongs to and nothing about which move it records, so a claim carrying a
    plausible-looking result and a valid tag would have replayed as a transition that never
    happened.

    This relation is the answer. Every column is a foreign key into a row the transition
    wrote, all of them composite so that referential integrity -- which is checked with row
    security bypassed -- cannot reach across tenants, and the replay path insists on the
    whole chain agreeing: the claim, its provenance, the transition, the instance, the event,
    and the stored result's own description of what happened.

    **Protected by privilege, like the definition tables and ``auth_bindings``.** No role
    holds anything on it. It is written by ``firmbatch.transition_lifecycle_instance()``,
    which is ``SECURITY DEFINER`` and therefore runs as the schema owner, and a trigger
    refuses ``INSERT`` from any other identity and refuses ``UPDATE`` and ``DELETE`` from
    everyone including the owner -- because a link that could be re-pointed afterwards would
    prove nothing about the claim it was written for.

    It carries ``tenant_id`` and has no policy of its own, which is deliberate rather than an
    omission: a policy bounds what a *granted* role may reach, and no role is granted
    anything here. Nothing reads it except through the four ``FORCE``-RLS tables its foreign
    keys point at, so the tenant filter is applied by the rows it is verified against.
    """

    __tablename__ = "lifecycle_claim_provenance"

    #: The claim is the identity: one provenance row per claim, so a second one is
    #: inexpressible rather than refused.
    idempotency_record_id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, nullable=False)
    lifecycle_transition_id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, nullable=False)
    lifecycle_instance_id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, nullable=False)
    machine_key: Mapped[str] = mapped_column(Text, nullable=False)
    machine_version: Mapped[int] = mapped_column(Integer, nullable=False)
    from_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    to_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    outbox_event_id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        _TIMESTAMPTZ, nullable=False, server_default=text("clock_timestamp()")
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["idempotency_record_id", "tenant_id"],
            [f"{SCHEMA}.idempotency_records.id", f"{SCHEMA}.idempotency_records.tenant_id"],
            name="fk_lifecycle_claim_provenance_record_idempotency_records",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["lifecycle_transition_id", "tenant_id"],
            [f"{SCHEMA}.lifecycle_transitions.id", f"{SCHEMA}.lifecycle_transitions.tenant_id"],
            name="fk_lifecycle_claim_provenance_transition_lifecycle_transitions",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
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
        ForeignKeyConstraint(
            ["outbox_event_id", "tenant_id"],
            [f"{SCHEMA}.outbox_events.id", f"{SCHEMA}.outbox_events.tenant_id"],
            name="fk_lifecycle_claim_provenance_event_outbox_events",
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "lifecycle_transition_id", name="uq_lifecycle_claim_provenance_transition_id"
        ),
        UniqueConstraint("outbox_event_id", name="uq_lifecycle_claim_provenance_event_id"),
        CheckConstraint("from_revision >= 0", name="from_revision_not_negative"),
        CheckConstraint("to_revision = from_revision + 1", name="revision_advances_by_one"),
    )


#: Tables that carry tenant data and must therefore be under forced row-level security,
#: mapped to the column the isolation policy compares against the **authenticated** tenant
#: context. ``tenants`` is scoped by its own primary key -- a tenant row is visible to
#: exactly the tenant it is.
#:
#: The migration and the tests both read this mapping, so a tenant-owned table added
#: without a policy fails the suite instead of quietly becoming readable across tenants.
#:
#: ``auth_bindings`` is deliberately **not** here. It is protected by having no grants
#: rather than policed by having a policy; see :data:`PROTECTED_TABLES` and the class
#: docstring.
TENANT_SCOPED_TABLES: dict[str, str] = {
    Tenant.__tablename__: "id",
    Workspace.__tablename__: "tenant_id",
    IdempotencyRecord.__tablename__: "tenant_id",
    OutboxEvent.__tablename__: "tenant_id",
    AuditEvent.__tablename__: "tenant_id",
    LifecycleInstance.__tablename__: "tenant_id",
    LifecycleTransition.__tablename__: "tenant_id",
}

#: Tables that no runtime role may reach at all. Re-exported from the permission catalogue
#: so that ``db/`` has one import for it and the two cannot disagree.
#:
#: The distinction from :data:`TENANT_SCOPED_TABLES` is the whole point: a policed table
#: is one a role may query under a predicate; a protected table is one no role may query.
#:
#: Most are tenant-owned, and the three Milestone 2.4 definition tables are **global** --
#: one machine version is one graph for every tenant. Being global does not make a table
#: less protected: a role that could write a definition could change what every tenant's
#: instances are allowed to do, and could lower the capability they require.
PROTECTED_TABLES: frozenset[str] = _CATALOGUE_PROTECTED_TABLES

#: Tenant-scoped tables that are also **append-only**: they get a ``SELECT`` policy and
#: an ``INSERT`` policy and no others, so ``UPDATE`` and ``DELETE`` match no row for any
#: role. Row security is ``FORCE``d, so that includes the table owner.
#:
#: This is the half of append-only that a grant cannot give you. Revoking ``UPDATE`` from
#: the application role stops the application role; it says nothing about the next role
#: somebody adds, or about the owner. Both halves are applied: ``db/roles.py`` grants
#: only ``SELECT, INSERT``, and the policies below mean even a role that somehow held
#: ``UPDATE`` would change nothing.
#:
#: One route remains open by design and is named rather than hidden: deleting a *tenant*
#: cascades through the foreign keys, and referential actions are not subject to row
#: security. No runtime role can take it -- neither the application role nor the
#: provisioning role holds ``DELETE`` on ``tenants`` -- and erasing a tenant's records
#: along with the tenant is the behaviour you want anyway.
APPEND_ONLY_TABLES: frozenset[str] = frozenset(
    {
        IdempotencyRecord.__tablename__,
        OutboxEvent.__tablename__,
        AuditEvent.__tablename__,
        LifecycleTransition.__tablename__,
    }
)

#: The definition tables, which are immutable in a third way the two above are not: a row
#: trigger refuses ``UPDATE`` and ``DELETE`` outright, so a registered machine version
#: cannot be revised even by the owner and even with row security out of the way. They are
#: not in :data:`APPEND_ONLY_TABLES` because that set is about *tenant-scoped* tables and
#: the policy arrangement that makes them append-only; these have no policies at all.
IMMUTABLE_DEFINITION_TABLES: frozenset[str] = frozenset(
    {
        LifecycleMachine.__tablename__,
        LifecycleState.__tablename__,
        LifecycleTransitionEdge.__tablename__,
    }
)
