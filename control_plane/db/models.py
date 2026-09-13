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

#: Milestone 3.1's third actor kind: a browser session bound to a workspace through an
#: active membership. The principal is the account; there is no binding. Kept **beside**
#: :data:`AUDIT_ACTOR_KINDS` rather than appended to it, because migrations ``0003`` and
#: ``0004`` carry a copy of the Milestone 2 tuple that the tests hold to be equal, and the
#: vocabulary the database enforces from ``0005`` on is :data:`ACTOR_KINDS`.
SESSION_ACTOR_KIND = "session"
ACTOR_KINDS: tuple[str, ...] = AUDIT_ACTOR_KINDS + (SESSION_ACTOR_KIND,)

#: The shape every actor-carrying row has to satisfy, since ``0005``: a credential actor
#: has a principal and a binding, a provisioning actor has neither, a session actor has a
#: principal (the account) and no binding.
ACTOR_SHAPE_SQL = (
    "(actor_kind = 'credential' AND actor_principal_id IS NOT NULL AND actor_binding_id IS NOT NULL)"
    " OR (actor_kind = 'provisioning' AND actor_principal_id IS NULL AND actor_binding_id IS NULL)"
    " OR (actor_kind = 'session' AND actor_principal_id IS NOT NULL AND actor_binding_id IS NULL)"
)

# ------------------------------------------------------------------- Milestone 3.1

#: A normalised email address: lower-cased, trimmed, one ``@``, a bounded local part and a
#: dotted domain. ASCII-explicit so Python and PostgreSQL agree without consulting a
#: locale; ``db/accounts`` applies it in Python and ``0005`` in the database.
EMAIL_REGEX = r"^[a-z0-9._%+-]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
EMAIL_MAX_LENGTH = 254

#: The stored password form and its bound. Mirrors ``security/passwords``.
PASSWORD_HASH_REGEX = (
    r"^\$argon2id\$v=19\$m=[0-9]{1,9},t=[0-9]{1,4},p=[0-9]{1,3}"
    r"\$[A-Za-z0-9+/]{16,}\$[A-Za-z0-9+/]{16,}$"
)
PASSWORD_HASH_MAX_LENGTH = 512

ACCOUNT_STATUSES: tuple[str, ...] = ("active", "unverified")
ACCOUNT_TOKEN_KINDS: tuple[str, ...] = ("account_recovery", "email_verification")

#: The closed role model, sorted. The authoritative statement is
#: ``security/permissions.MEMBERSHIP_ROLES``; this copy is what the check constraints
#: below render, and a test holds the two equal.
MEMBERSHIP_ROLES: tuple[str, ...] = ("admin", "member", "owner", "viewer")

#: A customer-chosen credential label: short, and never a place for a secret.
CREDENTIAL_LABEL_MAX_LENGTH = 100

# --------------------------------------------------------- Milestone 3.2 preferences
#
# The vocabularies ``workspace_preferences`` is closed over. Every one is taken from the
# target architecture; none is invented here, and none is a *setting* that changes what the
# system does. A row in that table is what the customer told us they intend, and the
# roadmap's M3.2 line qualifies it: captured "for later use **without claiming a quote or an
# execution**". Migration ``0006`` renders these as check constraints and
# ``tests/test_portal_migration.py`` holds the two copies equal.

#: Region groups a customer may state in ``region_policy``. **Closed, and deliberately
#: short.** The canonical JobSpec (target §5.2) names exactly one, ``EU``. The target's
#: own header says regions quoted from the sources "require fresh verification before use",
#: so adding ``US`` or ``APAC`` here would be inventing configuration no authority states. An
#: empty array means "no region constraint stated", which is the default.
REGION_GROUPS: tuple[str, ...] = ("EU",)

#: Provider classes a customer may exclude through ``provider_policy``. Named by target
#: §5.4 ("Phase 0 runs on Google, Microsoft and Amazon"), §4.4's spot drivers and the
#: roadmap's hosting paragraph, which adds Verda as qualified.
#:
#: ``amazon`` is the exclusion v1 **cannot honour**: ``provider_policy`` governs execution
#: placement only, and the payload plane is S3 for every tenant until a bucket per supplier
#: cloud region exists (§3.3, §5.4, §17 invariant 13). The value is accepted and recorded
#: anyway, because a customer who requires it is a fact worth having; what the portal must
#: not do is accept it silently, and the consent text says so exactly.
PROVIDER_CLASSES: tuple[str, ...] = ("amazon", "google", "microsoft", "verda")

#: Whether the customer intends to run the free 1,000-request evaluation (target §5.3).
#: Intent only: the evaluation tier, its caps, its corpus rule and its report are M4.1 and
#: M5, and nothing reads this to admit, quote or schedule anything.
EVALUATION_INTENTS: tuple[str, ...] = (
    "undecided",
    "planning_evaluation",
    "evaluation_not_needed",
)

#: The consent and subprocessor statements a row may acknowledge. The text itself lives in
#: ``api/consent.py`` and is served by ``GET /v1/consent``; this is the closed set of
#: versions, so assent cannot be recorded to text that does not exist.
CONSENT_VERSIONS: tuple[str, ...] = ("provider-policy-v1-d.1",)

#: A free-text note about the model and runtime profile the customer expects to run. Free
#: text on purpose: the certified profile registry with measured throughput is M6, the model
#: band is an open measurement decision (review register §3), and offering a closed list of
#: model ids here would present the target's *illustrative* examples as an available
#: catalogue. Bounded, and never a place for a secret.
MODEL_PROFILE_NOTE_MAX_LENGTH = 200

_UUID_PK = UUID(as_uuid=True)
_TIMESTAMPTZ = TIMESTAMP(timezone=True)
_JSONB = JSONB(none_as_null=True)


def _closed_array_check(column: str, values: tuple[str, ...]) -> str:
    """``column`` holds only values from a closed set, no null, and no more than the set.

    Three conditions rather than one, and the second and third are not redundant. ``<@``
    alone says nothing about a **null** element -- ``ARRAY['EU', NULL] <@ ARRAY['EU']`` is
    neither true nor false, and a check constraint admits a row whose predicate evaluates to
    NULL -- so the null is excluded explicitly.

    The third bounds the length at the size of the vocabulary. What one would rather write is
    "and no duplicates", but PostgreSQL refuses a subquery in a check constraint and there is
    no subquery-free way to say it, so the choice was a helper function in the schema or
    this. This, because a repeated element denotes the same set and is a tidiness problem
    rather than an isolation one, while an unbounded array of repeats is a storage problem
    and is what the bound actually closes. ``db/preferences.py`` normalises every array to a
    sorted set on the way in, so a stored duplicate means a writer that bypassed it.
    """
    rendered = ", ".join(f"'{value}'" for value in values)
    return (
        f"{column} <@ ARRAY[{rendered}]::text[] "
        f"AND array_position({column}, NULL) IS NULL "
        f"AND cardinality({column}) <= {len(values)}"
    )


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


class WorkspacePreferences(Base):
    """What one workspace's customer says they intend. Tenant-scoped, policed, not protected.

    Milestone 3.2. The roadmap asks M3.2 to "capture the customer's desired policy, profile
    and preferences for later use **without claiming a quote or an execution**", and the
    qualification is the design: this row is a *statement*. It is not a ``JobSpec``, it
    reserves no capacity, it prices nothing, and no admission or routing path reads it. M5
    owns the contract fields that carry the same ideas into something binding.

    **Why the foreign key is composite.** ``(workspace_id, tenant_id)`` references
    ``workspaces (id, tenant_id)``, not ``workspaces (id)``. PostgreSQL performs
    referential-integrity checks with row security bypassed, so a single-column reference
    would let a row name a workspace in one tenant while carrying another's ``tenant_id``,
    and the isolation predicate -- which compares ``tenant_id`` against the authenticated
    context -- would then be comparing a column the writer chose. Referencing the pair makes
    the consistency a database fact.

    **Why the consent columns are derived.** ``consent_acknowledged_at`` and
    ``consent_account_id`` are written by ``firmbatch.acknowledge_workspace_consent`` from
    ``clock_timestamp()`` and ``firmbatch.auth_principal_id()``, and re-derived by a ``BEFORE
    INSERT OR UPDATE`` trigger behind it, exactly as ``audit_events.occurred_at`` is, and for
    the same reason: a caller that could state who consented and when could state them
    wrongly. The row carries the acknowledgement **in force**; the history of
    acknowledgements is in ``audit_events``, which is append-only and immutable.

    **Why the application role cannot write it.** The role holds ``SELECT`` on this table and
    nothing else. Every write goes through one of two ``SECURITY DEFINER`` functions in
    migration ``0006`` -- ``state_workspace_preferences`` and
    ``acknowledge_workspace_consent`` -- which require a CSRF-verified workspace session,
    re-derive the caller's membership under the workspace lock, check the workspace the
    caller's page expected against the one the session is bound to, and append the audit
    event and write the row in one call. A statement the runtime role wrote itself is refused
    at permission-check time, before any policy or trigger is reached.
    """

    __tablename__ = "workspace_preferences"

    id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    workspace_id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, nullable=False)
    #: Region groups the customer wants execution confined to. Empty means none stated.
    region_policy: Mapped[list[str]] = mapped_column(
        ARRAY(Text()), nullable=False, server_default=text("'{}'::text[]")
    )
    #: Provider classes the customer excludes. Execution placement only; see
    #: :data:`PROVIDER_CLASSES` for the one exclusion v1 cannot honour.
    excluded_provider_classes: Mapped[list[str]] = mapped_column(
        ARRAY(Text()), nullable=False, server_default=text("'{}'::text[]")
    )
    model_profile_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    evaluation_intent: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("'undecided'")
    )
    consent_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Server-derived by the trigger, like ``audit_events.occurred_at``.
    consent_acknowledged_at: Mapped[datetime | None] = mapped_column(
        _TIMESTAMPTZ, nullable=True, server_default=FetchedValue(), server_onupdate=FetchedValue()
    )
    #: Server-derived by the trigger from the authenticated context. No foreign key: the
    #: identity plane is protected, and a reference from a policed relation into it would put
    #: a protected table's contents behind a constraint error message.
    consent_account_id: Mapped[uuid.UUID | None] = mapped_column(
        _UUID_PK, nullable=True, server_default=FetchedValue(), server_onupdate=FetchedValue()
    )
    created_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(
        _TIMESTAMPTZ, nullable=False, server_default=text("now()"), server_onupdate=FetchedValue()
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["workspace_id", "tenant_id"],
            [f"{SCHEMA}.workspaces.id", f"{SCHEMA}.workspaces.tenant_id"],
            ondelete="CASCADE",
            name="fk_workspace_preferences_workspace_id_tenant_id_workspaces",
        ),
        ForeignKeyConstraint(
            ["tenant_id"],
            [f"{SCHEMA}.tenants.id"],
            ondelete="CASCADE",
            name="fk_workspace_preferences_tenant_id_tenants",
        ),
        UniqueConstraint("workspace_id", name="uq_workspace_preferences_workspace_id"),
        UniqueConstraint("id", "tenant_id", name="uq_workspace_preferences_id_tenant_id"),
        CheckConstraint(_closed_array_check("region_policy", REGION_GROUPS), name="region_policy_known"),
        CheckConstraint(
            _closed_array_check("excluded_provider_classes", PROVIDER_CLASSES),
            name="excluded_provider_classes_known",
        ),
        CheckConstraint(
            "evaluation_intent IN (" + ", ".join(f"'{value}'" for value in EVALUATION_INTENTS) + ")",
            name="evaluation_intent_known",
        ),
        CheckConstraint(
            "model_profile_note IS NULL OR length(model_profile_note) BETWEEN 1 AND "
            f"{MODEL_PROFILE_NOTE_MAX_LENGTH}",
            name="model_profile_note_bounded",
        ),
        CheckConstraint(
            "consent_version IS NULL OR consent_version IN ("
            + ", ".join(f"'{value}'" for value in CONSENT_VERSIONS)
            + ")",
            name="consent_version_known",
        ),
        # The three consent columns move together. The trigger keeps them consistent; this
        # makes an inconsistent row unstorable even without it.
        CheckConstraint(
            "(consent_version IS NULL AND consent_acknowledged_at IS NULL "
            "AND consent_account_id IS NULL) "
            "OR (consent_version IS NOT NULL AND consent_acknowledged_at IS NOT NULL "
            "AND consent_account_id IS NOT NULL)",
            name="consent_complete_or_absent",
        ),
        Index("ix_workspace_preferences_tenant_id", "tenant_id"),
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
    #: **Milestone 3.1.** The membership this credential was issued from, with the
    #: workspace it belongs to, both NULL for a credential provisioned out of band. A
    #: composite reference to ``(id, workspace_id, tenant_id)`` on ``memberships``, so the
    #: binding cannot name a membership of another workspace or tenant. The ``BEFORE``
    #: trigger on ``memberships`` revokes every binding that names a revoked membership in
    #: the revoking statement's own sequence.
    membership_id: Mapped[uuid.UUID | None] = mapped_column(_UUID_PK, nullable=True)
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(_UUID_PK, nullable=True)
    #: A customer-chosen label, bounded, and refused if it carries a secret shape.
    label: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Written by ``record_api_credential_use()`` after a successful bind. A convenience
    #: metric, not a security property.
    last_used_at: Mapped[datetime | None] = mapped_column(_TIMESTAMPTZ, nullable=True)
    #: The binding this one replaced, when it was minted by rotation.
    rotated_from_id: Mapped[uuid.UUID | None] = mapped_column(_UUID_PK, nullable=True)
    #: **Milestone 3.1 security correction.** The issuing account's security epoch at the
    #: moment this credential was minted; NULL for a credential provisioned out of band.
    #: ``bind_authenticated_context`` refuses a membership-bound credential whose stamped
    #: epoch no longer equals the account's current one, which is how account recovery
    #: evicts credentials issued before it.
    principal_epoch: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (
        UniqueConstraint("fingerprint", name="uq_auth_bindings_fingerprint"),
        UniqueConstraint("id", "tenant_id", name="uq_auth_bindings_id_tenant_id"),
        ForeignKeyConstraint(
            ["membership_id", "workspace_id", "tenant_id"],
            [f"{SCHEMA}.memberships.id", f"{SCHEMA}.memberships.workspace_id", f"{SCHEMA}.memberships.tenant_id"],
            name="fk_auth_bindings_membership_memberships",
        ),
        ForeignKeyConstraint(
            ["rotated_from_id", "tenant_id"],
            [f"{SCHEMA}.auth_bindings.id", f"{SCHEMA}.auth_bindings.tenant_id"],
            name="fk_auth_bindings_rotated_from_auth_bindings",
        ),
        CheckConstraint("(membership_id IS NULL) = (workspace_id IS NULL)", name="membership_binding_complete"),
        CheckConstraint(
            f"label IS NULL OR length(label) BETWEEN 1 AND {CREDENTIAL_LABEL_MAX_LENGTH}", name="label_bounded"
        ),
        Index("ix_auth_bindings_tenant_id_workspace_id", "tenant_id", "workspace_id"),
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
            "actor_kind IN (" + ", ".join(f"'{value}'" for value in ACTOR_KINDS) + ")",
            name="actor_kind_known",
        ),
        # A credential actor has both identifiers; a provisioning actor has neither; a
        # session actor (Milestone 3.1) has the account as principal and no binding. A
        # half-filled actor would be a record nobody could interpret.
        CheckConstraint(ACTOR_SHAPE_SQL, name="actor_shape"),
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
            "actor_kind IN (" + ", ".join(f"'{value}'" for value in ACTOR_KINDS) + ")",
            name="actor_kind_known",
        ),
        CheckConstraint(ACTOR_SHAPE_SQL, name="actor_shape"),
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




# ------------------------------------------------------------------- Milestone 3.1
#
# The identity plane. **Every relation below is protected, not policed**: no runtime or
# provisioning role holds any privilege on any of them, exactly as for ``auth_bindings``,
# and the only way in is a hardened SECURITY DEFINER function in migration ``0005``. They
# carry no row-level security policy for the reason ``auth_bindings`` carries none -- a
# policy bounds a role that holds privileges, and here none does -- and the tenant-owned
# ones (memberships, invitations) carry ``tenant_id`` and composite foreign keys so the
# rows the definer functions read and write cannot reach across tenants.


class Account(Base):
    """One customer identity, existing before any workspace does. **Protected.**

    Global: an account is the outermost identity there is, so its normalised address is
    globally unique in the way a tenant slug is. That uniqueness is never observable by a
    runtime role -- nothing can query this table -- and the one function that could reveal
    it through success-versus-failure, ``signup_account``, returns the same shape for a
    new address and an existing one.
    """

    __tablename__ = "accounts"

    id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    email_normalized: Mapped[str] = mapped_column(Text, nullable=False)
    email_display: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'unverified'"))
    email_verified_at: Mapped[datetime | None] = mapped_column(_TIMESTAMPTZ, nullable=True)
    #: **Milestone 3.1 security correction.** Advanced by ``complete_account_recovery`` so
    #: that every credential this account issued before the recovery -- checked at bearer
    #: authentication against the epoch each was stamped with -- is durably evicted.
    security_epoch: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    created_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))

    __table_args__ = (
        UniqueConstraint("email_normalized", name="uq_accounts_email_normalized"),
        CheckConstraint(f"email_normalized ~ '{EMAIL_REGEX}'", name="email_normalized_format"),
        # The grammar does not bound the total length -- its domain group repeats labels
        # without an upper limit -- so the canonical maximum is its own constraint, matching
        # the bound both normalisers apply.
        CheckConstraint(
            f"length(email_normalized) <= {EMAIL_MAX_LENGTH}", name="email_normalized_length"
        ),
        CheckConstraint(f"length(email_display) BETWEEN 3 AND {EMAIL_MAX_LENGTH}", name="email_display_length"),
        CheckConstraint(
            "status IN (" + ", ".join(f"'{value}'" for value in ACCOUNT_STATUSES) + ")", name="status_known"
        ),
        CheckConstraint("(status = 'active') = (email_verified_at IS NOT NULL)", name="verified_status_consistent"),
    )


class AccountPassword(Base):
    """The Argon2id PHC hash of one account's password. **Protected.**

    One row per account, replaced by recovery. The check constraint is what stops a writer
    that reached the table another way storing a plaintext or a hash of another algorithm.
    The hash is fetched by ``login_lookup`` for exactly one account per call and verified
    in Python; see ``security/passwords``.
    """

    __tablename__ = "account_passwords"

    account_id: Mapped[uuid.UUID] = mapped_column(
        _UUID_PK,
        ForeignKey(f"{SCHEMA}.accounts.id", ondelete="CASCADE", name="fk_account_passwords_account_id_accounts"),
        primary_key=True,
    )
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    algorithm: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'argon2id'"))
    updated_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))

    __table_args__ = (
        CheckConstraint(f"password_hash ~ '{PASSWORD_HASH_REGEX}'", name="password_hash_format"),
        CheckConstraint(f"length(password_hash) <= {PASSWORD_HASH_MAX_LENGTH}", name="password_hash_bounded"),
        CheckConstraint("algorithm = 'argon2id'", name="algorithm_known"),
    )


class AccountToken(Base):
    """One email-verification or recovery token, as a fingerprint. **Protected.**

    Written once, and consumed or superseded once: a ``BEFORE UPDATE`` trigger refuses any
    other change to a written row. Deletion is refused by the **absent grant** rather than
    by that trigger -- no runtime role holds ``DELETE`` on this protected table -- and the
    one deletion that does occur is the cascade from ``purge_expired_unverified_accounts``,
    the owner-run reclaim of an expired unverified account (Milestone 3.1 security
    correction). The secret itself is minted in the database, returned once to the
    email-delivery boundary, and exists nowhere else.
    """

    __tablename__ = "account_tokens"

    id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    account_id: Mapped[uuid.UUID] = mapped_column(
        _UUID_PK,
        ForeignKey(f"{SCHEMA}.accounts.id", ondelete="CASCADE", name="fk_account_tokens_account_id_accounts"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))
    expires_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(_TIMESTAMPTZ, nullable=True)
    superseded_at: Mapped[datetime | None] = mapped_column(_TIMESTAMPTZ, nullable=True)

    __table_args__ = (
        UniqueConstraint("fingerprint", name="uq_account_tokens_fingerprint"),
        CheckConstraint(
            "kind IN (" + ", ".join(f"'{value}'" for value in ACCOUNT_TOKEN_KINDS) + ")", name="kind_known"
        ),
        CheckConstraint(f"fingerprint ~ '{FINGERPRINT_REGEX}'", name="fingerprint_format"),
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        Index("ix_account_tokens_account_id", "account_id"),
    )


class Membership(Base):
    """One account's role in one workspace of one tenant. **Protected.**

    The row that answers ``AUTH-MEMBERSHIP-BOUND-IDENTITY``'s question -- which
    workspaces may this person choose from -- and it is read only by the definer functions
    that bind sessions and issue credentials, every time, never cached as an authorization.
    Revocation is a state: the row stays, ``revoked_at`` is set once by a trigger that
    refuses to unset it, and the same trigger revokes every credential the membership
    issued and unbinds every session bound through it.
    """

    __tablename__ = "memberships"

    id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        _UUID_PK,
        ForeignKey(f"{SCHEMA}.tenants.id", ondelete="CASCADE", name="fk_memberships_tenant_id_tenants"),
        nullable=False,
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, nullable=False)
    account_id: Mapped[uuid.UUID] = mapped_column(
        _UUID_PK,
        ForeignKey(f"{SCHEMA}.accounts.id", ondelete="CASCADE", name="fk_memberships_account_id_accounts"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(Text, nullable=False)
    invited_by_account_id: Mapped[uuid.UUID | None] = mapped_column(
        _UUID_PK,
        ForeignKey(
            f"{SCHEMA}.accounts.id", ondelete="SET NULL", name="fk_memberships_invited_by_account_id_accounts"
        ),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))
    updated_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))
    revoked_at: Mapped[datetime | None] = mapped_column(_TIMESTAMPTZ, nullable=True)
    revoked_by_account_id: Mapped[uuid.UUID | None] = mapped_column(
        _UUID_PK,
        ForeignKey(
            f"{SCHEMA}.accounts.id", ondelete="SET NULL", name="fk_memberships_revoked_by_account_id_accounts"
        ),
        nullable=True,
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["workspace_id", "tenant_id"],
            [f"{SCHEMA}.workspaces.id", f"{SCHEMA}.workspaces.tenant_id"],
            name="fk_memberships_workspace_id_tenant_id_workspaces",
            ondelete="CASCADE",
        ),
        UniqueConstraint("id", "tenant_id", name="uq_memberships_id_tenant_id"),
        UniqueConstraint("id", "workspace_id", "tenant_id", name="uq_memberships_id_workspace_id_tenant_id"),
        CheckConstraint(
            "role IN (" + ", ".join(f"'{value}'" for value in MEMBERSHIP_ROLES) + ")", name="role_known"
        ),
        Index("ix_memberships_tenant_id", "tenant_id"),
        Index("ix_memberships_account_id", "account_id"),
        Index(
            "uq_memberships_active_workspace_id_account_id",
            "workspace_id",
            "account_id",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )


class WorkspaceDirectory(Base):
    """A protected copy of each workspace's slug and name, keyed like the workspace.

    Maintained by an ``AFTER`` trigger on ``workspaces`` for every writer, so it cannot
    drift; read only by ``account_workspaces()``, which has to tell an account the names of
    the workspaces it belongs to across tenants -- a read FORCE row security on
    ``workspaces`` refuses to a transaction that holds no tenant context yet. No runtime
    role holds anything on it.
    """

    __tablename__ = "workspace_directory"

    id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, nullable=False)
    slug: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["id", "tenant_id"],
            [f"{SCHEMA}.workspaces.id", f"{SCHEMA}.workspaces.tenant_id"],
            name="fk_workspace_directory_id_tenant_id_workspaces",
            ondelete="CASCADE",
        ),
    )


class BrowserSession(Base):
    """One browser session, as fingerprints, with its optional workspace binding. **Protected.**

    The session secret and the CSRF secret are minted in the database and returned once;
    the row holds their digests. The binding names one membership together with its
    workspace and tenant, so it cannot describe a membership of another workspace, and it
    is re-derived on every bind rather than trusted.
    """

    __tablename__ = "browser_sessions"

    id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    account_id: Mapped[uuid.UUID] = mapped_column(
        _UUID_PK,
        ForeignKey(f"{SCHEMA}.accounts.id", ondelete="CASCADE", name="fk_browser_sessions_account_id_accounts"),
        nullable=False,
    )
    fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    csrf_fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))
    expires_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(_TIMESTAMPTZ, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(_TIMESTAMPTZ, nullable=True)
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(_UUID_PK, nullable=True)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(_UUID_PK, nullable=True)
    membership_id: Mapped[uuid.UUID | None] = mapped_column(_UUID_PK, nullable=True)
    bound_at: Mapped[datetime | None] = mapped_column(_TIMESTAMPTZ, nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["membership_id", "workspace_id", "tenant_id"],
            [f"{SCHEMA}.memberships.id", f"{SCHEMA}.memberships.workspace_id", f"{SCHEMA}.memberships.tenant_id"],
            name="fk_browser_sessions_membership_memberships",
        ),
        UniqueConstraint("fingerprint", name="uq_browser_sessions_fingerprint"),
        CheckConstraint(f"fingerprint ~ '{FINGERPRINT_REGEX}'", name="fingerprint_format"),
        CheckConstraint(f"csrf_fingerprint ~ '{FINGERPRINT_REGEX}'", name="csrf_fingerprint_format"),
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        CheckConstraint(
            "((workspace_id IS NULL) = (tenant_id IS NULL)) AND ((workspace_id IS NULL) = (membership_id IS NULL))",
            name="binding_complete",
        ),
        Index("ix_browser_sessions_account_id", "account_id"),
    )


class WorkspaceInvitation(Base):
    """One invitation: workspace, tenant, recipient, role, expiry, one-time. **Protected.**"""

    __tablename__ = "workspace_invitations"

    id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        _UUID_PK,
        ForeignKey(f"{SCHEMA}.tenants.id", ondelete="CASCADE", name="fk_workspace_invitations_tenant_id_tenants"),
        nullable=False,
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, nullable=False)
    email_normalized: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    invited_by_account_id: Mapped[uuid.UUID | None] = mapped_column(
        _UUID_PK,
        ForeignKey(
            f"{SCHEMA}.accounts.id",
            ondelete="SET NULL",
            name="fk_workspace_invitations_invited_by_account_id_accounts",
        ),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))
    expires_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(_TIMESTAMPTZ, nullable=True)
    accepted_membership_id: Mapped[uuid.UUID | None] = mapped_column(_UUID_PK, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(_TIMESTAMPTZ, nullable=True)

    __table_args__ = (
        ForeignKeyConstraint(
            ["workspace_id", "tenant_id"],
            [f"{SCHEMA}.workspaces.id", f"{SCHEMA}.workspaces.tenant_id"],
            name="fk_workspace_invitations_workspace_id_tenant_id_workspaces",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["accepted_membership_id", "tenant_id"],
            [f"{SCHEMA}.memberships.id", f"{SCHEMA}.memberships.tenant_id"],
            name="fk_workspace_invitations_accepted_membership_memberships",
        ),
        UniqueConstraint("fingerprint", name="uq_workspace_invitations_fingerprint"),
        UniqueConstraint("id", "tenant_id", name="uq_workspace_invitations_id_tenant_id"),
        CheckConstraint(f"email_normalized ~ '{EMAIL_REGEX}'", name="email_normalized_format"),
        CheckConstraint(
            "role IN (" + ", ".join(f"'{value}'" for value in MEMBERSHIP_ROLES) + ")", name="role_known"
        ),
        CheckConstraint(f"fingerprint ~ '{FINGERPRINT_REGEX}'", name="fingerprint_format"),
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        Index("ix_workspace_invitations_tenant_id", "tenant_id"),
        Index(
            "uq_workspace_invitations_pending_workspace_id_email",
            "workspace_id",
            "email_normalized",
            unique=True,
            postgresql_where=text("accepted_at IS NULL AND revoked_at IS NULL"),
        ),
    )


class AccountIdempotencyRecord(Base):
    """The replay record for the two account-level mutations. **Protected**, append-only.

    Milestone 2.2's claims are tenant-scoped, and an account creating its first workspace
    or accepting an invitation has no tenant context until the operation has run. So the
    replay lookup for those two operations is keyed by account here, and the tenant-scoped
    claim and linked event are written as well once the tenant context exists.
    """

    __tablename__ = "account_idempotency_records"

    id: Mapped[uuid.UUID] = mapped_column(_UUID_PK, primary_key=True, server_default=text("gen_random_uuid()"))
    account_id: Mapped[uuid.UUID] = mapped_column(
        _UUID_PK,
        ForeignKey(
            f"{SCHEMA}.accounts.id", ondelete="CASCADE", name="fk_account_idempotency_records_account_id_accounts"
        ),
        nullable=False,
    )
    operation: Mapped[str] = mapped_column(Text, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(Text, nullable=False)
    request_fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    result: Mapped[dict[str, Any]] = mapped_column(_JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(_TIMESTAMPTZ, nullable=False, server_default=text("now()"))

    __table_args__ = (
        UniqueConstraint(
            "account_id", "operation", "idempotency_key",
            name="uq_account_idempotency_records_account_id_operation_key",
        ),
        CheckConstraint(f"operation ~ '{DOTTED_NAME_REGEX}'", name="operation_format"),
        CheckConstraint(f"idempotency_key ~ '{IDEMPOTENCY_KEY_REGEX}'", name="idempotency_key_format"),
        CheckConstraint(f"request_fingerprint ~ '{FINGERPRINT_REGEX}'", name="request_fingerprint_format"),
        *_metadata_constraints("result", "result"),
    )


#: The Milestone 3.1 relations, all protected. Named so a test can walk them.
IDENTITY_TABLES: frozenset[str] = frozenset(
    {
        Account.__tablename__,
        AccountPassword.__tablename__,
        AccountToken.__tablename__,
        Membership.__tablename__,
        WorkspaceDirectory.__tablename__,
        BrowserSession.__tablename__,
        WorkspaceInvitation.__tablename__,
        AccountIdempotencyRecord.__tablename__,
        # Unmodelled, like ``auth_transaction_context``: its key column is ``xid8``.
        "identity_transaction_context",
    }
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
    WorkspacePreferences.__tablename__: "tenant_id",
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
