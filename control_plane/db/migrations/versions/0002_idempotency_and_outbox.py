"""Idempotency records and the transactional outbox, both append-only.

Revision ID: 0002_idempotency_and_outbox
Revises: 0001_tenant_workspace_spine
Create Date: 2026-09-03

The second v1 migration, and the schema half of Milestone 2.2. It adds two tenant-scoped
tables to the spine ``0001`` created, and one new isolation shape alongside them.

**Append-only is expressed as an absence, not as a comment.** ``0001`` gave each
tenant-scoped table a single ``FOR ALL`` policy. These two get a ``FOR SELECT`` policy
and a ``FOR INSERT`` policy and nothing else, so ``UPDATE`` and ``DELETE`` find no rows
to act on -- for every role, the table owner included, because row security is ``FORCE``d
here exactly as it is there. That is the half a grant cannot buy: revoking ``UPDATE``
from today's application role says nothing about tomorrow's roles or about the owner.
``db/roles.py`` still revokes it, because two independent measures is the standard this
schema already holds itself to.

**Tenant consistency is a database fact.** ``outbox_events`` references
``idempotency_records`` on ``(id, tenant_id)`` against the composite unique key rather
than on ``id`` alone. PostgreSQL performs referential-integrity checks with row security
bypassed, so a single-column reference would happily attach an event to another tenant's
claim. That link is **optional**: the outbox serves every authoritative state transition,
and the internal ones -- controller, reconciler, validator, lifecycle -- have no API
idempotency key to point at.

**The concurrency control is the unique index.** ``uq_idempotency_records_tenant_id_
operation_idempotency_key`` is what makes two simultaneous claims of one key serialise:
the second inserter blocks on the index until the first commits, then sees a unique
violation. Nothing in the application holds a lock, so the guarantee does not evaporate
when a second control-plane process starts.

Everything is schema-qualified, and the migration names no role -- the grants live in
``db/roles.py`` because role names belong to an environment and not to a schema history.
Hand-written, like ``0001``, because ``op.create_table`` cannot emit RLS DDL;
``tests/test_migrations.py`` asserts with ``compare_metadata`` that it still matches
``db/models.py``.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP, UUID

revision: str = "0002_idempotency_and_outbox"
down_revision: str | None = "0001_tenant_workspace_spine"
branch_labels: str | None = None
depends_on: str | None = None

SCHEMA = "firmbatch"

# Mirrors db/models.py. The suite asserts the two agree, so a divergence fails the run
# rather than producing a schema that only one of them describes.
DOTTED_NAME_REGEX = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$"
SIMPLE_NAME_REGEX = r"^[a-z][a-z0-9_]{0,62}$"
IDEMPOTENCY_KEY_REGEX = r"^[A-Za-z0-9._:@=+-]{8,200}$"
FINGERPRINT_REGEX = r"^[0-9a-f]{64}$"
IDEMPOTENCY_STATUS_COMPLETED = "completed"
MAX_METADATA_BYTES = 4096

#: table -> the column compared against the tenant context, for the tables this
#: migration adds. Both are append-only.
APPEND_ONLY_TABLES = {"idempotency_records": "tenant_id", "outbox_events": "tenant_id"}

_UUID = UUID(as_uuid=True)
_TIMESTAMPTZ = TIMESTAMP(timezone=True)
_JSONB = JSONB(none_as_null=True)


def _metadata_checks(column: str) -> list[sa.CheckConstraint]:
    """Bare names: Alembic applies the ``ck_%(table_name)s_%(constraint_name)s``
    convention from ``db/base.py``, so a name that already carries the prefix gets it
    twice and is then hash-truncated."""
    return [
        sa.CheckConstraint(f"jsonb_typeof({column}) = 'object'", name=f"{column}_object"),
        sa.CheckConstraint(
            f"octet_length({column}::text) <= {MAX_METADATA_BYTES}", name=f"{column}_bounded"
        ),
    ]


def upgrade() -> None:
    op.create_table(
        "idempotency_records",
        sa.Column("id", _UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", _UUID, nullable=False),
        sa.Column("operation", sa.Text(), nullable=False),
        sa.Column("idempotency_key", sa.Text(), nullable=False),
        sa.Column("request_fingerprint", sa.Text(), nullable=False),
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default=sa.text(f"'{IDEMPOTENCY_STATUS_COMPLETED}'"),
        ),
        sa.Column("result", _JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_idempotency_records"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            [f"{SCHEMA}.tenants.id"],
            name="fk_idempotency_records_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        # The concurrency control. Tenant-scoped, and scoped by operation as well, so a
        # key is never global and never means two different things at once.
        sa.UniqueConstraint(
            "tenant_id",
            "operation",
            "idempotency_key",
            name="uq_idempotency_records_tenant_id_operation_idempotency_key",
        ),
        # Referential-integrity checks bypass row security, so outbox_events references
        # this pair rather than id alone.
        sa.UniqueConstraint("id", "tenant_id", name="uq_idempotency_records_id_tenant_id"),
        sa.CheckConstraint(f"operation ~ '{DOTTED_NAME_REGEX}'", name="operation_format"),
        sa.CheckConstraint(
            f"idempotency_key ~ '{IDEMPOTENCY_KEY_REGEX}'", name="idempotency_key_format"
        ),
        sa.CheckConstraint(
            f"request_fingerprint ~ '{FINGERPRINT_REGEX}'", name="request_fingerprint_format"
        ),
        # There is one durable status. A claim that does not commit is rolled back with
        # everything else in its transaction, so no 'in_progress' row can survive to be
        # interpreted by a recovery system that does not exist.
        sa.CheckConstraint(
            f"status = '{IDEMPOTENCY_STATUS_COMPLETED}'", name="status_completed"
        ),
        *_metadata_checks("result"),
        schema=SCHEMA,
    )

    op.create_table(
        "outbox_events",
        sa.Column("id", _UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", _UUID, nullable=False),
        # Nullable: an OPTIONAL causation link. The outbox belongs to every
        # authoritative state transition, and the internal ones -- controller,
        # reconciler, validator, lifecycle -- have no caller-supplied idempotency key.
        sa.Column("idempotency_record_id", _UUID, nullable=True),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("aggregate_type", sa.Text(), nullable=False),
        sa.Column("aggregate_id", _UUID, nullable=False),
        sa.Column("attributes", _JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("occurred_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_outbox_events"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            [f"{SCHEMA}.tenants.id"],
            name="fk_outbox_events_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        # Tenant-consistent when the link is present. A composite MATCH SIMPLE reference
        # is satisfied when any column is NULL, so an unlinked event is exempt from this
        # rather than dangling against it.
        sa.ForeignKeyConstraint(
            ["idempotency_record_id", "tenant_id"],
            [f"{SCHEMA}.idempotency_records.id", f"{SCHEMA}.idempotency_records.tenant_id"],
            name="fk_outbox_events_idempotency_record_id_tenant_id",
            ondelete="CASCADE",
        ),
        # AT MOST ONE linked event per claim. A unique constraint bounds duplicates; it
        # cannot require existence, so "the primitive writes exactly one, atomically" is
        # proved by the suite and not by this line. NULLs are distinct by default, so
        # unlinked events do not collide with one another.
        sa.UniqueConstraint(
            "tenant_id", "idempotency_record_id", name="uq_outbox_events_tenant_id_idempotency_record_id"
        ),
        sa.CheckConstraint(f"event_type ~ '{DOTTED_NAME_REGEX}'", name="event_type_format"),
        sa.CheckConstraint(f"aggregate_type ~ '{SIMPLE_NAME_REGEX}'", name="aggregate_type_format"),
        *_metadata_checks("attributes"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_outbox_events_tenant_id_occurred_at", "outbox_events", ["tenant_id", "occurred_at"], schema=SCHEMA
    )

    for table, tenant_column in APPEND_ONLY_TABLES.items():
        qualified = f"{SCHEMA}.{table}"
        op.execute(f"ALTER TABLE {qualified} ENABLE ROW LEVEL SECURITY")
        # FORCE is the half that matters, and here it does double duty: it is also what
        # makes the missing UPDATE and DELETE policies bind the owner.
        op.execute(f"ALTER TABLE {qualified} FORCE ROW LEVEL SECURITY")
        op.execute(f"REVOKE ALL ON TABLE {qualified} FROM PUBLIC")
        # A NULL context makes both predicates NULL: reads match nothing and writes are
        # rejected. Absence of tenant context fails closed by construction.
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_read ON {qualified}
            FOR SELECT
            TO PUBLIC
            USING ({tenant_column} = {SCHEMA}.app_current_tenant_id())
            """
        )
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_append ON {qualified}
            FOR INSERT
            TO PUBLIC
            WITH CHECK ({tenant_column} = {SCHEMA}.app_current_tenant_id())
            """
        )
        # Deliberately no UPDATE and no DELETE policy. A command with no policy matches
        # no row, which is what makes these tables append-only for every role rather than
        # for the one role today's grants happen to name.


def downgrade() -> None:
    for table in APPEND_ONLY_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_read ON {SCHEMA}.{table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_append ON {SCHEMA}.{table}")
    op.drop_index("ix_outbox_events_tenant_id_occurred_at", table_name="outbox_events", schema=SCHEMA)
    op.drop_table("outbox_events", schema=SCHEMA)
    op.drop_table("idempotency_records", schema=SCHEMA)
