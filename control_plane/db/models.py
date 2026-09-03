"""The tenant/workspace spine.

Two tables, both tenant-scoped, both under forced row-level security. They exist to
carry the isolation boundary that every later Milestone 2 table inherits, not to model
the product: there are no accounts, memberships, credentials, jobs, quotes, or ledgers
here, and adding one before its milestone would be later-milestone work.

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
  database fact rather than a code review.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Index, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import SCHEMA, Base

#: Lowercase DNS-safe slugs. Slugs appear in URLs and object-store keys, so the shape is
#: constrained in the database rather than trusted from the caller.
SLUG_REGEX = r"^[a-z0-9]([a-z0-9-]{0,60}[a-z0-9])?$"

_UUID_PK = UUID(as_uuid=True)
_TIMESTAMPTZ = TIMESTAMP(timezone=True)


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


#: Tables that carry tenant data and must therefore be under forced row-level security,
#: mapped to the column the isolation policy compares against the transaction-local
#: tenant context. ``tenants`` is scoped by its own primary key -- a tenant row is
#: visible to exactly the tenant it is.
#:
#: The migration and the tests both read this mapping, so a tenant-owned table added
#: without a policy fails the suite instead of quietly becoming readable across tenants.
TENANT_SCOPED_TABLES: dict[str, str] = {
    Tenant.__tablename__: "id",
    Workspace.__tablename__: "tenant_id",
}
