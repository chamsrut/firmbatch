"""Declarative base, the pinned schema, and the constraint naming convention.

**The schema is pinned and every relation is qualified.** Firmbatch v1 metadata lives in a
dedicated ``firmbatch`` schema, never in ``public``, and never by way of whatever
``search_path`` a caller happens to arrive with.

That is a security property, not tidiness. PostgreSQL searches the session's temporary
schema *before* ``search_path`` when resolving a relation name, so any role holding the
default ``TEMP`` privilege can run

    CREATE TEMP TABLE workspaces (...);

and every later unqualified ``SELECT ... FROM workspaces`` on that connection reads the
temporary table instead of the real one -- silently, and for the life of a pooled
connection. Row-level security does not help: the policy is attached to the table the
query never reaches.

Three independent measures close it, because one of them is always the one that gets
refactored away:

1. Every relation, foreign key, migration operation, raw statement, and the Alembic
   version table is schema-qualified (here, ``db/models.py``, the migration, ``migrate``).
2. Application connections are pinned to ``search_path = firmbatch, pg_catalog, pg_temp``
   at connect time, naming ``pg_temp`` explicitly and *last* so it stops being searched
   first (``db/engine.py``).
3. ``TEMP`` is revoked from PUBLIC and never granted to a runtime role
   (``db/roles.py``, ``testing/bootstrap.py``).

An explicit constraint naming convention is not cosmetic either. Alembic can only emit a
stable ``DROP CONSTRAINT`` for a constraint whose name it can predict, so an unnamed
unique or check constraint becomes a migration that works on the way up and fails on the
way down.
"""

from __future__ import annotations

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

#: The one schema holding v1 control-plane metadata. Never ``public``.
SCHEMA = "firmbatch"

#: The Alembic version table, pinned into the same schema so the migration history cannot
#: be split across two schemas by a stray search_path.
VERSION_TABLE = "alembic_version"

#: The search_path every application and migration connection is pinned to. ``pg_temp``
#: is named explicitly and last; omitting it is what makes it implicitly first.
SEARCH_PATH = f"{SCHEMA}, pg_catalog, pg_temp"

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(schema=SCHEMA, naming_convention=NAMING_CONVENTION)
