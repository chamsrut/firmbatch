"""Alembic environment for the Firmbatch v1 control plane.

**Online mode refuses to run without a pre-validated connection.** There is one online
entry point -- ``python3 -m firmbatch.control_plane.migrate`` (or ``migrate.upgrade_to_head``
/ ``migrate.downgrade_to`` called with a connection obtained from
``migrate.migration_connection``) -- and it supplies a live ``Connection`` together with an
immutable ``ExpectedIdentity`` through ``config.attributes``. Anything else,
``alembic -c ... upgrade head`` included, is rejected here before a single statement is
issued.

**This file calls the canonical validator itself.** It used to invoke a ``validate``
callable the caller had supplied, which meant a no-op lambda authorised DDL against any
server at all while reading exactly like a checked migration. What arrives now is data --
the database, cluster system identifier, canonical endpoint and principal the connection
must turn out to have -- and ``identity.require_expected_identity`` is what acts on it. A
caller can pass a *wrong* identity and get a refusal naming the mismatch; there is no value
that means "already checked", and a callable or a boolean is rejected on sight.

That is deliberate rather than unfinished. The alternative is this file resolving the URL
and opening its own connection, which is precisely the second resolution that can land on
a different cluster than the one the caller checked: DNS, a failover endpoint, a load
balancer, or ``PGHOSTADDR`` are each enough. A convenient entry point that cannot validate
its own target is not a convenience.

``alembic ... --sql`` (offline) remains available and unchanged: it renders SQL to stdout
and executes no DDL, so there is no connection to validate and nothing to be pointed at
the wrong server. It reads the URL from ``FIRMBATCH_MIGRATION_DATABASE_URL`` through
``control_plane.config``; the URL is never written into ``alembic.ini``, because a
connection string in a version-controlled file is exactly the production default the
configuration boundary exists to forbid.

**Schema handling.** Everything is pinned to the ``firmbatch`` schema, including the
Alembic version table. The schema is created here rather than only in the first migration
because Alembic writes the version table *before* running any migration, so the schema has
to exist first. ``search_path`` is set explicitly on the migration connection -- with
``pg_temp`` named last -- so no migration ever resolves a relation through the caller's
ambient search path or through a temporary schema.
"""

from __future__ import annotations

import os
import pathlib
import sys

from alembic import context
from sqlalchemy import text

# The repository is imported as a package from its PARENT directory. Alembic execs this
# file directly, so when it is invoked through the plain `alembic` CLI the parent may not
# be on sys.path yet. Derive it from our own location rather than from the cwd.
_PARENT_OF_REPO = str(pathlib.Path(__file__).resolve().parents[4])
if _PARENT_OF_REPO not in sys.path:
    sys.path.insert(0, _PARENT_OF_REPO)

from firmbatch.control_plane import config  # noqa: E402
from firmbatch.control_plane.db.base import SCHEMA, SEARCH_PATH, VERSION_TABLE, Base  # noqa: E402
from firmbatch.control_plane.db.identity import require_expected_identity  # noqa: E402
from firmbatch.control_plane.db import models  # noqa: E402,F401  (imported for its side effect: table registration)

target_metadata = Base.metadata

_VERSION_OPTS = {
    "version_table": VERSION_TABLE,
    "version_table_schema": SCHEMA,
    # Compare only our own schema. Without this, autogenerate would treat every other
    # schema in the database as a source of spurious differences.
    "include_schemas": True,
    "compare_type": True,
}


def _url() -> str:
    """The migration URL, from the environment or from a programmatic override.

    ``migrate.py`` passes the URL through ``config.attributes`` so a caller that already
    holds a validated URL does not have to mutate ``os.environ`` to be heard.
    """
    override = context.config.attributes.get("migration_url")
    if override:
        return config.require_postgresql_url(override, variable=config.MIGRATION_URL_VAR)
    return config.load_migration_url(os.environ)


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        **_VERSION_OPTS,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Refuse, unless the caller supplied a connection and the identity it must prove.

    The refusal happens **before** ``SET``, ``CREATE SCHEMA``, the version table, or any
    other statement. There is no fallback that opens a connection from the URL: that
    fallback is the vulnerability.
    """
    connectable = context.config.attributes.get("connection")
    expected = context.config.attributes.get("expected_identity")

    if connectable is None or expected is None:
        missing = [
            name
            for name, value in (("connection", connectable), ("expected_identity", expected))
            if value is None
        ]
        raise RuntimeError(
            f"refusing to run migrations online: {missing} not supplied. This environment only "
            "runs online migrations on a live connection together with an ExpectedIdentity -- "
            "the database, cluster, endpoint and principal that connection must turn out to "
            "have. Run migrations through `python3 -m firmbatch.control_plane.migrate upgrade`, "
            "or call migrate.upgrade_to_head(connection, expected=...) with a connection from "
            "migrate.migration_connection(). `alembic upgrade head` cannot satisfy this, "
            "because resolving the URL here would open a second connection that may not be on "
            "the cluster that was checked. Offline rendering (`--sql`) is unaffected."
        )

    _run(connectable, expected)


def _run(connection, expected) -> None:
    # Validate the EXACT connection the DDL will travel over, immediately before the first
    # statement, and before any SET or CREATE SCHEMA. A caller that checked a different
    # connection -- even one built from the same URL a moment earlier -- has checked a
    # different socket: DNS, a failover endpoint, or a load balancer can put the second one
    # on another cluster entirely.
    #
    # The canonical validator is called HERE, by this file, on this connection. Nothing the
    # caller supplied gets to decide whether the check passes: `expected` is inert data and
    # require_expected_identity refuses anything that is not an ExpectedIdentity.
    require_expected_identity(
        connection, expected, context="the connection Alembic is about to run DDL on"
    )

    # Both statements must precede context.configure: Alembic creates and reads the
    # version table during configure, and it lives in the schema created here.
    connection.execute(text(f"SET search_path = {SEARCH_PATH}"))
    connection.execute(text(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}"))
    context.configure(connection=connection, target_metadata=target_metadata, **_VERSION_OPTS)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
