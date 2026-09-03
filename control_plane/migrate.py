"""Run migrations. There is exactly one online entry point, and it validates.

    cd "$(git rev-parse --show-toplevel)/.."
    FIRMBATCH_ENV=production python3 -m firmbatch.control_plane.migrate upgrade
    FIRMBATCH_ENV=production python3 -m firmbatch.control_plane.migrate current
    FIRMBATCH_ENV=production python3 -m firmbatch.control_plane.migrate downgrade --revision base

**No online DDL path takes a URL, and none takes a validator.** Both were wrong, in
different ways. A URL is resolved when it is used, so validating one and then handing it
to Alembic lets Alembic open a *second* connection, which DNS, a failover endpoint, or a
load balancer is free to answer differently. And a caller-supplied ``validate`` callable
is a seam in a safety check, which is a bypass with extra steps:
``upgrade_to_head(conn, validate=lambda c: None)`` authorised DDL against anything at all
and read as though it had been checked. A boolean flag would be no better -- it is a claim
by the caller rather than evidence about a connection.

So what travels is **data**: an immutable
:class:`~firmbatch.control_plane.db.identity.ExpectedIdentity` recording the database,
cluster system identifier, canonical endpoint and principal the connection must turn out
to have. ``env.py`` calls the canonical validator itself on the exact ``Connection``
supplied, before any ``SET``, ``CREATE SCHEMA``, version-table access or migration
statement. A caller can supply a *wrong* identity and get a refusal naming the mismatch;
there is no value meaning "already checked".

:func:`upgrade_to_head` and :func:`downgrade_to` therefore require a live
:class:`~sqlalchemy.engine.Connection` **and** an ``ExpectedIdentity``, and they are the
only ways to run migrations online:

* the CLI opens the connection itself through :func:`migration_connection`, which parses
  the URL into a canonical spec, connects through an environment-guarded engine, and
  builds the ``ExpectedIdentity`` from what the server said;
* the test bootstrap passes the connection it already validated together with the same
  kind of value;
* ``alembic upgrade head`` invoked directly is **refused** by ``env.py``, because that
  path can only produce an unvalidated connection.

Offline mode (``alembic ... --sql``) is deliberately still available: it renders SQL and
executes no DDL, so there is no connection to validate.

All paths are derived from ``__file__``, so this works from any working directory. Only
redacted URLs are ever printed.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import pathlib
import sys
from typing import Iterator, Mapping

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, create_engine

from . import config
from .db.base import SCHEMA, VERSION_TABLE
from .db.engine import guard_connection_environment, install_connect_hardening
from .db.identity import ExpectedIdentity, expected_identity_for

_PACKAGE_DIR = pathlib.Path(__file__).resolve().parent
ALEMBIC_INI = _PACKAGE_DIR / "alembic.ini"
MIGRATIONS_DIR = _PACKAGE_DIR / "db" / "migrations"

class UnvalidatedMigrationError(RuntimeError):
    """Raised when an online migration is attempted without a validated connection."""


def alembic_config(*, connection: Connection, expected: ExpectedIdentity) -> Config:
    """An Alembic config bound to a live connection and the identity it must prove.

    Given a connection, Alembic runs its migrations on *that* connection instead of
    opening its own -- which is what makes it possible to validate the exact socket the
    DDL will travel over. There is no URL-bound form: that form let Alembic resolve and
    connect a second time.

    ``expected`` is a value, not a callable. Rejecting anything that is not an
    ``ExpectedIdentity`` here is what stops a caller authorising DDL by handing over a
    lambda, a ``True``, or an object that merely looks like one.
    """
    if connection is None:
        raise UnvalidatedMigrationError(
            "an online migration requires a live, already-validated Connection. Passing a URL "
            "would let Alembic resolve it a second time and reach a different server than the "
            "one that was checked; use migration_connection() to obtain one."
        )
    if not isinstance(expected, ExpectedIdentity):
        raise UnvalidatedMigrationError(
            "an online migration requires an ExpectedIdentity: the database, cluster, endpoint "
            "and principal the connection must turn out to have. It is produced by "
            "migration_connection() or by the test bootstrap. A callable or a flag is not "
            f"accepted (got {type(expected).__name__}) -- a validator a caller supplies is a "
            "validator a caller can make a no-op."
        )
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.attributes["connection"] = connection
    cfg.attributes["expected_identity"] = expected
    return cfg


def create_migration_engine(url: "str | config.MigrationSettings") -> Connection:
    """Engine for the privileged migration/owner role.

    It lives here, with the migration entry point, rather than in ``db/engine.py``. That
    module is what a runtime process imports, and a runtime process that can construct an
    owner engine is one refactor away from doing it. The static boundary check in
    ``scripts/check-runtime-imports.py`` enforces the separation.

    Deliberately tiny: migrations and provisioning are occasional, and a large pool of
    owner connections is a standing privilege nobody needs. The principal check is *not*
    applied -- this connection is supposed to be privileged -- but the search_path is
    still pinned, because a migration resolving a relation through a temporary schema
    would be worse, not better, and the environment guard applies exactly as it does to a
    runtime engine.
    """
    if isinstance(url, config.MigrationSettings):
        url = url.migration_url
    engine = create_engine(
        config.require_postgresql_url(url, variable=config.MIGRATION_URL_VAR),
        pool_size=1,
        max_overflow=1,
        pool_pre_ping=True,
        future=True,
    )
    return install_connect_hardening(engine, policy=None)


def head_revision() -> str:
    """The single head this repository expects. Raises if the history ever branches."""
    heads = ScriptDirectory(str(MIGRATIONS_DIR)).get_heads()
    if len(heads) != 1:
        raise RuntimeError(f"expected exactly one migration head, found {heads}")
    return heads[0]


def upgrade_to_head(connection: Connection, *, expected: ExpectedIdentity) -> str:
    """Apply every migration on ``connection`` and return the head revision."""
    command.upgrade(alembic_config(connection=connection, expected=expected), "head")
    return head_revision()


def downgrade_to(connection: Connection, revision: str, *, expected: ExpectedIdentity) -> None:
    """Reverse migrations down to ``revision`` on ``connection``.

    Validated on exactly the same terms as the upgrade. A downgrade drops tables and
    policies, so an unvalidated one is strictly more dangerous than an unvalidated
    upgrade -- it was the entry point that still took a bare URL.
    """
    command.downgrade(alembic_config(connection=connection, expected=expected), revision)


def current_revision(connection: Connection) -> str | None:
    """The revision stamped on an open connection, or ``None`` on an unmigrated database.

    The version table is pinned to the ``firmbatch`` schema, so it must be named here too;
    reading it through the ambient search path would find nothing (or, worse, something
    else) on a connection configured differently from the one that wrote it.
    """
    return MigrationContext.configure(
        connection,
        opts={"version_table": VERSION_TABLE, "version_table_schema": SCHEMA},
    ).get_current_revision()


@contextlib.contextmanager
def migration_connection(
    url: str, *, variable: str = config.MIGRATION_URL_VAR
) -> Iterator[tuple[Connection, ExpectedIdentity]]:
    """Open a migration connection and record the identity it must keep proving.

    Yields the connection together with the ``ExpectedIdentity`` built from it. That value
    is what gets handed to Alembic, so the facts established here are re-established on the
    same connection immediately before the first DDL statement -- which is what catches a
    connection that was swapped, reset, or re-authenticated in between.

    Four facts, in order: the canonical specification (one explicit identity, one explicit
    endpoint), a libpq environment that can no longer steer the connection -- enforced per
    physical connection by the engine guard -- then, once open, the live database, cluster,
    endpoint and principal.
    """
    spec = config.parse_connection_url(url, variable=variable)

    # The environment check lives on the engine, not here. Checking once before
    # ``connect()`` leaves a window: the engine can be built, the environment can change,
    # and the connection then opens under it. ``guard_connection_environment`` installs a
    # ``do_connect`` handler that runs immediately before *each* physical DBAPI
    # connection, which is the only placement with no window at all.
    engine = guard_connection_environment(create_engine(spec.url(), poolclass=None, future=True))
    try:
        with engine.connect() as connection:
            expected = expected_identity_for(
                connection,
                database=spec.database,
                expected_user=spec.username,
                endpoint=spec.endpoint,
            )
            yield connection, expected
    finally:
        engine.dispose()


def main(argv: list[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    env = os.environ if env is None else env
    parser = argparse.ArgumentParser(prog="python3 -m firmbatch.control_plane.migrate")
    parser.add_argument("action", choices=("upgrade", "downgrade", "current", "heads"))
    parser.add_argument("--revision", default=None, help="target revision (downgrade requires it)")
    args = parser.parse_args(argv)

    if args.action == "heads":
        print(head_revision())
        return 0

    if args.action == "downgrade" and not args.revision:
        print("downgrade requires --revision", file=sys.stderr)
        return 2

    # Explicitly the MIGRATION settings. There is no combined loader, and this entry
    # point must never hold the runtime or the bootstrap credential.
    try:
        settings = config.load_migration_settings(env)
    except config.ConfigurationError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    url = settings.migration_url
    print(f"database    {config.redact_database_url(url)}")

    with migration_connection(url) as (connection, expected):
        if args.action == "current":
            print(f"current     {current_revision(connection) or '<none>'}")
            return 0
        if args.action == "upgrade":
            head = upgrade_to_head(connection, expected=expected)
            connection.commit()
            print(f"upgraded to {head}")
            return 0
        downgrade_to(connection, args.revision, expected=expected)
        connection.commit()
        print(f"downgraded to {args.revision}")
        return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
