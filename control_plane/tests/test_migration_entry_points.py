"""Finding 2: online migration validation is mandatory and non-bypassable.

Two shapes were wrong, and the second is the interesting one.

**URL-taking entry points.** ``upgrade_to_head(url)`` and ``downgrade_to(url, rev)`` handed
a URL to Alembic, which resolved it and opened its *own* connection. A URL is resolved when
it is used, so validating one and passing it along validates a different connection than
the one the DDL travels over -- DNS, a failover endpoint, a load balancer, or ``PGHOSTADDR``
are each enough to make the two differ.

**A caller-supplied validator.** ``upgrade_to_head(conn, validate=lambda c: None)``
authorised DDL against anything at all, and read in review exactly like a checked
migration. A seam in a safety check is a bypass with extra steps, and a boolean flag would
be no better: ``validated=True`` is a claim by the caller, not evidence about a connection.

So what travels now is **data** -- an immutable ``ExpectedIdentity`` recording the database,
cluster system identifier, canonical endpoint and principal the connection must turn out to
have -- and ``env.py`` calls the canonical validator itself, on the exact ``Connection``
supplied, before any ``SET``, ``CREATE SCHEMA``, version-table access or migration
statement. A caller can pass a *wrong* identity and get a refusal naming the mismatch.
There is no value that means "already checked".

``downgrade_to`` mattered most: it drops tables and policies, so an unvalidated downgrade is
strictly more dangerous than an unvalidated upgrade, and it was the entry point that still
took a bare URL.

Offline rendering (``--sql``) is deliberately untouched. It executes no DDL, so there is no
connection to point at the wrong server.
"""

from __future__ import annotations

import dataclasses
import inspect

import pytest
from sqlalchemy import text

from firmbatch.control_plane import config, migrate
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.identity import ExpectedIdentity, LiveIdentityError
from firmbatch.control_plane.testing.bootstrap import create_disposable_database, drop_disposable_database


# ------------------------------------------------------------------ the shape of the API


def test_no_migration_entry_point_accepts_a_url_or_a_validator():
    """The two bypasses are gone from the signatures, not merely discouraged.

    ``alembic_config`` is the funnel: if it will not build a config from a URL or from a
    callable, nothing downstream can run one.
    """
    for name in ("upgrade_to_head", "downgrade_to", "alembic_config"):
        parameters = inspect.signature(getattr(migrate, name)).parameters
        assert "migration_url" not in parameters, f"{name} still takes a URL"
        assert "validate" not in parameters, f"{name} still takes a caller-supplied validator"
        assert "expected" in parameters, f"{name} does not require an ExpectedIdentity"


def test_the_expected_identity_is_immutable():
    """It is evidence about a connection, so nothing may edit one after it is built."""
    identity = ExpectedIdentity(
        database="db", system_identifier="1", endpoint=("h", 5432), expected_user="u"
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        identity.database = "other"  # type: ignore[misc]


def test_the_expected_identity_repr_carries_no_secret():
    identity = ExpectedIdentity(
        database="db", system_identifier="1", endpoint=("h", 5432), expected_user="u"
    )
    assert "system_identifier" not in repr(identity) or "1" in repr(identity)
    assert "password" not in repr(identity).lower()


# ------------------------------------------------------------------ negative: no entry point


def test_upgrade_refuses_without_a_connection():
    with pytest.raises(migrate.UnvalidatedMigrationError) as exc:
        migrate.upgrade_to_head(None, expected=None)
    assert "already-validated Connection" in str(exc.value)


def test_downgrade_refuses_without_a_connection():
    with pytest.raises(migrate.UnvalidatedMigrationError):
        migrate.downgrade_to(None, "base", expected=None)


@pytest.mark.parametrize(
    "forgery, label",
    [
        (None, "nothing at all"),
        (True, "a boolean flag"),
        (lambda _connection: None, "the former no-op callback"),
        (object(), "an unrelated object"),
    ],
)
def test_ddl_cannot_be_authorized_by_anything_but_an_expected_identity(
    disposable_database, forgery, label
):
    """The exact attack the callback seam allowed, plus the shapes near it.

    ``lambda c: None`` is what the previous contract accepted as proof that a connection
    had been checked. It now gets the same refusal as ``True`` and as ``None``.
    """
    with migrate.migration_connection(disposable_database.migration_url) as (connection, _):
        with pytest.raises(migrate.UnvalidatedMigrationError) as exc:
            migrate.upgrade_to_head(connection, expected=forgery)
        assert "ExpectedIdentity" in str(exc.value), label


def test_a_look_alike_object_is_refused(disposable_database):
    """Duck typing is not evidence: the canonical validator checks the type.

    An object carrying the right attribute names would otherwise pass every field
    comparison trivially, because it would be compared against itself.
    """

    class LooksRight:
        database = disposable_database.database
        system_identifier = "whatever"
        endpoint = disposable_database.endpoint
        expected_user = disposable_database.owner_role

    with migrate.migration_connection(disposable_database.migration_url) as (connection, _):
        with pytest.raises(migrate.UnvalidatedMigrationError):
            migrate.upgrade_to_head(connection, expected=LooksRight())


def test_alembic_env_refuses_a_direct_online_invocation(disposable_database):
    """``alembic upgrade head`` cannot satisfy the contract, so ``env.py`` refuses it."""
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(migrate.ALEMBIC_INI))
    cfg.set_main_option("script_location", str(migrate.MIGRATIONS_DIR))

    with pytest.raises(Exception) as exc:
        command.upgrade(cfg, "head")
    assert "refusing to run migrations online" in str(exc.value)


def test_alembic_env_refuses_a_connection_without_an_identity(disposable_database):
    """Supplying only the connection is not enough, and the message says what is missing."""
    from alembic import command
    from alembic.config import Config

    with migrate.migration_connection(disposable_database.migration_url) as (connection, _):
        cfg = Config(str(migrate.ALEMBIC_INI))
        cfg.set_main_option("script_location", str(migrate.MIGRATIONS_DIR))
        cfg.attributes["connection"] = connection
        with pytest.raises(Exception) as exc:
            command.upgrade(cfg, "head")
        assert "expected_identity" in str(exc.value)


def test_alembic_env_refuses_a_callable_smuggled_into_the_attribute(disposable_database):
    """The last route: set the attribute directly to something that is not an identity.

    ``env.py`` calls ``require_expected_identity``, which checks the type rather than
    calling anything the caller supplied -- so a callable placed in the attribute is
    refused rather than invoked.
    """
    from alembic import command
    from alembic.config import Config

    with migrate.migration_connection(disposable_database.migration_url) as (connection, _):
        cfg = Config(str(migrate.ALEMBIC_INI))
        cfg.set_main_option("script_location", str(migrate.MIGRATIONS_DIR))
        cfg.attributes["connection"] = connection
        cfg.attributes["expected_identity"] = lambda _c: None
        with pytest.raises(LiveIdentityError) as exc:
            command.upgrade(cfg, "head")
        assert "no expected identity" in str(exc.value)


def test_the_refusal_happens_before_any_ddl(environment):
    """No ``SET``, no ``CREATE SCHEMA``, nothing -- on a database with no schema at all."""
    from alembic import command
    from alembic.config import Config

    handle = create_disposable_database(environment)
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            migrate.downgrade_to(connection, "base", expected=expected)
            connection.execute(text(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE"))
            connection.commit()

        cfg = Config(str(migrate.ALEMBIC_INI))
        cfg.set_main_option("script_location", str(migrate.MIGRATIONS_DIR))
        with pytest.raises(Exception):
            command.upgrade(cfg, "head")

        with migrate.migration_connection(handle.migration_url) as (connection, _):
            present = connection.execute(
                text("SELECT count(*) FROM information_schema.schemata WHERE schema_name = :s"),
                {"s": SCHEMA},
            ).scalar()
        assert present == 0, "the refused invocation created the schema anyway"
    finally:
        drop_disposable_database(handle)


@pytest.mark.parametrize(
    "field, value, expected_text",
    [
        ("database", "postgres", "attached to database"),
        ("expected_user", "somebody_else", "not the expected principal"),
        ("endpoint", ("elsewhere", 1), "not the recorded"),
        ("system_identifier", "0000000000000000000", "not the recorded"),
    ],
)
def test_a_forged_identity_is_refused_field_by_field(
    disposable_database, field, value, expected_text
):
    """Each field is load-bearing, so each is proven to be compared."""
    with migrate.migration_connection(disposable_database.migration_url) as (connection, expected):
        forged = dataclasses.replace(expected, **{field: value})
        with pytest.raises(LiveIdentityError) as exc:
            migrate.upgrade_to_head(connection, expected=forged)
        assert expected_text in str(exc.value), field


def test_a_preselected_role_is_refused_by_the_principal_profile(disposable_database):
    """The migration-principal profile: ``RESET ROLE`` must not change who this is.

    A privileged login that preselected a restricted role looks correct in
    ``current_user`` while remaining one ``RESET ROLE`` from full privilege, so the check
    resets first and compares afterwards.
    """
    from firmbatch.control_plane.db.identity import require_expected_identity

    with migrate.migration_connection(disposable_database.migration_url) as (connection, expected):
        wrong = dataclasses.replace(expected, expected_user="postgres")
        with pytest.raises(LiveIdentityError):
            require_expected_identity(connection, wrong, context="test")


# ------------------------------------------------------------------ positive: the one path


def test_upgrade_and_downgrade_run_on_the_exact_validated_connection(environment):
    """The connection Alembic uses must be the object that was validated, not a twin.

    Proven with a temporary table: it belongs to one session and is invisible to every
    other, so seeing it from inside the canonical validator is only possible if Alembic
    really is running on this connection.

    Alembic execs ``env.py`` afresh for every command, and that file re-imports
    ``require_expected_identity`` from ``db.identity`` each time -- so patching it in its
    defining module is what the freshly exec'd environment picks up. (``env.py`` cannot be
    imported directly: its module body calls ``context.is_offline_mode()``, which only
    exists inside an Alembic run.)
    """
    from firmbatch.control_plane.db import identity as identity_module

    handle = create_disposable_database(environment)
    real = identity_module.require_expected_identity
    seen: dict[str, object] = {}
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            connection.execute(text("CREATE TEMP TABLE entry_point_sentinel (i int)"))

            def watching(live, identity, *, context):
                seen["same_object"] = live is connection
                seen["same_session"] = live.execute(
                    text("SELECT to_regclass('pg_temp.entry_point_sentinel') IS NOT NULL")
                ).scalar()
                return real(live, identity, context=context)

            identity_module.require_expected_identity = watching
            try:
                migrate.downgrade_to(connection, "base", expected=expected)
                connection.commit()
                assert seen["same_object"] is True
                assert seen["same_session"] is True
                assert migrate.current_revision(connection) is None

                assert migrate.upgrade_to_head(connection, expected=expected) == migrate.head_revision()
                connection.commit()
                assert migrate.current_revision(connection) == migrate.head_revision()
            finally:
                identity_module.require_expected_identity = real
    finally:
        drop_disposable_database(handle)


def test_migration_connection_validates_before_it_yields(disposable_database):
    """The first check happens on open, so a caller never holds an unvalidated connection."""
    with migrate.migration_connection(disposable_database.migration_url) as (connection, expected):
        database, user = connection.execute(
            text("SELECT current_database(), current_user")
        ).one()
        assert database == disposable_database.database
        assert user == disposable_database.owner_role
        assert expected.database == disposable_database.database
        assert expected.expected_user == disposable_database.owner_role
        assert expected.endpoint == disposable_database.endpoint
        assert expected.system_identifier


def test_migration_connection_refuses_a_url_that_is_not_canonical():
    """It parses through the same configuration boundary as everything else."""
    with pytest.raises(config.ConfigurationError):
        with migrate.migration_connection("postgresql+psycopg://u@h1,h2:5432/db"):
            pass  # pragma: no cover


def test_the_cli_uses_the_validated_path(disposable_database, monkeypatch, capsys):
    """``migrate current`` is a real online action and goes through the same connection."""
    monkeypatch.setenv(config.MIGRATION_URL_VAR, disposable_database.migration_url)
    monkeypatch.setenv(config.ENVIRONMENT_VAR, "test")
    assert migrate.main(["current"]) == 0
    assert migrate.head_revision() in capsys.readouterr().out


def test_offline_rendering_remains_available():
    """``--sql`` executes no DDL, so there is no connection to point at the wrong server.

    Read from disk rather than imported: ``env.py``'s module body calls
    ``context.is_offline_mode()``, which only exists inside an Alembic run.
    """
    source = (migrate.MIGRATIONS_DIR / "env.py").read_text()
    assert "def run_migrations_offline" in source
    assert "if context.is_offline_mode():" in source
    # And the online path is the one that refuses.
    assert "refusing to run migrations online" in source
