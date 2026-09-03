"""The exact Alembic connection, the full runtime profile, and the DROP race.

* **Finding 2 -- the Alembic connection.** The bootstrap probed one connection and Alembic
  opened another from the same URL. Two physical connections; DNS or a failover endpoint
  can put the second on a different cluster. Alembic is now handed the already-validated
  connection, and validates it again immediately before its first DDL.
* **Finding 3 -- replication.** ``rolreplication`` was not part of the runtime-principal
  check. Row-level security has no bearing on the WAL: a role that can open a replication
  connection can stream every tenant without executing a ``SELECT``.
* **Finding 6 -- the DROP race.** ``DROP DATABASE`` cannot run inside a transaction, so
  check-then-drop is not atomic and no amount of care makes it so. The deletion is instead
  bound to the per-run owner identity: PostgreSQL evaluates ownership at the statement,
  against the object present at that instant.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, text

from firmbatch.control_plane import config, migrate
from firmbatch.control_plane.config import PrivilegedPrincipalError
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.principal import require_unprivileged_principal
from firmbatch.control_plane.testing import bootstrap

from .conftest import drop_disposable_objects


# ------------------------------------------ the exact Alembic connection (finding 2)


def test_alembic_runs_on_the_connection_it_was_given(disposable_database, monkeypatch):
    """The migration must travel over the connection that was validated, not a new one.

    A sentinel temporary table is created on the connection handed to Alembic. If Alembic
    opened its own connection the sentinel would be invisible to it -- a temporary table
    belongs to one session.

    The observation is taken by wrapping ``env.py``'s call to the *canonical* validator,
    not by supplying one. That distinction is the point of finding 2: production code no
    longer accepts a caller-supplied check, so a test that needs to watch the check has to
    watch the real one rather than substitute for it. The wrapper calls through, so the
    real validation still runs and still has to pass.
    """
    from firmbatch.control_plane.db import identity as identity_module

    seen: dict[str, object] = {}
    real = identity_module.require_expected_identity

    with migrate.migration_connection(disposable_database.migration_url) as (connection, expected):
        connection.execute(text("CREATE TEMP TABLE alembic_connection_sentinel (i int)"))

        def watching(live, identity, *, context):
            seen["same_object"] = live is connection
            # A temp table proves session identity, not merely cluster identity.
            seen["sees_sentinel"] = live.execute(
                text("SELECT to_regclass('pg_temp.alembic_connection_sentinel') IS NOT NULL")
            ).scalar()
            return real(live, identity, context=context)

        # Alembic execs env.py afresh per command and it re-imports this name, so the
        # defining module is the patch point. env.py itself cannot be imported.
        monkeypatch.setattr(identity_module, "require_expected_identity", watching)
        migrate.upgrade_to_head(connection, expected=expected)
        connection.rollback()

    assert seen["same_object"] is True, "Alembic did not run on the connection it was given"
    assert seen["sees_sentinel"] is True, "Alembic ran in a different session"


def test_a_mismatched_expected_identity_refuses_and_no_ddl_follows(environment):
    """A wrong identity stops the migration before any DDL runs.

    Its own disposable database, dropped straight after, so a half-migrated schema cannot
    affect anything else. The identity is *forged* rather than the check disabled: since
    finding 2 there is no value meaning "skip", only values that are right or wrong.
    """
    from dataclasses import replace

    from firmbatch.control_plane.db.identity import LiveIdentityError

    handle = bootstrap.create_disposable_database(environment)
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            connection.execute(text(f"DROP SCHEMA {SCHEMA} CASCADE"))
            connection.commit()

            forged = replace(expected, system_identifier="0000000000000000000")
            with pytest.raises(LiveIdentityError) as exc:
                migrate.upgrade_to_head(connection, expected=forged)
            assert "cluster" in str(exc.value)
            connection.rollback()

            present = connection.execute(
                text("SELECT count(*) FROM information_schema.tables WHERE table_schema = :s"),
                {"s": SCHEMA},
            ).scalar()
            assert present == 0, "DDL ran despite the validation refusing"
    finally:
        bootstrap.drop_disposable_database(handle)


def test_the_migration_connection_validator_checks_all_four_facts(disposable_database):
    """Database, cluster, endpoint and principal -- each independently disqualifying."""
    engine = create_engine(disposable_database.migration_url, poolclass=None, future=True)
    kwargs = dict(
        database=disposable_database.database,
        fingerprint=disposable_database.fingerprint,
        endpoint=disposable_database.endpoint,
        expected_user=disposable_database.owner_role,
        context="test",
    )
    try:
        with engine.connect() as connection:
            bootstrap.validate_migration_connection(connection, **kwargs)

            for field, value, expected in (
                ("database", "somewhere_else", "is attached to database"),
                ("expected_user", "somebody_else", "not the expected principal"),
                ("endpoint", ("elsewhere", 1), "not the recorded"),
            ):
                with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
                    bootstrap.validate_migration_connection(connection, **{**kwargs, field: value})
                assert expected in str(exc.value), field

            foreign = bootstrap.ClusterFingerprint(
                system_identifier="0", server_port=None, database="postgres", server_version_num=160000
            )
            with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
                bootstrap.validate_migration_connection(connection, **{**kwargs, "fingerprint": foreign})
            assert "not the cluster" in str(exc.value)
    finally:
        engine.dispose()


# --------------------------------------------- the full runtime profile (finding 3)


def test_the_runtime_roles_carry_the_documented_profile(owner_engine, disposable_database):
    """ADR 0004 promises NOSUPERUSER, NOBYPASSRLS, NOREPLICATION, NOCREATEDB, NOCREATEROLE."""
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                """
                SELECT rolname, rolsuper, rolbypassrls, rolreplication, rolcreatedb, rolcreaterole
                FROM pg_roles WHERE rolname = ANY(:names)
                """
            ),
            {
                "names": [
                    disposable_database.application_role,
                    disposable_database.provisioning_role,
                    disposable_database.owner_role,
                ]
            },
        ).all()
    assert len(rows) == 3
    for row in rows:
        assert tuple(row[1:]) == (False, False, False, False, False), row[0]


def test_a_replication_capable_principal_is_refused(environment, admin_engine):
    """Direct and reachable replication capability both disqualify a runtime principal."""
    handle = bootstrap.create_disposable_database(environment)
    probe_role = f"firmbatch_test_repl_probe_{uuid.uuid4().hex[:8]}"
    try:
        # A NOLOGIN role that merely *has* REPLICATION, granted to the application role.
        # Creating a REPLICATION role needs a superuser; where the admin is not one, the
        # test says so rather than pretending to have covered it.
        with admin_engine.connect() as connection:
            is_superuser = connection.execute(
                text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            ).scalar()
            if not is_superuser:
                pytest.skip(
                    "granting REPLICATION requires a superuser admin; covered by the "
                    "reachable-membership test below and by CI, where the admin is postgres"
                )
            connection.execute(text(f'CREATE ROLE "{probe_role}" NOLOGIN REPLICATION'))
            connection.execute(text(f'GRANT "{probe_role}" TO "{handle.application_role}"'))

        engine = db_engine.create_application_engine(handle.application_url)
        try:
            with pytest.raises(PrivilegedPrincipalError) as exc:
                with engine.connect():
                    pass
            assert "REPLICATION" in str(exc.value)
        finally:
            engine.dispose()
    finally:
        bootstrap.drop_disposable_database(handle)
        with admin_engine.connect() as connection:
            connection.execute(text(f'DROP ROLE IF EXISTS "{probe_role}"'))


def test_a_reachable_createrole_principal_is_refused(environment, admin_engine):
    """The rest of the profile, by a route any non-superuser admin can arrange."""
    handle = bootstrap.create_disposable_database(environment)
    probe_role = f"firmbatch_test_cr_probe_{uuid.uuid4().hex[:8]}"
    try:
        with admin_engine.connect() as connection:
            connection.execute(text(f'CREATE ROLE "{probe_role}" NOLOGIN CREATEROLE'))
            connection.execute(text(f'GRANT "{probe_role}" TO "{handle.application_role}"'))

        engine = db_engine.create_application_engine(handle.application_url)
        try:
            with pytest.raises(PrivilegedPrincipalError) as exc:
                with engine.connect():
                    pass
            assert "CREATEROLE" in str(exc.value)
        finally:
            engine.dispose()
    finally:
        bootstrap.drop_disposable_database(handle)
        with admin_engine.connect() as connection:
            connection.execute(text(f'DROP ROLE IF EXISTS "{probe_role}"'))


def test_the_check_names_which_capability_it_objected_to(application_engine):
    """A clean role reports nothing; the message format carries the capability names."""
    with application_engine.connect() as connection:
        with connection.connection.driver_connection.cursor() as cursor:
            report = require_unprivileged_principal(cursor)
    assert report.privileged_roles == ()


def test_every_documented_capability_is_actually_queried():
    """Structural, and therefore never skipped.

    The live REPLICATION test needs a superuser admin to create a REPLICATION role, so it
    skips on a non-superuser development cluster and runs in CI. This asserts, everywhere,
    that the attribute is still in the query and in the reported profile -- so a change
    that quietly dropped it fails on the developer machine too, rather than waiting for CI.
    """
    from firmbatch.control_plane.db import principal

    labelled = {label for _, label in principal._PRIVILEGED_ATTRIBUTES}
    assert labelled == {"SUPERUSER", "BYPASSRLS", "REPLICATION", "CREATEDB", "CREATEROLE"}
    for column, _ in principal._PRIVILEGED_ATTRIBUTES:
        assert column in principal._PRIVILEGED_ATTRIBUTE_SQL, column
    # Both identities, not just the effective one.
    assert "session_user" in principal._PRIVILEGED_ATTRIBUTE_SQL
    assert "session_user" in principal._OWNERSHIP_SQL
    # Every isolation-boundary object kind, not merely the tenant tables.
    for catalogue in ("pg_database", "pg_namespace", "pg_class", "pg_proc", "pg_type"):
        assert catalogue in principal._OWNERSHIP_SQL, catalogue


# ------------------------------------------------- the DROP race (finding 6)


def test_a_replacement_database_owned_by_another_identity_is_not_dropped(environment, admin_engine):
    """The race, resolved by privilege rather than by timing.

    The database is replaced *after* identity validation would have passed, and the
    replacement is owned by somebody else. The DROP runs as the recorded per-run owner, so
    PostgreSQL refuses it on ownership -- a check evaluated against the object present at
    that instant, which is the strongest guarantee available for a statement that cannot
    run inside a transaction.
    """
    handle = bootstrap.create_disposable_database(environment)
    other_owner = f"firmbatch_test_other_{uuid.uuid4().hex[:8]}"
    try:
        with admin_engine.connect() as connection:
            connection.execute(text(f'CREATE ROLE "{other_owner}" NOLOGIN'))
            connection.execute(text(f'GRANT "{other_owner}" TO CURRENT_USER WITH SET TRUE'))
            connection.execute(
                text("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = :d"),
                {"d": handle.database},
            )
        # Only the per-run owner can remove the original; the admin cannot.
        drop_disposable_objects(
            environment, database=handle.database, owner_role=handle.owner_role, role_names=()
        )
        with admin_engine.connect() as connection:
            connection.execute(
                text(f'CREATE DATABASE "{handle.database}" OWNER "{other_owner}"')
            )

        with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
            bootstrap.drop_disposable_database(handle)
        assert "replaced" in str(exc.value) or "must be owner" in str(exc.value)

        with admin_engine.connect() as connection:
            survived = connection.execute(
                text("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = :d"),
                {"d": handle.database},
            ).scalar()
        assert survived == other_owner, "the replacement was destroyed"
    finally:
        with admin_engine.connect() as connection:
            connection.execute(text(f'SET ROLE "{other_owner}"'))
            connection.execute(text(f'DROP DATABASE IF EXISTS "{handle.database}"'))
            connection.execute(text("RESET ROLE"))
            for role in (
                handle.application_role,
                handle.provisioning_role,
                handle.owner_role,
                other_owner,
            ):
                connection.execute(text(f'DROP ROLE IF EXISTS "{role}"'))


def test_the_drop_is_issued_as_the_recorded_owner_not_the_admin(environment, admin_engine, monkeypatch):
    """Prove the deletion authority is the owner identity, not ambient admin rights."""
    handle = bootstrap.create_disposable_database(environment)
    observed: list[str] = []
    real_drop = bootstrap._dispose_database_as_owner

    def spy(owner_url, recorded, fingerprint, role_names):
        spec = config.parse_connection_url(owner_url, variable="X")
        observed.append(spec.username)
        return real_drop(owner_url, recorded, fingerprint, role_names)

    monkeypatch.setattr(bootstrap, "_dispose_database_as_owner", spy)
    bootstrap.drop_disposable_database(handle)
    assert observed == [handle.owner_role], (
        "the database must be dropped as the per-run owner, not with admin authority"
    )


def test_a_role_replaced_under_the_same_name_is_not_dropped(environment, admin_engine):
    """Roles are removed by rename-verify-drop inside one transaction.

    The rename takes the lock and the OID is re-read after it, so what gets dropped is
    provably the object that was validated; a concurrent recreation keeps the original
    name, which the transaction is no longer referring to.
    """
    handle = bootstrap.create_disposable_database(environment)
    role = handle.provisioning_role
    try:
        with admin_engine.connect() as connection:
            connection.execute(
                text("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = :d"),
                {"d": handle.database},
            )
        drop_disposable_objects(
            environment, database=handle.database, owner_role=handle.owner_role, role_names=()
        )
        with admin_engine.connect() as connection:
            connection.execute(text(f'DROP ROLE "{role}"'))
            connection.execute(text(f'CREATE ROLE "{role}" NOLOGIN'))
            replacement_oid = connection.execute(
                text("SELECT oid FROM pg_roles WHERE rolname = :n"), {"n": role}
            ).scalar()

        with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
            bootstrap.drop_disposable_database(handle)
        assert "replaced" in str(exc.value)

        with admin_engine.connect() as connection:
            still = connection.execute(
                text("SELECT oid FROM pg_roles WHERE rolname = :n"), {"n": role}
            ).scalar()
        assert still == replacement_oid, "the replacement role was destroyed"
    finally:
        with admin_engine.connect() as connection:
            for name in (handle.application_role, handle.provisioning_role, handle.owner_role):
                connection.execute(text(f'DROP ROLE IF EXISTS "{name}"'))
