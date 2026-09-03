"""The application role cannot step outside row-level security.

Forcing RLS is worth nothing if the role the application connects as owns the tables, is
a superuser, or holds ``BYPASSRLS`` -- in each of those cases the policies would be
decorative. These tests assert the role attributes, prove the runtime *principal check*
refuses a privileged URL, and then try, from a real connection, every ordinary way out:
disabling the policy, switching identity, creating a table, reading the schema history,
and creating a tenant from the application role.

What they do NOT claim: the application role can set ``app.tenant_id`` to any tenant it
likes. RLS bounds what a query reaches given a context; it does not bound a control plane
that chose the wrong context. Binding the context to an authenticated credential is
M2.3/M3 work. ADR 0004 records the limit rather than leaving it implied.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import ProgrammingError

from firmbatch.control_plane import config, migrate
from firmbatch.control_plane.config import PrivilegedPrincipalError
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.principal import inspect_principal, require_unprivileged_principal
from firmbatch.control_plane.db.repositories import TenantRepository
from firmbatch.control_plane.testing.bootstrap import create_disposable_database, drop_disposable_database


def test_application_role_has_no_privileged_attributes(owner_engine, disposable_database):
    with owner_engine.connect() as connection:
        row = connection.execute(
            text(
                """
                SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolreplication
                FROM pg_roles WHERE rolname = :role
                """
            ),
            {"role": disposable_database.application_role},
        ).one()
    assert row == (False, False, False, False, False)


def test_provisioning_role_has_no_privileged_attributes(owner_engine, disposable_database):
    """Privileged provisioning is a grant on one table, not a superuser."""
    with owner_engine.connect() as connection:
        row = connection.execute(
            text("SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = :role"),
            {"role": disposable_database.provisioning_role},
        ).one()
    assert row == (False, False, False, False)


def test_application_role_does_not_own_the_tenant_scoped_tables(owner_engine, disposable_database):
    with owner_engine.connect() as connection:
        owners = dict(
            connection.execute(
                text(
                    "SELECT tablename, tableowner FROM pg_tables "
                    "WHERE schemaname = :schema AND tablename IN ('tenants','workspaces')"
                ),
                {"schema": SCHEMA},
            ).all()
        )
    assert set(owners) == {"tenants", "workspaces"}
    for table, owner in owners.items():
        assert owner != disposable_database.application_role, f"{table} is owned by the application role"
        assert owner != disposable_database.provisioning_role, f"{table} is owned by the provisioning role"


# --------------------------------------------------------------- runtime principal check


def test_the_runtime_principal_check_accepts_the_application_role(application_engine):
    """Finding 1: the check must pass for a correctly restricted role."""
    with application_engine.connect() as connection:
        with connection.connection.driver_connection.cursor() as cursor:
            report = require_unprivileged_principal(cursor)
    assert report.is_safe
    assert report.privileged_roles == ()
    assert report.owned_tables == ()


def test_an_application_engine_refuses_the_owner_url(disposable_database):
    """Finding 1: the owner is not a legal application principal.

    An owner can ``ALTER TABLE ... NO FORCE ROW LEVEL SECURITY``, so pointing
    ``FIRMBATCH_DATABASE_URL`` at the migration principal would leave the policies in place
    and the boundary off. Refused on connect, from the live catalogue -- comparing URL
    strings could not have caught this, because both URLs are the same shape.
    """
    engine = db_engine.create_application_engine(disposable_database.migration_url)
    try:
        with pytest.raises(PrivilegedPrincipalError) as exc:
            with engine.connect():
                pass
    finally:
        engine.dispose()
    message = str(exc.value)
    assert "owns" in message or "SUPERUSER" in message or "BYPASSRLS" in message


def test_the_principal_check_sees_reachable_table_ownership(environment, admin_engine):
    """Finding 1: reachable ownership must disqualify the application role.

    ``GRANT <owner> TO <app>`` is one command, it looks harmless in a migration, and it
    hands the application role the ability to ``SET ROLE`` to a table owner and switch
    ``FORCE ROW LEVEL SECURITY`` off. Checking only the connected role's own attributes
    would miss it entirely, which is why the check uses ``pg_has_role``.

    Runs on its own disposable database because it transfers table ownership; a failure
    part-way through must not leave the shared one mis-owned.
    """
    handle = create_disposable_database(environment)
    probe_role = f"firmbatch_test_owner_probe_{uuid.uuid4().hex[:8]}"
    try:
        # Role creation and membership are ADMIN actions: the per-run owner role is
        # deliberately NOCREATEROLE, so it cannot do this and should not be able to.
        with admin_engine.connect() as connection:
            connection.execute(text(f'CREATE ROLE "{probe_role}" NOLOGIN'))
            connection.execute(text(f'GRANT "{probe_role}" TO "{handle.owner_role}" WITH SET TRUE'))
            connection.execute(text(f'GRANT "{probe_role}" TO "{handle.application_role}"'))

        owner = migrate.create_migration_engine(handle.migration_url)
        try:
            with owner.connect() as connection:
                # A new owner needs CREATE on the schema; harden_database revoked it from
                # PUBLIC, which is why this has to be granted back for the probe.
                connection.execute(text(f'GRANT CREATE, USAGE ON SCHEMA {SCHEMA} TO "{probe_role}"'))
                connection.execute(text(f'ALTER TABLE {SCHEMA}.workspaces OWNER TO "{probe_role}"'))
                connection.commit()
        finally:
            owner.dispose()

        engine = db_engine.create_application_engine(handle.application_url)
        try:
            with pytest.raises(PrivilegedPrincipalError) as exc:
                with engine.connect():
                    pass
        finally:
            engine.dispose()
        message = str(exc.value)
        assert "workspaces" in message
        assert "FORCE ROW LEVEL SECURITY off" in message
    finally:
        drop_disposable_database(handle)
        admin = create_engine(
            config.load_test_admin_url(environment), isolation_level="AUTOCOMMIT", future=True
        )
        try:
            with admin.connect() as connection:
                connection.execute(text(f'DROP ROLE IF EXISTS "{probe_role}"'))
        finally:
            admin.dispose()


def test_the_principal_check_reports_a_clean_application_role(application_engine):
    """The counterpart: the ordinary application role reports nothing disqualifying."""
    with application_engine.connect() as connection:
        with connection.connection.driver_connection.cursor() as cursor:
            report = inspect_principal(cursor)
    assert report.is_safe
    assert report.current_user.startswith("firmbatch_test_app_")


def test_the_principal_check_fails_closed_when_it_cannot_run(application_engine):
    """An inspection that cannot complete is a failure, not a pass."""

    class BrokenCursor:
        def execute(self, *_args, **_kwargs):
            raise RuntimeError("catalogue unavailable")

        def fetchone(self):  # pragma: no cover - never reached
            return None

        def fetchall(self):  # pragma: no cover - never reached
            return []

    with pytest.raises(PrivilegedPrincipalError) as exc:
        require_unprivileged_principal(BrokenCursor())
    assert "could not establish" in str(exc.value)


# --------------------------------------------------------------------- escape attempts


def test_application_role_cannot_disable_row_level_security(raw_application_connection):
    for statement in (
        f"ALTER TABLE {SCHEMA}.workspaces DISABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {SCHEMA}.workspaces NO FORCE ROW LEVEL SECURITY",
        f"DROP POLICY workspaces_tenant_isolation ON {SCHEMA}.workspaces",
    ):
        with pytest.raises(ProgrammingError) as exc:
            raw_application_connection.execute(text(statement))
        assert "must be owner" in str(exc.value).lower() or "permission denied" in str(exc.value).lower()


def test_application_role_cannot_ask_for_row_security_to_be_skipped(raw_application_connection):
    """``SET row_security = off`` is accepted, and then every affected query is refused.

    PostgreSQL lets any role set the GUC; what it does not let a non-``BYPASSRLS`` role do
    is *read through it*. The query fails with ``InsufficientPrivilege: query would be
    affected by row-level security policy`` rather than returning another tenant's rows,
    which is the fail-closed half that matters.
    """
    raw_application_connection.execute(text("SET row_security = off"))
    with pytest.raises(ProgrammingError) as exc:
        raw_application_connection.execute(text(f"SELECT * FROM {SCHEMA}.workspaces"))
    assert "row-level security policy" in str(exc.value).lower()
    raw_application_connection.execute(text("SET row_security = on"))


def test_application_role_cannot_become_another_role(raw_application_connection, disposable_database):
    for statement in (
        f'SET ROLE "{disposable_database.provisioning_role}"',
        "SET SESSION AUTHORIZATION postgres",
    ):
        with pytest.raises(Exception):
            raw_application_connection.execute(text(statement))


def test_application_role_cannot_create_tables(raw_application_connection):
    for statement in (
        f"CREATE TABLE {SCHEMA}.escape_hatch (id uuid PRIMARY KEY)",
        "CREATE TABLE public.escape_hatch (id uuid PRIMARY KEY)",
    ):
        with pytest.raises(ProgrammingError) as exc:
            raw_application_connection.execute(text(statement))
        assert "permission denied" in str(exc.value).lower()


def test_application_role_cannot_read_the_schema_history(raw_application_connection):
    """The migration history is not application data and is not granted to the app role."""
    with pytest.raises(ProgrammingError) as exc:
        raw_application_connection.execute(text(f"SELECT * FROM {SCHEMA}.alembic_version"))
    assert "permission denied" in str(exc.value).lower()


def test_application_role_cannot_create_a_tenant_even_with_matching_context(application_engine):
    """Provisioning is a separate privilege, not a matter of setting the right context."""
    tenant_id = uuid.uuid4()
    with pytest.raises(ProgrammingError) as exc:
        with db_engine.tenant_transaction(application_engine, tenant_id) as session:
            session.execute(
                text(f"INSERT INTO {SCHEMA}.tenants (id, slug, name) VALUES (:id, 'self-made', 'Self Made')"),
                {"id": tenant_id},
            )
    assert "permission denied" in str(exc.value).lower()


def test_provisioning_role_can_create_a_tenant(provisioning_engine):
    slug = f"provisioned-{uuid.uuid4().hex[:10]}"
    with db_engine.transaction(provisioning_engine) as session:
        tenant = TenantRepository(session).create(slug=slug, name="Provisioned")
        tenant_id = tenant.id
    with db_engine.tenant_transaction(provisioning_engine, tenant_id) as session:
        assert TenantRepository(session).get(tenant_id) is not None


def test_provisioning_role_cannot_read_tenant_data(provisioning_engine, tenant_a):
    """It creates the scope; it does not get to look inside it."""
    with pytest.raises(ProgrammingError) as exc:
        with db_engine.tenant_transaction(provisioning_engine, tenant_a) as session:
            session.execute(text(f"SELECT * FROM {SCHEMA}.workspaces"))
    assert "permission denied" in str(exc.value).lower()


def test_provisioning_role_cannot_modify_another_tenants_row(provisioning_engine, tenant_a, tenant_b):
    """Finding 11: prove the intended operation, not an incidental exception.

    The previous version of this test wrapped the whole block in ``pytest.raises(Exception)``
    and passed because a later ``assert`` raised ``AssertionError`` -- which is an
    ``Exception``. It never demonstrated that the UPDATE was refused. This version runs the
    UPDATE, asserts the row count, and then reads the row back from tenant B's own valid
    context to prove the stored value is unchanged.
    """
    with db_engine.tenant_transaction(provisioning_engine, tenant_b) as session:
        original = session.execute(
            text(f"SELECT name FROM {SCHEMA}.tenants WHERE id = :id"), {"id": tenant_b}
        ).scalar()
    assert original is not None, "tenant B must be readable from its own context for this test to mean anything"

    # Tenant A's context cannot see tenant B's row, so the UPDATE matches nothing.
    with db_engine.tenant_transaction(provisioning_engine, tenant_a) as session:
        result = session.execute(
            text(f"UPDATE {SCHEMA}.tenants SET name = 'seized' WHERE id = :id"), {"id": tenant_b}
        )
        assert result.rowcount == 0, "tenant A must not be able to update tenant B's row"
        # And from A's context the row is simply absent.
        assert session.execute(
            text(f"SELECT name FROM {SCHEMA}.tenants WHERE id = :id"), {"id": tenant_b}
        ).scalar() is None

    # The authoritative check: read it back from tenant B's valid context.
    with db_engine.tenant_transaction(provisioning_engine, tenant_b) as session:
        after = session.execute(
            text(f"SELECT name FROM {SCHEMA}.tenants WHERE id = :id"), {"id": tenant_b}
        ).scalar()
    assert after == original
    assert after != "seized"


def test_no_firmbatch_role_holds_bypassrls(owner_engine):
    """A BYPASSRLS role reachable from the application would undo the whole boundary."""
    with owner_engine.connect() as connection:
        bypass = connection.execute(
            text("SELECT rolname FROM pg_roles WHERE rolbypassrls AND rolname NOT LIKE 'pg\\_%'")
        ).scalars().all()
    assert [r for r in bypass if r.startswith("firmbatch_")] == []
