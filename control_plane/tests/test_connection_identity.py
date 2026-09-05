"""Regressions for what a connection *actually* is, as opposed to what its URL says.

A second review round found three ways the URL and the open connection could disagree,
and one way a connection could stop being safe after it had been approved. Each was
reproduced against a real PostgreSQL 16 server.

* **Finding 1 -- effective database.** ``/postgres?dbname=customer_prod`` validated as
  ``postgres`` and connected to ``customer_prod``; libpq gives the query string
  precedence. ``_swap_database`` preserved the override too, so migrations would have run
  somewhere other than the database the code believed it had created.
* **Finding 2 -- effective role.** A privileged login can preselect a restricted role
  with ``options=-c role=...``. PostgreSQL then reports the restricted role as
  ``current_user`` while the privileged identity remains ``session_user``, one ``RESET
  ROLE`` away. The principal check read ``current_user`` and pronounced it safe.
* **Finding 3 -- privileges change under a pooled connection.** Validation ran once, at
  connect. A connection accepted hours earlier went on serving DML after its role was
  granted ownership of a tenant-scoped table.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, make_url, text

from firmbatch.control_plane import config
from firmbatch.control_plane.config import PrivilegedPrincipalError
from firmbatch.control_plane.db import auth
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.principal import inspect_principal, require_unprivileged_principal
from firmbatch.control_plane.testing import bootstrap


# ------------------------------------------- effective database (finding 1)


def test_the_effective_database_is_verified_after_connecting(disposable_database, environment):
    """The server is asked which database it actually attached the connection to."""
    engine = create_engine(disposable_database.admin_url, isolation_level="AUTOCOMMIT", future=True)
    try:
        with engine.connect() as connection:
            live = connection.execute(text("SELECT current_database()")).scalar()
            config.require_maintenance_database_name(live, context="test")
            bootstrap._require_live_database(connection, live, context="test")
            with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
                bootstrap._require_live_database(connection, "some_other_database", context="test")
            assert "is attached to database" in str(exc.value)
    finally:
        engine.dispose()


def test_swapping_the_database_strips_every_routing_override():
    """``_swap_database`` must not carry a ``dbname`` from the source URL into the target."""
    source = "postgresql+psycopg://u@/postgres?host=/var/run/postgresql"
    swapped = bootstrap._swap_database(source, "firmbatch_test_0123456789ab")
    assert config.database_name(swapped) == "firmbatch_test_0123456789ab"
    # The socket directory survives; it is how the connection is made at all.
    assert "host=" in swapped
    # And a URL that somehow arrived with an override loses it rather than propagating it.
    smuggled = "postgresql+psycopg://u@/postgres?host=/var/run/postgresql&dbname=customer_prod"
    cleaned = bootstrap._swap_database(smuggled, "firmbatch_test_0123456789ab")
    assert "dbname" not in cleaned
    assert config.database_name(cleaned) == "firmbatch_test_0123456789ab"


def test_a_redirected_admin_url_never_reaches_creation(environment):
    """The bootstrap refuses a maintenance URL carrying a database override."""
    poisoned = dict(environment)
    poisoned[config.TEST_ADMIN_URL_VAR] = (
        make_url(config.load_test_admin_url(environment))
        .update_query_dict({"dbname": "template1"})
        .render_as_string(hide_password=False)
    )
    with pytest.raises(config.ConfigurationError) as exc:
        bootstrap.create_disposable_database(poisoned)
    assert "redirects the connection" in str(exc.value)


# ----------------------------------------------- effective role (finding 2)


def test_the_principal_check_sees_through_a_preselected_role(
    disposable_database, environment, admin_engine
):
    """A restricted ``current_user`` over a privileged ``session_user`` must not pass.

    Reproduced by having the owner ``SET ROLE`` to the restricted application role and then
    inspecting: the old check reported ``is_safe`` while the authenticated identity was the
    table owner, one ``RESET ROLE`` from full privilege.
    """
    app_role = disposable_database.application_role
    owner_role = disposable_database.owner_role
    # Granting membership is an admin action; the per-run owner is NOCREATEROLE.
    with admin_engine.connect() as admin_connection:
        admin_connection.execute(text(f'GRANT "{app_role}" TO "{owner_role}" WITH SET TRUE'))

    owner = create_engine(disposable_database.migration_url, isolation_level="AUTOCOMMIT", future=True)
    try:
        with owner.connect() as connection:
            try:
                connection.execute(text(f'SET ROLE "{app_role}"'))
                raw = connection.connection.driver_connection

                # Observed without the reset, this is exactly the disguise: restricted
                # current_user, privileged session_user.
                with raw.cursor() as cursor:
                    disguised = inspect_principal(cursor, reset_role=False)
                assert disguised.current_user == app_role
                assert disguised.session_user != app_role
                assert not disguised.is_safe, "a preselected role must not read as safe"

                # And the enforcing entry point refuses it, having reset the role first.
                connection.execute(text(f'SET ROLE "{app_role}"'))
                with raw.cursor() as cursor:
                    with pytest.raises(PrivilegedPrincipalError) as exc:
                        require_unprivileged_principal(cursor, expected_user=app_role)
                message = str(exc.value)
                assert "owns" in message or "SUPERUSER" in message or "BYPASSRLS" in message
            finally:
                connection.execute(text("RESET ROLE"))
    finally:
        owner.dispose()
        with admin_engine.connect() as admin_connection:
            admin_connection.execute(text(f'REVOKE "{app_role}" FROM "{owner_role}"'))


def test_an_authenticated_identity_other_than_the_url_role_is_refused(disposable_database):
    """``expected_user`` ties the connection back to the role the URL claimed."""
    engine = db_engine.create_application_engine(disposable_database.application_url, pool_size=1)
    try:
        with engine.connect() as connection:
            raw = connection.connection.driver_connection
            with raw.cursor() as cursor:
                # Correct expectation passes.
                require_unprivileged_principal(cursor, expected_user=disposable_database.application_role)
                # A different expectation is a mismatch, and mismatches fail closed.
                with pytest.raises(PrivilegedPrincipalError) as exc:
                    require_unprivileged_principal(cursor, expected_user="somebody_else")
            assert "authenticated as" in str(exc.value)
    finally:
        engine.dispose()


def test_a_url_carrying_a_startup_role_is_rejected_before_connecting(disposable_database):
    """``options`` never reaches libpq: it is refused during URL validation."""
    poisoned = make_url(disposable_database.migration_url).update_query_dict(
        {"options": f"-c role={disposable_database.application_role}"}
    )
    with pytest.raises(config.ConfigurationError) as exc:
        db_engine.create_application_engine(poisoned.render_as_string(hide_password=False))
    assert "preselect a role" in str(exc.value)


# -------------------------------- revalidation on pool checkout (finding 3)


def test_a_pooled_connection_is_revalidated_on_checkout(environment, admin_engine):
    """A connection approved at connect must be re-checked when it leaves the pool.

    Its own disposable database, because it transfers table ownership: a failure part-way
    through must not leave the shared one mis-owned.
    """
    handle = bootstrap.create_disposable_database(environment)
    probe_role = f"firmbatch_test_owner_probe_{uuid.uuid4().hex[:8]}"
    try:
        engine = db_engine.create_application_engine(handle.application_url, pool_size=1, max_overflow=0)
        try:
            # 1. A safe connection is established and validated, then returned to the pool.
            with db_engine.transaction(engine) as session:
                assert session.execute(text("SELECT 1")).scalar() == 1

            # 2. The role gains ownership of a tenant-scoped table while it sits idle.
            with admin_engine.connect() as connection:
                connection.execute(text(f'CREATE ROLE "{probe_role}" NOLOGIN'))
                connection.execute(text(f'GRANT "{probe_role}" TO "{handle.owner_role}" WITH SET TRUE'))
                connection.execute(text(f'GRANT "{probe_role}" TO "{handle.application_role}"'))
            owner = create_engine(handle.migration_url, isolation_level="AUTOCOMMIT", future=True)
            try:
                with owner.connect() as connection:
                    connection.execute(text(f'GRANT CREATE, USAGE ON SCHEMA {SCHEMA} TO "{probe_role}"'))
                    connection.execute(text(f'ALTER TABLE {SCHEMA}.workspaces OWNER TO "{probe_role}"'))
            finally:
                owner.dispose()

            # 3. The next checkout must refuse it, before any application DML runs.
            with pytest.raises(PrivilegedPrincipalError) as exc:
                with db_engine.transaction(engine):
                    pass
            assert "pool checkout" in str(exc.value)
            assert "workspaces" in str(exc.value)
        finally:
            engine.dispose()
    finally:
        # Restore ownership so the disposable database can be torn down cleanly.
        # No need to restore table ownership: the whole disposable database goes next, and
        # dropping it removes the probe role's dependent objects along with it.
        with admin_engine.connect() as connection:
            connection.execute(text(f'REVOKE "{probe_role}" FROM "{handle.application_role}"'))
        bootstrap.drop_disposable_database(handle)
        with admin_engine.connect() as connection:
            connection.execute(text(f'DROP ROLE IF EXISTS "{probe_role}"'))


def test_a_healthy_pooled_connection_survives_repeated_checkouts(application_engine, principal_a):
    """Revalidation must not break the ordinary path, only the compromised one.

    Three checkouts, each of which re-verifies the principal, re-pins ``search_path`` and
    empties the authentication context before the transaction acquires its own.
    """
    for _ in range(3):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            assert db_engine.current_tenant_context(session) == principal_a.id
