"""Fixtures for the PostgreSQL foundation suite.

Every fixture here fails rather than skips. A skipped isolation suite reports the same
green as a passing one, which is the failure mode this repository's evidence rules exist
to prevent -- so an absent ``FIRMBATCH_TEST_DATABASE_URL``, an unreachable server, an
environment that is not ``test``, a server that is not PostgreSQL 16, and a cluster with
no disposable-cluster marker all stop the run with an explanatory error.

Run it the way everything else in this repository runs, from the PARENT directory:

    cd "$(git rev-parse --show-toplevel)/.."
    FIRMBATCH_ENV=test FIRMBATCH_TEST_DATABASE_URL=... \\
      python3 -m pytest firmbatch/control_plane/tests

The server must first be attested as disposable, once per cluster:

    FIRMBATCH_ENV=test FIRMBATCH_TEST_DATABASE_URL=... \\
      python3 -m firmbatch.control_plane.testing.attestation --mark
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import create_engine, text

from firmbatch.control_plane import config, migrate
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.repositories import TenantRepository
from firmbatch.control_plane.testing import bootstrap as bootstrap_version
from firmbatch.control_plane.testing.bootstrap import create_disposable_database, drop_disposable_database

#: The suite asserts PostgreSQL 16 behaviour -- FORCE ROW LEVEL SECURITY, the SET/ADMIN
#: split on role membership, ``pg_has_role(..., 'SET')``, ``pg_control_system()`` readable
#: by a non-superuser, the PG15+ public-schema defaults. Running it against another major
#: version would report a green that says nothing about the server the product targets.
#:
#: **The authoritative check is the bootstrap preflight**
#: (``bootstrap.require_supported_server_version``), which runs before anything is created.
#: This constant and the fixture below are secondary evidence: they say the version out
#: loud in the suite that depends on it, and they are re-exported from the bootstrap so the
#: two cannot drift apart.
REQUIRED_SERVER_VERSION_MAJOR = bootstrap_version.REQUIRED_SERVER_VERSION_MAJOR


def drop_disposable_objects(
    environment, *, database: str | None, owner_role: str, role_names: "tuple[str, ...]"
) -> None:
    """Remove a disposable database and its roles, as the owner. For tests only.

    Tests that deliberately break the bootstrap or the teardown still have to leave the
    cluster clean, and they can no longer do it the easy way: since the per-run owner
    became the sole deletion authority, the shared admin gets "must be owner of database"
    for the ``DROP``, and ``DROP DATABASE ... WITH (FORCE)`` is not available to it either.
    That refusal is the property under test in half this suite, so it is not something to
    work around -- this helper takes the same route the product code takes, by acting as
    the owner.

    It does need to re-acquire ``SET`` first, which the bootstrap deliberately gave up.
    That is possible only because this admin holds ``ADMIN OPTION`` on the role it created,
    and it is a *deliberate* re-grant by a role-administrator rather than the standing
    reachability finding 5 was about. It says something true about the threat model: the
    per-run owner is protected from a concurrent process, not from the cluster
    administrator who created it. See ADR 0004 section 8e.
    """
    engine = create_engine(
        config.load_test_admin_url(environment), isolation_level="AUTOCOMMIT", future=True
    )
    try:
        with engine.connect() as connection:
            if database:
                connection.execute(
                    text(
                        f'GRANT "{owner_role}" TO CURRENT_USER '
                        "WITH SET TRUE, INHERIT FALSE, ADMIN FALSE"
                    )
                )
                connection.execute(text(f'SET ROLE "{owner_role}"'))
                connection.execute(text(f'DROP DATABASE IF EXISTS "{database}"'))
                connection.execute(text("RESET ROLE"))
                connection.execute(
                    text(f'REVOKE SET OPTION FOR "{owner_role}" FROM CURRENT_USER')
                )
            for role in role_names:
                connection.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
    finally:
        engine.dispose()


def drop_handle_objects(environment, handle) -> None:
    """:func:`drop_disposable_objects` for a full bootstrap handle."""
    drop_disposable_objects(
        environment,
        database=handle.database,
        owner_role=handle.owner_role,
        role_names=(handle.application_role, handle.provisioning_role, handle.owner_role),
    )


@pytest.fixture(scope="session")
def environment() -> dict[str, str]:
    """The process environment, checked. Fails loudly on anything but ``test``."""
    if config.load_environment(os.environ) is not config.Environment.TEST:
        raise RuntimeError(f"{config.ENVIRONMENT_VAR} must be 'test' to run this suite")
    return dict(os.environ)


@pytest.fixture(scope="session")
def disposable_database(environment):
    """One throwaway database per session: created, migrated, dropped."""
    handle = create_disposable_database(environment)
    try:
        yield handle
    finally:
        drop_disposable_database(handle)


@pytest.fixture(scope="session", autouse=True)
def require_postgresql_16(environment):
    """Secondary evidence, on its own connection, before anything is provisioned.

    It depends on ``environment`` rather than on ``disposable_database`` deliberately. The
    old version read the fingerprint of an already-created database, which meant the suite
    provisioned first and complained afterwards -- on PostgreSQL 15 or 17 it left a database
    and three roles behind before saying the server was unsupported.

    The authoritative check now lives in the bootstrap preflight and runs before any CREATE.
    This one is kept because an autouse session fixture states the requirement in the suite
    that depends on it, and it costs one short read-only connection.
    """
    engine = create_engine(
        config.load_test_admin_url(environment), isolation_level="AUTOCOMMIT", future=True
    )
    try:
        with engine.connect() as connection:
            version_num = int(connection.execute(text("SHOW server_version_num")).scalar())
    finally:
        engine.dispose()
    return bootstrap_version.require_supported_server_version(version_num)


@pytest.fixture(scope="session")
def application_engine(disposable_database):
    """The restricted, tenant-scoped application role."""
    engine = db_engine.create_application_engine(disposable_database.application_url)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture(scope="session")
def provisioning_engine(disposable_database):
    """The privileged tenant-provisioning role. Still non-owner and NOBYPASSRLS."""
    engine = db_engine.create_application_engine(disposable_database.provisioning_url, pool_size=2)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture()
def admin_engine(environment):
    """The cluster admin, in AUTOCOMMIT, for role administration.

    Role creation and membership grants are admin actions. The per-run owner role is
    deliberately ``NOCREATEROLE``, so a test that needs to create a probe role has to say
    so explicitly by taking this fixture rather than borrowing the migration connection.
    """
    engine = create_engine(
        config.load_test_admin_url(environment), isolation_level="AUTOCOMMIT", future=True
    )
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture(scope="session")
def owner_engine(disposable_database):
    """The migration/owner connection. Used only to inspect catalogue state."""
    engine = migrate.create_migration_engine(disposable_database.migration_url)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture()
def single_connection_engine(disposable_database):
    """An application engine with a pool of exactly one.

    Reusing one physical connection is the only way to prove that tenant context does not
    survive from one transaction into the next; with a larger pool a passing test could
    just be a different connection.
    """
    engine = db_engine.create_application_engine(disposable_database.application_url, pool_size=1, max_overflow=0)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture()
def raw_application_connection(disposable_database):
    """A plain autocommit connection as the application role, for privilege probes.

    Built through ``create_application_engine`` so it carries the same connect-time
    hardening as production -- pinned ``search_path``, cleared tenant setting, verified
    principal. A probe against an unhardened connection would be testing something the
    application never does.

    Each probe gets its own engine so a deliberately failed statement cannot poison a
    shared transaction.
    """
    engine = db_engine.create_application_engine(disposable_database.application_url, pool_size=1, max_overflow=0)
    engine = engine.execution_options(isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as connection:
            yield connection
    finally:
        engine.dispose()


def _new_tenant(provisioning_engine, label: str) -> uuid.UUID:
    suffix = uuid.uuid4().hex[:10]
    with db_engine.transaction(provisioning_engine) as session:
        tenant = TenantRepository(session).create(slug=f"{label}-{suffix}", name=f"Tenant {label} {suffix}")
        return tenant.id


@pytest.fixture()
def tenant_a(provisioning_engine) -> uuid.UUID:
    return _new_tenant(provisioning_engine, "alpha")


@pytest.fixture()
def tenant_b(provisioning_engine) -> uuid.UUID:
    return _new_tenant(provisioning_engine, "beta")


@pytest.fixture()
def server_version(owner_engine) -> int:
    with owner_engine.connect() as connection:
        return int(connection.execute(text("SHOW server_version_num")).scalar())
