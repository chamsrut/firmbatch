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
from contextlib import contextmanager
from dataclasses import dataclass

import pytest
from sqlalchemy import create_engine, text

from firmbatch.control_plane import config, migrate
from firmbatch.control_plane.db import auth
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.lifecycle import (
    LifecycleDefinition,
    create_lifecycle_instance,
    register_lifecycle_definition,
)
from firmbatch.control_plane.db.repositories import TenantRepository
from firmbatch.control_plane.security.authorization import Scope
from firmbatch.control_plane.security.secrets import Secret
from firmbatch.control_plane.testing import bootstrap as bootstrap_version
from firmbatch.control_plane.testing.bootstrap import create_disposable_database, drop_disposable_database

#: The suite asserts PostgreSQL 16 behaviour -- FORCE ROW LEVEL SECURITY, the SET/ADMIN
#: split on role membership, the ``pg_auth_members`` option columns, ``pg_control_system()``
#: readable by a non-superuser, the PG15+ public-schema defaults. Running it against another major
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
    became the sole deletion authority, a non-superuser admin gets "must be owner of
    database" for the ``DROP``, and ``DROP DATABASE ... WITH (FORCE)`` is not available to
    it either. That refusal is the property under test in half this suite, so it is not
    something to work around -- this helper takes the same route the product code takes, by
    acting as the owner.

    It re-acquires ``SET`` first, which the bootstrap deliberately gave up. That is a
    *deliberate* re-grant by the trusted bootstrap administrator -- through the ``ADMIN
    OPTION`` it holds on the role it created, or by superuser authority in CI -- and not the
    accidental standing grant finding 5 was about. It says something true about the threat
    model rather than working around it: the per-run owner is protected from a concurrent
    process, not from the administrator that created it. That reach is accepted inside an
    attested disposable cluster; see ADR 0004 section 8f.
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
        role_names=(
            handle.application_role,
            handle.provisioning_role,
            handle.owner_role,
            handle.lifecycle_writer_role,
            handle.authenticator_role,
        ),
    )


@contextmanager
def acting_as_lifecycle_writer(disposable_database, *, bind_as=None):
    """One owner connection running as the lifecycle writer, by the trusted administrator's hand.

    **This is the accepted limitation, exercised deliberately, and it is the only way any
    test reaches the writer's identity.** Nobody can ``SET ROLE`` to the writer -- the
    application, provisioning and owner roles are all refused, and that refusal is asserted
    by name elsewhere. What can happen is what happens here: the bootstrap administrator,
    which holds ``ADMIN OPTION`` on every role it created (or is a superuser, in CI), grants
    the owner a ``SET``-only membership for the duration of the block and takes it back
    afterwards, and a fresh connection then confirms nothing of it survived. That reach is
    the one ADR 0004 section 8f accepts.

    Tests use it for two things: to write rows that only the writer can write -- a tagged
    claim with no provenance, provenance pointing at the wrong transition -- so that the
    replay's chain verification can be exercised on rows the guards would otherwise make
    unconstructible; and to prove that the guards pass **for the writer** and for nobody
    else, which a refusal-only test could not distinguish from a guard that refuses always.

    ``bind_as`` binds the tenant's authenticated context on the connection **before** the
    ``SET ROLE``, as the owner, because ``bind_authenticated_context`` is not among the
    functions the writer may execute. The context is per backend and per transaction, so
    it survives the change of role.
    """
    from firmbatch.control_plane.testing.bootstrap import temporary_set_membership

    owner = migrate.create_migration_engine(disposable_database.migration_url)
    try:
        with temporary_set_membership(
            disposable_database.admin_url,
            role=disposable_database.lifecycle_writer_role,
            member=disposable_database.owner_role,
        ):
            with owner.connect() as connection:
                if bind_as is not None:
                    connection.execute(
                        text("SELECT firmbatch.bind_authenticated_context(:c)"),
                        {"c": bind_as.credential.reveal()},
                    )
                connection.execute(
                    text(f'SET ROLE "{disposable_database.lifecycle_writer_role}"')
                )
                try:
                    yield connection
                finally:
                    # A refused statement leaves the transaction aborted, and RESET ROLE
                    # is refused inside an aborted transaction; clear it first. SET ROLE
                    # is session-level, so the reset is still needed after the rollback.
                    connection.rollback()
                    connection.execute(text("RESET ROLE"))
    finally:
        owner.dispose()


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


@pytest.fixture(scope="session", autouse=True)
def authenticator_engine(disposable_database):
    """The trusted-issuer (authenticator) role (Milestone 3.1 security correction).

    A restricted, non-owner engine holding the pre-authentication identity functions --
    login, session opening, recovery -- which the application role no longer holds. Autouse
    and session-scoped so it is always registered for the identity helpers, which look it up
    by database and therefore need no change at their call sites. It goes through
    ``create_application_engine``, whose principal check refuses it if it is anything but a
    restricted role, exactly as for the application engine.
    """
    from firmbatch.control_plane.tests import identity_helpers

    engine = db_engine.create_application_engine(disposable_database.authenticator_url)
    identity_helpers.register_authenticator_engine(engine)
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


#: What a fixture credential carries unless a test asks for something narrower. Every
#: customer capability the Milestone 2.3 catalogue defines, and deliberately **not**
#: ``tenant:provision``: creating a tenant is not a customer capability, and a fixture that
#: handed one out by default would make every scope test weaker than it looks.
DEFAULT_SCOPES: tuple[Scope, ...] = (
    Scope.TENANT_READ,
    Scope.WORKSPACE_READ,
    Scope.WORKSPACE_WRITE,
    Scope.MUTATION_EXECUTE,
    Scope.AUDIT_READ,
    Scope.CREDENTIAL_MANAGE,
)


@dataclass(frozen=True)
class TenantPrincipal:
    """One tenant, one principal, and the credential that authenticates as it.

    The three arrive together because they have to: a tenant has no credential until it
    exists, and ``firmbatch.register_auth_binding`` derives the tenant from the current
    context -- so the first credential for a tenant is minted inside the same provisioning
    transaction that created it. That is the shape Milestone 3's signup flow will have,
    and the fixture is not allowed to cheat around it.
    """

    id: uuid.UUID
    principal_id: uuid.UUID
    binding_id: uuid.UUID
    credential: Secret
    scopes: tuple[str, ...]


def _new_principal(provisioning_engine, label: str, scopes=DEFAULT_SCOPES) -> TenantPrincipal:
    suffix = uuid.uuid4().hex[:10]
    principal_id = uuid.uuid4()
    with auth.provisioning_transaction(provisioning_engine) as session:
        tenant = TenantRepository(session).create(slug=f"{label}-{suffix}", name=f"Tenant {label} {suffix}")
        issued = auth.register_auth_binding(session, principal_id=principal_id, scopes=scopes)
        return TenantPrincipal(
            id=tenant.id,
            principal_id=principal_id,
            binding_id=issued.binding_id,
            credential=issued.credential,
            scopes=issued.scopes,
        )


@pytest.fixture()
def principal_a(provisioning_engine) -> TenantPrincipal:
    return _new_principal(provisioning_engine, "alpha")


@pytest.fixture()
def principal_b(provisioning_engine) -> TenantPrincipal:
    return _new_principal(provisioning_engine, "beta")


@pytest.fixture()
def tenant_a(principal_a) -> uuid.UUID:
    """The tenant id alone, for the assertions that only need to name a tenant."""
    return principal_a.id


@pytest.fixture()
def tenant_b(principal_b) -> uuid.UUID:
    return principal_b.id


@pytest.fixture()
def new_principal(provisioning_engine):
    """Make another tenant with a credential carrying exactly the scopes asked for."""

    def _make(label: str = "gamma", scopes=DEFAULT_SCOPES) -> TenantPrincipal:
        return _new_principal(provisioning_engine, label, scopes)

    return _make


@pytest.fixture()
def issue_credential(application_engine):
    """Mint a second credential **inside an existing tenant**, as that tenant.

    Goes through the ordinary authenticated path rather than through provisioning, because
    that is the path Milestone 3 will use and the one worth exercising: the issuing
    credential must itself hold ``credential:manage``, and the new binding lands in the
    issuer's tenant because the database derives it from the context.
    """

    def _issue(principal: TenantPrincipal, scopes, *, expires_at=None, principal_id=None):
        with auth.authenticated_transaction(application_engine, principal.credential) as session:
            issued = auth.register_auth_binding(
                session,
                principal_id=principal_id or uuid.uuid4(),
                scopes=scopes,
                expires_at=expires_at,
            )
            return TenantPrincipal(
                id=principal.id,
                principal_id=issued.principal_id,
                binding_id=issued.binding_id,
                credential=issued.credential,
                scopes=issued.scopes,
            )

    return _issue


# ------------------------------------------------------- Milestone 2.4 lifecycle machines
#
# **These are test-only definitions and they are deliberately not product machines.**
#
# Migration 0004 registers no machine at all: the job lifecycle of target architecture
# section 5.1 and the window-offer machine of section 12.1 belong to Milestones 5 and 6,
# alongside the domain tables they describe, and seeding a graph ahead of those rows would
# be a product decision taken by a foundation. So the suite installs its own, into the
# disposable database it created, through the trusted owner -- the only identity that can
# register one -- and ``test_lifecycle_definitions.py`` asserts that a *fresh* database
# carries none.
#
# The names all begin with ``test_`` so that a definition leaking into a real environment
# would be obvious rather than plausible. The scopes are existing customer capabilities
# from the closed catalogue; there is no ``lifecycle:*`` scope and Milestone 2.4 adds none.

#: The general-purpose machine. Its graph is chosen to exercise the properties a kernel has
#: to get right rather than to model anything: a **cycle** (active <-> paused), two distinct
#: terminal states, a state reachable two ways, and an edge out of the initial state
#: straight to a terminal one.
TEST_WORKFLOW = LifecycleDefinition(
    machine_key="test_workflow",
    version=1,
    initial_state="draft",
    states=("draft", "active", "paused", "closed", "cancelled"),
    terminal_states=("closed", "cancelled"),
    transitions=(
        ("draft", "active"),
        ("draft", "cancelled"),
        ("active", "paused"),
        ("paused", "active"),
        ("active", "closed"),
        ("active", "cancelled"),
    ),
    read_scope=Scope.WORKSPACE_READ.value,
    create_scope=Scope.WORKSPACE_WRITE.value,
    transition_scope=Scope.WORKSPACE_WRITE.value,
)

#: The same key, a **different version**, with a different graph. A change to a machine is a
#: new version, so this is what that looks like -- and an instance pinned to version 1 is
#: unaffected by it, which is the property version pinning exists for.
TEST_WORKFLOW_V2 = LifecycleDefinition(
    machine_key="test_workflow",
    version=2,
    initial_state="draft",
    states=("draft", "active", "closed"),
    terminal_states=("closed",),
    transitions=(("draft", "active"), ("active", "closed")),
    read_scope=Scope.WORKSPACE_READ.value,
    create_scope=Scope.WORKSPACE_WRITE.value,
    transition_scope=Scope.WORKSPACE_WRITE.value,
)

#: A machine requiring **different capabilities**, so that "the scope comes from the
#: definition" is something a test can observe rather than read. The pairing is arbitrary
#: and says nothing about what audit or credential management mean; what matters is that a
#: credential holding every workspace capability reaches none of this machine.
TEST_RESTRICTED = LifecycleDefinition(
    machine_key="test_restricted",
    version=1,
    initial_state="opened",
    states=("opened", "settled"),
    terminal_states=("settled",),
    transitions=(("opened", "settled"),),
    read_scope=Scope.AUDIT_READ.value,
    create_scope=Scope.CREDENTIAL_MANAGE.value,
    transition_scope=Scope.CREDENTIAL_MANAGE.value,
)

#: A **self-edge**, which is legal. A move that changes only the revision is a real thing to
#: want, and forbidding it would be a graph rule nobody asked for -- as would forbidding the
#: cycle in ``TEST_WORKFLOW``. Both are here so that "this kernel does not assume acyclicity"
#: is a test somebody has to delete on purpose.
TEST_CYCLIC = LifecycleDefinition(
    machine_key="test_cyclic",
    version=1,
    initial_state="idle",
    states=("idle",),
    terminal_states=(),
    transitions=(("idle", "idle"),),
    read_scope=Scope.WORKSPACE_READ.value,
    create_scope=Scope.WORKSPACE_WRITE.value,
    transition_scope=Scope.WORKSPACE_WRITE.value,
)

TEST_LIFECYCLE_DEFINITIONS: tuple[LifecycleDefinition, ...] = (
    TEST_WORKFLOW,
    TEST_WORKFLOW_V2,
    TEST_RESTRICTED,
    TEST_CYCLIC,
)


@pytest.fixture(scope="session")
def lifecycle_definitions(owner_engine) -> dict:
    """Install the test-only machines once, as the owner, into the disposable database.

    Through :func:`register_lifecycle_definition`, which is the supported interface and the
    one a later milestone's migration will use -- not through hand-written inserts, so the
    fixture exercises the registrar rather than working around it.

    Session-scoped and never removed: the definition tables refuse ``DELETE`` for every
    role, including this one, which is exactly the immutability property under test. The
    disposable database is dropped at the end of the session and takes them with it.
    """
    with owner_engine.connect() as connection:
        for definition in TEST_LIFECYCLE_DEFINITIONS:
            register_lifecycle_definition(connection, definition)
        connection.commit()
    return {(d.machine_key, d.version): d for d in TEST_LIFECYCLE_DEFINITIONS}


@pytest.fixture()
def workflow(lifecycle_definitions) -> LifecycleDefinition:
    """The general-purpose test machine, version 1."""
    return lifecycle_definitions[(TEST_WORKFLOW.machine_key, TEST_WORKFLOW.version)]


@pytest.fixture()
def new_instance(application_engine, lifecycle_definitions):
    """Create one lifecycle instance as a principal, and return where it starts."""

    def _create(principal, definition: LifecycleDefinition = TEST_WORKFLOW):
        with auth.authenticated_transaction(application_engine, principal.credential) as session:
            return create_lifecycle_instance(
                session,
                machine_key=definition.machine_key,
                machine_version=definition.version,
            )

    return _create


@pytest.fixture()
def server_version(owner_engine) -> int:
    with owner_engine.connect() as connection:
        return int(connection.execute(text("SHOW server_version_num")).scalar())


def exception_chain(error: BaseException) -> str:
    """Everything reachable from an exception, rendered -- not merely ``str(error)``.

    The one helper behind every "this refusal carries no secret" test in the suite, in one
    place because three copies of it is how one of them quietly stops walking the whole
    graph.

    Why the graph and not the message: ``raise X from None`` sets
    ``__suppress_context__``, which stops a *printed* traceback showing the original. It
    does **not** detach it. Anything that walks the chain still finds the original and
    everything it renders -- and a log aggregator, a crash reporter and pytest's own
    ``--tb=long`` are all exactly such a thing. A failing ``dict[key]`` is the same trap
    from the other direction: the ``KeyError`` carries the key in ``args``, so its ``repr``
    renders it even though its ``str`` is short.

    So: ``repr``, ``str`` and ``args`` of every exception reachable through ``__cause__``
    and ``__context__``, with a visited set because the graph can be cyclic.
    """
    seen: list[str] = []
    stack: list = [error]
    visited: set[int] = set()
    while stack:
        current = stack.pop()
        if current is None or id(current) in visited:
            continue
        visited.add(id(current))
        seen.append(repr(current))
        seen.append(str(current))
        seen.extend(repr(arg) for arg in getattr(current, "args", ()))
        stack.extend([current.__cause__, current.__context__])
    return "\n".join(seen)
