"""Create and destroy a disposable PostgreSQL database for the foundation suite.

The suite tests PostgreSQL semantics -- row-level security, forced policies, role
attributes, referential integrity, transaction-local settings. None of that has a
faithful in-memory substitute, so there is no fake and no fallback: the tests run against
a real server or they fail.

What one call to :func:`create_disposable_database` does, from an admin *maintenance*
connection (``.../postgres``):

1. Refuses to proceed unless ``FIRMBATCH_ENV=test``, the admin URL names a maintenance
   database **and the open connection is actually attached to one**, and the server
   carries the disposable-cluster marker (``attestation.py``).
2. Records the cluster fingerprint -- system identifier, port, database, version -- so
   teardown can prove it is talking to the same server it created on.
3. Creates ``firmbatch_test_<12 random hex>`` plus **three** per-run login roles with
   random passwords -- owner, application, provisioning -- all ``NOSUPERUSER NOCREATEDB
   NOCREATEROLE NOBYPASSRLS NOREPLICATION``, each created in its own transaction and
   recorded with its OID and a random provenance marker.
4. Revokes ``CONNECT`` and ``TEMPORARY`` from ``PUBLIC`` and grants ``CONNECT`` to those
   three roles only.
5. Applies every migration as the owner, after confirming the owner connection is
   attached to the database just created.
6. Grants the application and provisioning roles exactly the privileges in ``db/roles.py``.

Teardown removes all four objects. The one thing it must never remove is the persistent
``firmbatch_disposable_test_cluster`` attestation marker, which is what makes any of this
permissible on a given server; it does not match the disposable-role pattern, so cleanup
cannot reach it.

**Names are not identities.** A database or role can be dropped and recreated under the
same name between creation and teardown, and dropping the replacement would destroy
somebody else's object. Every object is therefore recorded by OID plus a random marker
(a database/role ``COMMENT``) written at creation, and re-checked immediately before any
drop. Verified: teardown used to destroy a same-name replacement.

**Nothing is dropped that this process did not create.** Objects are tracked
individually, and only on success -- a ``CREATE ROLE`` that collided with an existing role
is never recorded as created, so cleanup cannot remove a pre-existing role that merely
shares the name. Normal teardown and failed-setup cleanup go through the *same* validated
path: attestation, cluster fingerprint, maintenance database, name, provenance and object
identity are re-checked either way. If that validation cannot be completed the object is
**leaked deliberately** and reported, rather than dropped on a weaker check.

**The bootstrap administrator is trusted; the roles it creates are not.** This admin is
reachable only through :class:`config.TestBootstrapSettings`, and only against a cluster
that has explicitly attested it is disposable. Inside that boundary its administrative
reach over the per-run owner is **accepted rather than defended against**: CI runs as the
``postgres`` superuser of an ephemeral service container, and a superuser satisfies
``pg_has_role`` for every role in the cluster by definition. Nothing here claims the
bootstrap administrator is isolated from the roles it creates.

What *is* asserted is narrower, catalogue-level, and true of either kind of admin: the
temporary ``SET`` membership taken for one statement is given back, so no explicit
``set_option`` or ``inherit_option`` row survives where PostgreSQL permits revoking it.
The untrusted side of the boundary -- the per-run owner, application and provisioning
roles -- stays separated from the admin's credentials and from each other.

**Generated passwords never reach a log.** They are composed with psycopg's literal
quoting rather than f-string interpolation, and every exception raised out of role
creation is scrubbed of them before it propagates.

**Roles connect over TCP.** A freshly created role cannot authenticate through a unix
socket under the usual ``peer`` line in ``pg_hba.conf``, so the application and
provisioning URLs are built against the server's TCP endpoint even when the admin URL is
a socket.
"""

from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass, field
from typing import Mapping

from sqlalchemy import URL, create_engine, make_url, text

from .. import config
from ..db import roles
from ..db.engine import guard_connection_environment
from ..db.identity import ExpectedIdentity, require_expected_identity, require_live_identity
from ..migrate import upgrade_to_head
from .attestation import ClusterFingerprint, read_fingerprint, require_disposable_cluster

DEFAULT_TCP_HOST = "127.0.0.1"
DEFAULT_PORT = 5432

#: The only PostgreSQL major version this foundation is verified against.
#:
#: Every property the suite asserts is a PostgreSQL property -- forced row-level security,
#: the PG16 split of SET out of ADMIN on role membership, the ``pg_auth_members`` option
#: columns, ``pg_control_system()`` readable by a non-superuser, the PG15+ public-schema
#: defaults.
#: Provisioning against another major version would produce a green that says nothing about
#: the server the product targets, and on 15 or 17 several of them are simply different.
REQUIRED_SERVER_VERSION_MAJOR = 16

#: Handles this process created, mapped to the identity fields they were created with.
#:
#: Two things at once. Presence proves the handle came from create_disposable_database --
#: a hand-built dataclass, a pickled one from an earlier run, or a forgery in a test is
#: not a licence to drop. The recorded fields then prove nothing has been altered since:
#: ``dataclasses.replace`` preserves the token, so a token on its own would authorise a
#: handle whose database name had been swapped for somebody else's.
_PROVISIONED: dict[str, dict[str, str]] = {}


class DisposableDatabaseError(RuntimeError):
    """Raised when a disposable database cannot be created or safely destroyed."""


@dataclass(frozen=True)
class ObjectIdentity:
    """What was created, and enough to recognise it again.

    ``oid`` and ``marker`` together survive a same-name replacement: a recreated database
    or role gets a fresh OID and does not carry the marker this process wrote.
    """

    name: str
    kind: str  # "database" | "role"
    oid: int
    marker: str

    def mismatch(self, other: "ObjectIdentity | None") -> str | None:
        if other is None:
            return f"{self.kind} {self.name!r} no longer exists"
        for attribute in ("name", "kind", "oid", "marker"):
            mine, theirs = getattr(self, attribute), getattr(other, attribute)
            if mine != theirs:
                return (
                    f"{self.kind} {self.name!r} {attribute}: created {mine!r}, found {theirs!r} "
                    "-- the object has been replaced"
                )
        return None


@dataclass(frozen=True)
class DisposableDatabase:
    """Handle to one throwaway database and the three URLs that reach it.

    Frozen, and carrying a bootstrap-generated ``token``, the cluster fingerprint observed
    at creation, and the identity of every object created. Teardown validates all of them:
    the fields are evidence about specific objects on a specific server at a specific
    moment, not merely a set of names to interpolate.
    """

    database: str
    admin_url: str
    #: Owner connection. Runs migrations; not used by application-level tests.
    migration_url: str
    #: Restricted, tenant-scoped application role. Non-owner, NOBYPASSRLS.
    application_url: str
    #: Privileged tenant provisioning. Also non-owner and NOBYPASSRLS.
    provisioning_url: str
    application_role: str
    provisioning_role: str
    #: The per-run database owner. It is the migration principal AND the deletion
    #: authority: the final DROP DATABASE runs as this role, so PostgreSQL checks
    #: ownership of whatever object is present at that instant.
    owner_role: str
    head_revision: str
    fingerprint: ClusterFingerprint
    #: The TCP endpoint the runtime roles were built against, recorded at creation.
    #: Checked at teardown instead of ``inet_server_port()``, which is NULL for a unix
    #: socket connection and would let an endpoint mismatch through unnoticed.
    endpoint: tuple[str, int]
    #: Every object this process created, by kind. Only successful creations appear.
    created: tuple[ObjectIdentity, ...]
    #: The owner role connected to the *maintenance* database. The final DROP DATABASE is
    #: issued over this, so the permission check binds to the recorded owner identity
    #: rather than to ambient cluster-admin authority.
    owner_maintenance_url: str = ""
    token: str = field(default_factory=lambda: secrets.token_hex(16))

    def __repr__(self) -> str:  # pragma: no cover - exercised through str()
        return (
            f"DisposableDatabase(database={self.database!r}, "
            f"application_url={config.redact_database_url(self.application_url)!r}, "
            f"migration_url={config.redact_database_url(self.migration_url)!r}, "
            f"head_revision={self.head_revision!r})"
        )

    __str__ = __repr__


def _identity_fields(handle: DisposableDatabase) -> dict[str, str]:
    """The fields that decide what gets dropped. Any change to one invalidates the handle."""
    return {
        "database": handle.database,
        "admin_url": handle.admin_url,
        "migration_url": handle.migration_url,
        "application_url": handle.application_url,
        "provisioning_url": handle.provisioning_url,
        "application_role": handle.application_role,
        "provisioning_role": handle.provisioning_role,
        "owner_role": handle.owner_role,
        "owner_maintenance_url": handle.owner_maintenance_url,
        "endpoint": repr(handle.endpoint),
        "fingerprint": repr(handle.fingerprint),
        "created": repr(handle.created),
    }


# --------------------------------------------------------------------------- URL helpers


def _swap_database(url: str, database: str) -> str:
    """Point a validated URL at another database, leaving no routing override behind.

    ``require_postgresql_url`` already refuses ``dbname``/``host``/``port``/``user`` and
    the rest, so a validated URL cannot carry one. Stripping them again here is cheap and
    means this helper is still correct if it is ever handed a URL from somewhere else.
    """
    parsed = make_url(url)
    query = {
        key: value
        for key, value in parsed.query.items()
        if key.lower() not in config._ROUTING_OVERRIDE_REASONS
    }
    return parsed.set(database=database, query=query).render_as_string(hide_password=False)


def _endpoint(url: str) -> tuple[str | None, int | None]:
    parsed = make_url(url)
    return parsed.host, parsed.port


def _tcp_endpoint(admin_url: str, connection) -> tuple[str, int]:
    """The host and port a freshly created role can actually log in through.

    A URL whose host is absent or a filesystem path is a unix-socket connection; created
    roles fail ``peer`` authentication there, so fall back to loopback and ask the server
    which port it is listening on rather than guessing 5432.
    """
    url = make_url(admin_url)
    if url.host and not url.host.startswith("/"):
        return url.host, url.port or DEFAULT_PORT
    port = connection.execute(text("SHOW port")).scalar()
    return DEFAULT_TCP_HOST, int(port or DEFAULT_PORT)


def _role_url(role: str, password: str, host: str, port: int, database: str) -> str:
    return URL.create(
        config.DRIVER, username=role, password=password, host=host, port=port, database=database
    ).render_as_string(hide_password=False)


def _admin_engine(admin_url: str):
    """AUTOCOMMIT: for CREATE DATABASE and DROP DATABASE, which cannot run in a transaction."""
    return guard_connection_environment(
        create_engine(admin_url, isolation_level="AUTOCOMMIT", poolclass=None, future=True)
    )


def _transactional_engine(url: str):
    """A real transaction, for the sequences that must be all-or-nothing.

    ``CREATE ROLE`` *is* transactional in PostgreSQL, and so are ``COMMENT`` and the
    catalogue read that follows it. Running them on the AUTOCOMMIT engine made each an
    independent commit, so a failure between them left a role behind that no cleanup list
    knew about. The role rename-and-drop at teardown needs the same property for the same
    reason.
    """
    return guard_connection_environment(create_engine(url, poolclass=None, future=True))


def require_supported_server_version(server_version_num: int) -> int:
    """The version preflight. Read-only, and it runs before anything is created.

    Placed here rather than in a pytest fixture because the fixture depended on an
    already-provisioned disposable database: on PostgreSQL 15 or 17 the suite created a
    database and three roles, *then* announced the version was wrong. The check that
    decides whether to provision cannot be downstream of provisioning.

    ``server_version_num`` rather than ``version()``: it is an integer the server computes,
    so 16.1 and 16.15 both give major 16 and no string parsing can disagree about it. Patch
    releases are accepted; 15 and 17 are refused.
    """
    major = server_version_num // 10000
    if major != REQUIRED_SERVER_VERSION_MAJOR:
        raise DisposableDatabaseError(
            f"this foundation requires PostgreSQL {REQUIRED_SERVER_VERSION_MAJOR}; the server "
            f"reports server_version_num={server_version_num} (major {major}). Nothing has been "
            f"created. Point {config.TEST_ADMIN_URL_VAR} at a PostgreSQL "
            f"{REQUIRED_SERVER_VERSION_MAJOR} server -- every property this suite asserts is a "
            "PostgreSQL 16 property, and a pass on another major version would say nothing about "
            "the server the product targets."
        )
    return server_version_num


def _require_live_database(connection, expected: str, *, context: str) -> None:
    """Confirm the open connection is attached to the database we think it is.

    The URL is not the last word: libpq takes ``dbname`` from the query string in
    preference to the path, so a URL reading ``/postgres?dbname=customer_prod`` validates
    as ``postgres`` and connects to ``customer_prod``. ``parse_connection_url`` now
    refuses that shape, and this asks the server to confirm it independently.
    """
    live = connection.execute(text("SELECT current_database()")).scalar()
    if live != expected:
        raise DisposableDatabaseError(
            f"{context}: the connection is attached to database {live!r}, not {expected!r}. "
            "Refusing to continue against a database other than the one that was validated."
        )


def validate_migration_connection(
    connection,
    *,
    database: str,
    fingerprint: ClusterFingerprint,
    endpoint: tuple[str, int],
    expected_user: str,
    context: str,
) -> ExpectedIdentity:
    """Everything that must be true of the EXACT connection about to run DDL.

    Name-only validation is not enough, and neither is validating a *different*
    connection built from the same URL a moment earlier: DNS, a failover endpoint, or a
    load balancer can put the second connection on another cluster. This runs on the
    connection Alembic is handed, immediately before its first statement, and again
    immediately before the grants.

    Four independent facts: the database, the cluster, the endpoint, and the principal.
    All four go through ``db/identity.py``, which is the same canonical validator the
    production migration entry point uses -- the disposable suite does not get a second,
    friendlier implementation. The cluster fingerprint comparison on top of it is what only
    a disposable database can offer, because only here was a fingerprint recorded at
    creation.

    Returns the :class:`ExpectedIdentity` that Alembic is handed, so the value the
    migration is authorised with is the one this function just proved.
    """
    try:
        live = require_live_identity(
            connection,
            database=database,
            expected_user=expected_user,
            endpoint=endpoint,
            context=context,
        )
    except Exception as exc:
        raise DisposableDatabaseError(str(exc)) from None

    observed = read_fingerprint(connection)
    mismatch = fingerprint.mismatch(observed)
    if mismatch:
        raise DisposableDatabaseError(
            f"{context}: this connection is not the cluster the database was created on ({mismatch})."
        )

    expected = ExpectedIdentity(
        database=database,
        system_identifier=live.system_identifier,
        endpoint=endpoint,
        expected_user=expected_user,
    )
    try:
        require_expected_identity(connection, expected, context=context)
    except Exception as exc:
        raise DisposableDatabaseError(str(exc)) from None
    return expected


# --------------------------------------------------------------------------- provenance


def _read_database_identity(connection, name: str, marker: str | None = None) -> ObjectIdentity | None:
    row = connection.execute(
        text(
            "SELECT d.oid, coalesce(pg_catalog.shobj_description(d.oid, 'pg_database'), '') "
            "FROM pg_catalog.pg_database d WHERE d.datname = :n"
        ),
        {"n": name},
    ).one_or_none()
    if row is None:
        return None
    return ObjectIdentity(name=name, kind="database", oid=int(row[0]), marker=marker if marker is not None else row[1])


def _read_role_identity(connection, name: str, marker: str | None = None) -> ObjectIdentity | None:
    row = connection.execute(
        text(
            "SELECT r.oid, coalesce(pg_catalog.shobj_description(r.oid, 'pg_authid'), '') "
            "FROM pg_catalog.pg_roles r WHERE r.rolname = :n"
        ),
        {"n": name},
    ).one_or_none()
    if row is None:
        return None
    return ObjectIdentity(name=name, kind="role", oid=int(row[0]), marker=marker if marker is not None else row[1])


def _read_identity(connection, recorded: ObjectIdentity) -> ObjectIdentity | None:
    reader = _read_database_identity if recorded.kind == "database" else _read_role_identity
    return reader(connection, recorded.name)


def _comment_on(connection, kind: str, name: str, marker: str) -> None:
    """Write the provenance marker. ``COMMENT ON`` takes no bind parameters.

    Composed with psycopg literal quoting rather than interpolated, for the same reason
    the password is: the value never becomes part of a hand-built SQL string.
    """
    from psycopg import sql

    statement = sql.SQL("COMMENT ON {kind} {name} IS {marker}").format(
        kind=sql.SQL(kind.upper()),
        name=sql.Identifier(name),
        marker=sql.Literal(marker),
    )
    with connection.connection.driver_connection.cursor() as cursor:
        cursor.execute(statement)


def _role_exists(connection, name: str) -> bool:
    return bool(
        connection.execute(text("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = :n"), {"n": name}).scalar()
    )


def _database_exists(connection, name: str) -> bool:
    return bool(
        connection.execute(text("SELECT 1 FROM pg_catalog.pg_database WHERE datname = :n"), {"n": name}).scalar()
    )


def _create_login_role(engine, role: str, password: str, marker: str, record) -> ObjectIdentity:
    """Create one role: ``CREATE ROLE``, the provenance ``COMMENT``, and the identity read,
    as a single transaction.

    ``CREATE ROLE`` is transactional in PostgreSQL, so the three statements either all take
    effect or none do. Run on the AUTOCOMMIT admin connection they were three independent
    commits, and a failure at the second or third left a real role behind that no cleanup
    list had ever heard of -- an unrecorded object is one that is never dropped, because
    this module refuses to drop anything it cannot prove it created. PostgreSQL's own
    rollback removes it instead, which is both simpler and stronger than any compensating
    delete could be.

    **``record`` is called before the commit, deliberately.** The alternative -- recording
    after -- has a window in which the role is committed and unrecorded, which is exactly
    the leak this is closing. Recording first has the opposite failure mode: if the
    transaction rolls back, cleanup is left holding an identity for a role that never
    existed, and ``_drop_role_atomically`` returns cleanly when it finds nothing. One
    direction leaks a real object; the other is a no-op. This takes the no-op.

    Refuses outright if the role already exists: a pre-existing role is somebody else's,
    and recording it as created would put it on the cleanup list.
    """
    from psycopg import sql

    statement = sql.SQL(
        "CREATE ROLE {role} LOGIN PASSWORD {password} "
        "NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION NOINHERIT"
    ).format(role=sql.Identifier(role), password=sql.Literal(password))

    try:
        with engine.connect() as connection:
            with connection.begin():
                if _role_exists(connection, role):
                    raise DisposableDatabaseError(
                        f"role {role!r} already exists. It was not created by this process and must "
                        "not be adopted or removed; aborting rather than touching it."
                    )
                with connection.connection.driver_connection.cursor() as cursor:
                    cursor.execute(statement)
                _comment_on(connection, "role", role, marker)
                identity = _read_role_identity(connection, role, marker=marker)
                if identity is None:  # pragma: no cover - CREATE ROLE silently did nothing
                    raise DisposableDatabaseError(
                        f"role {role!r} is absent immediately after being created"
                    )
                record(identity)
            # committed here; anything that raised above took the role with it
    except DisposableDatabaseError:
        raise
    except Exception as exc:
        raise DisposableDatabaseError(
            f"could not create test role {role!r}: "
            f"{type(exc).__name__}: {config.scrub_secrets(str(exc), (password,))}"
        ) from None
    return identity


# ------------------------------------------- giving back the temporary owner membership


#: Every membership row naming ``role``, whoever granted it. Read straight out of
#: ``pg_auth_members`` rather than inferred, because the inference was wrong twice:
#: ``pg_has_role(..., 'MEMBER')`` stays true for an ADMIN-only grant, and a plain
#: ``REVOKE`` silently leaves rows it was not entitled to remove.
#:
#: The catalogue is also the *only* question worth asking here. ``pg_has_role`` answers
#: "may this role reach that one", which for the trusted bootstrap administrator is a
#: property of its cluster authority -- a superuser satisfies it unconditionally -- and not
#: something this module grants, revokes or can assert anything about.
_MEMBERSHIP_ROWS_SQL = """
SELECT m.grantor::regrole::text, m.member::regrole::text,
       m.admin_option, m.inherit_option, m.set_option
FROM pg_catalog.pg_auth_members m
JOIN pg_catalog.pg_roles r ON r.oid = m.roleid
WHERE r.rolname = %(role)s
ORDER BY 1, 2
"""

#: Every role reachable from ``current_user`` by following membership grants, and whether
#: the path carries SET or INHERIT. Deliberately a walk over stored grants rather than
#: ``pg_has_role``: it names the path an operator would have to revoke, and it answers only
#: about grants -- ``pg_has_role`` folds in superuser authority, which no revoke can change.
_REACHABLE_PATH_SQL = """
WITH RECURSIVE reachable(oid, path, can_set, inherits) AS (
    SELECT r.oid, ARRAY[r.rolname]::text[], true, true
    FROM pg_catalog.pg_roles r WHERE r.rolname = current_user
  UNION ALL
    SELECT g.oid,
           reachable.path || g.rolname,
           reachable.can_set AND m.set_option,
           reachable.inherits AND m.inherit_option
    FROM reachable
    JOIN pg_catalog.pg_auth_members m ON m.member = reachable.oid
    JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
    WHERE NOT g.rolname = ANY(reachable.path)
)
SELECT path, can_set, inherits
FROM reachable
WHERE path[array_length(path, 1)] = %(role)s AND array_length(path, 1) > 1
"""


def _membership_rows(connection, role: str) -> list[tuple]:
    """Direct ``pg_auth_members`` rows for ``role``, as the catalogue actually holds them."""
    with connection.connection.driver_connection.cursor() as cursor:
        cursor.execute(_MEMBERSHIP_ROWS_SQL, {"role": role})
        return list(cursor.fetchall())


def _reachable_paths(connection, role: str) -> list[tuple]:
    """Membership paths from the connected role to ``role``, with their carried options."""
    with connection.connection.driver_connection.cursor() as cursor:
        cursor.execute(_REACHABLE_PATH_SQL, {"role": role})
        return list(cursor.fetchall())


def _grant_set_option(connection, role: str) -> None:
    """Give the admin the ability to ``SET ROLE`` to ``role``, for one statement.

    PostgreSQL 16 splits ``SET`` out of ``ADMIN`` on role membership: a ``CREATEROLE``
    creator is granted ``ADMIN`` over the roles it creates but not ``SET``, and
    ``CREATE DATABASE ... OWNER`` requires being able to ``SET ROLE`` to the new owner.
    This is the narrowest thing that makes handing ownership over possible for a
    non-superuser admin.
    """
    connection.execute(
        text(
            f"GRANT {roles.quote_identifier(role)} TO CURRENT_USER "
            "WITH SET TRUE, INHERIT FALSE, ADMIN FALSE"
        )
    )


def _revoke_owner_membership(connection, role: str) -> None:
    """Give back every option the temporary grant took. Called from a ``finally``.

    Two statements, and the second one is where PostgreSQL stops being cooperative.

    ``REVOKE SET OPTION FOR`` removes what the bootstrap itself granted, and that works:
    the grantor of that row is the admin, so the admin may revoke it. Together with the
    ``INHERIT FALSE, ADMIN FALSE`` on the grant, what is left of *our* row carries nothing.
    (Granted without those options, the revoke leaves an *inheriting* grant behind and the
    admin holds the owner's privileges without being able to name them. Verified both ways
    round.)

    The plain ``REVOKE`` that follows is aimed at the **creator's row**, and it is a no-op.
    It is issued anyway, and deliberately: on a server where it ever becomes effective, the
    stronger outcome happens automatically. Today PostgreSQL 16 answers with

        WARNING: role "admin" has not been granted membership in role "owner" by role "admin"

    because a ``CREATEROLE`` role that creates a role receives a membership row whose
    *grantor is the bootstrap superuser*. A non-superuser cannot revoke it:
    ``REVOKE ... GRANTED BY postgres`` is refused outright with "Only roles with privileges
    of role postgres may revoke privileges granted by this role", and
    ``REVOKE ADMIN OPTION FOR`` hits the same warning. All three verified against a real
    PostgreSQL 16 server. (A superuser bootstrap administrator receives no creator row at
    all, so for it the first two statements simply remove what this function granted.)

    **What this is not.** Giving the temporary options back does not make the bootstrap
    administrator unable to reach the owner, and nothing here pretends otherwise. A
    non-superuser creator keeps ``ADMIN OPTION`` on a row nothing in this process may
    remove, so it may re-grant itself ``SET`` whenever it likes; a superuser needs no row
    at all. That reach is *accepted* -- the administrator is trusted, and is confined to an
    attested disposable cluster and to ``TestBootstrapSettings``. See ADR 0004 section 8f.

    The ADMIN row is also not something to fight: it is what lets a non-superuser admin
    ``DROP ROLE`` the per-run roles at teardown. Removing it, if that were possible, would
    trade an accepted property for a guaranteed leak.
    """
    quoted = roles.quote_identifier(role)
    connection.execute(text(f"REVOKE SET OPTION FOR {quoted} FROM CURRENT_USER"))
    connection.execute(text(f"REVOKE INHERIT OPTION FOR {quoted} FROM CURRENT_USER"))
    # Aimed at the creator row. A no-op on PostgreSQL 16 (see above); harmless, and correct
    # on any server that would honour it.
    connection.execute(text(f"REVOKE {quoted} FROM CURRENT_USER"))


def _require_temporary_membership_released(admin_url: str, role: str) -> None:
    """Prove, on a **new** connection, that the one-statement grant was actually given back.

    A new connection because role membership is resolved per session: checking on the
    session that just did the revoke could be answered from state that a fresh login would
    not have.

    Two readings, both straight out of the catalogue:

    1. Every direct ``pg_auth_members`` row naming ``role``. None may carry ``set_option``
       or ``inherit_option``. A plain ``REVOKE`` once looked like it worked and left the row
       untouched, so the inferred answer and the stored one disagreed -- the stored one is
       the fact.
    2. A recursive walk of membership paths, so an *indirect* route -- admin to some
       intermediate role to the owner -- is caught and named rather than missed.

    **What this deliberately does not ask.** It does not call ``pg_has_role``, and it does
    not require the bootstrap administrator to be unable to reach ``role``. That
    administrator is trusted: CI runs as the ``postgres`` superuser of an ephemeral service
    container, and a superuser satisfies ``pg_has_role(..., 'SET'/'USAGE')`` for every role
    in the cluster no matter what this module revokes. Requiring the opposite made bootstrap
    fail on exactly the cluster shape the accepted architecture describes.

    So the property here is hygiene rather than isolation, and it is real on either kind of
    admin: an explicit membership row carrying ``SET`` or ``INHERIT`` that PostgreSQL would
    have let us revoke must not be left behind. A non-superuser creator's ``ADMIN OPTION``
    row is not revocable (see :func:`_revoke_owner_membership`) and carries neither option,
    so it passes and stays -- teardown needs it. Containment of the trusted administrator is
    the attestation marker and ``TestBootstrapSettings``, not this check; ADR 0004 section
    8f states that boundary.
    """
    engine = _admin_engine(admin_url)
    try:
        with engine.connect() as connection:
            problems = []
            for grantor, member, admin_option, inherit_option, set_option in _membership_rows(
                connection, role
            ):
                if set_option or inherit_option:
                    carried = ", ".join(
                        label
                        for label, held in (("SET", set_option), ("INHERIT", inherit_option))
                        if held
                    )
                    problems.append(
                        f"pg_auth_members still has {member!r} granted by {grantor!r} carrying {carried}"
                    )

            for path, path_set, path_inherits in _reachable_paths(connection, role):
                if path_set or path_inherits:
                    problems.append(f"an indirect membership path carries it: {' -> '.join(path)}")

            if problems:
                raise DisposableDatabaseError(
                    f"the temporary SET membership on the per-run owner {role!r} was not given "
                    f"back ({'; '.join(problems)}). The bootstrap grants it for one statement "
                    "and revokes it in a finally, so a surviving option means that revoke did "
                    "not do what it claims -- bootstrap fails rather than leaving an explicit "
                    "grant nobody asked for."
                )
    finally:
        engine.dispose()


def _verify_owner_authority(
    owner_maintenance_url: str,
    owner_role: str,
    fingerprint: ClusterFingerprint,
    endpoint: tuple[str, int],
) -> None:
    """Prove the owner can log in and act, **before** there is anything to clean up.

    Ordering is the whole point. ``CREATE DATABASE`` is not transactional, so from the
    instant it returns there is an object that only the owner may drop; discovering *then*
    that the owner cannot authenticate, or reaches a different cluster, would leave a
    database that nothing in this process has the authority to remove.
    """
    engine = _admin_engine(owner_maintenance_url)
    try:
        with engine.connect() as connection:
            require_disposable_cluster(connection)
            require_live_identity(
                connection,
                database=config.database_name(owner_maintenance_url),
                expected_user=owner_role,
                endpoint=endpoint,
                context="the per-run owner's maintenance connection",
            )
            live = read_fingerprint(connection)
            config.require_maintenance_database_name(
                live.database, context="the per-run owner's maintenance connection"
            )
            mismatch = fingerprint.mismatch(live)
            if mismatch:
                raise DisposableDatabaseError(
                    f"the per-run owner's maintenance connection is on a different cluster "
                    f"({mismatch})."
                )
    except DisposableDatabaseError:
        raise
    except Exception as exc:
        raise DisposableDatabaseError(
            "the per-run owner could not establish the maintenance connection that teardown "
            f"depends on, so no database will be created: {type(exc).__name__}: {exc}"
        ) from None
    finally:
        engine.dispose()


# --------------------------------------------------------------------------- cleanup


def _drop_role_atomically(engine, recorded: ObjectIdentity) -> list[str]:
    """Rename, re-verify, then drop -- all in one transaction.

    ``DROP ROLE`` takes a name, and between the identity check and the statement another
    process could drop and recreate that name. Renaming first closes the window: the
    rename takes the lock on the role, and the OID is re-read *after* it, so what is
    dropped is provably the object that was validated. A concurrent recreation gets the
    original name, which this transaction is no longer referring to.

    Rolled back if the identity does not match, which leaves the rename undone.
    """
    doomed = f"{recorded.name}_gone_{secrets.token_hex(4)}"
    try:
        # A real transaction, so the rename and the drop cannot be separated. The admin
        # engine used elsewhere is AUTOCOMMIT, which would make this a no-op.
        with engine.connect() as connection:
            with connection.begin():
                live = _read_role_identity(connection, recorded.name)
                if live is None:
                    return []
                mismatch = recorded.mismatch(live)
                if mismatch:
                    raise _IdentityMismatch(mismatch)
                connection.execute(
                    text(
                        f"ALTER ROLE {roles.quote_identifier(recorded.name)} "
                        f"RENAME TO {roles.quote_identifier(doomed)}"
                    )
                )
                renamed = _read_role_identity(connection, doomed)
                if renamed is None or renamed.oid != recorded.oid:
                    raise _IdentityMismatch(
                        f"role {recorded.name!r} changed identity during the rename"
                    )
                connection.execute(text(f"DROP ROLE {roles.quote_identifier(doomed)}"))
    except _IdentityMismatch as exc:
        return [f"refused to drop: {exc}"]
    except Exception as exc:
        return [f"DROP ROLE {recorded.name}: {type(exc).__name__}: {exc}"]
    return []


class _IdentityMismatch(Exception):
    """Internal: an object is not the one that was created."""


def _dispose_database_as_owner(
    owner_url: str,
    recorded: ObjectIdentity,
    fingerprint: "ClusterFingerprint | None",
    role_names: tuple[str, ...],
) -> list[str]:
    """Revalidate, then revoke, terminate and drop -- all as the recorded owner.

    **Nothing here alters the database before its identity has been re-established on the
    connection doing the altering.** Revoking ``CONNECT``, lowering a connection limit and
    terminating backends are all destructive to a running system, and they used to happen
    on the admin connection, by name, before any OID or provenance check had run. Pointed
    at a same-name replacement that is exactly what they would have done to it.

    Three things now stand between a replacement and any change:

    1. the OID and provenance marker are re-read **on the owner connection**, immediately
       before the first statement;
    2. the live ``datdba`` must still be this owner role, so a replacement owned by
       anybody else is refused with nothing touched;
    3. every statement runs as that owner, so PostgreSQL evaluates its own ownership check
       against whatever object exists at the instant it runs. That check is the only part
       of this that is genuinely atomic, and it is the part that holds under a race.

    ``DROP DATABASE`` cannot run inside a transaction, so a check-then-drop sequence has a
    window no amount of care closes. What closes it is that the window is guarded by
    ownership rather than by our own re-reads.

    No ``FORCE``: ``FORCE`` needs the privileges of the roles whose backends it terminates,
    which would mean broadening this role rather than narrowing it. If the backends cannot
    be cleared, the database is **left in place and reported** -- a safe leak is the
    correct outcome, and an operator must not widen teardown authority to make it go away.
    """
    if not owner_url:
        return [
            f"refused to drop database {recorded.name!r}: no recorded owner identity to drop it as"
        ]
    try:
        owner_role = config.require_disposable_role(make_url(owner_url).username or "")
    except config.UnsafeTestDatabaseError as exc:
        return [f"refused to drop database {recorded.name!r}: {exc}"]

    engine = _admin_engine(owner_url)
    try:
        with engine.connect() as connection:
            # --- the owner connection must itself be what we think it is ---------------
            require_disposable_cluster(connection)
            live_cluster = read_fingerprint(connection)
            config.require_maintenance_database_name(
                live_cluster.database, context="owner connection used for DROP DATABASE"
            )
            if fingerprint is not None:
                mismatch = fingerprint.mismatch(live_cluster)
                if mismatch:
                    return [
                        f"refused to drop database {recorded.name!r}: the owner connection is on a "
                        f"different cluster ({mismatch}). Nothing was altered."
                    ]
            if connection.execute(text("SELECT current_user")).scalar() != owner_role:
                return [
                    f"refused to drop database {recorded.name!r}: the owner connection is not "
                    f"running as {owner_role!r}. Nothing was altered."
                ]

            # --- the target must still be the object that was created ------------------
            live = _read_database_identity(connection, recorded.name)
            if live is None:
                return []
            mismatch = recorded.mismatch(live)
            if mismatch:
                return [f"refused to drop: {mismatch}. Nothing was altered."]

            owned_by_us = connection.execute(
                text(
                    "SELECT pg_catalog.pg_get_userbyid(d.datdba) = current_user "
                    "FROM pg_catalog.pg_database d WHERE d.datname = :n"
                ),
                {"n": recorded.name},
            ).scalar()
            if not owned_by_us:
                return [
                    f"refused to drop database {recorded.name!r}: it is no longer owned by "
                    f"{owner_role!r}, so it is somebody else's object under a familiar name. "
                    "Nothing was altered."
                ]

            # --- only now may anything change ------------------------------------------
            quoted = roles.quote_identifier(recorded.name)
            notes: list[str] = []
            try:
                connection.execute(text(f"REVOKE CONNECT ON DATABASE {quoted} FROM PUBLIC"))
                for role in role_names:
                    connection.execute(
                        text(
                            f"REVOKE CONNECT ON DATABASE {quoted} FROM {roles.quote_identifier(role)}"
                        )
                    )
                connection.execute(
                    text(
                        "SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity "
                        "WHERE datname = :db AND pid <> pg_catalog.pg_backend_pid()"
                    ),
                    {"db": recorded.name},
                )
            except Exception as exc:
                # Not fatal on its own: the DROP may still succeed if nothing is connected.
                # Recorded so that, if it does not, the report says why.
                notes.append(f"could not release connections: {type(exc).__name__}: {exc}")

            try:
                connection.execute(text(f"DROP DATABASE {quoted}"))
            except Exception as exc:
                return notes + [
                    f"DROP DATABASE {recorded.name} as owner {owner_role!r}: "
                    f"{type(exc).__name__}: {exc}. The database has been LEFT IN PLACE; do not "
                    "broaden teardown authority to force it."
                ]
    except Exception as exc:
        return [
            f"refused to drop database {recorded.name!r}: the owner connection could not be "
            f"validated ({type(exc).__name__}: {exc}). Nothing was altered."
        ]
    finally:
        engine.dispose()
    return []


def _cleanup(
    admin_url: str,
    fingerprint: ClusterFingerprint | None,
    created: tuple[ObjectIdentity, ...],
    *,
    owner_url: str | None,
) -> list[str]:
    """The one validated cleanup path, used by teardown and by failed setup alike.

    Two phases with different authorities, on purpose:

    * the **admin** connection re-establishes that this is the attested, disposable
      cluster these objects were created on, and nothing more -- it neither alters nor
      drops the database;
    * the **owner** connection does everything that changes or removes the database, and
      revalidates the target itself first (see :func:`_dispose_database_as_owner`).

    The database goes before the roles: dropping it removes the grants that would
    otherwise block ``DROP ROLE``.
    """
    problems: list[str] = []
    databases = [o for o in created if o.kind == "database"]
    role_objects = [o for o in created if o.kind == "role"]
    role_names = tuple(o.name for o in role_objects)

    try:
        engine = _admin_engine(admin_url)
    except Exception as exc:  # pragma: no cover - only on a malformed URL
        return [f"could not open an admin connection: {type(exc).__name__}: {exc}"]

    # --- phase 1: admin attests the cluster. It changes nothing. ----------------------
    try:
        with engine.connect() as connection:
            require_disposable_cluster(connection)
            live = read_fingerprint(connection)
            config.require_maintenance_database_name(
                live.database, context="cleanup admin connection"
            )
            if fingerprint is not None:
                mismatch = fingerprint.mismatch(live)
                if mismatch:
                    return [
                        f"refused to clean up: the admin connection is not the server these objects "
                        f"were created on ({mismatch}). Leaving them in place."
                    ]
    except Exception as exc:
        # Validation itself failed, so nothing has been dropped and nothing may be:
        # leak deliberately and say so.
        return [f"cleanup could not be validated, so nothing was dropped: {type(exc).__name__}: {exc}"]
    finally:
        engine.dispose()

    # --- phase 2: the owner revalidates and disposes of the database ------------------
    for recorded in databases:
        problems.extend(
            _dispose_database_as_owner(owner_url or "", recorded, fingerprint, role_names)
        )

    # --- phase 3: then the roles, each over its own real transaction ------------------
    try:
        transactional = _transactional_engine(admin_url)
    except Exception as exc:  # pragma: no cover - only on a malformed URL
        problems.append(f"could not open a transactional admin connection: {type(exc).__name__}: {exc}")
        return problems
    try:
        for recorded in role_objects:
            problems.extend(_drop_role_atomically(transactional, recorded))
    finally:
        transactional.dispose()
    return problems


def _report_cleanup(problems: list[str]) -> None:
    """Say what cleanup could not remove, without replacing the original failure.

    Printed rather than raised: the caller is already unwinding a real error, and a
    cleanup complaint that masks it would cost more than it explains.
    """
    for problem in problems:
        print(f"warning: disposable-database cleanup: {problem}", file=sys.stderr)


# --------------------------------------------------------------------------- creation


def create_disposable_database(env: Mapping[str, str] | None = None) -> DisposableDatabase:
    """Provision a migrated, role-separated throwaway database. Raises if it cannot."""
    env = os.environ if env is None else env
    # Explicitly the TEST BOOTSTRAP settings: this credential creates and drops databases
    # and roles, and is confined to test tooling by its own loader rather than by
    # convention.
    admin_url = config.load_test_bootstrap_settings(env).admin_url

    suffix = secrets.token_hex(6)
    database = f"firmbatch_test_{suffix}"
    owner_role = f"firmbatch_test_own_{suffix}"
    application_role = f"firmbatch_test_app_{suffix}"
    provisioning_role = f"firmbatch_test_prov_{suffix}"
    owner_password, application_password, provisioning_password = (secrets.token_hex(16) for _ in range(3))
    passwords = (owner_password, application_password, provisioning_password)
    marker = f"firmbatch-disposable-{secrets.token_hex(16)}"

    # Re-validate the names we just generated. If the patterns and the generator ever
    # drift apart, this fails before anything exists rather than at teardown, when a drop
    # would be refused and the database would be left behind.
    config.require_disposable_database(_swap_database(admin_url, database))
    for role in (owner_role, application_role, provisioning_role):
        config.require_disposable_role(role)

    # ------------------------------------------------------------------ state machine
    #
    # CREATE DATABASE cannot run inside a transaction, so this sequence cannot be made
    # atomic and is written as explicit states instead. The rule at every transition is
    # the same: either the state supports owner-bound cleanup, or it deliberately leaks
    # and reports, and it NEVER deletes something it cannot prove it created.
    #
    #   S0  nothing exists                     -> nothing to clean up
    #   S1  roles exist and are recorded       -> each created in one transaction, so a
    #                                             partial role is impossible (finding 7)
    #   S2  the owner's cleanup authority is   -> established BEFORE anything needs
    #       proven: it can log in, on this        cleaning. Discovering after CREATE
    #       cluster, at this endpoint             DATABASE that the owner cannot connect
    #                                             would strand an undroppable database
    #   S3  the database exists and its OID    -> owner-bound cleanup works from here on,
    #       is recorded (marker still empty)      including if COMMENT never runs
    #   S4  the provenance marker is written   -> recorded identity upgraded to match
    #   S5  grants and revokes are applied     -> failures here still clean up fully
    #   S6  migrated, granted, handle returned
    #
    # The one state with no safe automatic exit is "CREATE DATABASE returned but its OID
    # could not be read": there is an object, and no proof of what it is. That leaks by
    # design, loudly.
    created: list[ObjectIdentity] = []
    fingerprint: ClusterFingerprint | None = None
    owner_maintenance_url = ""
    admin = _admin_engine(admin_url)
    transactional = _transactional_engine(admin_url)

    def _cleanup_now():
        _report_cleanup(
            _cleanup(admin_url, fingerprint, tuple(created), owner_url=owner_maintenance_url or None)
        )

    try:
        # --- S0 -> attest before anything is created ---------------------------------
        with admin.connect() as connection:
            # No CREATE of any kind before the server has been attested and confirmed to
            # be a maintenance connection in fact, not merely by URL.
            # Everything in this block is READ-ONLY, and it is ordered so that the last
            # read decides whether the first write happens:
            #
            #   1. the canonical maintenance URL is already parsed and validated (above);
            #   2. the environment is validated per physical connection by the engine guard;
            #   3. the disposable-cluster attestation is checked -- a catalogue read;
            #   4. server_version_num is read;
            #   5. PostgreSQL 16 is required.
            #
            # Only then does anything get created. Checking the version after provisioning
            # was the defect: on 15 or 17 the suite built a database and three roles before
            # announcing the server was unsupported.
            require_disposable_cluster(connection)
            fingerprint = read_fingerprint(connection)
            config.require_maintenance_database_name(
                fingerprint.database,
                context=f"{config.TEST_ADMIN_URL_VAR} live connection",
            )
            require_supported_server_version(fingerprint.server_version_num)
            host, port = _tcp_endpoint(admin_url, connection)

        # --- S0 -> S1: the three roles, each in its own transaction -------------------
        for role, password in zip((owner_role, application_role, provisioning_role), passwords):
            _create_login_role(transactional, role, password, marker, created.append)

        # The owner needs to be able to terminate the runtime roles' backends at teardown;
        # pg_terminate_backend allows it for a role the caller is a member of. Membership
        # runs owner -> app/prov, never the other way, so neither runtime role gains any
        # reach towards the owner (db/principal.py checks exactly that direction).
        with admin.connect() as connection:
            for role in (application_role, provisioning_role):
                connection.execute(
                    text(
                        f"GRANT {roles.quote_identifier(role)} TO "
                        f"{roles.quote_identifier(owner_role)}"
                    )
                )

        # --- S1 -> S2: prove the owner's cleanup authority BEFORE creating anything ---
        endpoint = (host, port)
        owner_maintenance_url = _role_url(
            owner_role, owner_password, host, port, config.database_name(admin_url)
        )
        _verify_owner_authority(owner_maintenance_url, owner_role, fingerprint, endpoint)

        quoted_db = roles.quote_identifier(database)

        # --- S2 -> S3: create the database, owned by the per-run role ----------------
        with admin.connect() as connection:
            if _database_exists(connection, database):
                raise DisposableDatabaseError(
                    f"database {database!r} already exists and was not created by this process"
                )

            # SET membership is granted for exactly one statement and revoked in a
            # finally, including when that statement fails. Not because it would otherwise
            # let the trusted admin reach the owner -- it can, and that is accepted -- but
            # because an explicit standing grant nobody asked for is state this bootstrap
            # would be leaving behind on somebody's cluster.
            _grant_set_option(connection, owner_role)
            try:
                # OWNER matters: this is what makes the per-run role the deletion
                # authority. PostgreSQL checks ownership at the DROP statement, against
                # whatever object is present then -- the closest thing to an atomic guard
                # available for a statement that cannot run inside a transaction.
                connection.execute(
                    text(f"CREATE DATABASE {quoted_db} OWNER {roles.quote_identifier(owner_role)}")
                )
            finally:
                _revoke_owner_membership(connection, owner_role)

            # Record the OID immediately, before anything else can fail. The marker is not
            # written yet, so this records the empty comment the database actually has --
            # already enough for cleanup, which compares against what it reads.
            provisional = _read_database_identity(connection, database)
            if provisional is None:  # pragma: no cover - CREATE DATABASE did nothing
                raise DisposableDatabaseError(
                    f"database {database!r} is absent immediately after creation"
                )
            created.append(provisional)

        # --- S3 -> S5: the owner configures its own database --------------------------
        #
        # Everything here is an owner operation, and the admin is deliberately no longer
        # able to perform any of it -- it cannot COMMENT on this database, cannot change
        # its grants, and cannot drop it. That is the separation working rather than an
        # inconvenience to route around: verified live, the admin gets "must be owner of
        # database" for all three.
        owner_admin = _admin_engine(owner_maintenance_url)
        try:
            with owner_admin.connect() as connection:
                _comment_on(connection, "database", database, marker)
                database_identity = _read_database_identity(connection, database, marker=marker)
                if database_identity is None:  # pragma: no cover
                    raise DisposableDatabaseError(
                        f"database {database!r} disappeared between creation and provenance"
                    )
                created[created.index(provisional)] = database_identity

                connection.execute(text(f"REVOKE CONNECT ON DATABASE {quoted_db} FROM PUBLIC"))
                connection.execute(text(f"REVOKE TEMPORARY ON DATABASE {quoted_db} FROM PUBLIC"))
                for role in (owner_role, application_role, provisioning_role):
                    connection.execute(
                        text(
                            f"GRANT CONNECT ON DATABASE {quoted_db} TO "
                            f"{roles.quote_identifier(role)}"
                        )
                    )
        finally:
            owner_admin.dispose()

        # The revoke above is verified from a NEW admin session, because membership is
        # resolved per session. Catalogue rows only: whether the trusted bootstrap
        # administrator can still *reach* the owner is a property of its cluster authority
        # -- a superuser always can -- and is accepted by ADR 0004 section 8f rather than
        # asserted against here.
        _require_temporary_membership_released(admin_url, owner_role)
    except (config.ConfigurationError, DisposableDatabaseError):
        # A deliberate refusal -- a missing attestation, an unsafe target, a name
        # collision. It already says exactly what was wrong and callers match on its
        # type; re-wrapping would only hide that.
        _cleanup_now()
        raise
    except Exception as exc:
        # Anything else is a surprise, and a surprise from inside provisioning is still a
        # provisioning failure. Wrapped so the module has one error type for that, and
        # scrubbed because an unexpected exception is exactly where a generated password
        # would otherwise surface.
        _cleanup_now()
        raise DisposableDatabaseError(
            f"could not provision disposable database {database!r}; every object created "
            "along the way has been removed or reported. Cause: "
            f"{type(exc).__name__}: {config.scrub_secrets(str(exc), passwords)}"
        ) from None
    finally:
        admin.dispose()
        transactional.dispose()

    # --- S5 -> S6: migrate and grant, on one validated owner connection --------------
    migration_url = _role_url(owner_role, owner_password, host, port, database)

    try:
        def _validate(connection, context="migration connection"):
            return validate_migration_connection(
                connection,
                database=database,
                fingerprint=fingerprint,
                endpoint=endpoint,
                expected_user=owner_role,
                context=context,
            )

        owner = _transactional_engine(migration_url)
        try:
            # ONE connection: validated, then handed to Alembic, then used for the grants.
            # Alembic is given the live connection rather than the URL precisely so that it
            # cannot resolve and connect a second time.
            with owner.connect() as connection:
                expected = _validate(connection, "migration connection before migrations")
                # `expected` is inert data. env.py re-runs the canonical validator against
                # it on this same connection before the first DDL statement; nothing this
                # function passes can make that check pass on a different server.
                head = upgrade_to_head(connection, expected=expected)
                connection.commit()

                _validate(connection, "owner connection before grants")
                roles.harden_database(connection, database)
                roles.revoke_public_table_privileges(connection)
                roles.grant_application_role(connection, application_role)
                roles.grant_provisioning_role(connection, provisioning_role)
                connection.commit()
        finally:
            owner.dispose()
    except Exception as exc:
        _cleanup_now()
        raise DisposableDatabaseError(
            f"failed to prepare disposable database {database!r}; its objects have been removed. "
            f"Cause: {type(exc).__name__}: {config.scrub_secrets(str(exc), passwords)}"
        ) from None

    handle = DisposableDatabase(
        database=database,
        admin_url=admin_url,
        migration_url=migration_url,
        application_url=_role_url(application_role, application_password, host, port, database),
        provisioning_url=_role_url(provisioning_role, provisioning_password, host, port, database),
        application_role=application_role,
        provisioning_role=provisioning_role,
        owner_role=owner_role,
        head_revision=head,
        fingerprint=fingerprint,
        endpoint=endpoint,
        created=tuple(created),
        owner_maintenance_url=owner_maintenance_url,
    )
    _PROVISIONED[handle.token] = _identity_fields(handle)
    return handle


# --------------------------------------------------------------------------- teardown


def _validate_teardown_target(handle: DisposableDatabase, connection) -> None:
    """Everything that must be true before a DROP DATABASE is allowed to run.

    Ordered so that the most specific, most explanatory check fires first and the
    catch-all last. Each is independent: the intrinsic checks are meaningful for any
    handle at all, and the registry comparison at the end catches whatever they miss.
    Per-object identity is checked separately, at the moment of each drop.
    """
    # --- names ---------------------------------------------------------------------
    if handle.database in config.PROTECTED_DATABASES:
        raise DisposableDatabaseError(f"refusing to drop protected database {handle.database!r}")
    config.require_disposable_database(handle.migration_url)
    config.require_disposable_role(handle.application_role)
    config.require_disposable_role(handle.provisioning_role)
    config.require_disposable_role(handle.owner_role)

    # --- the handle must be internally consistent ------------------------------------
    migration_database = config.database_name(handle.migration_url)
    if migration_database != handle.database:
        raise DisposableDatabaseError(
            f"refusing to drop: handle.database is {handle.database!r} but its migration URL points "
            f"at {migration_database!r}. A target derived two ways must agree."
        )
    for label, url in (
        ("migration", handle.migration_url),
        ("application", handle.application_url),
        ("provisioning", handle.provisioning_url),
    ):
        name = config.database_name(url)
        if name != handle.database:
            raise DisposableDatabaseError(
                f"refusing to drop: the {label} URL names database {name!r}, not {handle.database!r}"
            )

    # Every runtime URL must point at the endpoint recorded when the roles were created.
    # Compared against the recorded value rather than inet_server_port(), which is NULL on
    # a unix-socket admin connection -- a real gap that let a mismatched handle through.
    for label, url in (("application", handle.application_url), ("provisioning", handle.provisioning_url)):
        host, port = _endpoint(url)
        if (host, port) != handle.endpoint:
            raise DisposableDatabaseError(
                f"refusing to drop: the {label} URL is at {(host, port)!r} but this database was "
                f"provisioned at {handle.endpoint!r}. The handle spans two servers."
            )

    # --- the live server must be the one we created on, and still attested ------------
    require_disposable_cluster(connection)
    live = read_fingerprint(connection)
    config.require_maintenance_database_name(
        live.database, context="teardown admin connection"
    )
    mismatch = handle.fingerprint.mismatch(live)
    if mismatch:
        raise DisposableDatabaseError(
            f"refusing to drop: the admin connection is not the server this database was created on "
            f"({mismatch}). Host, port, URL or server has changed underneath the handle."
        )

    # --- the catch-all: created here, and unaltered since -----------------------------
    recorded = _PROVISIONED.get(handle.token)
    if recorded is None:
        raise DisposableDatabaseError(
            "refusing to drop: this handle was not produced by create_disposable_database in this "
            "process. A handle is evidence about a database this code created, not an instruction "
            "to destroy one it was handed."
        )
    altered = sorted(k for k, v in _identity_fields(handle).items() if recorded.get(k) != v)
    if altered:
        raise DisposableDatabaseError(
            f"refusing to drop: this handle has been altered since it was created (field(s) {altered}). "
            "A handle records what was provisioned; editing one does not re-target it."
        )


def drop_disposable_database(handle: DisposableDatabase) -> None:
    """Destroy the database and both roles. Refuses anything it did not create.

    Object identity is re-checked per object at the moment of the drop, so a database or
    role that has been replaced under the same name since creation is left alone and
    reported rather than destroyed.
    """
    admin = _admin_engine(handle.admin_url)
    try:
        with admin.connect() as connection:
            _validate_teardown_target(handle, connection)
    finally:
        admin.dispose()

    problems = _cleanup(
        handle.admin_url,
        handle.fingerprint,
        handle.created,
        owner_url=handle.owner_maintenance_url,
    )
    if problems:
        _report_cleanup(problems)
        raise DisposableDatabaseError(
            "teardown could not remove every object it created: " + "; ".join(problems)
        )
    _PROVISIONED.pop(handle.token, None)
