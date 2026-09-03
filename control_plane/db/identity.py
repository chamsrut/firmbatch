"""What a live connection actually is, asked of the server rather than of the URL.

A validated URL says where a connection was *meant* to go. This module says where one
went. The two are not the same thing, and every gap between them in this package has been
a real defect at some point:

* ``/postgres?dbname=customer_prod`` validated as ``postgres`` and connected to
  ``customer_prod``, because libpq gives the query string precedence over the path;
* ``?options=-c role=firmbatch_app`` made ``current_user`` look restricted while the
  authenticated ``session_user`` stayed privileged;
* a URL validated on one connection and then resolved a second time reached a different
  cluster, because DNS and failover endpoints are free to answer differently;
* ``PGHOSTADDR`` sent a fully explicit URL to another server entirely.

So: four facts, read from the connection that is about to be used, immediately before it
is used. Database, cluster, endpoint, principal. Anything that can move a connection has
to defeat all four, and the ones that matter most -- cluster and principal -- can only be
answered by the server.

``system_identifier`` comes from the control file and is unique per initialised cluster,
which is what makes it a *server* identity rather than a connection one. It stays readable
by an ordinary non-superuser role on a stock PostgreSQL 16; if a hardened deployment has
revoked it, the correct response is to grant it to the migration role, not to skip the
check. A cluster identity that cannot be read is a cluster identity that was not verified.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import make_url, text


class LiveIdentityError(RuntimeError):
    """Raised when a live connection is not the one that was validated."""


def read_system_identifier(connection) -> str:
    """The cluster's control-file identifier. Raises if it cannot be read."""
    try:
        value = connection.execute(
            text("SELECT system_identifier::text FROM pg_catalog.pg_control_system()")
        ).scalar()
    except Exception as exc:
        raise LiveIdentityError(
            "could not read the cluster system_identifier, so this connection cannot be proven to "
            "be on the cluster that was validated: "
            f"{type(exc).__name__}: {exc}. Grant EXECUTE on pg_control_system() to the migration "
            "role rather than skipping the check."
        ) from None
    if not value:  # pragma: no cover - would mean the control file read returned nothing
        raise LiveIdentityError("the cluster reported an empty system_identifier")
    return str(value)


def connection_endpoint(connection) -> tuple[str | None, int | None]:
    """The endpoint an open connection was built against.

    Taken from the engine URL rather than from ``inet_server_addr()``/``inet_server_port()``,
    both of which are **NULL over a unix socket** -- a real defect that once let a handle
    spanning two servers through unnoticed and dropped a live database.
    """
    url = make_url(connection.engine.url)
    host = url.query.get("host") or url.host
    port = url.query.get("port") or url.port
    return (host, int(port) if port is not None else None)


@dataclass(frozen=True)
class LiveIdentity:
    """The four facts, as the server reports them."""

    database: str
    system_identifier: str
    endpoint: tuple[str | None, int | None]
    current_user: str
    session_user: str


def read_live_identity(connection) -> LiveIdentity:
    database, current_user, session_user = connection.execute(
        text("SELECT current_database(), current_user, session_user")
    ).one()
    return LiveIdentity(
        database=database,
        system_identifier=read_system_identifier(connection),
        endpoint=connection_endpoint(connection),
        current_user=current_user,
        session_user=session_user,
    )


def require_live_identity(
    connection,
    *,
    database: str,
    expected_user: str,
    endpoint: tuple[str | None, int | None] | None = None,
    system_identifier: str | None = None,
    context: str,
) -> LiveIdentity:
    """Raise unless the open connection is the one that was validated.

    ``endpoint`` and ``system_identifier`` are optional only in the sense that the *first*
    read of a connection has nothing to compare them against; every later check on the
    same connection passes the values the first read returned, which is what makes a swap
    between validation and DDL detectable.
    """
    live = read_live_identity(connection)
    problems = []

    if live.database != database:
        problems.append(f"it is attached to database {live.database!r}, not {database!r}")
    if live.current_user != expected_user or live.session_user != expected_user:
        problems.append(
            f"it is running as {live.current_user!r} (authenticated as {live.session_user!r}), "
            f"not the expected principal {expected_user!r}"
        )
    if endpoint is not None and live.endpoint != endpoint:
        problems.append(f"it is at endpoint {live.endpoint!r}, not the recorded {endpoint!r}")
    if system_identifier is not None and live.system_identifier != system_identifier:
        problems.append(
            f"it is on cluster {live.system_identifier!r}, not the recorded {system_identifier!r}"
        )

    if problems:
        raise LiveIdentityError(f"{context}: " + "; and ".join(problems) + ".")
    return live


# --------------------------------------------------------------------------------------
# The expected identity: a value, not a callback.
#
# Online migrations used to take a ``validate`` callable. That is a seam, and a seam in a
# safety check is a bypass with extra steps: ``upgrade_to_head(conn, validate=lambda c:
# None)`` authorised DDL against anything at all, and read as though it had been checked.
# The same is true of a boolean flag -- ``validated=True`` is a claim by the caller, not
# evidence about a connection.
#
# So the thing that travels is DATA. An ``ExpectedIdentity`` records what the connection
# must turn out to be; ``require_expected_identity`` is the only code that acts on it, and
# ``env.py`` calls that function itself rather than anything a caller handed it. A caller
# can supply a wrong identity -- and gets a refusal naming the mismatch -- but cannot
# supply an identity that means "skip the check", because there is no such value.
#
# ``require_expected_identity`` deliberately takes the type rather than a protocol, and
# reads the fields itself rather than calling a method on the object, so a subclass that
# overrode a ``verify`` method would gain nothing.
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ExpectedIdentity:
    """Everything a connection must prove before it is allowed to run DDL.

    Immutable, and produced only by the canonical connection paths --
    ``migrate.migration_connection`` for an operator, ``testing.bootstrap`` for the suite.
    Both build it from a parsed :class:`~firmbatch.control_plane.config.ConnectionSpec`
    plus what the server said when the connection first opened.
    """

    #: The database the connection must be attached to, from the URL path.
    database: str
    #: The cluster's control-file identifier, read when the connection first opened.
    system_identifier: str
    #: Host and port, from the canonical specification rather than from the server --
    #: ``inet_server_port()`` is NULL over a unix socket.
    endpoint: tuple[str | None, int | None]
    #: The role the URL named. Both ``current_user`` and ``session_user`` must equal it.
    expected_user: str

    def __repr__(self) -> str:  # pragma: no cover - exercised through str()
        return (
            f"ExpectedIdentity(database={self.database!r}, endpoint={self.endpoint!r}, "
            f"expected_user={self.expected_user!r})"
        )

    __str__ = __repr__


def expected_identity_for(connection, *, database: str, expected_user: str, endpoint) -> ExpectedIdentity:
    """Build an :class:`ExpectedIdentity` from a connection that has just been validated.

    The cluster identifier comes from the live connection because there is nothing else it
    could come from -- a URL does not name a cluster. Every later check compares against
    the value read here, which is what makes a connection that was swapped, reset or
    re-authenticated in between detectable.
    """
    live = require_live_identity(
        connection,
        database=database,
        expected_user=expected_user,
        endpoint=endpoint,
        context="establishing the expected migration identity",
    )
    return ExpectedIdentity(
        database=database,
        system_identifier=live.system_identifier,
        endpoint=endpoint,
        expected_user=expected_user,
    )


def require_expected_identity(connection, expected, *, context: str) -> LiveIdentity:
    """The canonical validator. The only thing that may authorise online DDL.

    Called by ``env.py`` itself, on the exact ``Connection`` Alembic is about to use,
    before any ``SET``, ``CREATE SCHEMA``, version-table access or migration statement.

    Refuses anything that is not an :class:`ExpectedIdentity` -- a callable, a boolean, a
    look-alike object with the right attributes -- because the previous design accepted a
    caller-supplied callable and a no-op one authorised everything.
    """
    if not isinstance(expected, ExpectedIdentity):
        raise LiveIdentityError(
            f"{context}: no expected identity was supplied "
            f"(got {type(expected).__name__}). Online DDL is authorised by an ExpectedIdentity "
            "produced by migrate.migration_connection() or by the test bootstrap, never by a "
            "callable, a flag, or anything else a caller can construct to mean 'already checked'."
        )

    live = require_live_identity(
        connection,
        database=expected.database,
        expected_user=expected.expected_user,
        endpoint=expected.endpoint,
        system_identifier=expected.system_identifier,
        context=context,
    )

    # The migration-principal profile: the authenticated identity and the effective one
    # must agree, and must still agree after RESET ROLE. A privileged login that
    # preselected a restricted role with ``options=-c role=...`` otherwise looks correct
    # in ``current_user`` while remaining one RESET ROLE from full privilege.
    connection.execute(text("RESET ROLE"))
    after_reset = connection.execute(text("SELECT current_user, session_user")).one()
    if after_reset[0] != expected.expected_user or after_reset[1] != expected.expected_user:
        raise LiveIdentityError(
            f"{context}: after RESET ROLE this connection is {after_reset[0]!r} "
            f"(authenticated as {after_reset[1]!r}), not {expected.expected_user!r}. A "
            "preselected role hides the authenticated identity, so the principal that would "
            "own the migrated objects is not the one that was validated."
        )
    return live
