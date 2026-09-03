"""Disposable-cluster attestation: proof that a server is safe to create and drop on.

The problem this solves. ``FIRMBATCH_TEST_DATABASE_URL`` points at a maintenance database
so the bootstrap can ``CREATE DATABASE``. But *every* PostgreSQL cluster has a ``postgres``
database, production included, so "the URL ends in ``/postgres``" is not evidence of
anything. A copied environment variable, a stale shell, or a tunnel left open is enough to
aim the test bootstrap at something real.

The marker. A server is treated as disposable only if it carries a ``NOLOGIN`` role with an
exact comment:

    CREATE ROLE firmbatch_disposable_test_cluster NOLOGIN;
    COMMENT ON ROLE firmbatch_disposable_test_cluster IS 'firmbatch-disposable-test-cluster';

or, equivalently::

    cd "$(git rev-parse --show-toplevel)/.."
    FIRMBATCH_ENV=test FIRMBATCH_TEST_DATABASE_URL=... \\
      python3 -m firmbatch.control_plane.testing.attestation --mark

Why a role and a comment. It needs to be creatable by a non-superuser with ``CREATEROLE``
(the local WSL setup) *and* by the superuser in a CI service container; readable without
superuser rights (``pg_roles`` is, ``pg_authid`` is not); cluster-wide rather than
per-database, since the bootstrap creates databases; and impossible to arrive at by
accident. A custom GUC would have been the obvious choice but needs ``ALTER SYSTEM`` or a
config edit, which the local non-superuser admin cannot do.

Checked before **and** after: once before any ``CREATE ROLE``/``CREATE DATABASE``, and
again on the maintenance connection immediately before any ``DROP``. It is never skipped,
weakened, or defaulted -- including in CI, where the workflow marks the ephemeral service
container explicitly.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from typing import Mapping

from sqlalchemy import create_engine, text

from .. import config
from ..db.engine import guard_connection_environment

_MARKER_SQL = """
SELECT pg_catalog.shobj_description(r.oid, 'pg_authid')
FROM pg_catalog.pg_roles r
WHERE r.rolname = :role
"""


@dataclass(frozen=True)
class ClusterFingerprint:
    """Identity of the server a connection is actually attached to.

    Captured at bootstrap and re-checked before teardown. ``system_identifier`` comes from
    the control file and is unique per initialised cluster, so it distinguishes two servers
    that happen to share a host and port -- a container restarted between the two calls,
    say, or an SSH tunnel repointed.
    """

    system_identifier: str
    server_port: int | None
    database: str
    server_version_num: int

    def mismatch(self, other: "ClusterFingerprint") -> str | None:
        """Compare the *cluster*, and only the cluster.

        ``system_identifier`` comes from the control file and identifies the initialised
        cluster; it is the only field here that is a property of the server rather than of
        the connection. ``server_port`` is NULL over a unix socket and a number over TCP,
        and ``database`` differs by design between a maintenance connection and an owner
        connection -- comparing either would reject a perfectly good connection to the
        very same cluster, which is exactly what happened when they were included.

        The database and the endpoint are checked where they mean something: by
        ``require_maintenance_database_name``, ``_require_live_database``, and the recorded
        endpoint comparison in the bootstrap.
        """
        if self.system_identifier != other.system_identifier:
            return (
                f"system_identifier: expected {self.system_identifier!r}, "
                f"connected to {other.system_identifier!r}"
            )
        return None


def read_fingerprint(connection) -> ClusterFingerprint:
    """Identify the server on the other end of an open connection."""
    row = connection.execute(
        text(
            """
            SELECT (SELECT system_identifier::text FROM pg_catalog.pg_control_system()),
                   pg_catalog.inet_server_port(),
                   pg_catalog.current_database(),
                   current_setting('server_version_num')::int
            """
        )
    ).one()
    return ClusterFingerprint(
        system_identifier=row[0],
        server_port=row[1],
        database=row[2],
        server_version_num=row[3],
    )


def read_marker(connection) -> str | None:
    """The attestation comment on the marker role, or ``None`` when it does not exist."""
    return connection.execute(text(_MARKER_SQL), {"role": config.DISPOSABLE_CLUSTER_MARKER_ROLE}).scalar()


def require_disposable_cluster(connection) -> None:
    """Raise unless the connected server carries the disposable-cluster marker."""
    try:
        comment = read_marker(connection)
    except Exception as exc:
        raise config.DisposableClusterAttestationError(
            f"could not read the disposable-cluster marker, so the server cannot be assumed "
            f"disposable: {type(exc).__name__}: {exc}"
        ) from None

    if comment == config.DISPOSABLE_CLUSTER_MARKER_COMMENT:
        return

    detail = (
        f"role {config.DISPOSABLE_CLUSTER_MARKER_ROLE!r} does not exist"
        if comment is None
        else f"role {config.DISPOSABLE_CLUSTER_MARKER_ROLE!r} carries comment {comment!r}, "
        f"expected {config.DISPOSABLE_CLUSTER_MARKER_COMMENT!r}"
    )
    raise config.DisposableClusterAttestationError(
        f"this server is not attested as a disposable test cluster: {detail}. "
        "Every PostgreSQL cluster has a 'postgres' database, so the URL alone proves nothing. "
        "If, and only if, this server is a throwaway test cluster, mark it:\n"
        f"  CREATE ROLE {config.DISPOSABLE_CLUSTER_MARKER_ROLE} NOLOGIN;\n"
        f"  COMMENT ON ROLE {config.DISPOSABLE_CLUSTER_MARKER_ROLE} IS "
        f"'{config.DISPOSABLE_CLUSTER_MARKER_COMMENT}';\n"
        "or run: python3 -m firmbatch.control_plane.testing.attestation --mark"
    )


def mark_cluster(connection) -> None:
    """Create or re-comment the marker role. Deliberate, explicit, and idempotent."""
    role = config.DISPOSABLE_CLUSTER_MARKER_ROLE
    if read_marker(connection) is None:
        exists = connection.execute(
            text("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = :role"), {"role": role}
        ).scalar()
        if not exists:
            connection.execute(text(f'CREATE ROLE "{role}" NOLOGIN'))
    connection.execute(text(f"COMMENT ON ROLE \"{role}\" IS '{config.DISPOSABLE_CLUSTER_MARKER_COMMENT}'"))


def unmark_cluster(connection) -> None:
    """Remove the marker role."""
    connection.execute(text(f'DROP ROLE IF EXISTS "{config.DISPOSABLE_CLUSTER_MARKER_ROLE}"'))


def _admin_engine(env: Mapping[str, str]):
    """The one engine this module builds -- guarded like every other.

    Marking and unmarking are the two operations that decide whether *anything else* in
    this package is allowed to create or drop, so a connection made here under a
    misdirected environment is worse than an ordinary one, not better. ``PGHOSTADDR``
    would put the marker role on a different server, and the suite would then read its own
    attestation from a cluster it was never pointed at.

    The guard is installed as a ``do_connect`` handler, so it runs before libpq is handed
    anything and the marker role is never touched on a connection that should not exist.
    """
    return guard_connection_environment(
        create_engine(config.load_test_admin_url(env), isolation_level="AUTOCOMMIT", future=True)
    )


def main(argv: list[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    env = os.environ if env is None else env
    parser = argparse.ArgumentParser(
        prog="python3 -m firmbatch.control_plane.testing.attestation",
        description="Mark, unmark, or check a PostgreSQL server as a disposable test cluster.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--mark", action="store_true", help="attest this server as disposable")
    group.add_argument("--unmark", action="store_true", help="withdraw the attestation")
    group.add_argument("--check", action="store_true", help="exit 0 only if attested")
    args = parser.parse_args(argv)

    try:
        engine = _admin_engine(env)
    except config.ConfigurationError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    try:
        with engine.connect() as connection:
            fingerprint = read_fingerprint(connection)
            print(f"server      {config.redact_database_url(str(engine.url))}")
            print(f"cluster     system_identifier={fingerprint.system_identifier}")
            if args.mark:
                mark_cluster(connection)
                print("marked      this server is now attested as a disposable test cluster")
            elif args.unmark:
                unmark_cluster(connection)
                print("unmarked    attestation withdrawn")
            else:
                require_disposable_cluster(connection)
                print("attested    marker present and correct")
    except config.DisposableClusterAttestationError as exc:
        print(f"NOT attested: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
