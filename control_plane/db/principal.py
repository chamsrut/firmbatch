"""Validate the identity an application connection actually authenticated as.

Forcing row-level security is worth nothing if the application connects as a role that is
exempt from it. Nothing in a URL says whether that is the case: a connection string
carrying ``postgres:postgres@`` and one carrying ``firmbatch_app:...@`` are the same shape,
and the second can still be a superuser. **Comparing URL strings cannot establish this.**
The only authority is the server, asked after the connection is open.

**The authenticated identity is ``session_user``, not ``current_user``.** A privileged
login can preselect a restricted role at startup --
``?options=-c role=firmbatch_app`` -- and PostgreSQL then reports the restricted role as
``current_user`` while the privileged identity remains ``session_user``, one ``RESET
ROLE`` away. A check that read ``current_user`` reported such a connection safe; that was
verified against a real server. So this module:

* issues ``RESET ROLE`` before inspecting, discarding any preselected role;
* requires ``current_user`` and ``session_user`` to agree afterwards;
* requires ``session_user`` to be the role the URL claimed, when the caller supplies it;
* runs every privilege, ownership and membership test from **both** identities.

Disqualifying conditions, each checked against the live catalogue:

1. ``rolsuper`` -- a superuser bypasses row security entirely.
2. ``rolbypassrls`` -- the attribute that exists precisely to skip policies.
3. ``rolreplication`` -- row-level security has no bearing on the WAL. A role that can
   open a replication connection can stream the entire cluster, every tenant included,
   without executing a single ``SELECT``.
4. ``rolcreaterole`` and ``rolcreatedb`` -- the rest of the profile ADR 0004 promises.
   CREATEROLE is a route to the others: it can create roles and grant memberships.
5. Ownership of **any object the isolation boundary is built out of** -- not merely
   the two tenant-scoped tables. An owner does not have to defeat a policy; it can
   remove one. Each of these is a complete bypass on its own:

   * the **database** -- its owner can ``ALTER DATABASE ... SET`` a parameter for every
     future session, and holds ``CONNECT``/``TEMP`` grant authority over it;
   * the **``firmbatch`` schema** -- its owner can ``CREATE`` a relation inside it that
     shadows a real one for any connection whose ``search_path`` resolves there;
   * **every relation in that schema** -- table, sequence, view, materialised view,
     index, foreign table or partition. ``ALTER TABLE ... NO FORCE ROW LEVEL SECURITY``
     and ``DROP POLICY`` are both owner operations, and a view's owner decides whose
     privileges its rows are read with;
   * **``app_current_tenant_id()`` and every other function in the schema** -- the
     policies call it, so its owner can ``CREATE OR REPLACE`` it to return whatever it
     likes and every policy predicate follows;
   * **every type in the schema** -- a domain's owner can drop its constraints.

   FORCE currently binds the table owner, but that is one ``ALTER`` away from not being
   true, and none of the other five are bound by it at all.
6. Membership in any role holding 1-5 -- checked with ``pg_has_role(..., 'MEMBER')``,
   which covers both inherited privilege and the ability to reach it with ``SET ROLE``.
   Checking only the connected role's own attributes would miss ``GRANT postgres TO
   firmbatch_app``, which is one command and looks harmless in a migration.

Enforced fail-closed on **every new pooled connection and again on every checkout** (see
``db/engine.py``): role attributes and memberships change while a connection sits idle in
the pool, so a check that ran only at connect time would certify a role that has since
been granted ownership. A validation that cannot run -- because the catalogue query itself
failed -- is a validation that failed.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import PrivilegedPrincipalError
from .base import SCHEMA
from .models import TENANT_SCOPED_TABLES

#: The complete runtime profile ADR 0004 promises: NOSUPERUSER, NOBYPASSRLS, NOCREATEDB,
#: NOCREATEROLE, NOREPLICATION. Every one of them is disqualifying, on either identity or
#: on any role either can reach.
#:
#: * ``rolsuper`` and ``rolbypassrls`` skip row security outright.
#: * ``rolreplication`` can open a replication connection and stream the whole cluster,
#:   every tenant included -- row-level security has no bearing on WAL. It also permits
#:   ``pg_basebackup``. A runtime principal that can reach it has read everything.
#: * ``rolcreaterole`` can create roles and grant memberships, which is a route to the
#:   others; ``rolcreatedb`` can create a database it then owns.
#:
#: Both identities are tested because a preselected role hides the authenticated one
#: behind ``current_user``.
_PRIVILEGED_ATTRIBUTES = (
    ("rolsuper", "SUPERUSER"),
    ("rolbypassrls", "BYPASSRLS"),
    ("rolreplication", "REPLICATION"),
    ("rolcreatedb", "CREATEDB"),
    ("rolcreaterole", "CREATEROLE"),
)

_PRIVILEGED_ATTRIBUTE_SQL = """
SELECT DISTINCT r.rolname, r.rolsuper, r.rolbypassrls, r.rolreplication,
                r.rolcreatedb, r.rolcreaterole
FROM pg_catalog.pg_roles r
WHERE (r.rolsuper OR r.rolbypassrls OR r.rolreplication OR r.rolcreatedb OR r.rolcreaterole)
  AND (pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER')
       OR pg_catalog.pg_has_role(session_user, r.oid, 'MEMBER'))
ORDER BY r.rolname
"""

#: Ownership of, or SET-ROLE-reachable ownership of, **any** object the isolation
#: boundary is made of: the database, the schema, every relation in it, every function in
#: it, and every type in it.
#:
#: One UNION rather than five queries so that a new object kind cannot be added to the
#: schema and quietly escape the check by being added to only one of them. Each branch
#: reports a ``kind`` so the rejection can say what was owned. The kind is a single
#: token (``relation:r`` rather than ``relation (r)``) so that ``kind name`` splits
#: back apart on the first space -- it did not, and ``owned_tables`` silently
#: returned nothing while the underlying check was working perfectly.
#:
#: ``pg_has_role(..., 'MEMBER')`` covers both identities and both directions of reach:
#: holding the role, inheriting it, or being able to ``SET ROLE`` to it.
_OWNERSHIP_SQL = """
SELECT 'database' AS kind, d.datname AS name
FROM pg_catalog.pg_database d
WHERE d.datname = pg_catalog.current_database()
  AND (pg_catalog.pg_has_role(current_user, d.datdba, 'MEMBER')
       OR pg_catalog.pg_has_role(session_user, d.datdba, 'MEMBER'))
UNION ALL
SELECT 'schema', n.nspname
FROM pg_catalog.pg_namespace n
WHERE n.nspname = %(schema)s
  AND (pg_catalog.pg_has_role(current_user, n.nspowner, 'MEMBER')
       OR pg_catalog.pg_has_role(session_user, n.nspowner, 'MEMBER'))
UNION ALL
SELECT 'relation:' || c.relkind::text, c.relname
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = %(schema)s
  AND (pg_catalog.pg_has_role(current_user, c.relowner, 'MEMBER')
       OR pg_catalog.pg_has_role(session_user, c.relowner, 'MEMBER'))
UNION ALL
SELECT 'function', p.proname
FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = %(schema)s
  AND (pg_catalog.pg_has_role(current_user, p.proowner, 'MEMBER')
       OR pg_catalog.pg_has_role(session_user, p.proowner, 'MEMBER'))
UNION ALL
SELECT 'type', t.typname
FROM pg_catalog.pg_type t
JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
WHERE n.nspname = %(schema)s
  AND (pg_catalog.pg_has_role(current_user, t.typowner, 'MEMBER')
       OR pg_catalog.pg_has_role(session_user, t.typowner, 'MEMBER'))
ORDER BY 1, 2
"""


@dataclass(frozen=True)
class PrincipalReport:
    """What the server says about the identity a connection is using."""

    current_user: str
    session_user: str
    database: str
    privileged_roles: tuple[str, ...]
    #: Every isolation-boundary object this connection owns or can reach the owner of,
    #: rendered as ``"kind name"``. Empty is the only acceptable value at runtime.
    owned_objects: tuple[str, ...]

    @property
    def owned_tables(self) -> tuple[str, ...]:
        """The tenant-scoped tables among :attr:`owned_objects`.

        Kept as a narrower view because "owns a tenant table" is the finding an operator
        recognises fastest; the check itself is on the whole boundary.
        """
        return tuple(
            name
            for entry in self.owned_objects
            for kind, _, name in (entry.partition(" "),)
            if kind.startswith("relation:") and name in TENANT_SCOPED_TABLES
        )

    @property
    def is_safe(self) -> bool:
        return not self.privileged_roles and not self.owned_objects and self.current_user == self.session_user


def inspect_principal(cursor, *, reset_role: bool = True) -> PrincipalReport:
    """Ask the server who this connection is. Takes a raw DBAPI cursor.

    A raw cursor rather than a SQLAlchemy connection because this runs inside the pool's
    ``connect`` and ``checkout`` events, before any ORM machinery exists for it.

    ``RESET ROLE`` first: a role preselected through libpq ``options`` would otherwise
    make ``current_user`` look restricted while the authenticated identity is not. Callers
    that want to observe the preselected state pass ``reset_role=False``.
    """
    if reset_role:
        cursor.execute("RESET ROLE")

    cursor.execute("SELECT current_user, session_user, current_database()")
    current_user, session_user, database = cursor.fetchone()

    cursor.execute(_PRIVILEGED_ATTRIBUTE_SQL)
    privileged = tuple(
        f"{row[0]} ({', '.join(label for (_, label), held in zip(_PRIVILEGED_ATTRIBUTES, row[1:]) if held)})"
        for row in cursor.fetchall()
    )

    cursor.execute(_OWNERSHIP_SQL, {"schema": SCHEMA})
    owned = tuple(f"{kind} {name}" for kind, name in cursor.fetchall())

    return PrincipalReport(
        current_user=current_user,
        session_user=session_user,
        database=database,
        privileged_roles=privileged,
        owned_objects=owned,
    )


def require_unprivileged_principal(cursor, *, expected_user: str | None = None, stage: str = "connect"):
    """Raise unless this connection is safe to run tenant-scoped queries on.

    Fail-closed in both directions: a disqualifying finding raises, and so does an
    inspection that could not complete.

    ``expected_user`` is the role the URL claimed. When supplied, the authenticated
    ``session_user`` must match it -- so a connection that authenticated as somebody else
    entirely is refused even if that somebody else happens to be unprivileged.
    """
    try:
        report = inspect_principal(cursor)
    except PrivilegedPrincipalError:
        raise
    except Exception as exc:
        raise PrivilegedPrincipalError(
            f"could not establish the connected PostgreSQL principal at {stage}, so the connection "
            f"cannot be assumed to be subject to row-level security: {type(exc).__name__}: {exc}"
        ) from None

    reasons = []
    if report.current_user != report.session_user:
        reasons.append(
            f"it authenticated as {report.session_user!r} but is running as {report.current_user!r}; "
            "a preselected role hides the authenticated identity, which can be restored with RESET ROLE"
        )
    if expected_user and report.session_user != expected_user:
        reasons.append(
            f"the URL names role {expected_user!r} but the connection authenticated as "
            f"{report.session_user!r}"
        )
    if report.privileged_roles:
        reasons.append(
            "it is, or can SET ROLE to, "
            f"{sorted(report.privileged_roles)}, which hold capabilities a runtime principal "
            "must not have (ADR 0004 requires NOSUPERUSER, NOBYPASSRLS, NOREPLICATION, "
            "NOCREATEDB, NOCREATEROLE)"
        )
    if report.owned_objects:
        reasons.append(
            f"it owns, or can SET ROLE to the owner of, isolation-boundary object(s) "
            f"{sorted(report.owned_objects)}. An owner does not need to defeat the boundary, it "
            "can remove it: a table owner can turn FORCE ROW LEVEL SECURITY off or DROP POLICY, "
            "the schema owner can create a relation that shadows a real one, the function owner "
            "can redefine app_current_tenant_id(), and the database owner can ALTER DATABASE ... "
            "SET a parameter for every future session"
        )

    if not reasons:
        return report

    raise PrivilegedPrincipalError(
        f"at {stage}: the application database connection authenticates as {report.session_user!r} "
        f"(running as {report.current_user!r}) on database {report.database!r}, which is not a "
        "restricted tenant-scoped principal: " + "; and ".join(reasons) + ". "
        "Point FIRMBATCH_DATABASE_URL at a non-owner, NOSUPERUSER, NOBYPASSRLS role; use "
        "FIRMBATCH_MIGRATION_DATABASE_URL for privileged work."
    )
