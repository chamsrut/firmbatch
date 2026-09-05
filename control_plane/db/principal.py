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
   * **every function in the schema** -- the policies call ``firmbatch.auth_tenant_id()``
     and ``firmbatch.auth_has_scope()``, and the authentication context is written by
     ``firmbatch.auth_context_begin()``, so their owner can ``CREATE OR REPLACE`` any of
     them to return whatever it likes and every policy predicate follows. Since Milestone
     2.3 that is the whole authentication mechanism, not merely a tenant lookup;
   * **every type in the schema** -- a domain's owner can drop its constraints.

   FORCE currently binds the table owner, but that is one ``ALTER`` away from not being
   true, and none of the other five are bound by it at all.
6. **Any role membership at all.** Not merely membership in a role holding 1-5: a runtime
   principal has no documented need for one, the bootstrap grants none, and a membership is
   the cheapest route to every other condition here -- ``GRANT postgres TO firmbatch_app``
   is one command that looks harmless in a migration. Enumerated with
   ``pg_has_role(..., 'MEMBER')``, which is transitive, so a chain
   ``app -> middle -> privileged`` is reported as two findings rather than none.

7. **Any privilege at all on protected state, and ``EXECUTE`` on any internal function**
   -- held by the connecting identities **or by any role they can reach**. Ownership is
   not the only way to hold something a runtime principal must not have.
   ``ALTER DEFAULT PRIVILEGES FOR ROLE <owner> IN SCHEMA firmbatch GRANT ...`` puts a
   direct grant on ``auth_bindings``, on ``auth_transaction_context`` or on
   ``firmbatch.auth_context_begin`` at the instant they are created -- before any
   ``REVOKE ... FROM PUBLIC`` runs, and untouched by it. A role that can read the
   credential registry can enumerate every tenant's fingerprints; one that can write the
   transaction context can name its own tenant, principal and scope set; one that can
   delete from it can clear the context and bind again as somebody else inside one
   transaction; one that can call the context writer can do the first of those directly.

   The privilege test is run **per reachable role**, and that is the correction rather
   than a detail. ``has_table_privilege`` and ``has_function_privilege`` answer about
   *inherited* privilege, so ``GRANT other TO app WITH INHERIT FALSE, SET TRUE`` makes
   both of them say "no" while a single ``SET ROLE other`` reaches everything ``other``
   holds. Measured against a real server: an application connection carrying exactly that
   membership was certified safe by the previous version of this module, then read
   ``firmbatch.auth_bindings`` one statement later.

   Migration ``0003`` and ``db/roles.py`` both strip exactly these grants. This is the
   third measure, and it is the one that runs on the connection about to be used.

8. **Any column-level privilege on protected state**, held by either identity or by any
   role they can reach. PostgreSQL keeps column grants in ``pg_attribute.attacl``, and a
   role holding *only* column privileges does not appear in ``pg_class.relacl`` at all --
   measured, not assumed: after ``GRANT SELECT (a) ON t TO r`` the relation ACL is still
   NULL. Condition 7 asks ``has_table_privilege``, which answers about the table, so it
   saw none of this and one statement was a complete bypass:

       GRANT SELECT (backend_pid), UPDATE (tenant_id)
       ON firmbatch.auth_transaction_context TO <application role>;

   Measured against a real server before this was written: the hardened checkout accepted
   the connection, and an application authenticated as tenant A could then update the
   protected context row's ``tenant_id`` to tenant B and read tenant B's workspaces --
   the whole isolation boundary, from a grant that names no table privilege at all.

   So a column privilege is checked **independently** of the table privilege rather than
   through ``has_column_privilege``, which answers "at table level *or* column level" and
   would conflate the two. The ACL is read from ``pg_attribute.attacl`` for every
   non-dropped user column of every protected relation, and any entry naming PUBLIC or a
   reachable role disqualifies -- ``SELECT``, ``INSERT``, ``UPDATE`` and ``REFERENCES``
   alike, which is every column privilege PostgreSQL has.

   Migration ``0003`` and ``db/roles.py`` strip column ACLs too, in the same block they
   strip relation ACLs -- and the reason that needed a new loop rather than a wider
   ``REVOKE`` is the same fact: the sanitiser enumerated its grantees from ``relacl``, so
   a role holding only column privileges was never *named*, and the revoke that would
   have removed the grant was therefore never issued. Neither the column names nor the
   role names are written down anywhere: both are enumerated from the catalogue.

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
from .models import PROTECTED_TABLES, TENANT_SCOPED_TABLES
from .roles import INTERNAL_AUTH_FUNCTIONS

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

#: Every role either identity can *become*, directly or transitively.
#:
#: ``pg_has_role(..., 'MEMBER')`` and not ``'USAGE'``, and the difference is the whole of
#: finding 1. ``USAGE`` answers "are this role's privileges inherited", which is what the
#: ``has_*_privilege`` family follows; ``MEMBER`` answers "can this role be reached with
#: ``SET ROLE``", which is what an attacker uses. ``GRANT other TO app WITH INHERIT
#: FALSE, SET TRUE`` makes the first false and the second true, so a check built on
#: effective privilege alone reported a runtime principal safe while one ``SET ROLE`` away
#: from ``EXECUTE`` on the context writer. Measured against a real server before this was
#: written.
#:
#: Both identities, and the reachable set includes each of them: a role is a member of
#: itself, which is what makes this one query the basis of every check below rather than a
#: special case bolted beside them.
_REACHABLE_ROLES_CTE = """
WITH reachable AS (
    SELECT r.oid, r.rolname
    FROM pg_catalog.pg_roles r
    WHERE pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER')
       OR pg_catalog.pg_has_role(session_user, r.oid, 'MEMBER')
)
"""

#: Any role membership at all, beyond the connection's own two identities.
#:
#: The rule is "none", not "none that happens to hold something dangerous". A runtime
#: principal has no documented requirement for a membership -- the disposable test
#: bootstrap grants none, and the production runbook grants none -- and a membership is
#: the cheapest way to acquire every other disqualifying condition later, from a single
#: ``GRANT`` in a migration that looks harmless. The per-object checks below still run
#: against every reachable role, so relaxing this rule for a documented requirement would
#: leave the boundary checked rather than assumed.
_REACHABLE_MEMBERSHIP_SQL = (
    _REACHABLE_ROLES_CTE
    + """
SELECT reachable.rolname
FROM reachable
WHERE reachable.rolname <> current_user
  AND reachable.rolname <> session_user
ORDER BY 1
"""
)

_PRIVILEGED_ATTRIBUTE_SQL = (
    _REACHABLE_ROLES_CTE
    + """
SELECT DISTINCT r.rolname, r.rolsuper, r.rolbypassrls, r.rolreplication,
                r.rolcreatedb, r.rolcreaterole
FROM pg_catalog.pg_roles r
JOIN reachable ON reachable.oid = r.oid
WHERE r.rolsuper OR r.rolbypassrls OR r.rolreplication OR r.rolcreatedb OR r.rolcreaterole
ORDER BY r.rolname
"""
)

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
_OWNERSHIP_SQL = (
    _REACHABLE_ROLES_CTE
    + """
SELECT 'database' AS kind, d.datname AS name
FROM pg_catalog.pg_database d
WHERE d.datname = pg_catalog.current_database()
  AND d.datdba IN (SELECT oid FROM reachable)
UNION ALL
SELECT 'schema', n.nspname
FROM pg_catalog.pg_namespace n
WHERE n.nspname = %(schema)s
  AND n.nspowner IN (SELECT oid FROM reachable)
UNION ALL
SELECT 'relation:' || c.relkind::text, c.relname
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = %(schema)s
  AND c.relowner IN (SELECT oid FROM reachable)
UNION ALL
SELECT 'function', p.proname
FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = %(schema)s
  AND p.proowner IN (SELECT oid FROM reachable)
UNION ALL
SELECT 'type', t.typname
FROM pg_catalog.pg_type t
JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
WHERE n.nspname = %(schema)s
  AND t.typowner IN (SELECT oid FROM reachable)
ORDER BY 1, 2
"""
)


#: Any privilege on a protected relation, or EXECUTE on an internal function, held by
#: either identity. ``to_regclass``/``to_regprocedure`` return NULL rather than raising when
#: the object does not exist, which is what lets this run against a database migrated only
#: as far as ``0001`` -- the downgrade tests do exactly that.
#:
#: ``has_*_privilege`` answers about effective privilege, so a grant reached through a role
#: membership is caught alongside a direct one. The object names are interpolated from
#: module constants, never from anything a caller supplies.
_PROTECTED_ACL_SQL = (
    _REACHABLE_ROLES_CTE
    + """
, objects AS (
    -- Both branches cast to plain ``oid``: a UNION of ``regclass`` and ``regprocedure``
    -- does not type-unify, and the privilege functions take an oid either way.
    SELECT 'protected relation' AS kind, t.name AS name,
           pg_catalog.to_regclass(t.name)::pg_catalog.oid AS oid
    FROM (VALUES %(relations)s) AS t(name)
    UNION ALL
    SELECT 'internal function', f.name,
           pg_catalog.to_regprocedure(f.name)::pg_catalog.oid
    FROM (VALUES %(functions)s) AS f(name)
)
SELECT DISTINCT objects.kind, objects.name
FROM objects
CROSS JOIN reachable
WHERE objects.oid IS NOT NULL
  AND (
    CASE
        WHEN objects.kind = 'protected relation' THEN
            pg_catalog.has_table_privilege(
                reachable.oid, objects.oid,
                'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'
            )
        ELSE
            pg_catalog.has_function_privilege(reachable.oid, objects.oid, 'EXECUTE')
    END
  )
ORDER BY 1, 2
"""
)


#: Any **column-level** privilege on a protected relation, held by PUBLIC or by any role
#: either identity can reach. The other half of the protected-resource boundary, and a
#: separate query on purpose.
#:
#: PostgreSQL stores column grants in ``pg_attribute.attacl``, and a role holding only
#: column privileges is absent from ``pg_class.relacl`` entirely. The query above reads
#: relation privilege, so it saw none of them. That gap was a complete bypass of the
#: isolation boundary in one grant; see condition 8 in the module docstring.
#:
#: ``aclexplode`` rather than ``has_column_privilege``, because the two questions must be
#: answered **independently**: ``has_column_privilege`` returns true when the privilege is
#: held at the *table* level as well, so a report built on it could not distinguish "a
#: column was granted" from "the table was granted", and a column-only grant would be
#: indistinguishable from no grant once the table grant was revoked.
#:
#: ``acl.grantee = 0`` is PUBLIC, which every role reaches by definition.
#: ``NOT attisdropped`` and ``attnum > 0`` keep this to the relation's live user columns:
#: a dropped column keeps a ``pg_attribute`` row, and the system columns have none of this.
#: Nothing here names a column or a role -- both are enumerated from the catalogue -- and
#: ``quote_ident`` renders the column name for the report.
_PROTECTED_COLUMN_ACL_SQL = (
    _REACHABLE_ROLES_CTE
    + """
, protected AS (
    SELECT t.name AS name, pg_catalog.to_regclass(t.name)::pg_catalog.oid AS oid
    FROM (VALUES %(relations)s) AS t(name)
)
SELECT DISTINCT
       'protected column' AS kind,
       protected.name || '.' || pg_catalog.quote_ident(a.attname)
           || ' (' || acl.privilege_type || ')' AS name
FROM protected
JOIN pg_catalog.pg_attribute a ON a.attrelid = protected.oid
CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
WHERE protected.oid IS NOT NULL
  AND a.attnum > 0
  AND NOT a.attisdropped
  AND acl.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'REFERENCES')
  AND (acl.grantee = 0 OR acl.grantee IN (SELECT reachable.oid FROM reachable))
ORDER BY 1, 2
"""
)


def _protected_relations_values() -> str:
    """The ``VALUES`` list of protected relation names, schema-qualified and sorted."""
    return ", ".join(f"('{SCHEMA}.{table}')" for table in sorted(PROTECTED_TABLES))


def _protected_acl_sql() -> str:
    """Render the query with this schema's protected object names.

    A ``VALUES`` list rather than an array parameter so the whole thing is one statement
    with no bind parameters to get wrong in the raw-cursor context this runs in.
    """
    functions = ", ".join(
        f"('{SCHEMA}.{name}({signature})')" for name, signature in INTERNAL_AUTH_FUNCTIONS
    )
    return _PROTECTED_ACL_SQL % {
        "relations": _protected_relations_values(),
        "functions": functions,
    }


def _protected_column_acl_sql() -> str:
    """The column-privilege query, rendered with the same protected relation names."""
    return _PROTECTED_COLUMN_ACL_SQL % {"relations": _protected_relations_values()}


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
    #: Every protected object this connection, or any role it can reach, holds a privilege
    #: on -- rendered the same way. Empty is the only acceptable value at runtime.
    privileged_objects: tuple[str, ...] = ()
    #: Every protected **column** carrying a grant to PUBLIC or to a reachable role, as
    #: ``"protected column <relation>.<column> (<privilege>)"``. Separate from
    #: :attr:`privileged_objects` because column ACLs live in ``pg_attribute.attacl``,
    #: which the relation-privilege test cannot see and ``REVOKE ALL ON TABLE`` does not
    #: clear. Empty is the only acceptable value at runtime.
    privileged_columns: tuple[str, ...] = ()
    #: Every role either identity can ``SET ROLE`` to, other than the two identities
    #: themselves. Empty is the only acceptable value at runtime.
    reachable_roles: tuple[str, ...] = ()

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
        return (
            not self.privileged_roles
            and not self.owned_objects
            and not self.privileged_objects
            and not self.privileged_columns
            and not self.reachable_roles
            and self.current_user == self.session_user
        )


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

    cursor.execute(_protected_acl_sql())
    privileged_objects = tuple(f"{kind} {name}" for kind, name in cursor.fetchall())

    cursor.execute(_protected_column_acl_sql())
    privileged_columns = tuple(f"{kind} {name}" for kind, name in cursor.fetchall())

    cursor.execute(_REACHABLE_MEMBERSHIP_SQL)
    reachable = tuple(row[0] for row in cursor.fetchall())

    return PrincipalReport(
        current_user=current_user,
        session_user=session_user,
        database=database,
        privileged_roles=privileged,
        owned_objects=owned,
        privileged_objects=privileged_objects,
        privileged_columns=privileged_columns,
        reachable_roles=reachable,
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
    if report.reachable_roles:
        reasons.append(
            f"it can SET ROLE to {sorted(report.reachable_roles)}. A runtime principal holds no "
            "role membership at all: a membership granted WITH INHERIT FALSE confers no effective "
            "privilege -- so has_table_privilege and has_function_privilege both answer 'no' -- "
            "while one SET ROLE reaches everything the other role holds. Revoke the membership; "
            "if one is ever genuinely required, it must be documented and every reachable role "
            "must satisfy the same rules as the connecting one"
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
            "can redefine the authentication functions the policies call, and the database owner "
            "can ALTER DATABASE ... SET a parameter for every future session"
        )

    if report.privileged_objects:
        reasons.append(
            f"it holds a privilege on protected object(s) {sorted(report.privileged_objects)}. No "
            "runtime role may hold anything on the credential registry or on the function that "
            "writes an authentication context: the first enumerates every tenant's credential "
            "fingerprints, and the second can name any tenant at all. A grant like this arrives "
            "from ALTER DEFAULT PRIVILEGES at object-creation time, which revoking from PUBLIC "
            "does not touch -- re-run the role wiring in db/roles.py, which strips it"
        )

    if report.privileged_columns:
        reasons.append(
            f"it holds a column-level privilege on protected state {sorted(report.privileged_columns)}. "
            "A column grant lives in pg_attribute.attacl and leaves pg_class.relacl untouched, so it "
            "is checked separately from the table privilege rather than through "
            "has_column_privilege, which conflates the two. "
            "GRANT SELECT (backend_pid), UPDATE (tenant_id) ON the transaction-context relation is "
            "enough on its own: the connection can then rewrite its own authenticated tenant and "
            "read another tenant's rows -- re-run the role wiring in db/roles.py, which strips "
            "column ACLs alongside relation ACLs"
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
