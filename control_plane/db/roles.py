"""Grants that separate application access from privileged provisioning.

Deliberately **not** part of the Alembic migration. Role names differ per environment
(and per disposable test database), so putting them in a migration would either hard-code
an environment into the schema history or make that history non-deterministic. The schema
migration is role-agnostic; role wiring is an explicit admin action, run here by the test
bootstrap and by an operator runbook in production.

Three roles, three jobs:

``owner``
    Owns the schema and runs migrations. Privileged by definition. Not used at runtime.

``application``
    What the API, controller and validator connect as. Non-owner, ``NOSUPERUSER``,
    ``NOBYPASSRLS``, no DDL, **no TEMP**, and **no role membership of any kind** -- see
    ``db/principal.py``, which refuses a connection that can ``SET ROLE`` to anything. It
    gets DML on tenant-scoped tables and is fully subject to the isolation policies --
    including on ``tenants``, where it may read only its own row and may not INSERT at all,
    and on ``idempotency_records`` and ``outbox_events``, where it may read and append but
    never update or delete.

    On ``audit_events`` it holds ``SELECT`` and **not** ``INSERT``. Appending goes through
    ``firmbatch.append_audit_event()``, which applies the whole bounded-metadata policy
    inside the database; an ``INSERT`` privilege here would make that policy advisory,
    because the table's check constraints bound a details document's size and shape and say
    nothing about its content.

``provisioning``
    Creates tenants. Also non-owner, non-superuser and non-``BYPASSRLS``: it is
    privileged only in the narrow sense that it holds INSERT on ``tenants``, and it holds
    no privilege whatsoever on tenant data. Since Milestone 2.3 it cannot even name the
    tenant it is creating: ``firmbatch.begin_tenant_provisioning()`` generates the id.

Both runtime roles remain under RLS. Nothing here hands out ``BYPASSRLS``, and nothing
may: the point of forcing row security is that no runtime role can turn it off.

**Neither runtime role holds anything at all on the protected tables.** The credential
registry ``auth_bindings`` and the transaction-context relation
``auth_transaction_context`` are protected by the absence of grants rather than by a
policy, so "the runtime cannot enumerate credential fingerprints or their tenant mappings"
and "the runtime cannot write itself a context" are privilege facts rather than predicates
that have to be got right. The same applies to every internal function, ``auth_context_begin``
above all: it is granted to nobody, because a role that could call it could name any tenant
it liked.

**And the wiring is revision-aware.** Every statement below names a table or a function,
and which of those exist depends on the schema revision. See ``RevisionPlan``: two
supported revisions, an explicit plan for each, and a refusal for anything else.

**Nothing is inherited from a PostgreSQL default.** PUBLIC loses ``CREATE`` on every
schema, ``TEMP`` on the database, ``EXECUTE`` on every authentication function, and all
table privileges; each runtime role is then granted back only what it needs. Defaults
change between major versions and differ between a stock server and a hardened one, so a
grant that is only correct because of a default is a grant that is only correct here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import Connection, text

from .base import SCHEMA, VERSION_TABLE
from .models import PROTECTED_TABLES

_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


class UnsupportedSchemaRevision(RuntimeError):
    """The database's schema revision is not one this module knows how to wire.

    Raised rather than worked around. The grants below name tables and functions, so a
    revision that does not have them is a revision whose grant set this module has not
    been told. Guessing -- by catching ``UndefinedTable`` and continuing -- would leave a
    half-wired database that looks provisioned, which is the failure mode worth spending
    an explicit error to avoid.
    """


#: The functions every isolation policy calls, and the ones a caller uses to acquire and
#: inspect its own context. Policies are evaluated with the privileges of the querying
#: role, so a role without EXECUTE here cannot read a tenant-scoped table at all -- which
#: is the correct failure direction.
#:
#: ``bind_authenticated_context`` is here because presenting a credential is what a
#: runtime connection does; ``register_auth_binding`` and ``revoke_auth_binding`` are here
#: because Milestone 3's credential lifecycle runs on the application role. Neither
#: confers authority by being callable: both derive the tenant from the context and refuse
#: without ``credential:manage``.
RUNTIME_AUTH_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("auth_context", ""),
    ("auth_tenant_id", ""),
    ("auth_principal_id", ""),
    ("auth_binding_id", ""),
    ("auth_actor_kind", ""),
    ("auth_scopes", ""),
    ("auth_has_scope", "text"),
    ("bind_authenticated_context", "text"),
    ("register_auth_binding", "uuid, text[], timestamptz"),
    ("revoke_auth_binding", "uuid"),
    # The only way any role writes an audit row. No role holds INSERT on audit_events, so
    # this is not the polite path but the only one -- which is what makes the bounded
    # metadata policy hold under arbitrary runtime SQL rather than only when the Python
    # boundary was asked first.
    ("append_audit_event", "text, text, text, uuid, uuid, jsonb"),
)

#: Establishing context without a credential. Only the provisioning role, and only
#: because a tenant has no credential until it exists. It takes no arguments and
#: generates the tenant id itself, so it cannot be pointed at an existing tenant.
PROVISIONING_AUTH_FUNCTIONS: tuple[tuple[str, str], ...] = (("begin_tenant_provisioning", ""),)

#: Executable by **nobody**.
#:
#: ``auth_context_begin`` writes the authentication context: a role that could call it
#: could name any tenant and any scope set it liked, which is precisely the property
#: migration ``0003`` exists to remove. ``auth_require_read_committed`` is the isolation
#: guard it and the binding function share. Both are called only from inside
#: ``SECURITY DEFINER`` functions, where the current user is the schema owner and the
#: privilege is implicit.
#:
#: ``audit_events_set_occurred_at`` is a trigger function. PostgreSQL does not check
#: ``EXECUTE`` when firing a trigger, so it needs no grant to do its job -- and granting
#: one would only make it callable as an ordinary function, which nothing needs.
#: ``auth_require_writable_primary`` is the standby and read-only guard the context writer
#: calls before its write. ``secret_shape`` and ``audit_require_acceptable_details`` are
#: the metadata policy the audit append function applies; they are internal so that the
#: policy has exactly one caller and cannot be probed as an oracle in its own right.
INTERNAL_AUTH_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("auth_context_begin", "uuid, uuid, uuid, text, text[]"),
    ("auth_require_read_committed", ""),
    ("auth_require_writable_primary", ""),
    ("secret_shape", "text"),
    ("audit_require_acceptable_details", "jsonb"),
    ("audit_events_set_occurred_at", ""),
)

ALL_AUTH_FUNCTIONS: tuple[tuple[str, str], ...] = (
    RUNTIME_AUTH_FUNCTIONS + PROVISIONING_AUTH_FUNCTIONS + INTERNAL_AUTH_FUNCTIONS
)


# ------------------------------------------------------------------ revision awareness
#
# Role wiring lives outside Alembic (see the module docstring) but it is not
# schema-independent: every statement below names a table or a function, and which ones
# exist depends on the revision the database is at.
#
# Before this was explicit, ``grant_application_role`` at revision ``0002`` failed on
# ``REVOKE ALL ON TABLE firmbatch.auth_bindings FROM PUBLIC`` -- ``UndefinedTable`` --
# because the wiring assumed the Milestone 2.3 objects. Measured, not inferred: migrate to
# ``0003``, provision, downgrade to ``0002``, provision again. Two supported revisions and
# an explicit refusal for everything else is the correction; catching the undefined-object
# error and continuing would have been a half-wired database that reported success.
#
# **Application code at head does not run against schema ``0002``.** The revision is
# supported here so that a controlled rollback can still provision and validate its roles,
# and so that the round trip is testable. Nothing else in this package targets it: the
# authenticated context, the audit trail and every Milestone 2.3 policy are ``0003``
# objects, and a runtime process pointed at ``0002`` would fail at its first bind.

M2_2_REVISION = "0002_idempotency_and_outbox"
M2_3_REVISION = "0003_auth_context_and_audit"

#: The one function the ``0001``/``0002`` policies called: the caller-set tenant setting
#: that Milestone 2.3 removed. Named here only so the ``0002`` grant set can be reproduced
#: exactly during a rollback.
_LEGACY_TENANT_CONTEXT_FUNCTION: tuple[tuple[str, str], ...] = (("app_current_tenant_id", ""),)


@dataclass(frozen=True)
class RevisionPlan:
    """Exactly what this module grants, at one schema revision.

    Data rather than branching code, so that "what does the application role hold at
    ``0002``?" is a value a test can read and compare, and so that re-upgrading restores
    the same grant set it had before rather than whatever the current code happens to do.
    """

    revision: str
    #: Every relation this plan touches. Checked to exist before anything is granted.
    tables: tuple[str, ...]
    #: Functions granted to both runtime roles.
    common_functions: tuple[tuple[str, str], ...]
    #: Functions granted to the provisioning role alone.
    provisioning_functions: tuple[tuple[str, str], ...]
    #: Functions granted to nobody, checked to exist and asserted to stay ungranted.
    internal_functions: tuple[tuple[str, str], ...]
    #: ``(table, privileges)`` for the application role.
    application_grants: tuple[tuple[str, str], ...]
    #: ``(table, privileges)`` for the provisioning role.
    provisioning_grants: tuple[tuple[str, str], ...]


_M2_2_PLAN = RevisionPlan(
    revision=M2_2_REVISION,
    tables=("tenants", "workspaces", "idempotency_records", "outbox_events"),
    common_functions=_LEGACY_TENANT_CONTEXT_FUNCTION,
    provisioning_functions=(),
    internal_functions=(),
    application_grants=(
        ("tenants", "SELECT"),
        ("workspaces", "SELECT, INSERT, UPDATE, DELETE"),
        ("idempotency_records", "SELECT, INSERT"),
        ("outbox_events", "SELECT, INSERT"),
    ),
    provisioning_grants=(("tenants", "SELECT, INSERT, UPDATE"),),
)

_M2_3_PLAN = RevisionPlan(
    revision=M2_3_REVISION,
    tables=(
        "tenants",
        "workspaces",
        "idempotency_records",
        "outbox_events",
        "audit_events",
        *sorted(PROTECTED_TABLES),
    ),
    common_functions=RUNTIME_AUTH_FUNCTIONS,
    provisioning_functions=PROVISIONING_AUTH_FUNCTIONS,
    internal_functions=INTERNAL_AUTH_FUNCTIONS,
    application_grants=(
        # Read-only on tenants: an application resolves its own tenant, it never creates one.
        ("tenants", "SELECT"),
        ("workspaces", "SELECT, INSERT, UPDATE, DELETE"),
        # Append-only, and narrower than the tables above on purpose (Milestone 2.2). The
        # application claims idempotency keys and appends outbox events; it never revises a
        # committed claim or edits an event it has already published. UPDATE and DELETE are
        # not granted, so the attempt is an error rather than a silent no-op -- migration
        # 0002 additionally gives these tables no UPDATE or DELETE policy at all, which
        # binds every other role including the owner.
        ("idempotency_records", "SELECT, INSERT"),
        ("outbox_events", "SELECT, INSERT"),
        # SELECT and **not** INSERT. Reading the trail is a policed operation; writing one
        # goes through firmbatch.append_audit_event(), which is the only path that applies
        # the metadata policy to a row a runtime role composed. A direct INSERT privilege
        # would have made that boundary advisory: the check constraints on the table bound
        # a document's size and shape, never its content.
        ("audit_events", "SELECT"),
    ),
    # Provisioning gets tenants and nothing else. No INSERT on audit_events either: it
    # appends through the same hardened function, and it cannot read the trail back
    # because reading is the audit:read capability and a provisioning context has none.
    provisioning_grants=(("tenants", "SELECT, INSERT, UPDATE"),),
)

#: The revisions this module can wire. Anything else -- an older one, a newer one, a
#: database with no version table, or a version table carrying more than one row -- is
#: refused rather than guessed at.
REVISION_PLANS: dict[str, RevisionPlan] = {
    _M2_2_PLAN.revision: _M2_2_PLAN,
    _M2_3_PLAN.revision: _M2_3_PLAN,
}

SUPPORTED_REVISIONS: tuple[str, ...] = tuple(sorted(REVISION_PLANS))


def schema_revision(connection: Connection) -> str:
    """The single Alembic revision this database is at, or a refusal.

    Refuses a database with no version table, an empty one, and one carrying more than a
    single row -- the last being a branched or half-stamped history, which is precisely
    the state where guessing a grant set does the most damage.
    """
    present = connection.execute(
        text(
            "SELECT pg_catalog.to_regclass(:relation) IS NOT NULL"
        ),
        {"relation": f"{SCHEMA}.{VERSION_TABLE}"},
    ).scalar_one()
    if not present:
        raise UnsupportedSchemaRevision(
            f"{SCHEMA}.{VERSION_TABLE} does not exist, so this database has no schema revision to "
            "wire roles for. Run the migrations first; role wiring is a separate admin action and "
            "deliberately not part of them."
        )
    rows = connection.execute(
        text(f"SELECT version_num FROM {SCHEMA}.{VERSION_TABLE} ORDER BY version_num")
    ).scalars().all()
    if len(rows) != 1:
        raise UnsupportedSchemaRevision(
            f"{SCHEMA}.{VERSION_TABLE} holds {len(rows)} rows; role wiring requires exactly one "
            "revision. A branched or partially stamped history has no single grant set, and "
            "picking one would leave a database that looks provisioned and is not."
        )
    revision = rows[0]
    if revision not in REVISION_PLANS:
        raise UnsupportedSchemaRevision(
            f"schema revision {revision!r} has no role-wiring plan. Supported: "
            f"{list(SUPPORTED_REVISIONS)}. Upgrade to head, or add the plan -- do not let the "
            "grants fail object by object."
        )
    return revision


def revision_plan(connection: Connection) -> RevisionPlan:
    """The plan for this database's revision, after checking every object in it exists.

    The existence check is the other half of refusing to guess. At head this is what turns
    "a Milestone 2.3 object is unexpectedly missing" into an error naming it, rather than
    into an ``UndefinedTable`` from whichever statement happened to reach it first.
    """
    plan = REVISION_PLANS[schema_revision(connection)]
    missing = []
    for table in plan.tables:
        if not connection.execute(
            text("SELECT pg_catalog.to_regclass(:name) IS NOT NULL"),
            {"name": f"{SCHEMA}.{table}"},
        ).scalar_one():
            missing.append(f"table {table}")
    functions = plan.common_functions + plan.provisioning_functions + plan.internal_functions
    for name, signature in functions:
        if not connection.execute(
            text("SELECT pg_catalog.to_regprocedure(:name) IS NOT NULL"),
            {"name": _function(name, signature)},
        ).scalar_one():
            missing.append(f"function {name}({signature})")
    if missing:
        raise UnsupportedSchemaRevision(
            f"the database reports schema revision {plan.revision!r} but {sorted(missing)} "
            "do not exist. The schema and its stamped revision disagree; wiring roles against it "
            "would produce a database that reports success and denies access at runtime."
        )
    return plan


def _function(name: str, signature: str) -> str:
    return f"{SCHEMA}.{name}({signature})"


def quote_identifier(name: str) -> str:
    """Validate then quote a SQL identifier.

    Role names reach this module from the environment, and ``GRANT`` takes no bind
    parameters. Validating against a strict pattern before quoting is what keeps that
    from being an injection point.
    """
    if not _IDENTIFIER.match(name or ""):
        raise ValueError(f"{name!r} is not an acceptable SQL identifier for a role or table")
    return f'"{name}"'


#: The one statement that makes the schema's access control a *stated* fact rather than an
#: inherited one, duplicated verbatim in migration ``0003``.
#:
#: ``REVOKE ... FROM PUBLIC`` removes what PostgreSQL hands out by default. It does not
#: remove what an operator arranged with
#:
#:     ALTER DEFAULT PRIVILEGES FOR ROLE <owner> IN SCHEMA firmbatch
#:         GRANT SELECT ON TABLES TO <some role>;
#:
#: which is applied by the *creator* at the instant each object is created -- so the grant
#: is already on ``auth_bindings`` before the next statement of the migration runs, and no
#: amount of revoking from PUBLIC touches it. The grantees are therefore enumerated from
#: the catalogue and every one of them is revoked, leaving the owner's inherent rights and
#: nothing else. The explicit grants below then put back exactly the allowlist, and only
#: that.
#:
#: **Column ACLs need their own pass, and the reason is the enumeration rather than the
#: verb.** PostgreSQL keeps column grants in ``pg_attribute.attacl``, and a role holding
#: only column privileges never appears in ``pg_class.relacl`` -- measured: after
#: ``GRANT SELECT (a) ON t TO r`` the relation ACL is still NULL. The relation loop above
#: takes its grantee list from ``relacl``, so such a role was never named and the
#: ``REVOKE`` that would have removed the grant was never issued. Measured against a real
#: server: ``GRANT SELECT (backend_pid), UPDATE (tenant_id) ON
#: firmbatch.auth_transaction_context`` survived this block intact -- a complete bypass of
#: the isolation boundary, because the grantee can then rewrite its own authenticated
#: tenant. ``db/principal.py`` condition 8 refuses such a connection; these two loops are
#: what stop one being left behind in the first place.
#:
#: The PUBLIC pass is deliberately kept even though the unconditional
#: ``REVOKE ALL ON <table> FROM PUBLIC`` above already clears a column grant to PUBLIC.
#: The column boundary is then self-contained: narrowing that other loop cannot silently
#: reopen this one.
#:
#: Run in **both** places on purpose. The migration leaves a clean database even if nobody
#: ever calls this module; this module leaves a clean database even if a later migration
#: inherits a default privilege that ``0003`` could not have known about. Neither is
#: sufficient alone: default-privilege rules outlive a migration, and a database can be
#: migrated without being wired.
#:
#: Every identifier comes from ``pg_catalog`` and is rendered by ``format('%I')`` or by a
#: ``regclass``/``regprocedure``/``regtype`` cast, all of which quote. No name here comes
#: from a caller, and no environment's role names are written down.
SCHEMA_ACL_SANITIZER_SQL = """
DO $sanitize$
DECLARE
    entry record;
BEGIN
    EXECUTE 'REVOKE ALL ON SCHEMA firmbatch FROM PUBLIC';
    FOR entry IN
        SELECT pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_namespace n
        CROSS JOIN LATERAL pg_catalog.aclexplode(n.nspacl) acl
        WHERE n.nspname = 'firmbatch'
          AND acl.grantee <> 0
          AND acl.grantee <> n.nspowner
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON SCHEMA firmbatch FROM %I', entry.grantee);
    END LOOP;

    FOR entry IN
        SELECT c.oid::pg_catalog.regclass AS obj,
               CASE WHEN c.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END AS kind,
               c.relowner
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'firmbatch' AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON %s %s FROM PUBLIC', entry.kind, entry.obj);
    END LOOP;

    FOR entry IN
        SELECT c.oid::pg_catalog.regclass AS obj,
               CASE WHEN c.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END AS kind,
               pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) acl
        WHERE n.nspname = 'firmbatch'
          AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
          AND acl.grantee <> 0
          AND acl.grantee <> c.relowner
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL ON %s %s FROM %I', entry.kind, entry.obj, entry.grantee
        );
    END LOOP;

    FOR entry IN
        SELECT DISTINCT c.oid::pg_catalog.regclass AS obj,
               a.attname AS column_name
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
        CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
        WHERE n.nspname = 'firmbatch'
          AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND a.attnum > 0
          AND NOT a.attisdropped
          AND acl.grantee = 0
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL (%I) ON TABLE %s FROM PUBLIC', entry.column_name, entry.obj
        );
    END LOOP;

    FOR entry IN
        SELECT DISTINCT c.oid::pg_catalog.regclass AS obj,
               a.attname AS column_name,
               pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
        CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
        WHERE n.nspname = 'firmbatch'
          AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND a.attnum > 0
          AND NOT a.attisdropped
          AND acl.grantee <> 0
          AND acl.grantee <> c.relowner
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL (%I) ON TABLE %s FROM %I',
            entry.column_name, entry.obj, entry.grantee
        );
    END LOOP;

    FOR entry IN
        SELECT p.oid::pg_catalog.regprocedure AS obj
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'firmbatch'
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', entry.obj);
    END LOOP;

    FOR entry IN
        SELECT p.oid::pg_catalog.regprocedure AS obj,
               pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl
        WHERE n.nspname = 'firmbatch'
          AND acl.grantee <> 0
          AND acl.grantee <> p.proowner
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM %I', entry.obj, entry.grantee);
    END LOOP;

    FOR entry IN
        SELECT t.oid::pg_catalog.regtype AS obj
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = 'firmbatch' AND t.typtype IN ('c', 'd', 'e', 'r')
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON TYPE %s FROM PUBLIC', entry.obj);
    END LOOP;

    FOR entry IN
        SELECT t.oid::pg_catalog.regtype AS obj,
               pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(t.typacl) acl
        WHERE n.nspname = 'firmbatch'
          AND t.typtype IN ('c', 'd', 'e', 'r')
          AND acl.grantee <> 0
          AND acl.grantee <> t.typowner
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON TYPE %s FROM %I', entry.obj, entry.grantee);
    END LOOP;
END;
$sanitize$
"""


def sanitize_schema_privileges(connection: Connection) -> None:
    """Strip every privilege on every object in the schema except the owner's own.

    Called before the grants, so what a role holds afterwards is exactly what
    :func:`grant_application_role` and :func:`grant_provisioning_role` gave it.
    """
    connection.execute(text(SCHEMA_ACL_SANITIZER_SQL))


def harden_database(connection: Connection, database: str) -> None:
    """Remove the implicit rights every role gets just by being able to connect.

    ``TEMP`` is the one that matters most. PostgreSQL grants it to PUBLIC by default, and
    a role holding it can ``CREATE TEMP TABLE workspaces (...)``; because the temporary
    schema is searched before ``search_path``, every later unqualified reference on that
    connection resolves to the forgery -- for the life of a pooled connection, and with
    row-level security attached to a table the query no longer reaches.

    ``CREATE`` on ``public`` is revoked for the same family of reasons. PostgreSQL 15+
    already does it; doing it explicitly means the guarantee does not depend on which
    server version an environment happens to run.
    """
    # Refuse an unsupported revision here, at the first of the four wiring calls, so that
    # a database this module cannot wire is reported before anything has been changed.
    schema_revision(connection)
    connection.execute(text(f"REVOKE TEMPORARY ON DATABASE {quote_identifier(database)} FROM PUBLIC"))
    connection.execute(text("REVOKE CREATE ON SCHEMA public FROM PUBLIC"))
    # Everything inside the pinned schema, from everybody but its owner -- not only from
    # PUBLIC, and not only the objects this module happens to name. See
    # SCHEMA_ACL_SANITIZER_SQL for why revoking from PUBLIC is not enough.
    sanitize_schema_privileges(connection)


def revoke_public_table_privileges(connection: Connection) -> None:
    """Belt and braces: no tenant-owned table is reachable by PUBLIC.

    Both categories, for different reasons. A tenant-scoped table is policed and must not
    additionally be reachable by a role nobody granted it to; a protected table has no
    grants at all and this is what keeps it that way.

    Walks the revision's own table list. At ``0002`` the protected tables do not exist yet,
    and naming them anyway is what made role provisioning fail after a rollback.
    """
    for table in revision_plan(connection).tables:
        connection.execute(
            text(f"REVOKE ALL ON TABLE {quote_identifier(SCHEMA)}.{quote_identifier(table)} FROM PUBLIC")
        )


def _grant_common(connection: Connection, quoted: str, plan: RevisionPlan) -> None:
    connection.execute(text(f"GRANT USAGE ON SCHEMA {quote_identifier(SCHEMA)} TO {quoted}"))
    # Required to evaluate the isolation policies at all, and to acquire a context in the
    # first place; granted explicitly because harden_database took it away from PUBLIC.
    #
    # **Not** granted here: auth_context_begin, which writes the context. A role that
    # could call it could forge any tenant and any scope set, so it is executable by
    # nobody and every path to it goes through a SECURITY DEFINER function that decided
    # what the context may be. See INTERNAL_AUTH_FUNCTIONS.
    for name, signature in plan.common_functions:
        connection.execute(text(f"GRANT EXECUTE ON FUNCTION {_function(name, signature)} TO {quoted}"))
    # No GRANT TEMPORARY, and no GRANT CREATE. A runtime role creates nothing.
    #
    # TEMPORARY still matters for the reason ADR 0004 gives -- a temporary relation can
    # shadow a Firmbatch table for an unqualified reference. It is no longer load-bearing
    # for the authentication context: that lived in pg_temp in the first version of
    # Milestone 2.3, until ``DISCARD TEMP`` turned out to drop it. It is an ordinary
    # protected table now, and no privilege of the runtime's reaches it at all.


def _grant_tables(connection: Connection, quoted: str, grants) -> None:
    schema = quote_identifier(SCHEMA)
    for table, privileges in grants:
        connection.execute(
            text(f"GRANT {privileges} ON TABLE {schema}.{quote_identifier(table)} TO {quoted}")
        )


def grant_application_role(connection: Connection, role: str) -> None:
    """Give ``role`` exactly what a tenant-scoped application needs, and nothing more.

    The set is :data:`RevisionPlan.application_grants` for the revision the database is
    actually at, so a rollback to ``0002`` restores exactly the Milestone 2.2 grants and a
    re-upgrade restores exactly the Milestone 2.3 ones.
    """
    quoted = quote_identifier(role)
    plan = revision_plan(connection)
    _grant_common(connection, quoted, plan)
    _grant_tables(connection, quoted, plan.application_grants)
    # No privilege on alembic_version: the schema history is not application data.
    #
    # And **nothing at all** on auth_bindings or auth_transaction_context. The credential
    # registry is not application data either, and the application never reads a
    # fingerprint: it presents a credential to firmbatch.bind_authenticated_context() and
    # is told what context it got. The transaction context is the mechanism itself -- a
    # role that could write it would name its own tenant, and one that could delete from it
    # would bind again as somebody else inside one transaction. See PROTECTED_TABLES.


def grant_provisioning_role(connection: Connection, role: str) -> None:
    """Give ``role`` tenant provisioning, and no access to tenant data."""
    quoted = quote_identifier(role)
    plan = revision_plan(connection)
    _grant_common(connection, quoted, plan)
    for name, signature in plan.provisioning_functions:
        connection.execute(text(f"GRANT EXECUTE ON FUNCTION {_function(name, signature)} TO {quoted}"))
    _grant_tables(connection, quoted, plan.provisioning_grants)
    # Intentionally no grant on workspaces, on idempotency_records, on outbox_events, on
    # audit_events, or on auth_bindings. Provisioning creates the scope; it does not get to
    # look inside it, it has no business reading another role's idempotency keys or the
    # events they produced, and it may not enumerate credential fingerprints or their
    # tenant mappings. It records what it did through firmbatch.append_audit_event(), the
    # same hardened path the application uses, and it cannot read the trail back.
