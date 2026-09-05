"""The credential registry, and the hardening of every function that can reach it.

A ``SECURITY DEFINER`` function runs with the privileges of the role that owns it. That is
what makes the authenticated-context design possible -- a caller with no access to the
registry can still present a credential and be told what it authenticates as -- and it is
also the thing most likely to become a standing privilege escalation if any one of its
properties is got wrong. So each property is asserted separately, from the catalogue rather
than from the migration source, because what matters is what the database ended up with:

* **ownership** -- the schema owner, so no runtime role can ``CREATE OR REPLACE`` one;
* **``search_path``** -- fixed and safe on every function, so nothing resolves through
  whatever the caller arrived with;
* **``PUBLIC``** -- no ``EXECUTE`` anywhere, so a future role that gains only ``CONNECT``
  inherits none of this;
* **minimal grants** -- each function executable by exactly the roles that need it, and
  the two that write or inspect the context executable by **nobody**;
* **no dynamic SQL and no caller-controlled object lookup** -- the two shapes that turn a
  definer function into an injection surface.

And the registry itself: ``auth_bindings`` is protected by having no grants rather than
policed by having a policy. A policy bounds a role that holds privileges; here no role
does, which is a stronger and much simpler property -- and one this module asserts by
trying every command from both runtime roles.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DatabaseError, ProgrammingError
from sqlalchemy.pool import NullPool

from firmbatch.control_plane.config import PrivilegedPrincipalError
from firmbatch.control_plane.db import auth, roles
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.models import PROTECTED_TABLES
from firmbatch.control_plane.db.principal import inspect_principal, require_unprivileged_principal

#: Which functions run with the definer's privileges, and which do not. Stated as data so
#: that changing one is a deliberate edit here rather than a silent change of security
#: type in a migration.
#:
#: The accessors are invoker functions that call ``auth_context()``: they add no privilege
#: of their own, they only read back what the definer function is willing to hand over.
#: ``auth_context`` itself must be a definer because the relation it reads belongs to the
#: schema owner and the caller holds nothing on it.
SECURITY_DEFINER = {
    "auth_context_begin": True,
    "auth_require_read_committed": True,
    "auth_require_writable_primary": True,
    "auth_context": True,
    "bind_authenticated_context": True,
    "begin_tenant_provisioning": True,
    "register_auth_binding": True,
    "revoke_auth_binding": True,
    # The one path that writes an audit row. Definer because no role holds INSERT on
    # audit_events -- which is the whole point: the metadata policy is applied inside this
    # function, so it holds under arbitrary runtime SQL and not only when the Python
    # boundary was asked first.
    "append_audit_event": True,
    # Pure predicates over their arguments. They touch no relation and add no privilege,
    # so definer rights would buy nothing; they are executable by nobody, which is what
    # keeps the shape recogniser from being usable as an oracle in its own right.
    "secret_shape": False,
    "audit_require_acceptable_details": False,
    "auth_tenant_id": False,
    "auth_principal_id": False,
    "auth_binding_id": False,
    "auth_actor_kind": False,
    "auth_scopes": False,
    "auth_has_scope": False,
    # A trigger function. PostgreSQL does not check EXECUTE when firing a trigger, so it
    # needs no definer rights and no grant: it runs as whoever is inserting and only
    # overwrites a column of the row being inserted.
    "audit_events_set_occurred_at": False,
}

#: Shapes that make a definer function an injection surface. ``EXECUTE`` builds a
#: statement from text; ``format`` and ``quote_ident`` are how a caller-supplied name gets
#: into one; a ``regclass``/``regprocedure`` lookup would be an object resolved by name at
#: runtime, which is a name somebody could come to control.
#:
#: The migration's ACL sanitiser does use ``EXECUTE format(...)`` -- but it is migration
#: DDL run by the owner over names read from ``pg_catalog``, not a function any caller can
#: reach, and it is not in this list's scope. What is in scope is every function the
#: runtime can call and every one that writes an authentication context.
FORBIDDEN_BODY_FRAGMENTS = (
    "execute format",
    "execute '",
    "execute \"",
    "quote_ident",
    "format(",
    "to_regclass",
    "to_regprocedure",
    "::regclass",
    "::regprocedure",
)

ALL_NAMES = tuple(name for name, _signature in roles.ALL_AUTH_FUNCTIONS)


def _functions(owner_engine) -> dict:
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                """
                SELECT p.proname,
                       pg_get_userbyid(p.proowner) AS owner,
                       p.prosecdef,
                       coalesce(array_to_string(p.proconfig, ','), '') AS config,
                       coalesce(array_to_string(p.proacl, ','), '') AS acl,
                       p.prosrc
                FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = :schema
                """
            ),
            {"schema": SCHEMA},
        ).mappings().all()
    return {row["proname"]: row for row in rows}


def _table_privileges(connection, table: str, role: str) -> set:
    """Exactly which privileges ``role`` holds on ``table``, from the catalogue."""
    return set(
        connection.execute(
            text(
                "SELECT privilege_type FROM information_schema.role_table_grants "
                "WHERE table_schema = :s AND table_name = :t AND grantee = :r"
            ),
            {"s": SCHEMA, "t": table, "r": role},
        ).scalars()
    )


def _acl_entries(acl: str) -> list[str]:
    return [entry for entry in acl.split(",") if entry]


def _grantees(acl: str) -> set[str]:
    """Every role named in an ACL. The empty grantee is PUBLIC and is reported as such."""
    return {entry.split("=", 1)[0] or "PUBLIC" for entry in _acl_entries(acl)}


# --------------------------------------------------------------------------- the functions


def test_every_declared_function_exists(owner_engine):
    """The manifest in ``db/roles.py`` is what the grants are driven from.

    If it named a function the migration did not create, the grants would silently cover
    nothing -- so the two are checked against each other rather than assumed to agree.
    """
    present = _functions(owner_engine)
    missing = [name for name in ALL_NAMES if name not in present]
    assert missing == [], missing
    assert set(SECURITY_DEFINER) == set(ALL_NAMES), (
        "a function was added without deciding whether it runs with definer privileges"
    )


def test_every_function_is_owned_by_the_schema_owner(owner_engine, disposable_database):
    """A function's owner can redefine it, and these decide who every caller is."""
    functions = _functions(owner_engine)
    for name in ALL_NAMES:
        assert functions[name]["owner"] == disposable_database.owner_role, name
        assert functions[name]["owner"] not in (
            disposable_database.application_role,
            disposable_database.provisioning_role,
        ), name


def test_every_function_pins_a_safe_search_path(owner_engine):
    """``SET search_path = pg_catalog`` on the function, not on the session.

    Without it, a definer function resolves unqualified names through whatever
    ``search_path`` the caller arrived with -- and the caller controls that.
    """
    functions = _functions(owner_engine)
    for name in ALL_NAMES:
        config = functions[name]["config"]
        assert "search_path=pg_catalog" in config.replace(" ", ""), f"{name}: proconfig is {config!r}"


def test_the_security_type_of_every_function_is_what_was_decided(owner_engine):
    functions = _functions(owner_engine)
    for name, expected in SECURITY_DEFINER.items():
        assert functions[name]["prosecdef"] is expected, (
            f"{name}: SECURITY DEFINER is {functions[name]['prosecdef']}, expected {expected}"
        )


def test_public_holds_execute_on_nothing(owner_engine):
    """PostgreSQL grants ``EXECUTE`` to ``PUBLIC`` by default; nothing here inherits it."""
    functions = _functions(owner_engine)
    for name in ALL_NAMES:
        acl = functions[name]["acl"]
        assert acl != "", (
            f"{name}: an empty ACL means PostgreSQL's default applies, which grants EXECUTE to PUBLIC"
        )
        assert "PUBLIC" not in _grantees(acl), f"{name}: EXECUTE is granted to PUBLIC ({acl})"


def test_the_context_writer_and_its_guard_are_granted_to_nobody(owner_engine, disposable_database):
    """The functions that must never be callable, asserted from the catalogue.

    ``auth_context_begin`` writes a context: a role that could call it could name any
    tenant, any principal and any scope set, which is the whole property this milestone
    establishes. ``auth_require_read_committed`` is the isolation guard it shares with the
    binding function, and ``audit_events_set_occurred_at`` is a trigger function that needs
    no grant to fire. All three are reached only from inside the database, where the
    current user is the schema owner and the privilege is implicit.
    """
    functions = _functions(owner_engine)
    for name, _signature in roles.INTERNAL_AUTH_FUNCTIONS:
        grantees = _grantees(functions[name]["acl"])
        assert grantees <= {disposable_database.owner_role}, f"{name} is executable by {grantees}"


def test_the_runtime_functions_are_granted_to_exactly_the_runtime_roles(
    owner_engine, disposable_database
):
    functions = _functions(owner_engine)
    for name, _signature in roles.RUNTIME_AUTH_FUNCTIONS:
        grantees = _grantees(functions[name]["acl"])
        assert disposable_database.application_role in grantees, name
        assert disposable_database.provisioning_role in grantees, name
        assert grantees <= {
            disposable_database.owner_role,
            disposable_database.application_role,
            disposable_database.provisioning_role,
        }, f"{name} is executable by {grantees}"


def test_provisioning_only_functions_are_not_granted_to_the_application_role(
    owner_engine, disposable_database
):
    """Establishing a context without a credential is provisioning's, and only its."""
    functions = _functions(owner_engine)
    for name, _signature in roles.PROVISIONING_AUTH_FUNCTIONS:
        grantees = _grantees(functions[name]["acl"])
        assert disposable_database.provisioning_role in grantees, name
        assert disposable_database.application_role not in grantees, name


def test_no_function_builds_a_statement_or_looks_an_object_up_by_a_caller_name(owner_engine):
    """The two shapes that turn a definer function into an injection surface.

    Dynamic SQL is checked for by fragment; the object-lookup rule is checked by asserting
    that the only relation resolved at runtime is the one fixed literal the design uses.
    Every other reference is written out, schema-qualified, at definition time.
    """
    functions = _functions(owner_engine)
    for name in ALL_NAMES:
        body = functions[name]["prosrc"].lower()
        for fragment in FORBIDDEN_BODY_FRAGMENTS:
            assert fragment not in body, f"{name}: body contains {fragment!r}"


def test_every_reference_in_every_body_is_schema_qualified(owner_engine):
    """An unqualified name resolves through ``search_path``, which is why it is pinned.

    Belt and braces: even with the path pinned to ``pg_catalog``, a bare ``auth_bindings``
    would fail rather than resolve -- but it would fail at *call* time, in the middle of an
    authentication, which is the worst place to discover it.
    """
    import re

    functions = _functions(owner_engine)
    #: Whole-word matches only, so ``auth_context`` does not match inside
    #: ``auth_transaction_context`` or ``auth_context_begin`` and produce a finding about a
    #: reference that is not there.
    interesting = (
        "auth_bindings",
        "auth_transaction_context",
        "auth_context",
        "auth_context_begin",
        "auth_require_read_committed",
        "auth_tenant_id",
        "auth_has_scope",
    )
    for name in ALL_NAMES:
        body = functions[name]["prosrc"]
        for token in interesting:
            pattern = re.compile(rf"(?<![\w.])({SCHEMA}\.)?{token}(?![\w])")
            for match in pattern.finditer(body):
                assert match.group(1) is not None, (
                    f"{name}: unqualified reference to {token!r} near "
                    f"{body[max(0, match.start() - 40):match.end() + 20]!r}"
                )


# --------------------------------------------------------------------------- the registry


def test_the_registry_is_owned_by_the_schema_owner(owner_engine, disposable_database):
    with owner_engine.connect() as connection:
        owner = connection.execute(
            text("SELECT tableowner FROM pg_tables WHERE schemaname = :s AND tablename = 'auth_bindings'"),
            {"s": SCHEMA},
        ).scalar_one()
    assert owner == disposable_database.owner_role


#: Every command, per protected relation, in a form that would actually do something if
#: the privilege were there. A generic ``DELETE`` proves less than it looks: the planner
#: refuses on privilege before it touches a row either way, but an ``INSERT`` naming the
#: wrong columns would fail on the column list instead and would go on passing after
#: somebody granted the privilege. So the write statements are written per table.
#:
#: Both protected relations are covered by the same enumeration rather than by an
#: ``auth_bindings`` list with ``auth_transaction_context`` bolted beside it -- an
#: inventory with a special case is an inventory that gets the next object added to the
#: special case.
_PROTECTED_WRITES = {
    "auth_bindings": (
        "INSERT INTO {schema}.auth_bindings (tenant_id, principal_id, fingerprint, scopes) "
        "VALUES (gen_random_uuid(), gen_random_uuid(), repeat('a', 64), ARRAY['workspace:read'])",
        "UPDATE {schema}.auth_bindings SET revoked_at = now()",
    ),
    "auth_transaction_context": (
        # The forged context: this backend's pid, this transaction's id, and any tenant,
        # principal and scope set the caller likes. If this statement ever succeeded, the
        # entire authenticated-context mechanism would be advisory.
        "INSERT INTO {schema}.auth_transaction_context "
        "(backend_pid, xact_id, binding_id, tenant_id, principal_id, actor_kind, scopes, bound_at) "
        "VALUES (pg_backend_pid(), pg_current_xact_id(), NULL, gen_random_uuid(), NULL, "
        "'credential', ARRAY['workspace:write'], now())",
        "UPDATE {schema}.auth_transaction_context SET tenant_id = gen_random_uuid()",
    ),
}


def _protected_statements(table: str):
    insert_sql, update_sql = _PROTECTED_WRITES[table]
    return (
        f"SELECT count(*) FROM {{schema}}.{table}",
        f"SELECT * FROM {{schema}}.{table} LIMIT 1",
        insert_sql,
        update_sql,
        f"DELETE FROM {{schema}}.{table}",
        f"TRUNCATE {{schema}}.{table}",
    )


def test_the_write_statements_cover_every_protected_relation():
    """The enumeration below is data, so this is what keeps it complete.

    A protected relation added to the catalogue without a write statement here would
    otherwise be silently untested by the tests that walk PROTECTED_TABLES.
    """
    assert set(_PROTECTED_WRITES) == set(PROTECTED_TABLES)


@pytest.mark.parametrize("table", sorted(PROTECTED_TABLES))
def test_no_role_holds_any_privilege_on_protected_state(owner_engine, disposable_database, table):
    """Protected by absence of grants, which is why they need no policy.

    A policy constrains a role that holds privileges. Nothing here does, so there is
    nothing for a policy to constrain -- and a policy that looked like it was doing the
    work would be the more dangerous arrangement, because it could be dropped.
    """
    with owner_engine.connect() as connection:
        grants = connection.execute(
            text(
                "SELECT grantee, privilege_type FROM information_schema.role_table_grants "
                "WHERE table_schema = :s AND table_name = :t"
            ),
            {"s": SCHEMA, "t": table},
        ).all()
    grantees = {row[0] for row in grants}
    assert disposable_database.application_role not in grantees, grants
    assert disposable_database.provisioning_role not in grantees, grants
    assert "PUBLIC" not in grantees, grants
    assert grantees <= {disposable_database.owner_role}, grants


@pytest.mark.parametrize("table", sorted(PROTECTED_TABLES))
def test_the_application_role_is_refused_every_command_on_protected_state(
    raw_application_connection, table
):
    """Enumerate, do not sample: read, write, revise, remove and truncate are five grants."""
    for statement in _protected_statements(table):
        with pytest.raises(ProgrammingError) as exc:
            raw_application_connection.execute(text(statement.format(schema=SCHEMA)))
        assert "permission denied" in str(exc.value).lower(), statement
        raw_application_connection.rollback()


@pytest.mark.parametrize("table", sorted(PROTECTED_TABLES))
def test_the_provisioning_role_is_refused_protected_state_too(disposable_database, table):
    """It creates tenants and mints their first credential through a function. It does not
    get to see what it minted, or anybody else's -- and it cannot write itself a context."""
    engine = db_engine.create_application_engine(disposable_database.provisioning_url, pool_size=1)
    try:
        with engine.connect() as connection:
            for statement in _protected_statements(table):
                with pytest.raises(ProgrammingError) as exc:
                    connection.execute(text(statement.format(schema=SCHEMA)))
                assert "permission denied" in str(exc.value).lower(), statement
                connection.rollback()
    finally:
        engine.dispose()


def test_a_runtime_role_cannot_discover_whether_a_fingerprint_exists(
    application_engine, principal_a
):
    """Not even by counting, or by asking about a value it already knows.

    The application role holds the credential it was given, so it can compute the digest.
    What it cannot do is ask the registry anything at all -- which is what makes the
    registry's contents unavailable rather than merely unreadable in bulk.
    """
    import hashlib

    digest = hashlib.sha256(principal_a.credential.reveal().encode("utf-8")).hexdigest()
    with pytest.raises(ProgrammingError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(f"SELECT count(*) FROM {SCHEMA}.auth_bindings WHERE fingerprint = :f"),
                {"f": digest},
            )
    assert "permission denied" in str(exc.value).lower()


def test_the_registry_carries_no_row_level_security_and_says_why(owner_engine):
    """Deliberately not enabled, and asserted so that "we forgot" and "we decided" differ.

    Enabling it without ``FORCE`` would exempt the owner and read as though it did
    something. Enabling it *with* ``FORCE`` would lock out the definer functions that are
    the only legitimate access path. The grant list is the boundary here.
    """
    with owner_engine.connect() as connection:
        enabled, forced = connection.execute(
            text(
                "SELECT c.relrowsecurity, c.relforcerowsecurity FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = :s AND c.relname = 'auth_bindings'"
            ),
            {"s": SCHEMA},
        ).one()
        policies = connection.execute(
            text("SELECT count(*) FROM pg_policies WHERE schemaname = :s AND tablename = 'auth_bindings'"),
            {"s": SCHEMA},
        ).scalar_one()
    assert enabled is False and forced is False
    assert policies == 0


def test_the_owner_can_read_the_registry_so_the_refusals_mean_something(owner_engine, principal_a):
    """A positive control. Without it, every refusal above could be an empty table."""
    with owner_engine.connect() as connection:
        row = connection.execute(
            text(f"SELECT tenant_id, principal_id, scopes FROM {SCHEMA}.auth_bindings WHERE id = :b"),
            {"b": principal_a.binding_id},
        ).one()
    assert row.tenant_id == principal_a.id
    assert row.principal_id == principal_a.principal_id
    assert set(row.scopes) == set(principal_a.scopes)


def test_registering_and_revoking_go_through_functions_that_derive_the_tenant(
    application_engine, new_principal
):
    """The write path exists, and it takes no tenant.

    This is the minimal persistence foundation Milestone 3's credential lifecycle is built
    on: create, revoke, and rotate by doing both. What it deliberately is not is a
    management surface -- there is no listing, no last-use tracking, and no endpoint.
    """
    owner = new_principal("lifecycle")
    with auth.authenticated_transaction(application_engine, owner.credential) as session:
        issued = auth.register_auth_binding(session, principal_id=uuid.uuid4(), scopes=[])
        assert issued.tenant_id == owner.id

    with auth.authenticated_transaction(application_engine, issued.credential) as session:
        assert auth.current_authenticated_context(session).binding_id == issued.binding_id

    with auth.authenticated_transaction(application_engine, owner.credential) as session:
        assert auth.revoke_auth_binding(session, issued.binding_id) is True

    with pytest.raises(auth.AuthenticationError):
        with auth.authenticated_transaction(application_engine, issued.credential):
            pass


# ------------------------------------------------- inherited access control (finding 1)


def _acl_grantees(connection, *, relation: str = None, function: str = None) -> set:
    """Every non-owner role named in one object's ACL."""
    if relation is not None:
        statement = text(
            "SELECT pg_get_userbyid(acl.grantee) FROM pg_class c "
            "CROSS JOIN LATERAL aclexplode(c.relacl) acl "
            "WHERE c.oid = CAST(:name AS regclass) AND acl.grantee <> c.relowner"
        )
        target = relation
    else:
        statement = text(
            "SELECT pg_get_userbyid(acl.grantee) FROM pg_proc p "
            "CROSS JOIN LATERAL aclexplode(p.proacl) acl "
            "WHERE p.oid = CAST(:name AS regprocedure) AND acl.grantee <> p.proowner"
        )
        target = function
    return set(connection.execute(statement, {"name": target}).scalars())


def test_default_privileges_cannot_grant_protected_objects_to_anybody(environment):
    """Finding 1, staged the way it would actually happen.

    ``REVOKE ALL ... FROM PUBLIC`` -- which is all the first version of migration ``0003``
    did -- removes what PostgreSQL hands out by default. It does nothing about this:

        ALTER DEFAULT PRIVILEGES FOR ROLE <owner> IN SCHEMA firmbatch
            GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO <application role>;
            GRANT EXECUTE ON FUNCTIONS TO <application role>;

    which is applied **by the creator, at the instant each object is created** -- so the
    grant is on ``auth_bindings`` and on ``auth_context_begin`` before the migration's next
    statement runs, and no revoke aimed at PUBLIC touches it. An operator who set that up
    for convenience on ordinary tables would have handed the runtime role the credential
    registry and the context writer.

    So: set the rule, run the real migration, and check what the database ended up with.
    The control matters as much as the assertion -- a scratch table created *after* the
    sanitiser proves the rule was still live, so an empty ACL on the protected objects is
    the sanitiser working rather than the rule never having applied.

    Runs on its own disposable database, and reaches the state by downgrading to base and
    upgrading again, so the objects really are created with the rule in force.
    """
    from firmbatch.control_plane import migrate
    from firmbatch.control_plane.db import roles as roles_module
    from firmbatch.control_plane.testing.bootstrap import (
        create_disposable_database,
        drop_disposable_database,
    )

    handle = create_disposable_database(environment)
    beneficiary = handle.application_role
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            migrate.downgrade_to(connection, "base", expected=expected)
            connection.commit()

            connection.execute(
                text(
                    f'ALTER DEFAULT PRIVILEGES IN SCHEMA {SCHEMA} '
                    f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "{beneficiary}"'
                )
            )
            connection.execute(
                text(
                    f'ALTER DEFAULT PRIVILEGES IN SCHEMA {SCHEMA} '
                    f'GRANT EXECUTE ON FUNCTIONS TO "{beneficiary}"'
                )
            )
            connection.commit()
            assert connection.execute(
                text("SELECT count(*) FROM pg_default_acl")
            ).scalar() > 0, "the default-privilege rule was not recorded, so this proves nothing"

            migrate.upgrade_to_head(connection, expected=expected)
            connection.commit()

            # --- the control: the rule is still live -------------------------------
            connection.execute(text(f"CREATE TABLE {SCHEMA}.acl_probe (id int)"))
            connection.commit()
            assert beneficiary in _acl_grantees(connection, relation=f"{SCHEMA}.acl_probe"), (
                "a table created after the migration did not inherit the default privilege, so "
                "the rule was not in force and the assertions below would pass for the wrong reason"
            )

            # --- and the migration stripped it from everything it created ----------
            for table in sorted(PROTECTED_TABLES) + ["tenants", "workspaces", "audit_events"]:
                assert _acl_grantees(connection, relation=f"{SCHEMA}.{table}") == set(), table
            for name, signature in roles_module.ALL_AUTH_FUNCTIONS:
                assert _acl_grantees(
                    connection, function=f"{SCHEMA}.{name}({signature})"
                ) == set(), name

            # --- and the role wiring restores exactly its allowlist ----------------
            connection.execute(text(f"DROP TABLE {SCHEMA}.acl_probe"))
            roles_module.harden_database(connection, handle.database)
            roles_module.revoke_public_table_privileges(connection)
            roles_module.grant_application_role(connection, handle.application_role)
            roles_module.grant_provisioning_role(connection, handle.provisioning_role)
            connection.commit()

            for table in sorted(PROTECTED_TABLES):
                assert _acl_grantees(connection, relation=f"{SCHEMA}.{table}") == set(), table
            for name, signature in roles_module.INTERNAL_AUTH_FUNCTIONS:
                assert _acl_grantees(
                    connection, function=f"{SCHEMA}.{name}({signature})"
                ) == set(), name
            for name, signature in roles_module.RUNTIME_AUTH_FUNCTIONS:
                assert _acl_grantees(connection, function=f"{SCHEMA}.{name}({signature})") == {
                    handle.application_role,
                    handle.provisioning_role,
                }, name
            # The application role holds what the allowlist says on workspaces, and the
            # INSERT/UPDATE/DELETE the default-privilege rule tried to give it on the audit
            # trail are all gone. SELECT and nothing else: appending goes through
            # firmbatch.append_audit_event(), so an INSERT privilege here would be exactly
            # the bypass of the metadata policy that the function exists to close.
            assert _acl_grantees(connection, relation=f"{SCHEMA}.workspaces") == {
                handle.application_role
            }
            assert _table_privileges(connection, "audit_events", handle.application_role) == {
                "SELECT"
            }
            assert _table_privileges(connection, "audit_events", handle.provisioning_role) == set()
    finally:
        # The rule is attached to the owner role, which outlives the database, so it is
        # removed before the role is dropped rather than left on the cluster.
        try:
            with migrate.migration_connection(handle.migration_url) as (connection, _expected):
                for grant in ("SELECT, INSERT, UPDATE, DELETE ON TABLES", "EXECUTE ON FUNCTIONS"):
                    connection.execute(
                        text(
                            f'ALTER DEFAULT PRIVILEGES IN SCHEMA {SCHEMA} '
                            f'REVOKE {grant} FROM "{beneficiary}"'
                        )
                    )
                connection.commit()
        finally:
            drop_disposable_database(handle)


def test_a_runtime_connection_is_refused_when_it_holds_protected_privileges(
    environment, admin_engine
):
    """The third measure: the connection about to be used is asked, and refuses itself.

    Migration ``0003`` and ``db/roles.py`` both strip these grants. This is what happens if
    one is ever added afterwards -- by an operator, by a later migration, by a default
    privilege nobody remembered -- on a database that is already running.
    """
    from firmbatch.control_plane import config
    from firmbatch.control_plane.testing.bootstrap import (
        create_disposable_database,
        drop_disposable_database,
    )

    handle = create_disposable_database(environment)
    try:
        owner = db_engine.create_application_engine(handle.migration_url, validate_principal=False)
        try:
            with owner.connect() as connection:
                connection.execute(
                    text(f'GRANT SELECT ON {SCHEMA}.auth_bindings TO "{handle.application_role}"')
                )
                connection.commit()
        finally:
            owner.dispose()

        engine = db_engine.create_application_engine(handle.application_url)
        try:
            with pytest.raises(config.PrivilegedPrincipalError) as exc:
                engine.connect()
            assert "protected object" in str(exc.value)
            assert "auth_bindings" in str(exc.value)
        finally:
            engine.dispose()
    finally:
        drop_disposable_database(handle)


def test_execute_on_the_context_writer_also_refuses_the_connection(environment):
    """The other half of the same check, and the more dangerous grant of the two."""
    from firmbatch.control_plane import config
    from firmbatch.control_plane.testing.bootstrap import (
        create_disposable_database,
        drop_disposable_database,
    )

    handle = create_disposable_database(environment)
    try:
        owner = db_engine.create_application_engine(handle.migration_url, validate_principal=False)
        try:
            with owner.connect() as connection:
                connection.execute(
                    text(
                        f"GRANT EXECUTE ON FUNCTION "
                        f'{SCHEMA}.auth_context_begin(uuid, uuid, uuid, text, text[]) '
                        f'TO "{handle.application_role}"'
                    )
                )
                connection.commit()
        finally:
            owner.dispose()

        engine = db_engine.create_application_engine(handle.application_url)
        try:
            with pytest.raises(config.PrivilegedPrincipalError) as exc:
                engine.connect()
            assert "auth_context_begin" in str(exc.value)
        finally:
            engine.dispose()
    finally:
        drop_disposable_database(handle)


def test_the_sanitiser_is_the_same_statement_in_both_places(owner_engine):
    """``db/roles.py`` and migration ``0003`` run the identical block, deliberately.

    Two copies, because neither is sufficient alone: the migration leaves a clean database
    even if nobody wires roles, and the wiring leaves a clean database even if a later
    migration inherits a rule ``0003`` could not have known about. Duplicated text is the
    price, and this is what stops the copies drifting.
    """
    import importlib.util
    import pathlib

    from firmbatch.control_plane.db import models as models_module
    from firmbatch.control_plane.db import roles as roles_module

    path = (
        pathlib.Path(models_module.__file__).parent
        / "migrations"
        / "versions"
        / "0003_auth_context_and_audit.py"
    )
    spec = importlib.util.spec_from_file_location("firmbatch_migration_0003_acl", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    def normalised(sql: str) -> str:
        return " ".join(sql.split())

    assert normalised(migration._SANITIZE_SCHEMA_ACL) == normalised(
        roles_module.SCHEMA_ACL_SANITIZER_SQL
    )


# ------------------------------------------------------- reachable roles (SET ROLE)
#
# The correction this section exists for, measured against a real server before it was
# written:
#
#     GRANT other TO firmbatch_app WITH INHERIT FALSE, SET TRUE;
#     GRANT EXECUTE ON FUNCTION firmbatch.auth_context_begin(...) TO other;
#
# ``has_function_privilege(current_user, ...)`` answers **no**, because it follows
# inherited privilege. ``SET ROLE other`` then succeeds and the context writer is one call
# away. The application connection was certified safe by the previous version of
# ``db/principal.py`` and read ``firmbatch.auth_bindings`` one statement later.
#
# Two rules hold now, and both are checked here because either alone would be brittle: a
# runtime principal holds **no role membership at all**, and every object test is run
# against **every reachable role** rather than against the connecting identity.


@pytest.fixture()
def role_probe(admin_engine, owner_engine, disposable_database):
    """Create throwaway roles, grant them things, and take all of it back afterwards.

    Cleanup is explicit rather than left to ``DROP ROLE``: a role holding a privilege in a
    database cannot be dropped, and a membership or an ACL entry that outlived a *failing*
    test would change the answer for every test that ran after it. Everything is undone in
    ``finally``, in the reverse order it was granted, and a cleanup that could not complete
    is raised rather than swallowed -- a leaked membership is exactly the state these tests
    exist to detect.
    """
    created: list[str] = []
    memberships: list[tuple[str, str]] = []
    object_grants: list[str] = []

    class Probe:
        def role(self, label: str) -> str:
            name = f"fb_probe_{label}_{uuid.uuid4().hex[:8]}"
            with admin_engine.connect() as connection:
                connection.execute(text(f'CREATE ROLE "{name}" NOLOGIN'))
            created.append(name)
            return name

        def grant_membership(self, role: str, member: str, *, inherit: bool) -> None:
            """``member`` becomes a member of ``role``.

            ``INHERIT FALSE, SET TRUE`` is the shape that matters: no effective privilege
            passes to ``member``, and ``SET ROLE role`` still works.
            """
            clause = "INHERIT TRUE" if inherit else "INHERIT FALSE"
            with admin_engine.connect() as connection:
                connection.execute(text(f'GRANT "{role}" TO "{member}" WITH {clause}, SET TRUE'))
            memberships.append((role, member))

        def grant_object(self, statement: str) -> None:
            with owner_engine.connect() as connection:
                connection.execute(text(statement))
                connection.commit()
            object_grants.append(statement)

    probe = Probe()
    problems: list[str] = []
    try:
        yield probe
    finally:
        for statement in reversed(object_grants):
            undo = statement.replace("GRANT ", "REVOKE ", 1).replace(" TO ", " FROM ", 1)
            try:
                with owner_engine.connect() as connection:
                    connection.execute(text(undo))
                    connection.commit()
            except Exception as exc:  # pragma: no cover - reported, not hidden
                problems.append(f"{undo}: {exc}")
        with admin_engine.connect() as connection:
            for role, member in reversed(memberships):
                try:
                    connection.execute(text(f'REVOKE "{role}" FROM "{member}"'))
                except Exception as exc:  # pragma: no cover
                    problems.append(f"revoke {role} from {member}: {exc}")
            for name in reversed(created):
                try:
                    connection.execute(text(f'DROP ROLE IF EXISTS "{name}"'))
                except Exception as exc:  # pragma: no cover
                    problems.append(f"drop {name}: {exc}")
        assert problems == [], problems


def _principal_check(disposable_database):
    """``(report, refusal_or_None)`` for the application role, on a plain connection.

    Deliberately not through ``create_application_engine``: that one refuses to finish
    connecting, which is the behaviour under test at the end of this section. Here the
    report itself is the subject, so it is read from a connection with no hardening
    attached and the check is then run by hand on the same cursor.
    """
    engine = create_engine(disposable_database.application_url, future=True, poolclass=NullPool)
    try:
        with engine.connect() as connection:
            cursor = connection.connection.dbapi_connection.cursor()
            try:
                report = inspect_principal(cursor)
                try:
                    require_unprivileged_principal(
                        cursor,
                        expected_user=disposable_database.application_role,
                        stage="probe",
                    )
                except PrivilegedPrincipalError as exc:
                    return report, exc
                return report, None
            finally:
                cursor.close()
    finally:
        engine.dispose()


def test_a_bare_role_membership_is_disqualifying(disposable_database, role_probe):
    """No membership at all, not "no membership in a role that holds something".

    A membership is the cheapest route to every other disqualifying condition -- one
    ``GRANT`` in a migration that reads as housekeeping -- and a runtime principal has no
    documented need for one. The bootstrap grants none, so "none" is a rule that can be
    stated rather than a threshold that has to be tuned.
    """
    harmless = role_probe.role("harmless")
    role_probe.grant_membership(harmless, disposable_database.application_role, inherit=False)

    report, refusal = _principal_check(disposable_database)
    assert report.reachable_roles == (harmless,)
    assert not report.is_safe
    assert refusal is not None
    assert "SET ROLE" in str(refusal)


@pytest.mark.parametrize("inherit", [False, True])
@pytest.mark.parametrize(
    "target, privilege",
    [
        ("FUNCTION {schema}.auth_context_begin(uuid, uuid, uuid, text, text[])", "EXECUTE"),
        ("TABLE {schema}.auth_transaction_context", "SELECT, INSERT, UPDATE, DELETE"),
        ("TABLE {schema}.auth_bindings", "SELECT"),
    ],
)
def test_a_reachable_role_holding_protected_state_is_reported(
    disposable_database, role_probe, target, privilege, inherit
):
    """The per-reachable-role object test, which is the half a blanket rule cannot replace.

    Run with ``INHERIT FALSE`` **and** ``INHERIT TRUE``. The second is what the old check
    already caught, because effective privilege passes to the member; the first is what it
    missed entirely, because ``has_table_privilege`` and ``has_function_privilege`` follow
    inheritance and ``SET ROLE`` does not.
    """
    holder = role_probe.role("holder")
    rendered = target.format(schema=SCHEMA)
    role_probe.grant_object(f'GRANT USAGE ON SCHEMA {SCHEMA} TO "{holder}"')
    role_probe.grant_object(f'GRANT {privilege} ON {rendered} TO "{holder}"')
    role_probe.grant_membership(holder, disposable_database.application_role, inherit=inherit)

    report, refusal = _principal_check(disposable_database)
    assert report.privileged_objects != (), (
        "a role this connection can SET ROLE to holds protected state, and the report is empty"
    )
    assert refusal is not None
    assert "protected object" in str(refusal)


def test_a_membership_chain_is_followed_all_the_way(disposable_database, role_probe):
    """``app -> middle -> holder``, NOINHERIT at every hop.

    ``pg_has_role(..., 'MEMBER')`` is transitive, so the whole chain is enumerated. A check
    that looked one level deep would report this connection safe while two ``SET ROLE``
    statements reached the context writer.
    """
    holder = role_probe.role("chain_holder")
    middle = role_probe.role("chain_middle")
    role_probe.grant_object(f'GRANT USAGE ON SCHEMA {SCHEMA} TO "{holder}"')
    role_probe.grant_object(
        f"GRANT EXECUTE ON FUNCTION {SCHEMA}.auth_context_begin(uuid, uuid, uuid, text, text[]) "
        f'TO "{holder}"'
    )
    role_probe.grant_membership(holder, middle, inherit=False)
    role_probe.grant_membership(middle, disposable_database.application_role, inherit=False)

    report, refusal = _principal_check(disposable_database)
    assert set(report.reachable_roles) == {holder, middle}
    assert any("auth_context_begin" in entry for entry in report.privileged_objects), (
        report.privileged_objects
    )
    assert refusal is not None


def test_reaching_the_migration_owner_is_disqualifying(disposable_database, admin_engine):
    """The most valuable membership an attacker could arrange, and the one to be sure of.

    The schema owner can redefine every authentication function the policies call and can
    turn ``FORCE ROW LEVEL SECURITY`` off, so a runtime principal that can ``SET ROLE`` to
    it has the whole boundary.

    Two outcomes are acceptable and the test accepts either, because which one occurs
    depends on the role graph rather than on anything Firmbatch decides. PostgreSQL refuses
    a membership *loop*, and the bootstrap makes the owner a member of the runtime roles so
    that it can act as the roles it created -- while that edge is present, the reverse
    grant is impossible. Where it is possible, the principal check must refuse the
    connection, and that is asserted on the live report rather than assumed.

    The grant is taken back in ``finally`` either way. An earlier version of this test
    assumed the loop and asserted only the refusal, so on the run where the grant
    *succeeded* it left the application role a member of the schema owner -- and every
    tenant-isolation test that ran afterwards failed. That is the leak these tests exist to
    detect, arriving from the test rather than from the code.
    """
    grant = (
        f'GRANT "{disposable_database.owner_role}" '
        f'TO "{disposable_database.application_role}" WITH INHERIT FALSE, SET TRUE'
    )
    granted = False
    try:
        with admin_engine.connect() as connection:
            try:
                connection.execute(text(grant))
                granted = True
            except DatabaseError as exc:
                assert "is a member of role" in str(exc), str(exc)

        if granted:
            report, refusal = _principal_check(disposable_database)
            assert disposable_database.owner_role in report.reachable_roles
            assert report.owned_objects != (), "the owner's objects are reachable, unreported"
            assert report.privileged_objects != (), "the owner holds protected state, unreported"
            assert refusal is not None
    finally:
        if granted:
            with admin_engine.connect() as connection:
                connection.execute(
                    text(
                        f'REVOKE "{disposable_database.owner_role}" '
                        f'FROM "{disposable_database.application_role}"'
                    )
                )


def test_reachable_ownership_of_a_schema_object_is_disqualifying(
    disposable_database, admin_engine, owner_engine, role_probe
):
    """An owner does not have to defeat the boundary; it can remove it.

    Reached here through a ``SET ROLE``-only membership: the application role inherits
    nothing from the probe role, and the probe role owns ``firmbatch.workspaces``. One
    ``SET ROLE`` and ``ALTER TABLE ... NO FORCE ROW LEVEL SECURITY`` is available.
    """
    probe = role_probe.role("relowner")
    # A new owner needs CREATE on the schema; harden_database revoked it from PUBLIC.
    role_probe.grant_object(f'GRANT CREATE, USAGE ON SCHEMA {SCHEMA} TO "{probe}"')
    # The schema owner must be a member of a role before it can hand an object to it.
    with admin_engine.connect() as connection:
        connection.execute(
            text(f'GRANT "{probe}" TO "{disposable_database.owner_role}" WITH INHERIT TRUE, SET TRUE')
        )
    role_probe.grant_membership(probe, disposable_database.application_role, inherit=False)

    original = disposable_database.owner_role
    try:
        with owner_engine.connect() as connection:
            connection.execute(text(f'ALTER TABLE {SCHEMA}.workspaces OWNER TO "{probe}"'))
            connection.commit()

        report, refusal = _principal_check(disposable_database)
        assert any("workspaces" in entry for entry in report.owned_objects), report.owned_objects
        assert refusal is not None
        assert "isolation-boundary object" in str(refusal)
    finally:
        with owner_engine.connect() as connection:
            connection.execute(text(f'ALTER TABLE {SCHEMA}.workspaces OWNER TO "{original}"'))
            connection.commit()
        with admin_engine.connect() as connection:
            connection.execute(text(f'REVOKE "{probe}" FROM "{original}"'))


def test_a_direct_grant_on_the_transaction_context_is_disqualifying(
    disposable_database, role_probe
):
    """No membership involved: the connecting role itself is given the grant.

    ``auth_transaction_context`` is the mechanism rather than a record of it, so this is
    the grant that would turn the whole authenticated-context design into a convention --
    a role holding ``INSERT`` here writes itself any tenant, principal and scope set it
    likes. It arrives from ``ALTER DEFAULT PRIVILEGES``, and until this correction the
    inventory the principal check walked contained ``auth_bindings`` and nothing else.
    """
    role_probe.grant_object(
        f"GRANT INSERT ON TABLE {SCHEMA}.auth_transaction_context "
        f'TO "{disposable_database.application_role}"'
    )
    report, refusal = _principal_check(disposable_database)
    assert any("auth_transaction_context" in entry for entry in report.privileged_objects), (
        report.privileged_objects
    )
    assert refusal is not None


def test_a_membership_granted_after_wiring_fails_the_next_checkout(
    disposable_database, role_probe
):
    """The window a connect-time-only check leaves open, closed on the pool checkout.

    A connection validated minutes ago is not a connection that is still safe: memberships
    change while it sits idle. The engine here has a pool of one, so the second checkout is
    provably the same physical connection that passed the first.
    """
    engine = db_engine.create_application_engine(
        disposable_database.application_url, pool_size=1, max_overflow=0
    )
    try:
        with engine.connect() as connection:
            assert connection.execute(text("SELECT 1")).scalar() == 1

        holder = role_probe.role("late")
        role_probe.grant_object(f'GRANT USAGE ON SCHEMA {SCHEMA} TO "{holder}"')
        role_probe.grant_object(f'GRANT SELECT ON TABLE {SCHEMA}.auth_bindings TO "{holder}"')
        role_probe.grant_membership(holder, disposable_database.application_role, inherit=False)

        with pytest.raises(PrivilegedPrincipalError) as exc:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        assert "pool checkout" in str(exc.value) or "at connect" in str(exc.value)
    finally:
        engine.dispose()


def test_the_application_connection_is_refused_outright(disposable_database, role_probe):
    """End to end: with a membership in place, an application engine will not connect."""
    holder = role_probe.role("refuse")
    role_probe.grant_membership(holder, disposable_database.application_role, inherit=False)
    engine = db_engine.create_application_engine(
        disposable_database.application_url, pool_size=1, max_overflow=0
    )
    try:
        with pytest.raises(PrivilegedPrincipalError):
            with engine.connect():
                pass
    finally:
        engine.dispose()


def test_the_ordinary_application_principal_reaches_nothing(disposable_database):
    """The control. Without any of the above, the report is empty in every dimension.

    Without this the tests above could all be passing because the check refuses
    everything, which would be a different bug with the same green.
    """
    report, refusal = _principal_check(disposable_database)
    assert refusal is None, str(refusal)
    assert report.reachable_roles == ()
    assert report.privileged_objects == ()
    assert report.owned_objects == ()
    assert report.privileged_roles == ()
    assert report.is_safe


# ------------------------------------------------ column-level ACLs (pg_attribute.attacl)
#
# The correction this section exists for, measured against a real server before it was
# written. As the migration owner:
#
#     GRANT SELECT (backend_pid), UPDATE (tenant_id)
#     ON firmbatch.auth_transaction_context TO <application role>;
#
# The hardened checkout accepted the connection. The application could then authenticate
# as tenant A, ``UPDATE`` the protected context row's ``tenant_id`` to tenant B, and read
# tenant B's workspaces -- the whole isolation boundary, from a grant that confers no
# *table* privilege at all and that no part of this suite was looking at.
#
# Two reasons the earlier checks missed it, and both are corrected rather than patched:
#
# * PostgreSQL stores column grants in ``pg_attribute.attacl``, and a role holding only
#   column privileges never appears in ``pg_class.relacl`` -- measured below rather than
#   taken from the manual. The sanitiser in migration ``0003`` and in ``db/roles.py``
#   built its grantee list from ``relacl``, so the role was never *named* and the
#   ``REVOKE`` that would have removed the grant was never issued. The verb was never the
#   problem; the enumeration was, which is why the correction is another loop over another
#   catalogue rather than a wider ``REVOKE``.
# * ``has_table_privilege`` answers about the table, so the per-reachable-role privilege
#   test in ``db/principal.py`` returned nothing.
#
# So the column ACL is now read directly from ``pg_attribute``, for every non-dropped user
# column of every protected relation, and **independently** of the table privilege --
# ``has_column_privilege`` would have conflated the two, because it answers "at table level
# or column level" and cannot distinguish a column-only grant from a table grant.


def _column_acl_grantees(connection, relation: str) -> set:
    """Every non-owner grantee of a column privilege on ``relation``, from the catalogue."""
    rows = connection.execute(
        text(
            "SELECT pg_get_userbyid(acl.grantee), a.attname, acl.privilege_type "
            "FROM pg_class c "
            "JOIN pg_attribute a ON a.attrelid = c.oid "
            "CROSS JOIN LATERAL aclexplode(a.attacl) acl "
            "WHERE c.oid = CAST(:name AS regclass) "
            "  AND a.attnum > 0 AND NOT a.attisdropped "
            "  AND acl.grantee <> c.relowner"
        ),
        {"name": relation},
    ).all()
    return {(grantee, column, privilege) for grantee, column, privilege in rows}


def test_the_reported_column_grant_exploit_is_refused_at_connect(
    disposable_database, role_probe
):
    """The exact grant from the review, and the exact thing it used to buy.

    ``SELECT (backend_pid)`` is how the attacker finds its own context row and
    ``UPDATE (tenant_id)`` is how it rewrites which tenant that row says it is. Neither is
    a table privilege, so nothing before this correction saw either of them.
    """
    role_probe.grant_object(
        f"GRANT SELECT (backend_pid), UPDATE (tenant_id) "
        f"ON {SCHEMA}.auth_transaction_context "
        f'TO "{disposable_database.application_role}"'
    )

    report, refusal = _principal_check(disposable_database)
    assert report.privileged_columns != (), (
        "a column grant on the transaction context is not reported at all"
    )
    assert any("backend_pid" in entry for entry in report.privileged_columns), (
        report.privileged_columns
    )
    assert any("tenant_id" in entry for entry in report.privileged_columns), (
        report.privileged_columns
    )
    assert not report.is_safe
    assert refusal is not None
    assert "column-level privilege" in str(refusal)

    # And the hardened engine refuses to finish connecting, which is what an application
    # would actually meet.
    engine = db_engine.create_application_engine(
        disposable_database.application_url, pool_size=1, max_overflow=0
    )
    try:
        with pytest.raises(PrivilegedPrincipalError):
            with engine.connect():
                pass
    finally:
        engine.dispose()


def test_a_table_privilege_is_not_what_reports_a_column_privilege(
    disposable_database, role_probe
):
    """The two are checked independently, which is why they are two fields.

    ``has_column_privilege`` returns true when the privilege is held at the table level as
    well, so a report built on it could not tell "somebody granted a column" from
    "somebody granted the table" -- and revoking the table grant would have made the
    column grant invisible again. Here there is no table grant at all, and the column
    finding stands on its own.
    """
    role_probe.grant_object(
        f"GRANT SELECT (fingerprint) ON {SCHEMA}.auth_bindings "
        f'TO "{disposable_database.application_role}"'
    )
    report, _ = _principal_check(disposable_database)
    assert report.privileged_objects == (), (
        "a column-only grant was reported as a table privilege, so the two are not separate"
    )
    assert any("auth_bindings" in entry for entry in report.privileged_columns), (
        report.privileged_columns
    )


@pytest.mark.parametrize(
    "relation, column, privilege",
    [
        ("auth_transaction_context", "tenant_id", "UPDATE"),
        ("auth_transaction_context", "backend_pid", "SELECT"),
        ("auth_transaction_context", "scopes", "UPDATE"),
        ("auth_bindings", "fingerprint", "SELECT"),
        ("auth_bindings", "tenant_id", "REFERENCES"),
        ("auth_bindings", "scopes", "UPDATE"),
    ],
)
def test_any_column_privilege_on_protected_state_disqualifies(
    disposable_database, role_probe, relation, column, privilege
):
    """SELECT, UPDATE and REFERENCES, on both protected relations.

    ``INSERT`` is covered by the parametrisation below, which walks every column privilege
    PostgreSQL has against one column. The rule is "any", not "any that happens to be
    obviously dangerous": a column grant on the credential registry lets a role enumerate
    fingerprints one column at a time, and a column grant on the context relation is the
    mechanism itself.
    """
    role_probe.grant_object(
        f"GRANT {privilege} ({column}) ON {SCHEMA}.{relation} "
        f'TO "{disposable_database.application_role}"'
    )
    report, refusal = _principal_check(disposable_database)
    assert any(relation in entry and column in entry for entry in report.privileged_columns), (
        report.privileged_columns
    )
    assert refusal is not None
    assert not report.is_safe


@pytest.mark.parametrize("privilege", ["SELECT", "INSERT", "UPDATE", "REFERENCES"])
def test_every_column_privilege_postgresql_has_is_covered(
    disposable_database, role_probe, privilege
):
    """All four, named one at a time, so a partial rule is a failing test rather than a gap."""
    role_probe.grant_object(
        f"GRANT {privilege} (tenant_id) ON {SCHEMA}.auth_transaction_context "
        f'TO "{disposable_database.application_role}"'
    )
    report, refusal = _principal_check(disposable_database)
    assert any(privilege in entry for entry in report.privileged_columns), (
        privilege,
        report.privileged_columns,
    )
    assert refusal is not None


@pytest.mark.parametrize("inherit", [False, True])
def test_a_column_grant_on_a_reachable_role_is_reported(
    disposable_database, role_probe, inherit
):
    """The ``SET ROLE``-only case, which is the one an effective-privilege test cannot see.

    ``INHERIT FALSE, SET TRUE`` passes no effective privilege to the member, so every
    ``has_*_privilege`` answer is "no" -- and one ``SET ROLE`` reaches the column grant.
    Run with ``INHERIT TRUE`` as well, because a rule that only caught the exotic case
    would be a rule with a hole where the ordinary case is.
    """
    holder = role_probe.role("colholder")
    role_probe.grant_object(f'GRANT USAGE ON SCHEMA {SCHEMA} TO "{holder}"')
    role_probe.grant_object(
        f'GRANT UPDATE (tenant_id) ON {SCHEMA}.auth_transaction_context TO "{holder}"'
    )
    role_probe.grant_membership(holder, disposable_database.application_role, inherit=inherit)

    report, refusal = _principal_check(disposable_database)
    assert report.privileged_columns != (), report
    assert refusal is not None
    assert "column-level privilege" in str(refusal)


def test_a_column_grant_reached_through_a_membership_chain_is_reported(
    disposable_database, role_probe
):
    """``app -> middle -> holder``, NOINHERIT at every hop, with the grant on the far end.

    The reachable-role enumeration is transitive, and the column check runs against the
    whole reachable set rather than against the connecting identity -- so two ``SET ROLE``
    statements away is the same finding as zero.
    """
    holder = role_probe.role("col_chain_holder")
    middle = role_probe.role("col_chain_middle")
    role_probe.grant_object(f'GRANT USAGE ON SCHEMA {SCHEMA} TO "{holder}"')
    role_probe.grant_object(
        f'GRANT SELECT (fingerprint) ON {SCHEMA}.auth_bindings TO "{holder}"'
    )
    role_probe.grant_membership(holder, middle, inherit=False)
    role_probe.grant_membership(middle, disposable_database.application_role, inherit=False)

    report, refusal = _principal_check(disposable_database)
    assert set(report.reachable_roles) == {holder, middle}
    assert any("auth_bindings" in entry for entry in report.privileged_columns), (
        report.privileged_columns
    )
    assert refusal is not None


def test_a_column_grant_to_public_is_reported(disposable_database, role_probe):
    """PUBLIC is reachable by every role, so a column grant to it disqualifies everybody."""
    role_probe.grant_object(
        f"GRANT SELECT (tenant_id) ON {SCHEMA}.auth_transaction_context TO PUBLIC"
    )
    report, refusal = _principal_check(disposable_database)
    assert report.privileged_columns != (), report
    assert refusal is not None


def test_a_column_grant_after_provisioning_fails_the_next_checkout(
    disposable_database, role_probe
):
    """The idle-connection window, for column grants.

    A pool of one, so the second checkout is provably the same physical connection that
    passed the first. The grant arrives *after* the role was wired and after the
    connection was validated, which is exactly how it would arrive in production -- an
    operator granting one column for a dashboard.
    """
    engine = db_engine.create_application_engine(
        disposable_database.application_url, pool_size=1, max_overflow=0
    )
    try:
        with engine.connect() as connection:
            assert connection.execute(text("SELECT 1")).scalar() == 1

        role_probe.grant_object(
            f"GRANT SELECT (backend_pid), UPDATE (tenant_id) "
            f"ON {SCHEMA}.auth_transaction_context "
            f'TO "{disposable_database.application_role}"'
        )

        with pytest.raises(PrivilegedPrincipalError) as exc:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        assert "column-level privilege" in str(exc.value)
        assert "pool checkout" in str(exc.value) or "at connect" in str(exc.value)
    finally:
        engine.dispose()


def test_a_failing_column_probe_leaves_no_grant_and_no_role_behind(
    disposable_database, owner_engine, role_probe
):
    """The probe fixture's cleanup, asserted rather than assumed.

    Everything above grants column privileges on the *shared* session database, so a
    cleanup that missed one would silently change the answer for every test that ran
    afterwards -- and the failure would surface somewhere else entirely. This test grants,
    asserts the grant is visible, and then relies on ``role_probe``'s ``finally`` to take
    it back; :func:`test_the_ordinary_application_principal_reaches_no_column_either` is
    the control that runs afterwards and sees a clean database.
    """
    role_probe.grant_object(
        f"GRANT SELECT (tenant_id) ON {SCHEMA}.auth_transaction_context "
        f'TO "{disposable_database.application_role}"'
    )
    with owner_engine.connect() as connection:
        present = _column_acl_grantees(connection, f"{SCHEMA}.auth_transaction_context")
    assert (disposable_database.application_role, "tenant_id", "SELECT") in present


def test_the_ordinary_application_principal_reaches_no_column_either(
    disposable_database, owner_engine
):
    """The control, and the cleanup check for every test in this section.

    Without a deliberate grant the protected relations carry no column ACL at all and the
    report is empty in the new dimension as well as the old ones. If a probe above leaked
    a grant, this is where it shows up.
    """
    with owner_engine.connect() as connection:
        for table in sorted(PROTECTED_TABLES):
            assert _column_acl_grantees(connection, f"{SCHEMA}.{table}") == set(), table

    report, refusal = _principal_check(disposable_database)
    assert refusal is None, str(refusal)
    assert report.privileged_columns == ()
    assert report.is_safe


def test_both_sanitisers_remove_a_column_only_acl(environment):
    """Both copies of the sanitiser, on the ACL neither of them used to reach.

    Runs on its own disposable database, because it revokes every non-owner privilege in
    the schema and re-wires the roles afterwards -- doing that to the shared session
    database would leave every later test running against a differently wired one.

    Four things are established, in order:

    1. a column-only grant leaves ``pg_class.relacl`` empty of that grantee, so a
       sanitiser that enumerates grantees from ``relacl`` never names the role and never
       revokes anything from it. That is the actual defect, measured here rather than
       taken from the documentation, and it is why the fix is a second enumeration rather
       than a wider ``REVOKE``;
    2. ``db/roles.py``'s sanitiser removes the column grant;
    3. migration ``0003``'s copy, executed verbatim from the migration file, removes it
       too. Both copies are exercised because either one alone would leave a database
       clean only if somebody happened to run that half;
    4. a column grant to PUBLIC is removed as well.
    """
    import importlib.util
    import pathlib

    from firmbatch.control_plane import migrate
    from firmbatch.control_plane.db import models as models_module
    from firmbatch.control_plane.db import roles as roles_module
    from firmbatch.control_plane.testing.bootstrap import (
        create_disposable_database,
        drop_disposable_database,
    )

    path = (
        pathlib.Path(models_module.__file__).parent
        / "migrations"
        / "versions"
        / "0003_auth_context_and_audit.py"
    )
    spec = importlib.util.spec_from_file_location("firmbatch_migration_0003_columns", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    handle = create_disposable_database(environment)
    beneficiary = handle.application_role
    relation = f"{SCHEMA}.auth_transaction_context"
    try:
        engine = migrate.create_migration_engine(handle.migration_url)
        try:

            def grant(connection):
                connection.execute(
                    text(
                        f"GRANT SELECT (backend_pid), UPDATE (tenant_id) ON {relation} "
                        f'TO "{beneficiary}"'
                    )
                )
                connection.commit()

            expected = {
                (beneficiary, "backend_pid", "SELECT"),
                (beneficiary, "tenant_id", "UPDATE"),
            }

            with engine.connect() as connection:
                # 1. the defect itself: a column-only grantee is invisible in relacl, so
                #    the loop that revokes from every relacl grantee never sees it.
                grant(connection)
                assert _column_acl_grantees(connection, relation) == expected
                assert beneficiary not in _acl_grantees(connection, relation=relation), (
                    "a column-only grantee appears in pg_class.relacl, so the premise of this "
                    "correction is wrong and the relation loop would already have revoked it"
                )

                # 2. db/roles.py's sanitiser.
                roles_module.sanitize_schema_privileges(connection)
                connection.commit()
                assert _column_acl_grantees(connection, relation) == set()

                # 3. and migration 0003's copy, run verbatim from the migration file.
                grant(connection)
                assert _column_acl_grantees(connection, relation) == expected
                connection.execute(text(migration._SANITIZE_SCHEMA_ACL))
                connection.commit()
                assert _column_acl_grantees(connection, relation) == set()

                # And a column grant to PUBLIC, which is a separate pass.
                connection.execute(text(f"GRANT SELECT (tenant_id) ON {relation} TO PUBLIC"))
                connection.commit()
                assert _column_acl_grantees(connection, relation) != set()
                roles_module.sanitize_schema_privileges(connection)
                connection.commit()
                assert _column_acl_grantees(connection, relation) == set()

                # The wiring is restored, so the database is left the way the sanitiser's
                # callers always leave it: stripped, then granted exactly the allowlist.
                roles_module.harden_database(connection, handle.database)
                roles_module.revoke_public_table_privileges(connection)
                roles_module.grant_application_role(connection, handle.application_role)
                roles_module.grant_provisioning_role(connection, handle.provisioning_role)
                connection.commit()
        finally:
            engine.dispose()

        # And an application engine connects cleanly against the re-wired database, which
        # is what says the sanitiser removed the column ACL without removing anything the
        # allowlist puts back.
        application = db_engine.create_application_engine(handle.application_url)
        try:
            with application.connect() as connection:
                assert connection.execute(text("SELECT 1")).scalar() == 1
        finally:
            application.dispose()
    finally:
        drop_disposable_database(handle)
