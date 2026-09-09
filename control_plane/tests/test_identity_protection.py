"""The identity plane is protected state: reached through definer functions and nothing else.

What ``test_protected_auth_state.py`` asserts for the Milestone 2.3 registry, this asserts
for the Milestone 3.1 identity functions and tables: every function exists, is owned by
the schema owner, pins its search path, has the security type that was decided, builds no
statement from text and resolves no object by a caller's name; the application role can
execute exactly the application functions and nothing internal; no runtime role holds a
privilege on the identity tables or the identity transaction context; the triggers that
make revocation structural are installed and enabled; and the ACL sanitiser strips a stray
grant on any of it.
"""

from __future__ import annotations

import re

import pytest
from psycopg.errors import InsufficientPrivilege
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from firmbatch.control_plane import migrate
from firmbatch.control_plane.db import roles
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.models import IDENTITY_TABLES, PROTECTED_TABLES
from firmbatch.control_plane.db import accounts
from firmbatch.control_plane.security.secrets import Secret
from firmbatch.control_plane.testing.bootstrap import create_disposable_database, drop_disposable_database
from firmbatch.control_plane.tests.identity_helpers import (
    PASSWORD,
    login_session,
    owner_with_workspace,
    signup_verified,
    workspace_session,
)

APPLICATION_NAMES = tuple(name for name, _signature in roles.IDENTITY_APPLICATION_FUNCTIONS)
AUTHENTICATOR_NAMES = tuple(name for name, _signature in roles.IDENTITY_AUTHENTICATOR_FUNCTIONS)
INTERNAL_NAMES = tuple(name for name, _signature in roles.IDENTITY_INTERNAL_FUNCTIONS)
ALL_NAMES = APPLICATION_NAMES + AUTHENTICATOR_NAMES + INTERNAL_NAMES

#: The decision, written out. ``SECURITY DEFINER`` for everything that reads or writes a
#: protected relation or the transaction context; invoker rights for the pure functions
#: (a normaliser, a digest, a role table, a bound check) and for the two append-only
#: trigger functions, which only ever refuse.
SECURITY_DEFINER = {
    **{name: True for name in APPLICATION_NAMES},
    # The trusted-issuer boundary (Milestone 3.1): every one is SECURITY DEFINER over a
    # protected relation or the transaction context.
    **{name: True for name in AUTHENTICATOR_NAMES},
    "purge_expired_unverified_accounts": True,
    "membership_role_scopes": False,
    "identity_normalize_email": False,
    "identity_mint_secret": False,
    "identity_fingerprint": False,
    "identity_request_fingerprint": False,
    "identity_require_ttl": False,
    "identity_context": True,
    "identity_context_write": True,
    "identity_context_narrow": True,
    "identity_require_session": True,
    "identity_issue_token": True,
    "identity_replay": True,
    "identity_claim": True,
    "identity_active_owner_count": True,
    "memberships_revocation_cascade": True,
    "workspace_directory_sync": True,
    "account_tokens_append_only": False,
    "account_idempotency_records_append_only": False,
}

#: Same list as ``test_protected_auth_state.FORBIDDEN_BODY_FRAGMENTS``, restated so this
#: module reads on its own.
FORBIDDEN_BODY_FRAGMENTS = (
    "execute format",
    "execute '",
    'execute "',
    "quote_ident",
    "format(",
    "to_regclass",
    "to_regprocedure",
    "::regclass",
    "::regprocedure",
)

#: Relations and functions an identity body refers to. Every reference must be written
#: schema-qualified; an unqualified one would resolve through ``search_path`` at call time.
QUALIFIED_TOKENS = (
    "auth_bindings",
    "auth_transaction_context",
    "identity_transaction_context",
    "account_passwords",
    "account_tokens",
    "workspace_directory",
    "browser_sessions",
    "workspace_invitations",
    "account_idempotency_records",
    "idempotency_records",
    "outbox_events",
    "auth_context",
    "auth_context_begin",
    "auth_has_scope",
    "auth_tenant_id",
    "auth_require_writable_primary",
    "auth_require_read_committed",
    "append_audit_event",
    "secret_shape",
    "membership_role_scopes",
    "identity_context",
    "identity_context_write",
    "identity_context_narrow",
    "identity_require_session",
    "identity_require_ttl",
    "identity_issue_token",
    "identity_replay",
    "identity_claim",
    "identity_fingerprint",
    "identity_mint_secret",
    "identity_request_fingerprint",
    "identity_normalize_email",
    "identity_active_owner_count",
    "workspace_membership_authority",
)


def _functions(owner_engine) -> dict:
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                """
                SELECT p.proname,
                       pg_get_userbyid(p.proowner) AS owner,
                       p.prosecdef,
                       p.provolatile,
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


def _grantees(acl: str) -> set[str]:
    return {entry.split("=", 1)[0] or "PUBLIC" for entry in acl.split(",") if entry}


def _without_comments(body: str) -> str:
    return "\n".join(re.sub(r"--.*$", "", line) for line in body.splitlines())


# --------------------------------------------------------------------------- the functions


def test_the_inventories_agree_with_the_migration_and_each_other():
    """``db/roles.py`` and migration ``0005`` each list every identity function by hand."""
    import importlib.util
    import pathlib

    from firmbatch.control_plane.db import models

    path = pathlib.Path(models.__file__).parent / "migrations" / "versions" / "0005_identity_and_membership.py"
    spec = importlib.util.spec_from_file_location("firmbatch_migration_0005_protection", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    declared = {(name, signature): audience for name, signature, audience in migration.FUNCTIONS}
    assert set(declared) == set(roles.ALL_IDENTITY_FUNCTIONS)
    assert {key for key, audience in declared.items() if audience == "application"} == set(
        roles.IDENTITY_APPLICATION_FUNCTIONS
    )
    assert {key for key, audience in declared.items() if audience == "authenticator"} == set(
        roles.IDENTITY_AUTHENTICATOR_FUNCTIONS
    )
    assert {key for key, audience in declared.items() if audience == "internal"} == set(
        roles.IDENTITY_INTERNAL_FUNCTIONS
    )
    assert set(SECURITY_DEFINER) == set(ALL_NAMES)
    assert len(set(ALL_NAMES)) == len(ALL_NAMES)
    # The identity inventory is disjoint from the Milestone 2 ones: nothing is redefined.
    earlier = {name for name, _s in roles.ALL_AUTH_FUNCTIONS + roles.ALL_LIFECYCLE_FUNCTIONS}
    assert not earlier & set(ALL_NAMES)


def test_every_identity_function_exists_and_is_owned_by_the_schema_owner(owner_engine, disposable_database):
    functions = _functions(owner_engine)
    for name in ALL_NAMES:
        assert name in functions, f"{name} is not installed"
        assert functions[name]["owner"] == disposable_database.owner_role, name


def test_every_identity_function_pins_a_safe_search_path(owner_engine):
    functions = _functions(owner_engine)
    for name in ALL_NAMES:
        assert functions[name]["config"] == "search_path=pg_catalog", (name, functions[name]["config"])


def test_the_security_type_of_every_identity_function_is_what_was_decided(owner_engine):
    functions = _functions(owner_engine)
    for name, expected in SECURITY_DEFINER.items():
        assert functions[name]["prosecdef"] is expected, (
            f"{name}: SECURITY DEFINER is {functions[name]['prosecdef']}, expected {expected}"
        )
    # And the role table is a pure function: immutable, so a policy may call it freely.
    assert functions["membership_role_scopes"]["provolatile"] == "i"


def test_public_holds_execute_on_no_identity_function(owner_engine):
    functions = _functions(owner_engine)
    for name in ALL_NAMES:
        acl = functions[name]["acl"]
        assert acl != "", f"{name}: an empty ACL means PostgreSQL's default applies, which grants EXECUTE to PUBLIC"
        assert "PUBLIC" not in _grantees(acl), f"{name}: EXECUTE is granted to PUBLIC ({acl})"


def test_the_application_functions_are_granted_to_the_application_role_alone(owner_engine, disposable_database):
    """The provisioning role, the lifecycle writer and the authenticator get none of these."""
    functions = _functions(owner_engine)
    for name in APPLICATION_NAMES:
        grantees = _grantees(functions[name]["acl"])
        assert grantees == {disposable_database.owner_role, disposable_database.application_role}, (
            f"{name} is executable by {grantees}"
        )


def test_the_authenticator_functions_are_granted_to_the_authenticator_role_alone(owner_engine, disposable_database):
    """The trusted-issuer boundary (Milestone 3.1): login, session opening and recovery are
    the authenticator role's and the ordinary application role's not at all."""
    functions = _functions(owner_engine)
    assert AUTHENTICATOR_NAMES, "the authenticator inventory must not be empty"
    for name in AUTHENTICATOR_NAMES:
        grantees = _grantees(functions[name]["acl"])
        assert grantees == {disposable_database.owner_role, disposable_database.authenticator_role}, (
            f"{name} is executable by {grantees}"
        )
        assert disposable_database.application_role not in grantees, (
            f"{name} must not be executable by the application role"
        )


def test_the_internal_functions_are_executable_by_nobody(owner_engine, disposable_database):
    functions = _functions(owner_engine)
    for name in INTERNAL_NAMES:
        grantees = _grantees(functions[name]["acl"])
        assert grantees <= {disposable_database.owner_role}, f"{name} is executable by {grantees}"


def test_the_application_role_sees_the_same_boundary_from_its_side(application_engine):
    """``has_function_privilege`` as the runtime role: exactly the application functions."""
    with db_engine.transaction(application_engine) as session:
        for name, signature in roles.ALL_IDENTITY_FUNCTIONS:
            executable = session.execute(
                text("SELECT has_function_privilege(current_user, :f, 'EXECUTE')"),
                {"f": f"{SCHEMA}.{name}({signature})"},
            ).scalar_one()
            assert executable is (name in APPLICATION_NAMES), name


@pytest.mark.parametrize(
    "statement",
    (
        f"SELECT {SCHEMA}.identity_context()",
        f"SELECT {SCHEMA}.identity_context_write('session', gen_random_uuid(), NULL, NULL, NULL, NULL, NULL, true, NULL)",
        f"SELECT {SCHEMA}.identity_context_narrow(ARRAY[]::text[])",
        f"SELECT {SCHEMA}.identity_require_session('workspace', false)",
        f"SELECT {SCHEMA}.identity_issue_token(gen_random_uuid(), 'email_verification', interval '1 hour')",
        f"SELECT {SCHEMA}.identity_replay('x', NULL, NULL)",
        f"SELECT {SCHEMA}.identity_claim('x', NULL, NULL, NULL, 'x', 'x', gen_random_uuid(), NULL)",
        f"SELECT {SCHEMA}.identity_active_owner_count(gen_random_uuid(), gen_random_uuid())",
        f"SELECT {SCHEMA}.identity_mint_secret('fbs_')",
        f"SELECT {SCHEMA}.identity_fingerprint('x')",
        f"SELECT {SCHEMA}.identity_request_fingerprint('{{}}'::jsonb)",
        f"SELECT {SCHEMA}.identity_normalize_email('x@example.com')",
        f"SELECT {SCHEMA}.identity_require_ttl(interval '1 hour', interval '1 day')",
        f"SELECT {SCHEMA}.memberships_revocation_cascade()",
        f"SELECT {SCHEMA}.workspace_directory_sync()",
        f"SELECT {SCHEMA}.account_tokens_append_only()",
        f"SELECT {SCHEMA}.account_idempotency_records_append_only()",
        f"SELECT {SCHEMA}.purge_expired_unverified_accounts(interval '1 day')",
    ),
)
def test_the_application_role_cannot_call_an_internal_function_even_with_a_session(application_engine, statement):
    who, _ = owner_with_workspace(application_engine)
    with pytest.raises(ProgrammingError) as exc:
        with workspace_session(application_engine, who) as (session, _):
            session.execute(text(statement))
    assert isinstance(exc.value.orig, InsufficientPrivilege)
    assert "permission denied for function" in str(exc.value.orig)


def test_no_identity_function_builds_a_statement_or_resolves_an_object_by_name(owner_engine):
    functions = _functions(owner_engine)
    for name in ALL_NAMES:
        body = functions[name]["prosrc"].lower()
        for fragment in FORBIDDEN_BODY_FRAGMENTS:
            assert fragment not in body, f"{name}: body contains {fragment!r}"


def test_every_reference_in_every_identity_body_is_schema_qualified(owner_engine):
    functions = _functions(owner_engine)
    for name in ALL_NAMES:
        body = _without_comments(functions[name]["prosrc"])
        for token in QUALIFIED_TOKENS:
            pattern = re.compile(rf"(?<![\w.])({SCHEMA}\.)?{token}(?![\w])")
            for match in pattern.finditer(body):
                assert match.group(1) is not None, (
                    f"{name}: unqualified reference to {token!r} near "
                    f"{body[max(0, match.start() - 40):match.end() + 20]!r}"
                )


def test_the_context_narrowing_helper_only_ever_shrinks(owner_engine):
    """The body narrows by predicate: the new scope set must be contained by the old one."""
    body = _functions(owner_engine)["identity_context_narrow"]["prosrc"]
    assert "scopes @> COALESCE(p_scopes" in body
    assert "xact_id = pg_catalog.pg_current_xact_id()" in body
    assert "tenant_id" not in body.replace("-- ", "")  # it cannot re-point the tenant


# --------------------------------------------------------------------------- the tables


@pytest.mark.parametrize("table", sorted(IDENTITY_TABLES))
def test_every_identity_table_is_in_the_protected_catalogue(table):
    assert table in PROTECTED_TABLES


@pytest.mark.parametrize("table", sorted(IDENTITY_TABLES) + ["identity_transaction_context"])
def test_no_runtime_role_holds_any_privilege_on_the_identity_plane(owner_engine, disposable_database, table):
    runtime_roles = {
        disposable_database.application_role,
        disposable_database.provisioning_role,
        disposable_database.lifecycle_writer_role,
        disposable_database.authenticator_role,
    }
    with owner_engine.connect() as connection:
        grants = connection.execute(
            text(
                "SELECT grantee, privilege_type FROM information_schema.role_table_grants "
                "WHERE table_schema = :s AND table_name = :t"
            ),
            {"s": SCHEMA, "t": table},
        ).all()
        column_grants = connection.execute(
            text(
                "SELECT grantee, privilege_type FROM information_schema.role_column_grants "
                "WHERE table_schema = :s AND table_name = :t"
            ),
            {"s": SCHEMA, "t": table},
        ).all()
    grantees = {grantee for grantee, _p in grants} | {grantee for grantee, _p in column_grants}
    assert not grantees & runtime_roles, (table, grantees)
    assert "PUBLIC" not in grantees, table


def test_the_identity_context_is_unlogged_and_keyed_like_the_auth_context(owner_engine):
    with owner_engine.connect() as connection:
        persistence = connection.execute(
            text(
                "SELECT c.relpersistence FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = :s AND c.relname = 'identity_transaction_context'"
            ),
            {"s": SCHEMA},
        ).scalar_one()
        assert persistence == "u"
        columns = {
            name: data_type
            for name, data_type in connection.execute(
                text(
                    "SELECT column_name, udt_name FROM information_schema.columns "
                    "WHERE table_schema = :s AND table_name = 'identity_transaction_context'"
                ),
                {"s": SCHEMA},
            ).all()
        }
    assert columns["backend_pid"] == "int4" and columns["xact_id"] == "xid8"
    assert {"kind", "account_id", "session_id", "workspace_id", "tenant_id", "membership_id", "role",
            "csrf_verified", "security_epoch", "bound_at"} <= set(columns)
    # The login challenge carries the account's password version (Milestone 3.1 security
    # correction, recovery/login race); open_browser_session compares it under the account
    # row lock.
    assert columns["security_epoch"] == "int4"


def test_the_structural_triggers_are_installed_and_enabled(owner_engine):
    expected = {
        # As pg_get_triggerdef renders them: events in catalogue order, not statement order.
        "memberships_revocation_cascade": ("memberships", "BEFORE DELETE OR UPDATE"),
        "workspaces_directory_sync": ("workspaces", "AFTER INSERT OR DELETE OR UPDATE"),
        # Milestone 3.1 security correction: the token append-only guard is BEFORE UPDATE
        # only, so the owner-run purge of expired unverified accounts can cascade-delete
        # their tokens. DELETE remains impossible for every runtime role by the absent grant.
        "account_tokens_append_only": ("account_tokens", "BEFORE UPDATE"),
        "account_idempotency_records_append_only": ("account_idempotency_records", "BEFORE DELETE OR UPDATE"),
    }
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT t.tgname, c.relname, t.tgenabled, pg_get_triggerdef(t.oid) "
                "FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = :s AND NOT t.tgisinternal"
            ),
            {"s": SCHEMA},
        ).all()
    installed = {name: (table, enabled, definition) for name, table, enabled, definition in rows}
    for name, (table, timing) in expected.items():
        assert name in installed, name
        assert installed[name][0] == table
        assert installed[name][1] == "O", f"{name} is not enabled for the origin session"
        assert timing in installed[name][2], installed[name][2]
        assert "FOR EACH ROW" in installed[name][2]


# ------------------------------------------- the authenticator's least-privilege grant
#
# Milestone 3.1 security correction. The authenticator is the trusted-issuer principal: it
# holds the eight pre-authentication identity functions the application role does not, and
# beyond those exactly one read-side function -- ``auth_tenant_id``, which
# ``db/engine.transaction()`` calls to assert a transaction inherited no context. Everything
# below is asserted from the catalogue, function by function, rather than from the grant
# code's own description of itself.


def _authenticator_executable(owner_engine, role: str) -> "dict[str, bool]":
    """Every function in the schema, by name, and whether ``role`` may execute it.

    ``has_function_privilege`` resolves privileges the role holds **directly or through any
    role it is a member of**, so this answers the reachable-membership question too, not
    only the direct-grant one.

    Keyed by bare name rather than by signature: the schema overloads nothing (asserted
    here), and ``pg_get_function_identity_arguments`` renders parameter *names* alongside
    types, which would not match the type-only signatures the ``db/roles.py`` inventories
    carry.
    """
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT p.proname, "
                "       has_function_privilege(:role, p.oid, 'EXECUTE') AS executable "
                "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = :schema"
            ),
            {"role": role, "schema": SCHEMA},
        ).all()
    names = [name for name, _executable in rows]
    assert len(names) == len(set(names)), "a function name is overloaded; key this by signature instead"
    return {name: bool(executable) for name, executable in rows}


def test_the_authenticator_may_execute_exactly_its_own_functions_and_nothing_else(
    owner_engine, disposable_database
):
    """The whole grant, from the catalogue: eight pre-authentication entry points plus the
    two read-side accessors the transaction preamble needs, and not one function more.

    The eight are named here rather than only counted, so that moving a function into or
    out of the trusted-issuer boundary is a deliberate edit to this list.
    """
    expected = {name for name, _s in roles.IDENTITY_AUTHENTICATOR_FUNCTIONS} | {
        name for name, _s in roles.AUTHENTICATOR_READ_FUNCTIONS
    }
    assert expected == {
        # Signup and the two mailbox-proof paths: minting a verification or recovery secret
        # and consuming one is the mailbox-control proof itself.
        "signup_account",
        "request_email_verification",
        "verify_account_email",
        "request_account_recovery",
        "account_recovery_token_valid",
        "complete_account_recovery",
        # The password challenge and the session it opens.
        "login_lookup",
        "open_browser_session",
        # The two read-side accessors db/engine.transaction()'s preamble needs.
        "auth_context",
        "auth_tenant_id",
    }
    assert len(expected) == 10, "the authenticator's inventory changed; update this assertion deliberately"

    reachable = _authenticator_executable(owner_engine, disposable_database.authenticator_role)
    executable = {name for name, allowed in reachable.items() if allowed}

    unexpected = sorted(executable - expected)
    assert unexpected == [], f"the authenticator can execute functions it does not need: {unexpected}"
    missing = sorted(expected - executable)
    assert missing == [], f"the authenticator cannot execute functions it requires: {missing}"


@pytest.mark.parametrize(
    "name",
    (
        # The Milestone 2.3 credential registry: the untied minter and revoker.
        "register_auth_binding",
        "revoke_auth_binding",
        # Bearer-context binding and the generic audit writer.
        "bind_authenticated_context",
        "append_audit_event",
        # The Milestone 3.1 credential mutations, which are the application role's.
        "issue_api_credential",
        "rotate_api_credential",
        "revoke_api_credential",
        # Session binding, and the internals nobody may call.
        "bind_session_context",
        "identity_context_write",
        "identity_context_narrow",
        "identity_claim",
        "auth_context_begin",
        "purge_expired_unverified_accounts",
        # The remaining read-side accessors: needed by neither of the two call paths.
        "auth_has_scope",
        "auth_scopes",
        "auth_binding_id",
        "auth_principal_id",
        "auth_actor_kind",
    ),
)
def test_the_authenticator_cannot_reach_the_functions_it_has_no_call_path_to(
    owner_engine, disposable_database, name
):
    """Named explicitly as well as covered by the exhaustive test above, so a regression
    names the function it re-granted."""
    reachable = _authenticator_executable(owner_engine, disposable_database.authenticator_role)
    assert name in reachable, f"{name} is not a function of this schema; the list is stale"
    assert reachable[name] is False, f"the authenticator must not be able to execute {name}"


def test_the_authenticator_is_a_member_of_no_role_so_nothing_is_reachable_by_set_role(
    owner_engine, disposable_database
):
    """Least privilege is only least privilege if no membership widens it. The owner is
    granted membership in the authenticator so teardown can terminate its backends; the
    reverse direction -- the authenticator reaching anything -- must be empty."""
    with owner_engine.connect() as connection:
        memberships = connection.execute(
            text(
                "SELECT g.rolname FROM pg_auth_members m "
                "JOIN pg_roles r ON r.oid = m.member JOIN pg_roles g ON g.oid = m.roleid "
                "WHERE r.rolname = :role"
            ),
            {"role": disposable_database.authenticator_role},
        ).scalars().all()
    assert list(memberships) == [], (
        f"the authenticator is a member of {sorted(memberships)}; a membership would widen its grant"
    )


def test_the_authenticator_holds_no_table_or_column_privilege_anywhere_in_the_schema(
    owner_engine, disposable_database
):
    """Its whole reach is EXECUTE on six functions: no relation privilege of any kind."""
    with owner_engine.connect() as connection:
        tables = connection.execute(
            text(
                "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
                "WHERE table_schema = :s AND grantee = :role"
            ),
            {"s": SCHEMA, "role": disposable_database.authenticator_role},
        ).all()
        columns = connection.execute(
            text(
                "SELECT table_name, privilege_type FROM information_schema.role_column_grants "
                "WHERE table_schema = :s AND grantee = :role"
            ),
            {"s": SCHEMA, "role": disposable_database.authenticator_role},
        ).all()
    assert tables == [], f"the authenticator holds table privileges: {tables}"
    assert columns == [], f"the authenticator holds column privileges: {columns}"


def test_the_required_authenticator_flows_still_work_under_the_narrowed_grant(
    application_engine, authenticator_engine
):
    """The other half of least privilege: the six functions are also *enough*. Both
    pre-authentication flows the API runs on this engine are driven end to end here, so a
    grant narrowed too far fails as loudly as one left too wide."""
    email, account_id = signup_verified(application_engine)

    # Flow 1: login lookup plus session opening, in one transaction on the authenticator.
    opened = login_session(application_engine, email)
    assert opened.account_id == account_id
    with accounts.session_transaction(application_engine, opened.session_secret, mode="account") as (_s, ctx):
        assert ctx.account_id == account_id

    # Flow 2: recovery request, possession pre-check and completion.
    with db_engine.transaction(authenticator_engine) as session:
        outcome = accounts.request_recovery(session, email=email)
    assert outcome.secret is not None
    replacement = "a replacement password 2026"
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.complete_recovery(
            session, secret=outcome.secret, new_password=Secret(replacement)
        ) is True
    assert login_session(application_engine, email, password=replacement).account_id == account_id

    # And a wrong password still yields no account, so the narrowing changed no behaviour.
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.login(session, email=email, password=Secret(PASSWORD)).account_id is None


# --------------------------------------------------------------------------- the sanitiser


def test_the_sanitiser_strips_a_stray_grant_on_the_identity_plane(environment):
    """A grant an operator or a later migration leaves on identity state does not survive it.

    On its own disposable database: the sanitiser revokes every runtime privilege in the
    schema, which the wiring then re-grants -- running it against the shared database would
    leave the other tests' application role with nothing.
    """
    handle = create_disposable_database(environment)
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, _expected):
            connection.execute(text(f'GRANT SELECT ON {SCHEMA}.memberships TO "{handle.application_role}"'))
            connection.execute(
                text(f'GRANT SELECT (fingerprint) ON {SCHEMA}.browser_sessions TO "{handle.provisioning_role}"')
            )
            connection.execute(
                text(f'GRANT EXECUTE ON FUNCTION {SCHEMA}.identity_context_narrow(text[]) TO "{handle.application_role}"')
            )
            connection.execute(
                text(f'GRANT UPDATE ON {SCHEMA}.identity_transaction_context TO "{handle.application_role}"')
            )
            connection.commit()

            def privileges() -> set:
                rows = connection.execute(
                    text(
                        "SELECT grantee, table_name, privilege_type FROM information_schema.role_table_grants "
                        "WHERE table_schema = :s AND table_name IN "
                        "('memberships', 'browser_sessions', 'identity_transaction_context') "
                        "UNION ALL "
                        "SELECT grantee, table_name, privilege_type FROM information_schema.role_column_grants "
                        "WHERE table_schema = :s AND table_name IN "
                        "('memberships', 'browser_sessions', 'identity_transaction_context')"
                    ),
                    {"s": SCHEMA},
                ).all()
                return {row for row in rows if row[0] != handle.owner_role}

            def narrow_executable(role: str) -> bool:
                return connection.execute(
                    text("SELECT has_function_privilege(:r, :f, 'EXECUTE')"),
                    {"r": role, "f": f"{SCHEMA}.identity_context_narrow(text[])"},
                ).scalar_one()

            assert privileges()
            assert narrow_executable(handle.application_role)
            connection.execute(text(f"SELECT {SCHEMA}.sanitize_schema_privileges()"))
            connection.commit()
            assert privileges() == set()
            assert not narrow_executable(handle.application_role)
    finally:
        drop_disposable_database(handle)
