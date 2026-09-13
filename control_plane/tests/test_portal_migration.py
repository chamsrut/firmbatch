"""Migration ``0006``: no drift from the modules it mirrors, and the same hardening as ``0005``.

A migration must not import the models -- one that followed them would stop being a record of
what was applied -- so ``0006`` duplicates the constants it needs. This is what keeps the
duplicates honest, and it is the same arrangement ``test_identity_migration.py`` provides for
``0005``.

It also holds ``0006``'s six functions to the properties every function in this schema has:
owned by the schema owner, ``search_path`` pinned to ``pg_catalog``, ``EXECUTE`` revoked from
``PUBLIC``, granted to exactly the audience the inventory names, and free of dynamic SQL --
and it holds the three ``0005`` bodies ``0006`` replaces to their restore contract: the legacy
text is ``0005``'s verbatim, the downgrade puts it back, and a database taken back to ``0005``
has the catalogue a fresh migration to ``0005`` produces.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re

import pytest
from alembic import command
from sqlalchemy import text

from firmbatch.control_plane import migrate
from firmbatch.control_plane.api.consent import CONSENT_DOCUMENTS, CURRENT_CONSENT_VERSION
from firmbatch.control_plane.db import accounts, models, preferences, roles
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.security import passwords
from firmbatch.control_plane.testing.bootstrap import (
    create_disposable_database,
    drop_disposable_database,
    wire_handle_roles,
)
from firmbatch.control_plane.tests import identity_helpers

REVISION = "0006_preferences_and_password"


def _migration():
    return _load_migration_module(REVISION)


def _load_migration_module(revision: str):
    path = pathlib.Path(models.__file__).parent / "migrations" / "versions" / f"{revision}.py"
    spec = importlib.util.spec_from_file_location(f"firmbatch_migration_{revision}_portal", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _functions(owner_engine) -> dict:
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT p.proname, pg_get_userbyid(p.proowner) AS owner, p.prosecdef, "
                "       p.proconfig, p.proacl::text AS acl, p.prosrc "
                "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = :s"
            ),
            {"s": SCHEMA},
        ).mappings()
        return {row["proname"]: dict(row) for row in rows}


def _grantees(acl: str | None) -> set[str]:
    if not acl:
        return set()
    found = set()
    for entry in acl.strip("{}").split(","):
        grantee, _, rest = entry.partition("=")
        if "X" in rest.split("/")[0]:
            found.add(grantee)
    return found


# --------------------------------------------------------------------------- no drift


def test_the_revision_is_the_head_and_follows_0005():
    migration = _migration()
    assert migration.revision == REVISION == roles.M3_2_REVISION
    assert migration.down_revision == roles.M3_1_REVISION
    # Migrations 0001-0005 are history: this one adds, and modifies none of them.
    assert len(migration.revision) <= 32


@pytest.mark.parametrize(
    ("attribute", "expected"),
    (
        ("REGION_GROUPS", "REGION_GROUPS"),
        ("PROVIDER_CLASSES", "PROVIDER_CLASSES"),
        ("EVALUATION_INTENTS", "EVALUATION_INTENTS"),
        ("CONSENT_VERSIONS", "CONSENT_VERSIONS"),
        ("MODEL_PROFILE_NOTE_MAX_LENGTH", "MODEL_PROFILE_NOTE_MAX_LENGTH"),
    ),
)
def test_the_vocabularies_have_not_drifted_from_the_models(attribute, expected):
    assert getattr(_migration(), attribute) == getattr(models, expected)


def test_the_password_constants_have_not_drifted_from_the_security_module():
    migration = _migration()
    assert migration.PASSWORD_HASH_REGEX == passwords.PASSWORD_HASH_REGEX
    assert migration.PASSWORD_HASH_MAX_LENGTH == models.PASSWORD_HASH_MAX_LENGTH


def test_the_consent_versions_the_schema_knows_are_the_ones_the_api_serves():
    """A row cannot record assent to text that does not exist, and vice versa."""
    assert tuple(CONSENT_DOCUMENTS) == models.CONSENT_VERSIONS
    assert CURRENT_CONSENT_VERSION in models.CONSENT_VERSIONS
    assert _migration().CONSENT_VERSIONS == models.CONSENT_VERSIONS


def test_the_version_an_acknowledgement_records_is_the_one_the_api_offers():
    """The function writes its own constant, never the caller's; it must be the current one."""
    migration = _migration()
    assert migration.CURRENT_CONSENT_VERSION == CURRENT_CONSENT_VERSION
    assert migration.CURRENT_CONSENT_VERSION in migration.CONSENT_VERSIONS
    assert f"'{CURRENT_CONSENT_VERSION}'" in migration._ACKNOWLEDGE_WORKSPACE_CONSENT


def test_the_array_bound_and_the_whitespace_literal_have_not_drifted():
    migration = _migration()
    fifth = _load_migration_module(roles.M3_1_REVISION)
    assert migration.MAX_ARRAY_LENGTH == preferences.MAX_ARRAY_LENGTH
    assert migration.ASCII_WHITESPACE_SQL == fifth.ASCII_WHITESPACE_SQL


def test_the_binding_sqlstate_is_mirrored_distinct_and_in_the_reserved_class():
    """``FB014`` is translated by ``db/accounts.py`` and collides with nothing earlier."""
    migration = _migration()
    fifth = _load_migration_module(roles.M3_1_REVISION)
    fourth = _load_migration_module(roles.M2_4_REVISION)
    assert migration.IDENTITY_BINDING_SQLSTATE == accounts.IDENTITY_BINDING_SQLSTATE
    assert migration.IDENTITY_REFUSED_SQLSTATE == accounts.IDENTITY_REFUSED_SQLSTATE == fifth.IDENTITY_REFUSED_SQLSTATE
    assert migration.IDENTITY_CONFLICT_SQLSTATE == accounts.IDENTITY_CONFLICT_SQLSTATE == fifth.IDENTITY_CONFLICT_SQLSTATE
    assert migration.IDENTITY_CONTEXT_SQLSTATE == accounts.IDENTITY_CONTEXT_SQLSTATE == fifth.IDENTITY_CONTEXT_SQLSTATE
    earlier = {
        fifth.IDENTITY_REFUSED_SQLSTATE,
        fifth.IDENTITY_CONFLICT_SQLSTATE,
        fifth.IDENTITY_KEY_REUSE_SQLSTATE,
        fifth.IDENTITY_CONTEXT_SQLSTATE,
        fourth.LIFECYCLE_CONFLICT_SQLSTATE,
        fourth.LIFECYCLE_NOT_ALLOWED_SQLSTATE,
        fourth.LIFECYCLE_DEFINITION_SQLSTATE,
        fourth.LIFECYCLE_KEY_REUSE_SQLSTATE,
        fourth.LIFECYCLE_PROVENANCE_SQLSTATE,
        fourth.OUTBOX_LINK_SQLSTATE,
    }
    assert migration.IDENTITY_BINDING_SQLSTATE not in earlier
    assert len(migration.IDENTITY_BINDING_SQLSTATE) == 5 and migration.IDENTITY_BINDING_SQLSTATE.startswith("FB")
    # The neutral message names no identifier, in either copy.
    assert migration.IDENTITY_BINDING_MESSAGE.startswith("firmbatch: ")
    assert accounts.WORKSPACE_BINDING_MISMATCH_MESSAGE.startswith(
        migration.IDENTITY_BINDING_MESSAGE.removeprefix("firmbatch: ")
    )


# --------------------------------------------------------------------------- the replaced bodies


def test_the_replaced_0005_bodies_restore_0005s_text_exactly():
    """``0006`` brings two ``0005`` functions under the account-plane lock order; the downgrade
    puts ``0005``'s bodies back byte-for-byte, and ``0005`` is unedited."""
    migration = _migration()
    fifth = _load_migration_module(roles.M3_1_REVISION)

    assert migration._LEGACY_COMPLETE_ACCOUNT_RECOVERY == fifth._COMPLETE_ACCOUNT_RECOVERY
    assert migration._LEGACY_VERIFY_ACCOUNT_EMAIL == fifth._VERIFY_ACCOUNT_EMAIL
    assert migration._LEGACY_WORKSPACE_MEMBERSHIP_AUTHORITY == fifth._IDENTITY_REQUIRE_MEMBERSHIP
    for restore, legacy in (
        (migration._LEGACY_COMPLETE_ACCOUNT_RECOVERY_RESTORE, migration._LEGACY_COMPLETE_ACCOUNT_RECOVERY),
        (migration._LEGACY_VERIFY_ACCOUNT_EMAIL_RESTORE, migration._LEGACY_VERIFY_ACCOUNT_EMAIL),
        (
            migration._LEGACY_WORKSPACE_MEMBERSHIP_AUTHORITY_RESTORE,
            migration._LEGACY_WORKSPACE_MEMBERSHIP_AUTHORITY,
        ),
    ):
        assert restore.replace("CREATE OR REPLACE FUNCTION", "CREATE FUNCTION", 1) == legacy
        assert restore != legacy

    # The authority's head body is 0005's text plus one block: the expected-workspace
    # comparison, after the permission check and before the role is returned, so that no
    # mutation has written anything by the time a stale page is refused.
    head = migration._WORKSPACE_MEMBERSHIP_AUTHORITY_HEAD
    legacy = migration._LEGACY_WORKSPACE_MEMBERSHIP_AUTHORITY
    assert head.startswith("\nCREATE OR REPLACE FUNCTION")
    assert "identity_expected_workspace" not in legacy
    permission = head.index("this operation requires the % permission")
    comparison = head.index(f"FROM {SCHEMA}.identity_expected_workspace e")
    returned = head.index("v_session.role := v_role;")
    assert permission < comparison < returned
    assert f"USING ERRCODE = '{migration.IDENTITY_BINDING_SQLSTATE}'" in head[comparison:returned]
    # Removing the block gives 0005's body back, which is what "one block" means.
    block_start = head.index("    -- (0006) The workspace the caller's request was made **for**")
    without = head[:block_start] + head[head.index("    v_session.role := v_role;") :]
    without = without.replace("CREATE OR REPLACE FUNCTION", "CREATE FUNCTION", 1)
    without = without.replace("    v_role text;\n    v_expected uuid;\n", "    v_role text;\n", 1)
    assert without == legacy

    # The head bodies differ from the legacy ones in exactly the way the order requires: the
    # account row is locked before the token row is re-read and locked.
    for head, legacy in (
        (migration._COMPLETE_ACCOUNT_RECOVERY_HEAD, migration._LEGACY_COMPLETE_ACCOUNT_RECOVERY),
        (migration._VERIFY_ACCOUNT_EMAIL_HEAD, migration._LEGACY_VERIFY_ACCOUNT_EMAIL),
    ):
        assert head != legacy
        assert head.startswith("\nCREATE OR REPLACE FUNCTION")
        account_lock = head.index(f"FROM {SCHEMA}.accounts a WHERE a.id = v_account_id FOR UPDATE")
        token_lock = head.index("AND t.account_id = v_account_id\n    FOR UPDATE")
        assert account_lock < token_lock
        # And the legacy body locked the token first, which is the defect.
        assert "FOR UPDATE" in legacy and "v_account_id" not in legacy
    # Every replaced function stays in 0005's inventory, with the audience 0005 gave it.
    replaced = {(name, signature) for name, signature in migration.REPLACED_FUNCTIONS}
    assert replaced <= set(roles.ALL_IDENTITY_FUNCTIONS)
    assert replaced & set(roles.IDENTITY_AUTHENTICATOR_FUNCTIONS) == {
        ("verify_account_email", "text"),
        ("complete_account_recovery", "text, text"),
    }
    assert replaced & set(roles.IDENTITY_APPLICATION_FUNCTIONS) == {
        ("workspace_membership_authority", "text, boolean"),
    }


def test_the_replaced_functions_are_installed_with_the_head_bodies(owner_engine, disposable_database):
    functions = _functions(owner_engine)
    migration = _migration()
    for name, _signature in migration.REPLACED_FUNCTIONS:
        body = functions[name]["prosrc"]
        if name == "workspace_membership_authority":
            assert f"FROM {SCHEMA}.identity_expected_workspace e" in body
            # Still the application role's: CREATE OR REPLACE kept identity and ACL.
            assert disposable_database.application_role in _grantees(functions[name]["acl"])
        else:
            assert f"FROM {SCHEMA}.accounts a WHERE a.id = v_account_id FOR UPDATE" in body, name
            assert disposable_database.authenticator_role in _grantees(functions[name]["acl"])
        # Still hardened: CREATE OR REPLACE kept identity and ACL.
        assert functions[name]["prosecdef"] is True
        assert functions[name]["proconfig"] == ["search_path=pg_catalog"]


def test_the_policy_rule_matches_the_authorization_catalogue():
    from firmbatch.control_plane.security.authorization import RULES_BY_TABLE

    migration = _migration()
    rule = RULES_BY_TABLE["workspace_preferences"]
    commands = {command for command, _suffix, _using, _check in migration.POLICIES}
    assert commands == {"SELECT", "INSERT", "UPDATE"}
    rendered = " ".join(
        " ".join(part for part in (using, check) if part)
        for _command, _suffix, using, check in migration.POLICIES
    )
    for scope in rule.read or ():
        assert scope.value in rendered
    for scope in rule.write or ():
        assert scope.value in rendered
    # The tenant predicate is the authenticated context's, never a caller-set value.
    assert f"{SCHEMA}.auth_tenant_id()" in rendered
    assert "app.tenant_id" not in rendered


def test_the_function_inventory_matches_db_roles():
    migration = _migration()
    declared = {(name, signature): audience for name, signature, audience in migration.FUNCTIONS}
    assert set(declared) == set(roles.ALL_PORTAL_FUNCTIONS)
    assert {key for key, audience in declared.items() if audience == "authenticator"} == set(
        roles.IDENTITY_PASSWORD_CHANGE_FUNCTIONS
    )
    assert {key for key, audience in declared.items() if audience == "application"} == set(
        roles.PORTAL_APPLICATION_FUNCTIONS
    )
    assert {key for key, audience in declared.items() if audience == "internal"} == set(
        roles.PORTAL_INTERNAL_FUNCTIONS
    )
    # The head plan hands the application role exactly the two mutation entry points.
    plan = roles.REVISION_PLANS[roles.M3_2_REVISION]
    assert set(roles.PORTAL_APPLICATION_FUNCTIONS) <= set(plan.application_functions)
    assert not set(roles.PORTAL_APPLICATION_FUNCTIONS) & set(plan.authenticator_functions)
    assert not set(roles.PORTAL_APPLICATION_FUNCTIONS) & set(plan.provisioning_functions)
    assert ("workspace_preferences", "SELECT") in plan.application_grants
    assert not any(
        table == "workspace_preferences" and privileges != "SELECT"
        for table, privileges in plan.application_grants
    )
    # Disjoint from every earlier inventory: nothing is redefined.
    earlier = {
        name
        for name, _s in roles.ALL_AUTH_FUNCTIONS
        + roles.ALL_LIFECYCLE_FUNCTIONS
        + roles.ALL_IDENTITY_FUNCTIONS
    }
    assert not earlier & {name for name, _s in roles.ALL_PORTAL_FUNCTIONS}


# --------------------------------------------------------------------------- hardening


def test_every_new_function_is_owned_by_the_schema_owner(owner_engine, disposable_database):
    functions = _functions(owner_engine)
    for name, _signature in roles.ALL_PORTAL_FUNCTIONS:
        assert name in functions, f"{name} is not installed"
        assert functions[name]["owner"] == disposable_database.owner_role, name


def test_every_new_function_is_security_definer_with_a_pinned_search_path(owner_engine):
    functions = _functions(owner_engine)
    for name, _signature in roles.ALL_PORTAL_FUNCTIONS:
        assert functions[name]["prosecdef"] is True, name
        # pg_catalog only: an unqualified name cannot be resolved through a caller's path.
        assert functions[name]["proconfig"] == ["search_path=pg_catalog"], name


def test_public_holds_execute_on_none_of_them(owner_engine):
    functions = _functions(owner_engine)
    for name, _signature in roles.ALL_PORTAL_FUNCTIONS:
        grantees = _grantees(functions[name]["acl"])
        # PostgreSQL renders PUBLIC as the empty grantee in an ACL, so both spellings are
        # checked: an ACL of ``{=X/owner}`` is the default grant this schema always revokes.
        assert "PUBLIC" not in grantees, name
        assert "" not in grantees, name


def test_the_two_password_functions_are_the_authenticator_s_alone(
    owner_engine, disposable_database
):
    functions = _functions(owner_engine)
    for name, _signature in roles.IDENTITY_PASSWORD_CHANGE_FUNCTIONS:
        grantees = _grantees(functions[name]["acl"])
        assert disposable_database.authenticator_role in grantees, name
        # And the application role -- the large runtime surface -- holds nothing.
        assert disposable_database.application_role not in grantees, name
        assert disposable_database.provisioning_role not in grantees, name


def test_the_trigger_function_is_executable_by_nobody(owner_engine, disposable_database):
    functions = _functions(owner_engine)
    for name, _signature in roles.PORTAL_INTERNAL_FUNCTIONS:
        grantees = _grantees(functions[name]["acl"])
        assert grantees <= {disposable_database.owner_role}, f"{name} is executable by {grantees}"


def test_the_two_mutation_functions_are_the_application_role_s_alone(owner_engine, disposable_database):
    functions = _functions(owner_engine)
    for name, _signature in roles.PORTAL_APPLICATION_FUNCTIONS:
        grantees = _grantees(functions[name]["acl"])
        assert disposable_database.application_role in grantees, name
        assert disposable_database.authenticator_role not in grantees, name
        assert disposable_database.provisioning_role not in grantees, name
        assert disposable_database.lifecycle_writer_role not in grantees, name


def test_no_function_other_than_the_two_mutations_writes_workspace_preferences(owner_engine):
    """No unrelated ``SECURITY DEFINER`` function is a path into the relation."""
    functions = _functions(owner_engine)
    writers = set()
    for name, row in functions.items():
        body = "\n".join(re.sub(r"--.*$", "", line) for line in row["prosrc"].splitlines()).lower()
        if re.search(rf"\b(insert\s+into|update)\s+{SCHEMA}\.workspace_preferences\b", body):
            writers.add(name)
        assert not re.search(rf"\bdelete\s+from\s+{SCHEMA}\.workspace_preferences\b", body), name
    assert writers == {"state_workspace_preferences", "acknowledge_workspace_consent"}
    assert writers < {name for name, _signature in roles.PORTAL_APPLICATION_FUNCTIONS}


# --------------------------------------------------------------------------- the ladder


def _catalogue(connection) -> dict:
    """Everything the downgrade has to put back, as the catalogue holds it. ACLs excluded:
    the wiring is re-applied per revision and is tested by ``test_migrations.py``."""
    def rows(statement: str) -> list:
        return connection.execute(text(statement), {"s": SCHEMA}).all()

    def unqualify(value):
        # ``pg_get_*def`` renders a name schema-qualified only when the schema is off the
        # search path, which a migration run changes; the content does not.
        return value.replace(f"{SCHEMA}.", "") if isinstance(value, str) else value

    return {
        "functions": rows(
            "SELECT p.proname, pg_get_function_identity_arguments(p.oid), p.prosrc, p.prosecdef, "
            "p.provolatile, coalesce(array_to_string(p.proconfig, ','), '') "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = :s ORDER BY 1, 2"
        ),
        "tables": rows(
            "SELECT c.relname, c.relkind, c.relrowsecurity, c.relforcerowsecurity "
            "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = :s AND c.relkind IN ('r', 'i') ORDER BY 1"
        ),
        "policies": [
            tuple(unqualify(cell) for cell in row)
            for row in rows(
                "SELECT tablename, policyname, cmd, roles::text, qual, with_check FROM pg_policies "
                "WHERE schemaname = :s ORDER BY 1, 2"
            )
        ],
        "triggers": [
            tuple(unqualify(cell) for cell in row)
            for row in rows(
                "SELECT c.relname, t.tgname, pg_get_triggerdef(t.oid) FROM pg_trigger t "
                "JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = :s AND NOT t.tgisinternal ORDER BY 1, 2"
            )
        ],
        "revision": rows(f"SELECT version_num FROM {SCHEMA}.alembic_version"),
    }


def test_the_downgrade_to_0005_restores_the_milestone_31_catalogue_exactly(environment):
    """head -> 0005 by downgrade equals base -> 0005 by upgrade, and the ladder is whole.

    The replaced bodies are the point: a downgrade that left the head body of
    ``complete_account_recovery`` or ``verify_account_email`` behind would differ from a
    fresh ``0005`` in ``prosrc``, and equality here is what proves it did not.
    """
    handle = create_disposable_database(environment)
    fifth = _load_migration_module(roles.M3_1_REVISION)
    added = {name for name, _s in roles.ALL_PORTAL_FUNCTIONS}
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            head = _catalogue(connection)
            assert added <= {row[0] for row in head["functions"]}

            migrate.downgrade_to(connection, roles.M3_1_REVISION, expected=expected)
            connection.commit()
            via_downgrade = _catalogue(connection)
            assert via_downgrade["revision"] == [(roles.M3_1_REVISION,)]
            names = {row[0] for row in via_downgrade["functions"]}
            assert not added & names
            assert "workspace_preferences" not in {row[0] for row in via_downgrade["tables"]}
            bodies = {row[0]: row[2] for row in via_downgrade["functions"]}
            # 0005's text, verbatim, as the catalogue stores it: the body between the dollar quotes.
            for name, constant in (
                ("complete_account_recovery", fifth._COMPLETE_ACCOUNT_RECOVERY),
                ("verify_account_email", fifth._VERIFY_ACCOUNT_EMAIL),
            ):
                assert bodies[name] == constant.split("AS $function$", 1)[1].rsplit("$function$", 1)[0], name
            assert roles.schema_revision(connection) == roles.M3_1_REVISION

            migrate.downgrade_to(connection, "base", expected=expected)
            connection.commit()
            command.upgrade(migrate.alembic_config(connection=connection, expected=expected), roles.M3_1_REVISION)
            connection.commit()
            fresh = _catalogue(connection)
            assert fresh == via_downgrade, {
                key: (sorted(set(fresh[key]) - set(via_downgrade[key])), sorted(set(via_downgrade[key]) - set(fresh[key])))
                for key in fresh
                if fresh[key] != via_downgrade[key]
            }

            assert migrate.upgrade_to_head(connection, expected=expected) == migrate.head_revision()
            connection.commit()
            assert _catalogue(connection) == head
    finally:
        drop_disposable_database(handle)


def test_a_populated_database_downgrades_reconciles_and_reupgrades_with_the_boundary_intact(environment):
    """Upgrade, use, downgrade, reconcile, re-upgrade, use again.

    Real Milestone 3.2 activity -- a stated policy and an acknowledged consent -- lives in the
    one relation ``0006`` adds, and the audit trail records both with session actors. The
    downgrade drops the relation with its rows (that is the reconciliation: the reverted
    schema has no place for them, and the trail keeps the history) and restores the three
    ``0005`` bodies; the re-upgrade brings the relation back empty, the six functions back,
    and -- once the roles are re-wired for the revision -- the boundary works exactly as
    before: the application role can state through the function and cannot write the table.
    """
    handle = create_disposable_database(environment)
    current = CONSENT_DOCUMENTS[CURRENT_CONSENT_VERSION].version
    # One outer try/finally around everything, so a failure at any step -- setup included --
    # still drops the database and its roles rather than leaving them on the cluster.
    try:
        application = db_engine.create_application_engine(handle.application_url)
        authenticator = db_engine.create_application_engine(handle.authenticator_url)
        try:
            identity_helpers.register_authenticator_engine(authenticator)
            who, created = identity_helpers.owner_with_workspace(application, "ladder")
            with identity_helpers.workspace_session(application, who) as (session, _context):
                preferences.state(session, created.workspace_id, region_policy=["EU"])
                preferences.acknowledge_consent(session, created.workspace_id, version=current)
            assert _preference_rows(handle) == 1
        finally:
            # Dispose the runtime engines before the schema changes underneath them.
            application.dispose()
            authenticator.dispose()

        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            assert roles.schema_revision(connection) == roles.M3_2_REVISION
            migrate.downgrade_to(connection, roles.M3_1_REVISION, expected=expected)
            connection.commit()
            assert migrate.current_revision(connection) == roles.M3_1_REVISION
            assert not connection.execute(
                text("SELECT pg_catalog.to_regclass(:name) IS NOT NULL"),
                {"name": f"{SCHEMA}.workspace_preferences"},
            ).scalar_one()
            # The trail survives the downgrade: the history is not in the dropped relation.
            connection.execute(text(f"ALTER TABLE {SCHEMA}.audit_events NO FORCE ROW LEVEL SECURITY"))
            trail = connection.execute(
                text(
                    f"SELECT count(*) FROM {SCHEMA}.audit_events "
                    "WHERE action IN ('workspace.preferences_stated', 'workspace.consent_acknowledged')"
                )
            ).scalar_one()
            connection.execute(text(f"ALTER TABLE {SCHEMA}.audit_events FORCE ROW LEVEL SECURITY"))
            connection.commit()
            assert trail == 2

            assert migrate.upgrade_to_head(connection, expected=expected) == migrate.head_revision()
            connection.commit()
            assert roles.schema_revision(connection) == roles.M3_2_REVISION
            wire_handle_roles(connection, handle)
            connection.commit()

        application = db_engine.create_application_engine(handle.application_url)
        authenticator = db_engine.create_application_engine(handle.authenticator_url)
        try:
            identity_helpers.register_authenticator_engine(authenticator)
            assert _preference_rows(handle) == 0
            # The account and its workspace survived (identity is 0005's); the relation is empty;
            # the boundary is whole: the function writes, a direct statement is refused.
            with identity_helpers.workspace_session(application, who) as (session, _context):
                assert preferences.read(session, created.workspace_id).region_policy == ()
                stated = preferences.state(session, created.workspace_id, region_policy=["EU"])
                assert stated.region_policy == ("EU",)
            with pytest.raises(Exception) as exc:
                with identity_helpers.workspace_session(application, who) as (session, _context):
                    session.execute(
                        text(f"UPDATE {SCHEMA}.workspace_preferences SET region_policy = '{{}}' WHERE workspace_id = :w"),
                        {"w": created.workspace_id},
                    )
            assert "permission denied for table workspace_preferences" in str(exc.value)
        finally:
            application.dispose()
            authenticator.dispose()
    finally:
        drop_disposable_database(handle)


def _preference_rows(handle) -> int:
    """How many rows the relation holds. ``FORCE`` binds the owner too, so the count is read
    with row security lifted for one statement and restored immediately."""
    engine = migrate.create_migration_engine(handle.migration_url)
    try:
        with engine.connect() as connection:
            connection.execute(text(f"ALTER TABLE {SCHEMA}.workspace_preferences NO FORCE ROW LEVEL SECURITY"))
            count = connection.execute(text(f"SELECT count(*) FROM {SCHEMA}.workspace_preferences")).scalar_one()
            connection.execute(text(f"ALTER TABLE {SCHEMA}.workspace_preferences FORCE ROW LEVEL SECURITY"))
            connection.commit()
        return int(count)
    finally:
        engine.dispose()


def test_no_new_function_builds_a_statement_or_resolves_an_object_by_name(owner_engine):
    functions = _functions(owner_engine)
    forbidden = ("execute format", "execute '", 'execute "', "quote_ident(", "current_setting(")
    for name, _signature in roles.ALL_PORTAL_FUNCTIONS:
        body = "\n".join(
            re.sub(r"--.*$", "", line) for line in functions[name]["prosrc"].splitlines()
        ).lower()
        for fragment in forbidden:
            assert fragment not in body, f"{name}: body contains {fragment!r}"


def test_the_trigger_is_installed_and_enabled(owner_engine):
    with owner_engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT t.tgname, t.tgenabled FROM pg_trigger t "
                "JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = :s AND c.relname = 'workspace_preferences' AND NOT t.tgisinternal"
            ),
            {"s": SCHEMA},
        ).one()
    assert row[0] == "workspace_preferences_set_consent"
    # 'O' is "enabled, origin". A disabled trigger would leave the consent columns caller-set.
    assert row[1] == "O"
