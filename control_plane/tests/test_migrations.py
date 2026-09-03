"""Migrations: they reach head, they match the models, and they go back down again.

The schema assertions here are the ones a later milestone would otherwise silently
break -- UUID keys, ``timestamptz``, tenant-local uniqueness, forced row security, the
pinned schema, and the helper-function grants.
"""

from __future__ import annotations

from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect, text

from firmbatch.control_plane import migrate
from firmbatch.control_plane.db.base import SCHEMA, VERSION_TABLE
from firmbatch.control_plane.db.base import Base
from firmbatch.control_plane.db.models import TENANT_SCOPED_TABLES
from firmbatch.control_plane.testing.bootstrap import create_disposable_database, drop_disposable_database


def test_bootstrap_reaches_the_expected_head(disposable_database, owner_engine):
    expected = migrate.head_revision()
    assert disposable_database.head_revision == expected
    with owner_engine.connect() as connection:
        assert migrate.current_revision(connection) == expected


def test_there_is_exactly_one_head():
    """A branched history is a migration that applies differently in two environments."""
    assert migrate.head_revision() == "0001_tenant_workspace_spine"


def test_migrated_schema_matches_the_models(owner_engine):
    """``compare_metadata`` is the check that the hand-written migration has not drifted."""
    with owner_engine.connect() as connection:
        context = MigrationContext.configure(
            connection,
            opts={
                "version_table": VERSION_TABLE,
                "version_table_schema": SCHEMA,
                "include_schemas": True,
                # Compare only the pinned schema; every other schema in the database is
                # somebody else's business and would show up as a spurious difference.
                "include_name": lambda name, type_, parent: (type_ != "schema" or name == SCHEMA),
            },
        )
        diffs = [d for d in compare_metadata(context, Base.metadata) if VERSION_TABLE not in repr(d)]
    assert diffs == [], f"migration and models disagree: {diffs}"


def test_everything_lives_in_the_pinned_schema_and_nothing_in_public(owner_engine):
    """Relations in ``public`` are shadowable through an unqualified reference."""
    inspector = inspect(owner_engine)
    assert set(inspector.get_table_names(schema=SCHEMA)) >= {"tenants", "workspaces", VERSION_TABLE}
    assert inspector.get_table_names(schema="public") == []


def test_primary_keys_are_uuid_and_timestamps_are_timezone_aware(owner_engine):
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                """
                SELECT table_name, column_name, data_type
                FROM information_schema.columns
                WHERE table_schema = :schema AND table_name IN ('tenants', 'workspaces')
                """
            ),
            {"schema": SCHEMA},
        ).all()
    types = {(t, c): d for t, c, d in rows}
    assert types[("tenants", "id")] == "uuid"
    assert types[("workspaces", "id")] == "uuid"
    assert types[("workspaces", "tenant_id")] == "uuid"
    for table in ("tenants", "workspaces"):
        for column in ("created_at", "updated_at"):
            assert types[(table, column)] == "timestamp with time zone", (table, column)


def test_workspaces_carry_an_explicit_foreign_key_to_tenants(owner_engine):
    fks = inspect(owner_engine).get_foreign_keys("workspaces", schema=SCHEMA)
    assert [(fk["constrained_columns"], fk["referred_table"]) for fk in fks] == [(["tenant_id"], "tenants")]
    assert fks[0]["options"]["ondelete"].upper() == "CASCADE"
    # The foreign key must name the schema; an unqualified target resolves through
    # search_path, which is what the pinned schema removes.
    assert fks[0]["referred_schema"] == SCHEMA


def test_workspace_uniqueness_is_tenant_local_not_global(owner_engine):
    """A global unique index on slug would leak other tenants through constraint errors."""
    constraints = {
        c["name"]: c["column_names"]
        for c in inspect(owner_engine).get_unique_constraints("workspaces", schema=SCHEMA)
    }
    assert constraints["uq_workspaces_tenant_id_slug"] == ["tenant_id", "slug"]
    assert constraints["uq_workspaces_tenant_id_name"] == ["tenant_id", "name"]
    # The composite key later child tables reference, because FK checks bypass RLS.
    assert constraints["uq_workspaces_id_tenant_id"] == ["id", "tenant_id"]
    assert not any(cols == ["slug"] for cols in constraints.values()), "workspace slug must not be globally unique"


def test_row_level_security_is_enabled_and_forced_on_every_tenant_scoped_table(owner_engine):
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                """
                SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
                FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = :schema AND c.relname = ANY(:tables)
                """
            ),
            {"schema": SCHEMA, "tables": list(TENANT_SCOPED_TABLES)},
        ).all()
    state = {name: (enabled, forced) for name, enabled, forced in rows}
    assert set(state) == set(TENANT_SCOPED_TABLES)
    for table, (enabled, forced) in state.items():
        assert enabled, f"{table}: row-level security is not enabled"
        assert forced, f"{table}: row-level security is not FORCEd, so the owner is exempt"


def test_every_tenant_scoped_table_has_an_isolation_policy(owner_engine):
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text("SELECT tablename, policyname, qual, with_check FROM pg_policies WHERE schemaname = :schema"),
            {"schema": SCHEMA},
        ).all()
    policies = {table: (name, qual, check) for table, name, qual, check in rows}
    assert set(policies) == set(TENANT_SCOPED_TABLES)
    for table, tenant_column in TENANT_SCOPED_TABLES.items():
        name, qual, check = policies[table]
        assert name == f"{table}_tenant_isolation"
        assert "app_current_tenant_id()" in qual
        assert tenant_column in qual
        assert check is not None, f"{table}: policy has no WITH CHECK, so writes are unconstrained"


def test_tenant_context_function_returns_null_when_unset(owner_engine):
    with owner_engine.connect() as connection:
        assert connection.execute(text(f"SELECT {SCHEMA}.app_current_tenant_id()")).scalar() is None


def test_tenant_context_helper_is_not_executable_by_public(owner_engine):
    """Finding 10: do not inherit PostgreSQL's default of EXECUTE to PUBLIC.

    A future role that gains only CONNECT must not also inherit the ability to evaluate
    the tenant-context helper.
    """
    with owner_engine.connect() as connection:
        acl = connection.execute(
            text(
                """
                SELECT coalesce(array_to_string(p.proacl, ','), '')
                FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = :schema AND p.proname = 'app_current_tenant_id'
                """
            ),
            {"schema": SCHEMA},
        ).scalar()
    assert acl != "", "an empty ACL means PostgreSQL defaults apply, which grant EXECUTE to PUBLIC"
    # The PUBLIC grant is the entry with an empty grantee, i.e. one starting with "=".
    # A named grantee such as "firmbatch_test_app_x=X/owner" also contains "=X/", so the
    # entries have to be split apart rather than substring-tested.
    entries = [entry for entry in acl.split(",") if entry]
    public_grants = [entry for entry in entries if entry.startswith("=")]
    assert public_grants == [], f"EXECUTE is still granted to PUBLIC: {acl}"
    # And the roles that must be able to evaluate the policies do hold it.
    assert any(entry.split("=", 1)[0].startswith("firmbatch_test_app_") for entry in entries), acl
    assert any(entry.split("=", 1)[0].startswith("firmbatch_test_prov_") for entry in entries), acl


def test_the_helper_is_not_security_definer(owner_engine):
    """A definer-rights function inside a policy predicate is a standing bypass."""
    with owner_engine.connect() as connection:
        is_definer = connection.execute(
            text(
                """
                SELECT p.prosecdef FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = :schema AND p.proname = 'app_current_tenant_id'
                """
            ),
            {"schema": SCHEMA},
        ).scalar()
    assert is_definer is False


def test_the_version_table_lives_in_the_pinned_schema(owner_engine):
    with owner_engine.connect() as connection:
        schemas = connection.execute(
            text("SELECT schemaname FROM pg_tables WHERE tablename = :t"), {"t": VERSION_TABLE}
        ).scalars().all()
    assert schemas == [SCHEMA]


def test_migration_downgrades_and_upgrades_again(environment):
    """A migration that cannot be reversed is a migration nobody can roll back.

    Runs on its own disposable database so the suite's shared one is untouched.
    """
    handle = create_disposable_database(environment)
    try:
        # Both directions go through the one validated online entry point. There is no
        # URL-taking form any more: a downgrade drops tables and policies, so an
        # unvalidated one is strictly more dangerous than an unvalidated upgrade.
        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            migrate.downgrade_to(connection, "base", expected=expected)
            connection.commit()

            assert migrate.current_revision(connection) is None
            remaining = connection.execute(
                text(
                    "SELECT count(*) FROM information_schema.tables "
                    "WHERE table_schema = :schema AND table_name IN ('tenants','workspaces')"
                ),
                {"schema": SCHEMA},
            ).scalar()
            assert remaining == 0

            assert migrate.upgrade_to_head(connection, expected=expected) == migrate.head_revision()
            connection.commit()
    finally:
        drop_disposable_database(handle)
