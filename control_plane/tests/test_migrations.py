"""Migrations: they reach head, they match the models, and they go back down again.

The schema assertions here are the ones a later milestone would otherwise silently
break -- UUID keys, ``timestamptz``, tenant-local uniqueness, forced row security, the
pinned schema, and the helper-function grants.
"""

from __future__ import annotations

import importlib.util
import pathlib

from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect, text

from firmbatch.control_plane import migrate
from firmbatch.control_plane.db import models
from firmbatch.control_plane.db.base import SCHEMA, VERSION_TABLE
from firmbatch.control_plane.db.base import Base
from firmbatch.control_plane.db.models import APPEND_ONLY_TABLES, TENANT_SCOPED_TABLES
from firmbatch.control_plane.testing.bootstrap import create_disposable_database, drop_disposable_database


def _load_migration_module(revision: str):
    """Import one migration file by path. The versions directory is not a package."""
    path = pathlib.Path(models.__file__).parent / "migrations" / "versions" / f"{revision}.py"
    spec = importlib.util.spec_from_file_location(f"firmbatch_migration_{revision}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_bootstrap_reaches_the_expected_head(disposable_database, owner_engine):
    expected = migrate.head_revision()
    assert disposable_database.head_revision == expected
    with owner_engine.connect() as connection:
        assert migrate.current_revision(connection) == expected


def test_there_is_exactly_one_head():
    """A branched history is a migration that applies differently in two environments."""
    assert migrate.head_revision() == "0002_idempotency_and_outbox"


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
    assert set(inspector.get_table_names(schema=SCHEMA)) >= set(TENANT_SCOPED_TABLES) | {VERSION_TABLE}
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


def _policies(owner_engine) -> dict[str, list[dict]]:
    """Every policy in the pinned schema, grouped by table."""
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT tablename, policyname, cmd, qual, with_check "
                "FROM pg_policies WHERE schemaname = :schema ORDER BY tablename, policyname"
            ),
            {"schema": SCHEMA},
        ).all()
    grouped: dict[str, list[dict]] = {}
    for table, name, cmd, qual, check in rows:
        grouped.setdefault(table, []).append({"name": name, "cmd": cmd, "qual": qual, "with_check": check})
    return grouped


def test_every_tenant_scoped_table_has_an_isolation_policy(owner_engine):
    """Reads and writes are both scoped, on every tenant-owned table, in both shapes.

    Two shapes exist: the ``FOR ALL`` policy of the spine, and the read/append pair the
    append-only tables carry. What has to be true of both is the same thing -- no command
    reaches a row without the tenant predicate -- so this asserts that rather than the
    policy count.
    """
    policies = _policies(owner_engine)
    assert set(policies) == set(TENANT_SCOPED_TABLES)

    def carries_predicate(expression, tenant_column) -> bool:
        return bool(expression) and "app_current_tenant_id()" in expression and tenant_column in expression

    for table, tenant_column in TENANT_SCOPED_TABLES.items():
        assert policies[table], f"{table}: no policy at all"
        commands = {p["cmd"] for p in policies[table]}
        # Every table must scope reads and writes. ALL covers both; the append-only pair
        # covers them with one policy each.
        assert commands == {"ALL"} or commands == {"SELECT", "INSERT"}, (table, commands)

        # The two halves are asserted **independently**. Checking `qual or with_check`
        # would have read only `qual` for a FOR ALL policy, so a policy whose WITH CHECK
        # had been dropped or written against the wrong column would still have passed
        # while writes went unconstrained.
        read_scoped = False
        write_scoped = False
        for policy in policies[table]:
            if policy["cmd"] in ("ALL", "SELECT"):
                assert carries_predicate(policy["qual"], tenant_column), (
                    f"{table}: {policy['name']} ({policy['cmd']}) has no tenant-scoped USING clause, "
                    f"so reads through it are unconstrained: {policy['qual']!r}"
                )
                read_scoped = True
            if policy["cmd"] in ("ALL", "INSERT"):
                assert carries_predicate(policy["with_check"], tenant_column), (
                    f"{table}: {policy['name']} ({policy['cmd']}) has no tenant-scoped WITH CHECK, "
                    f"so writes through it are unconstrained: {policy['with_check']!r}"
                )
                write_scoped = True
        assert read_scoped, f"{table}: no policy scopes reads"
        assert write_scoped, f"{table}: no policy scopes writes"


def test_append_only_tables_have_no_update_or_delete_policy(owner_engine):
    """The half a grant cannot buy.

    Row security is FORCEd, and a command with no policy matches no row -- so with no
    UPDATE and no DELETE policy these tables are append-only for *every* role, including
    the table owner and any role a later migration adds. Revoking UPDATE from today's
    application role would only bind today's application role.
    """
    policies = _policies(owner_engine)
    assert APPEND_ONLY_TABLES, "the append-only set must not be empty"
    assert APPEND_ONLY_TABLES <= set(TENANT_SCOPED_TABLES)
    for table in APPEND_ONLY_TABLES:
        commands = {p["cmd"] for p in policies[table]}
        assert commands == {"SELECT", "INSERT"}, f"{table}: policies cover {sorted(commands)}"
        names = sorted(p["name"] for p in policies[table])
        assert names == [f"{table}_tenant_append", f"{table}_tenant_read"]


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


# ------------------------------------------------------- Milestone 2.2 schema shape


def test_the_migration_mirrors_the_model_constants():
    """0002 hard-codes the regexes and bounds; a divergence is a schema nobody described.

    The migration cannot import ``db/models.py`` -- a migration that follows the models
    stops being a record of what was applied -- so the constants are duplicated, and this
    is what stops the duplicate from drifting.

    Loaded by path: the versions directory is not a package, and the file name starts
    with a digit, so there is no import statement that could reach it.
    """
    migration = _load_migration_module("0002_idempotency_and_outbox")

    assert migration.DOTTED_NAME_REGEX == models.DOTTED_NAME_REGEX
    assert migration.SIMPLE_NAME_REGEX == models.SIMPLE_NAME_REGEX
    assert migration.IDEMPOTENCY_KEY_REGEX == models.IDEMPOTENCY_KEY_REGEX
    assert migration.FINGERPRINT_REGEX == models.FINGERPRINT_REGEX
    assert migration.IDEMPOTENCY_STATUS_COMPLETED == models.IDEMPOTENCY_STATUS_COMPLETED
    assert migration.MAX_METADATA_BYTES == models.MAX_METADATA_BYTES
    assert set(migration.APPEND_ONLY_TABLES) == APPEND_ONLY_TABLES
    for table, column in migration.APPEND_ONLY_TABLES.items():
        assert TENANT_SCOPED_TABLES[table] == column


def test_idempotency_keys_are_scoped_by_tenant_and_operation(owner_engine):
    """A globally unique key would collide across, and probe, the isolation boundary."""
    constraints = {
        c["name"]: c["column_names"]
        for c in inspect(owner_engine).get_unique_constraints("idempotency_records", schema=SCHEMA)
    }
    assert constraints["uq_idempotency_records_tenant_id_operation_idempotency_key"] == [
        "tenant_id",
        "operation",
        "idempotency_key",
    ]
    assert constraints["uq_idempotency_records_id_tenant_id"] == ["id", "tenant_id"]
    assert not any(cols == ["idempotency_key"] for cols in constraints.values()), (
        "an idempotency key must never be globally unique"
    )


def test_a_linked_outbox_event_is_tied_to_a_claim_in_the_same_tenant(owner_engine):
    """The composite reference, because FK checks run with row security bypassed."""
    fks = {fk["name"]: fk for fk in inspect(owner_engine).get_foreign_keys("outbox_events", schema=SCHEMA)}
    composite = fks["fk_outbox_events_idempotency_record_id_tenant_id"]
    assert composite["constrained_columns"] == ["idempotency_record_id", "tenant_id"]
    assert composite["referred_columns"] == ["id", "tenant_id"]
    assert composite["referred_table"] == "idempotency_records"
    assert composite["referred_schema"] == SCHEMA

    uniques = {
        c["name"]: c["column_names"]
        for c in inspect(owner_engine).get_unique_constraints("outbox_events", schema=SCHEMA)
    }
    # AT MOST ONE linked event per claim. A unique constraint bounds duplicates; it
    # cannot require that a claim has an event, so the "exactly one, atomically" property
    # is proved in test_idempotency.py and not here.
    assert uniques["uq_outbox_events_tenant_id_idempotency_record_id"] == ["tenant_id", "idempotency_record_id"]


def test_the_causation_link_is_optional(owner_engine):
    """The outbox serves every state transition, not only API mutations.

    An internal transition -- controller, reconciler, validator, lifecycle -- has no
    caller-supplied idempotency key, and requiring one would mean manufacturing a claim
    nobody can retry against.
    """
    columns = {
        c["name"]: c
        for c in inspect(owner_engine).get_columns("outbox_events", schema=SCHEMA)
    }
    assert columns["idempotency_record_id"]["nullable"] is True
    # Everything else that identifies the event stays mandatory.
    for required in ("tenant_id", "event_type", "aggregate_type", "aggregate_id", "attributes", "occurred_at"):
        assert columns[required]["nullable"] is False, required


def test_neither_new_table_has_a_binary_column(owner_engine):
    """A shape check on the schema, and deliberately not a claim about payload.

    Neither table has a ``bytea`` column, and the only free-form columns are ``jsonb``
    documents the database bounds. That makes storing bytes **inconvenient**; it does not
    make it impossible, because ``TEXT`` and ``JSONB`` hold text and an encoded payload is
    text. The data-flow proof that customer payload never reaches the API process or
    PostgreSQL (target architecture invariant 3) is Milestone 5's presigned S3 path, and
    is not established by any test in this milestone.
    """
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                """
                SELECT table_name, column_name, data_type
                FROM information_schema.columns
                WHERE table_schema = :schema AND table_name IN ('idempotency_records', 'outbox_events')
                """
            ),
            {"schema": SCHEMA},
        ).all()
    assert rows, "the M2.2 tables are missing"
    allowed = {"uuid", "text", "jsonb", "timestamp with time zone"}
    for table, column, data_type in rows:
        assert data_type in allowed, f"{table}.{column} is {data_type}"


def test_the_metadata_columns_are_bounded_objects_in_the_database(owner_engine):
    """The check constraints that hold when a writer bypasses ``db/idempotency.py``.

    Bounds, not proof: a bounded ``jsonb`` object is still a place text can go. What these
    establish is that the columns are objects and are small, which is defense in depth
    behind the metadata policy, not evidence that no content is present.
    """
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                """
                SELECT c.relname, con.conname, pg_get_constraintdef(con.oid)
                FROM pg_constraint con
                JOIN pg_class c ON c.oid = con.conrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = :schema AND con.contype = 'c'
                  AND c.relname IN ('idempotency_records', 'outbox_events')
                """
            ),
            {"schema": SCHEMA},
        ).all()
    definitions = {(table, name): definition for table, name, definition in rows}
    for table, column in (("idempotency_records", "result"), ("outbox_events", "attributes")):
        object_check = definitions[(table, f"ck_{table}_{column}_object")]
        bounded = definitions[(table, f"ck_{table}_{column}_bounded")]
        assert "jsonb_typeof" in object_check and "'object'" in object_check
        assert "octet_length" in bounded and str(models.MAX_METADATA_BYTES) in bounded
    # And the one durable status, so no 'in_progress' row can be written at all.
    status = definitions[("idempotency_records", "ck_idempotency_records_status_completed")]
    assert models.IDEMPOTENCY_STATUS_COMPLETED in status


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
