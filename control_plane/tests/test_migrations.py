"""Migrations: they reach head, they match the models, and they go back down again.

The schema assertions here are the ones a later milestone would otherwise silently
break -- UUID keys, ``timestamptz``, tenant-local uniqueness, forced row security, the
pinned schema, and the helper-function grants.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

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
    assert migrate.head_revision() == "0003_auth_context_and_audit"


def test_every_revision_fits_the_version_column():
    """``alembic_version.version_num`` is ``varchar(32)``, and a longer id fails at UPDATE.

    Not at ``CREATE``, and not at the start of the migration -- at the moment Alembic
    stamps the new revision, after the DDL has run. So a too-long name is a migration that
    applies its schema changes and then reports failure, which is the worst shape a
    migration failure can have. Found the honest way, by writing one.
    """
    from alembic.script import ScriptDirectory

    revisions = list(ScriptDirectory(str(migrate.MIGRATIONS_DIR)).walk_revisions())
    assert revisions, "the migration history is empty, so this proves nothing"
    for revision in revisions:
        assert len(revision.revision) <= 32, (
            f"{revision.revision!r} is {len(revision.revision)} characters; "
            "alembic_version.version_num is varchar(32)"
        )


#: Tables the metadata comparison deliberately does not see. Named here rather than
#: inline so that adding one is a decision somebody has to write down.
UNMODELLED_TABLES = frozenset({"auth_transaction_context"})


def _include_name(name, type_, parent_names) -> bool:
    if type_ == "schema":
        return name == SCHEMA
    if type_ == "table":
        return name not in UNMODELLED_TABLES
    return True


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
                #
                # ``auth_transaction_context`` is skipped too -- at the *name* stage, so it
                # is never reflected and no warning is raised about its type. It is internal
                # machinery rather than a model: written by one SECURITY DEFINER function,
                # read by one more, reachable by no role and no ORM query. Its key column is
                # ``xid8``, which has no SQLAlchemy type, so declaring it would mean
                # inventing one and then comparing the invention against itself. Its shape
                # is asserted directly instead, in the test immediately below.
                "include_name": _include_name,
            },
        )
        diffs = [d for d in compare_metadata(context, Base.metadata) if VERSION_TABLE not in repr(d)]
    assert diffs == [], f"migration and models disagree: {diffs}"


def test_the_transaction_context_table_has_the_shape_the_design_needs(owner_engine):
    """Asserted here because ``compare_metadata`` deliberately skips it -- see above.

    Three properties carry the whole mechanism. The primary key is the **backend pid**, so
    the table holds one row per backend and never grows. The authority column is
    ``xid8``, so a row is readable only by the transaction that wrote it and no future
    transaction can ever match a committed one. And it is **unlogged**, because every row
    is dead the moment its transaction ends, so the WAL it would write on every
    authenticated request buys nothing.
    """
    with owner_engine.connect() as connection:
        columns = dict(
            connection.execute(
                text(
                    "SELECT column_name, data_type FROM information_schema.columns "
                    "WHERE table_schema = :s AND table_name = 'auth_transaction_context'"
                ),
                {"s": SCHEMA},
            ).all()
        )
        persistence, kind = connection.execute(
            text(
                "SELECT c.relpersistence, c.relkind FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = :s AND c.relname = 'auth_transaction_context'"
            ),
            {"s": SCHEMA},
        ).one()
        primary_key = connection.execute(
            text(
                "SELECT a.attname FROM pg_index i "
                "JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "
                "WHERE i.indrelid = CAST(:rel AS regclass) AND i.indisprimary"
            ),
            {"rel": f"{SCHEMA}.auth_transaction_context"},
        ).scalars().all()

    assert columns["backend_pid"] == "integer"
    assert columns["xact_id"] == "xid8"
    assert columns["tenant_id"] == "uuid"
    assert columns["scopes"] == "ARRAY"
    assert columns["bound_at"] == "timestamp with time zone"
    assert primary_key == ["backend_pid"], primary_key
    assert persistence == "u", "the context table should be UNLOGGED"
    assert kind == "r"


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
    """Reads and writes are both scoped, on every tenant-owned table, by command.

    Since Milestone 2.3 there is one policy per command rather than one ``FOR ALL``
    policy: that is what makes "no policy" mean "no access" for a command nobody wrote a
    rule for. What has to be true is unchanged -- no command reaches a row without the
    tenant predicate -- and the predicate now names the **authenticated** tenant rather
    than a setting the caller could have written.
    """
    policies = _policies(owner_engine)
    assert set(policies) == set(TENANT_SCOPED_TABLES)

    def carries_predicate(expression, tenant_column) -> bool:
        return bool(expression) and "auth_tenant_id()" in expression and tenant_column in expression

    for table, tenant_column in TENANT_SCOPED_TABLES.items():
        assert policies[table], f"{table}: no policy at all"
        commands = {p["cmd"] for p in policies[table]}
        assert {"SELECT", "INSERT"} <= commands, (table, commands)
        assert "ALL" not in commands, (
            f"{table}: a FOR ALL policy hides which commands were actually considered"
        )

        # The two halves are asserted **independently**. Checking `qual or with_check`
        # would have read only `qual` for a FOR ALL policy, so a policy whose WITH CHECK
        # had been dropped or written against the wrong column would still have passed
        # while writes went unconstrained.
        read_scoped = False
        write_scoped = False
        for policy in policies[table]:
            if policy["cmd"] in ("SELECT", "UPDATE", "DELETE"):
                assert carries_predicate(policy["qual"], tenant_column), (
                    f"{table}: {policy['name']} ({policy['cmd']}) has no tenant-scoped USING clause, "
                    f"so reads through it are unconstrained: {policy['qual']!r}"
                )
                read_scoped = read_scoped or policy["cmd"] == "SELECT"
            if policy["cmd"] in ("INSERT", "UPDATE"):
                assert carries_predicate(policy["with_check"], tenant_column), (
                    f"{table}: {policy['name']} ({policy['cmd']}) has no tenant-scoped WITH CHECK, "
                    f"so writes through it are unconstrained: {policy['with_check']!r}"
                )
                write_scoped = write_scoped or policy["cmd"] == "INSERT"
        assert read_scoped, f"{table}: no policy scopes reads"
        assert write_scoped, f"{table}: no policy scopes writes"


def test_no_policy_anywhere_reads_a_caller_settable_value(owner_engine):
    """``AUTH-BOUND-TENANT-CONTEXT``, asserted on the whole policy catalogue at once.

    The Milestone 2.1 mechanism was ``current_setting('app.tenant_id')``, which any holder
    of the connection could write. Nothing may read it again -- not through the old helper,
    which migration 0003 drops, and not through a new predicate somebody adds later that
    reaches for ``current_setting`` directly.
    """
    for table, policies in _policies(owner_engine).items():
        for policy in policies:
            expression = f"{policy['qual']} {policy['with_check']}"
            assert "current_setting" not in expression, (
                f"{table}.{policy['name']} reads a GUC, which any caller can set"
            )
            assert "app_current_tenant_id" not in expression, (
                f"{table}.{policy['name']} still calls the Milestone 2.1 helper"
            )


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
        assert names == [f"{table}_authenticated_append", f"{table}_authenticated_read"]


def test_the_tenant_accessor_returns_null_without_a_context(owner_engine):
    """Fail closed, on the owner connection, which holds every privilege there is."""
    with owner_engine.connect() as connection:
        assert connection.execute(text(f"SELECT {SCHEMA}.auth_tenant_id()")).scalar() is None
        assert connection.execute(text(f"SELECT {SCHEMA}.auth_has_scope('workspace:read')")).scalar() is False


def test_the_milestone_21_helper_is_gone(owner_engine):
    """Dropped rather than deprecated.

    A function that looks like the tenant-context mechanism and is not one is worse than
    no function at all: the next person to read a policy would find two candidates and no
    way to tell which one decides.
    """
    with owner_engine.connect() as connection:
        assert connection.execute(
            text(
                "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = :schema AND p.proname = 'app_current_tenant_id'"
            ),
            {"schema": SCHEMA},
        ).scalar() == 0


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
    assert set(migration.APPEND_ONLY_TABLES) < APPEND_ONLY_TABLES, (
        "0002 describes the two tables it created; audit_events is 0003's"
    )
    for table, column in migration.APPEND_ONLY_TABLES.items():
        assert TENANT_SCOPED_TABLES[table] == column


def test_the_third_migration_mirrors_the_model_and_catalogue_constants():
    """0003 duplicates the scope catalogue and the audit vocabulary; this pins the copy.

    Same reason as 0002: a migration that imported the models would stop being a record of
    what was applied. The copy is checked instead of prevented.
    """
    from firmbatch.control_plane.security import authorization

    migration = _load_migration_module("0003_auth_context_and_audit")

    assert migration.KNOWN_SCOPES == authorization.KNOWN_SCOPES
    assert migration.MAX_SCOPES_PER_BINDING == authorization.MAX_SCOPES_PER_BINDING
    assert migration.AUDIT_OUTCOMES == models.AUDIT_OUTCOMES
    assert migration.AUDIT_ACTOR_KINDS == models.AUDIT_ACTOR_KINDS
    assert migration.DOTTED_NAME_REGEX == models.DOTTED_NAME_REGEX
    assert migration.SIMPLE_NAME_REGEX == models.SIMPLE_NAME_REGEX
    assert migration.FINGERPRINT_REGEX == models.CREDENTIAL_FINGERPRINT_REGEX
    assert migration.MAX_METADATA_BYTES == models.MAX_METADATA_BYTES
    # The credential format the database enforces is the one the generator mints.
    from firmbatch.control_plane.security import secrets as secrets_module

    assert migration.CREDENTIAL_FORMAT_REGEX == secrets_module.BEARER_CREDENTIAL_REGEX.pattern
    # And every policied table appears in the migration's policy catalogue.
    assert set(migration.POLICIES) == set(TENANT_SCOPED_TABLES)


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


def test_the_authentication_migration_reverses_to_the_milestone_22_shape(environment):
    """One step back, and the database is the one Milestone 2.2 left, exactly.

    The step to ``base`` above proves the whole history reverses. This proves the more
    demanding thing: that stopping at ``0002`` leaves a *working* database rather than a
    stripped one. ``0003`` replaced every policy and dropped the helper they called, so its
    downgrade has to put both back -- and a downgrade that dropped the new policies without
    restoring the old ones would leave a schema nothing could read or write, which is a
    failure mode a round trip to ``base`` cannot detect.
    """
    handle = create_disposable_database(environment)
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            migrate.downgrade_to(connection, "0002_idempotency_and_outbox", expected=expected)
            connection.commit()
            assert migrate.current_revision(connection) == "0002_idempotency_and_outbox"

            # The Milestone 2.3 objects are gone.
            for relation in ("auth_bindings", "audit_events"):
                assert connection.execute(
                    text(
                        "SELECT count(*) FROM information_schema.tables "
                        "WHERE table_schema = :schema AND table_name = :table"
                    ),
                    {"schema": SCHEMA, "table": relation},
                ).scalar() == 0
            assert connection.execute(
                text(
                    "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = :schema AND p.proname LIKE 'auth%'"
                ),
                {"schema": SCHEMA},
            ).scalar() == 0

            # And the Milestone 2.2 mechanism is back and functional: the helper exists,
            # every remaining table has its old policy, and the policies read the helper.
            assert connection.execute(
                text(f"SELECT {SCHEMA}.app_current_tenant_id()")
            ).scalar() is None
            policies = connection.execute(
                text(
                    "SELECT tablename, policyname, coalesce(qual, '') || ' ' || coalesce(with_check, '') "
                    "FROM pg_policies WHERE schemaname = :schema"
                ),
                {"schema": SCHEMA},
            ).all()
            by_table: dict[str, list] = {}
            for table, name, expression in policies:
                by_table.setdefault(table, []).append((name, expression))
            assert set(by_table) == {"tenants", "workspaces", "idempotency_records", "outbox_events"}
            for table, entries in by_table.items():
                for name, expression in entries:
                    assert "app_current_tenant_id" in expression, (table, name)

            # A round trip back up leaves the head where it started.
            assert migrate.upgrade_to_head(connection, expected=expected) == migrate.head_revision()
            connection.commit()
            assert migrate.current_revision(connection) == migrate.head_revision()
    finally:
        drop_disposable_database(handle)


def test_the_grants_still_apply_after_a_round_trip(environment):
    """Role wiring lives outside Alembic, so a migration round trip must not invalidate it.

    ``db/roles.py`` names functions and tables that ``0003`` creates. If a downgrade left
    the schema in a state those grants could not be applied to, the failure would appear
    at the next environment provisioning rather than here -- which is late.
    """
    from firmbatch.control_plane.db import roles

    handle = create_disposable_database(environment)
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            migrate.downgrade_to(connection, "base", expected=expected)
            connection.commit()
            migrate.upgrade_to_head(connection, expected=expected)
            connection.commit()

            roles.harden_database(connection, handle.database)
            roles.revoke_public_table_privileges(connection)
            roles.grant_application_role(connection, handle.application_role)
            roles.grant_provisioning_role(connection, handle.provisioning_role)
            connection.commit()

            granted = connection.execute(
                text(
                    "SELECT count(*) FROM information_schema.role_table_grants "
                    "WHERE table_schema = :schema AND grantee = :role"
                ),
                {"schema": SCHEMA, "role": handle.application_role},
            ).scalar()
            assert granted > 0
    finally:
        drop_disposable_database(handle)


# ------------------------------------------------- role wiring across a rollback
#
# Role wiring lives outside Alembic, and it is not schema-independent: every statement in
# ``db/roles.py`` names a table or a function, and which of those exist depends on the
# revision. Measured before this section was written:
#
#     upgrade to 0003, provision, downgrade to 0002, provision again
#     -> UndefinedTable: relation "firmbatch.auth_bindings" does not exist
#        [SQL: REVOKE ALL ON TABLE "firmbatch"."auth_bindings" FROM PUBLIC]
#
# So a controlled rollback left an environment that could not have its roles re-provisioned
# -- and the failure was on the *first* wiring call, before any grant had run, which is the
# good version of that bug rather than the bad one.
#
# The correction is revision-aware wiring with an explicit plan per supported revision, and
# a refusal for everything else. Catching the undefined-object error and continuing would
# have produced a half-wired database that reported success, which is the failure mode
# worth spending an explicit error to avoid.


def _wire(connection, handle):
    from firmbatch.control_plane.db import roles

    roles.harden_database(connection, handle.database)
    roles.revoke_public_table_privileges(connection)
    roles.grant_application_role(connection, handle.application_role)
    roles.grant_provisioning_role(connection, handle.provisioning_role)
    connection.commit()


def _granted(connection, role: str) -> dict:
    """``table -> {privileges}`` for one role, from the catalogue."""
    rows = connection.execute(
        text(
            "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
            "WHERE table_schema = :s AND grantee = :r"
        ),
        {"s": SCHEMA, "r": role},
    ).all()
    out: dict = {}
    for table, privilege in rows:
        out.setdefault(table, set()).add(privilege)
    return out


def _executable(connection, role: str) -> set:
    return set(
        connection.execute(
            text(
                "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = :s AND has_function_privilege(:r, p.oid, 'EXECUTE')"
            ),
            {"s": SCHEMA, "r": role},
        ).scalars()
    )


def test_role_provisioning_survives_a_rollback_to_0002_and_back(environment):
    """upgrade -> provision -> downgrade to 0002 -> provision -> re-upgrade -> provision.

    Every step provisions *and* validates, because "the statements did not raise" is not
    the property: the grant set at each revision has to be exactly the one that revision
    defines, and coming back up has to restore exactly what was there before going down.
    """
    from firmbatch.control_plane.db import roles

    handle = create_disposable_database(environment)
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            # --- at head, as the bootstrap left it -------------------------------------
            assert roles.schema_revision(connection) == roles.M2_3_REVISION
            _wire(connection, handle)
            head_tables = _granted(connection, handle.application_role)
            head_functions = _executable(connection, handle.application_role)
            head_provisioning = _granted(connection, handle.provisioning_role)

            assert head_tables["audit_events"] == {"SELECT"}, head_tables["audit_events"]
            assert "append_audit_event" in head_functions
            assert "auth_context_begin" not in head_functions
            assert "audit_events" not in head_provisioning

            # --- down to 0002 -----------------------------------------------------------
            migrate.downgrade_to(connection, roles.M2_2_REVISION, expected=expected)
            connection.commit()
            assert roles.schema_revision(connection) == roles.M2_2_REVISION

            _wire(connection, handle)
            rolled_back = _granted(connection, handle.application_role)
            assert set(rolled_back) == {
                "tenants",
                "workspaces",
                "idempotency_records",
                "outbox_events",
            }, rolled_back
            assert rolled_back["tenants"] == {"SELECT"}
            assert rolled_back["workspaces"] == {"SELECT", "INSERT", "UPDATE", "DELETE"}
            assert rolled_back["idempotency_records"] == {"SELECT", "INSERT"}
            # The Milestone 2.2 policies called this and it is back; none of the 2.3
            # functions exists to be granted.
            assert "app_current_tenant_id" in _executable(connection, handle.application_role)
            assert _granted(connection, handle.provisioning_role) == {
                "tenants": {"SELECT", "INSERT", "UPDATE"}
            }

            # --- and back up -------------------------------------------------------------
            migrate.upgrade_to_head(connection, expected=expected)
            connection.commit()
            assert roles.schema_revision(connection) == roles.M2_3_REVISION

            _wire(connection, handle)
            assert _granted(connection, handle.application_role) == head_tables
            assert _executable(connection, handle.application_role) == head_functions
            assert _granted(connection, handle.provisioning_role) == head_provisioning
    finally:
        drop_disposable_database(handle)


def test_an_unsupported_revision_is_refused_rather_than_guessed_at(environment):
    """``0001`` has a schema and no wiring plan, so wiring it is an error with a name.

    The alternative -- letting each statement fail on whichever object it reached first --
    is how a half-wired database gets created, and a half-wired database looks provisioned.
    """
    from firmbatch.control_plane.db import roles

    handle = create_disposable_database(environment)
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            migrate.downgrade_to(connection, "0001_tenant_workspace_spine", expected=expected)
            connection.commit()

            with pytest.raises(roles.UnsupportedSchemaRevision) as exc:
                roles.schema_revision(connection)
            assert "no role-wiring plan" in str(exc.value)
            assert roles.M2_3_REVISION in str(exc.value)

            # And every entry point refuses, not merely the resolver.
            for call in (
                lambda: roles.harden_database(connection, handle.database),
                lambda: roles.revoke_public_table_privileges(connection),
                lambda: roles.grant_application_role(connection, handle.application_role),
                lambda: roles.grant_provisioning_role(connection, handle.provisioning_role),
            ):
                with pytest.raises(roles.UnsupportedSchemaRevision):
                    call()
                connection.rollback()
    finally:
        drop_disposable_database(handle)


def test_a_mixed_or_missing_revision_is_refused(environment):
    """A branched or half-stamped history has no single grant set.

    Three states, all of them refusals: two rows (a branch), zero rows (downgraded to
    ``base``, where Alembic keeps the version table and empties it), and no version table
    at all. Picking a plan in any of them would mean guessing.
    """
    from firmbatch.control_plane.db import roles

    handle = create_disposable_database(environment)
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            connection.execute(
                text(f"INSERT INTO {SCHEMA}.{VERSION_TABLE} (version_num) VALUES (:v)"),
                {"v": roles.M2_2_REVISION},
            )
            with pytest.raises(roles.UnsupportedSchemaRevision) as exc:
                roles.schema_revision(connection)
            assert "holds 2 rows" in str(exc.value)
            connection.rollback()

            migrate.downgrade_to(connection, "base", expected=expected)
            connection.commit()
            with pytest.raises(roles.UnsupportedSchemaRevision) as exc:
                roles.schema_revision(connection)
            assert "holds 0 rows" in str(exc.value)

            connection.execute(text(f"DROP TABLE {SCHEMA}.{VERSION_TABLE}"))
            with pytest.raises(roles.UnsupportedSchemaRevision) as exc:
                roles.schema_revision(connection)
            assert "does not exist" in str(exc.value)
            assert "Run the migrations first" in str(exc.value)
            connection.rollback()
    finally:
        drop_disposable_database(handle)


def test_a_stamped_revision_whose_objects_are_missing_is_refused(environment):
    """The other direction: the schema and its stamp disagree.

    At head, every Milestone 2.3 object is required to exist. If one is unexpectedly
    missing, that is an error naming it rather than an ``UndefinedTable`` from whichever
    statement happened to reach it first.
    """
    from firmbatch.control_plane.db import roles

    handle = create_disposable_database(environment)
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, _expected):
            connection.execute(text(f"ALTER TABLE {SCHEMA}.auth_bindings RENAME TO auth_bindings_x"))
            with pytest.raises(roles.UnsupportedSchemaRevision) as exc:
                roles.revision_plan(connection)
            assert "auth_bindings" in str(exc.value)
            assert "do not exist" in str(exc.value)
            connection.rollback()

            connection.execute(
                text(
                    f"ALTER FUNCTION {SCHEMA}.append_audit_event(text, text, text, uuid, uuid, jsonb) "
                    "RENAME TO append_audit_event_x"
                )
            )
            with pytest.raises(roles.UnsupportedSchemaRevision) as exc:
                roles.revision_plan(connection)
            assert "append_audit_event" in str(exc.value)
            connection.rollback()
    finally:
        drop_disposable_database(handle)


def test_the_plans_name_only_objects_their_revision_has(environment):
    """Both plans, checked against the real schema at their own revision.

    Data that names a nonexistent object would make the existence check above fail for the
    wrong reason -- and would do it only at provisioning time, in whatever environment ran
    the rollback.
    """
    from firmbatch.control_plane.db import roles

    assert set(roles.REVISION_PLANS) == set(roles.SUPPORTED_REVISIONS)
    handle = create_disposable_database(environment)
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            for revision in (roles.M2_3_REVISION, roles.M2_2_REVISION):
                if revision != roles.M2_3_REVISION:
                    migrate.downgrade_to(connection, revision, expected=expected)
                    connection.commit()
                plan = roles.revision_plan(connection)
                assert plan.revision == revision
                # Every table the grants name is a table the plan declares.
                granted = {table for table, _privileges in plan.application_grants}
                granted |= {table for table, _privileges in plan.provisioning_grants}
                assert granted <= set(plan.tables), (revision, granted - set(plan.tables))
    finally:
        drop_disposable_database(handle)
