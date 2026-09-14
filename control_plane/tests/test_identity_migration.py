"""Migration ``0005``: it mirrors the code's constants, and it reverses to ``0004`` exactly.

Same shape as the ``0002``/``0003``/``0004`` mirror tests in ``test_migrations.py``: a
migration may not import application code, so the grammar, the role table, the catalogue,
the secret prefixes, the actor vocabulary and the SQLSTATEs are written twice and pinned
here. The round trip runs on its own disposable database and compares the catalogue after
two separate downgrades to ``0004`` so that an object the downgrade forgot would differ.
"""

from __future__ import annotations

import importlib.util
import pathlib

from sqlalchemy import text

from firmbatch.control_plane import migrate
from firmbatch.control_plane.db import accounts, models, roles
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.security import authorization, passwords, permissions
from firmbatch.control_plane.security import secrets as secrets_module
from firmbatch.control_plane.testing.bootstrap import create_disposable_database, drop_disposable_database
from firmbatch.control_plane.tests import identity_helpers

REVISION = "0005_identity_and_membership"


def _load_migration_module(revision: str):
    path = pathlib.Path(models.__file__).parent / "migrations" / "versions" / f"{revision}.py"
    spec = importlib.util.spec_from_file_location(f"firmbatch_migration_{revision}_identity", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_fifth_migration_mirrors_the_model_and_catalogue_constants():
    migration = _load_migration_module(REVISION)
    third = _load_migration_module("0003_auth_context_and_audit")

    assert migration.revision == REVISION == roles.M3_1_REVISION
    assert migration.down_revision == roles.M2_4_REVISION

    # The grammar shared with the earlier migrations, unchanged.
    assert migration.SLUG_REGEX == models.SLUG_REGEX
    assert migration.DOTTED_NAME_REGEX == models.DOTTED_NAME_REGEX
    assert migration.SIMPLE_NAME_REGEX == models.SIMPLE_NAME_REGEX
    assert migration.IDEMPOTENCY_KEY_REGEX == models.IDEMPOTENCY_KEY_REGEX
    assert migration.FINGERPRINT_REGEX == models.CREDENTIAL_FINGERPRINT_REGEX
    assert migration.IDEMPOTENCY_STATUS_COMPLETED == models.IDEMPOTENCY_STATUS_COMPLETED
    assert migration.MAX_METADATA_BYTES == models.MAX_METADATA_BYTES

    # Identity: addresses, hashes, roles, statuses, token kinds, the label bound.
    assert migration.EMAIL_REGEX == models.EMAIL_REGEX
    assert migration.EMAIL_MAX_LENGTH == models.EMAIL_MAX_LENGTH
    assert migration.PASSWORD_HASH_REGEX == models.PASSWORD_HASH_REGEX == passwords.PASSWORD_HASH_REGEX
    assert migration.PASSWORD_HASH_MAX_LENGTH == models.PASSWORD_HASH_MAX_LENGTH == passwords.PASSWORD_HASH_MAX_LENGTH
    assert migration.MEMBERSHIP_ROLES == models.MEMBERSHIP_ROLES == permissions.MEMBERSHIP_ROLES
    assert migration.TOKEN_KINDS == models.ACCOUNT_TOKEN_KINDS
    assert migration.ACCOUNT_STATUSES == models.ACCOUNT_STATUSES
    assert migration.LABEL_MAX_LENGTH == models.CREDENTIAL_LABEL_MAX_LENGTH
    assert migration.IDENTITY_SECRET_PREFIXES == secrets_module.IDENTITY_SECRET_PREFIXES

    # The role table, character for character, and the catalogue it is bounded by.
    assert set(migration.ROLE_SCOPES) == set(permissions.MEMBERSHIP_ROLES)
    for role, scopes in migration.ROLE_SCOPES.items():
        assert scopes == permissions.ROLE_PERMISSIONS[role] == tuple(sorted(scopes)), role
    assert migration.KNOWN_SCOPES == authorization.KNOWN_SCOPES == third.KNOWN_SCOPES
    assert migration.MAX_SCOPES_PER_BINDING == authorization.MAX_SCOPES_PER_BINDING
    assert migration.API_ISSUABLE_SCOPES == permissions.API_ISSUABLE_SCOPES
    assert set(migration.API_ISSUABLE_SCOPES) == set(authorization.DELEGABLE_SCOPES) - {"credential:manage"}

    # The actor vocabulary: the legacy pair is what 0003/0004 wrote, the widened triple is
    # what the models now declare, and the session shape is exactly one more disjunct.
    assert migration.LEGACY_AUDIT_ACTOR_KINDS == models.AUDIT_ACTOR_KINDS == third.AUDIT_ACTOR_KINDS
    assert migration.ACTOR_KINDS == models.ACTOR_KINDS
    assert migration.SESSION_ACTOR_KIND == models.SESSION_ACTOR_KIND == "session"
    assert migration.ACTOR_SHAPE == models.ACTOR_SHAPE_SQL
    assert migration.ACTOR_SHAPE.startswith(migration.LEGACY_ACTOR_SHAPE)
    assert migration.ACTOR_SHAPE.removeprefix(migration.LEGACY_ACTOR_SHAPE).count(" OR ") == 1

    # The SQLSTATEs, mirrored where they are translated, distinct, and outside 0004's six.
    assert migration.IDENTITY_REFUSED_SQLSTATE == accounts.IDENTITY_REFUSED_SQLSTATE
    assert migration.IDENTITY_CONFLICT_SQLSTATE == accounts.IDENTITY_CONFLICT_SQLSTATE
    assert migration.IDENTITY_KEY_REUSE_SQLSTATE == accounts.IDENTITY_KEY_REUSE_SQLSTATE
    assert migration.IDENTITY_CONTEXT_SQLSTATE == accounts.IDENTITY_CONTEXT_SQLSTATE
    # The neutral refusal is written in both places rather than passed through: psycopg
    # renders a plpgsql exception's CONTEXT, which names the raising line, so the database
    # text is dropped by the translator and the Python text carries the explanation.
    assert migration.IDENTITY_REFUSED_MESSAGE.startswith("firmbatch: ")
    assert accounts.IDENTITY_REFUSED_MESSAGE.startswith(migration.IDENTITY_REFUSED_MESSAGE.removeprefix("firmbatch: "))
    codes = {
        migration.IDENTITY_REFUSED_SQLSTATE,
        migration.IDENTITY_CONFLICT_SQLSTATE,
        migration.IDENTITY_KEY_REUSE_SQLSTATE,
        migration.IDENTITY_CONTEXT_SQLSTATE,
    }
    assert len(codes) == 4
    fourth = _load_migration_module("0004_lifecycle_state_machines")
    earlier = {
        fourth.LIFECYCLE_CONFLICT_SQLSTATE,
        fourth.LIFECYCLE_NOT_ALLOWED_SQLSTATE,
        fourth.LIFECYCLE_DEFINITION_SQLSTATE,
        fourth.LIFECYCLE_KEY_REUSE_SQLSTATE,
        fourth.LIFECYCLE_PROVENANCE_SQLSTATE,
        fourth.OUTBOX_LINK_SQLSTATE,
    }
    assert not codes & earlier
    for code in codes:
        assert len(code) == 5 and code.startswith("FB"), code

    # The function inventory and the protected catalogue, against the wiring layer.
    assert {(name, signature) for name, signature, _a in migration.FUNCTIONS} == set(roles.ALL_IDENTITY_FUNCTIONS)
    assert set(migration.PROTECTED_TABLES) == set(models.IDENTITY_TABLES)
    assert set(migration.PROTECTED_TABLES) == set(roles._M3_1_PROTECTED_TABLES) - set(roles._M2_4_PROTECTED_TABLES)


def test_the_secret_shape_recogniser_is_appended_to_and_restored_from_0003s_text():
    """The seven-shape function is 0003's six plus one; the downgrade puts 0003's text back."""
    migration = _load_migration_module(REVISION)
    third = _load_migration_module("0003_auth_context_and_audit")

    assert migration.LEGACY_SECRET_SHAPES == third.SECRET_SHAPES
    assert migration.SECRET_SHAPES == secrets_module.SECRET_SHAPE_PATTERNS
    assert migration.SECRET_SHAPES[: len(third.SECRET_SHAPES)] == third.SECRET_SHAPES
    assert len(migration.SECRET_SHAPES) == len(third.SECRET_SHAPES) + 1
    # The legacy rendering is byte-for-byte what 0003 executed; the restore differs from it
    # by the one word a downgrade needs, and the head rendering by the appended shape.
    assert migration.LEGACY_SECRET_SHAPE_SQL == third._SECRET_SHAPE
    assert migration.LEGACY_SECRET_SHAPE_RESTORE_SQL.replace("CREATE OR REPLACE FUNCTION", "CREATE FUNCTION", 1) == (
        migration.LEGACY_SECRET_SHAPE_SQL
    )
    assert migration.SECRET_SHAPE_SQL.startswith("\nCREATE OR REPLACE FUNCTION") or (
        migration.SECRET_SHAPE_SQL.lstrip().startswith("CREATE OR REPLACE FUNCTION")
    )
    assert "fb[cirsv]_" in migration.SECRET_SHAPE_SQL and "fb[cirsv]_" not in migration.LEGACY_SECRET_SHAPE_SQL


def test_the_revised_bind_authenticated_context_restores_0003s_text_exactly():
    """Milestone 3.1 replaces bind_authenticated_context to recheck membership and the account
    security epoch; the downgrade puts 0003's body back byte-for-byte, and 0003 is unedited."""
    migration = _load_migration_module(REVISION)
    third = _load_migration_module("0003_auth_context_and_audit")

    # The legacy constant is 0003's function verbatim, so the downgrade restores exactly what
    # a fresh migration to 0004 has.
    assert migration._LEGACY_BIND_AUTHENTICATED_CONTEXT == third._BIND_AUTHENTICATED_CONTEXT
    assert migration._LEGACY_BIND_AUTHENTICATED_CONTEXT_RESTORE.replace(
        "CREATE OR REPLACE FUNCTION", "CREATE FUNCTION", 1
    ) == third._BIND_AUTHENTICATED_CONTEXT
    # The head version differs from the legacy one, adds the epoch/membership recheck, and
    # still opens with the writable-primary guard the ordering test depends on.
    assert migration._BIND_AUTHENTICATED_CONTEXT_HEAD != migration._LEGACY_BIND_AUTHENTICATED_CONTEXT
    assert "principal_epoch" in migration._BIND_AUTHENTICATED_CONTEXT_HEAD
    assert "membership_id IS NOT NULL" in migration._BIND_AUTHENTICATED_CONTEXT_HEAD
    head_body = migration._BIND_AUTHENTICATED_CONTEXT_HEAD
    assert head_body[head_body.index("PERFORM"):].startswith(
        f"PERFORM {SCHEMA}.auth_require_writable_primary()"
    )


def _unqualified(rows) -> list:
    """``pg_get_*def`` and column defaults render a name schema-qualified only when the
    schema is off the search path, which a migration run changes; the content does not."""
    return [tuple(cell.replace(f"{SCHEMA}.", "") if isinstance(cell, str) else cell for cell in row) for row in rows]


def _catalogue(connection) -> dict:
    """Everything a downgrade has to put back, as the catalogue holds it. ACLs excluded:
    this database is never wired."""
    raw = _catalogue_raw(connection)
    return {key: (_unqualified(rows) if key != "functions" else rows) for key, rows in raw.items()}


def _catalogue_raw(connection) -> dict:
    return {
        "functions": connection.execute(
            text(
                "SELECT p.proname, pg_get_function_identity_arguments(p.oid), p.prosrc, p.prosecdef, "
                "p.provolatile, coalesce(array_to_string(p.proconfig, ','), '') "
                "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = :s ORDER BY 1, 2"
            ),
            {"s": SCHEMA},
        ).all(),
        "tables": connection.execute(
            text(
                "SELECT c.relname, c.relkind, c.relpersistence, c.relrowsecurity, c.relforcerowsecurity "
                "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = :s AND c.relkind IN ('r', 'i', 'c') ORDER BY 1"
            ),
            {"s": SCHEMA},
        ).all(),
        "columns": connection.execute(
            text(
                "SELECT table_name, column_name, udt_name, is_nullable, column_default "
                "FROM information_schema.columns WHERE table_schema = :s ORDER BY 1, 2"
            ),
            {"s": SCHEMA},
        ).all(),
        "constraints": connection.execute(
            text(
                "SELECT t.relname, c.conname, c.contype, pg_get_constraintdef(c.oid) "
                "FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid "
                "JOIN pg_namespace n ON n.oid = t.relnamespace WHERE n.nspname = :s ORDER BY 1, 2"
            ),
            {"s": SCHEMA},
        ).all(),
        "indexes": connection.execute(
            text("SELECT tablename, indexname, indexdef FROM pg_indexes WHERE schemaname = :s ORDER BY 1, 2"),
            {"s": SCHEMA},
        ).all(),
        "triggers": connection.execute(
            text(
                "SELECT c.relname, t.tgname, pg_get_triggerdef(t.oid) FROM pg_trigger t "
                "JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = :s AND NOT t.tgisinternal ORDER BY 1, 2"
            ),
            {"s": SCHEMA},
        ).all(),
        "policies": connection.execute(
            text(
                "SELECT tablename, policyname, cmd, roles, qual, with_check FROM pg_policies "
                "WHERE schemaname = :s ORDER BY 1, 2"
            ),
            {"s": SCHEMA},
        ).all(),
        "types": connection.execute(
            text(
                "SELECT t.typname FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace "
                "WHERE n.nspname = :s AND t.typtype = 'c' AND t.typrelid IN "
                "(SELECT oid FROM pg_class WHERE relkind = 'c') ORDER BY 1"
            ),
            {"s": SCHEMA},
        ).all(),
    }


def test_the_downgrade_to_0004_restores_the_milestone_24_catalogue_exactly(environment):
    """Down, up, down: the two downgraded catalogues are equal, and neither knows identity.

    Equality of two independent downgrades is what catches an object the downgrade forgot
    (it would be present the second time and not the first only if the upgrade were also
    broken; present both times means the downgrade leaves it), and the explicit assertions
    below are the ones a reader would otherwise have to infer from the equality.
    """
    handle = create_disposable_database(environment)
    identity_relations = set(models.IDENTITY_TABLES) | {"identity_transaction_context"}
    identity_functions = {name for name, _s in roles.ALL_IDENTITY_FUNCTIONS}
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            head = _catalogue(connection)
            assert identity_relations <= {row[0] for row in head["tables"]}
            assert identity_functions <= {row[0] for row in head["functions"]}

            migrate.downgrade_to(connection, roles.M2_4_REVISION, expected=expected)
            connection.commit()
            first = _catalogue(connection)
            assert migrate.current_revision(connection) == roles.M2_4_REVISION

            names = {row[0] for row in first["tables"]}
            assert not identity_relations & names
            assert not identity_functions & {row[0] for row in first["functions"]}
            assert not {"identity_context_row", "identity_session_row"} & {row[0] for row in first["types"]}
            columns = {(row[0], row[1]) for row in first["columns"]}
            for column in (
                "membership_id", "workspace_id", "label", "last_used_at", "rotated_from_id", "principal_epoch"
            ):
                assert ("auth_bindings", column) not in columns, column
            constraints = {(row[0], row[1]): row[3] for row in first["constraints"]}
            for table in ("audit_events", "lifecycle_transitions"):
                assert "session" not in constraints[(table, f"ck_{table}_actor_kind_known")]
                assert "session" not in constraints[(table, f"ck_{table}_actor_shape")]
            secret_shape = next(row[2] for row in first["functions"] if row[0] == "secret_shape")
            assert "fb[cirsv]_" not in secret_shape and "fbk_" in secret_shape
            assert not {row[1] for row in first["triggers"]} & {
                "memberships_revocation_cascade", "workspaces_directory_sync",
                "account_tokens_append_only", "account_idempotency_records_append_only",
            }
            # The Milestone 2.4 plan wires this revision and nothing identity-shaped.
            assert roles.schema_revision(connection) == roles.M2_4_REVISION

            assert migrate.upgrade_to_head(connection, expected=expected) == migrate.head_revision()
            connection.commit()
            again = _catalogue(connection)
            assert again == head
            constraints = {(row[0], row[1]): row[3] for row in again["constraints"]}
            for table in ("audit_events", "lifecycle_transitions"):
                assert "'session'" in constraints[(table, f"ck_{table}_actor_kind_known")]
                assert "'session'" in constraints[(table, f"ck_{table}_actor_shape")]

            migrate.downgrade_to(connection, roles.M2_4_REVISION, expected=expected)
            connection.commit()
            second = _catalogue(connection)
            assert second == first
            assert migrate.upgrade_to_head(connection, expected=expected) == migrate.head_revision()
            connection.commit()
    finally:
        drop_disposable_database(handle)


def test_the_identity_tables_are_declared_protected_and_unpoliced(owner_engine):
    """No policy on any identity table: protection is the absence of a grant, not a predicate."""
    with owner_engine.connect() as connection:
        policed = set(
            connection.execute(
                text("SELECT DISTINCT tablename FROM pg_policies WHERE schemaname = :s"), {"s": SCHEMA}
            ).scalars()
        )
        rls = dict(
            connection.execute(
                text(
                    "SELECT c.relname, c.relrowsecurity FROM pg_class c JOIN pg_namespace n "
                    "ON n.oid = c.relnamespace WHERE n.nspname = :s AND c.relkind = 'r'"
                ),
                {"s": SCHEMA},
            ).all()
        )
    for table in models.IDENTITY_TABLES:
        assert table not in policed, table
        assert rls[table] is False, table
        assert table in models.PROTECTED_TABLES
        assert table not in models.TENANT_SCOPED_TABLES


def test_the_populated_downgrade_and_reupgrade_ladder_is_deterministic(environment):
    """Review gap: a downgrade after real M3.1 activity previously failed with 23514.

    M3.1 activity records ``actor_kind = 'session'`` rows in audit_events; the 0003/0004
    actor-kind CHECK admits only 'credential' and 'provisioning', so re-adding it during the
    downgrade violated the constraint (SQLSTATE 23514) once such rows existed. The downgrade
    now reconciles those rows first. This exercises the populated ladder end to end: create a
    dedicated disposable database, do enough identity work to write session-actor audit rows,
    downgrade to 0004, and re-upgrade to head.
    """
    handle = create_disposable_database(environment)
    application = db_engine.create_application_engine(handle.application_url)
    authenticator = db_engine.create_application_engine(handle.authenticator_url)
    try:
        # Register the authenticator engine for this dedicated database so the helpers' login
        # path finds it (keyed by database, so it does not disturb the session-wide one).
        identity_helpers.register_authenticator_engine(authenticator)

        # Signup, verify, login, create a workspace, invite and accept, issue a credential:
        # every one writes a session-actor audit row in the new tenant.
        owner, created = identity_helpers.owner_with_workspace(application)
        member = identity_helpers.person(application, "member")
        identity_helpers.invite_and_accept(application, owner, member, role="member")
        identity_helpers.issue_credential(application, owner, scopes=("workspace:read",))

        with migrate.migration_connection(handle.migration_url) as (connection, _expected):
            # audit_events carries FORCE row security, which applies to the owner too, so a
            # plain count with no tenant context sees nothing. NO FORCE (owner-only, restored
            # immediately) lets this confirm the setup actually wrote session-actor rows.
            connection.execute(text(f"ALTER TABLE {SCHEMA}.audit_events NO FORCE ROW LEVEL SECURITY"))
            session_rows = connection.execute(
                text(f"SELECT count(*) FROM {SCHEMA}.audit_events WHERE actor_kind = 'session'")
            ).scalar()
            connection.execute(text(f"ALTER TABLE {SCHEMA}.audit_events FORCE ROW LEVEL SECURITY"))
            connection.commit()
            assert session_rows > 0, "the setup must have written session-actor audit rows"
    finally:
        # Dispose the runtime engines before the schema changes underneath them.
        application.dispose()
        authenticator.dispose()

    try:
        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            assert roles.schema_revision(connection) == roles.M3_3B_REVISION
            # The downgrade that used to fail with 23514 on populated data now succeeds.
            migrate.downgrade_to(connection, roles.M2_4_REVISION, expected=expected)
            connection.commit()
            assert migrate.current_revision(connection) == roles.M2_4_REVISION
            # The narrowed actor constraint is back, and no session-actor row remains to
            # violate it -- the reconciliation removed them.
            constraint = connection.execute(
                text(
                    "SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c "
                    "JOIN pg_class t ON t.oid = c.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace "
                    "WHERE n.nspname = :s AND t.relname = 'audit_events' AND c.conname = 'ck_audit_events_actor_kind_known'"
                ),
                {"s": SCHEMA},
            ).scalar_one()
            assert "session" not in constraint
            # The session-actor rows were reconciled away (owner-visible via NO FORCE); had
            # any survived, the constraint re-add above would have raised 23514 instead.
            connection.execute(text(f"ALTER TABLE {SCHEMA}.audit_events NO FORCE ROW LEVEL SECURITY"))
            remaining = connection.execute(
                text(f"SELECT count(*) FROM {SCHEMA}.audit_events WHERE actor_kind = 'session'")
            ).scalar()
            connection.execute(text(f"ALTER TABLE {SCHEMA}.audit_events FORCE ROW LEVEL SECURITY"))
            assert remaining == 0

            # Re-upgrade to head: the ladder is whole again.
            assert migrate.upgrade_to_head(connection, expected=expected) == migrate.head_revision()
            connection.commit()
            assert roles.schema_revision(connection) == roles.M3_3B_REVISION
    finally:
        drop_disposable_database(handle)
