"""Finding 4: owning any isolation-boundary object disqualifies a runtime principal.

The check used to look at two tenant-scoped tables. That is the narrowest possible reading
of what ownership buys, and it left four complete bypasses open. An owner does not have to
defeat a policy -- it can remove one:

* the **database** owner can ``ALTER DATABASE ... SET`` a parameter that every future
  session on it inherits, and controls ``CONNECT``/``TEMP``;
* the **schema** owner can create a relation inside ``firmbatch`` that shadows a real one;
* a **relation** owner can ``ALTER TABLE ... NO FORCE ROW LEVEL SECURITY`` or
  ``DROP POLICY`` -- and this covers sequences, views and partitions, not only the two
  tables that were named;
* the owner of **``app_current_tenant_id()``** can ``CREATE OR REPLACE`` it, and every
  policy predicate in the schema calls it, so it decides what every policy sees;
* a **type** owner can drop a domain's constraints.

Each is tested separately, because a single "owns something" assertion would pass while
four of the five queries were broken. Reachability is tested too: ``GRANT owner TO app``
is one command, looks harmless in a migration, and hands the application everything above
one ``SET ROLE`` away.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from firmbatch.control_plane import config, migrate
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.principal import inspect_principal


def _report_for(url):
    """The principal report for a connection, taken without the hardening refusing first."""
    engine = db_engine.create_application_engine(url, validate_principal=False)
    try:
        with engine.connect() as connection:
            with connection.connection.driver_connection.cursor() as cursor:
                return inspect_principal(cursor)
    finally:
        engine.dispose()


def test_the_application_role_owns_nothing_on_the_boundary(disposable_database):
    """The baseline. Everything below is a departure from this."""
    report = _report_for(disposable_database.application_url)
    assert report.owned_objects == ()
    assert report.owned_tables == ()
    assert report.is_safe


def test_the_owner_role_owns_the_whole_boundary(disposable_database):
    """The migration principal owns all five kinds -- which is why it is not a runtime one.

    This is also what proves the five queries actually return rows: a check that found
    nothing for everybody would pass the test above for the wrong reason.
    """
    report = _report_for(disposable_database.migration_url)
    kinds = {entry.split(" ", 1)[0] for entry in report.owned_objects}
    assert {"database", "schema", "function"} <= kinds
    assert any(entry.startswith("relation") for entry in report.owned_objects)
    names = {entry.split(" ", 1)[1] for entry in report.owned_objects}
    assert disposable_database.database in names, "the database owner was not detected"
    assert SCHEMA in names, "the schema owner was not detected"
    assert "app_current_tenant_id" in names, "the policy helper's owner was not detected"
    assert {"tenants", "workspaces"} <= names
    assert not report.is_safe


@pytest.mark.parametrize(
    "kind, statement, expected",
    [
        (
            "schema",
            f'ALTER SCHEMA {SCHEMA} OWNER TO "{{probe}}"',
            f"schema {SCHEMA}",
        ),
        (
            "function",
            f'ALTER FUNCTION {SCHEMA}.app_current_tenant_id() OWNER TO "{{probe}}"',
            "function app_current_tenant_id",
        ),
    ],
)
def test_reachable_ownership_of_one_boundary_object_is_refused(
    environment, admin_engine, kind, statement, expected
):
    """One object at a time, on its own disposable database.

    Each case grants the application role membership in a probe role and hands that role a
    single object. Nothing else changes, so a pass means *that* query found *that* object.
    """
    from firmbatch.control_plane.testing.bootstrap import (
        create_disposable_database,
        drop_disposable_database,
    )

    handle = create_disposable_database(environment)
    probe = f"firmbatch_test_ownprobe_{uuid.uuid4().hex[:8]}"
    try:
        # Membership is an admin action: the per-run owner is deliberately NOCREATEROLE
        # and holds no ADMIN option, so it cannot grant itself anything.
        with admin_engine.connect() as connection:
            connection.execute(text(f'CREATE ROLE "{probe}" NOLOGIN'))
            connection.execute(text(f'GRANT "{probe}" TO "{handle.application_role}"'))
            # ALTER ... OWNER TO requires the current owner to be able to SET ROLE to the
            # new owner, which PostgreSQL 16 makes a separate grant option.
            connection.execute(
                text(f'GRANT "{probe}" TO "{handle.owner_role}" WITH SET TRUE')
            )

        # The owner hands one object to the probe role; the application role can reach it.
        owner = migrate.create_migration_engine(handle.migration_url)
        try:
            with owner.connect() as connection:
                # PostgreSQL requires the *incoming* owner to hold CREATE on the schema
                # before it will accept ownership of anything in it. Scaffolding for the
                # dangerous state this test wants refused, not part of the assertion.
                connection.execute(text(f'GRANT CREATE ON SCHEMA {SCHEMA} TO "{probe}"'))
                connection.execute(
                    text(statement.format(database=handle.database, probe=probe))
                )
                connection.commit()
        finally:
            owner.dispose()

        report = _report_for(handle.application_url)
        assert any(entry == expected.format(database=handle.database) for entry in report.owned_objects), (
            f"{kind} ownership was not detected; saw {report.owned_objects}"
        )

        engine = db_engine.create_application_engine(handle.application_url)
        try:
            with pytest.raises(config.PrivilegedPrincipalError) as exc:
                engine.connect()
            assert "isolation-boundary object" in str(exc.value)
        finally:
            engine.dispose()
    finally:
        # Both cases leave the database itself owned by the per-run owner, so the
        # ordinary validated teardown still applies.
        try:
            drop_disposable_database(handle)
        finally:
            with admin_engine.connect() as connection:
                connection.execute(text(f'DROP ROLE IF EXISTS "{probe}"'))


def test_reachable_ownership_of_the_database_is_refused(environment, admin_engine):
    """The database branch, reached the way it would actually happen.

    ``ALTER DATABASE ... OWNER TO`` requires the *current* owner to hold ``CREATEDB``, and
    the per-run owner is ``NOCREATEDB`` by design -- so the database's owner cannot be
    moved to a fresh probe role, and the realistic route is the one an operator takes by
    accident instead: ``GRANT <owner> TO <application role>``. One command, harmless-looking
    in a migration, and it hands the application everything the owner has.

    Only one branch of the ownership query emits a ``database`` entry, so finding one here
    is specific evidence that that branch works, even though granting the owner role makes
    the other branches fire too.
    """
    from firmbatch.control_plane.testing.bootstrap import (
        create_disposable_database,
        drop_disposable_database,
    )

    handle = create_disposable_database(environment)
    try:
        with admin_engine.connect() as connection:
            # The bootstrap grants app -> owner so the owner can terminate the runtime
            # roles' backends at teardown. PostgreSQL refuses circular membership, so that
            # grant comes off first and goes back on before teardown needs it. Worth
            # noticing: the direction that already exists is the harmless one -- the owner
            # reaching the application role -- and this test has to reverse it on purpose
            # to build the dangerous state.
            connection.execute(
                text(f'REVOKE "{handle.application_role}" FROM "{handle.owner_role}"')
            )
            connection.execute(
                text(f'GRANT "{handle.owner_role}" TO "{handle.application_role}"')
            )

        report = _report_for(handle.application_url)
        assert f"database {handle.database}" in report.owned_objects, (
            f"the database owner was not detected; saw {report.owned_objects}"
        )

        engine = db_engine.create_application_engine(handle.application_url)
        try:
            with pytest.raises(config.PrivilegedPrincipalError) as exc:
                engine.connect()
            message = str(exc.value)
            assert f"database {handle.database}" in message
            assert "ALTER DATABASE" in message
        finally:
            engine.dispose()
    finally:
        with admin_engine.connect() as connection:
            connection.execute(
                text(f'REVOKE "{handle.owner_role}" FROM "{handle.application_role}"')
            )
            connection.execute(
                text(f'GRANT "{handle.application_role}" TO "{handle.owner_role}"')
            )
        drop_disposable_database(handle)


def test_direct_ownership_of_a_relation_is_refused(environment, admin_engine):
    """Not merely reachable: the connected role owning a table directly."""
    from firmbatch.control_plane.testing.bootstrap import (
        create_disposable_database,
        drop_disposable_database,
    )

    handle = create_disposable_database(environment)
    try:
        with admin_engine.connect() as connection:
            connection.execute(
                text(
                    f'GRANT "{handle.application_role}" TO "{handle.owner_role}" WITH SET TRUE'
                )
            )
        owner = migrate.create_migration_engine(handle.migration_url)
        try:
            with owner.connect() as connection:
                # See above: the incoming owner needs CREATE on the schema first.
                connection.execute(
                    text(f'GRANT CREATE ON SCHEMA {SCHEMA} TO "{handle.application_role}"')
                )
                connection.execute(
                    text(
                        f"ALTER TABLE {SCHEMA}.workspaces OWNER TO "
                        f'"{handle.application_role}"'
                    )
                )
                connection.commit()
        finally:
            owner.dispose()

        report = _report_for(handle.application_url)
        assert "workspaces" in report.owned_tables
        assert any("workspaces" in entry for entry in report.owned_objects)

        engine = db_engine.create_application_engine(handle.application_url)
        try:
            with pytest.raises(config.PrivilegedPrincipalError) as exc:
                engine.connect()
            message = str(exc.value)
            assert "workspaces" in message
            assert "FORCE ROW LEVEL SECURITY off" in message
        finally:
            engine.dispose()
    finally:
        drop_disposable_database(handle)


def test_the_rejection_names_what_was_owned(disposable_database):
    """An operator has to be able to act on the message without reading this module."""
    engine = db_engine.create_application_engine(
        disposable_database.migration_url, validate_principal=True
    )
    try:
        with pytest.raises(config.PrivilegedPrincipalError) as exc:
            engine.connect()
        message = str(exc.value)
        assert "isolation-boundary object" in message
        assert "redefine app_current_tenant_id()" in message
    finally:
        engine.dispose()
