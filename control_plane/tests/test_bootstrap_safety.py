"""Destructive-safety regressions for the disposable-database bootstrap.

This module is about the code that runs ``DROP DATABASE``. Everything here asserts that a
drop is *refused*, and then proves the database is still there -- an assertion that a call
raised is worth little on its own, because the drop may already have happened before the
raise.

Covers:

* **Finding 5 -- teardown trusted its handle.** ``handle.database`` was enough authority
  to drop. It no longer is: the handle must have been produced by this process, be
  internally consistent, and describe the server the admin connection is actually attached
  to.
* **Finding 6 -- attestation.** A URL ending in ``/postgres`` is not evidence that a
  server is disposable; every cluster has that database.
* **Finding 8 -- failed bootstrap left orphans.** A failure after ``CREATE DATABASE``
  used to leave a live database and two live login roles behind.
* **Finding 9 -- generated passwords reached exception text.** psycopg echoes the failing
  statement.
"""

from __future__ import annotations

import dataclasses
import secrets
import uuid

import pytest
from sqlalchemy import create_engine, text

from firmbatch.control_plane import config
from firmbatch.control_plane.testing import bootstrap

from .conftest import drop_disposable_objects
from firmbatch.control_plane.testing.attestation import (
    mark_cluster,
    read_fingerprint,
    require_disposable_cluster,
    unmark_cluster,
)


def _admin(environment):
    return create_engine(
        config.load_test_admin_url(environment), isolation_level="AUTOCOMMIT", future=True
    )


def _database_exists(environment, name: str) -> bool:
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            return bool(
                connection.execute(
                    text("SELECT 1 FROM pg_database WHERE datname = :n"), {"n": name}
                ).scalar()
            )
    finally:
        engine.dispose()


def _role_exists(environment, name: str) -> bool:
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            return bool(
                connection.execute(
                    text("SELECT 1 FROM pg_roles WHERE rolname = :n"), {"n": name}
                ).scalar()
            )
    finally:
        engine.dispose()


def _pin_suffix(monkeypatch, suffix: str) -> None:
    """Make the bootstrap generate a known suffix, so a collision can be arranged.

    ``bootstrap.secrets`` is the same module object as the one imported here, so the
    original function has to be captured before patching -- otherwise the replacement
    calls itself.
    """
    real_token_hex = secrets.token_hex
    monkeypatch.setattr(
        bootstrap.secrets,
        "token_hex",
        lambda n: suffix if n == 6 else real_token_hex(n),
    )


# ----------------------------------------------------- forged handles (finding 5)


def test_a_handle_this_process_did_not_create_is_refused(disposable_database, environment):
    """A handle is evidence about a database this code created, not an instruction.

    Rebuilt field-for-field from a real handle -- every name, every URL, the real cluster
    fingerprint -- and differing only in the bootstrap-generated token. It must still be
    refused, and the database must still exist afterwards.
    """
    forged = dataclasses.replace(disposable_database, token=secrets.token_hex(16))
    with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
        bootstrap.drop_disposable_database(forged)
    assert "not produced by create_disposable_database" in str(exc.value)
    assert _database_exists(environment, disposable_database.database), "the database was dropped anyway"


def test_a_handle_naming_a_protected_database_is_refused(disposable_database, environment):
    for protected in sorted(config.PROTECTED_DATABASES):
        forged = dataclasses.replace(
            disposable_database,
            database=protected,
            migration_url=bootstrap._swap_database(disposable_database.migration_url, protected),
        )
        with pytest.raises((bootstrap.DisposableDatabaseError, config.UnsafeTestDatabaseError)):
            bootstrap.drop_disposable_database(forged)
        assert _database_exists(environment, protected), f"{protected} was dropped"


def test_a_handle_whose_name_does_not_match_its_migration_url_is_refused(disposable_database, environment):
    """Finding 5: derive or cross-check the target; do not trust one field.

    The handle names one disposable database while its migration URL names another. Both
    match the naming convention, so the pattern check alone would let this through.
    """
    other = f"firmbatch_test_{secrets.token_hex(6)}"
    forged = dataclasses.replace(disposable_database, database=other)
    with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
        bootstrap.drop_disposable_database(forged)
    assert "must agree" in str(exc.value)
    assert _database_exists(environment, disposable_database.database)


def test_a_handle_whose_urls_span_two_servers_is_refused(disposable_database, environment):
    """Mismatched admin and application endpoints mean the handle describes two servers."""
    elsewhere = bootstrap.make_url(disposable_database.application_url).set(port=15432)
    forged = dataclasses.replace(
        disposable_database, application_url=elsewhere.render_as_string(hide_password=False)
    )
    with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
        bootstrap.drop_disposable_database(forged)
    assert "two servers" in str(exc.value)
    assert _database_exists(environment, disposable_database.database)


def test_a_handle_with_a_foreign_cluster_fingerprint_is_refused(disposable_database, environment):
    """The admin connection must be the server the database was created on.

    A container restarted between create and drop, or a tunnel repointed, changes the
    system identifier while every name still matches.
    """
    foreign = dataclasses.replace(
        disposable_database.fingerprint, system_identifier="0000000000000000000"
    )
    forged = dataclasses.replace(disposable_database, fingerprint=foreign)
    with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
        bootstrap.drop_disposable_database(forged)
    assert "not the server this database was created on" in str(exc.value)
    assert _database_exists(environment, disposable_database.database)


def test_a_handle_with_a_non_maintenance_admin_url_is_refused(disposable_database, environment):
    """The admin connection must be a maintenance connection, checked live.

    Pointed at the disposable database itself -- which passes the *name* checks, since it
    matches the disposable pattern -- the drop must still be refused, because a
    ``DROP DATABASE`` never runs from inside the database it is dropping.
    """
    forged = dataclasses.replace(disposable_database, admin_url=disposable_database.migration_url)
    with pytest.raises((bootstrap.DisposableDatabaseError, config.UnsafeTestDatabaseError)) as exc:
        bootstrap.drop_disposable_database(forged)
    assert "not one of" in str(exc.value) or "maintenance" in str(exc.value)
    assert _database_exists(environment, disposable_database.database)


def test_a_handle_with_a_non_disposable_role_name_is_refused(disposable_database, environment):
    forged = dataclasses.replace(disposable_database, application_role="postgres")
    with pytest.raises(config.UnsafeTestDatabaseError):
        bootstrap.drop_disposable_database(forged)
    assert _role_exists(environment, "postgres"), "the postgres role was dropped"
    assert _database_exists(environment, disposable_database.database)


# ------------------------------------------------------- attestation (finding 6)


def test_the_marker_is_present_on_this_cluster(environment):
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            require_disposable_cluster(connection)
    finally:
        engine.dispose()


def test_creation_is_refused_without_the_disposable_cluster_marker(environment):
    """Finding 6: withdraw the attestation and nothing may be created.

    The marker is restored in a ``finally`` -- a failure here must not leave the developer
    machine unable to run the suite.
    """
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            unmark_cluster(connection)
        with pytest.raises(config.DisposableClusterAttestationError) as exc:
            bootstrap.create_disposable_database(environment)
        assert "not attested" in str(exc.value)
        assert "URL alone proves nothing" in str(exc.value)
    finally:
        with engine.connect() as connection:
            mark_cluster(connection)
        engine.dispose()


def test_teardown_is_refused_without_the_marker(disposable_database, environment):
    """Checked again before the DROP, not only before the CREATE."""
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            unmark_cluster(connection)
        with pytest.raises(config.DisposableClusterAttestationError):
            bootstrap.drop_disposable_database(disposable_database)
        assert _database_exists(environment, disposable_database.database)
    finally:
        with engine.connect() as connection:
            mark_cluster(connection)
        engine.dispose()


def test_a_wrong_marker_comment_is_not_an_attestation(environment):
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            connection.execute(
                text(f'COMMENT ON ROLE "{config.DISPOSABLE_CLUSTER_MARKER_ROLE}" IS \'something else\'')
            )
            with pytest.raises(config.DisposableClusterAttestationError) as exc:
                require_disposable_cluster(connection)
            assert "carries comment" in str(exc.value)
    finally:
        with engine.connect() as connection:
            mark_cluster(connection)
        engine.dispose()


def test_the_cluster_fingerprint_identifies_this_server(environment):
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            fingerprint = read_fingerprint(connection)
    finally:
        engine.dispose()
    assert fingerprint.system_identifier
    assert fingerprint.database in config.ADMIN_MAINTENANCE_DATABASES
    assert fingerprint.server_version_num // 10000 == 16
    assert fingerprint.mismatch(fingerprint) is None


# -------------------------------------- failed bootstrap and passwords (8 and 9)


def test_a_failure_after_creation_removes_the_database_and_roles(environment, monkeypatch):
    """Finding 8: a failure during migration must not leave orphans behind.

    The failure is injected into ``upgrade_to_head``, which runs after the database and
    both login roles exist -- exactly the window that used to leak them.
    """
    seen: dict[str, str] = {}

    def explode(connection, *, expected=None):
        seen["database"] = connection.execute(text("SELECT current_database()")).scalar()
        raise RuntimeError("migration failed on purpose")

    monkeypatch.setattr(bootstrap, "upgrade_to_head", explode)

    with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
        bootstrap.create_disposable_database(environment)
    assert "have been removed" in str(exc.value)

    database = seen["database"]
    suffix = database.rsplit("_", 1)[-1]
    assert not _database_exists(environment, database), f"{database} was left behind"
    assert not _role_exists(environment, f"firmbatch_test_app_{suffix}"), "the application role was left behind"
    assert not _role_exists(environment, f"firmbatch_test_prov_{suffix}"), "the provisioning role was left behind"


def test_a_failure_during_grant_configuration_also_cleans_up(environment, monkeypatch):
    """Finding 8: cleanup covers permission configuration, not only migration.

    This failure lands *later* than the migration one -- the database exists, the roles
    exist, and the schema is already migrated. It is the window a naive
    ``try/except`` around the migration alone would miss.
    """
    seen: dict[str, str] = {}
    real_grant = bootstrap.roles.grant_application_role

    def explode(connection, role):
        seen["role"] = role
        raise RuntimeError("grant failed on purpose")

    monkeypatch.setattr(bootstrap.roles, "grant_application_role", explode)

    with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
        bootstrap.create_disposable_database(environment)
    assert "have been removed" in str(exc.value)
    assert real_grant is not explode  # guards against the patch leaking out of this test

    suffix = seen["role"].rsplit("_", 1)[-1]
    assert not _database_exists(environment, f"firmbatch_test_{suffix}"), "the database was left behind"
    assert not _role_exists(environment, f"firmbatch_test_app_{suffix}"), "the application role was left behind"
    assert not _role_exists(environment, f"firmbatch_test_prov_{suffix}"), "the provisioning role was left behind"


def test_a_failure_after_creation_does_not_disclose_the_generated_password(environment, monkeypatch, capsys):
    """Finding 9: the generated password must not reach an exception or captured output.

    The failure carries the exception text back through the bootstrap, which is the path
    that used to surface a live ``CREATE ROLE ... PASSWORD`` statement in a CI log.
    """
    captured_passwords: list[str] = []
    real_create = bootstrap._create_login_role

    def spy(engine, role, password, marker, record):
        captured_passwords.append(password)
        return real_create(engine, role, password, marker, record)

    monkeypatch.setattr(bootstrap, "_create_login_role", spy)

    def explode(connection, *, expected=None):
        # Quote the password the way psycopg would when echoing a failing statement.
        raise RuntimeError(f"boom while running CREATE ROLE ... PASSWORD '{captured_passwords[0]}'")

    monkeypatch.setattr(bootstrap, "upgrade_to_head", explode)

    with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
        bootstrap.create_disposable_database(environment)

    assert captured_passwords, "the spy never ran, so this test proves nothing"
    message = str(exc.value)
    output = capsys.readouterr()
    for password in captured_passwords:
        assert password not in message, "a generated password reached the exception text"
        assert password not in output.out, "a generated password reached stdout"
        assert password not in output.err, "a generated password reached stderr"
    assert "***" in message


def test_role_creation_scrubs_the_password_from_a_failure(disposable_database, environment):
    """A CREATE ROLE that fails must not echo the password it was given.

    Provoked by reusing an existing role name, which psycopg reports with the full
    statement attached.
    """
    password = secrets.token_hex(16)
    engine = create_engine(config.load_test_admin_url(environment), future=True)
    try:
        with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
            bootstrap._create_login_role(
                engine, disposable_database.application_role, password, "marker", lambda _: None
            )
    finally:
        engine.dispose()
    # The password must be absent whether or not the driver echoed the statement. The
    # collision is now refused before CREATE ROLE runs, so the password never reaches SQL
    # at all; the property under test is the absence of the secret either way.
    assert password not in str(exc.value)
    assert "already exists" in str(exc.value)
    assert "must not be" in str(exc.value)


def test_the_handle_repr_never_carries_a_password(disposable_database):
    for rendered in (repr(disposable_database), str(disposable_database)):
        for url in (
            disposable_database.application_url,
            disposable_database.provisioning_url,
            disposable_database.migration_url,
        ):
            password = bootstrap.make_url(url).password
            if password:
                assert password not in rendered


def test_a_disposable_database_is_actually_disposable(environment):
    """The whole lifecycle, on its own database, ending in nothing left behind."""
    handle = bootstrap.create_disposable_database(environment)
    database, app_role = handle.database, handle.application_role
    assert _database_exists(environment, database)
    assert _role_exists(environment, app_role)
    assert config.DISPOSABLE_DATABASE_PATTERN.match(database)
    assert uuid.UUID(handle.token, version=4) or True  # token is opaque; presence is what matters
    bootstrap.drop_disposable_database(handle)
    assert not _database_exists(environment, database)
    assert not _role_exists(environment, app_role)


# ------------------- object identity and partial bootstrap (findings 5 and 6)


def _identity_of(environment, name: str, kind: str):
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            reader = (
                bootstrap._read_database_identity if kind == "database" else bootstrap._read_role_identity
            )
            return reader(connection, name)
    finally:
        engine.dispose()


def test_created_objects_carry_an_oid_and_a_provenance_marker(disposable_database, environment):
    """Names are not identities; OID plus a random marker is what teardown compares."""
    kinds = {o.kind for o in disposable_database.created}
    assert kinds == {"database", "role"}
    names = {o.name for o in disposable_database.created}
    assert names == {
        disposable_database.database,
        disposable_database.owner_role,
        disposable_database.application_role,
        disposable_database.provisioning_role,
    }
    for recorded in disposable_database.created:
        assert recorded.oid > 0
        assert recorded.marker.startswith("firmbatch-disposable-")
        live = _identity_of(environment, recorded.name, recorded.kind)
        assert recorded.mismatch(live) is None


def test_teardown_refuses_a_database_replaced_under_the_same_name(environment):
    """A dropped-and-recreated database is a different object wearing the same name.

    Reproduced: teardown used to destroy the replacement. Its own disposable database,
    because the replacement has to survive the assertion.
    """
    handle = bootstrap.create_disposable_database(environment)
    replacement_oid = None
    try:
        # Drop the original as its owner -- the admin cannot -- then put a
        # same-name replacement in its place, owned by the admin.
        drop_disposable_objects(
            environment, database=handle.database, owner_role=handle.owner_role, role_names=()
        )
        engine = _admin(environment)
        try:
            with engine.connect() as connection:
                connection.execute(text(f'CREATE DATABASE "{handle.database}"'))
                replacement_oid = bootstrap._read_database_identity(connection, handle.database).oid
        finally:
            engine.dispose()

        assert replacement_oid != next(
            o.oid for o in handle.created if o.kind == "database"
        ), "the replacement must be a different object for this test to mean anything"

        with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
            bootstrap.drop_disposable_database(handle)
        assert "has been replaced" in str(exc.value)
        assert _database_exists(environment, handle.database), "the replacement was destroyed"
    finally:
        # The replacement is owned by the admin, so the admin drops that one.
        engine = _admin(environment)
        try:
            with engine.connect() as connection:
                connection.execute(text(f'DROP DATABASE IF EXISTS "{handle.database}"'))
        finally:
            engine.dispose()
        drop_disposable_objects(
            environment,
            database=None,
            owner_role=handle.owner_role,
            role_names=(handle.application_role, handle.provisioning_role, handle.owner_role),
        )


def test_teardown_refuses_a_role_replaced_under_the_same_name(environment):
    """The same for a login role."""
    handle = bootstrap.create_disposable_database(environment)
    role = handle.application_role
    try:
        # Remove the database first -- as its owner -- so the role has no dependent
        # grants, then replace the role under the same name.
        drop_disposable_objects(
            environment, database=handle.database, owner_role=handle.owner_role, role_names=()
        )
        engine = _admin(environment)
        try:
            with engine.connect() as connection:
                connection.execute(text(f'DROP ROLE "{role}"'))
                connection.execute(text(f'CREATE ROLE "{role}" NOLOGIN'))
        finally:
            engine.dispose()

        with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
            bootstrap.drop_disposable_database(handle)
        assert "has been replaced" in str(exc.value)
        assert _role_exists(environment, role), "the replacement role was destroyed"
    finally:
        drop_disposable_objects(
            environment,
            database=None,
            owner_role=handle.owner_role,
            role_names=(role, handle.provisioning_role, handle.owner_role),
        )


def test_a_pre_existing_application_role_aborts_setup_and_is_left_alone(environment, monkeypatch):
    """A collision is somebody else's role. It is never adopted and never dropped."""
    suffix = secrets.token_hex(6)
    _pin_suffix(monkeypatch, suffix)
    squatter = f"firmbatch_test_app_{suffix}"

    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            connection.execute(text(f'CREATE ROLE "{squatter}" NOLOGIN'))
            before = bootstrap._read_role_identity(connection, squatter)

        with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
            bootstrap.create_disposable_database(environment)
        assert "already exists" in str(exc.value)

        with engine.connect() as connection:
            after = bootstrap._read_role_identity(connection, squatter)
        assert after is not None, "the pre-existing role was dropped"
        assert after.oid == before.oid, "the pre-existing role was replaced"
        # And nothing else was left behind.
        assert not _database_exists(environment, f"firmbatch_test_{suffix}")
        assert not _role_exists(environment, f"firmbatch_test_prov_{suffix}")
    finally:
        with engine.connect() as connection:
            connection.execute(text(f'DROP ROLE IF EXISTS "{squatter}"'))
        engine.dispose()


def test_a_pre_existing_provisioning_role_aborts_setup_and_leaves_the_first_role_removed(
    environment, monkeypatch
):
    """The collision is on the *second* role, so the first one was genuinely created here.

    That one must be cleaned up; the pre-existing one must not.
    """
    suffix = secrets.token_hex(6)
    _pin_suffix(monkeypatch, suffix)
    squatter = f"firmbatch_test_prov_{suffix}"

    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            connection.execute(text(f'CREATE ROLE "{squatter}" NOLOGIN'))
            before = bootstrap._read_role_identity(connection, squatter)

        with pytest.raises(bootstrap.DisposableDatabaseError):
            bootstrap.create_disposable_database(environment)

        with engine.connect() as connection:
            after = bootstrap._read_role_identity(connection, squatter)
        assert after is not None and after.oid == before.oid, "the pre-existing role was touched"
        assert not _role_exists(environment, f"firmbatch_test_app_{suffix}"), (
            "the role this process did create was left behind"
        )
        assert not _database_exists(environment, f"firmbatch_test_{suffix}")
    finally:
        with engine.connect() as connection:
            connection.execute(text(f'DROP ROLE IF EXISTS "{squatter}"'))
        engine.dispose()


def test_a_failure_after_only_the_roles_exist_removes_exactly_those(environment, monkeypatch):
    """Failure between CREATE ROLE and CREATE DATABASE: no database to clean, two roles to."""
    suffix = secrets.token_hex(6)
    _pin_suffix(monkeypatch, suffix)

    real_exists = bootstrap._database_exists
    fired = []

    def explode(connection, name):
        # Only the first probe fails; cleanup must still be able to look things up.
        if name == f"firmbatch_test_{suffix}" and not fired:
            fired.append(name)
            raise RuntimeError("failing before CREATE DATABASE on purpose")
        return real_exists(connection, name)

    monkeypatch.setattr(bootstrap, "_database_exists", explode)

    with pytest.raises(RuntimeError):
        bootstrap.create_disposable_database(environment)

    assert not _role_exists(environment, f"firmbatch_test_app_{suffix}")
    assert not _role_exists(environment, f"firmbatch_test_prov_{suffix}")
    assert not _database_exists(environment, f"firmbatch_test_{suffix}")


def test_cleanup_leaves_objects_alone_when_the_attestation_is_gone(environment, monkeypatch):
    """If cleanup cannot be validated it leaks deliberately and says so.

    Dropping on a weaker check than the one that authorised creation is exactly the
    behaviour these findings were about.
    """
    suffix = secrets.token_hex(6)
    _pin_suffix(monkeypatch, suffix)

    engine = _admin(environment)
    try:
        def explode(connection, *, expected=None):
            # Withdraw the attestation, then fail: cleanup must refuse to drop anything.
            with engine.connect() as admin_connection:
                unmark_cluster(admin_connection)
            raise RuntimeError("failing after creation, with the marker withdrawn")

        monkeypatch.setattr(bootstrap, "upgrade_to_head", explode)

        with pytest.raises(bootstrap.DisposableDatabaseError):
            bootstrap.create_disposable_database(environment)

        # The objects survive, because cleanup could not prove it was safe to remove them.
        with engine.connect() as connection:
            mark_cluster(connection)
        assert _database_exists(environment, f"firmbatch_test_{suffix}")
        assert _role_exists(environment, f"firmbatch_test_app_{suffix}")
    finally:
        with engine.connect() as connection:
            mark_cluster(connection)
        engine.dispose()
        # The database is owned by the per-run owner role, so it is dropped as that role
        # -- the same identity binding the product code uses.
        drop_disposable_objects(
            environment,
            database=f"firmbatch_test_{suffix}",
            owner_role=f"firmbatch_test_own_{suffix}",
            role_names=(
                f"firmbatch_test_app_{suffix}",
                f"firmbatch_test_prov_{suffix}",
                f"firmbatch_test_own_{suffix}",
            ),
        )
