"""Findings 5-8: the disposable-database lifecycle, one state transition at a time.

``CREATE DATABASE`` cannot run inside a transaction, so this sequence cannot be made
atomic and is written as an explicit state machine instead. The rule at every transition
is the same: either the state supports owner-bound cleanup, or it deliberately leaks and
reports -- and it never deletes something it cannot prove it created.

    S0  nothing exists
    S1  roles exist and are recorded          (finding 7: one transaction each)
    S2  the owner's cleanup authority is proven (finding 8: before anything needs it)
    S3  the database exists and its OID is recorded
    S4  the provenance marker is written
    S5  grants and revokes are applied
    S6  migrated, granted, handle returned

Two properties are load-bearing and both are asserted below rather than described:

* **The temporary owner membership is given back** (finding 5). ``CREATE DATABASE ...
  OWNER`` needs the creator to be able to ``SET ROLE`` to the new owner, so the bootstrap
  takes that grant for one statement and revokes it in a ``finally``. Afterwards no
  ``pg_auth_members`` row carries ``SET`` or ``INHERIT``. This is a catalogue property, and
  it is deliberately *not* a claim that the bootstrap administrator cannot reach the owner:
  that administrator is trusted, CI runs it as a superuser, and a superuser reaches every
  role by fiat. See ADR 0004 section 8f and ``test_admin_escalation.py``.
* **Nothing is altered before it is identified** (finding 6). Revoking ``CONNECT`` and
  terminating backends are destructive to a running system, and they used to happen by
  name, on the admin connection, before any OID or provenance check had run.
"""

from __future__ import annotations

import secrets
import uuid

import pytest
from sqlalchemy import create_engine, text

from firmbatch.control_plane import config
from firmbatch.control_plane.testing import bootstrap

from .conftest import drop_disposable_objects


def _admin(environment):
    return create_engine(
        config.load_test_admin_url(environment), isolation_level="AUTOCOMMIT", future=True
    )


def _membership_options(environment, role: str) -> list[tuple]:
    """``(grantor, member, set_option, inherit_option)`` rows naming ``role``.

    A brand new connection, because membership is resolved per session: asking on the
    session that did the revoke could be answered from state a fresh login would not have.
    Stored grants only -- effective reach folds in the administrator's cluster authority,
    which no revoke changes and which this design accepts.
    """
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            return [
                tuple(row)
                for row in connection.execute(
                    text(
                        "SELECT m.grantor::regrole::text, m.member::regrole::text, "
                        "       m.set_option, m.inherit_option "
                        "FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid "
                        "WHERE r.rolname = :r"
                    ),
                    {"r": role},
                )
            ]
    finally:
        engine.dispose()


def _is_superuser(environment) -> bool:
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            return bool(
                connection.execute(
                    text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
                ).scalar()
            )
    finally:
        engine.dispose()


def _exists(environment, *, database=None, role=None) -> bool:
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            if database is not None:
                return bool(
                    connection.execute(
                        text("SELECT 1 FROM pg_database WHERE datname = :n"), {"n": database}
                    ).scalar()
                )
            return bool(
                connection.execute(
                    text("SELECT 1 FROM pg_roles WHERE rolname = :n"), {"n": role}
                ).scalar()
            )
    finally:
        engine.dispose()


def _pin_suffix(monkeypatch, suffix: str) -> None:
    """Make the next bootstrap use a known suffix, so a failure can be cleaned up by name."""
    original = bootstrap.secrets.token_hex

    def fixed(size: int = 32) -> str:
        return suffix if size == 6 else original(size)

    monkeypatch.setattr(bootstrap.secrets, "token_hex", fixed)


# ------------------------------------------- finding 5: the temporary grant is given back


def test_the_temporary_owner_membership_is_given_back_after_bootstrap(
    disposable_database, environment
):
    """A *new* admin session, and the catalogue rather than ``pg_has_role``.

    The grant the bootstrap takes for ``CREATE DATABASE ... OWNER`` is explicit and
    revocable, so its absence afterwards is a real, checkable property on any cluster. What
    the administrator can reach by virtue of *being* the administrator is a different
    question, accepted rather than asserted -- see the module docstring.
    """
    for grantor, member, set_option, inherit_option in _membership_options(
        environment, disposable_database.owner_role
    ):
        assert not set_option, f"{member} still holds SET on the owner, granted by {grantor}"
        assert not inherit_option, f"{member} still inherits the owner, granted by {grantor}"


def test_the_admin_cannot_act_on_the_database_it_created(disposable_database, environment):
    """The separation is not bookkeeping: PostgreSQL refuses a non-superuser admin outright.

    All three are owner operations, and a non-superuser admin is no longer the owner. This
    is the assertion that makes owner-bound deletion authority mean something *for that
    administrator*. A superuser administrator owns everything by fiat -- accepted by ADR
    0004 section 8f -- so this skips rather than reporting a green it did not earn; the
    per-run-role containment assertions in ``test_admin_escalation.py`` run either way.
    """
    if _is_superuser(environment):
        pytest.skip(
            "the bootstrap administrator is a superuser (CI's ephemeral service container); "
            "owner-only refusal has no meaning for it"
        )

    engine = _admin(environment)
    try:
        for statement in (
            f'COMMENT ON DATABASE "{disposable_database.database}" IS \'hijacked\'',
            f'REVOKE CONNECT ON DATABASE "{disposable_database.database}" FROM PUBLIC',
            f'ALTER DATABASE "{disposable_database.database}" CONNECTION LIMIT 0',
            f'DROP DATABASE "{disposable_database.database}"',
        ):
            with engine.connect() as connection:
                with pytest.raises(Exception) as exc:
                    connection.execute(text(statement))
                assert "must be owner" in str(exc.value) or "permission denied" in str(exc.value)
    finally:
        engine.dispose()


def test_a_partially_failed_bootstrap_leaves_no_object_or_grant(environment, monkeypatch):
    """The revoke is in a ``finally``, so a failure after the grant still gives it up.

    The failure is injected into the owner's own configuration step, which is after
    ``CREATE DATABASE`` -- the point at which the temporary SET membership has been taken
    and must have been handed back.
    """
    suffix = secrets.token_hex(6)
    _pin_suffix(monkeypatch, suffix)
    owner_role = f"firmbatch_test_own_{suffix}"

    real_comment = bootstrap._comment_on

    def explode(connection, kind, name, marker):
        if kind == "database":
            raise RuntimeError("failing right after CREATE DATABASE")
        return real_comment(connection, kind, name, marker)

    monkeypatch.setattr(bootstrap, "_comment_on", explode)

    with pytest.raises(bootstrap.DisposableDatabaseError):
        bootstrap.create_disposable_database(environment)

    # The role is gone with the rest of the cleanup, so a membership assertion would be
    # vacuous -- assert the stronger thing: no object and no grant survived at all.
    assert not _exists(environment, database=f"firmbatch_test_{suffix}")
    assert not _exists(environment, role=owner_role)
    assert not _exists(environment, role=f"firmbatch_test_app_{suffix}")


# ------------------------------------------------------- finding 7: transactional role creation


@pytest.mark.parametrize("stage", ["comment", "identity"])
def test_a_failure_during_role_creation_leaves_no_role_behind(environment, stage, monkeypatch):
    """``CREATE ROLE``, ``COMMENT`` and the identity read are one transaction.

    Run as three autocommit statements, a failure at the second or third left a real role
    behind that no cleanup list had ever heard of -- and this module refuses to drop
    anything it cannot prove it created, so that role was permanent. PostgreSQL's own
    rollback removes it instead.
    """
    suffix = secrets.token_hex(6)
    _pin_suffix(monkeypatch, suffix)

    if stage == "comment":
        def explode(connection, kind, name, marker):
            raise RuntimeError("failing after CREATE ROLE, before COMMENT lands")

        monkeypatch.setattr(bootstrap, "_comment_on", explode)
    else:
        def explode(connection, name, marker=None):
            return None  # the identity read finds nothing

        monkeypatch.setattr(bootstrap, "_read_role_identity", explode)

    with pytest.raises(bootstrap.DisposableDatabaseError):
        bootstrap.create_disposable_database(environment)

    for role in (
        f"firmbatch_test_own_{suffix}",
        f"firmbatch_test_app_{suffix}",
        f"firmbatch_test_prov_{suffix}",
    ):
        assert not _exists(environment, role=role), f"{role} survived a rolled-back creation"
    assert not _exists(environment, database=f"firmbatch_test_{suffix}")


def test_a_pre_existing_role_is_never_adopted_or_dropped(environment, monkeypatch):
    """A name collision is somebody else's role, inside the transaction as much as outside."""
    suffix = secrets.token_hex(6)
    _pin_suffix(monkeypatch, suffix)
    squatter = f"firmbatch_test_prov_{suffix}"

    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            connection.execute(text(f'CREATE ROLE "{squatter}" NOLOGIN'))
            before = connection.execute(
                text("SELECT oid FROM pg_roles WHERE rolname = :n"), {"n": squatter}
            ).scalar()

        with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
            bootstrap.create_disposable_database(environment)
        assert "already exists" in str(exc.value)

        with engine.connect() as connection:
            after = connection.execute(
                text("SELECT oid FROM pg_roles WHERE rolname = :n"), {"n": squatter}
            ).scalar()
        assert after == before, "a pre-existing role was dropped"
    finally:
        with engine.connect() as connection:
            connection.execute(text(f'DROP ROLE IF EXISTS "{squatter}"'))
            for role in (f"firmbatch_test_own_{suffix}", f"firmbatch_test_app_{suffix}"):
                connection.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
        engine.dispose()


def test_role_creation_records_before_it_commits(environment, monkeypatch):
    """Recording first is the fail-safe direction, and it is deliberate.

    Recording *after* the commit leaves a window in which a real role exists and is
    unrecorded, which is a permanent leak. Recording before leaves the opposite window: an
    identity for a role that never existed, which cleanup treats as a no-op because
    ``_drop_role_atomically`` returns cleanly when it finds nothing. One direction leaks a
    real object; the other does nothing at all.
    """
    recorded: list = []
    engine = create_engine(config.load_test_admin_url(environment), future=True)
    role = f"firmbatch_test_app_{secrets.token_hex(6)}"
    try:
        real_read = bootstrap._read_role_identity

        def fail_after_reading(connection, name, marker=None):
            real_read(connection, name, marker)  # the read itself succeeds
            raise RuntimeError("failing between the identity read and the commit")

        monkeypatch.setattr(bootstrap, "_read_role_identity", fail_after_reading)
        with pytest.raises(bootstrap.DisposableDatabaseError):
            bootstrap._create_login_role(engine, role, secrets.token_hex(16), "m", recorded.append)
    finally:
        engine.dispose()

    assert not _exists(environment, role=role), "the rolled-back role survived"
    # Whatever was recorded, cleaning it up must be a no-op rather than an error.
    problems = bootstrap._cleanup(
        config.load_test_admin_url(environment), None, tuple(recorded), owner_url=None
    )
    assert problems == [], problems


# ------------------------------------------------------- finding 8: transitions around CREATE


def test_the_owner_authority_is_proven_before_the_database_exists(environment, monkeypatch):
    """S2 comes before S3, and the ordering is the point.

    Discovering after ``CREATE DATABASE`` that the owner cannot authenticate would strand
    a database nothing in this process has the authority to remove. Verified by failing
    the owner-authority check and asserting no database was ever created.
    """
    suffix = secrets.token_hex(6)
    _pin_suffix(monkeypatch, suffix)
    seen: dict[str, bool] = {}

    def refuse(owner_url, owner_role, fingerprint, endpoint):
        seen["database_exists_yet"] = _exists(environment, database=f"firmbatch_test_{suffix}")
        raise bootstrap.DisposableDatabaseError("the owner cannot log in")

    monkeypatch.setattr(bootstrap, "_verify_owner_authority", refuse)

    with pytest.raises(bootstrap.DisposableDatabaseError):
        bootstrap.create_disposable_database(environment)

    assert seen["database_exists_yet"] is False, "the database was created before the check"
    assert not _exists(environment, database=f"firmbatch_test_{suffix}")
    for role in (f"firmbatch_test_own_{suffix}", f"firmbatch_test_app_{suffix}"):
        assert not _exists(environment, role=role)


def test_a_failure_before_the_marker_still_permits_owner_bound_cleanup(environment, monkeypatch):
    """S3: the OID is recorded immediately, so cleanup works with no marker written.

    This is the transition that used to leak. ``CREATE DATABASE`` succeeded, ``COMMENT``
    failed, and because the identity was only recorded *after* the comment the database was
    never on any cleanup list.
    """
    suffix = secrets.token_hex(6)
    _pin_suffix(monkeypatch, suffix)
    real_comment = bootstrap._comment_on

    def explode(connection, kind, name, marker):
        if kind == "database":
            raise RuntimeError("COMMENT ON DATABASE failed")
        return real_comment(connection, kind, name, marker)

    monkeypatch.setattr(bootstrap, "_comment_on", explode)

    with pytest.raises(bootstrap.DisposableDatabaseError):
        bootstrap.create_disposable_database(environment)

    assert not _exists(environment, database=f"firmbatch_test_{suffix}"), (
        "a database created before the marker was written was left behind"
    )
    for role in (
        f"firmbatch_test_own_{suffix}",
        f"firmbatch_test_app_{suffix}",
        f"firmbatch_test_prov_{suffix}",
    ):
        assert not _exists(environment, role=role)


def test_a_failure_during_the_grants_cleans_up_completely(environment, monkeypatch):
    """S5: the grants are owner operations, and a failure there still unwinds."""
    suffix = secrets.token_hex(6)
    _pin_suffix(monkeypatch, suffix)

    real = bootstrap.roles.grant_application_role

    def explode(connection, role):
        raise RuntimeError("GRANT failed")

    monkeypatch.setattr(bootstrap.roles, "grant_application_role", explode)

    with pytest.raises(bootstrap.DisposableDatabaseError):
        bootstrap.create_disposable_database(environment)
    assert real is not explode

    assert not _exists(environment, database=f"firmbatch_test_{suffix}")
    for role in (f"firmbatch_test_own_{suffix}", f"firmbatch_test_app_{suffix}"):
        assert not _exists(environment, role=role)


# ------------------------------------------------------- finding 6: identify before altering


def test_a_replacement_is_not_revoked_terminated_or_dropped(environment, admin_engine):
    """The race, run in the order that used to be destructive.

    The database is replaced under the same name, owned by somebody else, and a live
    session is opened on the replacement. Cleanup must make **no change at all**: not the
    grants, not the connection limit, not the session. Before the fix, ``REVOKE CONNECT``
    and ``pg_terminate_backend`` ran by name on the admin connection before any identity
    check, so all three would have hit the replacement.
    """
    handle = bootstrap.create_disposable_database(environment)
    other_owner = f"firmbatch_test_other_{uuid.uuid4().hex[:8]}"
    other_password = secrets.token_hex(16)
    victim = None
    try:
        with admin_engine.connect() as connection:
            connection.execute(
                text(
                    f'CREATE ROLE "{other_owner}" LOGIN PASSWORD \'{other_password}\' '
                    "NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION"
                )
            )
            connection.execute(text(f'GRANT "{other_owner}" TO CURRENT_USER WITH SET TRUE'))

        # Remove the original as its owner, then put a same-name replacement in its place.
        drop_disposable_objects(
            environment, database=handle.database, owner_role=handle.owner_role, role_names=()
        )
        with admin_engine.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{handle.database}" OWNER "{other_owner}"'))
            connection.execute(
                text(f'ALTER DATABASE "{handle.database}" CONNECTION LIMIT 42')
            )

        # A live session on the replacement, which must survive untouched.
        endpoint = handle.endpoint
        victim = create_engine(
            f"postgresql+psycopg://{other_owner}:{other_password}@"
            f"{endpoint[0]}:{endpoint[1]}/{handle.database}",
            poolclass=None,
            future=True,
        )
        victim_connection = victim.connect()
        victim_pid = victim_connection.execute(text("SELECT pg_backend_pid()")).scalar()

        with admin_engine.connect() as connection:
            acl_before, limit_before = connection.execute(
                text(
                    "SELECT coalesce(datacl::text, ''), datconnlimit "
                    "FROM pg_database WHERE datname = :d"
                ),
                {"d": handle.database},
            ).one()

        with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
            bootstrap.drop_disposable_database(handle)
        assert "Nothing was altered" in str(exc.value) or "replaced" in str(exc.value)

        with admin_engine.connect() as connection:
            acl_after, limit_after, owner_after = connection.execute(
                text(
                    "SELECT coalesce(datacl::text, ''), datconnlimit, pg_get_userbyid(datdba) "
                    "FROM pg_database WHERE datname = :d"
                ),
                {"d": handle.database},
            ).one()
            alive = connection.execute(
                text("SELECT count(*) FROM pg_stat_activity WHERE pid = :p"), {"p": victim_pid}
            ).scalar()

        assert owner_after == other_owner, "the replacement was destroyed"
        assert acl_after == acl_before, "the replacement's grants were altered"
        assert limit_after == limit_before == 42, "the replacement's connection limit was altered"
        assert alive == 1, "a session on the replacement was terminated"
        assert victim_connection.execute(text("SELECT 1")).scalar() == 1
    finally:
        if victim is not None:
            # dispose() does not close a connection that is still checked out, and the
            # DROP below would then fail on "being accessed by other users".
            victim_connection.close()
            victim.dispose()
        with admin_engine.connect() as connection:
            connection.execute(text(f'SET ROLE "{other_owner}"'))
            connection.execute(text(f'DROP DATABASE IF EXISTS "{handle.database}"'))
            connection.execute(text("RESET ROLE"))
            for role in (
                handle.application_role,
                handle.provisioning_role,
                handle.owner_role,
                other_owner,
            ):
                connection.execute(text(f'DROP ROLE IF EXISTS "{role}"'))


def test_cleanup_reports_a_safe_leak_rather_than_forcing(environment, monkeypatch):
    """If the backends cannot be cleared, the database is left in place and reported.

    ``DROP DATABASE ... WITH (FORCE)`` would need the privileges of the roles whose
    backends it terminates, which means broadening the owner rather than narrowing it.
    An operator must not widen teardown authority to make cleanup pass, so the failure is
    reported and the object is left alone.
    """
    handle = bootstrap.create_disposable_database(environment)
    holder = create_engine(handle.application_url, poolclass=None, future=True)
    connection = holder.connect()
    connection.execute(text("SELECT 1"))
    try:
        # Terminating is what would normally clear this; make it impossible.
        real_execute_guard = {"blocked": True}
        original = bootstrap.text

        def blocking_text(statement):
            if real_execute_guard["blocked"] and "pg_terminate_backend" in statement:
                raise RuntimeError("not allowed to terminate backends here")
            return original(statement)

        monkeypatch.setattr(bootstrap, "text", blocking_text)

        with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
            bootstrap.drop_disposable_database(handle)
        message = str(exc.value)
        assert "LEFT IN PLACE" in message
        assert "FORCE" not in message.upper() or "do not broaden" in message
        real_execute_guard["blocked"] = False
    finally:
        monkeypatch.undo()
        connection.close()
        holder.dispose()
        drop_disposable_objects(
            environment,
            database=handle.database,
            owner_role=handle.owner_role,
            role_names=(handle.application_role, handle.provisioning_role, handle.owner_role),
        )


def test_no_drop_path_uses_force(environment):
    """``FORCE`` appears nowhere in the destructive path. Asserted on the source."""
    import inspect

    source = inspect.getsource(bootstrap)
    assert "WITH (FORCE)" not in source
    assert "FORCE)" not in source


# --------------------------------------------------------------------------------------
# Finding 9: every per-run object disappears, and the persistent marker does not.
#
# "Zero roles" was the wrong assertion and it was reported that way twice. The cluster is
# *supposed* to keep exactly one role forever -- the ``firmbatch_disposable_test_cluster``
# attestation marker, which is what makes creating and dropping anything permissible in the
# first place. An assertion that counted it as a leak would have to be relaxed, and a count
# that ignored the difference could pass while a per-run role survived.
#
# So the two are separated: three per-run roles and one per-run database must be gone, and
# the marker must still be there.
# --------------------------------------------------------------------------------------

PER_RUN_ROLE_KINDS = ("own", "app", "prov")


def _per_run_objects(environment) -> tuple[list[str], list[str]]:
    """``(disposable databases, per-run roles)`` -- the marker deliberately excluded."""
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            databases = [
                row[0]
                for row in connection.execute(
                    text(
                        "SELECT datname FROM pg_database "
                        "WHERE datname ~ '^firmbatch_test_[0-9a-f]{12}$' ORDER BY 1"
                    )
                )
            ]
            roles = [
                row[0]
                for row in connection.execute(
                    text(
                        "SELECT rolname FROM pg_roles "
                        "WHERE rolname ~ '^firmbatch_test_(own|app|prov)_[0-9a-f]{12}$' ORDER BY 1"
                    )
                )
            ]
    finally:
        engine.dispose()
    return databases, roles


def _marker_present(environment) -> bool:
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            return bool(
                connection.execute(
                    text("SELECT 1 FROM pg_roles WHERE rolname = :r"),
                    {"r": config.DISPOSABLE_CLUSTER_MARKER_ROLE},
                ).scalar()
            )
    finally:
        engine.dispose()


def test_a_full_lifecycle_leaks_no_per_run_object_and_keeps_the_marker(environment):
    """Create, migrate, drop -- and account for every object by kind afterwards.

    The three per-run roles are named individually rather than counted, so a teardown that
    removed two of the three would fail here rather than pass a total that happened to
    match.
    """
    assert _marker_present(environment), "the cluster is not attested; nothing else is meaningful"

    handle = bootstrap.create_disposable_database(environment)
    created_roles = (handle.owner_role, handle.application_role, handle.provisioning_role)
    assert len({role.rsplit("_", 2)[1] for role in created_roles}) == 3, (
        "the three per-run roles must be distinguishable by kind"
    )

    databases, roles = _per_run_objects(environment)
    assert handle.database in databases
    for role in created_roles:
        assert role in roles, f"{role} was not created"

    bootstrap.drop_disposable_database(handle)

    databases, roles = _per_run_objects(environment)
    assert handle.database not in databases, "the disposable database survived teardown"
    for role in created_roles:
        assert role not in roles, f"the per-run role {role} survived teardown"

    assert _marker_present(environment), (
        "teardown removed the persistent attestation marker, which it must never do"
    )


def test_two_consecutive_lifecycles_leave_the_cluster_as_they_found_it(environment):
    """Run it twice: a leak that is one object per run only shows up as growth.

    Counted against the *starting* state rather than against zero, because the session
    fixture legitimately holds one disposable database open for the whole suite.
    """
    before_databases, before_roles = _per_run_objects(environment)

    for _ in range(2):
        handle = bootstrap.create_disposable_database(environment)
        bootstrap.drop_disposable_database(handle)

    after_databases, after_roles = _per_run_objects(environment)
    assert after_databases == before_databases, (
        f"per-run databases changed across two lifecycles: "
        f"{sorted(set(after_databases) - set(before_databases))} leaked"
    )
    assert after_roles == before_roles, (
        f"per-run roles changed across two lifecycles: "
        f"{sorted(set(after_roles) - set(before_roles))} leaked"
    )
    assert _marker_present(environment)


def test_the_marker_is_not_a_per_run_object(environment):
    """The one role that is supposed to outlive every run, named explicitly.

    It does not match the per-run pattern, so a "zero per-run roles" assertion is true
    while it exists -- which is the distinction the old "zero roles" phrasing lost.
    """
    import re

    marker = config.DISPOSABLE_CLUSTER_MARKER_ROLE
    assert not re.match(r"^firmbatch_test_(own|app|prov)_[0-9a-f]{12}$", marker)
    assert not config.DISPOSABLE_ROLE_PATTERN.match(marker), (
        "the marker matches the disposable-role pattern, so cleanup could delete it"
    )
    assert _marker_present(environment)
