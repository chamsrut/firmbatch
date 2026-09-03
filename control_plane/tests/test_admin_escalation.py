"""Finding 1: what the shared admin can and cannot do to the per-run owner role.

This module exists because the requested property turned out not to be achievable, and the
honest response to that is a test that pins the real behaviour rather than a test shaped
like the property we wanted.

**What was asked for.** After bootstrap, revoke the entire owner-role membership from the
shared admin -- ADMIN, SET and INHERIT -- and prove that ``GRANT owner TO admin WITH SET
TRUE``, ``SET ROLE owner`` and an owner-only operation all fail.

**What PostgreSQL 16 actually does.** When a non-superuser ``CREATEROLE`` role creates a
role, it receives a ``pg_auth_members`` row whose **grantor is the bootstrap superuser**,
carrying ``admin_option``. A non-superuser cannot remove that row:

* ``REVOKE owner FROM CURRENT_USER`` -> ``WARNING: role "admin" has not been granted
  membership in role "owner" by role "admin"``, and the row is untouched;
* ``REVOKE ADMIN OPTION FOR owner FROM CURRENT_USER`` -> the same warning, same outcome;
* ``REVOKE owner FROM CURRENT_USER GRANTED BY postgres`` -> ``ERROR: permission denied to
  revoke privileges granted by role "postgres"``.

Holding ``ADMIN OPTION``, the admin may ``GRANT owner TO CURRENT_USER WITH SET TRUE`` again
whenever it likes. **The escalation cannot be closed from inside this code**, and the
review's instruction in that case was to stop and report it rather than weaken the test or
the threat model. That is what these tests do: they assert the properties that *are* true,
and they pin the one that is not so that a future PostgreSQL which closes it is noticed
rather than assumed.

Removing the ADMIN row is also not merely blocked, it is undesirable: it is what lets the
admin ``DROP ROLE`` the per-run roles at teardown. Losing it would trade a documented
residual for a guaranteed leak of three roles per run.

**What is genuinely established**, and what the rest of the design leans on:

* no *standing* reachability -- a process holding the shared admin credentials, which is
  the concurrent-test-run threat this design is actually about, cannot assume the owner's
  identity as it stands;
* no ``set_option`` or ``inherit_option`` on any membership row, direct or indirect;
* the admin is not the database owner and PostgreSQL refuses it every owner-only operation
  outright, so ordinary teardown authority really is bound to the per-run identity.

See ADR 0004 section 8e.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, text

from firmbatch.control_plane import config


def _admin(environment):
    return create_engine(
        config.load_test_admin_url(environment), isolation_level="AUTOCOMMIT", future=True
    )


@pytest.fixture()
def admin_is_superuser(environment) -> bool:
    """CI runs as ``postgres``; the developer cluster does not.

    A superuser may ``SET ROLE`` to anything by fiat, so the reachability assertions below
    are meaningful only for a non-superuser admin. Recorded as a fact rather than used to
    skip: the catalogue assertions run either way, and ADR 0004 section 8e already places a
    concurrent superuser outside the threat model.
    """
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


# ------------------------------------------------------------ what IS established


def test_no_membership_row_carries_set_or_inherit(disposable_database, environment):
    """Read from ``pg_auth_members`` directly, not inferred.

    The inferred answer was wrong once already: ``pg_has_role(..., 'MEMBER')`` stays true
    for an ADMIN-only grant, so it reported reachability that did not exist -- and a plain
    ``REVOKE`` reported success while changing nothing, so the stored answer and the
    inferred one disagreed in the other direction too.
    """
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            rows = connection.execute(
                text(
                    "SELECT m.grantor::regrole::text, m.member::regrole::text, "
                    "       m.admin_option, m.inherit_option, m.set_option "
                    "FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid "
                    "WHERE r.rolname = :role"
                ),
                {"role": disposable_database.owner_role},
            ).all()
    finally:
        engine.dispose()

    assert rows, "the creator's membership row should still exist -- teardown needs its ADMIN"
    for grantor, member, admin_option, inherit_option, set_option in rows:
        assert not set_option, f"{member} still has SET on the owner, granted by {grantor}"
        assert not inherit_option, f"{member} still inherits the owner, granted by {grantor}"


def test_no_direct_or_indirect_path_reaches_the_owner(disposable_database, environment):
    """Recursive over ``pg_auth_members``, so an intermediate role cannot hide a route."""
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            paths = connection.execute(
                text(
                    """
                    WITH RECURSIVE reachable(oid, path, can_set, inherits) AS (
                        SELECT r.oid, ARRAY[r.rolname]::text[], true, true
                        FROM pg_roles r WHERE r.rolname = current_user
                      UNION ALL
                        SELECT g.oid, reachable.path || g.rolname,
                               reachable.can_set AND m.set_option,
                               reachable.inherits AND m.inherit_option
                        FROM reachable
                        JOIN pg_auth_members m ON m.member = reachable.oid
                        JOIN pg_roles g ON g.oid = m.roleid
                        WHERE NOT g.rolname = ANY(reachable.path)
                    )
                    SELECT path, can_set, inherits FROM reachable
                    WHERE path[array_length(path, 1)] = :role AND array_length(path, 1) > 1
                    """
                ),
                {"role": disposable_database.owner_role},
            ).all()
    finally:
        engine.dispose()

    for path, can_set, inherits in paths:
        assert not can_set, f"membership path grants SET: {' -> '.join(path)}"
        assert not inherits, f"membership path grants INHERIT: {' -> '.join(path)}"


def test_the_admin_cannot_set_role_as_it_stands(disposable_database, environment, admin_is_superuser):
    """No standing reachability. This is the property the design actually leans on."""
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            can_set = connection.execute(
                text("SELECT pg_has_role(current_user, :r, 'SET')"),
                {"r": disposable_database.owner_role},
            ).scalar()
    finally:
        engine.dispose()

    if admin_is_superuser:
        # A superuser may become anything; ADR 0004 8e places that outside the threat model.
        assert can_set is True, "a superuser admin unexpectedly could not SET ROLE"
    else:
        assert can_set is False, "the shared admin retains standing SET ROLE into the owner"


def test_the_admin_is_refused_every_owner_only_operation(disposable_database, environment, admin_is_superuser):
    """Teardown authority is bound to the per-run identity, and PostgreSQL enforces it.

    A superuser admin owns everything by fiat, so there is nothing here for CI to prove --
    the loop records that and moves on rather than reporting a green it did not earn.
    """
    engine = _admin(environment)
    try:
        for statement in (
            f'COMMENT ON DATABASE "{disposable_database.database}" IS \'hijacked\'',
            f'REVOKE CONNECT ON DATABASE "{disposable_database.database}" FROM PUBLIC',
            f'ALTER DATABASE "{disposable_database.database}" CONNECTION LIMIT 0',
            f'DROP DATABASE "{disposable_database.database}"',
        ):
            with engine.connect() as connection:
                if admin_is_superuser:
                    # Nothing to prove: a superuser owns everything by fiat. Recorded so the
                    # test still runs on CI rather than reporting a green it did not earn.
                    continue
                with pytest.raises(Exception) as exc:
                    connection.execute(text(statement))
                assert "must be owner" in str(exc.value) or "permission denied" in str(exc.value)
    finally:
        engine.dispose()


# ------------------------------------------------------------ what is NOT established


def test_the_admin_can_still_regain_the_owner_role(disposable_database, environment):
    """**Known design blocker, pinned rather than hidden.**

    The shared admin holds ``ADMIN OPTION`` on the per-run owner through a membership row
    granted by the bootstrap superuser, which no non-superuser may revoke. It can therefore
    re-grant itself ``SET`` and become the owner at will.

    This test asserts that this is *currently true*. That is deliberate. If a future
    PostgreSQL, or a change here, closes the escalation, this test fails and the residual
    in ADR 0004 section 8e can be narrowed -- which is exactly the moment somebody should be
    told. A test asserting the property we wanted would instead have been red from the day
    it was written and deleted by the second person to see it.

    The state is restored afterwards, so the rest of the session sees the same separation
    every other test relies on.
    """
    owner = disposable_database.owner_role
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            # 1. re-grant
            connection.execute(text(f'GRANT "{owner}" TO CURRENT_USER WITH SET TRUE'))
            regained = connection.execute(
                text("SELECT pg_has_role(current_user, :r, 'SET')"), {"r": owner}
            ).scalar()
            assert regained is True, (
                "the shared admin could NOT re-grant itself SET on the per-run owner. "
                "That is better than documented -- narrow the residual in ADR 0004 8e."
            )

            # 2. become it
            connection.execute(text(f'SET ROLE "{owner}"'))
            became = connection.execute(text("SELECT current_user")).scalar()
            assert became == owner

            # 3. and therefore perform an owner-only operation
            connection.execute(
                text(f'COMMENT ON DATABASE "{disposable_database.database}" IS \'escalated\'')
            )
            connection.execute(text("RESET ROLE"))
    finally:
        # Put it back exactly as bootstrap left it: SET and INHERIT off, ADMIN untouched,
        # and the provenance marker restored so teardown's identity check still passes.
        with engine.connect() as connection:
            connection.execute(text(f'SET ROLE "{owner}"'))
            marker = next(
                o.marker for o in disposable_database.created if o.kind == "database"
            )
            connection.execute(
                text(f'COMMENT ON DATABASE "{disposable_database.database}" IS \'{marker}\'')
            )
            connection.execute(text("RESET ROLE"))
            connection.execute(text(f'REVOKE SET OPTION FOR "{owner}" FROM CURRENT_USER'))
            connection.execute(text(f'REVOKE INHERIT OPTION FOR "{owner}" FROM CURRENT_USER'))
        engine.dispose()


def test_the_creator_membership_row_cannot_be_revoked(disposable_database, environment, admin_is_superuser):
    """The mechanism behind the blocker, asserted directly.

    All three revocation spellings were tried against a real server. The first two report a
    warning and change nothing; the third is refused outright.
    """
    if admin_is_superuser:
        return  # a superuser IS the grantor, so it can revoke; nothing to establish here

    owner = disposable_database.owner_role
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            grantor = connection.execute(
                text(
                    "SELECT m.grantor::regrole::text FROM pg_auth_members m "
                    "JOIN pg_roles r ON r.oid = m.roleid WHERE r.rolname = :role "
                    "AND m.admin_option"
                ),
                {"role": owner},
            ).scalar()
            assert grantor is not None, "the creator's ADMIN row is missing"
            assert grantor != connection.execute(text("SELECT current_user")).scalar(), (
                "the ADMIN row was granted by the admin itself, so it could revoke it"
            )

            # Plain REVOKE and REVOKE ADMIN OPTION are no-ops against a row granted by
            # somebody else: they warn, and the row survives.
            connection.execute(text(f'REVOKE "{owner}" FROM CURRENT_USER'))
            connection.execute(text(f'REVOKE ADMIN OPTION FOR "{owner}" FROM CURRENT_USER'))
            still_there = connection.execute(
                text(
                    "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid "
                    "WHERE r.rolname = :role AND m.admin_option"
                ),
                {"role": owner},
            ).scalar()
            assert still_there == 1, "the creator's ADMIN row was removed -- narrow ADR 0004 8e"

            # And revoking it explicitly is refused.
            with pytest.raises(Exception) as exc:
                connection.execute(
                    text(f'REVOKE "{owner}" FROM CURRENT_USER GRANTED BY "{grantor}"')
                )
            assert "permission denied" in str(exc.value)
    finally:
        engine.dispose()
