"""The bootstrap administrator's trust boundary, and what is contained inside it.

**The boundary, stated once.** The bootstrap administrator is **trusted**. It is reachable
only through ``TestBootstrapSettings``, and only against a cluster that has explicitly
attested it is disposable. CI runs it as the ``postgres`` superuser of an ephemeral
PostgreSQL 16 service container; local verification runs it as a non-superuser
``CREATEROLE`` admin on an explicitly attested disposable cluster. Inside that boundary,
PostgreSQL administrative reachability into the per-run roles is **accepted**. Outside it
there is nothing to reach: no production or staging cluster carries the marker, and no
runtime settings object can load these credentials.

This module therefore does **not** try to prove that the administrator is isolated from the
roles it creates. That claim was made once, it was false for a superuser by construction,
and asserting it made bootstrap fail on exactly the cluster shape the architecture
describes. Two questions are kept apart here:

* **Catalogue membership** -- what ``pg_auth_members`` actually stores. The bootstrap takes
  a ``SET`` grant on the per-run owner for one statement (``CREATE DATABASE ... OWNER``
  needs it) and gives it back in a ``finally``. No explicit ``set_option`` or
  ``inherit_option`` row may survive where PostgreSQL permits revoking it. True of a
  superuser admin and a non-superuser admin alike, and asserted for both.
* **Effective authority** -- what ``pg_has_role`` answers. For a superuser that is "yes" to
  everything, by fiat, and no revoke changes it. It is not a bootstrap-success requirement
  and is not asserted as one.

What is genuinely contained, and asserted below: the per-run owner, application and
provisioning roles gain **no** bootstrap-administrator authority -- no ``SUPERUSER``,
``CREATEDB``, ``CREATEROLE``, ``BYPASSRLS`` or ``REPLICATION``, no route into the
administrator, and (for the runtime pair) no route into the owner. The administrator's
credentials appear in no runtime URL. Those are the properties the customer-facing
separation rests on, and they hold identically in CI and locally.

PostgreSQL 16's own limitation is recorded rather than worked around: a non-superuser
``CREATEROLE`` administrator receives a membership row whose grantor is the bootstrap
superuser, carrying ``admin_option``, and **cannot remove it**. That row is also what lets
it ``DROP ROLE`` the per-run roles at teardown, so removing it -- if that were possible --
would trade an accepted property for a guaranteed leak of three roles per run.

See ADR 0004 section 8f.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, text

from firmbatch.control_plane import config

#: Operations PostgreSQL gates on database *ownership* alone, so every non-owner is refused
#: for the same reason whether or not it can connect.
#:
#: ``DROP DATABASE`` is deliberately absent: a role attached to the database is refused it
#: for being attached, which would prove nothing about privilege. ``REVOKE CONNECT`` is
#: absent for a subtler reason, measured rather than assumed -- a non-owner *holding*
#: ``CONNECT`` gets PostgreSQL's "no privileges could be revoked" warning and no error at
#: all, so it is a real refusal only for a role that cannot connect either.
OWNER_ONLY_DATABASE_STATEMENTS = (
    'COMMENT ON DATABASE "{database}" IS \'hijacked\'',
    'ALTER DATABASE "{database}" CONNECTION LIMIT 0',
    'ALTER DATABASE "{database}" RENAME TO "{database}_hijacked"',
)

#: Additionally refused to the bootstrap administrator, which is neither the owner nor a
#: grantee of ``CONNECT``: bootstrap revokes ``CONNECT`` from ``PUBLIC`` and grants it to
#: the three per-run roles only. Measured: ``permission denied for database`` and
#: ``must be owner of database`` respectively.
NON_CONNECTING_NON_OWNER_STATEMENTS = (
    'REVOKE CONNECT ON DATABASE "{database}" FROM PUBLIC',
    'DROP DATABASE "{database}"',
)

#: The two ``pg_has_role`` privilege types that describe real reach: may become the role,
#: and holds its privileges without becoming it. ``'MEMBER'`` is not one of them -- it stays
#: true for an ADMIN-only grant even when ``SET ROLE`` is refused.
REACH_PRIVILEGES = ("SET", "USAGE")


def _admin(environment):
    return create_engine(
        config.load_test_admin_url(environment), isolation_level="AUTOCOMMIT", future=True
    )


@pytest.fixture()
def admin_is_superuser(environment) -> bool:
    """CI runs as ``postgres``; the developer cluster does not.

    Both are inside the accepted boundary, so this is never a reason for bootstrap to fail.
    It is used only to skip the two assertions that are *about* PostgreSQL's treatment of a
    non-superuser ``CREATEROLE`` administrator and have no meaning for a superuser -- rather
    than letting them report a green they did not earn.
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


# ------------------------------------------- the accepted boundary: bootstrap must succeed


def test_bootstrap_completes_under_a_superuser_or_a_non_superuser_administrator(
    disposable_database, environment, admin_is_superuser
):
    """The regression this module exists for.

    Bootstrap used to assert that ``pg_has_role(admin, owner, 'SET'/'USAGE')`` was false and
    to refuse to return a handle otherwise. A superuser satisfies both unconditionally, so
    CI -- which runs as ``postgres`` inside an ephemeral service container, exactly as the
    accepted architecture says -- could never get past provisioning.

    Reaching this test at all means bootstrap completed; the assertions confirm it produced
    a real, owner-owned database rather than an empty success. The admin's superuser status
    is read out and deliberately *not* branched on: both shapes must pass identically.
    """
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            owner = connection.execute(
                text("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = :d"),
                {"d": disposable_database.database},
            ).scalar()
    finally:
        engine.dispose()

    assert owner == disposable_database.owner_role, (
        f"the disposable database is owned by {owner!r}, not by the per-run owner "
        f"{disposable_database.owner_role!r}"
    )
    assert disposable_database.head_revision, "bootstrap returned a handle with no migration head"
    assert isinstance(admin_is_superuser, bool)


# ---------------------------------------------- catalogue membership, read not inferred


def test_no_revocable_membership_row_carries_set_or_inherit(disposable_database, environment):
    """Read from ``pg_auth_members`` directly, not inferred.

    The inferred answer was wrong twice: ``pg_has_role(..., 'MEMBER')`` stays true for an
    ADMIN-only grant, so it reported reachability that did not exist -- and a plain
    ``REVOKE`` reported success while changing nothing, so the stored answer and the
    inferred one disagreed in the other direction too.

    The set of rows is deliberately not asserted to be non-empty. A non-superuser creator
    holds one (its ``ADMIN OPTION`` row, granted by the bootstrap superuser, carrying
    neither option under test); a superuser creator receives none at all, because
    PostgreSQL 16 grants the creator ``ADMIN`` only when the creator is not a superuser.
    Both are correct outcomes.
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

    for grantor, member, _admin_option, inherit_option, set_option in rows:
        assert not set_option, (
            f"{member} still holds SET on the per-run owner, granted by {grantor}. The "
            "bootstrap takes that grant for one statement and must give it back."
        )
        assert not inherit_option, (
            f"{member} still inherits the per-run owner, granted by {grantor}. Revoking only "
            "the SET option leaves an inheriting row behind; both must go."
        )


def test_no_membership_path_carries_set_or_inherit(disposable_database, environment):
    """Recursive over ``pg_auth_members``, so an intermediate role cannot hide a route.

    Stored grants only. A superuser's authority is not a grant and does not appear here,
    which is the point: this asks what was left behind, not who could get in.
    """
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


# ------------------------------------------------------------- containment of the per-run roles


def test_the_per_run_roles_hold_no_administrative_attribute(disposable_database, environment):
    """None of the three roles is an administrator, whatever created them.

    A superuser bootstrap administrator is accepted; a superuser *runtime* role would make
    forced row-level security decorative, which is the thing Milestone 2.1 actually sells.
    """
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            rows = connection.execute(
                text(
                    "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls, "
                    "       rolreplication "
                    "FROM pg_roles WHERE rolname = ANY(:names) ORDER BY rolname"
                ),
                {
                    "names": [
                        disposable_database.owner_role,
                        disposable_database.application_role,
                        disposable_database.provisioning_role,
                    ]
                },
            ).all()
    finally:
        engine.dispose()

    assert len(rows) == 3, f"expected all three per-run roles, saw {[row[0] for row in rows]}"
    for row in rows:
        assert tuple(row[1:]) == (False, False, False, False, False), (
            f"{row[0]} holds an administrative attribute: "
            f"super={row[1]} createdb={row[2]} createrole={row[3]} bypassrls={row[4]} "
            f"replication={row[5]}"
        )


def test_the_per_run_roles_gain_no_route_into_the_bootstrap_administrator(
    disposable_database, environment
):
    """Reach is asked in the direction that matters: outward from the untrusted roles.

    Bootstrap grants membership *to* itself for one statement, never the other way round.
    A per-run role that could become the administrator would carry every capability the
    previous test just ruled out, so this is the same boundary from the other side.
    """
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            administrator = connection.execute(text("SELECT current_user")).scalar()
            for role in (
                disposable_database.owner_role,
                disposable_database.application_role,
                disposable_database.provisioning_role,
            ):
                for privilege in REACH_PRIVILEGES:
                    reaches = connection.execute(
                        text("SELECT pg_has_role(:member, :target, :privilege)"),
                        {"member": role, "target": administrator, "privilege": privilege},
                    ).scalar()
                    assert reaches is False, (
                        f"{role} holds {privilege} on the bootstrap administrator "
                        f"{administrator}"
                    )
    finally:
        engine.dispose()


def test_the_runtime_roles_gain_no_route_into_the_migration_owner(
    disposable_database, environment
):
    """The application and provisioning roles are the untrusted, customer-facing pair.

    The owner is the migration principal: it owns every table, and forced row-level
    security binds it too, but it can drop a policy outright. A runtime role that could
    become it would make the boundary advisory.
    """
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            for role in (
                disposable_database.application_role,
                disposable_database.provisioning_role,
            ):
                for privilege in REACH_PRIVILEGES:
                    reaches = connection.execute(
                        text("SELECT pg_has_role(:member, :target, :privilege)"),
                        {
                            "member": role,
                            "target": disposable_database.owner_role,
                            "privilege": privilege,
                        },
                    ).scalar()
                    assert reaches is False, (
                        f"{role} holds {privilege} on the per-run owner "
                        f"{disposable_database.owner_role}"
                    )
    finally:
        engine.dispose()


def test_the_runtime_roles_are_refused_every_owner_only_operation(
    disposable_database, raw_application_connection
):
    """Not bookkeeping: PostgreSQL refuses the application role outright.

    This runs identically on a superuser and a non-superuser cluster, because the role
    being refused is a per-run runtime role either way -- which is what makes it the
    containment assertion rather than a statement about the administrator.
    """
    for statement in OWNER_ONLY_DATABASE_STATEMENTS:
        with pytest.raises(Exception) as exc:
            raw_application_connection.execute(
                text(statement.format(database=disposable_database.database))
            )
        message = str(exc.value).lower()
        assert "must be owner" in message or "permission denied" in message, message


def test_the_bootstrap_credentials_reach_no_runtime_url(disposable_database, environment):
    """The administrator is confined to ``TestBootstrapSettings``.

    ``load_application_settings`` refusing to see the bootstrap URL is asserted in
    ``test_settings_separation.py``; this is the complementary half, on the handle that
    bootstrap actually hands to the suite. Each URL names its own per-run role and none of
    them names the administrator.
    """
    administrator = config.parse_connection_url(
        config.load_test_admin_url(environment), variable="FIRMBATCH_TEST_DATABASE_URL"
    ).username

    for label, url, expected_role in (
        ("migration_url", disposable_database.migration_url, disposable_database.owner_role),
        (
            "application_url",
            disposable_database.application_url,
            disposable_database.application_role,
        ),
        (
            "provisioning_url",
            disposable_database.provisioning_url,
            disposable_database.provisioning_role,
        ),
    ):
        spec = config.parse_connection_url(url, variable=label)
        assert spec.username == expected_role, f"{label} names {spec.username!r}"
        assert spec.username != administrator, (
            f"{label} carries the bootstrap administrator's identity"
        )


# ------------------------- PostgreSQL 16's limitation, for a non-superuser administrator


def test_the_administrator_is_refused_every_owner_only_operation(
    disposable_database, environment, admin_is_superuser
):
    """A non-superuser administrator is not the owner and PostgreSQL says so.

    Skipped, not silently passed, where the administrator is a superuser: it owns every
    object by fiat, that is accepted by ADR 0004 section 8f, and a loop that quietly
    ``continue``d would report a green it did not earn.
    """
    if admin_is_superuser:
        pytest.skip(
            "the bootstrap administrator is a superuser (CI's ephemeral service container). "
            "Owner-only refusal has no meaning for it; ADR 0004 section 8f accepts that "
            "reach inside the attested disposable cluster. The containment assertions on "
            "the per-run roles above run here unchanged."
        )

    engine = _admin(environment)
    try:
        for statement in OWNER_ONLY_DATABASE_STATEMENTS + NON_CONNECTING_NON_OWNER_STATEMENTS:
            with engine.connect() as connection:
                with pytest.raises(Exception) as exc:
                    connection.execute(
                        text(statement.format(database=disposable_database.database))
                    )
                message = str(exc.value).lower()
                assert "must be owner" in message or "permission denied" in message, message
    finally:
        engine.dispose()


def test_the_creator_membership_row_cannot_be_revoked(
    disposable_database, environment, admin_is_superuser
):
    """PostgreSQL 16's ``CREATEROLE`` ``ADMIN OPTION`` limitation, asserted directly.

    When a non-superuser ``CREATEROLE`` role creates a role, it receives a
    ``pg_auth_members`` row whose **grantor is the bootstrap superuser**. All three
    revocation spellings were tried against a real server: the first two report a warning
    and change nothing, the third is refused outright. The row therefore stays, carrying
    ``ADMIN`` and neither ``SET`` nor ``INHERIT`` -- which is why the catalogue assertions
    above pass with it present, and why teardown can still ``DROP ROLE``.

    Documented here so a future PostgreSQL that changes it is noticed. Skipped for a
    superuser administrator, which is the grantor of its own rows and has no such row to
    begin with.
    """
    if admin_is_superuser:
        pytest.skip(
            "a superuser administrator receives no creator ADMIN row: PostgreSQL 16 grants "
            "the creator ADMIN only when the creator is not a superuser. The limitation "
            "documented here applies to a non-superuser CREATEROLE administrator."
        )

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
                "the ADMIN row was granted by the administrator itself, so it could revoke it"
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
            assert still_there == 1, (
                "the creator's ADMIN row was removed -- PostgreSQL's behaviour has changed; "
                "revisit ADR 0004 section 8f and teardown's DROP ROLE authority"
            )

            # And revoking it explicitly is refused.
            with pytest.raises(Exception) as exc:
                connection.execute(
                    text(f'REVOKE "{owner}" FROM CURRENT_USER GRANTED BY "{grantor}"')
                )
            assert "permission denied" in str(exc.value)
    finally:
        engine.dispose()
