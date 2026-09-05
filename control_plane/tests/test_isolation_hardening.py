"""Regressions for the ways the isolation boundary was reachable around.

Each of these was reproduced against a real PostgreSQL 16 server before the corresponding
defence existed. They are kept apart from ``test_tenant_isolation.py`` because that module
asserts the boundary works; this one asserts the specific ways it did not.

* **Finding 2 -- inherited tenant context.** A session-level ``app.tenant_id``, set by a
  plain ``SET`` on a pooled connection or smuggled in through libpq ``options``, became
  the effective tenant of a transaction that set none. Milestone 2.3 removed the setting
  from the mechanism entirely, so these tests now assert two things at once: the old route
  is still closed, and it no longer leads anywhere even when it is open.
* **Finding 3 -- identity-map leakage.** A reused ``Session`` served an object loaded
  under tenant A to tenant B out of its identity map, with PostgreSQL never consulted and
  the policy never evaluated.
* **Finding 4 -- temporary-table shadowing.** ``CREATE TEMP TABLE workspaces (...)``
  shadowed the real table for the life of a connection, because PostgreSQL searches the
  temporary schema before ``search_path``. Still closed the same way: no runtime role holds
  ``TEMPORARY``, and ``search_path`` names ``pg_temp`` last.

  The authentication context briefly lived in the temporary schema too, in the first
  version of Milestone 2.3. It does not any more -- ``DISCARD TEMP`` drops a temporary
  relation regardless of who owns it, and no privilege exists to revoke -- so the
  ``TEMPORARY`` revoke is back to doing one job. ``test_authenticated_context.py`` covers
  the replacement.
"""

from __future__ import annotations

import pytest
from sqlalchemy import make_url, select, text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

from firmbatch.control_plane.config import ConfigurationError
from firmbatch.control_plane.db import auth
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.models import Tenant, Workspace
from firmbatch.control_plane.db.repositories import WorkspaceRepository


def _make_workspace(engine, principal, slug, name=None):
    with auth.authenticated_transaction(engine, principal.credential) as session:
        return WorkspaceRepository(session).create(slug=slug, name=name or slug.replace("-", " ")).id


# --------------------------------------------------- inherited context (finding 2)


def test_a_session_level_setting_cannot_become_the_effective_tenant(single_connection_engine, principal_a):
    """Transaction-local is not the same as absent -- and the setting is now inert as well.

    A plain ``SET`` is a *session* value: it survives COMMIT, it survives the pool
    returning the connection, and ``current_setting`` hands it to the next transaction
    quite happily. One connection in the pool, so the poisoned connection is necessarily
    the one reused. At Milestone 2.1 the defence was to clear the value; at 2.3 there is
    additionally nothing that reads it.
    """
    engine = single_connection_engine
    _make_workspace(engine, principal_a, "poisoned-target")

    with engine.connect() as connection:
        connection.execute(text("SELECT set_config('app.tenant_id', :t, false)"), {"t": str(principal_a.id)})
        connection.commit()

    with db_engine.transaction(engine) as session:
        assert db_engine.current_tenant_context(session) is None, "a session-level value leaked in"
        assert WorkspaceRepository(session).list() == []
        assert session.scalars(select(Tenant)).all() == []


def test_a_url_supplied_option_is_refused_outright(disposable_database, tenant_a):
    """``options`` can preselect a role or unpin ``search_path``, so it is rejected as a class.

    The tenant setting it used to carry no longer means anything, and the parameter is
    still refused: what made it dangerous was never only the tenant.
    """
    poisoned = make_url(disposable_database.application_url).update_query_dict(
        {"options": f"-c app.tenant_id={tenant_a}"}
    )
    with pytest.raises(ConfigurationError) as exc:
        db_engine.create_application_engine(poisoned.render_as_string(hide_password=False))
    assert "options" in str(exc.value)


def test_an_authenticated_context_does_not_survive_the_pool(single_connection_engine, principal_a):
    """The Milestone 2.3 form of the same property, on the mechanism that replaced it.

    One physical connection. A transaction binds, commits, and the next holder of that
    connection must start with nothing -- which PostgreSQL guarantees by construction: the
    context row carries the transaction id that wrote it, and the next transaction's id is
    different. ``transaction()`` asserts that rather than clearing anything.
    """
    engine = single_connection_engine
    _make_workspace(engine, principal_a, "pool-context-target")

    with auth.authenticated_transaction(engine, principal_a.credential) as session:
        assert db_engine.current_tenant_context(session) == principal_a.id

    with db_engine.transaction(engine) as session:
        assert db_engine.current_tenant_context(session) is None
        assert WorkspaceRepository(session).list() == []
        assert session.scalars(select(Tenant)).all() == []


# ------------------------------------------------ identity-map leakage (finding 3)


def test_a_reused_session_cannot_serve_a_previous_tenants_object(
    application_engine, principal_a, principal_b
):
    """SQLAlchemy answers ``get()`` from its identity map, not from PostgreSQL.

    Holding a strong reference to an object loaded under tenant A and then using the same
    ``Session`` as tenant B used to return that object straight from the identity map. The
    strong reference matters: the identity map holds weak references, so a test that
    dropped the object would pass for the wrong reason.
    """
    a_workspace = _make_workspace(application_engine, principal_a, "identity-map-a", "Identity Map A")

    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.require_no_inherited_context(session)
            auth.bind_authenticated_context(session, principal_a.credential)
            held = session.get(Workspace, a_workspace)
            assert held is not None and held.slug == "identity-map-a"

        with session.begin():
            db_engine.require_no_inherited_context(session)
            auth.bind_authenticated_context(session, principal_b.credential)
            leaked = session.get(Workspace, a_workspace)
            assert leaked is None, "an object loaded under tenant A was served under tenant B"
            assert WorkspaceRepository(session).list() == []
        # The caller keeps the object it already loaded; what it loses is the ability to
        # have it served again without PostgreSQL being asked.
        assert held.slug == "identity-map-a"
    finally:
        session.close()


def test_a_reused_session_cannot_serve_an_object_in_an_unauthenticated_transaction(
    application_engine, principal_a
):
    """The same defence for the fail-closed state, reached the only way it can be reached.

    Milestone 2.3 originally offered a way to *drop* a context part-way through a
    transaction, and this test used it. That operation is gone -- it turned out to be a
    route by which a caller could abandon one identity and bind another inside the same
    transaction -- so the unauthenticated state is now reached the way a real request
    reaches it: by being a different transaction.
    """
    a_workspace = _make_workspace(application_engine, principal_a, "identity-map-clear", "Identity Map Clear")

    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.require_no_inherited_context(session)
            auth.bind_authenticated_context(session, principal_a.credential)
            held = session.get(Workspace, a_workspace)
            assert held is not None

        with session.begin():
            db_engine.require_no_inherited_context(session)
            assert held is not None  # strong reference kept on purpose
            assert session.get(Workspace, a_workspace) is None
    finally:
        session.close()


def test_switching_back_to_the_original_tenant_still_reads_from_postgresql(
    application_engine, principal_a, principal_b
):
    """Expunging must not break the legitimate case: A then B then A still works."""
    a_workspace = _make_workspace(application_engine, principal_a, "round-trip-a", "Round Trip A")

    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        for credential, expected in (
            (principal_a.credential, True),
            (principal_b.credential, False),
            (principal_a.credential, True),
        ):
            with session.begin():
                db_engine.require_no_inherited_context(session)
                auth.bind_authenticated_context(session, credential)
                found = session.get(Workspace, a_workspace)
                assert (found is not None) is expected
                if found is not None:
                    assert found.slug == "round-trip-a"
    finally:
        session.close()


# ------------------------------------------- temporary-table shadowing (finding 4)


def test_the_application_role_cannot_create_a_temporary_table(raw_application_connection):
    """TEMP is revoked from PUBLIC and granted to no runtime role.

    Load-bearing twice since Milestone 2.3: it stops a temporary relation shadowing a
    Firmbatch table, and it stops one being created where the authentication context
    lives.
    """
    with pytest.raises(ProgrammingError) as exc:
        raw_application_connection.execute(
            text("CREATE TEMP TABLE workspaces (id uuid, tenant_id uuid, slug text, name text)")
        )
    assert "permission denied" in str(exc.value).lower()


def test_the_provisioning_role_cannot_create_a_temporary_table(disposable_database):
    """The same for the privileged provisioning role: it creates scopes, not relations."""
    engine = db_engine.create_application_engine(disposable_database.provisioning_url, pool_size=1)
    try:
        with engine.connect() as connection:
            with pytest.raises(ProgrammingError) as exc:
                connection.execute(text("CREATE TEMP TABLE tenants (id uuid, slug text, name text)"))
            assert "permission denied" in str(exc.value).lower()
    finally:
        engine.dispose()


def test_an_unqualified_reference_resolves_to_the_real_table(application_engine, principal_a):
    """The second defence: search_path names pg_temp explicitly and last.

    Compared by OID rather than by rendered name: ``to_regclass`` omits the schema when the
    relation is reachable through ``search_path``, so a name comparison would fail on a
    correctly resolved table.
    """
    _make_workspace(application_engine, principal_a, "unqualified-target")
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        same = session.execute(
            text(f"SELECT to_regclass('workspaces') = to_regclass('{SCHEMA}.workspaces')")
        ).scalar()
        assert same is True
        assert session.execute(text("SELECT count(*) FROM workspaces")).scalar() == 1


def test_search_path_names_pg_temp_last_on_every_connection(application_engine):
    """Omitting pg_temp is what makes PostgreSQL search it first."""
    with application_engine.connect() as connection:
        search_path = connection.execute(text("SHOW search_path")).scalar()
    parts = [p.strip().strip('"') for p in search_path.split(",")]
    assert parts[0] == SCHEMA, f"the pinned schema must come first: {search_path!r}"
    assert parts[-1] == "pg_temp", f"pg_temp must be named explicitly and last: {search_path!r}"


def test_a_temporary_table_created_by_the_owner_cannot_shadow_the_real_one(
    owner_engine, application_engine, principal_a
):
    """Even where TEMP is held, the pinned search_path keeps resolution correct.

    The owner legitimately holds TEMP. This proves the second defence stands on its own:
    a temporary relation with the same name does not capture an unqualified reference,
    because pg_temp is searched last.
    """
    _make_workspace(application_engine, principal_a, "owner-shadow-target")
    with owner_engine.connect() as connection:
        connection.execute(text("CREATE TEMP TABLE workspaces (id uuid, tenant_id uuid, slug text, name text)"))
        connection.execute(
            text(
                "INSERT INTO pg_temp.workspaces "
                "VALUES (gen_random_uuid(), gen_random_uuid(), 'forged', 'FORGED')"
            )
        )
        resolves_to_real = connection.execute(
            text(f"SELECT to_regclass('workspaces') = to_regclass('{SCHEMA}.workspaces')")
        ).scalar()
        assert resolves_to_real is True, "a temporary relation shadowed the real table"
        slugs = connection.execute(text("SELECT slug FROM workspaces")).scalars().all()
        assert "forged" not in slugs
        connection.rollback()


# ------------------------------------------------------------- nested savepoints


def test_acquiring_a_context_inside_a_savepoint_is_refused(application_engine, principal_a, principal_b):
    """One authenticated context per outer transaction.

    A savepoint rollback removes a context written inside it while a release keeps one,
    and neither restores the ORM identity map -- so a bind here would sometimes survive
    and sometimes not, decided by how the caller happened to end the savepoint. Rather
    than trying to unwind that bookkeeping correctly, it is refused.
    """
    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.require_no_inherited_context(session)
            auth.bind_authenticated_context(session, principal_a.credential)
            nested = session.begin_nested()
            try:
                with pytest.raises(db_engine.TenantContextError) as exc:
                    auth.bind_authenticated_context(session, principal_b.credential)
                assert "SAVEPOINT" in str(exc.value)
                with pytest.raises(db_engine.TenantContextError):
                    auth.begin_tenant_provisioning(session)
            finally:
                nested.rollback()
    finally:
        session.close()


def test_there_is_no_raw_route_to_change_the_context_inside_a_savepoint(
    application_engine, principal_a, tenant_b
):
    """The defence that used to be needed here has been replaced by an absence.

    At Milestone 2.1 a caller could bypass this module and change tenant with a raw
    ``set_config`` inside a savepoint; the guard existed because the raw route worked. It
    no longer does -- the setting is read by nothing, and the function that writes a
    context is executable by no runtime role -- so what is asserted here is that both raw
    routes fail and the outer context is unchanged.
    """
    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.require_no_inherited_context(session)
            auth.bind_authenticated_context(session, principal_a.credential)

            nested = session.begin_nested()
            try:
                session.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_b)})
                assert db_engine.current_tenant_context(session) == principal_a.id
            finally:
                nested.rollback()

            nested = session.begin_nested()
            try:
                with pytest.raises(ProgrammingError) as exc:
                    session.execute(
                        text(
                            f"SELECT {SCHEMA}.auth_context_begin("
                            "NULL, :t, NULL, 'credential', ARRAY['workspace:read'])"
                        ),
                        {"t": str(tenant_b)},
                    )
                assert "permission denied" in str(exc.value).lower()
            finally:
                nested.rollback()

            assert db_engine.current_tenant_context(session) == principal_a.id
    finally:
        session.close()


def test_ending_a_savepoint_empties_the_identity_map(application_engine, principal_a):
    """The guard that fires whenever a savepoint ends, on rollback, commit and exception.

    It is what stopped an object loaded under one context being served after the context
    that loaded it was gone. The context can no longer change inside a savepoint, so this
    is now defence in depth rather than the primary fix -- and it is exactly the kind of
    guard that would be quietly refactored away if nothing asserted it.
    """
    a_workspace = _make_workspace(application_engine, principal_a, "savepoint-map", "Savepoint Map")

    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.require_no_inherited_context(session)
            auth.bind_authenticated_context(session, principal_a.credential)
            # Strong references throughout: the identity map holds weak ones, so a test
            # that let the object be collected would watch the map empty itself and
            # conclude the guard had worked.
            held = session.get(Workspace, a_workspace)
            assert held is not None and session.identity_map.keys() != set()

            nested = session.begin_nested()
            nested.commit()
            assert session.identity_map.keys() == set()

            held = session.get(Workspace, a_workspace)
            assert held is not None
            with session.begin_nested() as nested:
                nested.rollback()
            assert session.identity_map.keys() == set()

            held = session.get(Workspace, a_workspace)
            assert held is not None
            try:
                with session.begin_nested():
                    raise RuntimeError("deliberate failure inside a savepoint")
            except RuntimeError:
                pass
            assert session.identity_map.keys() == set()
    finally:
        session.close()


def test_the_outer_context_still_works_after_a_savepoint(application_engine, principal_a):
    """The prohibition must not break ordinary savepoint use within one tenant."""
    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.require_no_inherited_context(session)
            auth.bind_authenticated_context(session, principal_a.credential)
            repo = WorkspaceRepository(session)
            with session.begin_nested():
                repo.create(slug="savepoint-inner", name="Savepoint Inner")
            assert db_engine.current_tenant_context(session) == principal_a.id
            assert any(w.slug == "savepoint-inner" for w in repo.list())
    finally:
        session.close()
