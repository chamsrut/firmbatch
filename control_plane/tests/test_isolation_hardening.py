"""Regressions for the three ways the isolation boundary was reachable around.

Each of these was reproduced against a real PostgreSQL 16 server before the corresponding
defence existed. They are kept apart from ``test_tenant_isolation.py`` because that module
asserts the boundary works; this one asserts the specific ways it did not.

* **Finding 2 -- inherited tenant context.** A session-level ``app.tenant_id``, set by a
  plain ``SET`` on a pooled connection or smuggled in through libpq ``options``, became
  the effective tenant of a transaction that set none.
* **Finding 3 -- identity-map leakage.** A reused ``Session`` served an object loaded
  under tenant A to tenant B out of its identity map, with PostgreSQL never consulted and
  the policy never evaluated.
* **Finding 4 -- temporary-table shadowing.** ``CREATE TEMP TABLE workspaces (...)``
  shadowed the real table for the life of a connection, because PostgreSQL searches the
  temporary schema before ``search_path``. Row-level security does not help: the policy is
  attached to a table the query no longer reaches.
"""

from __future__ import annotations

import pytest
from sqlalchemy import make_url, select, text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

from firmbatch.control_plane.config import ConfigurationError
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.models import Tenant, Workspace
from firmbatch.control_plane.db.repositories import WorkspaceRepository


def _make_workspace(engine, tenant_id, slug, name=None):
    with db_engine.tenant_transaction(engine, tenant_id) as session:
        return WorkspaceRepository(session).create(slug=slug, name=name or slug.replace("-", " ")).id


# --------------------------------------------------- inherited context (finding 2)


def test_a_session_level_tenant_cannot_become_the_effective_tenant(single_connection_engine, tenant_a):
    """Transaction-local is not the same as absent.

    A plain ``SET`` is a *session* value: it survives COMMIT, it survives the pool
    returning the connection, and ``current_setting`` hands it to the next transaction
    quite happily. One connection in the pool, so the poisoned connection is necessarily
    the one reused.
    """
    engine = single_connection_engine
    _make_workspace(engine, tenant_a, "poisoned-target")

    with engine.connect() as connection:
        connection.execute(text("SELECT set_config('app.tenant_id', :t, false)"), {"t": str(tenant_a)})
        connection.commit()

    with db_engine.transaction(engine) as session:
        assert db_engine.current_tenant_context(session) is None, "a session-level value leaked into the transaction"
        assert WorkspaceRepository(session).list() == []
        assert session.scalars(select(Tenant)).all() == []


def test_a_url_supplied_tenant_option_is_refused_outright(disposable_database, tenant_a):
    """The same leak, arriving through libpq ``options`` instead of SQL.

    ``?options=-c app.tenant_id=<uuid>`` sets the GUC at connect time, before any of this
    package runs. It is now refused during URL validation rather than merely cleared
    afterwards: ``options`` can also preselect a role or unpin ``search_path``, so the
    parameter has no legitimate use here and is rejected as a class.
    """
    poisoned = make_url(disposable_database.application_url).update_query_dict(
        {"options": f"-c app.tenant_id={tenant_a}"}
    )
    with pytest.raises(ConfigurationError) as exc:
        db_engine.create_application_engine(poisoned.render_as_string(hide_password=False))
    assert "options" in str(exc.value)


def test_a_session_guc_set_after_connect_is_still_cleared(single_connection_engine, tenant_a):
    """Defence in depth: rejecting the URL is not the only thing standing between a
    session-level value and the effective tenant.

    The GUC is set here through ordinary SQL on a pooled connection -- a route no URL
    validation can see -- and must still not reach a transaction that asked for nothing.
    """
    engine = single_connection_engine
    _make_workspace(engine, tenant_a, "post-connect-target")
    with engine.connect() as connection:
        connection.execute(text("SELECT set_config('app.tenant_id', :t, false)"), {"t": str(tenant_a)})
        connection.commit()
    with db_engine.transaction(engine) as session:
        assert db_engine.current_tenant_context(session) is None
        assert WorkspaceRepository(session).list() == []


def test_the_baseline_is_applied_before_the_requested_tenant(single_connection_engine, tenant_a, tenant_b):
    """A poisoned connection must not influence a transaction that *does* set a context."""
    engine = single_connection_engine
    _make_workspace(engine, tenant_a, "baseline-a")
    _make_workspace(engine, tenant_b, "baseline-b")

    with engine.connect() as connection:
        connection.execute(text("SELECT set_config('app.tenant_id', :t, false)"), {"t": str(tenant_a)})
        connection.commit()

    with db_engine.tenant_transaction(engine, tenant_b) as session:
        assert db_engine.current_tenant_context(session) == tenant_b
        assert [w.slug for w in WorkspaceRepository(session).list()] == ["baseline-b"]


# ------------------------------------------------ identity-map leakage (finding 3)


def test_a_reused_session_cannot_serve_a_previous_tenants_object(application_engine, tenant_a, tenant_b):
    """SQLAlchemy answers ``get()`` from its identity map, not from PostgreSQL.

    Holding a strong reference to an object loaded under tenant A and then switching the
    same ``Session`` to tenant B used to return that object straight from the identity map.
    The strong reference matters: the identity map holds weak references, so a test that
    dropped the object would pass for the wrong reason.
    """
    a_workspace = _make_workspace(application_engine, tenant_a, "identity-map-a", "Identity Map A")

    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.set_tenant_context(session, tenant_a)
            held = session.get(Workspace, a_workspace)
            assert held is not None and held.slug == "identity-map-a"

        with session.begin():
            db_engine.set_tenant_context(session, tenant_b)
            leaked = session.get(Workspace, a_workspace)
            assert leaked is None, "an object loaded under tenant A was served under tenant B"
            assert WorkspaceRepository(session).list() == []
        # The caller keeps the object it already loaded; what it loses is the ability to
        # have it served again without PostgreSQL being asked.
        assert held.slug == "identity-map-a"
    finally:
        session.close()


def test_a_reused_session_cannot_serve_an_object_after_the_context_is_cleared(application_engine, tenant_a):
    """The same defence for a cleared context, which is the fail-closed state."""
    a_workspace = _make_workspace(application_engine, tenant_a, "identity-map-clear", "Identity Map Clear")

    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.set_tenant_context(session, tenant_a)
            held = session.get(Workspace, a_workspace)
            assert held is not None

        with session.begin():
            db_engine.reset_tenant_context(session)
            assert session.get(Workspace, a_workspace) is None
    finally:
        session.close()


def test_switching_back_to_the_original_tenant_still_reads_from_postgresql(
    application_engine, tenant_a, tenant_b
):
    """Expunging must not break the legitimate case: A then B then A still works."""
    a_workspace = _make_workspace(application_engine, tenant_a, "round-trip-a", "Round Trip A")

    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.set_tenant_context(session, tenant_a)
            assert session.get(Workspace, a_workspace) is not None
        with session.begin():
            db_engine.set_tenant_context(session, tenant_b)
            assert session.get(Workspace, a_workspace) is None
        with session.begin():
            db_engine.set_tenant_context(session, tenant_a)
            again = session.get(Workspace, a_workspace)
            assert again is not None and again.slug == "round-trip-a"
    finally:
        session.close()


# ------------------------------------------- temporary-table shadowing (finding 4)


def test_the_application_role_cannot_create_a_temporary_table(raw_application_connection):
    """TEMP is revoked from PUBLIC and granted to no runtime role."""
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


def test_an_unqualified_reference_resolves_to_the_real_table(application_engine, tenant_a):
    """The second defence: search_path names pg_temp explicitly and last.

    Compared by OID rather than by rendered name: ``to_regclass`` omits the schema when the
    relation is reachable through ``search_path``, so a name comparison would fail on a
    correctly resolved table.
    """
    _make_workspace(application_engine, tenant_a, "unqualified-target")
    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
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


def test_a_temporary_table_created_by_the_owner_cannot_shadow_the_real_one(owner_engine, application_engine, tenant_a):
    """Even where TEMP is held, the pinned search_path keeps resolution correct.

    The owner legitimately holds TEMP. This proves the second defence stands on its own:
    a temporary relation with the same name does not capture an unqualified reference,
    because pg_temp is searched last.
    """
    _make_workspace(application_engine, tenant_a, "owner-shadow-target")
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


# ------------------------------------------- nested savepoints (finding 4)


def test_a_tenant_switch_inside_a_savepoint_is_refused(application_engine, tenant_a, tenant_b):
    """One tenant context per outer transaction.

    A savepoint rollback restores the PostgreSQL setting but not the ORM identity map, so
    a switch inside one could leave another tenant rows cached. Rather than trying to
    unwind that bookkeeping correctly, the switch is refused.
    """
    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.set_tenant_context(session, tenant_a)
            nested = session.begin_nested()
            try:
                with pytest.raises(db_engine.TenantContextError) as exc:
                    db_engine.set_tenant_context(session, tenant_b)
                assert "SAVEPOINT" in str(exc.value)
                with pytest.raises(db_engine.TenantContextError):
                    db_engine.clear_tenant_context(session)
                with pytest.raises(db_engine.TenantContextError):
                    db_engine.reset_tenant_context(session)
            finally:
                nested.rollback()
    finally:
        session.close()


def test_a_raw_switch_inside_a_savepoint_cannot_survive_its_rollback(
    application_engine, tenant_a, tenant_b
):
    """The second defence, for a caller that bypasses this module and uses raw SQL.

    Reproduced against a real server: after the nested rollback PostgreSQL correctly
    restored tenant A, and ``session.get()`` still returned the tenant B object straight
    from the identity map. Ending a savepoint now empties the map.
    """
    a_workspace = _make_workspace(application_engine, tenant_a, "savepoint-a", "Savepoint A")
    b_workspace = _make_workspace(application_engine, tenant_b, "savepoint-b", "Savepoint B")

    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.set_tenant_context(session, tenant_a)
            assert session.get(Workspace, a_workspace) is not None

            nested = session.begin_nested()
            try:
                # Raw set_config, deliberately going around set_tenant_context.
                session.execute(
                    text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_b)}
                )
                held_b = session.get(Workspace, b_workspace)
                assert held_b is not None and held_b.slug == "savepoint-b"
            finally:
                nested.rollback()

            # PostgreSQL restored tenant A ...
            assert db_engine.current_tenant_context(session) == tenant_a
            # ... and the tenant B object must not be servable from the identity map.
            assert session.get(Workspace, b_workspace) is None
            assert session.get(Workspace, a_workspace) is not None
    finally:
        session.close()


def test_a_nested_commit_clears_the_identity_map_and_leaves_the_switch_standing(
    application_engine, tenant_a, tenant_b
):
    """The commit path, and the PostgreSQL fact that makes the API prohibition necessary.

    Releasing a savepoint does **not** undo a ``SET LOCAL`` made inside it -- only rolling
    the savepoint back does. So a raw switch inside a savepoint that commits leaves the
    outer transaction genuinely running as the other tenant, and no amount of Python
    bookkeeping can undo that. This is measured here rather than assumed, because it is
    the reason ``set_tenant_context`` refuses to switch inside a savepoint at all: the
    only safe answer is not to allow the switch.

    What the guard still does on this path is empty the identity map, so nothing is served
    from cache and every read is re-evaluated by PostgreSQL under whatever context is
    actually in force.
    """
    a_workspace = _make_workspace(application_engine, tenant_a, "savepoint-commit-a", "SC A")
    b_workspace = _make_workspace(application_engine, tenant_b, "savepoint-commit-b", "SC B")

    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.set_tenant_context(session, tenant_a)
            assert session.get(Workspace, a_workspace) is not None

            nested = session.begin_nested()
            session.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_b)})
            assert session.get(Workspace, b_workspace) is not None
            nested.commit()

            # The identity map was emptied when the savepoint ended.
            assert session.identity_map.keys() == set()
            # PostgreSQL keeps the switch: a released savepoint does not restore SET LOCAL.
            assert db_engine.current_tenant_context(session) == tenant_b
            # And every read now genuinely reflects that context rather than a cache.
            assert session.get(Workspace, a_workspace) is None
    finally:
        session.close()


def test_an_exception_unwinding_through_a_savepoint_clears_the_identity_map(
    application_engine, tenant_a, tenant_b
):
    """The exceptional path: no explicit rollback call, the context manager unwinds."""
    b_workspace = _make_workspace(application_engine, tenant_b, "savepoint-exc-b", "SE B")

    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.set_tenant_context(session, tenant_a)
            try:
                with session.begin_nested():
                    session.execute(
                        text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant_b)}
                    )
                    assert session.get(Workspace, b_workspace) is not None
                    raise RuntimeError("deliberate failure inside a savepoint")
            except RuntimeError:
                pass

            # An exception unwinds the savepoint by rollback, so the context is restored
            # and the cache is empty.
            assert db_engine.current_tenant_context(session) == tenant_a
            assert session.get(Workspace, b_workspace) is None
    finally:
        session.close()


def test_the_outer_tenant_context_still_works_after_a_savepoint(application_engine, tenant_a):
    """The prohibition must not break ordinary savepoint use within one tenant."""
    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.set_tenant_context(session, tenant_a)
            repo = WorkspaceRepository(session)
            with session.begin_nested():
                repo.create(slug="savepoint-inner", name="Savepoint Inner")
            assert db_engine.current_tenant_context(session) == tenant_a
            assert any(w.slug == "savepoint-inner" for w in repo.list())
    finally:
        session.close()
