"""Database-enforced tenant isolation.

Every test here runs as the restricted application role against real PostgreSQL, and
none of the queries under test carry a ``WHERE tenant_id = ...`` clause. That is the
point: if isolation depended on the repository remembering to filter, these tests would
pass while the property they claim was one forgotten clause away from being false.

Covers, in order: fail-closed without context; A sees itself and not B; A cannot insert,
update or delete into B; fabricated cross-tenant and dangling foreign keys; context is
transaction-local and does not survive the connection pool; tenant-local uniqueness.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError

from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.models import Tenant, Workspace
from firmbatch.control_plane.db.repositories import TenantContextMismatch, WorkspaceRepository


def _make_workspace(engine, tenant_id, slug, name=None):
    with db_engine.tenant_transaction(engine, tenant_id) as session:
        workspace = WorkspaceRepository(session).create(slug=slug, name=name or slug.replace("-", " "))
        return workspace.id


# --------------------------------------------------------------------------- fail closed


def test_without_tenant_context_no_tenant_rows_are_readable(application_engine, tenant_a):
    with db_engine.transaction(application_engine) as session:
        assert db_engine.current_tenant_context(session) is None
        assert session.scalars(select(Tenant)).all() == []
        assert session.scalars(select(Workspace)).all() == []


def test_without_tenant_context_a_write_is_rejected(application_engine, tenant_a):
    with pytest.raises(DBAPIError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(
                text(f"INSERT INTO {SCHEMA}.workspaces (tenant_id, slug, name) VALUES (:t, 'orphan', 'orphan')"),
                {"t": tenant_a},
            )
    assert "row-level security" in str(exc.value).lower()


def test_the_repository_also_refuses_without_context(application_engine):
    """Two layers. The database is the one that counts; this one says why."""
    with db_engine.transaction(application_engine) as session:
        with pytest.raises(TenantContextMismatch):
            WorkspaceRepository(session).create(slug="nope", name="nope")


def test_setting_context_outside_a_transaction_is_refused(application_engine):
    """``SET LOCAL`` outside a transaction lasts one statement, then silently vanishes."""
    from sqlalchemy.orm import Session

    session = Session(bind=application_engine)
    try:
        with pytest.raises(db_engine.TenantContextError):
            db_engine.set_tenant_context(session, uuid.uuid4())
    finally:
        session.close()


# --------------------------------------------------------------------------- read isolation


def test_tenant_sees_its_own_tenant_row_and_no_other(application_engine, tenant_a, tenant_b):
    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        visible = session.scalars(select(Tenant.id)).all()
    assert visible == [tenant_a]
    assert tenant_b not in visible


def test_tenant_a_cannot_read_tenant_b_workspaces(application_engine, tenant_a, tenant_b):
    a_workspace = _make_workspace(application_engine, tenant_a, "alpha-ws")
    b_workspace = _make_workspace(application_engine, tenant_b, "beta-ws")

    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        repo = WorkspaceRepository(session)
        assert [w.id for w in repo.list()] == [a_workspace]
        assert repo.get(a_workspace) is not None
        # Another tenant's id is simply not there. Not an error -- a non-existent row.
        assert repo.get(b_workspace) is None
        assert repo.get_by_slug("beta-ws") is None


def test_neither_tenant_can_count_the_other(application_engine, tenant_a, tenant_b):
    _make_workspace(application_engine, tenant_b, "beta-only-1")
    _make_workspace(application_engine, tenant_b, "beta-only-2")
    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        assert session.scalar(select(text("count(*)")).select_from(Workspace)) == 0


# --------------------------------------------------------------------------- write isolation


def test_tenant_a_cannot_insert_a_row_owned_by_tenant_b(application_engine, tenant_a, tenant_b):
    with pytest.raises(DBAPIError) as exc:
        with db_engine.tenant_transaction(application_engine, tenant_a) as session:
            session.execute(
                text(f"INSERT INTO {SCHEMA}.workspaces (tenant_id, slug, name) VALUES (:t, 'stolen', 'stolen')"),
                {"t": tenant_b},
            )
    assert "row-level security" in str(exc.value).lower()


def test_the_repository_refuses_a_cross_tenant_write_before_the_database_does(
    application_engine, tenant_a, tenant_b
):
    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        with pytest.raises(TenantContextMismatch):
            WorkspaceRepository(session).create(slug="stolen", name="stolen", tenant_id=tenant_b)


def test_tenant_a_cannot_update_tenant_b_rows(application_engine, tenant_a, tenant_b):
    b_workspace = _make_workspace(application_engine, tenant_b, "beta-original", "Beta Original")

    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        result = session.execute(
            update(Workspace).where(Workspace.id == b_workspace).values(name="Renamed By A")
        )
        assert result.rowcount == 0

    with db_engine.tenant_transaction(application_engine, tenant_b) as session:
        assert WorkspaceRepository(session).get(b_workspace).name == "Beta Original"


def test_tenant_a_cannot_delete_tenant_b_rows(application_engine, tenant_a, tenant_b):
    b_workspace = _make_workspace(application_engine, tenant_b, "beta-keeper")

    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        assert session.execute(delete(Workspace).where(Workspace.id == b_workspace)).rowcount == 0

    with db_engine.tenant_transaction(application_engine, tenant_b) as session:
        assert WorkspaceRepository(session).get(b_workspace) is not None


def test_tenant_a_cannot_reassign_its_own_row_to_tenant_b(application_engine, tenant_a, tenant_b):
    """The WITH CHECK half of the policy: you may not write a row out of your own scope."""
    a_workspace = _make_workspace(application_engine, tenant_a, "alpha-escapee")
    with pytest.raises(DBAPIError) as exc:
        with db_engine.tenant_transaction(application_engine, tenant_a) as session:
            session.execute(update(Workspace).where(Workspace.id == a_workspace).values(tenant_id=tenant_b))
    assert "row-level security" in str(exc.value).lower()


# --------------------------------------------------------------------------- foreign keys


def test_a_workspace_cannot_reference_a_tenant_that_does_not_exist(application_engine):
    """A fabricated tenant id satisfies the policy and still fails on the foreign key."""
    fabricated = uuid.uuid4()
    with pytest.raises(IntegrityError) as exc:
        with db_engine.tenant_transaction(application_engine, fabricated) as session:
            session.execute(
                text(f"INSERT INTO {SCHEMA}.workspaces (tenant_id, slug, name) VALUES (:t, 'ghost', 'ghost')"),
                {"t": fabricated},
            )
    assert "foreign key" in str(exc.value).lower()


def test_a_cross_tenant_foreign_key_cannot_be_fabricated_through_the_orm(
    application_engine, tenant_a, tenant_b
):
    with pytest.raises(DBAPIError) as exc:
        with db_engine.tenant_transaction(application_engine, tenant_a) as session:
            session.add(Workspace(tenant_id=tenant_b, slug="forged", name="forged"))
            session.flush()
    assert "row-level security" in str(exc.value).lower()


# --------------------------------------------------------------------------- context lifetime


def test_tenant_context_does_not_survive_into_the_next_transaction(single_connection_engine, tenant_a):
    """One physical connection, two transactions. The second must start with no context."""
    engine = single_connection_engine
    _make_workspace(engine, tenant_a, "pooled-ws")

    with db_engine.tenant_transaction(engine, tenant_a) as session:
        assert db_engine.current_tenant_context(session) == tenant_a
        assert len(WorkspaceRepository(session).list()) == 1

    with db_engine.transaction(engine) as session:
        assert db_engine.current_tenant_context(session) is None
        assert WorkspaceRepository(session).list() == []


def test_tenant_context_does_not_leak_between_two_tenants_on_one_connection(
    single_connection_engine, tenant_a, tenant_b
):
    engine = single_connection_engine
    _make_workspace(engine, tenant_a, "a-one")
    _make_workspace(engine, tenant_b, "b-one")

    with db_engine.tenant_transaction(engine, tenant_a) as session:
        assert [w.slug for w in WorkspaceRepository(session).list()] == ["a-one"]
    with db_engine.tenant_transaction(engine, tenant_b) as session:
        assert [w.slug for w in WorkspaceRepository(session).list()] == ["b-one"]
    with db_engine.tenant_transaction(engine, tenant_a) as session:
        assert [w.slug for w in WorkspaceRepository(session).list()] == ["a-one"]


def test_tenant_context_does_not_survive_a_rolled_back_transaction(single_connection_engine, tenant_a):
    engine = single_connection_engine
    with pytest.raises(RuntimeError):
        with db_engine.tenant_transaction(engine, tenant_a) as session:
            assert db_engine.current_tenant_context(session) == tenant_a
            raise RuntimeError("deliberate failure inside a tenant transaction")

    with db_engine.transaction(engine) as session:
        assert db_engine.current_tenant_context(session) is None


def test_context_can_be_cleared_within_a_transaction(application_engine, tenant_a):
    _make_workspace(application_engine, tenant_a, "clearable")
    with db_engine.tenant_transaction(application_engine, tenant_a) as session:
        assert WorkspaceRepository(session).list() != []
        db_engine.clear_tenant_context(session)
        assert db_engine.current_tenant_context(session) is None
        assert WorkspaceRepository(session).list() == []


def test_a_non_uuid_tenant_context_is_refused_before_it_reaches_the_database(application_engine):
    with pytest.raises(db_engine.TenantContextError):
        with db_engine.tenant_transaction(application_engine, "not-a-uuid"):
            pass


# --------------------------------------------------------------------------- uniqueness


def test_two_tenants_may_use_the_same_workspace_slug(application_engine, tenant_a, tenant_b):
    """Tenant-local uniqueness: the same name in two tenants is not a collision."""
    a_id = _make_workspace(application_engine, tenant_a, "production", "Production")
    b_id = _make_workspace(application_engine, tenant_b, "production", "Production")
    assert a_id != b_id


def test_a_duplicate_slug_within_one_tenant_is_rejected(application_engine, tenant_a):
    _make_workspace(application_engine, tenant_a, "duplicate-slug", "First")
    with pytest.raises(IntegrityError) as exc:
        _make_workspace(application_engine, tenant_a, "duplicate-slug", "Second")
    assert "uq_workspaces_tenant_id_slug" in str(exc.value)


def test_a_duplicate_name_within_one_tenant_is_rejected(application_engine, tenant_a):
    _make_workspace(application_engine, tenant_a, "name-one", "Shared Name")
    with pytest.raises(IntegrityError) as exc:
        _make_workspace(application_engine, tenant_a, "name-two", "Shared Name")
    assert "uq_workspaces_tenant_id_name" in str(exc.value)


def test_tenant_slugs_are_globally_unique(provisioning_engine, tenant_a):
    """Tenants are the outermost scope, so their slugs have nowhere to be local to."""
    from firmbatch.control_plane.db.repositories import TenantRepository

    slug = f"collide-{uuid.uuid4().hex[:10]}"
    with db_engine.transaction(provisioning_engine) as session:
        TenantRepository(session).create(slug=slug, name="First")
    with pytest.raises(IntegrityError) as exc:
        with db_engine.transaction(provisioning_engine) as session:
            TenantRepository(session).create(slug=slug, name="Second")
    assert "uq_tenants_slug" in str(exc.value)


def test_malformed_slugs_are_rejected_by_the_database(application_engine, tenant_a):
    for bad in ("Has Capitals", "trailing-", "-leading", "under_score"):
        with pytest.raises(IntegrityError) as exc:
            _make_workspace(application_engine, tenant_a, bad, f"name for {bad}")
        assert "ck_workspaces_slug_format" in str(exc.value)
