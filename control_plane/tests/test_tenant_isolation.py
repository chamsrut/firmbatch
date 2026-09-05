"""Database-enforced tenant isolation, under the authenticated context of Milestone 2.3.

Every test here runs as the restricted application role against real PostgreSQL, and none
of the queries under test carry a ``WHERE tenant_id = ...`` clause. That is the point: if
isolation depended on the repository remembering to filter, these tests would pass while
the property they claim was one forgotten clause away from being false.

What changed at Milestone 2.3 is where the context comes from. A transaction no longer
*chooses* its tenant; it presents a credential and is *told* which tenant it got. The
properties asserted below are the same ones Milestone 2.1 established -- they are simply
now established on a mechanism a compromised runtime cannot drive. The adversarial half
lives in ``test_authenticated_context.py``.

Covers, in order: fail-closed without a context; A sees itself and not B; A cannot insert,
update or delete into B; a cross-tenant foreign key cannot be fabricated; context is
transaction-local and does not survive the connection pool; tenant-local uniqueness.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError

from firmbatch.control_plane.db import auth
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.models import Tenant, Workspace
from firmbatch.control_plane.db.repositories import TenantContextMismatch, WorkspaceRepository


def _make_workspace(engine, principal, slug, name=None):
    with auth.authenticated_transaction(engine, principal.credential) as session:
        workspace = WorkspaceRepository(session).create(slug=slug, name=name or slug.replace("-", " "))
        return workspace.id


# --------------------------------------------------------------------------- fail closed


def test_without_a_context_no_tenant_rows_are_readable(application_engine, principal_a):
    with db_engine.transaction(application_engine) as session:
        assert db_engine.current_tenant_context(session) is None
        assert session.scalars(select(Tenant)).all() == []
        assert session.scalars(select(Workspace)).all() == []


def test_without_a_context_a_write_is_rejected(application_engine, tenant_a):
    with pytest.raises(DBAPIError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(
                text(f"INSERT INTO {SCHEMA}.workspaces (tenant_id, slug, name) VALUES (:t, 'orphan', 'orphan')"),
                {"t": tenant_a},
            )
    assert "row-level security" in str(exc.value).lower()


def test_the_repository_also_refuses_without_a_context(application_engine):
    """Two layers. The database is the one that counts; this one says why."""
    with db_engine.transaction(application_engine) as session:
        with pytest.raises(TenantContextMismatch):
            WorkspaceRepository(session).create(slug="nope", name="nope")


def test_binding_outside_a_transaction_is_refused(application_engine, principal_a):
    """The context is transaction-local, so outside one there is nothing for it to belong to."""
    from sqlalchemy.orm import Session

    session = Session(bind=application_engine)
    try:
        with pytest.raises(auth.AuthenticationError):
            auth.bind_authenticated_context(session, principal_a.credential)
    finally:
        session.close()


# --------------------------------------------------------------------------- read isolation


def test_tenant_sees_its_own_tenant_row_and_no_other(application_engine, principal_a, tenant_a, tenant_b):
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        visible = session.scalars(select(Tenant.id)).all()
    assert visible == [tenant_a]
    assert tenant_b not in visible


def test_tenant_a_cannot_read_tenant_b_workspaces(application_engine, principal_a, principal_b):
    a_workspace = _make_workspace(application_engine, principal_a, "alpha-ws")
    b_workspace = _make_workspace(application_engine, principal_b, "beta-ws")

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        repo = WorkspaceRepository(session)
        assert [w.id for w in repo.list()] == [a_workspace]
        assert repo.get(a_workspace) is not None
        # Another tenant's id is simply not there. Not an error -- a non-existent row.
        assert repo.get(b_workspace) is None
        assert repo.get_by_slug("beta-ws") is None


def test_neither_tenant_can_count_the_other(application_engine, principal_a, principal_b):
    _make_workspace(application_engine, principal_b, "beta-only-1")
    _make_workspace(application_engine, principal_b, "beta-only-2")
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert session.scalar(select(text("count(*)")).select_from(Workspace)) == 0


# --------------------------------------------------------------------------- write isolation


def test_tenant_a_cannot_insert_a_row_owned_by_tenant_b(application_engine, principal_a, tenant_b):
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(f"INSERT INTO {SCHEMA}.workspaces (tenant_id, slug, name) VALUES (:t, 'stolen', 'stolen')"),
                {"t": tenant_b},
            )
    assert "row-level security" in str(exc.value).lower()


def test_the_repository_offers_no_way_to_name_another_tenant(application_engine, principal_a, tenant_b):
    """The cross-tenant argument is gone, which is a stronger property than refusing it.

    At Milestone 2.1 ``WorkspaceRepository.create`` took a ``tenant_id`` so that a caller
    could *try* to write across tenants and be refused in Python before PostgreSQL refused
    it too. That parameter is exactly the independently supplied identifier Milestone 2.3
    removes: the tenant is whatever the transaction authenticated as, and there is nothing
    for it to disagree with.
    """
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        with pytest.raises(TypeError):
            WorkspaceRepository(session).create(slug="stolen", name="stolen", tenant_id=tenant_b)


def test_tenant_a_cannot_update_tenant_b_rows(application_engine, principal_a, principal_b):
    b_workspace = _make_workspace(application_engine, principal_b, "beta-original", "Beta Original")

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        result = session.execute(
            update(Workspace).where(Workspace.id == b_workspace).values(name="Renamed By A")
        )
        assert result.rowcount == 0

    with auth.authenticated_transaction(application_engine, principal_b.credential) as session:
        assert WorkspaceRepository(session).get(b_workspace).name == "Beta Original"


def test_tenant_a_cannot_delete_tenant_b_rows(application_engine, principal_a, principal_b):
    b_workspace = _make_workspace(application_engine, principal_b, "beta-keeper")

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert session.execute(delete(Workspace).where(Workspace.id == b_workspace)).rowcount == 0

    with auth.authenticated_transaction(application_engine, principal_b.credential) as session:
        assert WorkspaceRepository(session).get(b_workspace) is not None


def test_tenant_a_cannot_reassign_its_own_row_to_tenant_b(application_engine, principal_a, tenant_b):
    """The WITH CHECK half of the policy: you may not write a row out of your own scope."""
    a_workspace = _make_workspace(application_engine, principal_a, "alpha-escapee")
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(update(Workspace).where(Workspace.id == a_workspace).values(tenant_id=tenant_b))
    assert "row-level security" in str(exc.value).lower()


# --------------------------------------------------------------------------- foreign keys


def test_a_cross_tenant_foreign_key_cannot_be_fabricated_through_the_orm(
    application_engine, principal_a, tenant_b
):
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.add(Workspace(tenant_id=tenant_b, slug="forged", name="forged"))
            session.flush()
    assert "row-level security" in str(exc.value).lower()


def test_a_workspace_cannot_be_written_for_a_tenant_that_does_not_exist(application_engine, principal_a):
    """A fabricated tenant id is refused by the policy long before the foreign key.

    At Milestone 2.1 this test set the context to a made-up UUID and watched the foreign
    key catch it -- the policy could not, because the policy compared the row against the
    very value the caller had invented. There is no longer any way to make that value the
    context, so the row is refused for the right reason.
    """
    fabricated = uuid.uuid4()
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(f"INSERT INTO {SCHEMA}.workspaces (tenant_id, slug, name) VALUES (:t, 'ghost', 'ghost')"),
                {"t": fabricated},
            )
    assert "row-level security" in str(exc.value).lower()


# --------------------------------------------------------------------------- context lifetime


def test_a_context_does_not_survive_into_the_next_transaction(single_connection_engine, principal_a):
    """One physical connection, two transactions. The second must start with no context."""
    engine = single_connection_engine
    _make_workspace(engine, principal_a, "pooled-ws")

    with auth.authenticated_transaction(engine, principal_a.credential) as session:
        assert db_engine.current_tenant_context(session) == principal_a.id
        assert len(WorkspaceRepository(session).list()) == 1

    with db_engine.transaction(engine) as session:
        assert db_engine.current_tenant_context(session) is None
        assert WorkspaceRepository(session).list() == []


def test_a_context_does_not_leak_between_two_tenants_on_one_connection(
    single_connection_engine, principal_a, principal_b
):
    engine = single_connection_engine
    _make_workspace(engine, principal_a, "a-one")
    _make_workspace(engine, principal_b, "b-one")

    with auth.authenticated_transaction(engine, principal_a.credential) as session:
        assert [w.slug for w in WorkspaceRepository(session).list()] == ["a-one"]
    with auth.authenticated_transaction(engine, principal_b.credential) as session:
        assert [w.slug for w in WorkspaceRepository(session).list()] == ["b-one"]
    with auth.authenticated_transaction(engine, principal_a.credential) as session:
        assert [w.slug for w in WorkspaceRepository(session).list()] == ["a-one"]


def test_a_context_does_not_survive_a_rolled_back_transaction(single_connection_engine, principal_a):
    engine = single_connection_engine
    with pytest.raises(RuntimeError):
        with auth.authenticated_transaction(engine, principal_a.credential) as session:
            assert db_engine.current_tenant_context(session) == principal_a.id
            raise RuntimeError("deliberate failure inside an authenticated transaction")

    with db_engine.transaction(engine) as session:
        assert db_engine.current_tenant_context(session) is None


def test_a_context_cannot_be_dropped_within_a_transaction(application_engine, principal_a):
    """There is no clearing operation, and that absence is a security property.

    Milestone 2.3 shipped one at first -- ``reset_auth_context`` -- on the reasoning that
    clearing only ever removes authority. It does, taken alone. Taken with
    ``bind_authenticated_context`` it is a way to *abandon one identity and take another
    inside the same transaction*, which is the property the primary key on the context row
    exists to prevent. So the function is gone, and this test is what stops it coming back.
    """
    _make_workspace(application_engine, principal_a, "clearable")
    assert not hasattr(db_engine, "reset_auth_context")
    assert not hasattr(db_engine, "clear_tenant_context")
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert WorkspaceRepository(session).list() != []
        # And the database offers none either: the function that used to do it is not
        # there, and every other route is a privilege the runtime does not hold.
        # ``test_authenticated_context.py`` enumerates those routes; this is the Python
        # half of the same property.
        with pytest.raises(DBAPIError) as exc:
            session.execute(text(f"SELECT {SCHEMA}.auth_context_reset()"))
        assert "does not exist" in str(exc.value).lower()


def test_a_malformed_credential_never_reaches_the_database(application_engine):
    """Refused in Python, so a typo cannot end up in a statement log."""
    for bad in ("", "not-a-credential", "fbk_short", "fbk_" + "x" * 44, None, 12345):
        with pytest.raises(auth.AuthenticationError):
            with auth.authenticated_transaction(application_engine, bad):
                pass


# --------------------------------------------------------------------------- uniqueness


def test_two_tenants_may_use_the_same_workspace_slug(application_engine, principal_a, principal_b):
    """Tenant-local uniqueness: the same name in two tenants is not a collision."""
    a_id = _make_workspace(application_engine, principal_a, "production", "Production")
    b_id = _make_workspace(application_engine, principal_b, "production", "Production")
    assert a_id != b_id


def test_a_duplicate_slug_within_one_tenant_is_rejected(application_engine, principal_a):
    _make_workspace(application_engine, principal_a, "duplicate-slug", "First")
    with pytest.raises(IntegrityError) as exc:
        _make_workspace(application_engine, principal_a, "duplicate-slug", "Second")
    assert "uq_workspaces_tenant_id_slug" in str(exc.value)


def test_a_duplicate_name_within_one_tenant_is_rejected(application_engine, principal_a):
    _make_workspace(application_engine, principal_a, "name-one", "Shared Name")
    with pytest.raises(IntegrityError) as exc:
        _make_workspace(application_engine, principal_a, "name-two", "Shared Name")
    assert "uq_workspaces_tenant_id_name" in str(exc.value)


def test_tenant_slugs_are_globally_unique(provisioning_engine):
    """Tenants are the outermost scope, so their slugs have nowhere to be local to."""
    from firmbatch.control_plane.db.repositories import TenantRepository

    slug = f"collide-{uuid.uuid4().hex[:10]}"
    with auth.provisioning_transaction(provisioning_engine) as session:
        TenantRepository(session).create(slug=slug, name="First")
    with pytest.raises(IntegrityError) as exc:
        with auth.provisioning_transaction(provisioning_engine) as session:
            TenantRepository(session).create(slug=slug, name="Second")
    assert "uq_tenants_slug" in str(exc.value)


def test_malformed_slugs_are_rejected_by_the_database(application_engine, principal_a):
    for bad in ("Has Capitals", "trailing-", "-leading", "under_score"):
        with pytest.raises(IntegrityError) as exc:
            _make_workspace(application_engine, principal_a, bad, f"name for {bad}")
        assert "ck_workspaces_slug_format" in str(exc.value)
