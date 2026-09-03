"""The minimum persistence API needed to exercise the isolation boundary.

Two repositories and nothing else. No HTTP, no accounts, no memberships, no credentials,
no jobs, no idempotency, no outbox, no audit -- those are M2.2, M2.3 and later, and
building them here would be the opportunistic later-milestone work the working contract
forbids.

The split between them *is* the privilege split:

* :class:`TenantRepository` runs on the provisioning connection. Creating tenant X still
  requires the context of tenant X, so the ``WITH CHECK`` on ``tenants`` holds even for
  the privileged path -- a provisioning bug cannot write a row into another scope.
* :class:`WorkspaceRepository` runs on the restricted application connection inside a
  tenant transaction. It writes no ``WHERE tenant_id = ...`` anywhere, on purpose:
  every query below is scoped by PostgreSQL, and a reader can check that claim by
  noticing there is no filter to get wrong.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from .engine import current_tenant_context, set_tenant_context
from .models import Tenant, Workspace


class TenantContextMismatch(RuntimeError):
    """Raised when a caller asks for a write outside the transaction's tenant context."""


@dataclass(frozen=True)
class TenantRepository:
    """Privileged tenant provisioning. Runs on the provisioning role, not the app role."""

    session: Session

    def create(self, *, slug: str, name: str, tenant_id: uuid.UUID | None = None) -> Tenant:
        """Create a tenant and set the transaction context to it.

        The context is set here because the isolation policy on ``tenants`` is
        ``id = app_current_tenant_id()``: a tenant row is visible to exactly the tenant
        it is, so inserting one means asserting that identity for the transaction. That
        self-reference is what lets provisioning stay under RLS instead of needing an
        exemption.
        """
        tenant_id = tenant_id or uuid.uuid4()
        set_tenant_context(self.session, tenant_id)
        tenant = Tenant(id=tenant_id, slug=slug, name=name)
        self.session.add(tenant)
        self.session.flush()
        return tenant

    def get(self, tenant_id: uuid.UUID) -> Tenant | None:
        """Fetch a tenant. Returns ``None`` for any tenant the context is not."""
        return self.session.get(Tenant, tenant_id)

    def visible(self) -> list[Tenant]:
        """Every tenant row this transaction can see -- at most one, by policy."""
        return list(self.session.scalars(select(Tenant).order_by(Tenant.created_at)))


@dataclass(frozen=True)
class WorkspaceRepository:
    """Tenant-scoped workspace access. Runs on the restricted application role."""

    session: Session

    def _tenant_id(self) -> uuid.UUID:
        tenant_id = current_tenant_context(self.session)
        if tenant_id is None:
            raise TenantContextMismatch(
                "no tenant context is set on this transaction. The database would reject the write "
                "anyway; failing here says why."
            )
        return tenant_id

    def create(self, *, slug: str, name: str, tenant_id: uuid.UUID | None = None) -> Workspace:
        """Create a workspace in the transaction's tenant.

        ``tenant_id`` exists only so a caller can *try* to write across tenants and be
        refused; the check below refuses in Python and the ``WITH CHECK`` policy refuses
        in PostgreSQL. Two layers, and the database is the one that counts.
        """
        context_tenant = self._tenant_id()
        if tenant_id is not None and tenant_id != context_tenant:
            raise TenantContextMismatch(
                f"refusing to write a row owned by {tenant_id} inside the context of {context_tenant}"
            )
        workspace = Workspace(tenant_id=context_tenant, slug=slug, name=name)
        self.session.add(workspace)
        self.session.flush()
        return workspace

    def get(self, workspace_id: uuid.UUID) -> Workspace | None:
        """Fetch a workspace by id. Another tenant's id returns ``None``, not an error."""
        return self.session.get(Workspace, workspace_id)

    def get_by_slug(self, slug: str) -> Workspace | None:
        return self.session.scalars(select(Workspace).where(Workspace.slug == slug)).one_or_none()

    def list(self) -> list[Workspace]:
        """Every workspace visible to this transaction. No tenant filter: RLS is the filter."""
        return list(self.session.scalars(select(Workspace).order_by(Workspace.created_at, Workspace.slug)))
