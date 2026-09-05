"""Deny-by-default authorization: what each scope buys, and what nothing buys.

``test_authenticated_context.py`` asserts that a transaction cannot choose *which tenant*
it is. This module asserts the other half: given a tenant, what a credential may do inside
it is exactly what its scopes say, and a capability that was not granted is refused.

Three places have to agree about that, and a test here checks each of them:

* the catalogue in ``security/authorization.py`` -- the names, and the rule per table;
* the check constraint on ``auth_bindings.scopes`` -- so an unknown capability cannot be
  stored and later become meaningful when somebody adds a policy that reads it;
* the policies themselves -- which are what actually decides, and which the behavioural
  tests below exercise from the restricted application role against real PostgreSQL.

The negative space matters as much as the positive: a credential with **no** scopes is
authenticated and can do nothing, and there is no scope in the catalogue that names an
operator, supplier, provider, routing, settlement, certification or internal-control
capability. Customer authorization stops at the customer surface, and it stops there
because those capabilities do not exist here to be granted.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from firmbatch.control_plane.tests.conftest import exception_chain as _exception_chain
from firmbatch.control_plane.db import audit, auth
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.idempotency import (
    MutationOutcome,
    OutboxEventSpec,
    execute_idempotent_mutation,
)
from firmbatch.control_plane.db.models import PROTECTED_TABLES, TENANT_SCOPED_TABLES, Tenant, Workspace
from firmbatch.control_plane.db.repositories import WorkspaceRepository
from firmbatch.control_plane.security.authorization import (
    DELEGABLE_SCOPES,
    KNOWN_SCOPES,
    RESERVED_NON_CUSTOMER_DOMAINS,
    RESOURCE_RULES,
    RULES_BY_TABLE,
    AuthorizationError,
    Scope,
    require_scope,
    scope_values,
)

WRITE_SCOPES = (Scope.WORKSPACE_READ, Scope.WORKSPACE_WRITE)


# --------------------------------------------------------------------------- the catalogue


def test_every_tenant_owned_table_has_exactly_one_rule():
    """A table added without a rule fails here rather than inheriting somebody else's."""
    catalogued = {rule.table for rule in RESOURCE_RULES}
    assert catalogued == set(TENANT_SCOPED_TABLES) | set(PROTECTED_TABLES)
    assert len(catalogued) == len(RESOURCE_RULES), "a table appears twice in the catalogue"


def test_the_rules_agree_with_the_models_about_which_tables_are_which():
    for rule in RESOURCE_RULES:
        if rule.kind == "protected":
            assert rule.table in PROTECTED_TABLES
            assert rule.tenant_column is None
            assert rule.read is None and rule.write is None, (
                f"{rule.table} is protected, so there is no scope that reaches it"
            )
        else:
            assert rule.table in TENANT_SCOPED_TABLES
            assert rule.tenant_column == TENANT_SCOPED_TABLES[rule.table]
            assert rule.read is not None and rule.write is not None
        assert rule.note.strip(), f"{rule.table}: a rule without a reason is a rule nobody can review"


def test_the_database_and_the_catalogue_agree_on_the_scope_vocabulary(owner_engine):
    """The closed catalogue, read back from the check constraint that enforces it."""
    with owner_engine.connect() as connection:
        definition = connection.execute(
            text(
                "SELECT pg_get_constraintdef(con.oid) FROM pg_constraint con "
                "JOIN pg_class c ON c.oid = con.conrelid "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = :schema AND c.relname = 'auth_bindings' "
                "AND con.conname = 'ck_auth_bindings_scopes_known'"
            ),
            {"schema": SCHEMA},
        ).scalar_one()
    for scope in KNOWN_SCOPES:
        assert f"'{scope}'" in definition, f"{scope} is in the catalogue and not in the constraint"
    # And nothing the constraint allows is missing from the catalogue: every quoted
    # literal in the definition has to be a known scope.
    quoted = {part.split("'")[0] for part in definition.split("'")[1::2]}
    assert quoted <= set(KNOWN_SCOPES), quoted - set(KNOWN_SCOPES)


def test_no_scope_names_a_non_customer_capability():
    """Customer authorization never reaches the supplier, operator or internal surfaces.

    Enforced by absence rather than by a rule: there is no such scope, so no credential can
    carry one, and no policy would honour it if it did. This is what stops the customer
    product from quietly acquiring an operator console.
    """
    for scope in KNOWN_SCOPES:
        domain = scope.split(":", 1)[0]
        assert domain not in RESERVED_NON_CUSTOMER_DOMAINS, scope
        for reserved in RESERVED_NON_CUSTOMER_DOMAINS:
            assert reserved not in scope, scope


def test_an_unknown_scope_is_refused_before_it_can_be_requested():
    with pytest.raises(AuthorizationError) as exc:
        scope_values(["workspace:read", "operator:settle"])
    assert "closed" in str(exc.value)
    assert scope_values([Scope.WORKSPACE_READ, "workspace:read"]) == ("workspace:read",)


def test_require_scope_names_the_missing_capability(application_engine, principal_a):
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        context = auth.current_authenticated_context(session)
    require_scope(context, Scope.WORKSPACE_READ)
    with pytest.raises(AuthorizationError) as exc:
        require_scope(context, Scope.TENANT_PROVISION)
    assert "tenant:provision" in str(exc.value)
    with pytest.raises(AuthorizationError):
        require_scope(None, Scope.WORKSPACE_READ)


# --------------------------------------------------------------------- deny by default


def test_a_credential_with_no_scopes_reaches_nothing(application_engine, new_principal, issue_credential):
    """Authenticated and authorized for nothing. The default is no, everywhere."""
    owner = new_principal("no-scopes")
    with auth.authenticated_transaction(application_engine, owner.credential) as session:
        WorkspaceRepository(session).create(slug="visible-to-owner", name="Visible")
    powerless = issue_credential(owner, [])

    with auth.authenticated_transaction(application_engine, powerless.credential) as session:
        context = auth.current_authenticated_context(session)
        assert context.tenant_id == owner.id, "it is authenticated"
        assert context.scopes == frozenset(), "and authorized for nothing"
        assert session.scalars(select(Workspace)).all() == []
        assert session.scalars(select(Tenant)).all() == []
        assert session.scalar(select(func.count()).select_from(Workspace)) == 0

    with pytest.raises(DBAPIError):
        with auth.authenticated_transaction(application_engine, powerless.credential) as session:
            WorkspaceRepository(session).create(slug="denied", name="Denied")


# ------------------------------------------------------------- customer resource scopes


def test_a_read_only_credential_can_read_and_cannot_write(
    application_engine, new_principal, issue_credential
):
    owner = new_principal("read-only")
    with auth.authenticated_transaction(application_engine, owner.credential) as session:
        workspace_id = WorkspaceRepository(session).create(slug="readable", name="Readable").id

    reader = issue_credential(owner, [Scope.WORKSPACE_READ])

    with auth.authenticated_transaction(application_engine, reader.credential) as session:
        assert [w.id for w in WorkspaceRepository(session).list()] == [workspace_id]

    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, reader.credential) as session:
            WorkspaceRepository(session).create(slug="not-allowed", name="Not Allowed")
    assert "row-level security" in str(exc.value).lower()

    # UPDATE and DELETE have their own policies, and both take the write scope.
    with auth.authenticated_transaction(application_engine, reader.credential) as session:
        assert session.execute(
            update(Workspace).where(Workspace.id == workspace_id).values(name="Renamed")
        ).rowcount == 0
        assert session.execute(delete(Workspace).where(Workspace.id == workspace_id)).rowcount == 0

    with auth.authenticated_transaction(application_engine, owner.credential) as session:
        assert WorkspaceRepository(session).get(workspace_id).name == "Readable"


def test_a_write_credential_can_amend_and_remove(application_engine, new_principal, issue_credential):
    """The positive control for the same policies, so the test above is not passing on an
    accident of privilege rather than of scope."""
    owner = new_principal("read-write")
    writer = issue_credential(owner, WRITE_SCOPES)

    with auth.authenticated_transaction(application_engine, writer.credential) as session:
        workspace_id = WorkspaceRepository(session).create(slug="mutable", name="Mutable").id

    with auth.authenticated_transaction(application_engine, writer.credential) as session:
        assert session.execute(
            update(Workspace).where(Workspace.id == workspace_id).values(name="Renamed")
        ).rowcount == 1

    with auth.authenticated_transaction(application_engine, writer.credential) as session:
        assert session.execute(delete(Workspace).where(Workspace.id == workspace_id)).rowcount == 1
        assert WorkspaceRepository(session).list() == []


def test_a_write_only_credential_cannot_use_the_orm_to_insert(
    application_engine, new_principal, issue_credential
):
    """A PostgreSQL fact worth stating out loud rather than discovering in production.

    ``INSERT ... RETURNING`` applies the table's ``SELECT`` policies to the returned rows,
    and the ORM writes rows carrying server-side defaults with ``RETURNING``. So a
    credential holding ``workspace:write`` and **not** ``workspace:read`` can insert with a
    plain statement and cannot insert through the repository. That is the database
    behaving correctly, not a defect -- and it is why the ``tenants`` read rule includes
    the provisioning scope.
    """
    owner = new_principal("write-only")
    writer = issue_credential(owner, [Scope.WORKSPACE_WRITE])

    with auth.authenticated_transaction(application_engine, writer.credential) as session:
        session.execute(
            text(f"INSERT INTO {SCHEMA}.workspaces (tenant_id, slug, name) VALUES (:t, 'plain', 'Plain')"),
            {"t": owner.id},
        )

    with pytest.raises(DBAPIError):
        with auth.authenticated_transaction(application_engine, writer.credential) as session:
            WorkspaceRepository(session).create(slug="returning", name="Returning")

    with auth.authenticated_transaction(application_engine, owner.credential) as session:
        assert [w.slug for w in WorkspaceRepository(session).list()] == ["plain"]


def test_reading_the_tenant_row_takes_its_own_scope(application_engine, new_principal, issue_credential):
    owner = new_principal("tenant-scope")
    without = issue_credential(owner, [Scope.WORKSPACE_READ])
    with_read = issue_credential(owner, [Scope.TENANT_READ])

    with auth.authenticated_transaction(application_engine, without.credential) as session:
        assert session.scalars(select(Tenant)).all() == []
    with auth.authenticated_transaction(application_engine, with_read.credential) as session:
        assert [t.id for t in session.scalars(select(Tenant))] == [owner.id]


def test_tenant_provision_cannot_be_issued_to_a_credential_at_all(
    application_engine, new_principal, issue_credential
):
    """``tenant:provision`` is not a scope a customer credential is issued...

    ...and since the Milestone 2.3 correction that is enforced rather than merely true of
    the call sites: it is absent from :data:`DELEGABLE_SCOPES`, so
    ``firmbatch.register_auth_binding`` refuses to place it on any credential, whoever asks.
    Before that, a credential holding ``credential:manage`` could mint itself one carrying
    any scope in the catalogue.
    """
    owner = new_principal("no-provision")
    assert Scope.TENANT_PROVISION.value not in owner.scopes
    assert Scope.TENANT_PROVISION.value not in DELEGABLE_SCOPES

    with pytest.raises(AuthorizationError):
        issue_credential(owner, [Scope.TENANT_PROVISION, Scope.TENANT_READ])


def test_a_customer_credential_cannot_create_a_tenant(application_engine, new_principal):
    """And the privilege system says so too, independently of any scope.

    The second measure, which is what holds if the first is ever mis-issued: the
    application role holds no ``INSERT`` on ``tenants`` at all, so no context reachable
    through it can create one.
    """
    owner = new_principal("no-provision-2")
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, owner.credential) as session:
            session.execute(
                text(f"INSERT INTO {SCHEMA}.tenants (id, slug, name) VALUES (:i, 'sneaky', 'Sneaky')"),
                {"i": uuid.uuid4()},
            )
    assert "permission denied" in str(exc.value).lower()


# ------------------------------------------------------------------- framework tables


def test_the_framework_tables_take_the_minimal_framework_capability(
    application_engine, new_principal, issue_credential
):
    """``mutation:execute`` and nothing else: a claim says nothing about what was claimed."""
    owner = new_principal("framework")
    without = issue_credential(owner, WRITE_SCOPES)
    with_mutation = issue_credential(owner, WRITE_SCOPES + (Scope.MUTATION_EXECUTE,))

    def mutate(unit_of_work):
        workspace = WorkspaceRepository(unit_of_work).create(slug="framework-ws", name="Framework")
        return MutationOutcome(
            result={"workspace_id": workspace.id},
            event=OutboxEventSpec(
                event_type="workspace.created",
                aggregate_type="workspace",
                aggregate_id=workspace.id,
            ),
        )

    with pytest.raises(AuthorizationError) as exc:
        with auth.authenticated_transaction(application_engine, without.credential) as session:
            execute_idempotent_mutation(
                session,
                operation="workspace.create",
                idempotency_key=f"scoped-{uuid.uuid4().hex}",
                request_identity={"workspace_slug": "framework-ws"},
                mutate=mutate,
            )
    assert "mutation:execute" in str(exc.value)

    with auth.authenticated_transaction(application_engine, with_mutation.credential) as session:
        outcome = execute_idempotent_mutation(
            session,
            operation="workspace.create",
            idempotency_key=f"scoped-{uuid.uuid4().hex}",
            request_identity={"workspace_slug": "framework-ws"},
            mutate=mutate,
        )
    assert outcome.replayed is False

    # And the reads are scoped the same way.
    with auth.authenticated_transaction(application_engine, without.credential) as session:
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.idempotency_records")
        ).scalar() == 0
        assert session.execute(text(f"SELECT count(*) FROM {SCHEMA}.outbox_events")).scalar() == 0
    with auth.authenticated_transaction(application_engine, with_mutation.credential) as session:
        assert session.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.idempotency_records")
        ).scalar() == 1


def test_reading_the_audit_trail_takes_audit_read(application_engine, new_principal, issue_credential):
    owner = new_principal("audit-scope")
    blind = issue_credential(owner, [Scope.WORKSPACE_READ])
    sighted = issue_credential(owner, [Scope.AUDIT_READ])

    with auth.authenticated_transaction(application_engine, blind.credential) as session:
        audit.append_audit_event(
            session, audit.AuditEventSpec(action="workspace.viewed", resource_type="workspace")
        )
        # It can append and it cannot read back what it appended.
        assert audit.audit_events(session) == []

    with auth.authenticated_transaction(application_engine, sighted.credential) as session:
        actions = [e.action for e in audit.audit_events(session)]
    assert "workspace.viewed" in actions


def test_appending_to_the_audit_trail_needs_no_scope(application_engine, new_principal, issue_credential):
    """Deliberate, and the cost is named rather than hidden.

    An ``audit:append`` capability would make it possible to issue a credential that acts
    without leaving a trail, which is the one outcome an audit trail exists to prevent. The
    price is that a credential with no scopes at all can write audit rows in its own
    tenant -- bounded metadata, scoped to that tenant, and preferable to the alternative.
    """
    owner = new_principal("audit-append")
    powerless = issue_credential(owner, [])

    with auth.authenticated_transaction(application_engine, powerless.credential) as session:
        event_id = audit.append_audit_event(
            session, audit.AuditEventSpec(action="thing.attempted", resource_type="thing", outcome="denied")
        )
    assert event_id is not None

    with auth.authenticated_transaction(application_engine, owner.credential) as session:
        recorded = {e.id: e for e in audit.audit_events(session)}
    assert recorded[event_id].outcome == "denied"
    assert recorded[event_id].actor_binding_id == powerless.binding_id


# ------------------------------------------------------------- credential management


def test_managing_credentials_takes_credential_manage(
    application_engine, new_principal, issue_credential
):
    owner = new_principal("credential-scope")
    narrow = issue_credential(owner, [Scope.WORKSPACE_READ])

    with pytest.raises(AuthorizationError) as exc:
        with auth.authenticated_transaction(application_engine, narrow.credential) as session:
            auth.register_auth_binding(session, principal_id=uuid.uuid4(), scopes=[Scope.WORKSPACE_READ])
    assert "credential:manage" in str(exc.value)

    with pytest.raises(AuthorizationError):
        with auth.authenticated_transaction(application_engine, narrow.credential) as session:
            auth.revoke_auth_binding(session, narrow.binding_id)


def test_the_database_refuses_credential_management_without_the_scope(
    application_engine, new_principal, issue_credential
):
    """Around the Python check, straight at the function. Same answer.

    Note what the call does *not* pass: there is no credential argument any more. The value
    is minted inside the function and returned once, so a caller cannot submit a candidate
    -- which is what removed the cross-tenant existence oracle.
    """
    owner = new_principal("credential-db-scope")
    narrow = issue_credential(owner, [Scope.WORKSPACE_READ])

    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, narrow.credential) as session:
            session.execute(
                text(
                    f"SELECT * FROM {SCHEMA}.register_auth_binding("
                    ":p, ARRAY['workspace:read']::text[], NULL)"
                ),
                {"p": uuid.uuid4()},
            )
    assert "credential:manage" in str(exc.value)


def test_a_credential_cannot_be_minted_into_another_tenant(
    application_engine, new_principal, issue_credential
):
    """The tenant is not a parameter, so there is no wrong value to pass.

    A credential issued by tenant A's ``credential:manage`` lands in tenant A, whatever the
    caller had in mind -- and the test proves it by using the new credential and seeing
    where it arrives.
    """
    mine = new_principal("minting-mine")
    theirs = new_principal("minting-theirs")

    with auth.authenticated_transaction(application_engine, mine.credential) as session:
        issued = auth.register_auth_binding(
            session, principal_id=uuid.uuid4(), scopes=[Scope.TENANT_READ]
        )
    assert issued.tenant_id == mine.id

    with auth.authenticated_transaction(application_engine, issued.credential) as session:
        context = auth.current_authenticated_context(session)
        assert context.tenant_id == mine.id
        assert context.tenant_id != theirs.id
        assert [t.id for t in session.scalars(select(Tenant))] == [mine.id]


def test_scopes_are_stored_sorted_and_deduplicated(application_engine, new_principal):
    """Two credentials with the same capability should not differ by typing order."""
    owner = new_principal("scope-order")
    with auth.authenticated_transaction(application_engine, owner.credential) as session:
        issued = auth.register_auth_binding(
            session,
            principal_id=uuid.uuid4(),
            scopes=[Scope.WORKSPACE_WRITE, Scope.AUDIT_READ, Scope.WORKSPACE_WRITE],
        )
    assert issued.scopes == ("audit:read", "workspace:write")

    with auth.authenticated_transaction(application_engine, issued.credential) as session:
        assert auth.current_authenticated_context(session).scopes == {"audit:read", "workspace:write"}


def test_a_scope_held_in_one_tenant_means_nothing_in_another(
    application_engine, new_principal, issue_credential
):
    """Scopes are carried by a binding, and a binding belongs to exactly one tenant."""
    mine = new_principal("scope-mine")
    theirs = new_principal("scope-theirs")
    with auth.authenticated_transaction(application_engine, theirs.credential) as session:
        victim = WorkspaceRepository(session).create(slug="theirs", name="Theirs").id

    powerful = issue_credential(mine, [Scope.WORKSPACE_READ, Scope.WORKSPACE_WRITE, Scope.AUDIT_READ])
    with auth.authenticated_transaction(application_engine, powerful.credential) as session:
        assert session.get(Workspace, victim) is None
        assert audit.audit_events(session) == [] or all(
            e.tenant_id == mine.id for e in audit.audit_events(session)
        )


# ------------------------------------------------------------------- protected state


def test_no_scope_reaches_the_protected_registry(application_engine, new_principal):
    """There is no scope that grants access to ``auth_bindings``, by construction.

    It is protected by having no grants rather than policed by having a policy, so the
    question "which scope reads it" has no answer -- and the catalogue says so.
    """
    for table in PROTECTED_TABLES:
        rule = RULES_BY_TABLE[table]
        assert rule.read is None and rule.write is None

    owner = new_principal("all-scopes", scopes=[Scope(value) for value in DELEGABLE_SCOPES])
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, owner.credential) as session:
            session.execute(text(f"SELECT count(*) FROM {SCHEMA}.auth_bindings"))
    assert "permission denied" in str(exc.value).lower()


def test_holding_every_scope_still_reaches_only_one_tenant(
    application_engine, new_principal
):
    """The final control: authorization is inside the tenant, never across it."""
    # Every scope a credential can be issued. ``tenant:provision`` is excluded because it
    # cannot be issued to one at all -- see
    # test_tenant_provision_cannot_be_issued_to_a_credential_at_all.
    everything = new_principal("everything", scopes=[Scope(value) for value in DELEGABLE_SCOPES])
    other = new_principal("bystander")
    with auth.authenticated_transaction(application_engine, other.credential) as session:
        victim = WorkspaceRepository(session).create(slug="bystander-ws", name="Bystander").id

    with auth.authenticated_transaction(application_engine, everything.credential) as session:
        assert session.get(Workspace, victim) is None
        assert [t.id for t in session.scalars(select(Tenant))] == [everything.id]


def test_an_unauthenticated_session_holds_no_scope(application_engine):
    session_scopes = []
    with db_engine.transaction(application_engine) as session:
        assert auth.current_authenticated_context(session) is None
        for scope in KNOWN_SCOPES:
            session_scopes.append(
                session.execute(
                    text(f"SELECT {SCHEMA}.auth_has_scope(:s)"), {"s": scope}
                ).scalar()
            )
    assert session_scopes == [False] * len(KNOWN_SCOPES)


def test_the_scope_check_is_false_rather_than_null_without_a_context(application_engine):
    """NULL in a policy predicate is not false -- it is "unknown", and combines differently.

    ``auth_has_scope`` coalesces, so an unbound transaction gets ``false`` and every
    predicate that mentions it is decidably false. A NULL here would still fail closed for
    ``AND``, and would be one refactor away from not doing so.
    """
    with db_engine.transaction(application_engine) as session:
        value = session.execute(
            text(f"SELECT {SCHEMA}.auth_has_scope('workspace:read')")
        ).scalar()
    assert value is False and value is not None


def test_a_session_bound_by_hand_still_gets_the_catalogue_it_was_issued(
    application_engine, new_principal, issue_credential
):
    """The context reports the scopes stored on the binding, not the ones asked for."""
    owner = new_principal("hand-bound")
    narrow = issue_credential(owner, [Scope.AUDIT_READ])

    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            context = auth.bind_authenticated_context(session, narrow.credential)
            assert context.scopes == {"audit:read"}
            assert context.has_scope(Scope.AUDIT_READ)
            assert not context.has_scope(Scope.WORKSPACE_WRITE)
    finally:
        session.close()


# ------------------------------------------------------------------ scope delegation
#
# ``credential:manage`` authorises *creating* a credential. Until this correction it also
# decided what that credential could do: ``register_auth_binding`` accepted any scope in
# the catalogue, so a leaked credential holding nothing but ``credential:manage`` could
# mint itself a successor holding ``workspace:write`` and ``audit:read`` -- privilege
# escalation inside the tenant, performed entirely through the supported interface.
#
# Two rules, both enforced in PostgreSQL because that is the only place they hold under
# arbitrary runtime SQL, and mirrored in Python so a caller gets the rule by name:
#
# 1. every requested scope must be **delegable**;
# 2. a **credential** issuer may grant only scopes it holds itself.
#
# The provisioning actor is exempt from (2) and only from (2). It has no credential to
# inherit from, and the tenant it is acting in was generated inside the same transaction
# by ``begin_tenant_provisioning()``, so it cannot reach an existing one. Bootstrapping a
# tenant's first credential has to come from somewhere.


def _raw_register(engine, credential, scopes: str):
    """Call the database function directly, bypassing every Python check.

    ``scopes`` is a PostgreSQL array literal, so this can express things ``scope_values``
    would normalise away -- duplicates, in particular.
    """
    with auth.authenticated_transaction(engine, credential) as session:
        return session.execute(
            text(
                f"SELECT * FROM {SCHEMA}.register_auth_binding("
                ":p, CAST(:s AS text[]), NULL)"
            ),
            {"p": uuid.uuid4(), "s": scopes},
        ).one()


def test_an_exact_subset_is_delegable(application_engine, new_principal, issue_credential):
    """The ordinary case, and the one a rotation depends on."""
    issuer = new_principal("subset")
    issued = issue_credential(issuer, [Scope.WORKSPACE_READ, Scope.AUDIT_READ])
    assert issued.scopes == ("audit:read", "workspace:read")
    assert set(issued.scopes) < set(issuer.scopes)


def test_the_whole_scope_set_is_delegable(application_engine, new_principal, issue_credential):
    """A subset includes the improper one: rotation must be able to reproduce a credential."""
    issuer = new_principal("whole")
    issued = issue_credential(issuer, [Scope(value) for value in issuer.scopes])
    assert issued.scopes == issuer.scopes


def test_credential_manage_may_be_delegated(application_engine, new_principal, issue_credential):
    """Decided, and decided in favour, because the subset rule already bounds it.

    Delegating ``credential:manage`` grants nothing the issuer does not already hold, it is
    confined to the issuer's own tenant -- the database derives the tenant from the context
    -- and refusing it would only mean credential rotation could not itself be delegated.
    There is deliberately no administrator wildcard anywhere in this catalogue: no scope,
    and no value of any scope, means "all".
    """
    issuer = new_principal("self-delegating")
    issued = issue_credential(issuer, [Scope.CREDENTIAL_MANAGE])
    assert issued.scopes == ("credential:manage",)

    # And the delegate can delegate in turn -- still only within the subset rule.
    onward = issue_credential(issued, [Scope.CREDENTIAL_MANAGE])
    assert onward.scopes == ("credential:manage",)
    with pytest.raises(AuthorizationError):
        issue_credential(issued, [Scope.WORKSPACE_READ])


def test_a_management_only_credential_cannot_mint_a_permission(
    application_engine, new_principal, issue_credential
):
    """The escalation this rule exists to stop, in both enforcement points."""
    issuer = new_principal("manager", scopes=[Scope.CREDENTIAL_MANAGE])
    manager = issue_credential(issuer, [Scope.CREDENTIAL_MANAGE])
    assert manager.scopes == ("credential:manage",)

    for scope in (Scope.WORKSPACE_WRITE, Scope.WORKSPACE_READ, Scope.AUDIT_READ, Scope.MUTATION_EXECUTE):
        with pytest.raises(AuthorizationError):
            issue_credential(manager, [scope])

    # And with Python out of the way entirely.
    with pytest.raises(DBAPIError) as exc:
        _raw_register(application_engine, manager.credential, "{workspace:write}")
    assert "does not hold" in str(exc.value.orig)


def test_an_attempted_superset_is_refused_scope_by_scope(
    application_engine, new_principal, issue_credential
):
    """Partly-held is not held: one ungranted scope refuses the whole request."""
    issuer = new_principal("partial", scopes=[Scope.CREDENTIAL_MANAGE, Scope.WORKSPACE_READ])
    holder = issue_credential(issuer, [Scope.CREDENTIAL_MANAGE, Scope.WORKSPACE_READ])
    with pytest.raises(AuthorizationError):
        issue_credential(holder, [Scope.WORKSPACE_READ, Scope.WORKSPACE_WRITE])
    # And nothing partial was minted.
    assert issue_credential(holder, [Scope.WORKSPACE_READ]).scopes == ("workspace:read",)


def test_an_empty_scope_set_is_permitted(new_principal, issue_credential):
    """A credential with no capability at all is a legitimate thing to issue.

    It can authenticate and it can append to its own tenant's audit trail, which is
    deliberate (see AUDIT_APPEND_REQUIRES_NO_SCOPE) and is the whole of what it can do.
    """
    issuer = new_principal("empty")
    assert issue_credential(issuer, []).scopes == ()


def test_duplicate_scopes_are_refused_by_the_database(application_engine, principal_a):
    """Python normalises a repeat away; the database refuses it.

    The two are not in conflict -- ``scope_values`` sorts and de-duplicates before anything
    is sent, so the database never sees a duplicate from that path. What the database
    refuses is a raw caller, and a set that repeats itself is a caller that has lost track
    of what it is asking for.
    """
    assert scope_values([Scope.WORKSPACE_READ, Scope.WORKSPACE_READ]) == ("workspace:read",)
    with pytest.raises(DBAPIError) as exc:
        _raw_register(application_engine, principal_a.credential, "{workspace:read,workspace:read}")
    assert "repeats a scope" in str(exc.value.orig)


def test_tenant_provision_cannot_be_delegated_by_anybody(
    application_engine, provisioning_engine, principal_a
):
    """Not by a credential, and not by the provisioning context that holds it either.

    The delegable rule is checked before the issuer rule, so this holds for the one actor
    that actually carries ``tenant:provision``. It is a capability of the bootstrap path,
    not a capability a credential may carry.
    """
    with pytest.raises(DBAPIError) as exc:
        _raw_register(application_engine, principal_a.credential, "{tenant:provision}")
    assert "may not be placed on an issued credential" in str(exc.value.orig)

    with pytest.raises(DBAPIError) as exc:
        with auth.provisioning_transaction(provisioning_engine) as session:
            session.execute(
                text(f"SELECT * FROM {SCHEMA}.register_auth_binding(:p, CAST(:s AS text[]), NULL)"),
                {"p": uuid.uuid4(), "s": "{tenant:provision}"},
            )
    assert "may not be placed on an issued credential" in str(exc.value.orig)


@pytest.mark.parametrize(
    "invented",
    ["operator:settle", "supplier:bid", "provider:read", "admin:all", "workspace:admin", "*"],
)
def test_a_cross_surface_scope_is_impossible_and_is_not_echoed(
    application_engine, principal_a, invented
):
    """Every one of these names a surface a customer credential must never reach.

    Refused because the catalogue is closed, not because a denylist recognised the domain
    -- ``workspace:admin`` is refused by exactly the same rule as ``operator:settle``, and
    that is the property worth having. And the rejected value is not repeated back: it is
    unvetted caller input whether or not it looks dangerous.
    """
    with pytest.raises(DBAPIError) as exc:
        _raw_register(application_engine, principal_a.credential, "{" + invented + "}")
    message = str(exc.value.orig)
    assert "not in the catalogue" in message
    assert invented not in message


def test_the_provisioning_actor_may_grant_what_it_does_not_hold(provisioning_engine, new_principal):
    """The one exemption, stated and tested rather than left implicit.

    The provisioning context carries ``tenant:provision`` and ``credential:manage`` and
    nothing else, yet it issues a tenant's first credential with the customer capabilities.
    That is not an escalation: it cannot name a tenant, so the only tenant it can act in is
    the one PostgreSQL generated for it moments earlier.
    """
    bootstrapped = new_principal("bootstrap", scopes=[Scope.WORKSPACE_WRITE, Scope.AUDIT_READ])
    assert bootstrapped.scopes == ("audit:read", "workspace:write")

    with auth.provisioning_transaction(provisioning_engine) as session:
        context = auth.current_authenticated_context(session)
        assert context.actor_kind == "provisioning"
        assert context.scopes == frozenset({"tenant:provision", "credential:manage"})


# ------------------------------------------------------------ scopes are never echoed


#: Values that must never come back out of a refusal. Two shapes a recogniser catches,
#: two it does not, and two that are simply wrong.
#:
#: A **one-character** probe is deliberately absent, and its absence is a statement about
#: this test rather than about the code: every single letter occurs somewhere in the fixed
#: prose of the message, so "the value was not echoed" is not a property a one-character
#: probe can distinguish. The rule the code follows is "never interpolate the value at
#: all", which is checkable by reading ``scope_values``; what these cases check is that
#: nobody reintroduces an interpolation.
HOSTILE_SCOPE_VALUES = [
    "fbk_" + "A" * 43,
    "Bearer abcdefghijklmnop",
    "postgresql://user:hunter2@localhost/db",
    "AKIAIOSFODNN7EXAMPLE",
    # Short, and recognised by nothing. This is the case the rule exists for.
    "hunter2",
    "zq7",
    # Plausible, plausible-looking, and still not in the catalogue.
    "workspace:admin",
    "not a scope at all",
]


@pytest.mark.parametrize("hostile", HOSTILE_SCOPE_VALUES)
def test_an_invalid_scope_value_is_never_repeated_back(hostile):
    """Including the ones no pattern recognises as a secret.

    An invalid scope is unvetted caller input. "It did not look like a credential" is not a
    reason to put it in an exception that travels into a traceback and a retained CI log --
    the rule and the position are enough to fix the call.
    """
    with pytest.raises(AuthorizationError) as exc:
        scope_values([hostile])
    chain = _exception_chain(exc.value)
    assert hostile not in chain, chain
    assert "position 0" in str(exc.value)


def test_an_invalid_scope_deep_in_a_list_names_its_position(hostile="fbk_" + "B" * 43):
    with pytest.raises(AuthorizationError) as exc:
        scope_values([Scope.WORKSPACE_READ, Scope.AUDIT_READ, hostile])
    assert "position 2" in str(exc.value)
    assert hostile not in _exception_chain(exc.value)
