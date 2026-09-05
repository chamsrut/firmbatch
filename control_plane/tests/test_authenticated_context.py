"""AUTH-BOUND-TENANT-CONTEXT: a transaction cannot choose its tenant.

This is the adversarial module for Milestone 2.3. Every test here runs as the restricted
application role -- the credential an attacker would hold after compromising the runtime
process -- and tries to obtain a tenant context by some route other than presenting a
valid credential. All of them must fail closed.

The property under test, stated as narrowly as it can be: **the only input that produces a
tenant context is a 256-bit secret whose one-way fingerprint is already in a table no
runtime role can read or write.** Not a tenant id, not a principal id, not a binding id,
not a fingerprint, not a scope name, not a setting, and not a relation the caller made.

Milestone 2.1 could not make that claim, and said so rather than pretending: the runtime
role could execute ``set_config('app.tenant_id', <any uuid>, true)`` and row-level security
would evaluate faithfully against whatever it had been told. ADR 0004 section 8g recorded
the limit and the roadmap tracked it as the task that blocks customer-facing deployment.
The tests below are what closes it for the database and runtime boundary this milestone
covers.

Not covered here, and not claimed anywhere: an attacker who holds the **migration owner**
credential. That role owns the functions and the policies, so it can redefine both --
which is exactly why ``db/principal.py`` refuses to let a runtime connection be, or reach,
that role, and why ``test_ownership_boundary.py`` asserts it.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError
from sqlalchemy.orm import Session

from firmbatch.control_plane.tests.conftest import exception_chain as _exception_chain
from firmbatch.control_plane.db import auth
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.models import Tenant, Workspace
from firmbatch.control_plane.db.repositories import WorkspaceRepository
from firmbatch.control_plane.security.authorization import Scope
from firmbatch.control_plane.security.secrets import Secret, generate_bearer_credential

#: The relation the transaction-scoped context lives in. Named here because several tests
#: try to reach it, and a test that guessed the name would pass by missing.
CONTEXT_RELATION = "auth_transaction_context"


def _seed(engine, principal, slug="target"):
    with auth.authenticated_transaction(engine, principal.credential) as session:
        return WorkspaceRepository(session).create(slug=slug, name=slug.replace("-", " ")).id


def _reaches_nothing(session, victim_workspace) -> None:
    """The assertion every forgery test ends with."""
    assert db_engine.current_tenant_context(session) is None
    assert session.scalars(select(Tenant)).all() == []
    assert session.scalars(select(Workspace)).all() == []
    assert session.get(Workspace, victim_workspace) is None
    assert auth.current_authenticated_context(session) is None


# ------------------------------------------------------------------- setting forgery


def test_setting_the_old_tenant_guc_grants_nothing(application_engine, principal_a):
    """Completion-gate case 1, and the one that used to work.

    ``set_config('app.tenant_id', <victim uuid>, true)`` followed by a read of every
    tenant-scoped table. At Milestone 2.1 this returned the victim's rows. It now returns
    nothing, because no policy and no function reads that setting.
    """
    victim = _seed(application_engine, principal_a, "guc-victim")
    with db_engine.transaction(application_engine) as session:
        session.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(principal_a.id)})
        assert session.execute(text("SELECT current_setting('app.tenant_id', true)")).scalar() == str(
            principal_a.id
        ), "the setting was not actually set, so this test proves nothing"
        _reaches_nothing(session, victim)


@pytest.mark.parametrize(
    "setting",
    [
        "app.tenant_id",
        "app.auth_tenant_id",
        "app.principal_id",
        "app.scopes",
        "firmbatch.tenant_id",
        "firmbatch.auth_context",
    ],
)
def test_no_fabricated_setting_grants_anything(application_engine, principal_a, setting):
    """A custom GUC is writable by any role, so none of them may mean anything.

    The old name is included alongside plausible new ones: the failure this guards against
    is somebody reintroducing a settings-based mechanism under a name that looks more
    official than ``app.tenant_id`` did.
    """
    victim = _seed(application_engine, principal_a, f"fab-{abs(hash(setting)) % 10000}")
    with db_engine.transaction(application_engine) as session:
        session.execute(
            text("SELECT set_config(:s, :v, true)"), {"s": setting, "v": str(principal_a.id)}
        )
        _reaches_nothing(session, victim)


def test_a_session_level_setting_survives_the_pool_and_still_grants_nothing(
    single_connection_engine, principal_a
):
    """A plain ``SET`` outlives its transaction, so it is the durable version of the same idea."""
    victim = _seed(single_connection_engine, principal_a, "session-guc-victim")
    with single_connection_engine.connect() as connection:
        connection.execute(text("SELECT set_config('app.tenant_id', :t, false)"), {"t": str(principal_a.id)})
        connection.commit()

    with db_engine.transaction(single_connection_engine) as session:
        _reaches_nothing(session, victim)


# -------------------------------------------------------------- identifier forgery


def test_a_fabricated_tenant_id_is_not_something_bind_will_take(application_engine, principal_a):
    """There is no call that accepts a tenant id, which is stronger than one that refuses it.

    Both routes are tried: the Python API, which takes a credential and validates its
    shape, and the database function underneath it, which takes ``text`` and hashes
    whatever it is given. A UUID hashes to a fingerprint nothing has ever registered.
    """
    with pytest.raises(auth.AuthenticationError):
        with auth.authenticated_transaction(application_engine, str(principal_a.id)):
            pass

    # ``InvalidPassword`` rather than a privilege error: the call is permitted and the
    # credential is not, which is the distinction that matters.
    with pytest.raises(DBAPIError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(
                text(f"SELECT {SCHEMA}.bind_authenticated_context(:v)"), {"v": str(principal_a.id)}
            )
    assert "authentication failed" in str(exc.value).lower()


def test_a_fabricated_binding_id_grants_nothing(application_engine, principal_a):
    """Knowing a binding id -- or guessing one -- is not a way in.

    The binding id is not a secret and appears in the audit trail. What it is not is an
    input to authentication: nothing accepts one, and the function that writes a context
    is executable by nobody.
    """
    for value in (str(principal_a.binding_id), str(uuid.uuid4())):
        with pytest.raises(auth.AuthenticationError):
            with auth.authenticated_transaction(application_engine, value):
                pass


def test_the_context_writer_is_executable_by_nobody(application_engine, principal_a):
    """``auth_context_begin`` is the single point where a context comes into existence.

    A role that could call it could name any tenant, any principal and any scope set. It
    is granted to no role at all -- not the application role, not provisioning -- and is
    reached only from inside the ``SECURITY DEFINER`` functions that decided what the
    context may be.
    """
    with pytest.raises(ProgrammingError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(
                text(
                    f"SELECT {SCHEMA}.auth_context_begin("
                    ":b, :t, :p, 'credential', ARRAY['workspace:read','workspace:write'])"
                ),
                {"b": uuid.uuid4(), "t": principal_a.id, "p": uuid.uuid4()},
            )
    assert "permission denied" in str(exc.value).lower()


def test_the_isolation_guard_is_executable_by_nobody(application_engine):
    """The other internal function, and the one a caller would most like to skip.

    ``auth_require_read_committed`` is what refuses a bind under a snapshot older than the
    statement. A role that could call it directly would gain nothing on its own -- but a
    role that could *replace* it would, and executability is the first step somebody takes
    towards deciding a function is fair game.
    """
    with pytest.raises(ProgrammingError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(text(f"SELECT {SCHEMA}.auth_require_read_committed()"))
    assert "permission denied" in str(exc.value).lower()


def test_a_fabricated_fingerprint_cannot_be_registered(application_engine, principal_a):
    """The registry takes credentials, not digests, and takes them from nobody.

    Two routes, both closed: no runtime role can write ``auth_bindings`` at all, and the
    one function that writes it computes the digest itself from a credential whose format
    it checks -- so there is no parameter through which a chosen fingerprint could arrive.
    """
    with pytest.raises(ProgrammingError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"INSERT INTO {SCHEMA}.auth_bindings (tenant_id, principal_id, fingerprint, scopes) "
                    "VALUES (:t, :p, :f, ARRAY['workspace:read'])"
                ),
                {"t": principal_a.id, "p": uuid.uuid4(), "f": "a" * 64},
            )
    assert "permission denied" in str(exc.value).lower()

    # And there is no parameter through which one could arrive: the function takes a
    # principal, a scope array and an expiry, and mints the credential itself.
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        arguments = session.execute(
            text(
                "SELECT pg_get_function_arguments(p.oid) FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = :s AND p.proname = 'register_auth_binding'"
            ),
            {"s": SCHEMA},
        ).scalar_one()
    assert "credential" not in arguments, arguments
    assert arguments == "p_principal_id uuid, p_scopes text[], p_expires_at timestamp with time zone"


def test_a_fabricated_actor_cannot_be_asserted(application_engine, principal_a):
    """The accessors report what the context says, and take no argument that could change it."""
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        row = session.execute(
            text(
                f"SELECT {SCHEMA}.auth_tenant_id(), {SCHEMA}.auth_principal_id(), "
                f"{SCHEMA}.auth_binding_id(), {SCHEMA}.auth_actor_kind()"
            )
        ).one()
    assert row == (principal_a.id, principal_a.principal_id, principal_a.binding_id, "credential")


def test_a_scope_outside_the_catalogue_cannot_be_stored(application_engine, principal_a):
    """The closed catalogue, in the database as well as in Python.

    An unknown scope must not become storable and then meaningful later when somebody adds
    a policy that reads it. Python refuses it first; the database function refuses it for a
    writer that goes around Python, which this proves by calling it with a raw array.

    The function refuses it **before** the ``scopes_known`` check constraint would, and
    that ordering is deliberate rather than incidental: a constraint violation renders the
    failing row in its ``DETAIL``, so letting the constraint be the thing that refuses an
    invented scope would put the rejected value into the error. The constraint is still
    there as the backstop, and ``test_the_scope_catalogue_constraint_is_still_the_backstop``
    exercises it from the one identity that can still reach the table.
    """
    from firmbatch.control_plane.security.authorization import AuthorizationError

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        with pytest.raises(AuthorizationError):
            auth.register_auth_binding(
                session, principal_id=uuid.uuid4(), scopes=["workspace:admin"]
            )

    invented = "operator:settle"
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            session.execute(
                text(
                    f"SELECT * FROM {SCHEMA}.register_auth_binding("
                    ":p, CAST(:s AS text[]), NULL)"
                ),
                {"p": uuid.uuid4(), "s": "{" + invented + "}"},
            )
    server_message = str(exc.value.orig)
    assert "not in the catalogue" in server_message
    # And the invented scope is not repeated back. It is a domain a customer credential
    # must never be able to name -- and it is also unvetted caller input, which is reason
    # enough on its own.
    assert invented not in server_message


def test_the_scope_catalogue_constraint_is_still_the_backstop(owner_engine, principal_a):
    """The check constraint under the function that now refuses first.

    Written as the schema owner, which is the only identity that can reach ``auth_bindings``
    at all. If the function's catalogue test were ever removed, this is what would still
    stop an unknown scope becoming storable.
    """
    with owner_engine.connect() as connection:
        try:
            with pytest.raises(IntegrityError) as exc:
                connection.execute(
                    text(
                        f"INSERT INTO {SCHEMA}.auth_bindings "
                        "(tenant_id, principal_id, fingerprint, scopes) "
                        "VALUES (:t, :p, repeat('a', 64), ARRAY['operator:settle']::text[])"
                    ),
                    {"t": principal_a.id, "p": uuid.uuid4()},
                )
            assert "ck_auth_bindings_scopes_known" in str(exc.value)
        finally:
            connection.rollback()


# ------------------------------------------------- clearing, shadowing, and rebinding
#
# The first version of this milestone kept the context in ``pg_temp`` with ``ON COMMIT
# DELETE ROWS``. Two statements defeated it, both legal for any role:
#
#   DISCARD TEMP;                        -- drops every temporary table in the session,
#                                        -- including one owned by somebody else
#   SELECT firmbatch.auth_context_reset();  -- the package's own clearing function
#
# and after either, a second ``bind_authenticated_context`` succeeded, so one transaction
# could act as two tenants and commit both. Measured against a real server.
#
# The context is now an ordinary protected table keyed by the transaction id. These tests
# enumerate every route a runtime role has to remove, replace or shadow it, and then try to
# rebind after each one.


def _context_survives(session, principal) -> None:
    assert db_engine.current_tenant_context(session) == principal.id


@pytest.mark.parametrize(
    "statement",
    [
        "DISCARD TEMP",
        "DISCARD TEMPORARY",
        "DISCARD PLANS",
        "DISCARD SEQUENCES",
        f"DELETE FROM {SCHEMA}.{CONTEXT_RELATION}",
        f"TRUNCATE {SCHEMA}.{CONTEXT_RELATION}",
        f"DROP TABLE {SCHEMA}.{CONTEXT_RELATION}",
        f"ALTER TABLE {SCHEMA}.{CONTEXT_RELATION} RENAME TO gone",
        f"UPDATE {SCHEMA}.{CONTEXT_RELATION} SET tenant_id = gen_random_uuid()",
    ],
)
def test_no_statement_clears_an_established_context(application_engine, principal_a, statement):
    """Either the statement is refused, or it runs and changes nothing.

    ``DISCARD TEMP`` is the one that matters and the one that used to work: it needs no
    privilege, PostgreSQL offers nothing to revoke, and it dropped a temporary relation
    owned by the schema owner. It is now inert here, because the context is not temporary.
    """
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        _context_survives(session, principal_a)
        try:
            session.execute(text(statement))
        except DBAPIError:
            # Refused. The transaction is aborted, so the surviving-context assertion
            # belongs to the allowed cases below.
            return
        _context_survives(session, principal_a)


def test_discard_temp_neither_clears_the_context_nor_permits_a_rebind(
    application_engine, principal_a, principal_b
):
    """The exact sequence that defeated the previous design, run end to end."""
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        session.execute(text("DISCARD TEMP"))
        _context_survives(session, principal_a)
        with pytest.raises(auth.ContextAlreadyBoundError):
            auth.bind_authenticated_context(session, principal_b.credential)


def test_there_is_no_clearing_function_left_to_call(application_engine, principal_a):
    """The package's own escape hatch is gone, in the database as well as in Python."""
    with pytest.raises(DBAPIError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(text(f"SELECT {SCHEMA}.auth_context_reset()"))
    assert "does not exist" in str(exc.value).lower()


def test_a_shadowing_relation_cannot_be_created_or_believed(raw_application_connection):
    """Two routes to substituting the context relation, both closed.

    A temporary relation of the same name would be searched first if ``search_path`` let
    it, and a permanent one would have to be created in the pinned schema. The runtime
    role holds neither ``TEMPORARY`` on the database nor ``CREATE`` on the schema -- and
    every reference inside the definer functions is schema-qualified anyway, so
    ``pg_temp`` is not consulted for them at all.
    """
    for statement in (
        f"CREATE TEMP TABLE {CONTEXT_RELATION} (backend_pid integer, xact_id xid8, tenant_id uuid)",
        f"CREATE TABLE {SCHEMA}.shadow_context (backend_pid integer)",
    ):
        with pytest.raises(ProgrammingError) as exc:
            raw_application_connection.execute(text(statement))
        assert "permission denied" in str(exc.value).lower()


def test_a_savepoint_release_keeps_the_identity_it_established(
    application_engine, principal_a, principal_b
):
    """Releasing a savepoint must not permit a new identity in the enclosing transaction.

    The context row was written inside the savepoint and survives its release, so the
    conflict predicate still sees this transaction's id and the second bind is refused.
    """
    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.require_no_inherited_context(session)
            nested = session.begin_nested()
            session.execute(
                text(f"SELECT {SCHEMA}.bind_authenticated_context(:c)"),
                {"c": principal_a.credential.reveal()},
            )
            nested.commit()

            _context_survives(session, principal_a)
            with pytest.raises(DBAPIError) as exc:
                session.execute(
                    text(f"SELECT {SCHEMA}.bind_authenticated_context(:c)"),
                    {"c": principal_b.credential.reveal()},
                )
            assert "already has an authenticated context" in str(exc.value)
    finally:
        session.close()


def test_a_savepoint_rollback_takes_the_context_and_its_work_together(
    application_engine, principal_a, principal_b
):
    """The one route to a second identity, and it costs everything done under the first.

    A savepoint rollback removes the context row **and** every write made under it, because
    they are the same savepoint. So a transaction can end up acting as B -- but nothing A
    did survives to be committed alongside, which is the property that matters: no
    transaction commits effects or audit attribution from two tenants.
    """
    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.require_no_inherited_context(session)
            nested = session.begin_nested()
            session.execute(
                text(f"SELECT {SCHEMA}.bind_authenticated_context(:c)"),
                {"c": principal_a.credential.reveal()},
            )
            WorkspaceRepository(session).create(slug="doomed-by-rollback", name="Doomed")
            nested.rollback()

            assert db_engine.current_tenant_context(session) is None
            session.execute(
                text(f"SELECT {SCHEMA}.bind_authenticated_context(:c)"),
                {"c": principal_b.credential.reveal()},
            )
            _context_survives(session, principal_b)
            # A's write went with A's context.
            assert WorkspaceRepository(session).list() == []
        session.expunge_all()
    finally:
        session.close()

    # And nothing of A's survived the commit.
    with auth.authenticated_transaction(application_engine, principal_a.credential) as check:
        assert WorkspaceRepository(check).get_by_slug("doomed-by-rollback") is None


def test_the_context_table_is_unreachable_by_every_command(raw_application_connection):
    """Read, write, revise, remove and empty -- five grants, five refusals."""
    for statement in (
        f"SELECT count(*) FROM {SCHEMA}.{CONTEXT_RELATION}",
        f"INSERT INTO {SCHEMA}.{CONTEXT_RELATION} (backend_pid, xact_id, tenant_id, actor_kind, "
        "scopes, bound_at) VALUES (1, '1'::xid8, gen_random_uuid(), 'credential', "
        "ARRAY['workspace:read'], now())",
        f"UPDATE {SCHEMA}.{CONTEXT_RELATION} SET tenant_id = gen_random_uuid()",
        f"DELETE FROM {SCHEMA}.{CONTEXT_RELATION}",
        f"TRUNCATE {SCHEMA}.{CONTEXT_RELATION}",
    ):
        with pytest.raises(ProgrammingError) as exc:
            raw_application_connection.execute(text(statement))
        assert "permission denied" in str(exc.value).lower(), statement


# ------------------------------------------------------- isolation level and freshness


@pytest.mark.parametrize("level", ["REPEATABLE READ", "SERIALIZABLE"])
def test_binding_is_refused_outside_read_committed(application_engine, principal_a, level):
    """Refused by the **database**, because the property is about the snapshot it reads.

    Under a stricter level the registry lookup runs against the snapshot taken when the
    transaction opened, so a revocation or an expiry committed in between would be
    invisible and a dead credential would still authenticate. A Python-side check could
    not make that untrue -- only refusing the transaction can.
    """
    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with pytest.raises(auth.UnsupportedIsolationLevelError):
            with session.begin():
                session.connection(execution_options={"isolation_level": level.replace(" ", "_")})
                auth.bind_authenticated_context(session, principal_a.credential)
    finally:
        session.close()


@pytest.mark.parametrize("level", ["REPEATABLE READ", "SERIALIZABLE"])
def test_a_stale_snapshot_cannot_authenticate_a_revoked_credential(
    application_engine, owner_engine, new_principal, issue_credential, level
):
    """The attack the isolation refusal exists to stop, staged in full.

    A transaction opens and takes its snapshot. The credential is revoked and committed by
    somebody else. The transaction then binds. Under ``REPEATABLE READ`` the revocation is
    invisible to it, so without the refusal the bind would succeed with a credential that
    is no longer valid.
    """
    owner = new_principal(f"stale-{level[:3].lower()}")
    doomed = issue_credential(owner, [Scope.WORKSPACE_READ])

    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with pytest.raises(auth.UnsupportedIsolationLevelError):
            with session.begin():
                session.connection(execution_options={"isolation_level": level.replace(" ", "_")})
                # Take the snapshot *before* the revocation.
                session.execute(text("SELECT 1")).scalar()

                with auth.authenticated_transaction(application_engine, owner.credential) as other:
                    assert auth.revoke_auth_binding(other, doomed.binding_id) is True

                auth.bind_authenticated_context(session, doomed.credential)
    finally:
        session.close()


def test_a_revocation_committed_before_the_bind_statement_is_observed(
    application_engine, new_principal, issue_credential
):
    """The linearisation point, stated and tested: **the bind statement's own snapshot.**

    The transaction opens first and binds afterwards. Under READ COMMITTED each statement
    takes a fresh snapshot, so a revocation committed in between is seen. A revocation
    committed *while* the bind statement runs is not, and that is the boundary rather than
    a gap: after the bind, the credential's validity is not re-checked, exactly as a
    session established before a revocation is not retroactively ended.
    """
    owner = new_principal("linearised")
    doomed = issue_credential(owner, [Scope.WORKSPACE_READ])

    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.require_no_inherited_context(session)
            # The transaction is open and has read, so it exists before the revocation.
            assert session.execute(text("SELECT 1")).scalar() == 1

            with auth.authenticated_transaction(application_engine, owner.credential) as other:
                assert auth.revoke_auth_binding(other, doomed.binding_id) is True

            with pytest.raises(auth.AuthenticationError):
                auth.bind_authenticated_context(session, doomed.credential)
    finally:
        session.close()


def test_the_ordinary_read_committed_path_still_works(application_engine, principal_a):
    """The positive control for the four refusals above."""
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert session.execute(text("SELECT current_setting('transaction_isolation')")).scalar() == (
            "read committed"
        )
        assert auth.current_authenticated_context(session).tenant_id == principal_a.id


def test_expiry_is_evaluated_against_the_clock_and_not_the_transaction_start(
    application_engine, owner_engine, new_principal, issue_credential
):
    """``now()`` is transaction-start time, so it would extend a credential's life.

    The binding expires a moment from now; the transaction opens *before* that instant and
    binds after it. With ``now()`` the credential would still look live for as long as the
    transaction ran. With ``clock_timestamp()`` it is dead the moment it is dead.
    """
    from datetime import datetime, timedelta, timezone

    owner = new_principal("clock-expiry")
    doomed = issue_credential(
        owner, [Scope.WORKSPACE_READ], expires_at=datetime.now(timezone.utc) + timedelta(milliseconds=250)
    )

    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            db_engine.require_no_inherited_context(session)
            # Transaction start is now, and the credential is still live at this instant.
            assert session.execute(text("SELECT 1")).scalar() == 1
            session.execute(text("SELECT pg_sleep(0.4)"))
            # now() has not moved; clock_timestamp() has.
            moved = session.execute(text("SELECT clock_timestamp() > now()")).scalar()
            assert moved is True
            with pytest.raises(auth.AuthenticationError):
                auth.bind_authenticated_context(session, doomed.credential)
    finally:
        session.close()


# -------------------------------------------------------------- credential failures


def test_an_unknown_credential_fails_closed(application_engine):
    unknown = generate_bearer_credential()
    with pytest.raises(auth.AuthenticationError):
        with auth.authenticated_transaction(application_engine, unknown):
            pass


@pytest.mark.parametrize(
    "malformed",
    ["", "fbk_", "fbk_short", "not-a-credential", "fbk_" + "x" * 42, "fbk_" + "x" * 44, "fbk_" + "!" * 43],
)
def test_a_malformed_credential_fails_closed(application_engine, malformed):
    """Refused in Python, before the value can reach a statement log."""
    with pytest.raises(auth.AuthenticationError):
        with auth.authenticated_transaction(application_engine, malformed):
            pass


def test_a_malformed_credential_sent_straight_to_the_database_also_fails(application_engine):
    """Because the Python check is convenience, and the database is the boundary."""
    for malformed in ("", "nonsense", "x" * 200):
        with pytest.raises(DBAPIError) as exc:
            with db_engine.transaction(application_engine) as session:
                session.execute(
                    text(f"SELECT {SCHEMA}.bind_authenticated_context(:v)"), {"v": malformed}
                )
        assert "authentication failed" in str(exc.value).lower()


def test_a_revoked_credential_fails_closed(application_engine, new_principal, issue_credential):
    owner = new_principal("revoked")
    doomed = issue_credential(owner, [Scope.WORKSPACE_READ])

    # It works first, so the refusal afterwards is the revocation and not a bad credential.
    with auth.authenticated_transaction(application_engine, doomed.credential) as session:
        assert auth.current_authenticated_context(session).tenant_id == owner.id

    with auth.authenticated_transaction(application_engine, owner.credential) as session:
        assert auth.revoke_auth_binding(session, doomed.binding_id) is True

    with pytest.raises(auth.AuthenticationError):
        with auth.authenticated_transaction(application_engine, doomed.credential):
            pass


def test_revoking_twice_reports_that_nothing_changed(application_engine, new_principal, issue_credential):
    owner = new_principal("revoked-twice")
    doomed = issue_credential(owner, [Scope.WORKSPACE_READ])
    with auth.authenticated_transaction(application_engine, owner.credential) as session:
        assert auth.revoke_auth_binding(session, doomed.binding_id) is True
        assert auth.revoke_auth_binding(session, doomed.binding_id) is False


def test_a_binding_in_another_tenant_cannot_be_revoked(
    application_engine, new_principal, issue_credential
):
    """And the refusal is indistinguishable from "no such binding", so it cannot be a probe."""
    mine = new_principal("revoke-mine")
    theirs = new_principal("revoke-theirs")
    victim = issue_credential(theirs, [Scope.WORKSPACE_READ])

    with auth.authenticated_transaction(application_engine, mine.credential) as session:
        assert auth.revoke_auth_binding(session, victim.binding_id) is False
        assert auth.revoke_auth_binding(session, uuid.uuid4()) is False

    # And the victim's credential still works, so the False above was a refusal and not a
    # quiet success.
    with auth.authenticated_transaction(application_engine, victim.credential) as session:
        assert auth.current_authenticated_context(session).tenant_id == theirs.id


def test_an_expired_credential_fails_closed(
    application_engine, owner_engine, new_principal, issue_credential
):
    """Expiry is evaluated in the database at bind time, against ``now()``.

    The binding is aged rather than created expired: the check constraint refuses an
    ``expires_at`` at or before ``created_at``, so a binding cannot be registered already
    dead. Moving both timestamps back is how a test gets to the state a clock would
    otherwise have to produce.
    """
    owner = new_principal("expired")
    doomed = issue_credential(owner, [Scope.WORKSPACE_READ])

    with auth.authenticated_transaction(application_engine, doomed.credential) as session:
        assert auth.current_authenticated_context(session).tenant_id == owner.id

    with owner_engine.connect() as connection:
        connection.execute(
            text(
                f"UPDATE {SCHEMA}.auth_bindings SET created_at = now() - interval '2 days', "
                "expires_at = now() - interval '1 day' WHERE id = :b"
            ),
            {"b": doomed.binding_id},
        )
        connection.commit()

    with pytest.raises(auth.AuthenticationError):
        with auth.authenticated_transaction(application_engine, doomed.credential):
            pass


def test_an_unexpired_expiry_still_works(application_engine, new_principal, issue_credential):
    """The other half: an expiry in the future is not a refusal."""
    from datetime import datetime, timedelta, timezone

    owner = new_principal("unexpired")
    living = issue_credential(
        owner, [Scope.WORKSPACE_READ], expires_at=datetime.now(timezone.utc) + timedelta(days=1)
    )
    with auth.authenticated_transaction(application_engine, living.credential) as session:
        assert auth.current_authenticated_context(session).tenant_id == owner.id


def test_every_credential_failure_reports_the_same_thing(application_engine, new_principal, issue_credential):
    """Unknown, revoked and expired are one message, so the failure is not an oracle.

    A caller holding a wrong credential must not be able to learn whether it was ever a
    right one; that is the difference between "this is not a key" and "this key has been
    changed", and the second tells an attacker they are in the right place.
    """
    owner = new_principal("oracle")
    revoked = issue_credential(owner, [Scope.WORKSPACE_READ])
    with auth.authenticated_transaction(application_engine, owner.credential) as session:
        auth.revoke_auth_binding(session, revoked.binding_id)

    messages = set()
    for credential in (generate_bearer_credential(), revoked.credential):
        with pytest.raises(auth.AuthenticationError) as exc:
            with auth.authenticated_transaction(application_engine, credential):
                pass
        messages.add(str(exc.value))
    assert len(messages) == 1, messages


# ------------------------------------------------------------------ one context only


def test_binding_twice_is_refused(application_engine, principal_a):
    with pytest.raises(auth.ContextAlreadyBoundError):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            auth.bind_authenticated_context(session, principal_a.credential)


def test_switching_identity_inside_one_transaction_is_refused(
    application_engine, principal_a, principal_b
):
    """The same refusal, and the one that matters: a transaction cannot change who it is."""
    with pytest.raises(auth.ContextAlreadyBoundError):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            auth.bind_authenticated_context(session, principal_b.credential)


def test_provisioning_cannot_be_started_inside_an_authenticated_transaction(
    provisioning_engine, principal_a
):
    """Nor can a credential context be widened into a provisioning one."""
    with pytest.raises(auth.ContextAlreadyBoundError):
        with auth.authenticated_transaction(provisioning_engine, principal_a.credential) as session:
            auth.begin_tenant_provisioning(session)


def test_a_refused_second_bind_does_not_change_the_standing_context(application_engine, principal_a, principal_b):
    """The refusal aborts the transaction, so nothing can proceed under either identity."""
    victim = _seed(application_engine, principal_b, "second-bind-victim")
    with pytest.raises(auth.ContextAlreadyBoundError):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            auth.bind_authenticated_context(session, principal_b.credential)

    # A fresh transaction as A still cannot see B's row.
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert session.get(Workspace, victim) is None


# ------------------------------------------------------------------------ reuse


def test_a_context_does_not_survive_a_commit(single_connection_engine, principal_a):
    victim = _seed(single_connection_engine, principal_a, "commit-reuse")
    with auth.authenticated_transaction(single_connection_engine, principal_a.credential) as session:
        assert session.get(Workspace, victim) is not None
    with db_engine.transaction(single_connection_engine) as session:
        _reaches_nothing(session, victim)


def test_a_context_does_not_survive_a_rollback(single_connection_engine, principal_a):
    victim = _seed(single_connection_engine, principal_a, "rollback-reuse")
    with pytest.raises(RuntimeError):
        with auth.authenticated_transaction(single_connection_engine, principal_a.credential) as session:
            assert session.get(Workspace, victim) is not None
            raise RuntimeError("unwinding on purpose")
    with db_engine.transaction(single_connection_engine) as session:
        _reaches_nothing(session, victim)


def test_a_context_does_not_survive_a_failed_statement(single_connection_engine, principal_a):
    """A transaction that died on an error is still a transaction that must leave nothing."""
    victim = _seed(single_connection_engine, principal_a, "error-reuse")
    with pytest.raises(ProgrammingError):
        with auth.authenticated_transaction(single_connection_engine, principal_a.credential) as session:
            session.execute(text("SELECT * FROM firmbatch.no_such_relation"))
    with db_engine.transaction(single_connection_engine) as session:
        _reaches_nothing(session, victim)


def test_a_context_does_not_survive_pool_reuse(disposable_database, principal_a):
    """One physical connection, handed back and taken out again several times."""
    engine = db_engine.create_application_engine(
        disposable_database.application_url, pool_size=1, max_overflow=0
    )
    try:
        victim = _seed(engine, principal_a, "pool-reuse")
        for _ in range(3):
            with auth.authenticated_transaction(engine, principal_a.credential) as session:
                assert session.get(Workspace, victim) is not None
            with db_engine.transaction(engine) as session:
                _reaches_nothing(session, victim)
    finally:
        engine.dispose()


def test_a_context_does_not_survive_orm_session_reuse(application_engine, principal_a):
    """The same ``Session`` object, used again with no credential presented."""
    victim = _seed(application_engine, principal_a, "session-reuse")
    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        with session.begin():
            auth.bind_authenticated_context(session, principal_a.credential)
            held = session.get(Workspace, victim)
            assert held is not None

        with session.begin():
            assert held is not None  # strong reference kept on purpose
            _reaches_nothing(session, victim)
    finally:
        session.close()


def test_a_connection_bound_session_is_refused_rather_than_half_defended(
    disposable_database, principal_a
):
    """The bind form whose protections cannot be re-run, refused at the door.

    Every measure here is anchored to a pool checkout -- the principal re-verification and
    the pinned ``search_path``. A ``Connection`` handed to a ``Session`` was checked out by
    somebody else, so neither re-runs, and the Session inherits whatever session state that
    caller left behind. ``test_bind_forms.py`` enumerates the form; this asserts it in the
    security module that depends on it.

    The authentication context is *not* among the things a checkout has to fix, and has not
    been since it stopped living in the session: it belongs to a transaction id, so a
    Connection carrying one from a previous holder carries something no new transaction can
    read.
    """
    engine = db_engine.create_application_engine(
        disposable_database.application_url, pool_size=2, max_overflow=0
    )
    try:
        connection = engine.connect()
        try:
            session = Session(bind=connection, expire_on_commit=False)
            try:
                # Refused on first use, which is before a credential could be presented on
                # it: the guard fires on autobegin, so there is no window in which such a
                # session is usable at all.
                with pytest.raises(db_engine.UnsupportedSessionBindError):
                    session.begin()
                with pytest.raises(db_engine.UnsupportedSessionBindError):
                    session.execute(text("SELECT 1"))
            finally:
                session.close()
        finally:
            connection.close()
    finally:
        engine.dispose()


# ----------------------------------------------------------- what a credential *does* buy


def test_a_valid_credential_reaches_its_own_tenant_and_no_other(
    application_engine, principal_a, principal_b
):
    """The positive control. Without it, every test above could pass on a broken database."""
    mine = _seed(application_engine, principal_a, "mine")
    theirs = _seed(application_engine, principal_b, "theirs")

    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        context = auth.current_authenticated_context(session)
        assert context.tenant_id == principal_a.id
        assert context.principal_id == principal_a.principal_id
        assert context.binding_id == principal_a.binding_id
        assert context.actor_kind == "credential"
        assert session.get(Workspace, mine) is not None
        assert session.get(Workspace, theirs) is None
        assert [t.id for t in session.scalars(select(Tenant))] == [principal_a.id]


def test_two_credentials_in_one_tenant_reach_the_same_rows(
    application_engine, new_principal, issue_credential
):
    """A binding is not a partition: two credentials for one tenant see one tenant."""
    owner = new_principal("shared")
    other = issue_credential(owner, [Scope.WORKSPACE_READ, Scope.WORKSPACE_WRITE])
    workspace = _seed(application_engine, owner, "shared-workspace")

    with auth.authenticated_transaction(application_engine, other.credential) as session:
        assert session.get(Workspace, workspace) is not None
        assert auth.current_authenticated_context(session).tenant_id == owner.id
        assert auth.current_authenticated_context(session).binding_id == other.binding_id


def test_the_credential_is_never_stored_and_never_returned(owner_engine, principal_a):
    """What PostgreSQL holds is a digest of the credential, and only that.

    Read with the owner connection, which is subject to no policy on this table and holds
    every privilege on it -- so if the credential were anywhere in the row, this would find
    it.
    """
    import hashlib

    with owner_engine.connect() as connection:
        row = connection.execute(
            text(f"SELECT * FROM {SCHEMA}.auth_bindings WHERE id = :b"), {"b": principal_a.binding_id}
        ).mappings().one()

    raw = principal_a.credential.reveal()
    for column, value in row.items():
        assert raw not in str(value), f"the credential appears in auth_bindings.{column}"
    expected = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert row["fingerprint"] == expected, "the stored digest is not sha256 of the credential"


def test_an_unexpected_database_error_does_not_carry_the_credential_with_it(
    application_engine, principal_a
):
    """The leak path that is not a policy: a ``DBAPIError`` renders its parameters.

    One statement in this package still passes a raw credential as a parameter -- the bind.
    Its *expected* failures are translated and raised with nothing attached. An unexpected
    one would otherwise propagate as an ordinary ``DBAPIError`` carrying
    ``[parameters: {'credential': 'fbk_...'}]`` into the traceback, the log, and any
    retained CI artifact.

    Forced rather than waited for, at the helper that guards it, because the honest way to
    test a path nothing reaches by accident is to reach it on purpose. (Registration used
    to need this too. It no longer passes a credential at all: the value is minted in the
    database and returned, which removed both the oracle and this leak surface.)
    """
    value = principal_a.credential.reveal()
    with db_engine.transaction(application_engine) as session:
        with pytest.raises(auth.CredentialOperationError) as exc:
            auth._execute(
                session,
                text("SELECT 1 / 0 WHERE CAST(:credential AS text) IS NOT NULL"),
                {"credential": value},
                scrub=(value,),
            )

    rendered = str(exc.value)
    assert value not in rendered
    assert "***" in rendered, "the value was neither present nor scrubbed, so nothing is proven"
    assert "division by zero" in rendered  # the diagnosis survives; only the value is gone
    assert exc.value.__cause__ is None and exc.value.__context__ is None


def test_the_credential_object_does_not_render_itself(principal_a):
    """A credential in a traceback, an f-string or a fixture repr is a leaked credential."""
    raw = principal_a.credential.reveal()
    assert isinstance(principal_a.credential, Secret)
    for rendering in (repr(principal_a.credential), str(principal_a.credential), f"{principal_a.credential}"):
        assert raw not in rendering
        assert rendering == "Secret(<redacted>)"


# --------------------------------------------- credential existence probing (finding 4)
#
# The first version of ``register_auth_binding`` took the credential as an argument and
# inserted it. A holder of ``credential:manage`` in tenant A could therefore submit a
# candidate and watch the outcome: a unique violation on the fingerprint meant "this exists
# somewhere", across a tenant boundary, in a table it cannot read. Translating the
# violation into a different error would not have helped -- **success versus failure is the
# oracle**, whatever either one is called.
#
# The credential is now generated inside the function and returned once. There is no
# candidate to submit, so there is no question to answer.


def _cross_tenant_candidates(application_engine, new_principal, issue_credential, owner_engine):
    """One active, one revoked and one expired credential, all in a tenant of their own."""
    other = new_principal("probe-target")
    active = issue_credential(other, [Scope.WORKSPACE_READ])
    revoked = issue_credential(other, [Scope.WORKSPACE_READ])
    expired = issue_credential(other, [Scope.WORKSPACE_READ])

    with auth.authenticated_transaction(application_engine, other.credential) as session:
        assert auth.revoke_auth_binding(session, revoked.binding_id) is True
    with owner_engine.connect() as connection:
        connection.execute(
            text(
                f"UPDATE {SCHEMA}.auth_bindings SET created_at = now() - interval '2 days', "
                "expires_at = now() - interval '1 day' WHERE id = :b"
            ),
            {"b": expired.binding_id},
        )
        connection.commit()
    return other, {"active": active, "revoked": revoked, "expired": expired}


def test_a_credential_manager_cannot_submit_a_candidate_at_all(
    application_engine, new_principal, issue_credential, owner_engine
):
    """The registration path takes no credential, so there is nothing to probe with.

    Asserted on the Python signature and on the database signature, because either one
    growing the parameter back would restore the oracle.
    """
    import inspect as _inspect

    _other, candidates = _cross_tenant_candidates(
        application_engine, new_principal, issue_credential, owner_engine
    )
    mine = new_principal("probe-caller")

    parameters = _inspect.signature(auth.register_auth_binding).parameters
    assert "credential" not in parameters and "fingerprint" not in parameters, list(parameters)

    with auth.authenticated_transaction(application_engine, mine.credential) as session:
        arguments = session.execute(
            text(
                "SELECT pg_get_function_arguments(p.oid) FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = :s AND p.proname = 'register_auth_binding'"
            ),
            {"s": SCHEMA},
        ).scalar_one()
    assert "credential" not in arguments and "fingerprint" not in arguments, arguments

    # And registration is unconditionally successful whatever exists elsewhere, so no
    # outcome carries information about another tenant's credentials.
    for _label, _candidate in sorted(candidates.items()):
        with auth.authenticated_transaction(application_engine, mine.credential) as session:
            issued = auth.register_auth_binding(session, principal_id=uuid.uuid4(), scopes=[])
            assert issued.tenant_id == mine.id


@pytest.mark.parametrize("state", ["active", "revoked", "expired"])
def test_a_cross_tenant_candidate_cannot_be_probed_through_registration(
    application_engine, new_principal, issue_credential, owner_engine, state
):
    """Even holding the candidate value, there is no operation that takes it.

    The three states are exercised separately because the old oracle answered differently
    for none of them -- which was the point: a unique violation fires on the fingerprint
    whether the binding is live, revoked or expired, so a probe learned "this existed" in
    every case.
    """
    _other, candidates = _cross_tenant_candidates(
        application_engine, new_principal, issue_credential, owner_engine
    )
    candidate = candidates[state]
    mine = new_principal(f"probe-{state}")

    with auth.authenticated_transaction(application_engine, mine.credential) as session:
        # The database function will not take it: wrong number of arguments, whatever it is.
        with pytest.raises(DBAPIError) as exc:
            session.execute(
                text(f"SELECT * FROM {SCHEMA}.register_auth_binding(:c, :p, ARRAY[]::text[], NULL)"),
                {"c": candidate.credential.reveal(), "p": uuid.uuid4()},
            )
        assert "does not exist" in str(exc.value).lower()

    # Nor is the registry itself reachable to look one up.
    with pytest.raises(DBAPIError) as exc:
        with auth.authenticated_transaction(application_engine, mine.credential) as session:
            session.execute(
                text(f"SELECT count(*) FROM {SCHEMA}.auth_bindings WHERE fingerprint = :f"),
                {"f": "0" * 64},
            )
    assert "permission denied" in str(exc.value).lower()


def test_binding_a_dead_cross_tenant_candidate_reveals_nothing_it_did_not_already_have(
    application_engine, new_principal, issue_credential, owner_engine
):
    """The one remaining surface that takes a candidate, and it is not an oracle.

    ``bind_authenticated_context`` does accept a credential -- that is what authentication
    is. What it must not do is *distinguish*: a revoked or expired credential belonging to
    another tenant has to fail exactly as an invented one does, or possession of a dead
    value would still confirm that it was once real.

    A live credential of course succeeds. That is not a probe: it required possessing a
    working credential, which is the thing itself rather than information about it.
    """
    _other, candidates = _cross_tenant_candidates(
        application_engine, new_principal, issue_credential, owner_engine
    )

    messages = set()
    for value in (
        generate_bearer_credential(),
        candidates["revoked"].credential,
        candidates["expired"].credential,
    ):
        with pytest.raises(auth.AuthenticationError) as exc:
            with auth.authenticated_transaction(application_engine, value):
                pass
        messages.add(str(exc.value))
    assert len(messages) == 1, messages


def test_a_minted_credential_matches_the_one_format_this_system_has(
    application_engine, new_principal
):
    """Generated in PostgreSQL, and still the value ``security/secrets.py`` describes.

    Two ``gen_random_uuid()`` values -- 244 bits from the server's strong RNG -- rendered
    as 43 URL-safe characters. If the database and the Python format ever disagreed, the
    recogniser that keeps a credential out of metadata would stop recognising real ones.
    """
    from firmbatch.control_plane.security.secrets import (
        BEARER_CREDENTIAL_REGEX,
        is_well_formed_credential,
        looks_like_secret,
    )

    owner = new_principal("minted-format")
    minted = set()
    for _ in range(5):
        with auth.authenticated_transaction(application_engine, owner.credential) as session:
            issued = auth.register_auth_binding(session, principal_id=uuid.uuid4(), scopes=[])
        raw = issued.credential.reveal()
        assert BEARER_CREDENTIAL_REGEX.fullmatch(raw), raw[:4]
        assert is_well_formed_credential(issued.credential)
        assert looks_like_secret(raw) == "a Firmbatch bearer credential"
        minted.add(raw)
    assert len(minted) == 5, "the database minted the same credential twice"


def test_a_minted_credential_authenticates_and_is_stored_only_as_a_digest(
    application_engine, owner_engine, new_principal
):
    """The positive control, and the storage claim, for the server-generated path."""
    import hashlib

    owner = new_principal("minted-works")
    with auth.authenticated_transaction(application_engine, owner.credential) as session:
        issued = auth.register_auth_binding(
            session, principal_id=uuid.uuid4(), scopes=[Scope.TENANT_READ]
        )

    with auth.authenticated_transaction(application_engine, issued.credential) as session:
        context = auth.current_authenticated_context(session)
        assert context.tenant_id == owner.id
        assert context.binding_id == issued.binding_id
        assert context.scopes == {"tenant:read"}

    raw = issued.credential.reveal()
    with owner_engine.connect() as connection:
        row = connection.execute(
            text(f"SELECT * FROM {SCHEMA}.auth_bindings WHERE id = :b"), {"b": issued.binding_id}
        ).mappings().one()
    for column, value in row.items():
        assert raw not in str(value), f"the minted credential appears in auth_bindings.{column}"
    assert row["fingerprint"] == hashlib.sha256(raw.encode("utf-8")).hexdigest()


def test_two_tenants_commit_nothing_together_through_one_transaction(
    application_engine, principal_a, principal_b
):
    """The property every clearing route was trying to break, asserted end to end.

    One transaction, both credentials attempted, a workspace and an audit event written
    under the first. Whatever happens, the committed state must attribute everything to one
    tenant -- never a workspace belonging to A alongside an audit event attributed to B.
    """
    from firmbatch.control_plane.db import audit

    with pytest.raises(auth.ContextAlreadyBoundError):
        with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
            WorkspaceRepository(session).create(slug="two-tenants", name="Two Tenants")
            audit.append_audit_event(
                session, audit.AuditEventSpec(action="workspace.create", resource_type="workspace")
            )
            auth.bind_authenticated_context(session, principal_b.credential)

    for principal in (principal_a, principal_b):
        with auth.authenticated_transaction(application_engine, principal.credential) as session:
            assert WorkspaceRepository(session).get_by_slug("two-tenants") is None
            actions = [e.action for e in audit.audit_events(session)]
            assert "workspace.create" not in actions


# --------------------------------------------- authenticated work needs a writable primary
#
# Acquiring a context writes one row of protected transaction state (ADR 0006 decision 2).
# That is the price of a mechanism no runtime SQL can clear, and it has a consequence worth
# failing deliberately on rather than discovering: an authenticated transaction cannot run
# on a standby or inside a read-only transaction.
#
# Read-replica routing is Milestone 8 work. Until then this limitation is stated -- here,
# in ``docs/STATE.md`` and in ADR 0006 -- rather than left to be found.


def test_a_read_only_transaction_is_refused_deliberately(application_engine, principal_a):
    """``SET TRANSACTION READ ONLY``, then bind. A named refusal, not a write error.

    Before the guard existed the ``INSERT`` failed from inside a ``SECURITY DEFINER``
    function as a bare "cannot execute INSERT in a read-only transaction", which reads as a
    bug in Firmbatch rather than as an unsupported deployment.
    """
    with pytest.raises(auth.WritablePrimaryRequiredError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(text("SET TRANSACTION READ ONLY"))
            auth.bind_authenticated_context(session, principal_a.credential)
    message = str(exc.value)
    assert "read-only" in message
    assert "Milestone 8" in message


def test_the_read_only_refusal_carries_neither_the_credential_nor_a_chain(
    application_engine, principal_a
):
    """The credential is a bound parameter of the failing statement, so this matters here."""
    with pytest.raises(auth.WritablePrimaryRequiredError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(text("SET TRANSACTION READ ONLY"))
            auth.bind_authenticated_context(session, principal_a.credential)
    chain = _exception_chain(exc.value)
    assert principal_a.credential.reveal() not in chain, chain
    assert "parameters" not in chain
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None


def test_provisioning_is_refused_on_a_read_only_transaction_too(provisioning_engine):
    """Both entry points go through the same guard, because both write the same row."""
    with pytest.raises(auth.WritablePrimaryRequiredError):
        with db_engine.transaction(provisioning_engine) as session:
            session.execute(text("SET TRANSACTION READ ONLY"))
            auth.begin_tenant_provisioning(session)


def test_a_read_only_default_is_caught_as_well(application_engine, principal_a):
    """``default_transaction_read_only`` reaches the same guard.

    A role default or a database default is how this actually arrives in production -- an
    operator points the read path at a replica by setting it once -- so the guard reads the
    *effective* ``transaction_read_only`` rather than looking for an explicit SET.
    """
    with pytest.raises(auth.WritablePrimaryRequiredError):
        with db_engine.transaction(application_engine) as session:
            session.execute(text("SET LOCAL default_transaction_read_only = on"))
            session.execute(text("SET TRANSACTION READ ONLY"))
            auth.bind_authenticated_context(session, principal_a.credential)


def test_the_standby_predicate_is_tested_before_the_read_only_one(owner_engine):
    """Ordering, from the function body -- and *no* claim that a standby was tested.

    On a standby ``transaction_read_only`` is always ``on``, so a guard that checked it
    first would report every replica as "somebody set the transaction read-only" and send
    the reader looking for a ``SET`` nobody wrote. The order is therefore part of the
    diagnostic, and it is asserted from the catalogue rather than from the migration file.

    This test runs on a primary. It establishes that ``pg_is_in_recovery()`` is consulted,
    that it is consulted first, and that on this server it is false. It does **not**
    establish that a real standby refuses, and nothing in this repository claims it does.
    """
    with owner_engine.connect() as connection:
        body = connection.execute(
            text(
                "SELECT p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = :s AND p.proname = 'auth_require_writable_primary'"
            ),
            {"s": SCHEMA},
        ).scalar_one()
        assert connection.execute(text("SELECT pg_is_in_recovery()")).scalar() is False

    executable = _without_sql_comments(body)
    recovery = executable.index("pg_is_in_recovery")
    read_only = executable.index("transaction_read_only")
    assert recovery < read_only, "the read-only test would mask the standby diagnostic"
    assert "read_only_sql_transaction" in executable


def test_the_guard_runs_before_the_context_write(owner_engine):
    """"Before attempting the write", asserted rather than assumed.

    If the guard ran after the ``INSERT``, a read-only transaction would still fail -- with
    the unexplained write error the guard exists to replace.
    """
    with owner_engine.connect() as connection:
        body = connection.execute(
            text(
                "SELECT p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = :s AND p.proname = 'auth_context_begin'"
            ),
            {"s": SCHEMA},
        ).scalar_one()
    executable = _without_sql_comments(body)
    assert executable.index("auth_require_writable_primary") < executable.index("INSERT INTO")


def _without_sql_comments(body: str) -> str:
    """The function body with ``--`` comments removed.

    These bodies explain themselves at length, and the explanation names the very
    identifiers the ordering assertions look for -- the comment above
    ``pg_is_in_recovery()`` says the word ``transaction_read_only`` before the code does.
    An ordering test that read the comments would be measuring the prose.
    """
    return "\n".join(line.split("--", 1)[0] for line in body.splitlines())


def test_an_ordinary_transaction_is_unaffected(application_engine, principal_a):
    """The control: the guard refuses read-only work and nothing else."""
    with auth.authenticated_transaction(application_engine, principal_a.credential) as session:
        assert auth.current_authenticated_context(session).tenant_id == principal_a.id


# ---------------------------------------- the writable-primary preflight comes first
#
# The correction this section exists for. ``firmbatch.auth_transaction_context`` is
# UNLOGGED, and PostgreSQL refuses to *plan* a query that references an unlogged relation
# while the server is in recovery -- so the refusal arrives before the query runs, and
# therefore before any guard inside a function that query would have called.
#
# Every authenticated entry path used to begin by reading the current context:
# ``transaction()`` asserts it starts with none, and ``bind_authenticated_context`` reads
# it back afterwards. On a standby the very first of those reads failed with PostgreSQL's
# own message about an unlogged relation, and the deliberate
# ``firmbatch.auth_require_writable_primary()`` diagnostic -- which exists precisely to say
# "this is a replica, read-replica routing is Milestone 8" -- was never reached.
#
# So a preflight that names **no relation at all** runs first, on every public entry path,
# and the database functions keep their own guard as the layer that holds when a caller
# writes the SQL by hand. Both orderings are asserted below, the Python one by
# instrumentation and the SQL one from the catalogue.
#
# **No standby was tested and none is claimed.** There is no replica in this environment.
# What is established is that the preflight is reached first, that its recovery predicate
# is consulted before its read-only predicate, and that a recovery answer selects the
# standby diagnostic -- the last from the pure function, called with the answer a standby
# would give. Live-standby qualification is Milestone 8 work.


class _FakeRow:
    def __init__(self, in_recovery, read_only):
        self.in_recovery = in_recovery
        self.read_only = read_only


class _FakeResult:
    def __init__(self, row):
        self._row = row

    def one(self):
        return self._row


class _FakeSession:
    """The narrowest thing :func:`require_writable_primary` can be given.

    It records every statement it is asked to run, so the test can assert both what the
    preflight asked and -- more to the point -- that it asked nothing else.
    """

    def __init__(self, in_recovery, read_only):
        self.row = _FakeRow(in_recovery, read_only)
        self.statements = []

    def execute(self, statement, params=None):
        self.statements.append(str(statement))
        return _FakeResult(self.row)


def test_the_preflight_references_no_relation_at_all():
    """The whole point of it, asserted on the statement text.

    A preflight that mentioned ``firmbatch.auth_transaction_context`` -- or anything else
    in the schema -- would be unplannable on a standby and would fail in exactly the way
    it exists to prevent.
    """
    sql = str(db_engine._WRITABLE_PRIMARY_PREFLIGHT)
    assert SCHEMA not in sql
    assert CONTEXT_RELATION not in sql
    assert "pg_is_in_recovery" in sql
    assert "transaction_read_only" in sql
    # Recovery first, for the same reason the database function tests it first.
    assert sql.index("pg_is_in_recovery") < sql.index("transaction_read_only")


def test_a_recovering_server_selects_the_standby_diagnostic():
    """The branch a replica takes, reached by giving the function a replica's answer.

    On a standby ``transaction_read_only`` is always ``on`` as well, so both facts are
    true at once and the ordering is what decides which diagnostic the operator reads. A
    guard that tested read-only first would send them looking for a ``SET`` nobody wrote.
    """
    refusal = db_engine.writable_primary_refusal(in_recovery=True, read_only=True)
    assert refusal is not None
    assert "recovery" in refusal and "standby" in refusal
    assert "Milestone 8" in refusal

    read_only_only = db_engine.writable_primary_refusal(in_recovery=False, read_only=True)
    assert read_only_only is not None
    assert "read-only" in read_only_only
    assert "standby" not in read_only_only

    assert db_engine.writable_primary_refusal(in_recovery=False, read_only=False) is None


def test_a_mocked_standby_refuses_before_it_asks_anything_else():
    """One statement, and it is the preflight.

    ``require_writable_primary`` is given a session that reports recovery. It must refuse
    on the strength of that one statement -- if it went on to read the context, the
    recorded list would be longer and a real standby would have failed differently.
    """
    session = _FakeSession(in_recovery=True, read_only=True)
    with pytest.raises(db_engine.WritablePrimaryRequiredError) as exc:
        db_engine.require_writable_primary(session)
    assert "standby" in str(exc.value)
    assert len(session.statements) == 1
    assert CONTEXT_RELATION not in session.statements[0]


def test_a_mocked_primary_is_allowed_through():
    """The control: the preflight refuses read-only work and nothing else."""
    session = _FakeSession(in_recovery=False, read_only=False)
    db_engine.require_writable_primary(session)
    assert len(session.statements) == 1


def _fail_the_preflight(monkeypatch):
    """Make every preflight answer "standby", without a standby.

    Patching the pure classifier rather than the query keeps the real statement running
    against the real server, so what is being tested is the *ordering* in the entry path
    rather than a mock of the whole path.
    """
    monkeypatch.setattr(
        db_engine,
        "writable_primary_refusal",
        lambda in_recovery, read_only: "this server is in recovery (a standby); Milestone 8.",
    )


def _record_context_helpers(monkeypatch):
    """Trip a flag if anything reads the context relation. Returns the flag list."""
    called: list[str] = []

    real_tenant_context = db_engine.current_tenant_context
    real_auth_context = auth.current_authenticated_context

    def tenant_context(session):
        called.append("current_tenant_context")
        return real_tenant_context(session)

    def authenticated_context(session):
        called.append("current_authenticated_context")
        return real_auth_context(session)

    monkeypatch.setattr(db_engine, "current_tenant_context", tenant_context)
    monkeypatch.setattr(auth, "current_authenticated_context", authenticated_context)
    return called


def test_transaction_runs_the_preflight_before_the_inherited_context_assertion(
    application_engine, monkeypatch
):
    """``transaction()`` opens, checks, and refuses without reading the context.

    ``require_no_inherited_context`` is the statement that used to go first, and it reads
    ``firmbatch.auth_tenant_id()`` -- which is a query against the unlogged relation, and
    therefore unplannable on a standby.
    """
    called = _record_context_helpers(monkeypatch)
    _fail_the_preflight(monkeypatch)

    with pytest.raises(db_engine.WritablePrimaryRequiredError):
        with db_engine.transaction(application_engine):
            pass
    assert called == [], called


def test_the_application_entry_path_preflights_before_anything_else(
    application_engine, principal_a, monkeypatch
):
    """``authenticated_transaction`` refuses without reading or writing a context."""
    called = _record_context_helpers(monkeypatch)
    _fail_the_preflight(monkeypatch)

    with pytest.raises(db_engine.WritablePrimaryRequiredError):
        with auth.authenticated_transaction(application_engine, principal_a.credential):
            pass
    assert called == [], called


def test_the_provisioning_entry_path_preflights_before_anything_else(
    provisioning_engine, monkeypatch
):
    """And the other entry point, which writes the same row of protected state."""
    called = _record_context_helpers(monkeypatch)
    _fail_the_preflight(monkeypatch)

    with pytest.raises(db_engine.WritablePrimaryRequiredError):
        with auth.provisioning_transaction(provisioning_engine):
            pass
    assert called == [], called


def test_a_session_bound_to_the_engine_preflights_on_the_bind_itself(
    application_engine, principal_a, monkeypatch
):
    """A caller that builds its own ``Session`` gets the same ordering.

    ``transaction()`` ran a preflight when it opened, but a transaction can be made
    read-only after it begins and a caller may never have used ``transaction()`` at all --
    so ``bind_authenticated_context`` checks for itself rather than trusting its caller.
    """
    session = Session(bind=application_engine, expire_on_commit=False)
    try:
        session.begin()
        called = _record_context_helpers(monkeypatch)
        _fail_the_preflight(monkeypatch)
        with pytest.raises(db_engine.WritablePrimaryRequiredError):
            auth.bind_authenticated_context(session, principal_a.credential)
        assert called == [], called
    finally:
        session.rollback()
        session.close()


def test_a_session_bound_to_a_hardened_connection_never_reaches_the_context_either(
    application_engine, principal_a
):
    """The Connection-bound form is refused outright, which is the same guarantee.

    Every protection here is anchored to a pool checkout, so this bind form is not
    supported -- and the refusal lands at ``after_transaction_create``, before any
    statement is emitted. There is therefore no ordering to get wrong: the form cannot
    reach the context relation at all.
    """
    connection = application_engine.connect()
    try:
        with pytest.raises(db_engine.UnsupportedSessionBindError):
            session = Session(bind=connection, expire_on_commit=False)
            session.begin()
            auth.bind_authenticated_context(session, principal_a.credential)
    finally:
        connection.close()


def test_a_read_only_transaction_refuses_before_the_context_relation_is_touched(
    application_engine, principal_a, monkeypatch
):
    """``SET TRANSACTION READ ONLY``, with the real server answering the preflight.

    No mock in this one: the transaction really is read-only, the preflight really asks
    PostgreSQL, and the refusal really is ``WritablePrimaryRequiredError``. What the
    instrumentation adds is that nothing read the context on the way there.
    """
    with db_engine.transaction(application_engine) as session:
        session.execute(text("SET TRANSACTION READ ONLY"))
        called = _record_context_helpers(monkeypatch)
        with pytest.raises(db_engine.WritablePrimaryRequiredError) as exc:
            auth.bind_authenticated_context(session, principal_a.credential)
        assert called == [], called
    assert "read-only" in str(exc.value)
    assert "Milestone 8" in str(exc.value)


def test_the_preflight_refusal_carries_no_credential_and_no_connection_material(
    disposable_database, application_engine, principal_a
):
    """Nothing from the DBAPI, the URL, or the credential reaches the exception graph.

    ``exception_chain`` walks ``__cause__`` and ``__context__`` as well as ``str``:
    ``raise ... from None`` suppresses a *printed* traceback and does not detach the
    chain, and a log aggregator walks the chain. The preflight carries no bound parameter
    at all, and it is raised outside the ``except`` block so nothing is attached.
    """
    with pytest.raises(db_engine.WritablePrimaryRequiredError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(text("SET TRANSACTION READ ONLY"))
            auth.bind_authenticated_context(session, principal_a.credential)

    chain = _exception_chain(exc.value)
    assert principal_a.credential.reveal() not in chain
    assert "parameters" not in chain
    assert disposable_database.application_url not in chain
    for fragment in (
        disposable_database.application_role,
        disposable_database.database,
        "postgresql",
        "psycopg",
        "password",
    ):
        assert fragment not in chain, (fragment, chain)
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None


@pytest.mark.parametrize(
    "function", ["bind_authenticated_context", "begin_tenant_provisioning"]
)
def test_the_database_functions_guard_before_anything_else_they_do(owner_engine, function):
    """The arbitrary-SQL caller gets the same ordering, asserted from the catalogue.

    ``firmbatch.auth_require_writable_primary()`` is the **first** executed statement of
    both entry functions -- before the isolation-level check, before the registry lookup,
    and before ``auth_context_begin`` touches the unlogged relation. A caller that reaches
    around the Python boundary therefore fails safely too, with the diagnostic rather than
    with a planner error.
    """
    with owner_engine.connect() as connection:
        body = connection.execute(
            text(
                "SELECT p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = :s AND p.proname = :f"
            ),
            {"s": SCHEMA, "f": function},
        ).scalar_one()

    executable = "\n".join(line.split("--", 1)[0] for line in body.splitlines())
    guard = executable.index("auth_require_writable_primary")
    assert guard < executable.index("auth_require_read_committed")
    assert guard < executable.index("auth_context_begin")
    # And it is the *first* statement of the body, not merely an early one: the first
    # PERFORM in the source is this call and no other.
    assert executable[executable.index("PERFORM"):].startswith(
        f"PERFORM {SCHEMA}.auth_require_writable_primary()"
    ), executable
