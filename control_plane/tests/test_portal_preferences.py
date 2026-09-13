"""Workspace preferences and consent: isolation, the mutation boundary, and derived consent.

Milestone 3.2's one new relation, against real PostgreSQL 16. What is asserted here is not
that the CRUD works -- that is the least of it -- but that the relation is on the isolation
model every other customer table is on; that **the only way a runtime role writes it is
through the two ``SECURITY DEFINER`` mutation functions**, which require a CSRF-verified
session, re-derive the membership under the workspace lock, check the workspace the page
expected against the one the session is bound to, decide no-op or transition under that lock,
and write the row and its audit event together; and that the two consent columns a caller
must not be able to state are stated by the database instead.

The concurrency cases use the same choreography as ``test_identity_concurrency.py``: one
transaction pauses holding a lock, the other is proven to be waiting on it through
``pg_locks``, and the outcome is asserted after both finish.
"""

from __future__ import annotations

import re
import uuid
from contextlib import contextmanager

import pytest
from psycopg.errors import CheckViolation, ForeignKeyViolation, InsufficientPrivilege
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from firmbatch.control_plane.db import accounts, membership, preferences
from firmbatch.control_plane.db.audit import audit_events
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.models import (
    CONSENT_VERSIONS,
    EVALUATION_INTENTS,
    MODEL_PROFILE_NOTE_MAX_LENGTH,
    PROVIDER_CLASSES,
    REGION_GROUPS,
)
from firmbatch.control_plane.db.roles import PORTAL_APPLICATION_FUNCTIONS
from firmbatch.control_plane.security.authorization import RULES_BY_TABLE, AuthorizationError, Scope
from firmbatch.control_plane.tests.identity_helpers import (
    account_session,
    bind,
    create_workspace,
    invite_and_accept,
    owner_with_workspace,
    person,
    workspace_session,
)
from firmbatch.control_plane.tests.test_identity_concurrency import (
    BLOCK_TIMEOUT_SECONDS,
    _join,
    _Race,
    _thread,
    _unwrap,
    _wait_for_a_blocked_backend,
)

CURRENT_CONSENT = CONSENT_VERSIONS[0]

STATE_STATEMENT = (
    f"SELECT workspace_id FROM {SCHEMA}.state_workspace_preferences("
    ":w, CAST(:regions AS text[]), CAST(:excluded AS text[]), :note, :intent)"
)
ACKNOWLEDGE_STATEMENT = (
    f"SELECT workspace_id FROM {SCHEMA}.acknowledge_workspace_consent(:w, :version)"
)


# --------------------------------------------------------------------------- the catalogue


def test_the_relation_is_policed_like_every_other_customer_table():
    rule = RULES_BY_TABLE["workspace_preferences"]
    assert rule.kind == "customer"
    assert rule.tenant_column == "tenant_id"
    assert rule.read == (Scope.WORKSPACE_READ,)
    assert rule.write == (Scope.WORKSPACE_WRITE,)
    assert rule.scope_source == "catalogue"
    # Not protected: it carries no secret and gates nothing, so it gets the ordinary
    # tenant-and-scope predicate rather than the identity plane's no-grants treatment.
    assert rule.kind != "protected"


def test_row_security_is_enabled_and_forced(owner_engine):
    with owner_engine.connect() as connection:
        enabled, forced = connection.execute(
            text(
                "SELECT c.relrowsecurity, c.relforcerowsecurity FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = :s AND c.relname = 'workspace_preferences'"
            ),
            {"s": SCHEMA},
        ).one()
    assert enabled is True
    # FORCE is what makes "no policy for this command" mean "no row for anybody", the owner
    # included -- and what makes the INSERT and UPDATE policies evaluate inside the two
    # definer functions, which run as the owner.
    assert forced is True


def test_the_application_role_holds_select_alone_and_the_relation_keeps_its_three_policies(
    owner_engine, disposable_database
):
    """The privilege change the review required, from the catalogue.

    ``SELECT`` is the one table privilege the application role holds: it reads the row under
    the ``SELECT`` policy. Every write goes through ``state_workspace_preferences`` or
    ``acknowledge_workspace_consent``; a statement the role writes itself is refused at
    permission-check time, before any policy or trigger is reached. The ``INSERT`` and
    ``UPDATE`` policies stay, because ``FORCE`` binds the owner those functions run as, and
    there is still no ``DELETE`` policy and no ``DELETE`` grant.
    """
    with owner_engine.connect() as connection:
        commands = {
            row[0]
            for row in connection.execute(
                text(
                    "SELECT p.polcmd FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = :s AND c.relname = 'workspace_preferences'"
                ),
                {"s": SCHEMA},
            )
        }
        privileges = {
            row[0]
            for row in connection.execute(
                text(
                    "SELECT privilege_type FROM information_schema.role_table_grants "
                    "WHERE table_schema = :s AND table_name = 'workspace_preferences' "
                    "AND grantee = :role"
                ),
                {"s": SCHEMA, "role": disposable_database.application_role},
            )
        }
        column_privileges = connection.execute(
            text(
                "SELECT count(*) FROM information_schema.role_column_grants "
                "WHERE table_schema = :s AND table_name = 'workspace_preferences' "
                "AND grantee = :role AND privilege_type <> 'SELECT'"
            ),
            {"s": SCHEMA, "role": disposable_database.application_role},
        ).scalar_one()
    # r = SELECT, a = INSERT, w = UPDATE. No 'd'.
    assert commands == {"r", "a", "w"}
    assert privileges == {"SELECT"}
    assert column_privileges == 0


# --------------------------------------------------------------------------- owner access
#
# ``FORCE ROW LEVEL SECURITY`` binds the schema owner too, which is the property
# ``test_row_security_is_enabled_and_forced`` asserts -- so an owner ``INSERT`` with no
# authenticated context is refused by the **policy**, before a check constraint or a foreign
# key is ever evaluated. That is the right behaviour and it is stronger than the constraints
# themselves; it also means a test that wants to prove a *constraint* binds has to reach the
# table with the policy briefly out of the way.
#
# Lifting ``FORCE`` for one statement and restoring it immediately is the device migration
# ``0005``'s own downgrade uses, for the same reason. It runs as the schema owner inside a
# test against a disposable database, it is restored in a ``finally``, and
# ``test_row_security_is_enabled_and_forced`` re-asserts the steady state.


@contextmanager
def owner_bypassing_force(owner_engine):
    """One connection that can reach ``workspace_preferences`` as the owner. Restores FORCE."""
    with owner_engine.connect() as connection:
        connection.execute(text(f"ALTER TABLE {SCHEMA}.workspace_preferences NO FORCE ROW LEVEL SECURITY"))
        connection.commit()
        try:
            yield connection
        finally:
            connection.rollback()
            connection.execute(text(f"ALTER TABLE {SCHEMA}.workspace_preferences FORCE ROW LEVEL SECURITY"))
            connection.commit()


@contextmanager
def injected_failure(owner_engine, table: str, *, when: str):
    """A trigger, installed by the schema owner, that makes every qualifying write fail.

    The device behind the two atomicity tests: the only way to make one half of a
    function's work fail on purpose is to make the database refuse it, and a trigger that
    raises is exactly that. Installed and removed by the owner inside the disposable
    database, removed in a ``finally``, and named so a leak would be obvious.
    """
    function = f"{SCHEMA}.zz_test_injected_failure"
    trigger = "zz_test_injected_failure"
    with owner_engine.connect() as connection:
        connection.execute(
            text(
                f"CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql "
                "SET search_path = pg_catalog AS $f$ BEGIN "
                "RAISE EXCEPTION 'firmbatch test: injected failure' USING ERRCODE = 'internal_error'; "
                "END $f$"
            )
        )
        connection.execute(
            text(
                f"CREATE TRIGGER {trigger} {when} ON {SCHEMA}.{table} "
                f"FOR EACH ROW EXECUTE FUNCTION {function}()"
            )
        )
        connection.commit()
        try:
            yield
        finally:
            connection.rollback()
            connection.execute(text(f"DROP TRIGGER IF EXISTS {trigger} ON {SCHEMA}.{table}"))
            connection.execute(text(f"DROP FUNCTION IF EXISTS {function}()"))
            connection.commit()


def preference_rows(owner_engine, workspace_id: uuid.UUID | None = None) -> list:
    """The relation's rows as they are stored. ``FORCE`` binds the owner too, so a plain
    owner read with no context sees nothing; this lifts it for one read and restores it."""
    with owner_bypassing_force(owner_engine) as connection:
        return (
            connection.execute(
                text(
                    f"SELECT * FROM {SCHEMA}.workspace_preferences "
                    "WHERE CAST(:w AS uuid) IS NULL OR workspace_id = :w ORDER BY created_at"
                ),
                {"w": workspace_id},
            )
            .mappings()
            .all()
        )


def _events(session, action: str, workspace_id: uuid.UUID) -> list:
    return [
        event
        for event in audit_events(session, limit=200)
        if event.action == action and event.resource_id == workspace_id
    ]


# --------------------------------------------------------------------------- reading


def test_a_workspace_that_stated_nothing_reads_as_the_empty_statement(application_engine, owner_engine):
    who, created = owner_with_workspace(application_engine, "prefs-empty")
    with workspace_session(application_engine, who) as (session, _context):
        row = preferences.read(session, created.workspace_id)
    # No row exists, and the caller cannot tell: absence and "stated nothing" are the same
    # answer, so a client never has to distinguish them.
    assert row.region_policy == ()
    assert row.excluded_provider_classes == ()
    assert row.evaluation_intent == "undecided"
    assert row.consent_version is None
    assert row.updated_at is None
    assert preference_rows(owner_engine, created.workspace_id) == []


def test_a_viewer_may_read_and_may_not_write(application_engine):
    owner, created = owner_with_workspace(application_engine, "prefs-viewer")
    viewer = person(application_engine, "viewer")
    invite_and_accept(application_engine, owner, viewer, role="viewer")
    with account_session(application_engine, viewer) as (session, _context):
        membership.bind_session_workspace(session, created.workspace_id)

    with workspace_session(application_engine, viewer) as (session, _context):
        assert preferences.read(session, created.workspace_id).evaluation_intent == "undecided"

    with pytest.raises(AuthorizationError) as exc:
        with workspace_session(application_engine, viewer) as (session, _context):
            preferences.state(session, created.workspace_id, evaluation_intent="undecided")
    # Refused inside the function, by name: the session never gets far enough to write, and
    # the refusal names the missing capability rather than the row.
    assert "workspace:write" in str(exc.value)


# --------------------------------------------------------------------------- writing


def test_stating_a_policy_persists_it_and_appends_one_audit_event(application_engine):
    who, created = owner_with_workspace(application_engine, "prefs-state")
    with workspace_session(application_engine, who) as (session, _context):
        stated = preferences.state(
            session,
            created.workspace_id,
            region_policy=["EU"],
            excluded_provider_classes=["google", "amazon"],
            model_profile_note="  Qwen3-8B on vllm-fp8  ",
            evaluation_intent="planning_evaluation",
        )
        events = _events(session, "workspace.preferences_stated", created.workspace_id)

    assert stated.region_policy == ("EU",)
    # Sorted and deduplicated on the way in, so the stored array is canonical.
    assert stated.excluded_provider_classes == ("amazon", "google")
    assert stated.model_profile_note == "Qwen3-8B on vllm-fp8"
    assert stated.evaluation_intent == "planning_evaluation"
    assert stated.unservable_exclusion is True

    assert len(events) == 1
    # Bounded metadata about what was stated, never the customer's own free text: an
    # immutable trail is the wrong place for a field somebody can type anything into.
    assert events[0].details["region_policy"] == ["EU"]
    assert events[0].details["excluded_provider_classes"] == ["amazon", "google"]
    assert events[0].details["model_profile_note_present"] is True
    assert events[0].details["unservable_exclusion"] is True
    assert events[0].details["session_id"] == str(who.session_id)
    assert "model_profile_note" not in events[0].details
    # The actor columns are derived by the M2.3 audit function from the context the
    # session established, not stated by the mutation.
    assert events[0].actor_kind == "session"
    assert events[0].actor_principal_id == who.account_id
    assert events[0].resource_type == "workspace_preferences"
    assert events[0].outcome == "succeeded"


def test_stating_is_a_full_replacement_and_is_naturally_idempotent(application_engine, owner_engine):
    who, created = owner_with_workspace(application_engine, "prefs-replace")
    for _ in range(2):
        with workspace_session(application_engine, who) as (session, _context):
            preferences.state(
                session, created.workspace_id, region_policy=["EU"], evaluation_intent="undecided"
            )
    with workspace_session(application_engine, who) as (session, _context):
        after = preferences.state(session, created.workspace_id, evaluation_intent="undecided")
        events = _events(session, "workspace.preferences_stated", created.workspace_id)
    # The second call named no region, so the region is gone: PUT replaces, and that is why
    # it needs no idempotency key.
    assert after.region_policy == ()
    # Amended, never accumulated: three statements leave exactly one row.
    with owner_bypassing_force(owner_engine) as connection:
        count = connection.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.workspace_preferences WHERE workspace_id = :w"),
            {"w": created.workspace_id},
        ).scalar_one()
    assert count == 1
    # And the trail records the two transitions, not the repeat: re-stating the statement in
    # force is a true no-op that appends nothing.
    assert len(events) == 2


def test_re_stating_the_statement_in_force_changes_nothing_and_records_nothing(
    application_engine, owner_engine
):
    who, created = owner_with_workspace(application_engine, "prefs-noop")
    with workspace_session(application_engine, who) as (session, _context):
        first = preferences.state(
            session, created.workspace_id, region_policy=["EU"], model_profile_note="Qwen3-8B"
        )
    with workspace_session(application_engine, who) as (session, _context):
        # Equivalent, not identical: duplicates and whitespace normalise to the same statement.
        second = preferences.state(
            session, created.workspace_id, region_policy=["EU", "EU"], model_profile_note=" Qwen3-8B "
        )
        events = _events(session, "workspace.preferences_stated", created.workspace_id)
    assert second == first
    assert second.updated_at == first.updated_at
    assert len(events) == 1


def test_stating_the_empty_statement_on_a_silent_workspace_writes_no_row(
    application_engine, owner_engine
):
    who, created = owner_with_workspace(application_engine, "prefs-empty-write")
    with workspace_session(application_engine, who) as (session, _context):
        stated = preferences.state(session, created.workspace_id)
        events = _events(session, "workspace.preferences_stated", created.workspace_id)
    assert stated == preferences._default(created.workspace_id)
    assert preference_rows(owner_engine, created.workspace_id) == []
    assert events == []


@pytest.mark.parametrize(
    "kwargs",
    (
        {"region_policy": ["US"]},
        {"region_policy": ["EU", "MARS"]},
        {"excluded_provider_classes": ["oracle"]},
        {"evaluation_intent": "definitely"},
        {"model_profile_note": "x" * (MODEL_PROFILE_NOTE_MAX_LENGTH + 1)},
        {"region_policy": "EU"},
        {"region_policy": [None]},
        {"excluded_provider_classes": ["amazon"] * 40},
    ),
)
def test_a_value_outside_the_closed_vocabulary_is_refused(application_engine, kwargs):
    who, created = owner_with_workspace(application_engine, "prefs-closed")
    with pytest.raises(Exception) as exc:
        with workspace_session(application_engine, who) as (session, _context):
            preferences.state(session, created.workspace_id, **kwargs)
    # And the refusal never repeats the value, for the reason every refusal in this package
    # gives: a value in the wrong argument may be a secret.
    for value in kwargs.values():
        if isinstance(value, str) and len(value) > 3:
            assert value not in str(exc.value)


@pytest.mark.parametrize(
    "params",
    (
        {"regions": ["US"], "excluded": [], "note": None, "intent": "undecided"},
        {"regions": [], "excluded": ["oracle"], "note": None, "intent": "undecided"},
        {"regions": [], "excluded": [], "note": None, "intent": "definitely"},
        {"regions": [], "excluded": [], "note": "x" * (MODEL_PROFILE_NOTE_MAX_LENGTH + 1), "intent": "undecided"},
        {"regions": ["EU", None], "excluded": [], "note": None, "intent": "undecided"},
        {"regions": [], "excluded": ["amazon"] * 40, "note": None, "intent": "undecided"},
        {"regions": [], "excluded": [], "note": "fbk_" + "a" * 43, "intent": "undecided"},
    ),
)
def test_the_function_refuses_a_value_outside_the_vocabulary_without_python(
    application_engine, owner_engine, params
):
    """The Python checks are convenience; the function applies the rule to whatever it is handed."""
    who, created = owner_with_workspace(application_engine, "prefs-closed-sql")
    with pytest.raises(DBAPIError) as exc:
        with workspace_session(application_engine, who) as (session, _context):
            session.execute(text(STATE_STATEMENT), {"w": created.workspace_id, **params})
    assert exc.value.orig.sqlstate == "22023", exc.value.orig
    if isinstance(params["note"], str):
        assert params["note"] not in str(exc.value.orig)
    assert preference_rows(owner_engine, created.workspace_id) == []


def test_a_secret_shaped_note_is_refused_without_being_echoed(application_engine):
    who, created = owner_with_workspace(application_engine, "prefs-secret")
    secret = "fbk_" + "a" * 43
    with pytest.raises(Exception) as exc:
        with workspace_session(application_engine, who) as (session, _context):
            preferences.state(session, created.workspace_id, model_profile_note=secret)
    assert secret not in str(exc.value)


def test_the_check_constraints_bind_a_writer_that_reached_the_table_another_way(owner_engine, application_engine):
    """The Python bounds are convenience; these are the control.

    Attempted as the **schema owner**, with row security forced, so what refuses the row is
    the constraint rather than a policy, a function or a Python guard.
    """
    _who, created = owner_with_workspace(application_engine, "prefs-constraint")
    with owner_bypassing_force(owner_engine) as connection:
        for column, value in (
            ("region_policy", "ARRAY['US']::text[]"),
            ("excluded_provider_classes", "ARRAY['oracle']::text[]"),
            ("evaluation_intent", "'definitely'"),
            ("consent_version", "'made-up-v9'"),
        ):
            with pytest.raises(DBAPIError) as exc:
                connection.execute(
                    text(
                        f"INSERT INTO {SCHEMA}.workspace_preferences "
                        f"(workspace_id, tenant_id, {column}) "
                        f"VALUES (:w, :t, {value})"
                    ),
                    {"w": created.workspace_id, "t": created.tenant_id},
                )
            connection.rollback()
            assert isinstance(exc.value.orig, CheckViolation), column


def test_the_composite_key_refuses_a_workspace_from_another_tenant(owner_engine, application_engine):
    """The isolation control, tested where it actually binds.

    A foreign-key check bypasses row security, which is exactly why the reference is to the
    **pair**. A row naming one tenant's workspace and another's tenant id is not a policy
    question; it is a referential one, and it fails.
    """
    _first, first_ws = owner_with_workspace(application_engine, "prefs-tenant-a")
    _second, second_ws = owner_with_workspace(application_engine, "prefs-tenant-b")
    assert first_ws.tenant_id != second_ws.tenant_id
    with owner_bypassing_force(owner_engine) as connection:
        with pytest.raises(DBAPIError) as exc:
            connection.execute(
                text(
                    f"INSERT INTO {SCHEMA}.workspace_preferences (workspace_id, tenant_id) "
                    "VALUES (:w, :t)"
                ),
                {"w": first_ws.workspace_id, "t": second_ws.tenant_id},
            )
        connection.rollback()
    assert isinstance(exc.value.orig, ForeignKeyViolation)


# --------------------------------------------------------------------------- the boundary
#
# The independent Milestone 3.2 review's findings 2, 3, 4 and 9, each as a test that fails
# without the correction: the application role could INSERT and UPDATE the relation with a
# statement of its own; a read-bound (csrf=False) transaction could reach a write; the
# trigger was being treated as the authorization and audit boundary; and the row and its
# audit event were written by two separate statements.


@pytest.mark.parametrize(
    "statement",
    (
        f"INSERT INTO {SCHEMA}.workspace_preferences (workspace_id, tenant_id, region_policy) "
        f"VALUES (:w, {SCHEMA}.auth_tenant_id(), ARRAY['EU']::text[])",
        f"UPDATE {SCHEMA}.workspace_preferences SET region_policy = ARRAY['EU']::text[] WHERE workspace_id = :w",
        f"UPDATE {SCHEMA}.workspace_preferences SET consent_version = '{CURRENT_CONSENT}' WHERE workspace_id = :w",
        f"DELETE FROM {SCHEMA}.workspace_preferences WHERE workspace_id = :w",
    ),
)
def test_direct_dml_by_the_application_role_is_refused_even_from_a_write_bound_session(
    application_engine, owner_engine, statement
):
    """Finding 2: the relation is written through the functions or not at all.

    The session here is bound in workspace mode **with** its CSRF secret, as an owner, so
    every policy would admit the row. What refuses it is the absent table privilege, at
    permission-check time, before a policy or the trigger is reached -- which is what makes
    "no unaudited write" a fact about grants rather than about what a caller remembers.
    """
    who, created = owner_with_workspace(application_engine, "prefs-dml")
    with workspace_session(application_engine, who) as (session, _context):
        preferences.state(session, created.workspace_id, region_policy=["EU"])
    with pytest.raises(ProgrammingError) as exc:
        with workspace_session(application_engine, who) as (session, _context):
            session.execute(text(statement), {"w": created.workspace_id})
    assert isinstance(exc.value.orig, InsufficientPrivilege)
    assert "permission denied for table workspace_preferences" in str(exc.value.orig)
    (row,) = preference_rows(owner_engine, created.workspace_id)
    assert list(row["region_policy"]) == ["EU"]
    assert row["consent_version"] is None


def test_the_two_mutation_functions_are_the_application_role_s_and_nobody_else_s(
    owner_engine, disposable_database
):
    with owner_engine.connect() as connection:
        for name, signature in PORTAL_APPLICATION_FUNCTIONS:
            grantees = {
                grantee
                for (grantee,) in connection.execute(
                    text(
                        "SELECT pg_get_userbyid(acl.grantee) FROM pg_proc p "
                        "JOIN pg_namespace n ON n.oid = p.pronamespace "
                        "CROSS JOIN LATERAL aclexplode(p.proacl) acl "
                        "WHERE n.nspname = :s AND p.oid = to_regprocedure(:f) "
                        "AND acl.privilege_type = 'EXECUTE'"
                    ),
                    {"s": SCHEMA, "f": f"{SCHEMA}.{name}({signature})"},
                )
            }
            assert grantees == {disposable_database.owner_role, disposable_database.application_role}, (
                f"{name} is executable by {grantees}"
            )


def test_a_read_bound_session_cannot_mutate_through_the_functions(application_engine, owner_engine):
    """Finding 3: a transaction bound without its CSRF secret is a read transaction.

    Both mutation functions call ``identity_require_session('workspace', true)`` first, so a
    bind that never verified a CSRF token -- the transaction a ``GET`` opens -- cannot reach
    a write through either function, and cannot reach the table directly (above).
    """
    who, created = owner_with_workspace(application_engine, "prefs-readbound")
    for act in (
        lambda session: preferences.state(session, created.workspace_id, region_policy=["EU"]),
        lambda session: preferences.acknowledge_consent(session, created.workspace_id, version=CURRENT_CONSENT),
    ):
        with pytest.raises(accounts.SessionContextError) as exc:
            with workspace_session(application_engine, who, csrf=False) as (session, _context):
                act(session)
        assert "CSRF" in str(exc.value)
    # And with the Python layer out of the way: the function itself is what refuses.
    for statement, params in (
        (STATE_STATEMENT, {"regions": ["EU"], "excluded": [], "note": None, "intent": "undecided"}),
        (ACKNOWLEDGE_STATEMENT, {"version": CURRENT_CONSENT}),
    ):
        with pytest.raises(DBAPIError) as exc:
            with workspace_session(application_engine, who, csrf=False) as (session, _context):
                session.execute(text(statement), {"w": created.workspace_id, **params})
        assert exc.value.orig.sqlstate == accounts.IDENTITY_CONTEXT_SQLSTATE
    assert preference_rows(owner_engine, created.workspace_id) == []


def test_the_functions_derive_the_consent_actor_and_time_with_the_trigger_disabled(
    owner_engine, application_engine
):
    """Finding 4: the trigger is defence in depth, not the boundary.

    With the trigger disabled by the schema owner, an acknowledgement still records who and
    when -- the function derives both -- so the derivation does not depend on the trigger
    firing, and a row with an acknowledgement but no actor is unstorable either way.
    """
    who, created = owner_with_workspace(application_engine, "prefs-notrigger")
    with owner_engine.connect() as connection:
        connection.execute(
            text(f"ALTER TABLE {SCHEMA}.workspace_preferences DISABLE TRIGGER workspace_preferences_set_consent")
        )
        connection.commit()
    try:
        with workspace_session(application_engine, who) as (session, _context):
            acknowledged = preferences.acknowledge_consent(
                session, created.workspace_id, version=CURRENT_CONSENT
            )
        assert acknowledged.consent_version == CURRENT_CONSENT
        assert acknowledged.consent_account_id == who.account_id
        assert acknowledged.consent_acknowledged_at is not None
    finally:
        with owner_engine.connect() as connection:
            connection.execute(
                text(f"ALTER TABLE {SCHEMA}.workspace_preferences ENABLE TRIGGER workspace_preferences_set_consent")
            )
            connection.commit()


def test_the_audit_event_rolls_back_when_the_preference_write_fails(owner_engine, application_engine):
    """Finding 9, first half: the function appends the event and then writes the row; a row
    that cannot be written takes its event down with it."""
    who, created = owner_with_workspace(application_engine, "prefs-atomic-row")
    with injected_failure(owner_engine, "workspace_preferences", when="BEFORE INSERT OR UPDATE"):
        with pytest.raises(Exception) as exc:
            with workspace_session(application_engine, who) as (session, _context):
                preferences.state(session, created.workspace_id, region_policy=["EU"])
        assert "injected failure" in str(exc.value)
        with pytest.raises(Exception):
            with workspace_session(application_engine, who) as (session, _context):
                preferences.acknowledge_consent(session, created.workspace_id, version=CURRENT_CONSENT)
    assert preference_rows(owner_engine, created.workspace_id) == []
    with workspace_session(application_engine, who) as (session, _context):
        assert _events(session, "workspace.preferences_stated", created.workspace_id) == []
        assert _events(session, "workspace.consent_acknowledged", created.workspace_id) == []


def test_the_preference_write_rolls_back_when_the_audit_append_fails(owner_engine, application_engine):
    """Finding 9, second half: an event that cannot be appended leaves no row behind, and
    an existing row is left exactly as it was."""
    who, created = owner_with_workspace(application_engine, "prefs-atomic-event")
    with workspace_session(application_engine, who) as (session, _context):
        before = preferences.state(session, created.workspace_id, region_policy=["EU"])
    with injected_failure(owner_engine, "audit_events", when="BEFORE INSERT"):
        with pytest.raises(Exception) as exc:
            with workspace_session(application_engine, who) as (session, _context):
                preferences.state(session, created.workspace_id, region_policy=[], model_profile_note="changed")
        assert "injected failure" in str(exc.value)
        with pytest.raises(Exception):
            with workspace_session(application_engine, who) as (session, _context):
                preferences.acknowledge_consent(session, created.workspace_id, version=CURRENT_CONSENT)
    with workspace_session(application_engine, who) as (session, _context):
        after = preferences.read(session, created.workspace_id)
        stated = _events(session, "workspace.preferences_stated", created.workspace_id)
        acknowledged = _events(session, "workspace.consent_acknowledged", created.workspace_id)
    assert after == before
    assert len(stated) == 1
    assert acknowledged == []


def test_one_successful_mutation_produces_exactly_one_correct_audit_event(application_engine):
    who, created = owner_with_workspace(application_engine, "prefs-one-event")
    with workspace_session(application_engine, who) as (session, context):
        preferences.state(session, created.workspace_id, excluded_provider_classes=["verda"])
        preferences.acknowledge_consent(session, created.workspace_id, version=CURRENT_CONSENT)
        stated = _events(session, "workspace.preferences_stated", created.workspace_id)
        acknowledged = _events(session, "workspace.consent_acknowledged", created.workspace_id)
        everything = [
            e for e in audit_events(session, limit=200) if e.resource_type == "workspace_preferences"
        ]
    assert len(stated) == 1 and len(acknowledged) == 1 and len(everything) == 2
    for event in everything:
        assert event.actor_kind == "session"
        assert event.actor_principal_id == who.account_id
        assert event.outcome == "succeeded"
        assert event.details["session_id"] == str(context.session_id)
    assert stated[0].details["excluded_provider_classes"] == ["verda"]
    assert stated[0].details["unservable_exclusion"] is False
    assert acknowledged[0].details["consent_version"] == CURRENT_CONSENT
    assert acknowledged[0].details["superseded_version"] is None


def test_a_member_demoted_after_its_session_bound_is_refused_by_the_function(application_engine, owner_engine):
    """The membership as it is now, not as the bind cached it.

    The member's transaction binds -- caching ``workspace:write`` in its context -- and
    pauses; the owner demotes it to viewer and commits; the member's transaction then acts
    on the cached authority, and the function re-derives the role under the workspace lock
    and refuses.
    """
    owner, created = owner_with_workspace(application_engine, "prefs-demoted")
    member = person(application_engine, "member")
    accepted = invite_and_accept(application_engine, owner, member, role="member")
    bind(application_engine, member, created.workspace_id)

    paused, released, results = _threading_events()

    def stale():
        with workspace_session(application_engine, member) as (session, context):
            assert context.role == "member"
            paused.set()
            assert released.wait(timeout=BLOCK_TIMEOUT_SECONDS), "never released"
            return preferences.state(session, created.workspace_id, region_policy=["EU"])

    thread = _thread("stale", results, stale)
    thread.start()
    assert paused.wait(timeout=BLOCK_TIMEOUT_SECONDS), "the member never bound"
    with workspace_session(application_engine, owner) as (session, _context):
        membership.change_membership_role(session, accepted.membership_id, "viewer")
    released.set()
    _join((thread,))

    with pytest.raises(AuthorizationError):
        _unwrap(results["stale"])
    assert preference_rows(owner_engine, created.workspace_id) == []


def test_a_removal_that_overlaps_a_bound_session_waits_for_it_and_then_the_member_is_refused(
    application_engine, owner_engine
):
    """A revoked membership, in the shape it can actually take.

    A bound transaction holds its own session row (the bind stamps ``last_seen_at``), and
    the revocation cascade clears that row's binding -- so a removal cannot slip between a
    member's bind and its write; it waits, provably, and what the member wrote while it was
    still a member stands. The next transaction the member opens is refused outright, and
    so is a mutation attempted through the functions with the membership gone.
    """
    owner, created = owner_with_workspace(application_engine, "prefs-removed-race")
    member = person(application_engine, "member")
    accepted = invite_and_accept(application_engine, owner, member, role="member")
    bind(application_engine, member, created.workspace_id)
    race = _Race(application_engine)

    def member_states_and_holds():
        with workspace_session(application_engine, member) as (session, _context):
            stated = preferences.state(session, created.workspace_id, region_policy=["EU"])
            race.hold()
            return stated

    def owner_removes():
        with workspace_session(application_engine, owner) as (session, _context):
            return membership.remove_membership(session, accepted.membership_id)

    assert race.run(member_states_and_holds, owner_removes) is True, (
        "the removal must wait for the member's bound transaction"
    )
    assert _unwrap(race.results["winner"]).region_policy == ("EU",)
    _unwrap(race.results["loser"])

    with pytest.raises(accounts.IdentityError):
        with workspace_session(application_engine, member) as (session, _context):
            preferences.state(session, created.workspace_id, region_policy=[])
    (row,) = preference_rows(owner_engine, created.workspace_id)
    assert list(row["region_policy"]) == ["EU"]


def _threading_events():
    import threading

    return threading.Event(), threading.Event(), {}


# --------------------------------------------------------------------------- the expected binding
#
# Finding 1. Every mutation carries the workspace the page loaded its form for, and the
# function compares it with the workspace the session is bound to, under the workspace lock.


def _two_workspaces(application_engine, label: str):
    """One account owning two workspaces (two tenants), bound to the first."""
    who, first = owner_with_workspace(application_engine, label)
    second = create_workspace(application_engine, who)
    return who, first, second


def test_a_forged_a_cross_workspace_and_a_cross_tenant_identifier_are_one_refusal(
    application_engine, owner_engine
):
    who, first, second = _two_workspaces(application_engine, "prefs-forged")
    _stranger, foreign = owner_with_workspace(application_engine, "prefs-foreign")
    messages = set()
    for expected in (uuid.uuid4(), second.workspace_id, foreign.workspace_id):
        for act in (
            lambda session, w=expected: preferences.state(session, w, region_policy=["EU"]),
            lambda session, w=expected: preferences.acknowledge_consent(session, w, version=CURRENT_CONSENT),
        ):
            with pytest.raises(accounts.WorkspaceBindingMismatch) as exc:
                with workspace_session(application_engine, who) as (session, _context):
                    act(session)
            messages.add(str(exc.value))
            # Nothing about the identifier travels with the refusal.
            assert str(expected) not in str(exc.value)
    # One message for all three shapes: the refusal is not an existence oracle.
    assert len(messages) == 1
    assert preference_rows(owner_engine) == [] or all(
        row["workspace_id"] not in (first.workspace_id, second.workspace_id, foreign.workspace_id)
        for row in preference_rows(owner_engine)
    )
    with workspace_session(application_engine, who) as (session, _context):
        assert _events(session, "workspace.preferences_stated", first.workspace_id) == []
        assert _events(session, "workspace.consent_acknowledged", first.workspace_id) == []


def test_a_form_loaded_for_one_workspace_is_refused_after_the_session_moves_to_another(
    application_engine, owner_engine
):
    who, first, second = _two_workspaces(application_engine, "prefs-stale")
    with workspace_session(application_engine, who) as (session, _context):
        preferences.state(session, first.workspace_id, region_policy=["EU"], model_profile_note="A's form")

    # Another tab re-binds the shared session to the second workspace.
    bind(application_engine, who, second.workspace_id)

    # The first tab's form, loaded for the first workspace, is saved.
    for act in (
        lambda session: preferences.state(session, first.workspace_id, region_policy=[], model_profile_note="edited on A"),
        lambda session: preferences.acknowledge_consent(session, first.workspace_id, version=CURRENT_CONSENT),
    ):
        with pytest.raises(accounts.WorkspaceBindingMismatch):
            with workspace_session(application_engine, who) as (session, _context):
                act(session)

    # Neither workspace changed: A keeps its statement, B has none.
    (a_row,) = preference_rows(owner_engine, first.workspace_id)
    assert list(a_row["region_policy"]) == ["EU"] and a_row["model_profile_note"] == "A's form"
    assert a_row["consent_version"] is None
    assert preference_rows(owner_engine, second.workspace_id) == []

    # A save that names the workspace the session is now bound to succeeds, and lands there.
    with workspace_session(application_engine, who) as (session, _context):
        stated = preferences.state(session, second.workspace_id, model_profile_note="B's form")
    assert stated.workspace_id == second.workspace_id
    (b_row,) = preference_rows(owner_engine, second.workspace_id)
    assert b_row["model_profile_note"] == "B's form"
    (a_row,) = preference_rows(owner_engine, first.workspace_id)
    assert a_row["model_profile_note"] == "A's form"


def test_a_switch_that_overlaps_a_save_waits_for_it_and_the_save_lands_where_it_was_aimed(
    application_engine, owner_engine
):
    """The concurrent switch/save case, and what actually serialises it.

    A bound transaction holds its own session row, and re-binding the session is an update
    of that row -- so a switch started while a save is in flight waits for the save to
    commit (asserted through ``pg_locks``), the save lands on the workspace it named, and
    only then does the session move. A second save from the same stale page is then refused
    by the binding check.
    """
    who, first, second = _two_workspaces(application_engine, "prefs-overlap")
    race = _Race(application_engine)

    def save_and_hold():
        with workspace_session(application_engine, who) as (session, _context):
            race.hold()
            return preferences.state(session, first.workspace_id, region_policy=["EU"])

    def switch():
        return bind(application_engine, who, second.workspace_id)

    assert race.run(save_and_hold, switch) is True, "the switch must wait for the in-flight save"
    saved = _unwrap(race.results["winner"])
    switched = _unwrap(race.results["loser"])
    assert saved.workspace_id == first.workspace_id and saved.region_policy == ("EU",)
    assert switched.workspace_id == second.workspace_id

    (a_row,) = preference_rows(owner_engine, first.workspace_id)
    assert list(a_row["region_policy"]) == ["EU"]
    assert preference_rows(owner_engine, second.workspace_id) == []

    with pytest.raises(accounts.WorkspaceBindingMismatch):
        with workspace_session(application_engine, who) as (session, _context):
            preferences.state(session, first.workspace_id, region_policy=[])
    assert preference_rows(owner_engine, second.workspace_id) == []


def test_an_absent_or_malformed_expected_workspace_is_refused_before_the_statement(application_engine):
    who, created = owner_with_workspace(application_engine, "prefs-noexpected")
    for value in (None, "not-a-uuid", str(created.workspace_id)):
        with pytest.raises(accounts.IdentityError):
            with workspace_session(application_engine, who) as (session, _context):
                preferences.state(session, value, region_policy=["EU"])  # type: ignore[arg-type]
    # And the function refuses a NULL the same way it refuses a mismatch.
    with pytest.raises(DBAPIError) as exc:
        with workspace_session(application_engine, who) as (session, _context):
            session.execute(
                text(STATE_STATEMENT),
                {"w": None, "regions": ["EU"], "excluded": [], "note": None, "intent": "undecided"},
            )
    assert exc.value.orig.sqlstate == accounts.IDENTITY_BINDING_SQLSTATE


# --------------------------------------------------------------------------- isolation


def test_two_tenants_cannot_see_or_affect_one_another(application_engine):
    alpha, alpha_ws = owner_with_workspace(application_engine, "prefs-alpha")
    beta, beta_ws = owner_with_workspace(application_engine, "prefs-beta")

    with workspace_session(application_engine, alpha) as (session, _context):
        preferences.state(session, alpha_ws.workspace_id, region_policy=["EU"])
    with workspace_session(application_engine, beta) as (session, _context):
        preferences.state(session, beta_ws.workspace_id, excluded_provider_classes=["google"])

    with workspace_session(application_engine, beta) as (session, _context):
        # Beta asks about alpha's workspace by id. The policy compares the tenant, so the
        # row is not there -- and the answer is the same shape as "stated nothing", which is
        # what stops this being an existence oracle.
        seen = preferences.read(session, alpha_ws.workspace_id)
        assert seen.region_policy == ()
        assert seen.consent_version is None
        # And beta's own row is untouched by alpha's write.
        own = preferences.read(session, beta_ws.workspace_id)
        assert own.excluded_provider_classes == ("google",)


def test_a_removed_member_can_no_longer_read_or_state(application_engine):
    owner, created = owner_with_workspace(application_engine, "prefs-removed")
    colleague = person(application_engine, "colleague")
    accepted = invite_and_accept(application_engine, owner, colleague, role="member")
    with account_session(application_engine, colleague) as (session, _context):
        membership.bind_session_workspace(session, created.workspace_id)
    with workspace_session(application_engine, colleague) as (session, _context):
        preferences.state(session, created.workspace_id, region_policy=["EU"])

    with workspace_session(application_engine, owner) as (session, _context):
        membership.remove_membership(session, accepted.membership_id)

    # The membership is gone, so the bind no longer establishes a workspace context at all.
    with pytest.raises(accounts.IdentityError):
        with workspace_session(application_engine, colleague) as (session, _context):
            preferences.read(session, created.workspace_id)


# --------------------------------------------------------------------------- consent


def test_consent_records_the_version_and_derives_who_and_when(application_engine):
    who, created = owner_with_workspace(application_engine, "prefs-consent")
    with workspace_session(application_engine, who) as (session, _context):
        acknowledged = preferences.acknowledge_consent(
            session, created.workspace_id, version=CURRENT_CONSENT
        )
    assert acknowledged.consent_version == CURRENT_CONSENT
    assert acknowledged.consent_acknowledged_at is not None
    # Derived from the bound session by the function, and again by the trigger. There is
    # no parameter for it, so there is nothing a caller could have stated wrongly.
    assert acknowledged.consent_account_id == who.account_id


def test_the_trigger_overwrites_a_supplied_actor_and_timestamp(owner_engine, application_engine):
    """Not "corrected" -- ignored, which is the only outcome that cannot be raced. The owner
    is the only writer that can reach the table with a statement of its own."""
    who, created = owner_with_workspace(application_engine, "prefs-derived")
    with workspace_session(application_engine, who) as (session, _context):
        preferences.acknowledge_consent(session, created.workspace_id, version=CURRENT_CONSENT)

    impostor = uuid.uuid4()
    with owner_bypassing_force(owner_engine) as connection:
        connection.execute(
            text(
                f"UPDATE {SCHEMA}.workspace_preferences "
                "SET consent_account_id = :who, consent_acknowledged_at = '2000-01-01T00:00:00Z', "
                "    consent_version = NULL "
                "WHERE workspace_id = :w"
            ),
            {"who": impostor, "w": created.workspace_id},
        )
        connection.commit()
        row = (
            connection.execute(
                text(f"SELECT * FROM {SCHEMA}.workspace_preferences WHERE workspace_id = :w"),
                {"w": created.workspace_id},
            )
            .mappings()
            .one()
        )
    # Clearing the version clears the actor and the timestamp with it: a row asserting that
    # somebody consented to nothing is not storable.
    assert row["consent_version"] is None
    assert row["consent_account_id"] is None
    assert row["consent_acknowledged_at"] is None


def test_re_acknowledging_the_same_version_changes_nothing_and_records_nothing(application_engine):
    who, created = owner_with_workspace(application_engine, "prefs-reack")
    with workspace_session(application_engine, who) as (session, _context):
        first = preferences.acknowledge_consent(session, created.workspace_id, version=CURRENT_CONSENT)
    with workspace_session(application_engine, who) as (session, _context):
        second = preferences.acknowledge_consent(session, created.workspace_id, version=CURRENT_CONSENT)
        events = _events(session, "workspace.consent_acknowledged", created.workspace_id)
    assert second.consent_acknowledged_at == first.consent_acknowledged_at
    assert second.updated_at == first.updated_at
    # Idempotent by state rather than by key, and no second audit row: nothing happened.
    assert len(events) == 1


def test_two_simultaneous_acknowledgements_leave_one_row_one_timestamp_and_one_event(
    application_engine, owner_engine
):
    """The no-op / transition decision, serialised on the workspace lock.

    The first acknowledgement holds the lock uncommitted; the second is proven to be waiting
    on it; when the first commits, the second re-reads the row it now sees, finds the version
    in force, and does nothing. Both callers get the same acknowledgement back.
    """
    who, created = owner_with_workspace(application_engine, "prefs-simultaneous")
    race = _Race(application_engine)

    def acknowledge_and_hold():
        with workspace_session(application_engine, who) as (session, _context):
            acknowledged = preferences.acknowledge_consent(session, created.workspace_id, version=CURRENT_CONSENT)
            race.hold()
            return acknowledged

    def acknowledge():
        with workspace_session(application_engine, who) as (session, _context):
            return preferences.acknowledge_consent(session, created.workspace_id, version=CURRENT_CONSENT)

    assert race.run(acknowledge_and_hold, acknowledge) is True, "the second must wait on the workspace lock"
    first = _unwrap(race.results["winner"])
    second = _unwrap(race.results["loser"])
    assert second.consent_acknowledged_at == first.consent_acknowledged_at
    assert second.consent_account_id == first.consent_account_id == who.account_id

    rows = preference_rows(owner_engine, created.workspace_id)
    assert len(rows) == 1
    with workspace_session(application_engine, who) as (session, _context):
        assert len(_events(session, "workspace.consent_acknowledged", created.workspace_id)) == 1


def test_an_ordinary_preference_edit_never_re_dates_a_consent(application_engine):
    who, created = owner_with_workspace(application_engine, "prefs-untouched")
    with workspace_session(application_engine, who) as (session, _context):
        acknowledged = preferences.acknowledge_consent(
            session, created.workspace_id, version=CURRENT_CONSENT
        )
    with workspace_session(application_engine, who) as (session, _context):
        after = preferences.state(session, created.workspace_id, region_policy=["EU"])
    assert after.consent_version == CURRENT_CONSENT
    assert after.consent_acknowledged_at == acknowledged.consent_acknowledged_at
    assert after.consent_account_id == acknowledged.consent_account_id


def test_an_unpublished_consent_version_is_refused_in_python_in_the_function_and_in_the_schema(
    application_engine, owner_engine
):
    who, created = owner_with_workspace(application_engine, "prefs-badversion")
    with pytest.raises(accounts.IdentityError):
        with workspace_session(application_engine, who) as (session, _context):
            preferences.acknowledge_consent(session, created.workspace_id, version="made-up-v9")

    with pytest.raises(DBAPIError) as exc:
        with workspace_session(application_engine, who) as (session, _context):
            session.execute(text(ACKNOWLEDGE_STATEMENT), {"w": created.workspace_id, "version": "made-up-v9"})
    assert exc.value.orig.sqlstate == "22023"
    assert "made-up-v9" not in str(exc.value.orig)

    with owner_bypassing_force(owner_engine) as connection:
        with pytest.raises(DBAPIError) as exc:
            connection.execute(
                text(
                    f"INSERT INTO {SCHEMA}.workspace_preferences "
                    "(workspace_id, tenant_id, consent_version) VALUES (:w, :t, 'made-up-v9')"
                ),
                {"w": created.workspace_id, "t": created.tenant_id},
            )
        connection.rollback()
    assert isinstance(exc.value.orig, CheckViolation)


def test_the_consent_history_is_the_audit_trail(application_engine):
    """The row carries the acknowledgement in force; the trail carries how it got there."""
    who, created = owner_with_workspace(application_engine, "prefs-history")
    with workspace_session(application_engine, who) as (session, _context):
        preferences.acknowledge_consent(session, created.workspace_id, version=CURRENT_CONSENT)
        events = _events(session, "workspace.consent_acknowledged", created.workspace_id)
    assert len(events) == 1
    assert events[0].details["consent_version"] == CURRENT_CONSENT
    # The actor columns are derived by the M2.3 audit function, not stated by this module.
    assert events[0].actor_kind == "session"
    assert events[0].actor_principal_id == who.account_id
    assert events[0].resource_type == "workspace_preferences"


# --------------------------------------------------------------------------- vocabularies


def test_the_vocabularies_are_closed_and_short():
    assert REGION_GROUPS == ("EU",)
    assert PROVIDER_CLASSES == ("amazon", "google", "microsoft", "verda")
    assert EVALUATION_INTENTS[0] == "undecided"
    assert CONSENT_VERSIONS == ("provider-policy-v1-d.1",)


def test_amazon_is_the_exclusion_v1_cannot_honour(application_engine):
    """Accepted and recorded, and flagged -- not refused.

    Target §3.3 and §5.4: `provider_policy` governs execution placement only, and the payload
    plane is S3 for every tenant until a bucket per supplier cloud region exists. Refusing the
    value would deny the customer the ability to record the requirement that makes them
    unservable, which is a fact the business needs; accepting it silently would promise an
    exclusion the design cannot honour.
    """
    who, created = owner_with_workspace(application_engine, "prefs-amazon")
    with workspace_session(application_engine, who) as (session, _context):
        stated = preferences.state(
            session, created.workspace_id, excluded_provider_classes=["amazon"]
        )
    assert stated.excluded_provider_classes == ("amazon",)
    assert stated.unservable_exclusion is True

    with workspace_session(application_engine, who) as (session, _context):
        without = preferences.state(
            session, created.workspace_id, excluded_provider_classes=["google", "microsoft"]
        )
    assert without.unservable_exclusion is False


def test_the_application_role_cannot_call_the_consent_trigger_directly(application_engine):
    who, _created = owner_with_workspace(application_engine, "prefs-trigger")
    with pytest.raises(ProgrammingError) as exc:
        with workspace_session(application_engine, who) as (session, _context):
            session.execute(text(f"SELECT {SCHEMA}.workspace_preferences_set_consent()"))
    assert isinstance(exc.value.orig, InsufficientPrivilege)


def test_the_two_functions_are_the_only_bodies_that_write_the_relation(owner_engine):
    """No unrelated ``SECURITY DEFINER`` function is a path into the table.

    Every function in the schema, comments stripped, scanned for a write against
    ``workspace_preferences``: exactly the two mutation entry points write it, and nothing
    deletes from it.
    """
    with owner_engine.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT p.proname, p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = :s"
            ),
            {"s": SCHEMA},
        ).all()
    writers = set()
    for name, body in rows:
        stripped = "\n".join(re.sub(r"--.*$", "", line) for line in body.splitlines()).lower()
        if re.search(rf"\b(insert\s+into|update)\s+{SCHEMA}\.workspace_preferences\b", stripped):
            writers.add(name)
        assert not re.search(rf"\bdelete\s+from\s+{SCHEMA}\.workspace_preferences\b", stripped), name
    assert writers == {"state_workspace_preferences", "acknowledge_workspace_consent"}
    assert writers < {name for name, _signature in PORTAL_APPLICATION_FUNCTIONS}
    _ = _wait_for_a_blocked_backend  # imported for the race helpers; keeps the import honest
