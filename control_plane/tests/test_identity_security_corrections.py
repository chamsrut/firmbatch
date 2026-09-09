"""Regression tests for the Milestone 3.1 Codex security corrections, against PostgreSQL 16.

Each test names the finding it closes. The theme is the same one ADR 0009 (revised) records:
the pre-authentication trusted-issuer boundary -- signup, mailbox verification, login,
session opening, recovery -- is a distinct database principal (the authenticator), so raw SQL
as the ordinary application role can neither mint a victim session, reset a victim password,
nor issue and consume a mailbox-verification token for an address it does not control;
account recovery evicts the credentials issued before it through a durable security epoch;
and memory-hard work is admission-bounded so an unauthenticated flood cannot exhaust the
process.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from psycopg.errors import InsufficientPrivilege
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from firmbatch.control_plane.db import accounts, auth
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.security import passwords
from firmbatch.control_plane.security.authorization import AuthorizationError
from firmbatch.control_plane.security.secrets import Secret
from firmbatch.control_plane.tests.identity_helpers import (
    PASSWORD,
    everything_stored,
    issue_credential,
    login_session,
    owner_rows,
    owner_with_workspace,
    signup_verified,
    unique_email,
)

# A syntactically valid stored hash, for probing a function's EXECUTE privilege without
# reaching its body -- permission is checked before the body runs.
_WELL_FORMED_HASH = "$argon2id$v=19$m=65536,t=3,p=4$" + "a" * 22 + "$" + "b" * 43


# ------------------------------------------------------- finding 1: passwordless session


def test_finding1_application_role_cannot_mint_a_session_without_password_proof(
    application_engine, authenticator_engine
):
    """The application role holds neither login_lookup nor open_browser_session, so it cannot
    combine them to open a session for a victim account. The authority lives on the distinct
    authenticator role -- the trusted-issuer boundary the finding requires."""
    email, account_id = signup_verified(application_engine)

    for statement, params in (
        (f"SELECT * FROM {SCHEMA}.login_lookup(:e)", {"e": email}),
        (f"SELECT * FROM {SCHEMA}.open_browser_session(interval '1 hour')", {}),
    ):
        with pytest.raises(ProgrammingError) as exc:
            with db_engine.transaction(application_engine) as session:
                session.execute(text(statement), params)
        assert isinstance(exc.value.orig, InsufficientPrivilege), statement
        assert "permission denied for function" in str(exc.value.orig)

    # Even chaining them in one application-role transaction is refused at the first call,
    # so no login challenge is ever written and no session is ever opened.
    with pytest.raises(ProgrammingError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(text(f"SELECT * FROM {SCHEMA}.login_lookup(:e)"), {"e": email})
            session.execute(text(f"SELECT * FROM {SCHEMA}.open_browser_session(interval '1 hour')"))
    assert isinstance(exc.value.orig, InsufficientPrivilege)

    # The supported flow, on the authenticator role, still authenticates and mints one
    # session -- and only after a real password check.
    opened = login_session(application_engine, email)
    assert opened.account_id == account_id
    with accounts.session_transaction(application_engine, opened.session_secret, mode="account") as (_s, ctx):
        assert ctx.account_id == account_id
    # A wrong password yields no account to the caller. The Argon2 verification runs in the
    # process (PostgreSQL has no Argon2, ADR 0009); the database cannot enforce the match, so
    # the login wrapper returns no account and the caller does not open a session. The value
    # of the authenticator split is that this whole flow -- and the challenge it writes -- is
    # reachable only by the narrow authenticator role, never by the application runtime.
    with db_engine.transaction(authenticator_engine) as session:
        wrong = accounts.login(session, email=email, password=Secret("the wrong password entirely"))
    assert wrong.account_id is None


# ------------------------------------------------------- finding 2: recovery no mailbox


def test_finding2_application_role_cannot_request_or_consume_a_recovery_secret(
    application_engine, authenticator_engine
):
    """The application role can neither request a recovery secret nor complete a recovery: the
    raw secret is never handed to it, and it cannot replace a password. Only the trusted
    delivery path (the authenticator role) receives the secret, and completion proves
    possession of it."""
    email, account_id = signup_verified(application_engine)

    with pytest.raises(ProgrammingError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(
                text(f"SELECT * FROM {SCHEMA}.request_account_recovery(:e, interval '1 hour')"), {"e": email}
            )
    assert isinstance(exc.value.orig, InsufficientPrivilege)
    with pytest.raises(ProgrammingError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(
                text(f"SELECT {SCHEMA}.complete_account_recovery(:s, :h)"),
                {"s": "fbr_" + "a" * 43, "h": _WELL_FORMED_HASH},
            )
    assert isinstance(exc.value.orig, InsufficientPrivilege)

    # The trusted delivery path receives the one-time secret, and completion needs it.
    with db_engine.transaction(authenticator_engine) as session:
        outcome = accounts.request_recovery(session, email=email)
    assert outcome.secret is not None and outcome.secret.reveal().startswith("fbr_")
    new_password = "a recovered password 2026"
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.complete_recovery(session, secret=outcome.secret, new_password=Secret(new_password)) is True
    assert login_session(application_engine, email, password=new_password).account_id == account_id


# --------------------------------------------- finding: mailbox-verification authority


def test_the_application_role_cannot_issue_or_consume_a_mailbox_verification_token(
    application_engine, authenticator_engine, owner_engine
):
    """Mailbox verification is a mailbox proof, and its authority is the authenticator's.

    ``signup_account`` and ``request_email_verification`` mint a verification secret and
    **return it in the result row**; ``verify_account_email`` consumes one and flips the
    account to ``active``. A role holding all three needs no mailbox at all: it registers an
    address it does not control, reads the secret out of its own result, consumes it, and
    holds a verified account -- which then satisfies the verified-account precondition on
    workspace creation and invitation acceptance. The application role therefore holds none
    of the three, exactly as it holds none of the recovery path.
    """
    email = unique_email("mailbox")
    for statement, params in (
        (f"SELECT * FROM {SCHEMA}.signup_account(:e, :h, interval '1 hour')", {"e": email, "h": _WELL_FORMED_HASH}),
        (f"SELECT * FROM {SCHEMA}.request_email_verification(:e, interval '1 hour')", {"e": email}),
        (f"SELECT {SCHEMA}.verify_account_email(:s)", {"s": "fbv_" + "a" * 43}),
    ):
        with pytest.raises(ProgrammingError) as exc:
            with db_engine.transaction(application_engine) as session:
                session.execute(text(statement), params)
        assert isinstance(exc.value.orig, InsufficientPrivilege), statement
        assert "permission denied for function" in str(exc.value.orig)

    # Chaining them in one application-role transaction is refused at the first call, so no
    # account is created and no token is ever minted for it.
    with pytest.raises(ProgrammingError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(
                text(f"SELECT * FROM {SCHEMA}.signup_account(:e, :h, interval '1 hour')"),
                {"e": email, "h": _WELL_FORMED_HASH},
            )
            session.execute(
                text(f"SELECT * FROM {SCHEMA}.request_email_verification(:e, interval '1 hour')"), {"e": email}
            )
    assert isinstance(exc.value.orig, InsufficientPrivilege)
    assert owner_rows(owner_engine, "accounts", email_normalized=email) == [], (
        "a refused signup must leave no account behind"
    )

    # And the supported flow, on the authenticator role, still works end to end: one
    # account, one token, the raw secret returned once, consumed once, account active.
    with db_engine.transaction(authenticator_engine) as session:
        created = accounts.signup(session, email=email, password=Secret(PASSWORD))
    assert created.outcome == "created" and created.verification_secret is not None
    assert created.verification_secret.reveal().startswith("fbv_")
    (row,) = owner_rows(owner_engine, "accounts", id=created.account_id)
    assert row["status"] == "unverified"
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.verify_email(session, created.verification_secret) is True
    (row,) = owner_rows(owner_engine, "accounts", id=created.account_id)
    assert row["status"] == "active" and row["email_verified_at"] is not None
    # The raw secret is nowhere in the database: the token row holds a fingerprint.
    assert created.verification_secret.reveal() not in everything_stored(owner_engine)
    # And the account signs in, so the narrowed grant is also *enough*.
    assert login_session(application_engine, email).account_id == created.account_id


# ------------------------------------------------------- finding 6: recovery epoch


def test_finding6_account_recovery_evicts_credentials_via_the_security_epoch(
    application_engine, authenticator_engine, owner_engine
):
    """Recovery advances the account's security epoch, and a membership-bound credential is
    stamped with the epoch at issue time, so every credential from before the recovery is
    refused at bearer authentication -- a durable eviction, not a best-effort sweep."""
    owner, created = owner_with_workspace(application_engine)
    issued = issue_credential(application_engine, owner, scopes=("workspace:read",))
    (before,) = owner_rows(owner_engine, "accounts", id=owner.account_id)
    assert before["security_epoch"] == 0
    (binding,) = owner_rows(owner_engine, "auth_bindings", id=issued.binding_id)
    assert binding["principal_epoch"] == 0

    with auth.authenticated_transaction(application_engine, issued.credential) as session:
        assert auth.current_authenticated_context(session).binding_id == issued.binding_id

    with db_engine.transaction(authenticator_engine) as session:
        outcome = accounts.request_recovery(session, email=owner.email)
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.complete_recovery(
            session, secret=outcome.secret, new_password=Secret("a password after the breach")
        ) is True

    with pytest.raises(auth.AuthenticationError):
        with auth.authenticated_transaction(application_engine, issued.credential):
            pass
    (after,) = owner_rows(owner_engine, "accounts", id=owner.account_id)
    assert after["security_epoch"] == 1
    (revoked,) = owner_rows(owner_engine, "auth_bindings", id=issued.binding_id)
    assert revoked["revoked_at"] is not None


def test_finding6_a_credential_stamped_with_a_stale_epoch_is_refused(
    application_engine, authenticator_engine, owner_engine
):
    """The mechanism directly: a membership-bound binding whose stamped epoch is behind the
    account's current one is refused at bind, which is exactly the state a credential that
    raced a recovery ends up in (it carries the pre-recovery epoch)."""
    owner, _ = owner_with_workspace(application_engine)
    issued = issue_credential(application_engine, owner, scopes=("workspace:read",))
    # Authenticates while epoch matches.
    with auth.authenticated_transaction(application_engine, issued.credential):
        pass
    # Advance only the account epoch, as a recovery would, leaving the binding's stamp behind.
    with owner_engine.connect() as connection:
        connection.execute(
            text(f"UPDATE {SCHEMA}.accounts SET security_epoch = security_epoch + 1 WHERE id = :a"),
            {"a": owner.account_id},
        )
        connection.commit()
    with pytest.raises(auth.AuthenticationError):
        with auth.authenticated_transaction(application_engine, issued.credential):
            pass


# ------------------------------------------------------- finding 8/10: KDF admission


def test_finding8_memory_hard_work_is_admission_bounded_and_turned_away_when_saturated(monkeypatch):
    """A bounded gate around Argon2: when its only slot is occupied, further hashing and
    verification are turned away deterministically rather than piling on more 64 MiB work."""
    gate = passwords.KDFAdmissionGate(max_concurrency=1, acquire_timeout=0.05)
    monkeypatch.setattr(passwords, "KDF_GATE", gate)
    with gate.admit():  # occupy the only slot
        with pytest.raises(passwords.KDFUnavailableError):
            passwords.verify_password(passwords.DUMMY_HASH, Secret("a candidate password"))
        with pytest.raises(passwords.KDFUnavailableError):
            passwords.hash_password(Secret("another candidate password"))
    # Released: work is admitted again.
    assert passwords.verify_password(passwords.DUMMY_HASH, Secret("a candidate password")) is False


# The HTTP-level counterparts of findings 8 and 10 (login-under-saturation 503, the
# signup no-oracle check, and the chunked-body streaming cap) live in test_api_http.py,
# where the Starlette test client fixture is defined.


# ------------------------------------------------------- finding 9: recovery hash order


def test_finding9_a_malformed_or_invalid_recovery_token_never_invokes_argon2(
    application_engine, authenticator_engine, monkeypatch
):
    """Instrument the hasher: a malformed token and a well-shaped token that matches nothing
    are both refused before any Argon2 hash of the new password; a valid token does hash."""
    # Create the verified account first, before the hasher is instrumented, so the spy counts
    # only the recovery-completion hash.
    email, _ = signup_verified(application_engine)

    calls: list[int] = []
    real_hash = passwords.hash_password

    def spy(password):
        calls.append(1)
        return real_hash(password)

    monkeypatch.setattr(accounts, "hash_password", spy)

    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.complete_recovery(session, secret="garbage", new_password=Secret(PASSWORD)) is False
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.complete_recovery(
            session, secret="fbr_" + "Z" * 43, new_password=Secret(PASSWORD)
        ) is False
    assert calls == [], "Argon2 must not run for a malformed or non-existent recovery token"

    with db_engine.transaction(authenticator_engine) as session:
        outcome = accounts.request_recovery(session, email=email)
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.complete_recovery(
            session, secret=outcome.secret, new_password=Secret("a valid replacement password")
        ) is True
    assert calls == [1], "a valid token must hash exactly once"


# ------------------------------------------------------- finding 10: unverified growth


def test_finding10_expired_unverified_accounts_are_reclaimable_and_purge_is_owner_only(
    application_engine, authenticator_engine, owner_engine
):
    """The explicit expiry control: an unverified account older than the cutoff, holding no
    active membership, is reclaimed; a verified account is untouched; and the purge is not
    callable by a runtime role."""
    stale_email = unique_email("stale")
    with db_engine.transaction(authenticator_engine) as session:
        stale = accounts.signup(session, email=stale_email, password=Secret(PASSWORD))
    with owner_engine.connect() as connection:
        connection.execute(
            text(f"UPDATE {SCHEMA}.accounts SET created_at = now() - interval '10 days' WHERE id = :a"),
            {"a": stale.account_id},
        )
        connection.commit()
    _fresh_email, active_id = signup_verified(application_engine)

    with owner_engine.connect() as connection:
        reclaimed = connection.execute(
            text(f"SELECT {SCHEMA}.purge_expired_unverified_accounts(interval '1 day')")
        ).scalar_one()
        connection.commit()
    assert reclaimed >= 1
    assert owner_rows(owner_engine, "accounts", id=stale.account_id) == []
    assert len(owner_rows(owner_engine, "accounts", id=active_id)) == 1

    # The runtime role cannot call the purge: it is executable by nobody. The wrapper
    # translates the database's InsufficientPrivilege into AuthorizationError.
    with pytest.raises(AuthorizationError):
        with db_engine.transaction(application_engine) as session:
            accounts.purge_expired_unverified_accounts(session, older_than=timedelta(days=1))
