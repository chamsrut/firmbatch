"""Accounts, verification, recovery and browser sessions -- Milestone 3.1, against real PostgreSQL 16.

What these tests establish, each fail-closed:

* an account exists and can hold a session **before any workspace does**;
* signup answers the same shape for a new address and an existing one; a wrong password
  and an unknown address are one outcome; an unverified account gets no session;
* verification and recovery tokens are one-time, expire, are superseded by re-issue, and
  recovery ends every session of the account;
* sessions are listed, revoked one at a time and all at once, expire, and a revoked or
  expired one is refused with the same message as an unknown one;
* **no raw secret is ever persisted**: every table is scanned for every secret a flow
  produced, and every refusal is walked for it too.
"""

from __future__ import annotations

import re
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from firmbatch.control_plane.db import accounts
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.db.models import EMAIL_MAX_LENGTH, EMAIL_REGEX
from firmbatch.control_plane.security.passwords import PasswordPolicyError
from firmbatch.control_plane.security.secrets import Secret, generate_bearer_credential
from firmbatch.control_plane.tests.conftest import exception_chain
from firmbatch.control_plane.tests.identity_helpers import (
    PASSWORD,
    everything_stored,
    login_session,
    owner_rows,
    person,
    signup_verified,
    unique_email,
)


# --------------------------------------------------------------------------- signup


def test_signup_creates_an_unverified_account_and_returns_the_token_once(application_engine, authenticator_engine, owner_engine):
    email = unique_email("signup")
    with db_engine.transaction(authenticator_engine) as session:
        outcome = accounts.signup(session, email=email, password=Secret(PASSWORD))
    assert outcome.outcome == "created"
    assert outcome.account_id is not None
    assert outcome.verification_secret is not None
    (row,) = owner_rows(owner_engine, "accounts", id=outcome.account_id)
    assert row["status"] == "unverified"
    assert row["email_verified_at"] is None
    assert row["email_normalized"] == email
    # The token is stored as a fingerprint only.
    tokens = owner_rows(owner_engine, "account_tokens", account_id=outcome.account_id)
    assert len(tokens) == 1
    assert tokens[0]["kind"] == "email_verification"
    assert outcome.verification_secret.reveal() not in everything_stored(owner_engine)


def test_signup_for_an_existing_address_has_the_same_shape_and_creates_nothing(application_engine, authenticator_engine, owner_engine):
    email, account_id = signup_verified(application_engine)
    with db_engine.transaction(authenticator_engine) as session:
        outcome = accounts.signup(session, email=email.upper(), password=Secret("another password entirely"))
    assert outcome.outcome == "existing"
    assert outcome.account_id is None
    assert outcome.verification_secret is None
    assert len(owner_rows(owner_engine, "accounts", email_normalized=email)) == 1
    # And the password of the existing account is untouched.
    assert login_session(application_engine, email).account_id == account_id


def test_the_password_is_stored_only_as_an_argon2id_hash(application_engine, authenticator_engine, owner_engine):
    email = unique_email("hash")
    with db_engine.transaction(authenticator_engine) as session:
        outcome = accounts.signup(session, email=email, password=Secret(PASSWORD))
    (row,) = owner_rows(owner_engine, "account_passwords", account_id=outcome.account_id)
    assert row["password_hash"].startswith("$argon2id$v=19$")
    assert PASSWORD not in row["password_hash"]
    assert PASSWORD not in everything_stored(owner_engine)


@pytest.mark.parametrize("bad", ["tiny1", "x" * 300, "with\x00nul"])
def test_a_password_outside_the_bounds_is_refused_without_an_echo(application_engine, authenticator_engine, bad):
    with pytest.raises(PasswordPolicyError) as exc:
        with db_engine.transaction(authenticator_engine) as session:
            accounts.signup(session, email=unique_email(), password=Secret(bad))
    assert bad not in exception_chain(exc.value)


@pytest.mark.parametrize("bad", ["not-an-address", "a@b", "two@@example.com", " ", "x" * 300 + "@example.com"])
def test_a_malformed_address_is_refused_without_an_echo(application_engine, authenticator_engine, bad):
    with pytest.raises(accounts.IdentityError) as exc:
        with db_engine.transaction(authenticator_engine) as session:
            accounts.signup(session, email=bad, password=Secret(PASSWORD))
    assert bad.strip() not in exception_chain(exc.value) or bad.strip() == ""


def test_a_plain_string_password_is_refused_by_type(application_engine, authenticator_engine):
    with pytest.raises(PasswordPolicyError):
        with db_engine.transaction(authenticator_engine) as session:
            accounts.signup(session, email=unique_email(), password=PASSWORD)  # type: ignore[arg-type]


# ------------------------------------------------ the canonical address length bound


def _address_of_length(total: int) -> str:
    """A regex-valid normalised address of exactly ``total`` characters.

    The local part is at its own 64-character maximum and the domain is single-character
    labels plus a TLD, so the only thing separating the two addresses below is total length
    -- not the grammar, which admits both.
    """
    local = "a" * 64
    want = total - len(local) - 1
    for tld in range(2, 64):
        rest = want - tld
        if rest > 0 and rest % 2 == 0:
            return local + "@" + "a." * (rest // 2) + "e" * tld
    raise AssertionError(f"no construction for a {total}-character address")


def test_the_canonical_address_maximum_is_enforced_by_the_database_itself(owner_engine):
    """254 is stored and 255 is refused by the CHECK, not merely by the normalisers.

    The lowest boundary that can answer this is the constraint: ``accounts`` is protected, so
    no runtime role can insert at all, and the two normalisers sit above it. This drives the
    insert as the schema owner -- the one identity that *can* reach the table -- so what is
    proven is the table's own bound rather than a Python or SQL guard in front of it.

    Both addresses satisfy ``EMAIL_REGEX``: its domain group repeats labels without an upper
    limit, so the grammar alone would accept the 255-character one. Only the length
    constraint separates them.
    """
    accepted = _address_of_length(EMAIL_MAX_LENGTH)
    refused = _address_of_length(EMAIL_MAX_LENGTH + 1)
    assert len(accepted) == 254 and len(refused) == 255
    assert re.fullmatch(EMAIL_REGEX, accepted) and re.fullmatch(EMAIL_REGEX, refused), (
        "both addresses must be grammar-valid, or this proves the regex rather than the bound"
    )

    insert = text(
        f"INSERT INTO {SCHEMA}.accounts (email_normalized, email_display, status) "
        "VALUES (:normalized, :display, 'unverified')"
    )
    # A short, always-valid display value, so only the email_normalized bound can refuse.
    display = "bounded@example.com"

    with owner_engine.connect() as connection:
        connection.execute(insert, {"normalized": accepted, "display": display})
        connection.commit()
        stored = connection.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.accounts WHERE email_normalized = :e"),
            {"e": accepted},
        ).scalar_one()
        assert stored == 1, "the 254-character address must be accepted"

        with pytest.raises(IntegrityError) as exc:
            connection.execute(insert, {"normalized": refused, "display": display})
        connection.rollback()
    assert "email_normalized_length" in str(exc.value), (
        "the refusal must come from the length constraint, not from another check"
    )


def test_both_normalisers_refuse_an_address_over_the_canonical_maximum(owner_engine):
    """The bound is the same at all three layers, so none can produce what another refuses."""
    refused = _address_of_length(EMAIL_MAX_LENGTH + 1)
    # Python.
    with pytest.raises(accounts.IdentityError):
        accounts.normalize_email(refused)
    # SQL. identity_normalize_email is internal, so it is read as the owner.
    with owner_engine.connect() as connection:
        assert connection.execute(
            text(f"SELECT {SCHEMA}.identity_normalize_email(:e)"), {"e": refused}
        ).scalar_one() is None
        # And the accepted length passes both.
        accepted = _address_of_length(EMAIL_MAX_LENGTH)
        assert accounts.normalize_email(accepted) == accepted
        assert connection.execute(
            text(f"SELECT {SCHEMA}.identity_normalize_email(:e)"), {"e": accepted}
        ).scalar_one() == accepted


# --------------------------------------------------------------------------- verification


def test_verification_is_one_time_and_activates_the_account(application_engine, authenticator_engine, owner_engine):
    email = unique_email("verify")
    with db_engine.transaction(authenticator_engine) as session:
        outcome = accounts.signup(session, email=email, password=Secret(PASSWORD))
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.verify_email(session, outcome.verification_secret) is True
    (row,) = owner_rows(owner_engine, "accounts", id=outcome.account_id)
    assert row["status"] == "active" and row["email_verified_at"] is not None
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.verify_email(session, outcome.verification_secret) is False


def test_an_unknown_or_malformed_verification_token_is_false_not_an_error(application_engine, authenticator_engine):
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.verify_email(session, Secret("fbv_" + "A" * 43)) is False
        assert accounts.verify_email(session, "garbage") is False
        assert accounts.verify_email(session, generate_bearer_credential()) is False


def test_reissuing_verification_supersedes_the_earlier_token(application_engine, authenticator_engine):
    email = unique_email("reissue")
    with db_engine.transaction(authenticator_engine) as session:
        first = accounts.signup(session, email=email, password=Secret(PASSWORD))
    with db_engine.transaction(authenticator_engine) as session:
        second = accounts.request_email_verification(session, email=email)
    assert second.outcome == "issued" and second.secret is not None
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.verify_email(session, first.verification_secret) is False
        assert accounts.verify_email(session, second.secret) is True


def test_verification_requests_are_neutral_for_unknown_and_verified_addresses(application_engine, authenticator_engine):
    email, _ = signup_verified(application_engine)
    with db_engine.transaction(authenticator_engine) as session:
        verified = accounts.request_email_verification(session, email=email)
        unknown = accounts.request_email_verification(session, email=unique_email("nobody"))
        malformed = accounts.request_email_verification(session, email="not an address")
    assert verified.secret is None and unknown.secret is None and malformed.secret is None
    assert verified.outcome == "already_verified"
    assert unknown.outcome == "unknown" and malformed.outcome == "unknown"


def test_an_expired_verification_token_is_refused(application_engine, authenticator_engine, owner_engine):
    email = unique_email("expired")
    with db_engine.transaction(authenticator_engine) as session:
        outcome = accounts.signup(session, email=email, password=Secret(PASSWORD), ttl=timedelta(minutes=1))
    # A token's expiry is immutable to every ordinary writer, the owner included; moving
    # it takes the deliberate DDL-shaped act the design leaves to a trusted administrator.
    with owner_engine.connect() as connection:
        connection.execute(text(f"ALTER TABLE {SCHEMA}.account_tokens DISABLE TRIGGER account_tokens_append_only"))
        connection.execute(
            text(
                f"UPDATE {SCHEMA}.account_tokens SET created_at = now() - interval '1 hour', "
                "expires_at = now() - interval '59 minutes' WHERE account_id = :a"
            ),
            {"a": outcome.account_id},
        )
        connection.execute(text(f"ALTER TABLE {SCHEMA}.account_tokens ENABLE TRIGGER account_tokens_append_only"))
        connection.commit()
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.verify_email(session, outcome.verification_secret) is False


def test_a_token_lifetime_outside_the_bound_is_refused(application_engine, authenticator_engine):
    with pytest.raises(accounts.IdentityError):
        with db_engine.transaction(authenticator_engine) as session:
            accounts.signup(session, email=unique_email(), password=Secret(PASSWORD), ttl=timedelta(days=30))


# --------------------------------------------------------------------------- login and sessions


def test_a_verified_account_opens_a_session_before_any_workspace_exists(application_engine, owner_engine):
    email, account_id = signup_verified(application_engine)
    opened = login_session(application_engine, email)
    assert opened.account_id == account_id
    assert opened.session_secret.reveal().startswith("fbs_")
    assert opened.csrf_secret.reveal().startswith("fbc_")
    with accounts.session_transaction(application_engine, opened.session_secret, mode="account") as (session, context):
        assert context.account_id == account_id
        assert context.workspace_id is None and context.tenant_id is None
        assert context.email_verified is True
        assert db_engine.current_tenant_context(session) is None
        profile = accounts.account_profile(session)
        assert profile.account_id == account_id and profile.email == email
    stored = everything_stored(owner_engine)
    assert opened.session_secret.reveal() not in stored
    assert opened.csrf_secret.reveal() not in stored


def test_a_wrong_password_and_an_unknown_address_are_one_outcome(application_engine, authenticator_engine):
    email, _ = signup_verified(application_engine)
    # Login is the authenticator role's, not the application role's.
    with db_engine.transaction(authenticator_engine) as session:
        wrong = accounts.login(session, email=email, password=Secret("not the password, no"))
    with db_engine.transaction(authenticator_engine) as session:
        unknown = accounts.login(session, email=unique_email("ghost"), password=Secret(PASSWORD))
    with db_engine.transaction(authenticator_engine) as session:
        malformed = accounts.login(session, email="garbage", password=Secret(PASSWORD))
    assert wrong == unknown == malformed
    assert wrong.account_id is None and wrong.email_verified is False


def test_an_unverified_account_cannot_open_a_session(application_engine, authenticator_engine):
    email = unique_email("unverified")
    with db_engine.transaction(authenticator_engine) as session:
        accounts.signup(session, email=email, password=Secret(PASSWORD))
    with pytest.raises(accounts.IdentityRefused):
        with db_engine.transaction(authenticator_engine) as session:
            outcome = accounts.login(session, email=email, password=Secret(PASSWORD))
            assert outcome.account_id is not None and outcome.email_verified is False
            accounts.open_session(session)


def test_a_session_is_opened_only_for_the_account_this_transaction_challenged(application_engine, authenticator_engine):
    """No account parameter exists; a transaction that looked nothing up gets nothing."""
    signup_verified(application_engine)
    with pytest.raises(accounts.SessionContextError):
        with db_engine.transaction(authenticator_engine) as session:
            accounts.open_session(session)
    # And a lookup that found nothing opens nothing either.
    with pytest.raises(accounts.IdentityRefused):
        with db_engine.transaction(authenticator_engine) as session:
            accounts.login(session, email=unique_email("nobody"), password=Secret(PASSWORD))
            accounts.open_session(session)


def test_a_transaction_challenges_one_login_and_keeps_it(application_engine, authenticator_engine):
    email, _ = signup_verified(application_engine)
    other, _ = signup_verified(application_engine)
    with pytest.raises(accounts.SessionContextError):
        with db_engine.transaction(authenticator_engine) as session:
            accounts.login(session, email=email, password=Secret(PASSWORD))
            accounts.login(session, email=other, password=Secret(PASSWORD))


def test_unknown_revoked_and_expired_sessions_are_one_refusal(application_engine, owner_engine):
    who = person(application_engine)
    revoked = login_session(application_engine, who.email)
    with accounts.session_transaction(application_engine, revoked.session_secret, csrf_secret=revoked.csrf_secret) as (session, ctx):
        assert accounts.revoke_session(session, ctx.session_id) is True
    expired = login_session(application_engine, who.email, ttl=timedelta(minutes=1))
    with owner_engine.connect() as connection:
        connection.execute(
            text(
                f"UPDATE {SCHEMA}.browser_sessions SET created_at = now() - interval '1 hour', "
                "expires_at = now() - interval '59 minutes' WHERE id = :s"
            ),
            {"s": expired.session_id},
        )
        connection.commit()
    messages = set()
    for secret in (Secret("fbs_" + "A" * 43), revoked.session_secret, expired.session_secret):
        with pytest.raises(accounts.IdentityRefused) as exc:
            with accounts.session_transaction(application_engine, secret):
                pass
        messages.add(str(exc.value))
        assert secret.reveal() not in exception_chain(exc.value)
    assert len(messages) == 1


def test_a_bearer_credential_is_not_a_session_secret_and_never_reaches_the_database(application_engine, principal_a):
    with pytest.raises(accounts.SessionAuthenticationError) as exc:
        with accounts.session_transaction(application_engine, principal_a.credential):
            pass
    assert "without being sent to the database" in str(exc.value)
    assert principal_a.credential.reveal() not in exception_chain(exc.value)


def test_a_wrong_csrf_secret_is_refused_and_a_missing_one_leaves_the_bind_unverified(application_engine):
    who = person(application_engine)
    other = login_session(application_engine, who.email)
    with pytest.raises(accounts.IdentityRefused):
        with accounts.session_transaction(application_engine, who.session_secret, csrf_secret=other.csrf_secret):
            pass
    with accounts.session_transaction(application_engine, who.session_secret) as (session, context):
        assert context.csrf_verified is False
        # A mutation needs the verified token, and the database is what says so.
        with pytest.raises(accounts.SessionContextError):
            accounts.revoke_session(session, context.session_id)


def test_sessions_are_listed_revoked_individually_and_all_at_once(application_engine):
    who = person(application_engine)
    second = login_session(application_engine, who.email)
    third = login_session(application_engine, who.email)
    with accounts.session_transaction(application_engine, who.session_secret, csrf_secret=who.csrf_secret) as (session, ctx):
        listed = accounts.account_sessions(session)
        assert {row.session_id for row in listed} == {ctx.session_id, second.session_id, third.session_id}
        assert [row.is_current for row in listed].count(True) == 1
        assert accounts.revoke_session(session, second.session_id) is True
        assert accounts.revoke_session(session, second.session_id) is False
        assert accounts.revoke_session(session, uuid.uuid4()) is False
    with pytest.raises(accounts.IdentityRefused):
        with accounts.session_transaction(application_engine, second.session_secret):
            pass
    with accounts.session_transaction(application_engine, who.session_secret, csrf_secret=who.csrf_secret) as (session, ctx):
        assert accounts.revoke_all_sessions(session, keep_current=True) == 1
        assert [row.session_id for row in accounts.account_sessions(session)] == [ctx.session_id]
        assert accounts.revoke_all_sessions(session) == 1
    with pytest.raises(accounts.IdentityRefused):
        with accounts.session_transaction(application_engine, who.session_secret):
            pass


def test_another_accounts_session_cannot_be_revoked_and_is_not_distinguishable(application_engine):
    alice = person(application_engine, "alice")
    bob = person(application_engine, "bob")
    with accounts.session_transaction(application_engine, alice.session_secret, csrf_secret=alice.csrf_secret) as (session, _):
        assert accounts.revoke_session(session, bob.session_id) is False
        assert accounts.revoke_session(session, uuid.uuid4()) is False
    with accounts.session_transaction(application_engine, bob.session_secret) as (_session, context):
        assert context.session_id == bob.session_id


def test_a_session_binds_once_per_transaction(application_engine):
    who = person(application_engine)
    other = login_session(application_engine, who.email)
    with pytest.raises(accounts.SessionContextError):
        with db_engine.transaction(application_engine) as session:
            accounts.bind_session_context(session, who.session_secret)
            accounts.bind_session_context(session, other.session_secret)


def test_binding_inside_a_savepoint_is_refused(application_engine):
    who = person(application_engine)
    with db_engine.transaction(application_engine) as session:
        with session.begin_nested():
            with pytest.raises(db_engine.TenantContextError):
                accounts.bind_session_context(session, who.session_secret)


# --------------------------------------------------------------------------- recovery


def test_recovery_replaces_the_password_verifies_the_account_and_ends_every_session(
    application_engine, authenticator_engine, owner_engine
):
    who = person(application_engine)
    second = login_session(application_engine, who.email)
    # Recovery request and completion are the authenticator role's.
    with db_engine.transaction(authenticator_engine) as session:
        outcome = accounts.request_recovery(session, email=who.email)
    assert outcome.outcome == "issued" and outcome.secret is not None
    assert outcome.secret.reveal().startswith("fbr_")
    new_password = "a brand new password 2026"
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.complete_recovery(session, secret=outcome.secret, new_password=Secret(new_password)) is True
    for secret in (who.session_secret, second.session_secret):
        with pytest.raises(accounts.IdentityRefused):
            with accounts.session_transaction(application_engine, secret):
                pass
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.login(session, email=who.email, password=Secret(PASSWORD)).account_id is None
    assert login_session(application_engine, who.email, password=new_password).account_id == who.account_id
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.complete_recovery(session, secret=outcome.secret, new_password=Secret(new_password)) is False
    stored = everything_stored(owner_engine)
    assert outcome.secret.reveal() not in stored and new_password not in stored


def test_recovery_of_an_unverified_account_verifies_it(application_engine, authenticator_engine, owner_engine):
    """The mailbox owner takes back an address somebody else registered."""
    email = unique_email("takeback")
    with db_engine.transaction(authenticator_engine) as session:
        signed = accounts.signup(session, email=email, password=Secret("the impostors password 1"))
    with db_engine.transaction(authenticator_engine) as session:
        outcome = accounts.request_recovery(session, email=email)
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.complete_recovery(session, secret=outcome.secret, new_password=Secret(PASSWORD)) is True
    (row,) = owner_rows(owner_engine, "accounts", id=signed.account_id)
    assert row["status"] == "active"
    # And the impostor's verification token is superseded along with everything else.
    with db_engine.transaction(authenticator_engine) as session:
        assert accounts.verify_email(session, signed.verification_secret) is False
    assert login_session(application_engine, email).account_id == signed.account_id


def test_recovery_requests_are_neutral_and_tokens_are_one_time(authenticator_engine):
    with db_engine.transaction(authenticator_engine) as session:
        unknown = accounts.request_recovery(session, email=unique_email("nobody"))
        malformed = accounts.request_recovery(session, email="nope")
        assert unknown.secret is None and malformed.secret is None
        assert accounts.complete_recovery(session, secret="fbr_" + "B" * 43, new_password=Secret(PASSWORD)) is False
        assert accounts.complete_recovery(session, secret="garbage", new_password=Secret(PASSWORD)) is False


# --------------------------------------------------------------------------- secrets


def test_no_secret_of_the_whole_flow_appears_anywhere_persisted(application_engine, authenticator_engine, owner_engine):
    email = unique_email("scan")
    with db_engine.transaction(authenticator_engine) as session:
        signed = accounts.signup(session, email=email, password=Secret(PASSWORD))
    with db_engine.transaction(authenticator_engine) as session:
        accounts.verify_email(session, signed.verification_secret)
    opened = login_session(application_engine, email)
    with db_engine.transaction(authenticator_engine) as session:
        recovery = accounts.request_recovery(session, email=email)
    stored = everything_stored(owner_engine)
    for secret in (
        PASSWORD,
        signed.verification_secret.reveal(),
        opened.session_secret.reveal(),
        opened.csrf_secret.reveal(),
        recovery.secret.reveal(),
    ):
        assert secret not in stored


def test_a_secret_never_travels_in_an_exception(application_engine):
    who = person(application_engine)
    secret = who.session_secret.reveal()
    with pytest.raises(accounts.IdentityError) as exc:
        with db_engine.transaction(application_engine) as session:
            accounts.bind_session_context(session, who.session_secret, mode="sideways")
    assert secret not in exception_chain(exc.value)
    with pytest.raises(accounts.SessionAuthenticationError) as exc:
        with db_engine.transaction(application_engine) as session:
            accounts.bind_session_context(session, who.session_secret, csrf_secret=Secret("fbc_short"))
    assert secret not in exception_chain(exc.value)
