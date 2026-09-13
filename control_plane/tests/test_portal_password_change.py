"""The signed-in password change: atomicity, the account-plane lock order, and what it ends.

Milestone 3.1 deliberately did not build this -- ``api/app.py`` said a change flow "needs the
re-authentication design Milestone 3.2 owns". Migration ``0006`` adds two functions on the
trusted-issuer boundary and this is what holds them to their claims, against real
PostgreSQL 16.

The claims, in order of how much they matter:

1. **All of it, or none of it.** One transaction verifies the current password, replaces it,
   supersedes every outstanding token, advances the security epoch, revokes every
   membership-bound credential and **every** browser session, and mints the replacement.
2. **Overlapping account-plane writers never deadlock, and exactly one wins.** Every writer
   takes the account row ``FOR UPDATE`` first (migration ``0006``'s lock order), so a
   recovery, a login or a second change that overlaps a change waits at that row and then
   observes what committed. The independent Milestone 3.2 review found that ``0005``'s
   recovery locked its token row first and could deadlock with the change (``40P01``); the
   tests in the concurrency section drive real overlap -- one transaction holds the account
   row, the others are proven through ``pg_locks`` to be waiting on it -- and assert one
   controlled outcome, a neutral refusal for every loser, no partial state, and no
   connection or lock left behind.
3. **The authority stays where the M3.1 correction put it.** The application role cannot call
   either function; only the authenticator can.
"""

from __future__ import annotations

import threading
import uuid

import pytest
from psycopg.errors import InsufficientPrivilege
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from firmbatch.control_plane.db import accounts, credentials
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.security.passwords import hash_password, verify_password
from firmbatch.control_plane.security.secrets import Secret
from firmbatch.control_plane.tests.identity_helpers import (
    PASSWORD,
    account_session,
    authenticator_engine_for,
    everything_stored,
    issue_credential,
    owner_rows,
    owner_with_workspace,
    person,
)
from firmbatch.control_plane.tests.test_identity_concurrency import (
    BLOCK_TIMEOUT_SECONDS,
    _join,
    _thread,
    _unwrap,
)

NEW_PASSWORD = "an entirely different passphrase 91"
RECOVERED_PASSWORD = "a recovered passphrase entirely 77"
SECOND_NEW_PASSWORD = "a second replacement passphrase 33"

#: PostgreSQL's deadlock SQLSTATE. Asserted absent from every outcome below.
DEADLOCK_DETECTED = "40P01"


def change(engine, who, current=PASSWORD, new=NEW_PASSWORD, session_id=None):
    """Run one password change on the authenticator engine, as the API's handler does."""
    with db_engine.transaction(authenticator_engine_for(engine)) as session:
        return accounts.change_password(
            session,
            account_id=who.account_id,
            session_id=session_id if session_id is not None else who.session_id,
            current_password=Secret(current),
            new_password=Secret(new),
        )


def change_holding_the_account_row(engine, who, hold, new=NEW_PASSWORD):
    """The change, statement by statement, pausing **between the lookup and the change**.

    ``accounts.change_password`` runs the lookup, the Argon2 verification and the change in
    one call with no seam to pause at, so the overlap tests drive the two database
    statements themselves, with the same verification in between. The pause is the window
    the review named: the account row is locked by the lookup and held while Python runs
    Argon2, and every other account-plane writer that starts now waits at that row.
    """
    trusted = authenticator_engine_for(engine)
    with db_engine.transaction(trusted) as session:
        row = session.execute(
            text(f"SELECT password_hash FROM {SCHEMA}.password_change_lookup(:a, :s)"),
            {"a": who.account_id, "s": who.session_id},
        ).one()
        assert verify_password(row.password_hash, Secret(PASSWORD))
        hold()
        opened = accounts._execute(
            session,
            text(
                "SELECT session_id, account_id, session_secret, csrf_secret, expires_at "
                f"FROM {SCHEMA}.change_account_password(:expected, :new_hash, CAST(:ttl AS interval))"
            ),
            {"expected": row.password_hash, "new_hash": hash_password(Secret(new)), "ttl": "1 hour"},
        ).one()
        return accounts.OpenedSession(
            session_id=opened.session_id,
            account_id=opened.account_id,
            session_secret=Secret(opened.session_secret),
            csrf_secret=Secret(opened.csrf_secret),
            expires_at=opened.expires_at,
        )


# --------------------------------------------------------------------------- the happy path


def test_a_change_replaces_the_password_and_returns_a_working_session(application_engine):
    who = person(application_engine, "pw-happy")
    opened = change(application_engine, who)
    assert opened is not None
    assert opened.account_id == who.account_id

    # The replacement session works, and it is a different session from the one that asked.
    assert opened.session_id != who.session_id
    with accounts.session_transaction(
        application_engine, opened.session_secret, csrf_secret=opened.csrf_secret, mode="account"
    ) as (session, context):
        assert context.account_id == who.account_id
        assert context.csrf_verified is True

    # The old password no longer signs in, and the new one does.
    trusted = authenticator_engine_for(application_engine)
    with db_engine.transaction(trusted) as session:
        assert accounts.login(session, email=who.email, password=Secret(PASSWORD)).account_id is None
    with db_engine.transaction(trusted) as session:
        assert accounts.login(session, email=who.email, password=Secret(NEW_PASSWORD)).account_id is not None


def test_every_other_session_is_revoked_including_the_one_that_asked(application_engine):
    who = person(application_engine, "pw-sessions")
    trusted = authenticator_engine_for(application_engine)
    with db_engine.transaction(trusted) as session:
        accounts.login(session, email=who.email, password=Secret(PASSWORD))
        elsewhere = accounts.open_session(session)

    opened = change(application_engine, who)
    assert opened is not None

    for secret in (who.session_secret, elsewhere.session_secret):
        with pytest.raises(accounts.IdentityError):
            with accounts.session_transaction(application_engine, secret, mode="account"):
                pass
    # And the replacement, minted after the sweep, survives it.
    with accounts.session_transaction(application_engine, opened.session_secret, mode="account"):
        pass


def test_every_membership_bound_credential_is_revoked(application_engine, owner_engine):
    who, _created = owner_with_workspace(application_engine, "pw-credentials")
    issued = issue_credential(application_engine, who, scopes=("workspace:read",))

    # It works before the change.
    from firmbatch.control_plane.db import auth

    with auth.authenticated_transaction(application_engine, issued.credential) as session:
        assert auth.current_authenticated_context(session) is not None

    assert change(application_engine, who) is not None

    # And is refused afterwards. The security epoch is what makes this durable rather than a
    # best-effort sweep of the rows that happened to be visible.
    with pytest.raises(Exception):
        with auth.authenticated_transaction(application_engine, issued.credential):
            pass
    rows = owner_rows(owner_engine, "auth_bindings", id=issued.binding_id)
    assert rows == [] or rows[0]["revoked_at"] is not None


def test_outstanding_tokens_are_superseded(application_engine):
    """A recovery link minted under the old password should not still work afterwards."""
    who = person(application_engine, "pw-tokens")
    trusted = authenticator_engine_for(application_engine)
    with db_engine.transaction(trusted) as session:
        outcome = accounts.request_recovery(session, email=who.email)
    assert outcome.secret is not None

    assert change(application_engine, who) is not None

    with db_engine.transaction(trusted) as session:
        assert accounts.complete_recovery(session, secret=outcome.secret, new_password=Secret("another one entirely 55")) is False


def test_the_security_epoch_advances(application_engine, owner_engine):
    who = person(application_engine, "pw-epoch")
    before = owner_rows(owner_engine, "accounts", id=who.account_id)[0]["security_epoch"]
    assert change(application_engine, who) is not None
    after = owner_rows(owner_engine, "accounts", id=who.account_id)[0]["security_epoch"]
    assert after == before + 1


# --------------------------------------------------------------------------- refusals


def test_a_wrong_current_password_changes_nothing(application_engine, owner_engine):
    who = person(application_engine, "pw-wrong")
    stored_before = owner_rows(owner_engine, "account_passwords", account_id=who.account_id)[0][
        "password_hash"
    ]

    assert change(application_engine, who, current="not the password at all") is None

    stored_after = owner_rows(owner_engine, "account_passwords", account_id=who.account_id)[0][
        "password_hash"
    ]
    assert stored_after == stored_before
    # The session that asked is untouched: a failed attempt is not a reason to sign somebody
    # out, and the transaction rolled back the challenge with it.
    with accounts.session_transaction(application_engine, who.session_secret, mode="account"):
        pass


def test_a_session_that_is_not_this_account_s_is_refused(application_engine):
    who = person(application_engine, "pw-foreign-a")
    other = person(application_engine, "pw-foreign-b")
    # A live session id, and a live account id, that do not belong together.
    with pytest.raises(accounts.IdentityRefused):
        change(application_engine, who, session_id=other.session_id)


def test_a_revoked_session_cannot_authorize_a_change(application_engine):
    who = person(application_engine, "pw-revoked")
    with account_session(application_engine, who) as (session, context):
        accounts.revoke_session(session, context.session_id)
    with pytest.raises(accounts.IdentityRefused):
        change(application_engine, who)


def test_an_unknown_account_or_session_is_the_same_neutral_refusal(application_engine):
    who = person(application_engine, "pw-unknown")
    for account_id, session_id in (
        (uuid.uuid4(), who.session_id),
        (who.account_id, uuid.uuid4()),
        (uuid.uuid4(), uuid.uuid4()),
    ):
        with pytest.raises(accounts.IdentityRefused):
            with db_engine.transaction(authenticator_engine_for(application_engine)) as session:
                accounts.change_password(
                    session,
                    account_id=account_id,
                    session_id=session_id,
                    current_password=Secret(PASSWORD),
                    new_password=Secret(NEW_PASSWORD),
                )


def test_a_change_without_a_challenge_is_refused(application_engine):
    """``change_account_password`` has no account parameter, for ``open_browser_session``'s reason."""
    with pytest.raises(DBAPIError) as exc:
        with db_engine.transaction(authenticator_engine_for(application_engine)) as session:
            session.execute(
                text(
                    f"SELECT * FROM {SCHEMA}.change_account_password("
                    ":expected, :new_hash, CAST(:ttl AS interval))"
                ),
                {
                    "expected": "$argon2id$v=19$m=65536,t=3,p=4$" + "a" * 22 + "$" + "b" * 43,
                    "new_hash": "$argon2id$v=19$m=65536,t=3,p=4$" + "c" * 22 + "$" + "d" * 43,
                    "ttl": "1 hour",
                },
            )
    # FB013: a context problem, which is a caller-side programming error and is therefore
    # specific rather than neutral.
    assert exc.value.orig.sqlstate == "FB013"


# --------------------------------------------------------------------------- concurrency
#
# Real overlap, every time. One transaction runs the lookup -- which takes the account row
# FOR UPDATE -- and pauses with the row held; the others start, and the watcher confirms
# through pg_locks that they are waiting on a lock before the first is released. Nothing
# here depends on thread scheduling for its overlap.


def _other_backends_waiting(engine) -> int:
    with engine.connect() as connection:
        return connection.execute(
            text(
                "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid "
                "WHERE NOT l.granted AND l.pid <> pg_backend_pid() AND a.datname = current_database()"
            )
        ).scalar_one()


def _wait_until_waiting(engine, count: int) -> bool:
    import time

    deadline = time.monotonic() + BLOCK_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if _other_backends_waiting(engine) >= count:
            return True
        time.sleep(0.05)
    return False


def _other_backends_in_a_transaction(engine) -> int:
    """Backends of this database, other than the asking one, that hold an open transaction.

    Every open transaction holds a ``virtualxid`` lock, whether or not it has written, and
    ``pg_locks`` is readable by every role -- unlike ``pg_stat_activity``'s state columns,
    which a non-superuser sees as NULL for another role's backend. So this is the one
    honest "nothing was left open" check the suite's roles can make.
    """
    with engine.connect() as connection:
        return connection.execute(
            text(
                "SELECT count(DISTINCT l.pid) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid "
                "WHERE l.locktype = 'virtualxid' AND l.pid <> pg_backend_pid() "
                "AND a.datname = current_database() AND a.backend_type = 'client backend'"
            )
        ).scalar_one()


def _assert_nothing_leaked(application_engine, authenticator_engine):
    """No transaction left open by any thread, and every pooled connection checked back in."""
    assert _other_backends_in_a_transaction(application_engine) == 0
    assert application_engine.pool.checkedout() == 0
    assert authenticator_engine.pool.checkedout() == 0


def _assert_not_a_deadlock(results: dict) -> None:
    for label, outcome in results.items():
        if isinstance(outcome, BaseException):
            state = getattr(getattr(outcome, "orig", None), "sqlstate", None)
            assert state != DEADLOCK_DETECTED, f"{label} was resolved by deadlock detection"
            assert DEADLOCK_DETECTED not in repr(outcome), f"{label}: {outcome!r}"


def _accepted_passwords(engine, who, candidates) -> list[str]:
    trusted = authenticator_engine_for(engine)
    accepted = []
    for candidate in candidates:
        with db_engine.transaction(trusted) as session:
            if accounts.login(session, email=who.email, password=Secret(candidate)).account_id:
                accepted.append(candidate)
    return accepted


def test_two_overlapping_changes_leave_exactly_one_winner(application_engine, authenticator_engine, owner_engine):
    """The first change holds the account row; the second is proven to wait on it.

    When the first commits, the second proceeds and finds its authorising session revoked --
    the winner ended every session of the account -- so it is refused neutrally, before the
    compare-and-swap would have refused it. One password in force, one epoch increment, one
    live session, and no deadlock.
    """
    who = person(application_engine, "pw-race")
    paused, released, results = threading.Event(), threading.Event(), {}

    def hold():
        paused.set()
        assert released.wait(timeout=BLOCK_TIMEOUT_SECONDS), "the first change was never released"

    first = _thread("first", results, lambda: change_holding_the_account_row(application_engine, who, hold))
    second = _thread("second", results, lambda: change(application_engine, who, new=SECOND_NEW_PASSWORD))
    first.start()
    assert paused.wait(timeout=BLOCK_TIMEOUT_SECONDS), "the first change never paused"
    second.start()
    assert _wait_until_waiting(application_engine, 1), "the second change must block on the account row"
    released.set()
    _join((first, second))

    _assert_not_a_deadlock(results)
    winner = _unwrap(results["first"])
    assert isinstance(winner, accounts.OpenedSession)
    with pytest.raises(accounts.IdentityRefused):
        _unwrap(results["second"])

    assert _accepted_passwords(application_engine, who, (NEW_PASSWORD, SECOND_NEW_PASSWORD, PASSWORD)) == [NEW_PASSWORD]
    assert owner_rows(owner_engine, "accounts", id=who.account_id)[0]["security_epoch"] == 1
    live = [row for row in owner_rows(owner_engine, "browser_sessions", account_id=who.account_id) if row["revoked_at"] is None]
    assert [row["id"] for row in live] == [winner.session_id]
    _assert_nothing_leaked(application_engine, authenticator_engine)


def test_a_recovery_that_overlaps_a_change_waits_at_the_account_row_and_loses_cleanly(
    application_engine, authenticator_engine, owner_engine
):
    """The deadlock the review found, driven as real overlap, and the documented outcome.

    Under ``0005``'s recovery the change held the account row and waited for the token row,
    the recovery held the token row and waited for the account row, and PostgreSQL killed
    one of them with ``40P01``. Under the lock order both take the account row first: the
    recovery is proven to wait there, then observes that the change superseded its token,
    and returns ``False`` -- the same answer an expired link gets. The change's password is
    the one in force, the token is superseded rather than consumed, nothing is half-done, and
    nothing is left open.
    """
    who = person(application_engine, "pw-recovery-overlap")
    trusted = authenticator_engine_for(application_engine)
    with db_engine.transaction(trusted) as session:
        issued = accounts.request_recovery(session, email=who.email)
    assert issued.secret is not None
    paused, released, results = threading.Event(), threading.Event(), {}

    def hold():
        paused.set()
        assert released.wait(timeout=BLOCK_TIMEOUT_SECONDS), "the change was never released"

    def recover():
        with db_engine.transaction(trusted) as session:
            return accounts.complete_recovery(session, secret=issued.secret, new_password=Secret(RECOVERED_PASSWORD))

    changing = _thread("change", results, lambda: change_holding_the_account_row(application_engine, who, hold))
    recovering = _thread("recovery", results, recover)
    changing.start()
    assert paused.wait(timeout=BLOCK_TIMEOUT_SECONDS), "the change never paused with the row held"
    recovering.start()
    assert _wait_until_waiting(application_engine, 1), "the recovery must block on the account row, not on the token"
    # The order, observed: the recovery is waiting, and its token row is still unlocked --
    # under 0005's body it would already be held, which is the half of the cycle.
    assert _token_row_is_unlocked(owner_engine, issued.secret), "the recovery locked its token before the account row"
    released.set()
    _join((changing, recovering))

    _assert_not_a_deadlock(results)
    winner = _unwrap(results["change"])
    assert isinstance(winner, accounts.OpenedSession)
    assert _unwrap(results["recovery"]) is False

    # One controlled outcome, and no partial state.
    assert _accepted_passwords(application_engine, who, (NEW_PASSWORD, RECOVERED_PASSWORD, PASSWORD)) == [NEW_PASSWORD]
    assert owner_rows(owner_engine, "accounts", id=who.account_id)[0]["security_epoch"] == 1
    tokens = owner_rows(owner_engine, "account_tokens", account_id=who.account_id, kind="account_recovery")
    assert len(tokens) == 1
    assert tokens[0]["consumed_at"] is None and tokens[0]["superseded_at"] is not None
    live = [row for row in owner_rows(owner_engine, "browser_sessions", account_id=who.account_id) if row["revoked_at"] is None]
    assert [row["id"] for row in live] == [winner.session_id]
    _assert_nothing_leaked(application_engine, authenticator_engine)


def test_a_login_a_recovery_and_a_second_change_all_wait_behind_a_change_and_each_loses_cleanly(
    application_engine, authenticator_engine, owner_engine
):
    """Four account-plane writers overlapping on one account: one winner, three neutral losers.

    The change holds the account row. A login verifies the **old** password (against the
    hash it read before the change committed) and then blocks opening its session; a
    recovery blocks completing; a second change blocks at its lookup. All three are proven
    to be waiting. When the change commits: the login is refused because the epoch moved
    under the lock (the API renders that ``401 invalid_credentials``), the recovery finds its
    token superseded and returns ``False`` (``400 invalid_token``), and the second change
    finds its session revoked and is refused (``409 conflict`` on the password route). No
    deadlock, one password, one epoch increment, one live session, nothing left open.
    """
    who = person(application_engine, "pw-four-way")
    trusted = authenticator_engine_for(application_engine)
    with db_engine.transaction(trusted) as session:
        issued = accounts.request_recovery(session, email=who.email)
    assert issued.secret is not None
    paused, released, results = threading.Event(), threading.Event(), {}

    def hold():
        paused.set()
        assert released.wait(timeout=BLOCK_TIMEOUT_SECONDS), "the change was never released"

    def login_with_the_old_password():
        with db_engine.transaction(trusted) as session:
            outcome = accounts.login(session, email=who.email, password=Secret(PASSWORD))
            assert outcome.account_id == who.account_id, "the old hash is still the one read before the commit"
            return accounts.open_session(session)

    def recover():
        with db_engine.transaction(trusted) as session:
            return accounts.complete_recovery(session, secret=issued.secret, new_password=Secret(RECOVERED_PASSWORD))

    def second_change():
        return change(application_engine, who, new=SECOND_NEW_PASSWORD)

    change_thread = _thread("change", results, lambda: change_holding_the_account_row(application_engine, who, hold))
    others = (
        _thread("login", results, login_with_the_old_password),
        _thread("recovery", results, recover),
        _thread("second_change", results, second_change),
    )
    change_thread.start()
    assert paused.wait(timeout=BLOCK_TIMEOUT_SECONDS), "the change never paused with the row held"
    for thread in others:
        thread.start()
    assert _wait_until_waiting(application_engine, 3), "all three must block on the account row"
    released.set()
    _join((change_thread, *others))

    _assert_not_a_deadlock(results)
    winner = _unwrap(results["change"])
    assert isinstance(winner, accounts.OpenedSession)
    with pytest.raises(accounts.IdentityRefused):
        _unwrap(results["login"])
    assert _unwrap(results["recovery"]) is False
    with pytest.raises(accounts.IdentityRefused):
        _unwrap(results["second_change"])

    assert _accepted_passwords(
        application_engine, who, (NEW_PASSWORD, SECOND_NEW_PASSWORD, RECOVERED_PASSWORD, PASSWORD)
    ) == [NEW_PASSWORD]
    assert owner_rows(owner_engine, "accounts", id=who.account_id)[0]["security_epoch"] == 1
    live = [row for row in owner_rows(owner_engine, "browser_sessions", account_id=who.account_id) if row["revoked_at"] is None]
    assert [row["id"] for row in live] == [winner.session_id]
    tokens = owner_rows(owner_engine, "account_tokens", account_id=who.account_id, kind="account_recovery")
    assert all(row["consumed_at"] is None and row["superseded_at"] is not None for row in tokens)
    _assert_nothing_leaked(application_engine, authenticator_engine)


def _token_row_is_unlocked(owner_engine, secret: Secret) -> bool:
    """Whether the token row for ``secret`` can be locked right now, without waiting.

    The probe that tells the two lock orders apart. A consumer that locked its token row
    first (``0005``'s shape) holds that row while it waits for the account row, and this
    ``NOWAIT`` fails with ``55P03``; a consumer that waits at the account row first has not
    touched its token yet, and this succeeds.
    """
    with owner_engine.connect() as connection:
        try:
            connection.execute(
                text(
                    f"SELECT 1 FROM {SCHEMA}.account_tokens t "
                    f"WHERE t.fingerprint = {SCHEMA}.identity_fingerprint(:secret) FOR UPDATE NOWAIT"
                ),
                {"secret": secret.reveal()},
            ).all()
            return True
        except DBAPIError as error:
            assert getattr(error.orig, "sqlstate", None) == "55P03", error
            return False
        finally:
            connection.rollback()


def test_a_verification_that_overlaps_an_account_plane_writer_waits_at_the_account_row_first(
    application_engine, authenticator_engine, owner_engine
):
    """The same defect shape in the other token consumer, corrected the same way.

    ``verify_account_email`` locked its token row first at ``0005``. Once the recovery moved
    under the account row, an unchanged verification would deadlock with a recovery of the
    same unverified account: each holding its token row, each waiting for the other's. It
    now takes the account row first, and this proves it: while another writer holds the
    account row -- the schema owner stands in for it, because a verification is for an
    account that cannot yet sign in -- the verification is shown to be waiting **with its
    token row still unlocked**, and it completes once the row is released.
    """
    trusted = authenticator_engine_for(application_engine)
    email = f"pw-verify-overlap-{uuid.uuid4().hex[:12]}@example.com"
    with db_engine.transaction(trusted) as session:
        outcome = accounts.signup(session, email=email, password=Secret(PASSWORD))
    assert outcome.outcome == "created" and outcome.verification_secret is not None
    account_id, secret = outcome.account_id, outcome.verification_secret
    paused, released, results = threading.Event(), threading.Event(), {}

    def hold_the_account_row():
        with owner_engine.connect() as connection:
            connection.execute(
                text(f"SELECT 1 FROM {SCHEMA}.accounts a WHERE a.id = :a FOR UPDATE"), {"a": account_id}
            ).all()
            paused.set()
            assert released.wait(timeout=BLOCK_TIMEOUT_SECONDS), "the holder was never released"
            connection.rollback()
        return True

    def verify():
        with db_engine.transaction(trusted) as session:
            return accounts.verify_email(session, secret)

    holder = _thread("holder", results, hold_the_account_row)
    verifying = _thread("verify", results, verify)
    holder.start()
    assert paused.wait(timeout=BLOCK_TIMEOUT_SECONDS)
    verifying.start()
    assert _wait_until_waiting(application_engine, 1), "the verification must block on the account row"
    # The order, observed: waiting at the account row, and the token row not yet taken.
    assert _token_row_is_unlocked(owner_engine, secret), "the verification locked its token before the account row"
    released.set()
    _join((holder, verifying))

    _assert_not_a_deadlock(results)
    assert _unwrap(results["verify"]) is True
    (account,) = owner_rows(owner_engine, "accounts", id=account_id)
    assert account["status"] == "active"
    tokens = owner_rows(owner_engine, "account_tokens", account_id=account_id, kind="email_verification")
    assert [row["consumed_at"] is not None for row in tokens] == [True]
    _assert_nothing_leaked(application_engine, authenticator_engine)


def test_a_change_racing_a_recovery_does_not_overwrite_it(application_engine):
    """The epoch check catches what the hash comparison alone would not.

    A recovery advances the epoch. A change prepared before it must not commit afterwards,
    because the caller verified against a hash the account no longer has.
    """
    who = person(application_engine, "pw-recovery-race")
    trusted = authenticator_engine_for(application_engine)
    with db_engine.transaction(trusted) as session:
        outcome = accounts.request_recovery(session, email=who.email)
    with db_engine.transaction(trusted) as session:
        assert accounts.complete_recovery(session, secret=outcome.secret, new_password=Secret("recovered passphrase 77")) is True

    # The change still holds the old password, and the session it names is gone with the
    # recovery -- so it is refused before it reaches the hash at all.
    with pytest.raises(accounts.IdentityError):
        change(application_engine, who)


def test_the_lock_order_is_stated_in_every_account_plane_writer(owner_engine):
    """The account row is locked before the token row in both replaced functions, and the
    change supersedes tokens before it touches the password row: one sequence, everywhere."""
    with owner_engine.connect() as connection:
        bodies = {
            name: body
            for name, body in connection.execute(
                text(
                    "SELECT p.proname, p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
                    "WHERE n.nspname = :s AND p.proname IN ('complete_account_recovery', 'verify_account_email', "
                    "'change_account_password', 'password_change_lookup', 'open_browser_session')"
                ),
                {"s": SCHEMA},
            )
        }
    for name in ("complete_account_recovery", "verify_account_email"):
        body = bodies[name]
        account_lock = body.index(f"FROM {SCHEMA}.accounts a WHERE a.id = v_account_id FOR UPDATE")
        token_lock = body.index("AND t.account_id = v_account_id\n    FOR UPDATE")
        assert account_lock < token_lock, name
    change_body = bodies["change_account_password"]
    assert change_body.index(f"UPDATE {SCHEMA}.account_tokens") < change_body.index(f"UPDATE {SCHEMA}.account_passwords")
    assert change_body.index(f"UPDATE {SCHEMA}.account_passwords") < change_body.index(f"UPDATE {SCHEMA}.auth_bindings")
    assert change_body.index(f"UPDATE {SCHEMA}.auth_bindings") < change_body.index(f"UPDATE {SCHEMA}.browser_sessions")
    for name in ("password_change_lookup", "open_browser_session"):
        assert f"FROM {SCHEMA}.accounts a WHERE" in bodies[name] and "FOR UPDATE" in bodies[name], name


# --------------------------------------------------------------------------- the boundary


@pytest.mark.parametrize(
    "statement",
    (
        f"SELECT * FROM {SCHEMA}.password_change_lookup(gen_random_uuid(), gen_random_uuid())",
        f"SELECT * FROM {SCHEMA}.change_account_password('x', 'y', interval '1 hour')",
    ),
)
def test_the_application_role_cannot_call_either_function(application_engine, statement):
    """The M3.1 correction's boundary, extended rather than reopened.

    The application role is the large runtime surface. Reading a stored Argon2id hash and
    replacing it is authority that milestone moved off it, and Milestone 3.2 keeps it off.
    """
    who, _created = owner_with_workspace(application_engine, "pw-boundary")
    with pytest.raises(ProgrammingError) as exc:
        with account_session(application_engine, who) as (session, _context):
            session.execute(text(statement))
    assert isinstance(exc.value.orig, InsufficientPrivilege)
    assert "permission denied for function" in str(exc.value.orig)


def test_no_password_or_secret_reaches_any_stored_row(application_engine, owner_engine):
    who = person(application_engine, "pw-nostore")
    opened = change(application_engine, who)
    assert opened is not None
    stored = everything_stored(owner_engine)
    for secret in (PASSWORD, NEW_PASSWORD, opened.session_secret.reveal(), opened.csrf_secret.reveal()):
        assert secret not in stored


def test_the_replacement_session_has_the_same_properties_as_a_login_s(application_engine, owner_engine):
    """``change_account_password`` mints inline rather than calling ``open_browser_session``.

    The migration says why (``identity_context_write`` refuses to re-point a context inside
    one transaction, so a function that wrote a ``password_change_challenge`` cannot then
    write the ``login_challenge`` the other function requires). This is the drift control for
    that duplication: both paths must produce a session row of the same shape.
    """
    who = person(application_engine, "pw-shape")
    from_login = owner_rows(owner_engine, "browser_sessions", id=who.session_id)[0]
    opened = change(application_engine, who)
    assert opened is not None
    from_change = owner_rows(owner_engine, "browser_sessions", id=opened.session_id)[0]

    assert set(from_change) == set(from_login)
    assert from_change["account_id"] == from_login["account_id"]
    assert from_change["revoked_at"] is None
    # Both fingerprints are present and are digests, not secrets.
    for column in ("fingerprint", "csrf_fingerprint"):
        assert len(from_change[column]) == 64
        assert opened.session_secret.reveal() != from_change[column]
    assert credentials  # imported for the credential test above; keeps the import used
