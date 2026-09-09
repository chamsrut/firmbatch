"""Accounts and browser sessions: the Python side of Milestone 3.1's identity functions.

Deliberately thin, like ``db/auth.py``: no decision made here is load-bearing, because
every one is made again inside a ``SECURITY DEFINER`` function in migration ``0005`` that
the caller cannot reach around. What this module adds is typed results, an explanatory
error where the database would otherwise give a bare SQLSTATE, the pre-checks that keep a
malformed secret out of a statement a server could log, and the transaction helper that
opens a session, presents a session secret, and refuses everything that would let the
context leak.

Two credential types, two binding paths
---------------------------------------

* :func:`bind_session_context` presents a **session secret** (``fbs_...``) and, when the
  request is a cookie-authenticated mutation, the session's **CSRF secret** (``fbc_...``).
  ``firmbatch.bind_session_context`` hashes both, looks the session up in a table no
  runtime role can read, re-derives the membership behind its workspace binding, and --
  in ``workspace`` mode -- establishes a tenant context with ``actor_kind = 'session'``
  and the membership role's permission set. In ``account`` mode it establishes no tenant
  context at all: an account-level session exists before any workspace does.
* Milestone 2.3's :func:`~firmbatch.control_plane.db.auth.bind_authenticated_context`
  presents a **bearer credential** (``fbk_...``), as before.

Neither path accepts the other's secret. The format check here refuses a bearer credential
before it is sent to the session function and vice versa; the database refuses both again,
because the two fingerprints live in different tables. Nothing converts one into the other.

What the runtime is trusted for, and how the database bounds it
---------------------------------------------------------------

PostgreSQL has no Argon2, so the **password comparison happens here**, in
:func:`login`, against the hash ``firmbatch.login_lookup`` returns for one address. The
database bounds that trust: the lookup records which account was challenged in a
transaction-scoped row no runtime role can write, and ``open_browser_session`` opens a
session only for that account, in that transaction. A runtime process that skipped the
comparison could sign in as an account it looked up; it could not sign in as one it did
not, and everything after sign-in -- workspace binding, credential issuance -- is decided
by membership inside the database. ADR 0009 records the limitation.

The challenge is bound to a **version** as well as to an account. ``login_lookup`` reads the
stored hash and the account's ``security_epoch`` in one statement, and
``open_browser_session`` compares that epoch against the account row under a lock that
conflicts with account recovery, held to commit. So a password verified here against a hash
a concurrent recovery has already replaced opens no session -- the window between the read
and the comparison is exactly as long as Argon2 takes, and it is a window a recovery can
commit in.

The trusted-issuer boundary
---------------------------

Eight of the functions this module calls are **not the application role's**: signup, the two
mailbox-verification entry points, login lookup, session opening, and the three recovery
ones. They mint or consume a mailbox-proof secret, hand back a stored hash, or turn a
challenge into a session, and each is granted to the narrow **authenticator** role instead.
A caller therefore passes the authenticator engine to :func:`signup`,
:func:`request_email_verification`, :func:`verify_email`, :func:`login`,
:func:`open_session`, :func:`request_recovery` and :func:`complete_recovery`; every other
function here is the application role's. ``db/roles.py`` holds the inventory and ADR 0009
records why.

Secrets
-------

Every secret this module receives from the database is wrapped in
:class:`~firmbatch.control_plane.security.secrets.Secret` immediately and is never bound
to a plain name. Every statement that carries a secret parameter is executed through
:func:`_execute` with ``scrub`` set, so an unexpected database error cannot render it.
Expected failures are translated with ``from None`` **outside** the ``except`` block, so
no psycopg exception -- and no parameter rendering -- travels as ``__cause__`` or
``__context__``.
"""

from __future__ import annotations

import re
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterator

from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from .. import config
from ..security.authorization import AuthorizationError
from ..security.passwords import (
    DUMMY_HASH,
    PasswordPolicyError,
    hash_password,
    verify_password,
)
from ..security.secrets import Secret, is_well_formed_identity_secret, looks_like_secret
from . import engine as db_engine
from .base import SCHEMA
from .idempotency import IdempotencyConflict
from .models import EMAIL_MAX_LENGTH, EMAIL_REGEX

#: The SQLSTATEs migration ``0005`` raises, mirrored here because this module translates
#: them; a test holds the copies equal.
IDENTITY_REFUSED_SQLSTATE = "FB010"
IDENTITY_CONFLICT_SQLSTATE = "FB011"
IDENTITY_KEY_REUSE_SQLSTATE = "FB012"
IDENTITY_CONTEXT_SQLSTATE = "FB013"

_INSUFFICIENT_PRIVILEGE = "42501"
_INVALID_PARAMETER_VALUE = "22023"
_INVALID_TRANSACTION_STATE = "25000"
_FEATURE_NOT_SUPPORTED = "0A000"
_READ_ONLY_SQL_TRANSACTION = "25006"
_UNIQUE_VIOLATION = "23505"

#: The one thing a neutral refusal ever says. Written here as a constant rather than taken
#: from the database's message, because psycopg renders a plpgsql exception's ``CONTEXT``,
#: which names the line that raised -- and a line number is a branch identifier.
IDENTITY_REFUSED_MESSAGE = (
    "the identity operation was refused. The target is absent, hidden, in another tenant, "
    "revoked, expired, not addressed to this account, or not bound -- the cases are "
    "deliberately indistinguishable, because a refusal that told them apart would answer "
    "whether an identifier exists outside what this session may see."
)

#: Lifetimes. Configuration inside the bounds the database enforces; stated here rather
#: than left to a caller, so the product has one answer.
DEFAULT_SESSION_TTL = timedelta(hours=12)
DEFAULT_VERIFICATION_TTL = timedelta(hours=24)
DEFAULT_RECOVERY_TTL = timedelta(hours=1)

_EMAIL_PATTERN = re.compile(EMAIL_REGEX)
#: What an address is trimmed of. ASCII only, mirrored by migration 0005's
#: ``ASCII_WHITESPACE_SQL``; ``str.strip()`` with no argument would also strip Unicode
#: whitespace that the database does not, and the two sides must agree on every input.
ASCII_WHITESPACE = " \t\n\r\f\v"


class IdentityError(RuntimeError):
    """Base class for every refusal this module and its siblings make."""


class IdentityRefused(IdentityError):
    """The neutral refusal. One message for every way a target can be unavailable."""


class IdentityConflict(IdentityError):
    """A state conflict inside the caller's own visible scope: the last owner, an existing member."""


class SessionContextError(IdentityError):
    """No bound session, a CSRF token that was not verified, or the wrong bind mode.

    A caller-side programming error rather than a refusal about a target, which is why it
    may be specific.
    """


class SessionAuthenticationError(IdentityError):
    """A session secret was refused before it reached the database: it is not one."""


@dataclass(frozen=True)
class SessionContext:
    """What one transaction's bound browser session is, as PostgreSQL reports it."""

    session_id: uuid.UUID
    account_id: uuid.UUID
    email: str
    email_verified: bool
    workspace_id: uuid.UUID | None
    tenant_id: uuid.UUID | None
    membership_id: uuid.UUID | None
    role: str | None
    expires_at: datetime
    csrf_verified: bool
    #: ``account`` or ``workspace``: which mode the bind ran in.
    mode: str

    @property
    def bound(self) -> bool:
        return self.workspace_id is not None

    def __repr__(self) -> str:
        return (
            f"SessionContext(session_id={self.session_id}, account_id={self.account_id}, "
            f"workspace_id={self.workspace_id}, role={self.role!r}, mode={self.mode!r}, "
            f"csrf_verified={self.csrf_verified})"
        )


@dataclass(frozen=True)
class OpenedSession:
    """A freshly opened session: the two secrets exist here and in the caller's response."""

    session_id: uuid.UUID
    account_id: uuid.UUID
    session_secret: Secret
    csrf_secret: Secret
    expires_at: datetime

    def __repr__(self) -> str:
        return f"OpenedSession(session_id={self.session_id}, account_id={self.account_id}, secrets=<redacted>)"


@dataclass(frozen=True)
class SignupOutcome:
    """What signup produced. ``verification_secret`` is present only for a new account."""

    outcome: str
    account_id: uuid.UUID | None
    verification_secret: Secret | None

    def __repr__(self) -> str:
        return f"SignupOutcome(outcome={self.outcome!r}, account_id={self.account_id}, secret=<redacted>)"


@dataclass(frozen=True)
class TokenOutcome:
    outcome: str
    account_id: uuid.UUID | None
    secret: Secret | None

    def __repr__(self) -> str:
        return f"TokenOutcome(outcome={self.outcome!r}, account_id={self.account_id}, secret=<redacted>)"


@dataclass(frozen=True)
class LoginOutcome:
    """The result of a password check. ``account_id`` is set only when the password matched."""

    account_id: uuid.UUID | None
    email_verified: bool


@dataclass(frozen=True)
class AccountProfile:
    account_id: uuid.UUID
    email: str
    email_verified: bool
    created_at: datetime


@dataclass(frozen=True)
class SessionSummary:
    session_id: uuid.UUID
    created_at: datetime
    last_seen_at: datetime | None
    expires_at: datetime
    workspace_id: uuid.UUID | None
    is_current: bool


# --------------------------------------------------------------------------- translation


def _sqlstate(error: DBAPIError) -> str | None:
    return getattr(getattr(error, "orig", None), "sqlstate", None)


def translate(error: DBAPIError) -> Exception | None:
    """The database's refusal, as the Python error that means the same thing.

    Shared by the three identity modules. Only the server's own primary message travels,
    and only for the SQLSTATEs migration ``0005`` raises deliberately; the neutral refusal
    drops the database's text entirely, for the reason :data:`IDENTITY_REFUSED_MESSAGE`
    gives. Anything unanticipated becomes ``None``, and the caller decides.
    """
    state = _sqlstate(error)
    message = str(getattr(error, "orig", "")).strip()
    if state == IDENTITY_REFUSED_SQLSTATE:
        return IdentityRefused(IDENTITY_REFUSED_MESSAGE)
    if state == IDENTITY_CONFLICT_SQLSTATE:
        return IdentityConflict(message or "the identity operation conflicts with the current state")
    if state == IDENTITY_KEY_REUSE_SQLSTATE:
        return IdempotencyConflict(
            "that idempotency key was already used for a different request. Reusing a key for a "
            "changed request is a caller bug -- retry the original request with this key, or use "
            "a new key for the new one. Nothing about the existing request is disclosed here."
        )
    if state == IDENTITY_CONTEXT_SQLSTATE:
        return SessionContextError(message or "this transaction has no usable session context")
    if state == _INSUFFICIENT_PRIVILEGE:
        return AuthorizationError(message or "this context is not permitted to do that")
    if state == _INVALID_PARAMETER_VALUE:
        return IdentityError(message or "the identity request was refused")
    if state == _INVALID_TRANSACTION_STATE:
        return SessionContextError(
            "this transaction already carries an identity or tenant context. A transaction binds "
            "one session and keeps it; open a separate transaction to act as another."
        )
    if state == _FEATURE_NOT_SUPPORTED:
        return SessionContextError(
            "binding a session requires the READ COMMITTED isolation level, so that a revocation "
            "committed before the bind statement began is observed."
        )
    if state == _READ_ONLY_SQL_TRANSACTION:
        return db_engine.WritablePrimaryRequiredError(
            f"{message or 'a writable primary is required'} Binding a session writes protected "
            "transaction state; authenticated work is primary-only at this milestone."
        )
    return None


def _execute(session: Session, statement, params=None, *, scrub: tuple[str, ...] = ()):
    """Run one statement, translating a refusal and attaching nothing.

    The raise happens after the ``except`` block, not inside it, so that nothing is
    attached as ``__context__``; and an unexpected error on a statement that carried a
    secret is re-raised with the value scrubbed out, because a ``DBAPIError`` renders its
    parameters.
    """
    failure: Exception | None = None
    try:
        return session.execute(statement, params or {})
    except DBAPIError as error:
        failure = translate(error)
        if failure is None:
            if not scrub:
                raise
            failure = IdentityError(
                "the identity statement failed unexpectedly; the database's explanation is "
                f"deliberately scrubbed: {config.scrub_secrets(str(error), scrub)}"
            )
    raise failure from None


# --------------------------------------------------------------------------- inputs


def normalize_email(value: object) -> str:
    """Trim and lower-case an address, and refuse one outside the bounded grammar.

    The same rule ``firmbatch.identity_normalize_email`` applies, so the two agree; a test
    walks a corpus through both. The refusal never repeats the value.
    """
    shape = looks_like_secret(value)
    if shape is not None:
        raise IdentityError(
            f"the email address looks like {shape}; the value is deliberately not repeated"
        )
    if not isinstance(value, str) or len(value) > EMAIL_MAX_LENGTH + 32:
        raise IdentityError("the email address is not acceptable; the value is deliberately not repeated")
    normalized = value.strip(ASCII_WHITESPACE).lower()
    if len(normalized) > EMAIL_MAX_LENGTH or not _EMAIL_PATTERN.fullmatch(normalized):
        raise IdentityError("the email address is not acceptable; the value is deliberately not repeated")
    return normalized


def _require_secret(value: object, kind: str) -> str:
    """A well-formed secret of ``kind``, or a refusal that never reached the database.

    The check is what keeps a bearer credential out of the session function, a session
    secret out of the credential function, and a typo out of a statement log.
    """
    if not is_well_formed_identity_secret(value, kind):
        raise SessionAuthenticationError(
            f"the presented value is not a well-formed Firmbatch {kind} secret, so it was refused "
            "without being sent to the database."
        )
    return value.reveal() if isinstance(value, Secret) else value


def _require_ttl(ttl: timedelta, *, what: str) -> timedelta:
    if not isinstance(ttl, timedelta) or ttl <= timedelta(0):
        raise IdentityError(f"the {what} lifetime is a positive timedelta")
    return ttl


def _require_transaction(session: Session, function: str) -> None:
    if not session.in_transaction():
        raise IdentityError(f"{function} requires an open transaction")


# --------------------------------------------------------------------------- accounts


def signup(session: Session, *, email: str, password: Secret, ttl: timedelta = DEFAULT_VERIFICATION_TTL) -> SignupOutcome:
    """Create an account, or learn that the address already has one. Neutral at the boundary.

    The password is hashed here and only the hash travels. The verification secret comes
    back once, for the email-delivery boundary; nothing persists it.
    """
    _require_transaction(session, "signup")
    normalized = normalize_email(email)
    password_hash = hash_password(password)
    row = _execute(
        session,
        text(
            f"SELECT outcome, account_id, verification_secret FROM {SCHEMA}.signup_account("
            ":email, :password_hash, CAST(:ttl AS interval))"
        ),
        {"email": normalized, "password_hash": password_hash, "ttl": _require_ttl(ttl, what="verification")},
        scrub=(password_hash,),
    ).one()
    return SignupOutcome(
        outcome=row.outcome,
        account_id=row.account_id,
        verification_secret=Secret(row.verification_secret) if row.verification_secret else None,
    )


def request_email_verification(session: Session, *, email: str, ttl: timedelta = DEFAULT_VERIFICATION_TTL) -> TokenOutcome:
    _require_transaction(session, "request_email_verification")
    try:
        normalized = normalize_email(email)
    except IdentityError:
        return TokenOutcome(outcome="unknown", account_id=None, secret=None)
    row = _execute(
        session,
        text(
            f"SELECT outcome, account_id, verification_secret FROM {SCHEMA}.request_email_verification("
            ":email, CAST(:ttl AS interval))"
        ),
        {"email": normalized, "ttl": _require_ttl(ttl, what="verification")},
    ).one()
    return TokenOutcome(
        outcome=row.outcome,
        account_id=row.account_id,
        secret=Secret(row.verification_secret) if row.verification_secret else None,
    )


def verify_email(session: Session, secret: Secret | str) -> bool:
    """Consume a verification token. ``False`` for unknown, consumed, superseded and expired alike."""
    _require_transaction(session, "verify_email")
    if not is_well_formed_identity_secret(secret, "email_verification"):
        return False
    value = secret.reveal() if isinstance(secret, Secret) else secret
    return bool(
        _execute(
            session,
            text(f"SELECT {SCHEMA}.verify_account_email(:secret)"),
            {"secret": value},
            scrub=(value,),
        ).scalar_one()
    )


def request_recovery(session: Session, *, email: str, ttl: timedelta = DEFAULT_RECOVERY_TTL) -> TokenOutcome:
    _require_transaction(session, "request_recovery")
    try:
        normalized = normalize_email(email)
    except IdentityError:
        return TokenOutcome(outcome="unknown", account_id=None, secret=None)
    row = _execute(
        session,
        text(
            f"SELECT outcome, account_id, recovery_secret FROM {SCHEMA}.request_account_recovery("
            ":email, CAST(:ttl AS interval))"
        ),
        {"email": normalized, "ttl": _require_ttl(ttl, what="recovery")},
    ).one()
    return TokenOutcome(
        outcome=row.outcome,
        account_id=row.account_id,
        secret=Secret(row.recovery_secret) if row.recovery_secret else None,
    )


def complete_recovery(session: Session, *, secret: Secret | str, new_password: Secret) -> bool:
    """Consume a recovery token and replace the password. Revokes every session of the account.

    The expensive memory-hard hash of the new password is the **last** thing that happens,
    and only once possession of a valid, unconsumed recovery token is established. A malformed
    token is refused by shape; a well-shaped token that matches nothing outstanding is refused
    by the possession pre-check -- neither reaches Argon2. The completion function then
    re-validates and consumes the token atomically under a row lock, so the ordering does not
    open a window between the pre-check and the consume.
    """
    _require_transaction(session, "complete_recovery")
    # Shape first: a malformed token never invokes the KDF.
    if not is_well_formed_identity_secret(secret, "account_recovery"):
        return False
    value = secret.reveal() if isinstance(secret, Secret) else secret
    # Possession before the hash: a well-shaped token matching no live recovery token is
    # refused before any Argon2 work. This reveals nothing the completion result would not.
    valid = _execute(
        session,
        text(f"SELECT {SCHEMA}.account_recovery_token_valid(:secret)"),
        {"secret": value},
        scrub=(value,),
    ).scalar_one()
    if not valid:
        return False
    password_hash = hash_password(new_password)
    return bool(
        _execute(
            session,
            text(f"SELECT {SCHEMA}.complete_account_recovery(:secret, :password_hash)"),
            {"secret": value, "password_hash": password_hash},
            scrub=(value, password_hash),
        ).scalar_one()
    )


def purge_expired_unverified_accounts(session: Session, *, older_than: timedelta) -> int:
    """Reclaim unverified accounts older than ``older_than`` that hold no active membership.

    The explicit expiry control against unbounded unverified-account and verification-token
    growth (Milestone 3.1 security correction). ``firmbatch.purge_expired_unverified_accounts``
    is executable by nobody at runtime -- it is a maintenance operation the schema owner runs
    -- so a runtime role calling this is refused, which is the intended boundary. Returns the
    number of accounts reclaimed.
    """
    _require_transaction(session, "purge_expired_unverified_accounts")
    if not isinstance(older_than, timedelta) or older_than <= timedelta(0):
        raise IdentityError("the reclaim age is a positive timedelta")
    return int(
        _execute(
            session,
            text(f"SELECT {SCHEMA}.purge_expired_unverified_accounts(CAST(:age AS interval))"),
            {"age": older_than},
        ).scalar_one()
    )


def login(session: Session, *, email: str, password: Secret) -> LoginOutcome:
    """Check a password. Costs the same whether or not the address has an account.

    On success the transaction is left carrying the login challenge, so
    :func:`open_session` can open a session for exactly this account. ``account_id`` is
    ``None`` for a wrong password and an unknown address alike.
    """
    _require_transaction(session, "login")
    if not isinstance(password, Secret):
        raise PasswordPolicyError("a password is handled as a Secret, never as a plain string")
    try:
        normalized = normalize_email(email)
    except IdentityError:
        # Still consult the database, so the challenge row is written and the request
        # takes the same path; the address cannot match anything.
        normalized = None
    row = _execute(
        session,
        text(f"SELECT account_id, password_hash, email_verified FROM {SCHEMA}.login_lookup(:email)"),
        {"email": normalized},
    ).one()
    stored = row.password_hash if row.password_hash else DUMMY_HASH
    matched = verify_password(stored, password)
    if row.account_id is None or not matched:
        return LoginOutcome(account_id=None, email_verified=False)
    return LoginOutcome(account_id=row.account_id, email_verified=bool(row.email_verified))


def open_session(session: Session, *, ttl: timedelta = DEFAULT_SESSION_TTL) -> OpenedSession:
    """Open a browser session for the account this transaction challenged and verified.

    Requires :func:`login` to have run in this transaction and returned an account; the
    database refuses otherwise, and refuses an unverified account with the neutral message.
    """
    _require_transaction(session, "open_session")
    row = _execute(
        session,
        text(
            "SELECT session_id, account_id, session_secret, csrf_secret, expires_at "
            f"FROM {SCHEMA}.open_browser_session(CAST(:ttl AS interval))"
        ),
        {"ttl": _require_ttl(ttl, what="session")},
    ).one()
    return OpenedSession(
        session_id=row.session_id,
        account_id=row.account_id,
        session_secret=Secret(row.session_secret),
        csrf_secret=Secret(row.csrf_secret),
        expires_at=row.expires_at,
    )


# --------------------------------------------------------------------------- sessions


def bind_session_context(
    session: Session,
    session_secret: Secret | str,
    *,
    csrf_secret: Secret | str | None = None,
    mode: str = "account",
) -> SessionContext:
    """Present a session secret and, optionally, its CSRF secret; acquire this transaction's session.

    ``mode`` is ``account`` (no tenant context; account-level operations) or ``workspace``
    (the session's bound workspace, re-derived from its membership, becomes the tenant
    context). Fails closed on everything: no transaction, a savepoint, a malformed or
    wrong secret, a revoked or expired session, a wrong CSRF secret, and -- in workspace
    mode -- a session that is not bound or whose membership is gone.
    """
    if mode not in ("account", "workspace"):
        raise IdentityError("the session bind mode is 'account' or 'workspace'")
    if not session.in_transaction():
        raise SessionAuthenticationError("bind_session_context requires an open transaction")
    db_engine.refuse_inside_savepoint(session, "bind a browser session")
    db_engine.require_writable_primary(session)
    secret_value = _require_secret(session_secret, "session")
    csrf_value = _require_secret(csrf_secret, "csrf") if csrf_secret is not None else None
    scrub = (secret_value,) + ((csrf_value,) if csrf_value else ())
    row = _execute(
        session,
        text(
            "SELECT session_id, account_id, email, email_verified, workspace_id, tenant_id, "
            "membership_id, role, expires_at, csrf_verified "
            f"FROM {SCHEMA}.bind_session_context(:secret, :csrf, :mode)"
        ),
        {"secret": secret_value, "csrf": csrf_value, "mode": mode},
        scrub=scrub,
    ).one()
    context = SessionContext(
        session_id=row.session_id,
        account_id=row.account_id,
        email=row.email,
        email_verified=bool(row.email_verified),
        workspace_id=row.workspace_id,
        tenant_id=row.tenant_id,
        membership_id=row.membership_id,
        role=row.role,
        expires_at=row.expires_at,
        csrf_verified=bool(row.csrf_verified),
        mode=mode,
    )
    db_engine.note_context_change(session, context.tenant_id if mode == "workspace" else None)
    return context


@contextmanager
def session_transaction(
    engine: Engine,
    session_secret: Secret | str,
    *,
    csrf_secret: Secret | str | None = None,
    mode: str = "account",
) -> Iterator[tuple[Session, SessionContext]]:
    """One transaction acting as one browser session. Commits on success, rolls back on error."""
    with db_engine.transaction(engine) as session:
        context = bind_session_context(session, session_secret, csrf_secret=csrf_secret, mode=mode)
        yield session, context


def account_profile(session: Session) -> AccountProfile:
    row = _execute(
        session, text(f"SELECT account_id, email, email_verified, created_at FROM {SCHEMA}.account_profile()")
    ).one()
    return AccountProfile(
        account_id=row.account_id, email=row.email, email_verified=bool(row.email_verified), created_at=row.created_at
    )


def account_sessions(session: Session) -> list[SessionSummary]:
    rows = _execute(
        session,
        text(
            "SELECT session_id, created_at, last_seen_at, expires_at, workspace_id, is_current "
            f"FROM {SCHEMA}.account_sessions()"
        ),
    ).all()
    return [
        SessionSummary(
            session_id=row.session_id,
            created_at=row.created_at,
            last_seen_at=row.last_seen_at,
            expires_at=row.expires_at,
            workspace_id=row.workspace_id,
            is_current=bool(row.is_current),
        )
        for row in rows
    ]


def revoke_session(session: Session, session_id: uuid.UUID) -> bool:
    """Revoke one of this account's sessions. ``False`` for another account's, an unknown id, or an already-revoked one."""
    if not isinstance(session_id, uuid.UUID):
        raise IdentityError("a session id is a UUID")
    return bool(
        _execute(
            session, text(f"SELECT {SCHEMA}.revoke_browser_session(:session_id)"), {"session_id": session_id}
        ).scalar_one()
    )


def revoke_all_sessions(session: Session, *, keep_current: bool = False) -> int:
    return int(
        _execute(
            session,
            text(f"SELECT {SCHEMA}.revoke_all_browser_sessions(:keep)"),
            {"keep": bool(keep_current)},
        ).scalar_one()
    )
