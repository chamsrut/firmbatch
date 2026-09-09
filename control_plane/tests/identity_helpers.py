"""Shared helpers for the Milestone 3.1 identity suites. Not a test module.

Every helper goes through the supported Python entry points -- ``db/accounts.py``,
``db/membership.py``, ``db/credentials.py`` -- never through hand-written SQL, so the
fixtures exercise the boundary rather than working around it. The one exception is
:func:`owner_rows`, which reads a protected table as the schema owner so a test can
assert what was persisted; it is a *reading* of the truth, not a path into it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import make_url, text

from firmbatch.control_plane.db import accounts, credentials, membership
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.security.secrets import Secret

PASSWORD = "correct horse battery staple 42"

# --------------------------------------------------------------------------- authenticator

#: The trusted-issuer (authenticator) engine, keyed by disposable-database name (Milestone
#: 3.1 security correction). Signup, email verification, login, session opening and recovery
#: are executable by the authenticator role and NOT by the application role, so a helper
#: that registers an account, verifies a mailbox, signs in or recovers must run those on
#: this engine. The ``authenticator_engine`` fixture in conftest registers it; helpers look
#: it up by the database the application engine is connected to, so callers keep passing the
#: application engine and nothing at every call site has to change.
_AUTHENTICATOR_ENGINES: dict = {}


def register_authenticator_engine(engine) -> None:
    _AUTHENTICATOR_ENGINES[make_url(str(engine.url)).database] = engine


def authenticator_engine_for(application_engine):
    database = make_url(str(application_engine.url)).database
    engine = _AUTHENTICATOR_ENGINES.get(database)
    if engine is None:  # pragma: no cover - a wiring error, surfaced loudly
        raise RuntimeError(
            "no authenticator engine is registered for this database. A test that signs in, "
            "recovers an account, or builds a person must let the authenticator_engine fixture "
            "run (it is autouse and session-scoped, so this means the fixture failed to set up)."
        )
    return engine


def unique_email(label: str = "person") -> str:
    return f"{label}-{uuid.uuid4().hex[:12]}@example.com"


def key(prefix: str = "k") -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


@dataclass(frozen=True)
class Person:
    email: str
    account_id: uuid.UUID
    session_id: uuid.UUID
    session_secret: Secret
    csrf_secret: Secret


def signup_verified(engine, email: str | None = None, password: str = PASSWORD) -> tuple[str, uuid.UUID]:
    """Sign up and verify one account. Returns the address and the account id.

    Signup and mailbox verification are the authenticator role's, not the application
    role's: minting a verification secret and consuming one is the mailbox-control proof,
    and only the principal trusted to hand a raw secret to the email adapter holds it.
    """
    email = email or unique_email()
    trusted = authenticator_engine_for(engine)
    with db_engine.transaction(trusted) as session:
        outcome = accounts.signup(session, email=email, password=Secret(password))
        assert outcome.outcome == "created", outcome.outcome
        token = outcome.verification_secret
        account_id = outcome.account_id
    with db_engine.transaction(trusted) as session:
        assert accounts.verify_email(session, token) is True
    return email, account_id


def login_session(engine, email: str, password: str = PASSWORD, ttl: timedelta = timedelta(hours=1)) -> accounts.OpenedSession:
    # Login and session opening are the authenticator role's, not the application role's.
    with db_engine.transaction(authenticator_engine_for(engine)) as session:
        outcome = accounts.login(session, email=email, password=Secret(password))
        assert outcome.account_id is not None, "login failed for a fixture account"
        return accounts.open_session(session, ttl=ttl)


def person(engine, label: str = "person") -> Person:
    """A verified account with one open, account-level session."""
    email, account_id = signup_verified(engine, unique_email(label))
    opened = login_session(engine, email)
    return Person(
        email=email,
        account_id=account_id,
        session_id=opened.session_id,
        session_secret=opened.session_secret,
        csrf_secret=opened.csrf_secret,
    )


def create_workspace(engine, who: Person, slug: str | None = None, idempotency_key: str | None = None) -> membership.CreatedWorkspace:
    slug = slug or f"ws-{uuid.uuid4().hex[:8]}"
    with accounts.session_transaction(engine, who.session_secret, csrf_secret=who.csrf_secret, mode="account") as (session, _):
        return membership.create_workspace(session, slug=slug, name=f"Workspace {slug}", idempotency_key=idempotency_key)


def bind(engine, who: Person, workspace_id: uuid.UUID) -> membership.WorkspaceBinding:
    with accounts.session_transaction(engine, who.session_secret, csrf_secret=who.csrf_secret, mode="account") as (session, _):
        return membership.bind_session_workspace(session, workspace_id)


def workspace_session(engine, who: Person, *, csrf: bool = True):
    """A transaction bound to ``who``'s selected workspace, CSRF-verified unless told otherwise."""
    return accounts.session_transaction(
        engine, who.session_secret, csrf_secret=who.csrf_secret if csrf else None, mode="workspace"
    )


def account_session(engine, who: Person, *, csrf: bool = True):
    return accounts.session_transaction(
        engine, who.session_secret, csrf_secret=who.csrf_secret if csrf else None, mode="account"
    )


def owner_with_workspace(engine, label: str = "owner") -> tuple[Person, membership.CreatedWorkspace]:
    """A verified account that owns one workspace and has selected it."""
    who = person(engine, label)
    created = create_workspace(engine, who)
    bind(engine, who, created.workspace_id)
    return who, created


def invite_and_accept(engine, inviter: Person, invitee: Person, role: str = "member") -> membership.AcceptedInvitation:
    with workspace_session(engine, inviter) as (session, _):
        invitation = membership.create_invitation(session, email=invitee.email, role=role, idempotency_key=key("inv"))
    with account_session(engine, invitee) as (session, _):
        return membership.accept_invitation(session, invitation.secret, idempotency_key=key("acc"))


def issue_credential(engine, who: Person, scopes=("workspace:read",), label: str | None = "test") -> credentials.IssuedCredential:
    with workspace_session(engine, who) as (session, context):
        return credentials.issue(session, role=context.role, scopes=scopes, label=label, idempotency_key=key("iss"))


def owner_rows(owner_engine, table: str, **where) -> list:
    """Read a protected table as the schema owner. For assertions about persistence only."""
    clauses = " AND ".join(f"{column} = :{column}" for column in where) or "true"
    with owner_engine.connect() as connection:
        return connection.execute(text(f"SELECT * FROM {SCHEMA}.{table} WHERE {clauses}"), where).mappings().all()


def everything_stored(owner_engine) -> str:
    """Every row of every table in the schema, rendered, so a test can assert a secret is absent."""
    with owner_engine.connect() as connection:
        tables = connection.execute(
            text(
                "SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
                "ON n.oid = c.relnamespace WHERE n.nspname = :s AND c.relkind = 'r'"
            ),
            {"s": SCHEMA},
        ).scalars().all()
        rendered = []
        for table in tables:
            for row in connection.execute(text(f"SELECT * FROM {SCHEMA}.{table}")).all():
                rendered.append(repr(tuple(row)))
    return "\n".join(rendered)
