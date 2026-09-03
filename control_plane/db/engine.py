"""Engines, transactions, and the transaction-local tenant context.

The isolation boundary in this package is enforced by PostgreSQL row-level security, not
by remembering to write ``WHERE tenant_id = ...``. What the application supplies is the
*context*: one PostgreSQL custom setting, ``app.tenant_id``, set with ``set_config(...,
is_local => true)`` so it belongs to the transaction and to nothing else.

Four properties, each of which is a separate defence and each of which is tested:

* **Absence fails closed.** With no context, ``app_current_tenant_id()`` is NULL, every
  policy predicate is NULL, so reads return no rows and writes are rejected. A forgotten
  ``set`` cannot become a cross-tenant read.

* **Context is never inherited.** Every transaction opens by clearing ``app.tenant_id``
  to empty *before* applying whatever the caller asked for. Transaction-local is not the
  same as absent: a ``SET`` (not ``SET LOCAL``) executed earlier on a pooled connection,
  or an ``options=-c app.tenant_id=...`` smuggled into a URL, is a **session** value that
  ``current_setting`` returns quite happily to a transaction that set nothing. Both were
  reproduced against a real server before this baseline existed. The session value is also
  cleared on connect, so the two cover each other.

* **The identity map cannot outlive a context.** SQLAlchemy answers ``session.get()`` from
  its identity map without going to the database, so a ``Session`` reused across a tenant
  switch will hand back the previous tenant's object with PostgreSQL never consulted --
  also reproduced. Any change of context expunges the map, forcing re-evaluation.

* **The principal is verified, not assumed.** Every new pooled connection is asked who it
  authenticated as, and refused if it is a superuser, ``BYPASSRLS``, a tenant-table owner,
  or a member of any role that is. See ``db/principal.py``.

``set_tenant_context`` refuses to run outside a transaction. Outside one, ``SET LOCAL``
silently applies to the current statement only -- it would appear to work and then leave
the next statement unscoped, which is the exact failure this design exists to prevent.

What this does NOT claim: the application role can set ``app.tenant_id`` to any value it
likes. RLS bounds what a *query* can reach given a context; it does not bound a control
plane that has been compromised into choosing the wrong context. Resolving the context
from an authenticated credential is M2.3/M3 work, and ADR 0004 records the limit.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import Connection, Engine, create_engine, event, make_url, text
from sqlalchemy.orm import Session

from .. import config
from .base import SEARCH_PATH

#: The PostgreSQL custom setting carrying the transaction-local tenant. The SQL function
#: ``firmbatch.app_current_tenant_id()`` created by migration 0001 reads this and nothing
#: else.
TENANT_SETTING = "app.tenant_id"

#: Where the tenant a Session was last scoped to is remembered, so a change of context can
#: be detected and the identity map dropped.
_SESSION_TENANT_KEY = "firmbatch_tenant_context"


class TenantContextError(RuntimeError):
    """Raised when tenant context is missing, malformed, or set outside a transaction."""


class UnsupportedSessionBindError(RuntimeError):
    """Raised when a Session is bound to an already checked-out hardened Connection."""


def _expected_user(url: str) -> str | None:
    """The role the URL claims, so the server can be asked to confirm it authenticated as it."""
    try:
        return make_url(url).username
    except Exception:  # pragma: no cover - make_url already validated upstream
        return None


def _harden_connection(dbapi_connection, validate_principal: bool) -> None:
    """Put a freshly opened connection into a known, safe state.

    Runs on every new pooled connection, not once per engine: a pool replaces connections
    over time, and a check that ran only at startup would stop being true.

    A connection that cannot be hardened is closed here rather than left for the pool. The
    ``connect`` event fires after the DBAPI connection is open, so raising without closing
    leaks a live backend for every attempt -- which, for a misconfigured application URL,
    means one leaked connection per retry rather than one clear failure.
    """
    try:
        with dbapi_connection.cursor() as cursor:
            # pg_temp named explicitly and LAST. Omitting it is what makes PostgreSQL
            # search the temporary schema first, which is how a CREATE TEMP TABLE
            # workspaces shadows the real table for a connection. See db/base.py.
            cursor.execute(f"SET search_path = {SEARCH_PATH}")
            # Clear any session-level tenant that arrived with the connection -- via URL
            # options, a connect-time server setting, or a role default.
            cursor.execute("SELECT set_config(%(setting)s, '', false)", {"setting": TENANT_SETTING})
            if validate_principal:
                from .principal import require_unprivileged_principal

                require_unprivileged_principal(
                    cursor, expected_user=validate_principal.expected_user, stage="connect"
                )
        dbapi_connection.commit()
    except BaseException:
        try:
            dbapi_connection.close()
        except Exception:  # pragma: no cover - the original failure is what matters
            pass
        raise


class _PrincipalPolicy:
    """Marker carrying the role the URL claimed. Truthy so it reads as a flag."""

    def __init__(self, expected_user: str | None):
        self.expected_user = expected_user

    def __bool__(self) -> bool:
        return True


def _revalidate_on_checkout(dbapi_connection, connection_record, policy) -> None:
    """Re-verify the principal every time a connection leaves the pool.

    A connection validated at connect time can sit idle for hours. In that window the role
    it authenticated as may be granted ``BYPASSRLS``, made a superuser, given ownership of
    a tenant-scoped table, or made a member of a role that has any of those -- and the
    connection would go on serving application DML as if nothing had happened. Verified
    against a real server: a pooled connection was accepted on checkout after its role was
    granted table ownership.

    On failure the connection is invalidated and discarded rather than returned to the
    pool, so the next checkout opens a fresh one and fails the connect-time check too.
    """
    from .principal import require_unprivileged_principal

    try:
        with dbapi_connection.cursor() as cursor:
            require_unprivileged_principal(
                cursor, expected_user=policy.expected_user, stage="pool checkout"
            )
            # Re-assert session state as well: a caller may have left a plain SET behind.
            cursor.execute(f"SET search_path = {SEARCH_PATH}")
            cursor.execute("SELECT set_config(%(setting)s, '', false)", {"setting": TENANT_SETTING})
        dbapi_connection.commit()
    except BaseException:
        try:
            dbapi_connection.rollback()
        except Exception:  # pragma: no cover - best effort before invalidating
            pass
        connection_record.invalidate()
        raise



def guard_connection_environment(engine: Engine) -> Engine:
    """Refuse to connect while the ambient environment can still steer the connection.

    Installed on **every** engine this package builds -- application, migration, and the
    test bootstrap's admin and owner engines -- through the ``do_connect`` dialect event,
    which fires after the pool has decided to open a connection and *before* libpq is
    handed anything. Raising there aborts the connect instead of validating one endpoint
    and opening another.

    Why this cannot live in the URL check: ``PGHOSTADDR`` overrides the host of a fully
    explicit URL, and ``PGOPTIONS`` is appended to the startup packet regardless of what
    the URL says. Both were reproduced against a real server. No amount of inspecting the
    connection string can see either of them.

    The check reads the environment; it never writes it. Unsetting variables around a
    connect would race every other thread in the process, and the race window is exactly
    the moment the connection is made -- so this fails closed instead. See
    ``config.ALLOWED_LIBPQ_ENVIRONMENT`` -- an allowlist, so a ``PG*`` variable that
    PostgreSQL has not shipped yet is refused rather than assumed harmless.
    """

    def _check(stage: str) -> None:
        config.require_clean_libpq_environment(
            context=f"{stage} {config.redact_database_url(str(engine.url))}"
        )

    @event.listens_for(engine, "do_connect")
    def _check_before_connecting(_dialect, _record, _cargs, _cparams):  # pragma: no cover
        _check("opening a connection to")
        return None  # fall through to the dialect's own connect

    @event.listens_for(engine, "checkout")
    def _check_before_reuse(_dbapi_connection, _record, _proxy):  # pragma: no cover
        # A pooled connection was opened under a clean environment, so reusing it is not
        # itself unsafe -- ``PGHOSTADDR`` cannot retroactively move an open socket. This
        # is here so the guarantee is the broader one: no Firmbatch database work happens
        # while the environment is in a state that would misdirect the *next* connection,
        # rather than the narrower "no connection is opened". A pool that hands out
        # existing connections would otherwise let a process run indefinitely after its
        # environment went wrong, and only fail when the pool next grew.
        _check("using a pooled connection to")

    return engine


def install_connect_hardening(engine: Engine, *, policy) -> Engine:
    _mark_hardened(engine)
    guard_connection_environment(engine)

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_connection, _record):  # pragma: no cover - exercised via engines
        _harden_connection(dbapi_connection, policy)

    if policy:

        @event.listens_for(engine, "checkout")
        def _on_checkout(dbapi_connection, connection_record, _proxy):  # pragma: no cover
            _revalidate_on_checkout(dbapi_connection, connection_record, policy)

    return engine


def create_application_engine(
    url: "str | config.ApplicationSettings",
    *,
    pool_size: int = 5,
    max_overflow: int = 0,
    validate_principal: bool = True,
) -> Engine:
    """Engine for the restricted, tenant-scoped application role.

    Takes the application URL or an :class:`~firmbatch.control_plane.config.ApplicationSettings`,
    and nothing else. A ``MigrationSettings`` or ``TestBootstrapSettings`` is refused
    rather than quietly accepted: the runtime pool is the one place an owner credential
    must never reach, and the type is the cheapest place to say so.

    ``pool_pre_ping`` because the control plane is expected to outlive individual
    database connections. The pool default of ``reset_on_return="rollback"`` is
    load-bearing: it is what discards ``SET LOCAL`` before the connection is reused.

    ``validate_principal`` exists so a test can build an engine for a deliberately
    privileged role and assert that it is refused. Production callers leave it on; there
    is no environment variable that turns it off.
    """
    # An allowlist, and stated as one: this accepts the application URL or the application
    # settings, and refuses everything else by not recognising it. Naming the privileged
    # settings types here in order to reject them would mean this module referred to them,
    # which is the coupling the boundary check exists to prevent.
    if isinstance(url, config.ApplicationSettings):
        url = url.application_url
    elif not isinstance(url, str):
        raise config.ConfigurationError(
            f"the application engine was given {type(url).__name__}. It accepts the application "
            "URL or ApplicationSettings and nothing else: the runtime pool is the one place a "
            "privileged credential must never reach."
        )
    validated = config.require_postgresql_url(url, variable=config.APPLICATION_URL_VAR)
    engine = create_engine(
        validated,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=True,
        future=True,
    )
    policy = _PrincipalPolicy(_expected_user(validated)) if validate_principal else None
    return install_connect_hardening(engine, policy=policy)


def _coerce_tenant_id(tenant_id: uuid.UUID | str) -> uuid.UUID:
    if isinstance(tenant_id, uuid.UUID):
        return tenant_id
    try:
        return uuid.UUID(str(tenant_id))
    except (ValueError, AttributeError, TypeError):
        raise TenantContextError(f"tenant context must be a UUID; got {tenant_id!r}") from None


def _apply_setting(session: Session, value: str) -> None:
    session.execute(
        text("SELECT set_config(:setting, :value, true)"),
        {"setting": TENANT_SETTING, "value": value},
    )


def _refuse_inside_savepoint(session: Session, action: str) -> None:
    """One tenant context per outer transaction. No switching inside a savepoint.

    A nested transaction that switched tenant and then rolled back left PostgreSQL correct
    -- the outer ``SET LOCAL`` value is restored by the savepoint rollback -- and Python
    wrong: the identity map still held the other tenant's object, and ``session.get()``
    returned it without the policy being evaluated again. Verified against a real server.

    Rather than trying to unwind that bookkeeping correctly, the context is fixed for the
    life of an outer transaction. A caller that needs a different tenant opens a different
    transaction, which is what the isolation model means anyway.
    """
    if session.in_nested_transaction():
        raise TenantContextError(
            f"refusing to {action} inside a SAVEPOINT: the tenant context is fixed for the lifetime "
            "of an outer transaction. A savepoint rollback restores the PostgreSQL setting but not "
            "the ORM identity map, so a switch here can leave another tenant's rows cached. Open a "
            "separate transaction for the other tenant."
        )


#: The durable marker. It lives on the **pool**, not on the Engine, because every bind
#: form that can reach a hardened database shares that pool: the Engine itself, the
#: ``OptionEngine`` returned by ``engine.execution_options(...)``, a ``Connection`` checked
#: out of it, and a Session bound through a mapper-specific ``binds={}`` mapping. Comparing
#: Engine identity recognised only the first of those -- measured, and the savepoint guard
#: silently did nothing for ``Session(bind=engine.connect())``.
#:
#: ``Engine`` has no ``.info`` mapping in SQLAlchemy 2.0; ``Pool`` is an ordinary object and
#: takes an attribute. Nothing holds a strong reference to the pool from here, so a
#: disposed engine is still collectable.
_HARDENED_POOL_FLAG = "_firmbatch_hardened"


def _mark_hardened(engine: Engine) -> None:
    setattr(engine.pool, _HARDENED_POOL_FLAG, True)


def _bind_is_hardened(bind) -> bool:
    """True when ``bind`` -- an Engine, OptionEngine, or Connection -- reaches our pool."""
    pool = getattr(bind, "pool", None)
    if pool is None:
        engine = getattr(bind, "engine", None)  # Connection
        pool = getattr(engine, "pool", None)
    return bool(getattr(pool, _HARDENED_POOL_FLAG, False))


def _session_binds(session: Session):
    """Every bind a Session might use, without assuming ``get_bind()`` can answer.

    ``get_bind()`` raises on a Session configured only with mapper-specific binds and no
    default, so it cannot be the single source of truth. This yields whatever is reachable
    and lets the caller decide.
    """
    try:
        bind = session.get_bind()
    except Exception:
        bind = None
    if bind is not None:
        yield bind
    for attribute in ("bind", "_bind"):
        candidate = getattr(session, attribute, None)
        if candidate is not None:
            yield candidate
    for mapping in ("_bind_mapping", "_Session__binds", "binds"):
        candidate = getattr(session, mapping, None)
        if isinstance(candidate, dict):
            yield from candidate.values()


def _is_hardened(session: Session) -> bool:
    return any(_bind_is_hardened(bind) for bind in _session_binds(session))


def _clear_session_state(session: Session) -> None:
    """Drop every cached ORM object and the tenant bookkeeping with it."""
    session.expunge_all()
    session.info.pop(_SESSION_TENANT_KEY, None)


@event.listens_for(Session, "after_transaction_end")
def _clear_at_transaction_boundaries(session: Session, transaction) -> None:
    """Empty the identity map whenever a transaction or savepoint ends on our sessions.

    Two distinct leaks, one listener:

    * **Savepoints.** A savepoint rollback restores the PostgreSQL ``SET LOCAL`` value but
      not the ORM identity map, so an object loaded under another tenant inside the
      savepoint stayed cached and ``session.get()`` returned it with the policy never
      re-evaluated.

    * **Outer transactions.** With ``expire_on_commit=False`` -- which this package uses,
      so that objects survive the ``with`` block that loaded them -- a committed Session
      keeps its identity map. A later transaction on the same Session, with no tenant
      context at all, then answered ``session.get()`` from that map without emitting SQL.
      Measured: the same row read through SQL under no context returned ``[]`` while
      ``session.get()`` returned the tenant-A object.

    Both were reproduced against a real server. The listener fires on commit, on rollback,
    and on an exception unwinding through either.

    Registered on the ``Session`` **class**, and gated on the bind reaching a pool this
    module hardened -- so it covers a hand-constructed ``Session(bind=...)``, which is the
    case a contributor is most likely to write, and leaves unrelated SQLAlchemy engines in
    the same process completely alone. Registration happens once, at import, so listeners
    cannot accumulate as engines are created.
    """
    if not _is_hardened(session):
        return
    # transaction.parent is None for the outermost transaction; nested is the savepoint.
    if transaction.nested or transaction.parent is None:
        _clear_session_state(session)


#: ``Session(bind=<a checked-out Connection from a hardened engine>)`` is **not
#: supported**, and is refused rather than half-defended.
#:
#: Every protection this package provides is anchored to a pool *checkout*: the principal
#: is re-verified there, ``search_path`` is re-pinned there, and the session-level
#: ``app.tenant_id`` is cleared there. A Connection handed to a ``Session`` was checked out
#: before, by somebody else, and may have been used in between -- so the Session inherits
#: whatever session-level PostgreSQL state that caller left behind, and nothing re-runs the
#: checkout hardening because no checkout happens.
#:
#: The earlier design tried to *support* this form by teaching the identity-map guard to
#: recognise it. That closed the identity-map half and left the session-state half open,
#: which is the worse outcome: a bind form that looks supported and is not. Refusing it is
#: both simpler and honest, and nothing in this package needs it -- ``tenant_transaction``
#: and ``transaction`` take an Engine and check out their own connection.
#:
#: Unrelated Connection-bound Sessions on engines this package did not build are
#: untouched: the check is on *our* pool flag, not on the bind form in general.


def _hardened_connection_bind(session: Session):
    """The hardened ``Connection`` this Session is bound to, if any."""
    for bind in _session_binds(session):
        if isinstance(bind, Connection) and _bind_is_hardened(bind):
            return bind
    return None


def _refuse_connection_bound_session(session: Session) -> None:
    bind = _hardened_connection_bind(session)
    if bind is None:
        return
    raise UnsupportedSessionBindError(
        "a Session bound to an already checked-out Connection from a hardened Firmbatch engine "
        "is not supported. Every protection here is anchored to a pool checkout -- the principal "
        "re-verification, the pinned search_path, and the cleared session-level app.tenant_id all "
        "run there -- and binding an existing Connection skips all of it while inheriting whatever "
        "session state the previous holder left behind. Bind the Session to the Engine instead, or "
        "use tenant_transaction()/transaction(), which check out their own connection."
    )


@event.listens_for(Session, "after_transaction_create")
def _refuse_at_transaction_start(session: Session, transaction) -> None:
    """Refuse before anything can be read, written, or served from the identity map.

    ``after_transaction_create`` fires on the autobegin that precedes the *first* ORM
    operation on a Session, including a ``session.get()`` that would otherwise be answered
    from the identity map without emitting SQL. So the refusal lands before a cached
    cross-tenant object could come back, which is the failure mode that matters.
    """
    _refuse_connection_bound_session(session)


@event.listens_for(Session, "do_orm_execute")
def _refuse_at_execute(state) -> None:
    """Defence in depth, on the other path into the ORM."""
    _refuse_connection_bound_session(state.session)


def _install_session_guards(session: Session) -> Session:
    """The explicit entry point. The guards themselves are registered class-wide above."""
    _refuse_connection_bound_session(session)
    return session


def _note_context(session: Session, value: uuid.UUID | None) -> None:
    """Record the context and drop the identity map when it changes.

    Expunging is what makes a tenant switch safe on a reused ``Session``. Without it,
    ``session.get()`` answers from the identity map and PostgreSQL never re-evaluates the
    policy -- the object loaded under tenant A comes back under tenant B. Objects the
    caller still holds become detached with their loaded attributes intact; what they lose
    is the ability to be served again without a query, which is exactly the point.
    """
    if session.info.get(_SESSION_TENANT_KEY) != value:
        session.expunge_all()
        session.info[_SESSION_TENANT_KEY] = value


def reset_tenant_context(session: Session) -> None:
    """Establish an empty transaction-local baseline. Called at the top of every transaction.

    This is what stops a session-level ``app.tenant_id`` -- from a reused connection, a URL
    option, or an earlier plain ``SET`` -- from becoming the effective tenant of a
    transaction that never asked for one.
    """
    if not session.in_transaction():
        raise TenantContextError("reset_tenant_context requires an open transaction")
    _refuse_inside_savepoint(session, "reset the tenant context")
    _apply_setting(session, "")
    _note_context(session, None)


def set_tenant_context(session: Session, tenant_id: uuid.UUID | str) -> uuid.UUID:
    """Set ``app.tenant_id`` for the remainder of the current transaction.

    ``set_config`` rather than ``SET LOCAL`` because it takes a bind parameter; the value
    is additionally parsed as a UUID first, so nothing but a UUID ever reaches the
    setting.
    """
    if not session.in_transaction():
        raise TenantContextError(
            "set_tenant_context requires an open transaction: SET LOCAL outside one applies to a "
            "single statement and then silently disappears."
        )
    _refuse_inside_savepoint(session, "change the tenant context")
    value = _coerce_tenant_id(tenant_id)
    _note_context(session, value)
    _apply_setting(session, str(value))
    return value


def current_tenant_context(session: Session) -> uuid.UUID | None:
    """The tenant context PostgreSQL currently sees, or ``None`` when unset."""
    raw = session.execute(text("SELECT current_setting(:setting, true)"), {"setting": TENANT_SETTING}).scalar()
    if raw is None or raw == "":
        return None
    return uuid.UUID(raw)


def clear_tenant_context(session: Session) -> None:
    """Drop the tenant context inside the current transaction, and the identity map with it."""
    if not session.in_transaction():
        raise TenantContextError("clear_tenant_context requires an open transaction")
    _refuse_inside_savepoint(session, "clear the tenant context")
    _note_context(session, None)
    _apply_setting(session, "")


def _require_engine(engine, function: str) -> Engine:
    """The session factories take an Engine, and say so.

    Passing a checked-out ``Connection`` here would produce exactly the bind form above,
    so it is refused at the door with a message naming the caller rather than several
    frames later inside SQLAlchemy.
    """
    if isinstance(engine, Connection):
        raise UnsupportedSessionBindError(
            f"{function}() takes an Engine, not a checked-out Connection. It checks out its own "
            "connection so that the connect-time and checkout-time hardening actually runs; "
            "handing it an existing Connection would skip both."
        )
    return engine


@contextmanager
def tenant_transaction(engine: Engine, tenant_id: uuid.UUID | str) -> Iterator[Session]:
    """One transaction scoped to one tenant. Commits on success, rolls back on error."""
    # Reject a malformed tenant before opening anything, so the caller gets the real error
    # rather than a rollback of an empty transaction.
    value = _coerce_tenant_id(tenant_id)
    engine = _require_engine(engine, "tenant_transaction")
    session = _install_session_guards(Session(bind=engine, expire_on_commit=False))
    try:
        with session.begin():
            reset_tenant_context(session)
            set_tenant_context(session, value)
            yield session
    finally:
        session.close()


@contextmanager
def transaction(engine: Engine) -> Iterator[Session]:
    """One transaction with **no** tenant context.

    For privileged provisioning and for tests that assert the fail-closed behaviour.
    Every tenant-scoped read through this session returns nothing and every tenant-scoped
    write is rejected -- that is the point, not a limitation.
    """
    engine = _require_engine(engine, "transaction")
    session = _install_session_guards(Session(bind=engine, expire_on_commit=False))
    try:
        with session.begin():
            reset_tenant_context(session)
            yield session
    finally:
        session.close()
