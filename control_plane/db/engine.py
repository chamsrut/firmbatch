"""Engines, transactions, and the connection-level half of the isolation boundary.

The isolation boundary in this package is enforced by PostgreSQL row-level security, not
by remembering to write ``WHERE tenant_id = ...``. Since Milestone 2.3 the *context* those
policies read is not something the application supplies at all: it is what
``firmbatch.auth_tenant_id()`` reports, which is the tenant recorded in a protected
transaction-local store that only a valid credential can write. Acquiring one is
``db/auth.py``'s job; this module owns the engines, the transactions, and the properties
that have to hold around them.

Four properties, each a separate defence and each tested:

* **Absence fails closed.** With no context, ``firmbatch.auth_tenant_id()`` is NULL, every
  policy predicate is NULL, so reads return no rows and writes are rejected. A forgotten
  bind cannot become a cross-tenant read.

* **Context is never inherited, and nothing has to clear it.** The authenticated context
  is a row carrying the ``xid8`` of the transaction that wrote it, and it is read back
  only when that id equals ``pg_current_xact_id_if_assigned()``. A committed row therefore
  grants nothing to anybody ever again, because a transaction id is never reissued, and an
  uncommitted one is invisible outside its own transaction. There is no clearing
  operation in this package and no clearing operation is needed.

  That is a stronger arrangement than the one it replaced twice over. Milestone 2.1
  cleared ``app.tenant_id`` at the top of every transaction because a session-level GUC
  could arrive **with** a connection. The first version of Milestone 2.3 cleared a
  temporary table for the same reason -- and that clearing function turned out to be a way
  for the caller to *drop its own context and bind a second identity*. What replaces both
  is an assertion: every transaction this module opens checks that it starts with no
  context, rather than making that true by removing one.

* **The identity map cannot outlive a context.** SQLAlchemy answers ``session.get()`` from
  its identity map without going to the database, so a ``Session`` reused across a change
  of context will hand back the previous tenant's object with PostgreSQL never consulted
  -- reproduced against a real server. Any change of context expunges the map.

* **The principal is verified, not assumed.** Every new pooled connection is asked who it
  authenticated as, and refused if it is a superuser, ``BYPASSRLS``, a tenant-table owner,
  a member of any role that is, or the holder of a table- **or column-level** grant on
  protected state. See ``db/principal.py``.

* **Authenticated work is writable-primary-only, and says so first.** Acquiring a context
  writes a row, so a standby and a read-only transaction cannot hold one. Every entry path
  here runs :func:`require_writable_primary` *before* any statement that references
  ``firmbatch.auth_transaction_context`` -- which is ``UNLOGGED``, and which PostgreSQL
  refuses to plan against during recovery, so a context read placed first meant a standby
  never reached the deliberate diagnostic at all. Read-replica routing is Milestone 8.

What changed at Milestone 2.3, and what it is worth: the runtime role can still execute
``set_config('app.tenant_id', <any uuid>, true)``, and it now buys **nothing** -- no
policy reads that setting, and the function that used to has been dropped. A transaction
acquires context by presenting a credential to ``firmbatch.bind_authenticated_context``
and no other way. ADR 0006 records the design; ADR 0004 section 8g records what it
replaced.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import Connection, Engine, create_engine, event, make_url, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from .. import config
from .base import SCHEMA, SEARCH_PATH

#: Reads the authenticated tenant out of the protected transaction-local context.
#: Migration 0003 creates it; nothing but that context decides what it returns.
TENANT_FUNCTION = f"{SCHEMA}.auth_tenant_id()"

#: Where the tenant a Session was last scoped to is remembered, so a change of context can
#: be detected and the identity map dropped.
_SESSION_TENANT_KEY = "firmbatch_tenant_context"


class TenantContextError(RuntimeError):
    """Raised when tenant context is missing, or acquired somewhere it may not be."""


class UnsupportedSessionBindError(RuntimeError):
    """Raised when a Session is bound to an already checked-out hardened Connection."""


class WritablePrimaryRequiredError(RuntimeError):
    """This transaction cannot hold an authenticated context because it cannot write.

    Acquiring a context writes one row of protected transaction state (ADR 0006 decision
    2), so an authenticated transaction requires a writable primary. Two situations reach
    here, and they are distinguished because the difference decides where an operator
    looks:

    * the transaction is **read-only** -- ``SET TRANSACTION READ ONLY``, or a
      ``default_transaction_read_only`` inherited from a role or database default;
    * the server is **in recovery** -- a standby.

    Defined here rather than in ``db/auth.py``, and re-exported from there for the callers
    that already name it. The reason is the preflight below: it has to run before anything
    touches ``firmbatch.auth_transaction_context``, which means it has to run inside this
    module's transaction machinery, and this module cannot import ``db/auth.py``.

    **Read-replica routing is Milestone 8 work.** At this milestone every authenticated
    read runs on the primary, and that limitation is stated here, in ``docs/STATE.md`` and
    in ADR 0006 rather than discovered.
    """


#: The writable-primary preflight, and the one property that matters about it: it names
#: **nothing** in the ``firmbatch`` schema.
#:
#: ``firmbatch.auth_transaction_context`` is ``UNLOGGED``, and PostgreSQL refuses to plan
#: a query that references an unlogged relation while the server is in recovery -- before
#: the query runs, so before any guard inside a function it would have called. Every
#: authenticated entry path used to begin by reading the current context, which is exactly
#: such a query, so on a standby the deliberate ``auth_require_writable_primary()``
#: diagnostic was never reached and the caller got PostgreSQL's own message about an
#: unlogged relation instead. This runs first, and it is two catalogue functions and no
#: relation at all.
#:
#: ``pg_is_in_recovery()`` is selected **first**, and the order is the diagnostic rather
#: than a detail: on a standby ``transaction_read_only`` is always ``on``, so a check that
#: read it first would report every replica as "somebody set the transaction read-only"
#: and send the reader looking for a ``SET`` nobody wrote.
_WRITABLE_PRIMARY_PREFLIGHT = text(
    "SELECT pg_catalog.pg_is_in_recovery() AS in_recovery, "
    "pg_catalog.current_setting('transaction_read_only') = 'on' AS read_only"
)


def writable_primary_refusal(in_recovery: bool, read_only: bool) -> str | None:
    """The refusal these two facts warrant, or ``None`` when the transaction may proceed.

    Split out from the query so that the standby branch is reachable without a standby.
    No PostgreSQL cluster in this repository's test environment is in recovery, so the
    only honest way to exercise the branch that a replica would take is to call this with
    the answer a replica would give -- which is what ``tests/test_authenticated_context.py``
    does. That is **not** a live-standby qualification and nothing here claims it is.

    Recovery is tested before read-only for the reason
    :data:`_WRITABLE_PRIMARY_PREFLIGHT` gives.
    """
    if in_recovery:
        return (
            "this server is in recovery (a standby), so it cannot hold an authenticated context: "
            "acquiring one writes a row of protected transaction state. Authenticated work is "
            "primary-only at this milestone; read-replica routing is Milestone 8."
        )
    if read_only:
        return (
            "this transaction is read-only, so it cannot hold an authenticated context: acquiring "
            "one writes a row of protected transaction state. Authenticated work is primary-only "
            "at this milestone; read-replica routing is Milestone 8."
        )
    return None


def require_writable_primary(session: Session) -> None:
    """Refuse, before anything reads the context relation, if this cannot be a primary write.

    Called at the top of every public entry path that leads to an authenticated context --
    :func:`transaction`, and both binding functions in ``db/auth.py`` -- so the ordering
    holds for a Session bound to an Engine and for one a caller constructed itself.

    The database functions keep their own ``firmbatch.auth_require_writable_primary()``
    guard. This does not replace it: that one is what holds when a caller writes the SQL
    by hand, and this one is what makes the diagnostic reachable at all on a standby.

    Nothing from the DBAPI is retained. The preflight carries no bound parameters, no URL
    and no credential; a driver failure is reported by exception *type* alone, and every
    refusal is raised outside the ``except`` block so that no driver exception is attached
    as ``__cause__`` or ``__context__``.

    Only ``DBAPIError`` is translated. This is the first statement of the transaction, so
    it is also what triggers the pool checkout -- and a checkout refusal is
    ``PrivilegedPrincipalError``, which must reach the caller as itself. Catching
    everything reported "this connection cannot write" for a connection that was rejected
    as privileged, which is the more serious finding wearing the milder name.
    """
    failure: str | None = None
    try:
        row = session.execute(_WRITABLE_PRIMARY_PREFLIGHT).one()
        refusal = writable_primary_refusal(bool(row.in_recovery), bool(row.read_only))
    except DBAPIError as error:
        failure = (
            "the writable-primary preflight could not be answered, so this transaction cannot be "
            f"assumed able to acquire an authenticated context: {type(error).__name__}"
        )
        refusal = None
    if failure is not None:
        raise WritablePrimaryRequiredError(failure) from None
    if refusal is not None:
        raise WritablePrimaryRequiredError(refusal) from None


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
            # There is deliberately nothing to clear here. A session-level
            # ``app.tenant_id`` could arrive *with* a connection -- through URL options, a
            # connect-time setting, or a role default -- which is why Milestone 2.1
            # cleared one on every connect. Authentication context cannot arrive with
            # anything: it is a row keyed by the transaction id that wrote it, and this
            # connection has not opened a transaction yet.
            #
            # Nor could a clearing call run here even if one existed: this fires on the
            # migration engine's first connection too, which happens before the schema
            # that would define it.
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
            # Nothing to clear. The authenticated context belongs to a transaction id, and
            # a connection returning to the pool has ended its transaction one way or the
            # other -- so the next holder's transaction has a different id and the previous
            # row is unreadable by construction. ``transaction()`` asserts that rather than
            # trusting it.
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


def refuse_inside_savepoint(session: Session, action: str) -> None:
    """One authenticated context per outer transaction. Nothing acquired inside a savepoint.

    Two reasons, and they survive the change of mechanism.

    The first is the identity map. A nested transaction that changed tenant and then
    rolled back left PostgreSQL correct and Python wrong: the map still held the other
    tenant's object, and ``session.get()`` returned it without the policy being evaluated
    again. Verified against a real server.

    The second is what a savepoint does to the context itself. The context is a row, so a
    savepoint rollback removes one written inside it while a savepoint *release* keeps it
    -- meaning a bind inside a nested transaction would sometimes survive and sometimes
    not, decided by how the caller happened to end the savepoint. A context whose
    lifetime depends on that is not a context anybody can reason about.

    So it is fixed for the life of an outer transaction. A caller that needs a different
    identity opens a different transaction, which is what the isolation model means
    anyway.
    """
    if session.in_nested_transaction():
        raise TenantContextError(
            f"refusing to {action} inside a SAVEPOINT: the authenticated context is fixed for the "
            "lifetime of an outer transaction. A savepoint rollback removes a context written "
            "inside it while a release keeps one, and neither restores the ORM identity map, so a "
            "change here can leave another tenant's rows cached or leave the transaction running "
            "as an identity the caller thinks it abandoned. Open a separate transaction."
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
#: both simpler and honest, and nothing in this package needs it -- ``authenticated_transaction``
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
        "use authenticated_transaction()/transaction(), which check out their own connection."
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


def note_context_change(session: Session, value: uuid.UUID | None) -> None:
    """Record the context and drop the identity map when it changes.

    Expunging is what makes a change of context safe on a reused ``Session``. Without it,
    ``session.get()`` answers from the identity map and PostgreSQL never re-evaluates the
    policy -- the object loaded under tenant A comes back under tenant B. Objects the
    caller still holds become detached with their loaded attributes intact; what they lose
    is the ability to be served again without a query, which is exactly the point.

    Public because ``db/auth.py`` is what changes the context now, and this bookkeeping
    belongs with the engines and the session guards rather than with the credential logic.
    """
    if session.info.get(_SESSION_TENANT_KEY) != value:
        session.expunge_all()
        session.info[_SESSION_TENANT_KEY] = value


def require_no_inherited_context(session: Session) -> None:
    """Assert this transaction starts unauthenticated, and drop the ORM identity map.

    Called at the top of every transaction this module opens. It **asserts** rather than
    clears, and that difference is the correction: a function that could remove an
    established context was a function the caller could use to drop its own identity and
    bind another one inside the same transaction. There is no such function any more.

    What makes the assertion cheap to keep true is the mechanism rather than this call: a
    context row carries the transaction id that wrote it, so a new transaction cannot read
    an old one's. A failure here would mean that property had broken, which is why it
    raises rather than repairing anything.
    """
    if not session.in_transaction():
        raise TenantContextError("require_no_inherited_context requires an open transaction")
    inherited = current_tenant_context(session)
    if inherited is not None:  # pragma: no cover - would mean the xid scoping had failed
        raise TenantContextError(
            f"this transaction began with an authenticated context for tenant {inherited}, which "
            "should not be reachable: a context row is readable only by the transaction whose id "
            "it carries. Treat this as a corrupted isolation boundary, not as a caller error."
        )
    note_context_change(session, None)


def current_tenant_context(session: Session) -> uuid.UUID | None:
    """The tenant PostgreSQL says this transaction authenticated as, or ``None``.

    Read from the database rather than remembered in Python: what matters is the value the
    policies will evaluate against, and the only authority for that is the server.
    """
    raw = session.execute(text(f"SELECT {TENANT_FUNCTION}")).scalar()
    if raw is None:
        return None
    return raw if isinstance(raw, uuid.UUID) else uuid.UUID(str(raw))


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
def transaction(engine: Engine) -> Iterator[Session]:
    """One transaction with **no** authenticated context.

    Every tenant-scoped read through this session returns nothing and every tenant-scoped
    write is rejected -- that is the point, not a limitation. It is the starting state for
    a request that has not presented a credential yet, and the state the fail-closed tests
    assert against.

    There is deliberately no ``tenant_transaction(engine, tenant_id)`` any more. A
    transaction that could be handed a tenant id was the whole of
    ``AUTH-BOUND-TENANT-CONTEXT``: it made the runtime a trusted setter of context. What
    replaces it is ``db/auth.py``'s ``authenticated_transaction(engine, credential)``,
    which opens one of these and then presents a credential to PostgreSQL.
    """
    engine = _require_engine(engine, "transaction")
    session = _install_session_guards(Session(bind=engine, expire_on_commit=False))
    try:
        with session.begin():
            # Before ``require_no_inherited_context``, and that order is load-bearing
            # rather than tidy: the inherited-context assertion reads
            # ``firmbatch.auth_transaction_context``, which is UNLOGGED, and PostgreSQL
            # refuses to plan a query against an unlogged relation during recovery. On a
            # standby that refusal arrived before the deliberate guard could speak, so the
            # caller got a message about an unlogged relation instead of "this is a
            # replica". The preflight names no relation at all.
            require_writable_primary(session)
            require_no_inherited_context(session)
            yield session
    finally:
        session.close()
