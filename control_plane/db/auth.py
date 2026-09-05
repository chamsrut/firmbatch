"""Acquiring an authenticated tenant context, and the credential foundation under it.

This is the Python side of what migration ``0003`` enforces. It is deliberately thin: no
decision this module makes is load-bearing, because every one of them is made again in
PostgreSQL by a function the caller cannot reach around. What it adds is a typed result,
an explanatory error where the database would otherwise give a bare policy violation, and
a transaction helper that opens a session, presents a credential, and refuses everything
that would let context leak out of it.

How a transaction gets a context
--------------------------------

Exactly two ways, and both go through a hardened ``SECURITY DEFINER`` function:

* :func:`bind_authenticated_context` presents a bearer credential.
  ``firmbatch.bind_authenticated_context`` hashes it, looks the digest up in the protected
  registry, and -- if the binding is known, unrevoked and unexpired -- writes one row into
  a protected transaction-local store. The caller supplies no tenant, no principal, no
  binding id and no scope, so there is nothing to forge: the only input is a 244-bit
  secret, and the only thing a wrong one produces is a refusal.

  244 bits and not 256, and the difference is written down rather than rounded up: the
  value is generated inside PostgreSQL from two ``gen_random_uuid()`` values, each of
  which carries 122 random bits. The standalone Python generator in
  ``security/secrets.py`` uses 32 random bytes and is 256 bits. Both are unguessable and
  both render as the same 43 URL-safe characters; the length of the rendering is not the
  entropy and is not quoted as though it were.

* :func:`begin_tenant_provisioning` establishes the one context that cannot come from a
  credential, because a tenant has no credential until it exists. The database function
  takes **no arguments** and generates the tenant id itself, so even this path cannot be
  pointed at an existing tenant.

There is no third way. Setting ``app.tenant_id``, or any other custom setting, buys
nothing: no policy reads one, and the function that used to has been dropped.

What the context is, and how long it lasts
------------------------------------------

One row in ``firmbatch.auth_transaction_context``, keyed by the backend's pid and
carrying the ``xid8`` of the transaction that wrote it. No runtime role holds any
privilege on that table, so nothing but the ``SECURITY DEFINER`` writer can touch it.

Its lifetime is PostgreSQL's, not this module's, and not by a rule anybody has to keep: a
row is read back only when its ``xact_id`` equals ``pg_current_xact_id_if_assigned()``, so
an uncommitted row is invisible to every other transaction and a committed one can never
match a future transaction's id. Nothing clears it because nothing needs to, and --
importantly -- there is no operation that *could*. Binding twice in one transaction is
refused by the writer's own conflict predicate, so a request cannot change identity
part-way through, and :func:`refuse_inside_savepoint` keeps binding out of nested
transactions where its survival would depend on how the savepoint happened to end.

An earlier version of this milestone kept the context in a temporary table with
``ON COMMIT DELETE ROWS``. ``DISCARD TEMP`` -- one statement, legal for any role, needing
no privilege -- dropped it and let the caller bind a second identity in the same
transaction. ADR 0006 decision 2 records the measurement and the replacement.

What this module does **not** do
--------------------------------

It does not manage credentials. :func:`register_auth_binding` and
:func:`revoke_auth_binding` are the minimal persistence foundation Milestone 3's
credential lifecycle will be built on -- create, revoke, and rotate-by-doing-both -- and
nothing more: no listing, no last-use tracking, no HTTP surface, no memberships, no
sessions, no account model. Those are Milestone 3, and building them here would be the
opportunistic later-milestone work the working contract forbids.

It also holds no authority of its own. Both functions derive the tenant from the current
context rather than taking one, so a leaked runtime credential cannot mint a capability
into a tenant it does not already hold.

**And it does not choose credentials.** The value is generated inside
``firmbatch.register_auth_binding`` and returned once. A caller that could *submit* a
candidate could submit somebody else's and learn from the outcome whether it already
existed -- in another tenant, in a table it cannot read. Translating the unique violation
into a different error would not have helped: success versus failure is the oracle.
Removing the caller's choice removes the question.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator

from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from .. import config
from ..security.authorization import (
    DELEGABLE_SCOPES,
    AuthorizationError,
    Scope,
    scope_values,
)
from ..security.secrets import Secret, is_well_formed_credential
from . import engine as db_engine
from .base import SCHEMA

#: PostgreSQL SQLSTATEs the database functions raise, and what each one means here.
#: Matched on the code rather than on the message: a message is prose and can be improved,
#: a SQLSTATE is a contract.
_INVALID_PASSWORD = "28P01"
_INSUFFICIENT_PRIVILEGE = "42501"
_INVALID_TRANSACTION_STATE = "25000"
_INVALID_PARAMETER_VALUE = "22023"
_FEATURE_NOT_SUPPORTED = "0A000"
_READ_ONLY_SQL_TRANSACTION = "25006"


class AuthenticationError(RuntimeError):
    """The presented credential did not resolve to a usable binding.

    Deliberately undifferentiated. Unknown, revoked and expired all produce this, with the
    same message, because telling a caller *which* one it was tells the holder of a wrong
    credential whether it was ever a right one.
    """


class UnsupportedIsolationLevelError(RuntimeError):
    """The transaction is not ``READ COMMITTED``, which the binding path requires.

    Raised by the database and translated here, rather than checked in Python, because the
    property is about the snapshot the *registry lookup* runs under. Under ``REPEATABLE
    READ`` or ``SERIALIZABLE`` every statement reads the snapshot taken at the first one,
    so a revocation or an expiry committed after the transaction opened would be invisible
    and a dead credential would still authenticate.
    """


#: Re-exported from ``db/engine.py``, which is where it has to be defined: the preflight
#: that raises it runs inside ``transaction()``, before anything reads the context
#: relation, and ``db/engine.py`` cannot import this module. Callers name it here because
#: this is where the binding functions are.
#:
#: Three places raise it, and they are three different defences rather than one repeated:
#: :func:`~firmbatch.control_plane.db.engine.require_writable_primary` at the top of every
#: Python entry path, so the refusal is reachable on a standby at all; the database's own
#: ``firmbatch.auth_require_writable_primary()``, which is what holds when a caller writes
#: the SQL by hand; and :func:`_translate` below, which turns that database refusal into
#: this error.
WritablePrimaryRequiredError = db_engine.WritablePrimaryRequiredError


class CredentialOperationError(RuntimeError):
    """A credential-bearing statement failed in a way this module did not anticipate.

    One statement in this package carries a raw credential as a parameter -- the bind --
    and a ``DBAPIError`` renders the statement **and its parameters** in its message. Every
    *expected* failure of it is translated into one of the errors above, with ``from None``
    so the psycopg exception does not travel with it. This class covers what is left: an
    unexpected database error on that statement, re-raised with the credential scrubbed out
    of the text rather than allowed to propagate carrying it into a traceback, a log, or a
    retained CI artifact.

    Registration no longer needs it. Since the credential is generated in the database and
    returned rather than submitted, that statement's parameters contain no secret to leak.
    """


class ContextAlreadyBoundError(RuntimeError):
    """This transaction already has an authenticated context.

    A transaction acquires context once. Acquiring a second -- the same identity or
    another -- is refused rather than merged: a transaction that has acted as one
    principal must not go on to act as another, and a request that binds twice is a
    request whose author has lost track of which identity it is serving.
    """


@dataclass(frozen=True)
class AuthenticatedContext:
    """What one transaction authenticated as, as PostgreSQL reports it.

    Read back from the database rather than assembled from what was presented: the
    authority for the context is the context, and a value this module constructed from its
    own inputs would be a claim about what it *asked* for.
    """

    #: The binding that was presented. ``None`` for the provisioning path, which has no
    #: credential.
    binding_id: uuid.UUID | None
    tenant_id: uuid.UUID
    #: The acting identity. ``None`` for the provisioning path.
    principal_id: uuid.UUID | None
    #: ``credential`` or ``provisioning``.
    actor_kind: str
    scopes: frozenset[str]

    def has_scope(self, scope: Scope | str) -> bool:
        return (scope.value if isinstance(scope, Scope) else scope) in self.scopes

    def require_scope(self, scope: Scope) -> None:
        """Raise :class:`AuthorizationError` unless this context holds ``scope``."""
        from ..security.authorization import require_scope

        require_scope(self, scope)

    def __repr__(self) -> str:
        # Every field here is an identifier or a capability name. None of it is secret --
        # the credential is not in this object and never was.
        return (
            f"AuthenticatedContext(tenant_id={self.tenant_id}, actor_kind={self.actor_kind!r}, "
            f"principal_id={self.principal_id}, binding_id={self.binding_id}, "
            f"scopes={sorted(self.scopes)})"
        )


@dataclass(frozen=True)
class RegisteredCredential:
    """A newly minted credential, and the binding it authenticates.

    :attr:`credential` is the **only** time the value exists outside the caller's hand:
    PostgreSQL stored a digest of it and cannot return it. Show it once and drop it.
    """

    binding_id: uuid.UUID
    tenant_id: uuid.UUID
    principal_id: uuid.UUID
    scopes: tuple[str, ...]
    credential: Secret

    def __repr__(self) -> str:
        # The Secret redacts itself, but naming it here would still put the word in a log
        # line next to a tenant id. The count is enough for a traceback.
        return (
            f"RegisteredCredential(binding_id={self.binding_id}, tenant_id={self.tenant_id}, "
            f"principal_id={self.principal_id}, scopes={list(self.scopes)}, credential=<redacted>)"
        )


# --------------------------------------------------------------------------- reading


_CONTEXT_QUERY = text(
    f"SELECT binding_id, tenant_id, principal_id, actor_kind, scopes FROM {SCHEMA}.auth_context()"
)


def current_authenticated_context(session: Session) -> AuthenticatedContext | None:
    """What this transaction authenticated as, or ``None`` when it has not.

    ``None`` is the ordinary unauthenticated state, not an error: a transaction that has
    not presented a credential reads nothing and writes nothing, which is the fail-closed
    behaviour the policies provide.
    """
    row = session.execute(_CONTEXT_QUERY).one()
    if row.tenant_id is None:
        return None
    return AuthenticatedContext(
        binding_id=row.binding_id,
        tenant_id=row.tenant_id,
        principal_id=row.principal_id,
        actor_kind=row.actor_kind,
        scopes=frozenset(row.scopes or ()),
    )


def require_authenticated_context(session: Session) -> AuthenticatedContext:
    """The context, or an explanatory refusal. Used where work cannot proceed without one."""
    context = current_authenticated_context(session)
    if context is None:
        raise AuthenticationError(
            "this transaction has no authenticated context. Present a credential with "
            "bind_authenticated_context() -- there is no other way to acquire one, and setting a "
            "tenant identifier by any route grants nothing."
        )
    return context


# --------------------------------------------------------------------------- binding


def _sqlstate(error: DBAPIError) -> str | None:
    return getattr(getattr(error, "orig", None), "sqlstate", None)


def _translate(error: DBAPIError):
    """Turn the database's refusal into the Python one that means the same thing."""
    state = _sqlstate(error)
    if state == _INVALID_PASSWORD:
        return AuthenticationError(
            "authentication failed: the presented binding is unknown, revoked, or expired. The "
            "three are deliberately indistinguishable from outside."
        )
    if state == _INVALID_TRANSACTION_STATE:
        return ContextAlreadyBoundError(
            "this transaction already has an authenticated context. A transaction acquires one "
            "identity and keeps it; open a separate transaction to act as another."
        )
    if state == _FEATURE_NOT_SUPPORTED:
        return UnsupportedIsolationLevelError(
            "acquiring an authenticated context requires the READ COMMITTED isolation level. A "
            "stricter level reads the credential registry through a snapshot older than the "
            "statement, so a revocation committed in between would not be seen."
        )
    if state == _READ_ONLY_SQL_TRANSACTION:
        # The server's own message, which distinguishes "this transaction is read-only"
        # from "this server is a standby" and contains no parameter and no caller value.
        return WritablePrimaryRequiredError(
            f"{str(error.orig).strip() or 'a writable primary is required'} "
            "Acquiring an authenticated context writes one row of protected transaction state, so "
            "authenticated work is primary-only at this milestone; read-replica routing is "
            "Milestone 8."
        )
    if state == _INSUFFICIENT_PRIVILEGE:
        return AuthorizationError(str(error.orig).strip() or "the authenticated context is not permitted to do this")
    if state == _INVALID_PARAMETER_VALUE:
        return ValueError(str(error.orig).strip())
    return None


def _execute(session: Session, statement, params=None, *, scrub: "tuple[str, ...]" = ()):
    """Run one statement, and turn a database refusal into the Python error that means it.

    ``scrub`` is the raw credential the statement carries, when it carries one. An expected
    failure is translated; an **unexpected** one on a credential-bearing statement is
    re-raised with the value removed, because a ``DBAPIError`` renders the failing
    statement *and its parameters*.

    The raise happens **after** the ``except`` block rather than inside it, and that is the
    whole reason this is a function rather than a context manager. Inside a handler --
    including inside a context manager's ``__exit__``, which runs while the caller is
    unwinding -- Python attaches the exception being handled as ``__context__``. ``from
    None`` suppresses that when a traceback is *printed*; it does not detach it, so
    anything that walks the exception chain still finds the psycopg error and the
    parameters it renders. Out here there is no exception being handled, so nothing is
    attached at all.
    """
    failure = None
    try:
        return session.execute(statement, params or {})
    except DBAPIError as error:
        failure = _translate(error)
        if failure is None:
            if not scrub:
                raise
            failure = CredentialOperationError(config.scrub_secrets(str(error), scrub))
    raise failure from None


def bind_authenticated_context(session: Session, credential: Secret | str) -> AuthenticatedContext:
    """Present a credential and acquire this transaction's context. Returns what it got.

    Fails closed on everything: no transaction, a savepoint, a malformed credential, an
    unknown one, a revoked one, an expired one, or a second bind. A database-side refusal
    aborts the transaction, which is correct -- a request that could not authenticate has
    nothing further to do -- so the caller's ``with`` block should let it unwind.

    The credential travels as a bound parameter and is hashed inside PostgreSQL. It is not
    stored, not returned, and not rendered by anything in this package: the malformed-input
    check below is what keeps a typo out of the server logs entirely.
    """
    if not session.in_transaction():
        raise AuthenticationError(
            "bind_authenticated_context requires an open transaction: the context it acquires is "
            "transaction-local, and outside a transaction there is nothing for it to belong to."
        )
    db_engine.refuse_inside_savepoint(session, "acquire an authenticated context")
    # First database operation on this path, before the credential is sent anywhere and
    # before anything reads the context relation. ``transaction()`` ran the same preflight
    # when it opened, but a transaction can be made read-only after it begins and a caller
    # may have built the Session itself, so the entry point checks for itself.
    db_engine.require_writable_primary(session)

    # Checked here so that a malformed value never reaches the server -- not because the
    # server would accept it, but because a credential in a statement is a credential a
    # statement log can retain. The message names neither the value nor its length.
    if not is_well_formed_credential(credential):
        raise AuthenticationError(
            "the presented value is not a well-formed Firmbatch credential, so it was refused "
            "without being sent to the database."
        )
    value = credential.reveal() if isinstance(credential, Secret) else credential

    _execute(
        session,
        text(f"SELECT {SCHEMA}.bind_authenticated_context(:credential)"),
        {"credential": value},
        scrub=(value,),
    )

    context = current_authenticated_context(session)
    if context is None:  # pragma: no cover - the database raises rather than returning nothing
        raise AuthenticationError("the database accepted the credential and established no context")
    db_engine.note_context_change(session, context.tenant_id)
    return context


def begin_tenant_provisioning(session: Session) -> AuthenticatedContext:
    """Acquire the one context that does not come from a credential.

    A tenant has no credential until it exists, so tenant creation needs a context it
    cannot authenticate into. The way this avoids becoming "provisioning may select any
    tenant" is that the tenant id is generated **inside** the database function: the
    caller cannot name an existing tenant because it cannot name a tenant at all.

    The context carries ``tenant:provision`` and ``credential:manage``, so one transaction
    can create the tenant and register its first credential, and nothing else.
    """
    if not session.in_transaction():
        raise AuthenticationError("begin_tenant_provisioning requires an open transaction")
    db_engine.refuse_inside_savepoint(session, "begin tenant provisioning")
    # The same preflight, for the same reason, on the other entry point: both write the
    # same row of protected transaction state.
    db_engine.require_writable_primary(session)

    _execute(session, text(f"SELECT {SCHEMA}.begin_tenant_provisioning()"))

    context = require_authenticated_context(session)
    db_engine.note_context_change(session, context.tenant_id)
    return context


@contextmanager
def authenticated_transaction(engine: Engine, credential: Secret | str) -> Iterator[Session]:
    """One transaction acting as one credential. Commits on success, rolls back on error.

    The successor to Milestone 2.1's ``tenant_transaction(engine, tenant_id)``, and the
    difference is the whole of ``AUTH-BOUND-TENANT-CONTEXT``: that one was handed the
    tenant it wanted, this one is told which tenant it gets.
    """
    with db_engine.transaction(engine) as session:
        bind_authenticated_context(session, credential)
        yield session


@contextmanager
def provisioning_transaction(engine: Engine) -> Iterator[Session]:
    """One transaction that may create exactly one new tenant, and act in it."""
    with db_engine.transaction(engine) as session:
        begin_tenant_provisioning(session)
        yield session


# ----------------------------------------------------------- the credential foundation


def _require_delegable(context: AuthenticatedContext, requested: "tuple[str, ...]") -> None:
    """Mirror of the delegation rule ``firmbatch.register_auth_binding`` enforces.

    The database is the one that counts -- this check can be reached around by writing the
    ``SELECT`` by hand, and the function refuses there too. What this adds is that the
    caller is told which rule it broke at the boundary, and by name rather than by
    SQLSTATE.

    Two clauses, both from ``security/authorization.py``:

    * every scope must be **delegable**. ``tenant:provision`` is not: it belongs to the
      bootstrap path and is acquired from ``begin_tenant_provisioning()``;
    * a **credential** issuer may grant only scopes it holds. ``credential:manage``
      authorises creating a credential; it does not imply the permissions that credential
      carries, and without this a credential holding only ``credential:manage`` could mint
      itself a successor holding ``workspace:write``.

    The **provisioning** actor is exempt from the second clause and only from it: it holds
    no credential to inherit from, and the tenant it is acting in was generated inside this
    same transaction, so it cannot reach an existing one.

    No refusal names a scope value it rejected. The requested set reached here through
    ``scope_values``, so every member is already in the closed catalogue -- but the habit
    is the point, and the position is enough to fix the call.
    """
    forbidden = [value for value in requested if value not in DELEGABLE_SCOPES]
    if forbidden:
        raise AuthorizationError(
            f"{len(forbidden)} of the requested scopes may not be placed on an issued credential. "
            "That capability belongs to the provisioning path and is acquired from "
            "begin_tenant_provisioning(); the rejected values are deliberately not repeated."
        )
    if context.actor_kind == "provisioning":
        return
    ungranted = [value for value in requested if value not in context.scopes]
    if ungranted:
        raise AuthorizationError(
            f"{len(ungranted)} of the requested scopes are not held by the issuing context. A "
            "credential may only issue capabilities it has: credential:manage authorises creating "
            "a credential, it does not imply the permissions that credential carries. The rejected "
            "values are deliberately not repeated."
        )


def register_auth_binding(
    session: Session,
    *,
    principal_id: uuid.UUID,
    scopes,
    expires_at: datetime | None = None,
) -> RegisteredCredential:
    """Mint a credential for **this transaction's tenant** and store only its fingerprint.

    There is no tenant parameter, deliberately: the database function derives the tenant
    from the current context, so no caller -- runtime or provisioning -- can mint a
    capability into a tenant it does not already hold. It requires
    ``credential:manage``, which a provisioning context has for the tenant it just
    created and which a customer credential has only if it was granted one.

    The credential is **generated by the database** and returned once; there is no
    parameter through which a caller could supply or probe one. The returned
    :class:`Secret` is the only copy -- PostgreSQL holds a SHA-256 digest of it and has no
    way to produce the value again.
    """
    if not session.in_transaction():
        raise AuthenticationError("register_auth_binding requires an open transaction")
    if not isinstance(principal_id, uuid.UUID):
        raise ValueError("a principal is a UUID; the binding records who acts, not what they typed")

    requested = scope_values(scopes)
    context = require_authenticated_context(session)
    # Refused here as well as in the database, so the caller gets the capability it is
    # missing by name rather than a SQLSTATE.
    context.require_scope(Scope.CREDENTIAL_MANAGE)
    _require_delegable(context, requested)

    issued = _execute(
        session,
        text(
            f"SELECT binding_id, credential FROM {SCHEMA}.register_auth_binding("
            ":principal_id, CAST(:scopes AS text[]), :expires_at)"
        ),
        {
            "principal_id": principal_id,
            "scopes": list(requested),
            "expires_at": expires_at,
        },
    ).one()
    binding_id = issued.binding_id
    # Wrapped immediately, and the plain value is never bound to a name of its own: from
    # here on the only way to reach it is Secret.reveal(), which is greppable.
    credential = Secret(issued.credential)

    _audit(
        session,
        action="auth.binding_registered",
        resource_id=binding_id,
        details={
            "principal_id": principal_id,
            "scope_count": len(requested),
            "expires": expires_at is not None,
        },
    )
    return RegisteredCredential(
        binding_id=binding_id,
        tenant_id=context.tenant_id,
        principal_id=principal_id,
        scopes=requested,
        credential=credential,
    )


def revoke_auth_binding(session: Session, binding_id: uuid.UUID) -> bool:
    """Revoke a binding in this transaction's tenant. ``True`` if one was revoked.

    Revocation is a state and not a deletion: the audit trail references the binding that
    acted, and a deleted binding would take that reference with it.

    A binding in another tenant, an unknown id, and an already-revoked binding all return
    ``False``. Indistinguishable on purpose -- a caller must not be able to probe another
    tenant's bindings by watching this answer.
    """
    if not session.in_transaction():
        raise AuthenticationError("revoke_auth_binding requires an open transaction")
    if not isinstance(binding_id, uuid.UUID):
        raise ValueError("a binding id is a UUID")

    context = require_authenticated_context(session)
    context.require_scope(Scope.CREDENTIAL_MANAGE)

    revoked = bool(
        _execute(
            session,
            text(f"SELECT {SCHEMA}.revoke_auth_binding(:binding_id)"),
            {"binding_id": binding_id},
        ).scalar_one()
    )

    # Recorded either way. "somebody tried to revoke a binding and nothing happened" is
    # exactly the kind of thing a trail is for -- and it is recorded without saying which
    # of the three reasons it was, because this function does not know either.
    _audit(
        session,
        action="auth.binding_revoked",
        resource_id=binding_id if revoked else None,
        outcome="succeeded" if revoked else "failed",
    )
    return revoked


def _audit(session: Session, *, action: str, resource_id=None, outcome: str = "succeeded", details=None) -> None:
    """Record one authentication-lifecycle action in the caller's transaction.

    Imported inside the function because ``db/audit.py`` needs the authenticated context
    this module resolves, so the two would otherwise import each other. The dependency
    runs one way in the type system and both ways in fact, and a deferred import is the
    honest way to say so rather than splitting a helper out to hide it.

    **Only the lifecycle operations are audited, not authentication itself.** A successful
    bind happens on every request, so recording one would make the audit trail an access
    log with the write volume of the traffic; and a *failed* bind cannot be recorded at
    all, because a failed authentication yields no tenant to scope the row to and aborts
    the transaction that would have written it. Authentication failure belongs in the
    application log at Milestone 8, and ADR 0006 says so rather than leaving the gap
    unexplained.
    """
    from .audit import AuditEventSpec, append_audit_event

    append_audit_event(
        session,
        AuditEventSpec(
            action=action,
            resource_type="auth_binding",
            outcome=outcome,
            resource_id=resource_id,
            details=details or {},
        ),
    )
