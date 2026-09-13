"""The native v1 HTTP boundary for Milestone 3.1: accounts, sessions, workspaces, members, credentials.

A thin ASGI application on Starlette. Every handler does the same four things: bound the
input **as it is read**, authenticate at exactly one of two boundaries, run one database
transaction through the functions in ``db/accounts.py``, ``db/membership.py`` and
``db/credentials.py``, and render a response that names identifiers and never a secret it
did not just mint. What follows is the set of rules a reader should be able to verify
against the code below.

Reading a body, and interpreting one
------------------------------------

They are separate steps, in that order, and authentication sits between them. The bounded
stream read (:func:`_read_body`) has to come first -- it is what stops an oversized request
being buffered at all -- and it is the only thing that precedes the credential. What the
bytes *are* -- a supported media type, valid UTF-8, valid JSON, a JSON object -- is decided
by :meth:`RequestBody.json`, which a protected route calls only inside ``Boundary.bind``.
A ``415`` or a ``400`` handed to an unauthenticated caller would tell it the boundary read
what it sent, and would let absent, invalid and mixed credentials be told apart by the shape
of the refusal; all three are one ``401``, whatever the body is.

Two authentication boundaries, and they do not overlap
------------------------------------------------------

* **Browser sessions** authenticate with the ``fb_session`` cookie. Every ``/v1/account``
  and ``/v1/workspace`` route is a browser route. A browser route that receives an
  ``Authorization`` header is refused outright, whatever the cookie says: a request
  carrying both credential types is a request whose author has lost track of which one it
  means, and answering it with either would be accepting a credential at the wrong
  boundary.
* **API credentials** authenticate with ``Authorization: Bearer fbk_...``. Every
  ``/v1/api`` route is a bearer route, and it ignores cookies in the same way -- a bearer
  route that receives the session cookie is refused.
* Nothing converts one into the other. The one route that *produces* an API credential,
  ``POST /v1/workspace/credentials``, is a browser route that asks the database to mint a
  new one after re-deriving the membership and the scopes; it never returns the session's
  secret, and it never accepts a session secret as a bearer token.

Cookie, CSRF and origin
-----------------------

The session cookie is host-only, ``Path=/``, ``HttpOnly``, ``Secure`` (except in the test
environment when told otherwise) and ``SameSite=Strict``. On top of that, **every
cookie-authenticated mutation** must carry the session's CSRF secret in ``X-CSRF-Token`` --
verified inside the database against the session's own fingerprint -- and an ``Origin``
header on the explicit allow-list. CORS is that same allow-list with credentials, and never
a wildcard; the Milestone 3.2 portal is served same-origin behind a proxy, so it does not
use CORS at all, and the allow-list is what the ``Origin`` check reads.

**Milestone 3.2 adds a second cookie, and it is not a credential.** The CSRF secret exists
in plaintext exactly once -- in the login response -- because the database stores only its
fingerprint, so a portal that kept it in memory could read but never write after a reload,
and nothing could re-issue it. The same secret is therefore also set as a readable,
host-only, ``SameSite=Strict`` cookie with the session's lifetime (``__Host-`` prefixed when
it is ``Secure``), cleared with the session cookie. The boundary **never compares the two**:
the header alone is checked, inside PostgreSQL, against the stored fingerprint, so a caller
must produce the session's actual secret rather than echo a value it set itself. See
``api/settings.py``.

Errors
------

Authentication and lookup failures are neutral. A wrong password and an unknown address
are one ``401``; an unknown, foreign, revoked or expired session is one ``401``; a
workspace, member, invitation or credential that is absent, hidden, in another tenant or
already gone is one ``404``. Every error body is ``{"error": <code>}`` and nothing else --
no field value, no database text, no identifier the caller did not send. Validation
failures say which rule, not which value.

What Milestone 3.2 added
------------------------

``POST /v1/account/password`` -- the signed-in password change M3.1 left to this milestone.
Cookie, CSRF **and** the current password; one atomic transaction on the authenticator
engine that verifies, replaces by compare-and-swap, ends every token, credential and
session, and mints the replacement. ``GET``/``PUT /v1/workspace/preferences`` and
``POST /v1/workspace/preferences/consent`` -- the customer's stated policy, profile and
preferences, and their acknowledgement of the consent statement, which
``GET /v1/consent`` serves publicly. Nothing here is a job, a quote or an invoice.

**Every workspace mutation names the workspace the page or action began under** (the
``X-Workspace-Id`` header on every one; the two preference mutations also carry it as
``workspace_id`` in the body, their original contract), and the database compares it with
the workspace the session is bound to, inside the mutation, under the workspace lock, before
anything is written. A page loaded for one workspace whose shared session another tab has
since re-bound to another is refused as ``409 workspace_mismatch`` -- the same answer a
forged or another tenant's identifier gets -- and the portal reloads the current workspace
rather than applying one workspace's action to another. A mutation with no header is a
``422``. **Every workspace read answers with the workspace it describes** (``workspace_id``
in the envelope), so the portal can drop an answer that arrives after the page's workspace
has changed rather than render one workspace's data under another.

What is deliberately not here
-----------------------------

No HTML and no template: the portal is a separate TypeScript application under ``portal/``
that calls this API same-origin behind a proxy, and this process serves JSON only. No rate
limiting, no request logging beyond method, route and status, no metrics: Milestone 8's
observability work, stated rather than half-built. No real email provider (see
``api/email.py``). No job, quote, invoice, evaluation, supplier or operator surface --
those are M4 onward, and the operator capacity agent is separate operator-side software
that never appears in a customer interface at all.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from sqlalchemy import Engine
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .. import config
from ..db import accounts, auth, credentials, membership, preferences
from ..db import engine as db_engine
from ..db.audit import audit_events
from ..db.idempotency import IdempotencyConflict, IdempotencyError
from ..db.repositories import WorkspaceRepository
from ..security.authorization import AuthorizationError, Scope
from ..security.passwords import KDFUnavailableError, PasswordPolicyError
from ..security.secrets import (
    Secret,
    SecretError,
    is_well_formed_credential,
    is_well_formed_identity_secret,
    looks_like_secret,
)
from .consent import CONSENT_DOCUMENTS, CURRENT_CONSENT_VERSION
from .email import EmailDelivery, EmailDeliveryError, OutboundEmail
from .settings import (
    CSRF_COOKIE_SAMESITE,
    CSRF_HEADER,
    IDEMPOTENCY_KEY_HEADER,
    MAX_BODY_BYTES,
    SESSION_COOKIE_NAME,
    SESSION_COOKIE_SAMESITE,
    ApiSettings,
)

log = logging.getLogger("firmbatch.api")

#: Bounds on the strings a body may carry, beyond what the database enforces. A body is
#: identifiers, addresses and short labels; a field longer than this is refused before it
#: is looked at.
MAX_FIELD_LENGTH = 512

#: The header every workspace mutation carries: the workspace the page or action began under.
WORKSPACE_HEADER = "x-workspace-id"
MAX_SCOPES = 16
_UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_ROLES = ("admin", "member", "owner", "viewer")
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


class ApiError(Exception):
    """A refusal rendered as ``{"error": code}`` with a status. Never carries a value."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


def _json(status: int, payload: dict[str, Any]) -> JSONResponse:
    return JSONResponse(payload, status_code=status, headers=_NO_STORE)


def _error(status: int, code: str) -> JSONResponse:
    return _json(status, {"error": code})


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _ident(value: uuid.UUID | None) -> str | None:
    return str(value) if value is not None else None


# --------------------------------------------------------------------------- inputs


def _require_object(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise ApiError(422, "invalid_request")
    return body


def _string(body: dict[str, Any], key: str, *, required: bool = True, maximum: int = MAX_FIELD_LENGTH) -> str | None:
    value = body.get(key)
    if value is None:
        if required:
            raise ApiError(422, "invalid_request")
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise ApiError(422, "invalid_request")
    return value


def _secret(body: dict[str, Any], key: str) -> Secret:
    value = _string(body, key)
    return Secret(value)


def _uuid_field(body: dict[str, Any], key: str) -> uuid.UUID:
    return _uuid_path(_string(body, key, maximum=36))


def _uuid_path(value: str) -> uuid.UUID:
    if not isinstance(value, str) or not _UUID_PATTERN.match(value.lower()):
        raise ApiError(404, "not_found")
    return uuid.UUID(value)


def _role(body: dict[str, Any], key: str = "role") -> str:
    value = _string(body, key, maximum=16)
    if value not in _ROLES:
        raise ApiError(422, "invalid_request")
    return value


def _scopes(body: dict[str, Any]) -> tuple[str, ...]:
    value = body.get("scopes")
    if not isinstance(value, list) or len(value) > MAX_SCOPES:
        raise ApiError(422, "invalid_request")
    out = []
    for item in value:
        if not isinstance(item, str) or not 1 <= len(item) <= 64 or looks_like_secret(item) is not None:
            raise ApiError(422, "invalid_request")
        out.append(item)
    return tuple(out)


def _timestamp(body: dict[str, Any], key: str) -> datetime | None:
    value = _string(body, key, required=False, maximum=64)
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ApiError(422, "invalid_request") from None
    if parsed.tzinfo is None:
        raise ApiError(422, "invalid_request")
    return parsed


def _boolean(body: dict[str, Any], key: str, *, default: bool = False) -> bool:
    """A JSON Boolean, strictly. An absent key takes ``default``; anything else is ``422``.

    ``bool(value)`` is what this replaces, and it accepted every JSON type: ``"false"``,
    ``0``, ``[]``, ``{}`` and ``null`` each meant something, and none of them meant what the
    caller wrote. A field that decides whether the caller's own session survives is not a
    field to guess at, so only ``true`` and ``false`` are accepted and the refusal happens
    before anything is changed. ``isinstance(True, int)`` is true and ``isinstance(1, bool)``
    is not, which is why the test is on ``bool`` and a JSON number is refused.
    """
    if key not in body:
        return default
    value = body[key]
    if not isinstance(value, bool):
        raise ApiError(422, "invalid_request")
    return value


async def _read_body(request: Request) -> bytes:
    """The request's raw bytes, bounded **as they are read**. No interpretation of any kind.

    ``Content-Length`` is honoured as an early rejection when present, but it is never the
    only guard: a chunked request omits it, and a hostile one may understate it. So the ASGI
    receive stream is consumed incrementally and the running total is checked against the
    limit on every chunk -- the read is abandoned the moment it would exceed
    :data:`MAX_BODY_BYTES`, rather than after the whole body has been materialised in memory.

    This is the **only** thing done to a request before its route authenticates it. The
    media type, the JSON and the schema are :class:`RequestBody`'s, and a handler asks for
    them after it has established who is calling.
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > MAX_BODY_BYTES:
                raise ApiError(413, "request_too_large")
        except ValueError:
            raise ApiError(400, "invalid_request") from None
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_BODY_BYTES:
            # Stop reading now. A body without Content-Length, or one that understated it,
            # cannot force us to buffer more than the limit.
            raise ApiError(413, "request_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


class RequestBody:
    """Bounded raw bytes, parsed only when a handler asks -- which is after it authenticates.

    **Reading a body is not interpreting one.** Enforcing the size limit needs the stream and
    nothing else, so it stays first, where it has to be: an oversized request is refused
    before it is buffered, whatever it claims to be and whoever sent it. Everything after
    that -- is this ``application/json``, is it valid UTF-8, is it valid JSON, is it an
    object -- is a statement *about the body*, and a protected route must not answer one of
    those before it has decided whether the caller may be answered at all. A ``415`` or a
    ``400`` on an unauthenticated request tells its sender that the boundary got as far as
    reading what it sent, and lets absent, invalid and mixed credentials be told apart by
    the shape of the refusal instead of being one answer.

    So the handler receives this, and calls :meth:`json` where the body is actually needed --
    inside ``Boundary.bind`` for a protected route, immediately for an unauthenticated one.
    The parse happens once and its result is kept, so asking twice costs nothing.
    """

    __slots__ = ("_raw", "_content_type", "_parsed")

    def __init__(self, raw: bytes, content_type: str | None) -> None:
        self._raw = raw
        self._content_type = content_type or ""
        self._parsed: dict[str, Any] | None = None

    def json(self) -> dict[str, Any]:
        """The JSON object this body carries. ``415``, ``400`` or ``422`` if it carries none."""
        if self._parsed is None:
            self._parsed = self._parse()
        return self._parsed

    def _parse(self) -> dict[str, Any]:
        if not self._raw:
            return {}
        if not self._content_type.lower().startswith("application/json"):
            raise ApiError(415, "unsupported_media_type")
        try:
            parsed = json.loads(self._raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "invalid_json") from None
        return _require_object(parsed)

    def __repr__(self) -> str:
        return f"RequestBody({len(self._raw)} bytes, parsed={self._parsed is not None})"


# --------------------------------------------------------------------------- boundaries


def _origin_allowed(request: Request, settings: ApiSettings) -> bool:
    origin = request.headers.get("origin")
    if origin is None:
        return False
    return origin.strip().lower() in settings.allowed_origins


def _idempotency_key(request: Request, *, required: bool) -> str | None:
    value = request.headers.get(IDEMPOTENCY_KEY_HEADER)
    if value is None:
        if required:
            raise ApiError(428, "idempotency_key_required")
        return None
    if looks_like_secret(value) is not None or len(value) > 200:
        raise ApiError(422, "invalid_idempotency_key")
    return value


class Boundary:
    """The two authentication boundaries and the transaction helpers behind the routes."""

    def __init__(
        self,
        settings: ApiSettings,
        engine: Engine,
        email: EmailDelivery,
        authenticator_engine: Engine | None = None,
    ) -> None:
        self.settings = settings
        self.engine = engine
        # The trusted-issuer (authenticator) engine (Milestone 3.1 security correction). The
        # pre-authentication routes -- signup, email verification, login, recovery request
        # and completion -- run on this restricted role, which holds those functions; the
        # ordinary application engine does not, so a compromised application credential can
        # neither mint a session, reset a password, nor issue and consume a mailbox-
        # verification token. Defaults to the application engine only for callers that
        # predate the split; production wiring always supplies a distinct one.
        self.authenticator_engine = authenticator_engine if authenticator_engine is not None else engine
        self.email = email

    # --- browser sessions ---------------------------------------------------------------

    def session_secret(self, request: Request) -> Secret:
        """The session cookie, and one refusal for absent, malformed and mixed credentials.

        The three are deliberately indistinguishable and are all decided **here**, before
        the origin and CSRF preconditions and before the body is interpreted: a caller
        learns that it is not authenticated, and nothing about which of the three ways it
        managed that. A cookie that is not a well-formed session secret is refused without
        being sent to the database, which is also what keeps a typo out of a statement log.
        """
        if "authorization" in request.headers:
            # Mixed credentials, or an API credential presented at the browser boundary:
            # refused without consulting either. The session cookie is not read at all.
            raise ApiError(401, "authentication_required")
        value = request.cookies.get(SESSION_COOKIE_NAME)
        if not value or not is_well_formed_identity_secret(value, "session"):
            raise ApiError(401, "authentication_required")
        return Secret(value)

    def csrf_secret(self, request: Request) -> Secret:
        """The CSRF secret a cookie-authenticated mutation must carry, plus the origin check."""
        if not _origin_allowed(request, self.settings):
            raise ApiError(403, "origin_not_allowed")
        value = request.headers.get(CSRF_HEADER)
        if not value:
            raise ApiError(403, "csrf_token_required")
        return Secret(value)

    @contextlib.contextmanager
    def bind(self, request: Request, *, mode: str, mutation: bool):
        """Open a transaction bound to the request's session. Sync; run in a threadpool.

        The database answers every bad bind with one neutral refusal, so that it cannot be
        asked whether a secret exists. This boundary turns that into the two statuses a
        client can act on without learning anything it did not already hold: ``401`` when
        the session itself is refused, and ``412`` when the session is fine but has not
        selected a workspace and the route needs one. The two are told apart by binding
        the same session again in account mode, which succeeds only in the second case.
        """
        secret = self.session_secret(request)
        csrf = self.csrf_secret(request) if mutation else None
        transaction = accounts.session_transaction(self.engine, secret, csrf_secret=csrf, mode=mode)
        try:
            pair = transaction.__enter__()
        except accounts.IdentityRefused:
            raise self._refused_bind(secret, mode, csrf) from None
        try:
            if mode == "workspace" and mutation:
                # The workspace the page or action began under, recorded in the transaction
                # before the handler runs, so that the database compares it with the binding
                # inside the mutation itself, under the workspace lock, before anything is
                # written. Read after the bind, so a request with no session is 401 before it
                # is anything else, and a missing or malformed header is the syntactic 422.
                accounts.expect_workspace(pair[0], _expected_workspace_header(request))
            yield pair
        except BaseException:
            if not transaction.__exit__(*sys.exc_info()):
                raise
        else:
            transaction.__exit__(None, None, None)

    def _refused_bind(self, secret: Secret, mode: str, csrf: Secret | None) -> ApiError:
        """Tell "this session is refused" apart from "this session has chosen no workspace".

        The retry carries **the same CSRF proof the request carried**. Without it the retry
        was a strictly easier question than the one that just failed, so a mutation whose
        CSRF token was wrong -- which the database refuses with the same neutral message as
        an unknown session -- came back as ``412 workspace_required``: a classification that
        says the credentials were fine and only a workspace was missing, and that a client
        would act on by selecting a workspace and retrying the forgery. With the proof
        carried through, a wrong CSRF token fails the retry too and is ``401``, while a
        session that really is unbound and really did present its own token still gets the
        ``412`` it needs.
        """
        if mode == "workspace":
            try:
                with accounts.session_transaction(self.engine, secret, csrf_secret=csrf, mode="account"):
                    pass
            except accounts.IdentityError:
                return ApiError(401, "authentication_required")
            return ApiError(412, "workspace_required")
        return ApiError(401, "authentication_required")

    # --- API credentials ----------------------------------------------------------------

    def bearer_credential(self, request: Request) -> Secret:
        if SESSION_COOKIE_NAME in request.cookies:
            # The session cookie at the bearer boundary: refused, whatever else is present.
            raise ApiError(401, "authentication_required")
        header = request.headers.get("authorization")
        if not header:
            raise ApiError(401, "authentication_required")
        scheme, _, value = header.strip().partition(" ")
        value = value.strip()
        if scheme.lower() != "bearer" or not is_well_formed_credential(value):
            raise ApiError(401, "authentication_required")
        return Secret(value)

    # --- email ---------------------------------------------------------------------------

    def send(self, message: OutboundEmail) -> None:
        """Deliver after commit. A delivery failure is logged without the message and swallowed:
        the account state is committed either way, and the customer can ask again."""
        try:
            self.email.deliver(message)
        except EmailDeliveryError as exc:
            log.warning("email delivery unavailable for kind=%s: %s", message.kind, type(exc).__name__)

    # --- cookies --------------------------------------------------------------------------

    def set_session_cookie(self, response: Response, opened: accounts.OpenedSession) -> None:
        """The two cookies one opened session hands the browser, and they are not alike.

        ``fb_session`` is the credential: ``HttpOnly``, so no script reads it. The CSRF
        cookie is not a credential and must be readable, because the portal has to put its
        value in ``X-CSRF-Token`` on every mutation and PostgreSQL verifies *that* against
        the session's stored fingerprint. See ``api/settings.py`` for why handing it over
        this way is not a weakening, and why it carries ``__Host-`` when it is ``Secure``.

        Both are set together, both carry the session's own lifetime, and both are cleared
        together, so a browser never holds one without the other for longer than one
        response.
        """
        max_age = int(self.settings.session_ttl.total_seconds())
        response.set_cookie(
            SESSION_COOKIE_NAME,
            opened.session_secret.reveal(),
            max_age=max_age,
            path="/",
            secure=self.settings.cookie_secure,
            httponly=True,
            samesite=SESSION_COOKIE_SAMESITE,
        )
        response.set_cookie(
            self.settings.csrf_cookie,
            opened.csrf_secret.reveal(),
            max_age=max_age,
            path="/",
            secure=self.settings.cookie_secure,
            # Readable by the portal, deliberately, and by nothing else: the cookie is
            # host-only (no Domain), so a sibling subdomain cannot read it either.
            httponly=False,
            samesite=CSRF_COOKIE_SAMESITE,
        )

    def clear_session_cookie(self, response: Response) -> None:
        response.delete_cookie(
            SESSION_COOKIE_NAME,
            path="/",
            secure=self.settings.cookie_secure,
            httponly=True,
            samesite=SESSION_COOKIE_SAMESITE,
        )
        response.delete_cookie(
            self.settings.csrf_cookie,
            path="/",
            secure=self.settings.cookie_secure,
            httponly=False,
            samesite=CSRF_COOKIE_SAMESITE,
        )


def _translate(exc: Exception) -> JSONResponse | None:
    """The one place a database-layer refusal becomes a status and a code."""
    if isinstance(exc, ApiError):
        return _error(exc.status, exc.code)
    if isinstance(exc, accounts.SessionAuthenticationError):
        return _error(401, "authentication_required")
    if isinstance(exc, accounts.WorkspaceBindingMismatch):
        # The workspace the page named is not the one the session is bound to: a stale form,
        # a forged identifier or another tenant's, indistinguishably. A client acts on it by
        # reloading the current workspace, which is why it is a 409 with its own code rather
        # than the neutral 404.
        return _error(409, "workspace_mismatch")
    if isinstance(exc, accounts.IdentityRefused):
        return _error(404, "not_found")
    if isinstance(exc, accounts.SessionContextError):
        return _error(403, "session_context_required")
    if isinstance(exc, accounts.IdentityConflict):
        return _error(409, "conflict")
    if isinstance(exc, IdempotencyConflict):
        return _error(409, "idempotency_key_reuse")
    if isinstance(exc, KDFUnavailableError):
        # Memory-hard admission gate saturated. Deterministic overload, and the same answer
        # for a known and an unknown address, so it discloses nothing about any account.
        return _error(503, "service_unavailable")
    if isinstance(exc, AuthorizationError):
        return _error(403, "forbidden")
    if isinstance(exc, auth.AuthenticationError):
        return _error(401, "authentication_required")
    if isinstance(exc, (PasswordPolicyError, accounts.IdentityError, IdempotencyError, SecretError, ValueError)):
        return _error(422, "invalid_request")
    return None


def _endpoint(boundary: Boundary, handler: Callable[..., Any]):
    """Wrap a handler: read, run in a threadpool, translate every refusal, log metadata only.

    **Read**, not parse. The bounded stream read is the one thing that has to happen before
    the route authenticates -- it is what stops an oversized body being buffered at all --
    and it is the only thing that does. What the bytes are is decided inside the handler,
    after the credential, by :meth:`RequestBody.json`.
    """

    async def endpoint(request: Request) -> Response:
        started = time.monotonic()
        status = 500
        try:
            raw = await _read_body(request) if request.method in ("POST", "PUT", "PATCH", "DELETE") else b""
            body = RequestBody(raw, request.headers.get("content-type"))
            response = await run_in_threadpool(handler, boundary, request, body)
            status = response.status_code
            return response
        except Exception as exc:  # noqa: BLE001 - every refusal is translated or becomes a neutral 500
            translated = _translate(exc)
            if translated is None:
                log.error("unhandled error in %s %s: %s", request.method, request.url.path, type(exc).__name__)
                translated = _error(500, "internal_error")
            status = translated.status_code
            return translated
        finally:
            # Method, route template, status and duration. No header, no body, no query,
            # no identifier: nothing here is ever a secret.
            route = request.scope.get("route")
            template = getattr(route, "path", request.url.path)
            log.info("%s %s -> %s (%.1f ms)", request.method, template, status, (time.monotonic() - started) * 1000)

    return endpoint


# --------------------------------------------------------------------------- handlers: accounts


def h_signup(b: Boundary, request: Request, body: RequestBody) -> Response:
    fields = body.json()
    email = _string(fields, "email", maximum=300)
    password = _secret(fields, "password")
    # Signup runs on the authenticator engine: signup_account mints a mailbox-verification
    # secret and returns it, which is authority the application role does not hold.
    with db_engine.transaction(b.authenticator_engine) as session:
        outcome = accounts.signup(session, email=email, password=password)
    if outcome.outcome == "created" and outcome.verification_secret is not None:
        b.send(OutboundEmail(kind="email_verification", recipient=accounts.normalize_email(email), secret=outcome.verification_secret))
    elif outcome.outcome == "existing":
        b.send(OutboundEmail(kind="account_exists", recipient=accounts.normalize_email(email)))
    # One answer for a new address and an existing one.
    return _json(202, {"status": "accepted"})


def h_verification_request(b: Boundary, request: Request, body: RequestBody) -> Response:
    email = _string(body.json(), "email", maximum=300)
    with db_engine.transaction(b.authenticator_engine) as session:
        outcome = accounts.request_email_verification(session, email=email)
    if outcome.outcome == "issued" and outcome.secret is not None:
        b.send(OutboundEmail(kind="email_verification", recipient=accounts.normalize_email(email), secret=outcome.secret))
    return _json(202, {"status": "accepted"})


def h_verification_complete(b: Boundary, request: Request, body: RequestBody) -> Response:
    token = _secret(body.json(), "token")
    with db_engine.transaction(b.authenticator_engine) as session:
        verified = accounts.verify_email(session, token)
    if not verified:
        return _error(400, "invalid_token")
    return _json(200, {"verified": True})


def h_recovery_request(b: Boundary, request: Request, body: RequestBody) -> Response:
    email = _string(body.json(), "email", maximum=300)
    with db_engine.transaction(b.authenticator_engine) as session:
        outcome = accounts.request_recovery(session, email=email)
    if outcome.outcome == "issued" and outcome.secret is not None:
        b.send(OutboundEmail(kind="account_recovery", recipient=accounts.normalize_email(email), secret=outcome.secret))
    return _json(202, {"status": "accepted"})


def h_recovery_complete(b: Boundary, request: Request, body: RequestBody) -> Response:
    fields = body.json()
    token = _secret(fields, "token")
    password = _secret(fields, "password")
    with db_engine.transaction(b.authenticator_engine) as session:
        completed = accounts.complete_recovery(session, secret=token, new_password=password)
    if not completed:
        return _error(400, "invalid_token")
    return _json(200, {"recovered": True})


def h_login(b: Boundary, request: Request, body: RequestBody) -> Response:
    if "authorization" in request.headers:
        raise ApiError(401, "authentication_required")
    if not _origin_allowed(request, b.settings):
        raise ApiError(403, "origin_not_allowed")
    fields = body.json()
    email = _string(fields, "email", maximum=300)
    password = _secret(fields, "password")
    # Login runs on the authenticator engine: login_lookup and open_browser_session are the
    # authenticator role's, not the application role's.
    with db_engine.transaction(b.authenticator_engine) as session:
        outcome = accounts.login(session, email=email, password=password)
        if outcome.account_id is None:
            raise ApiError(401, "invalid_credentials")
        if not outcome.email_verified:
            # The password matched, so the caller already knows the account exists; saying
            # why it cannot sign in reveals nothing further.
            raise ApiError(403, "email_verification_required")
        try:
            opened = accounts.open_session(session, ttl=b.settings.session_ttl)
        except accounts.IdentityRefused:
            # The password verified against a hash the account no longer has: a recovery or a
            # signed-in change committed while Argon2 ran, and `open_browser_session` refused
            # under the account row lock. The neutral answer is the one a wrong password
            # gets -- the old password *is* wrong now -- never the boundary's generic 404.
            raise ApiError(401, "invalid_credentials") from None
    response = _json(
        200,
        {
            "account_id": str(opened.account_id),
            "session_id": str(opened.session_id),
            "csrf_token": opened.csrf_secret.reveal(),
            "expires_at": _iso(opened.expires_at),
        },
    )
    b.set_session_cookie(response, opened)
    return response


def h_logout(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="account", mutation=True) as (session, context):
        accounts.revoke_session(session, context.session_id)
    response = Response(status_code=204, headers=_NO_STORE)
    b.clear_session_cookie(response)
    return response


def h_account(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="account", mutation=False) as (session, context):
        profile = accounts.account_profile(session)
    return _json(
        200,
        {
            "account_id": str(profile.account_id),
            "email": profile.email,
            "email_verified": profile.email_verified,
            "created_at": _iso(profile.created_at),
            "session": {
                "session_id": str(context.session_id),
                "workspace_id": _ident(context.workspace_id),
                "role": context.role,
                "expires_at": _iso(context.expires_at),
            },
        },
    )


def h_change_password(b: Boundary, request: Request, body: RequestBody) -> Response:
    """Change a signed-in account's password. Cookie, CSRF, and the current password.

    Milestone 3.2, and the flow ``app.py`` said Milestone 3.1 was leaving to it. Three
    proofs, and none of them substitutes for another: the session cookie says which account
    is asking, the CSRF secret says the request came from the portal rather than from
    another site, and the **current password** says the person at the keyboard is the
    account holder rather than somebody who sat down at an unlocked screen.

    Two transactions on two engines, in this order and for this reason. The first binds the
    session on the **application** engine -- that is where a session secret is proved, and
    the authenticator role deliberately cannot bind one -- and yields nothing but the account
    id, the session id and the two passwords from the body. It is closed before the second
    begins: holding a transaction open on one engine while a second runs on another is how
    an avoidable deadlock gets written. The second, on the **authenticator** engine, is where
    everything that changes state happens, and it is atomic: verify, replace by
    compare-and-swap, end every token, credential and session, mint the replacement.

    The replacement session is what the browser leaves with. Every other session of this
    account -- other devices, other browsers, an attacker's -- is revoked by the same
    statement sequence, which is the point of asking.
    """
    with b.bind(request, mode="account", mutation=True) as (_session, context):
        fields = body.json()
        current_password = _secret(fields, "current_password")
        new_password = _secret(fields, "new_password")
        account_id = context.account_id
        session_id = context.session_id
    try:
        with db_engine.transaction(b.authenticator_engine) as session:
            opened = accounts.change_password(
                session,
                account_id=account_id,
                session_id=session_id,
                current_password=current_password,
                new_password=new_password,
                ttl=b.settings.session_ttl,
            )
    except accounts.IdentityRefused:
        # **Not a 404 here, unlike everywhere else on this boundary.** The neutral refusal
        # normally means "absent, hidden, in another tenant, revoked or expired", and `404` is
        # the honest rendering of that. It cannot mean "absent" on this route: the bind one
        # transaction earlier proved this session was live for this account, so a refusal now
        # says the account state moved in between -- another session changed the password, or
        # a recovery completed, either of which revokes every session including this one.
        # `409` is what a client can act on, and it is what the portal renders as "changed
        # somewhere else; nothing was changed here".
        raise ApiError(409, "conflict") from None
    if opened is None:
        # The same refusal a wrong password gets anywhere else, and it names no field: the
        # caller already knows which account it is signed in as, and learns nothing more.
        raise ApiError(401, "invalid_credentials")
    response = _json(
        200,
        {
            "account_id": str(opened.account_id),
            "session_id": str(opened.session_id),
            "csrf_token": opened.csrf_secret.reveal(),
            "expires_at": _iso(opened.expires_at),
            # Stated rather than implied: every other session is gone, and a client that
            # renders "you have been signed out everywhere else" is telling the truth.
            "other_sessions_revoked": True,
        },
    )
    b.set_session_cookie(response, opened)
    return response


def h_sessions(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="account", mutation=False) as (session, _context):
        rows = accounts.account_sessions(session)
    return _json(
        200,
        {
            "sessions": [
                {
                    "session_id": str(row.session_id),
                    "created_at": _iso(row.created_at),
                    "last_seen_at": _iso(row.last_seen_at),
                    "expires_at": _iso(row.expires_at),
                    "workspace_id": _ident(row.workspace_id),
                    "current": row.is_current,
                }
                for row in rows
            ]
        },
    )


def h_session_revoke(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="account", mutation=True) as (session, _context):
        target = _uuid_path(request.path_params["session_id"])
        revoked = accounts.revoke_session(session, target)
    if not revoked:
        return _error(404, "not_found")
    return Response(status_code=204, headers=_NO_STORE)


def h_sessions_revoke_all(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="account", mutation=True) as (session, _context):
        # Strictly a JSON Boolean, and decided before anything is revoked: a body that
        # says anything else is a 422 and the transaction rolls back untouched.
        keep = _boolean(body.json(), "keep_current")
        count = accounts.revoke_all_sessions(session, keep_current=keep)
    response = _json(200, {"revoked": count})
    if not keep:
        b.clear_session_cookie(response)
    return response


# --------------------------------------------------------------------------- handlers: workspaces


def h_account_workspaces(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="account", mutation=False) as (session, _context):
        rows = membership.account_workspaces(session)
    return _json(
        200,
        {
            "workspaces": [
                {
                    "workspace_id": str(row.workspace_id),
                    "slug": row.slug,
                    "name": row.name,
                    "role": row.role,
                    "membership_id": str(row.membership_id),
                    "joined_at": _iso(row.joined_at),
                }
                for row in rows
            ]
        },
    )


def h_create_workspace(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="account", mutation=True) as (session, _context):
        key = _idempotency_key(request, required=True)
        fields = body.json()
        slug = _string(fields, "slug", maximum=64)
        name = _string(fields, "name", maximum=200)
        created = membership.create_workspace(session, slug=slug, name=name, idempotency_key=key)
    return _json(
        200 if created.replayed else 201,
        {
            "workspace_id": str(created.workspace_id),
            "membership_id": str(created.membership_id),
            "role": "owner",
            "replayed": created.replayed,
        },
    )


def h_accept_invitation(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="account", mutation=True) as (session, _context):
        key = _idempotency_key(request, required=False)
        token = _secret(body.json(), "token")
        accepted = membership.accept_invitation(session, token, idempotency_key=key)
    return _json(
        200,
        {
            "workspace_id": str(accepted.workspace_id),
            "membership_id": str(accepted.membership_id),
            "role": accepted.role,
            "replayed": accepted.replayed,
        },
    )


def h_bind_workspace(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="account", mutation=True) as (session, _context):
        workspace_id = _uuid_field(body.json(), "workspace_id")
        binding = membership.bind_session_workspace(session, workspace_id)
    return _json(200, {"workspace_id": str(binding.workspace_id), "role": binding.role, "membership_id": str(binding.membership_id)})


def h_unbind_workspace(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="account", mutation=True) as (session, _context):
        membership.unbind_session_workspace(session)
    return Response(status_code=204, headers=_NO_STORE)


def h_workspace(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="workspace", mutation=False) as (session, context):
        # The role this discloses is the one the membership holds now, re-derived under the
        # workspace lock, not the one the bind cached.
        authority = membership.require_membership(session, scope=Scope.WORKSPACE_READ.value)
        workspace = WorkspaceRepository(session).get(context.workspace_id)
        if workspace is None:
            raise ApiError(404, "not_found")
        payload = {
            "workspace_id": str(workspace.id),
            "slug": workspace.slug,
            "name": workspace.name,
            "role": authority.role,
            "membership_id": _ident(authority.membership_id),
            "created_at": _iso(workspace.created_at),
        }
    return _json(200, payload)


def h_rename_workspace(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="workspace", mutation=True) as (session, context):
        key = _idempotency_key(request, required=True)
        name = _string(body.json(), "name", maximum=200)
        result = membership.rename_workspace(session, name=name, idempotency_key=key)
    return _json(200, {"workspace_id": str(context.workspace_id), "name": name, "replayed": result.replayed})


# ------------------------------------------------------------------- handlers: preferences


def _preferences_payload(row: preferences.WorkspacePreferencesRow) -> dict[str, Any]:
    return {
        "workspace_id": str(row.workspace_id),
        "region_policy": list(row.region_policy),
        "excluded_provider_classes": list(row.excluded_provider_classes),
        "model_profile_note": row.model_profile_note,
        "evaluation_intent": row.evaluation_intent,
        "consent_version": row.consent_version,
        "consent_acknowledged_at": _iso(row.consent_acknowledged_at),
        # The account that acknowledged, not the membership: a membership can be removed and
        # re-created, and the acknowledgement was made by a person.
        "consent_account_id": _ident(row.consent_account_id),
        "updated_at": _iso(row.updated_at),
        # Derived from the architecture, not stored. True when the stated exclusions include
        # one v1 cannot honour -- today, excluding Amazon, because the payload plane is S3.
        "unservable_exclusion": row.unservable_exclusion,
        # So a client never renders a stale statement as current.
        "current_consent_version": CURRENT_CONSENT_VERSION,
    }


def h_preferences(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="workspace", mutation=False) as (session, context):
        row = preferences.read(session, context.workspace_id)
    return _json(200, _preferences_payload(row))


def _expected_workspace_header(request: Request) -> uuid.UUID:
    """The workspace a mutation's page or action began under, from ``X-Workspace-Id``.

    Required on every workspace mutation and never defaulted, for the reason
    :func:`_expected_workspace` gives: defaulting an absent value to the binding would skip
    exactly the comparison the header exists for.
    """
    value = request.headers.get(WORKSPACE_HEADER)
    if not isinstance(value, str) or not _UUID_PATTERN.match(value.strip().lower()):
        raise ApiError(422, "invalid_request")
    return uuid.UUID(value.strip())


def _expected_workspace(fields: dict[str, Any]) -> uuid.UUID:
    """The workspace the page loaded its form for. Required, and never defaulted.

    The bound workspace is what the session says; this is what the *page* says, and the
    database compares the two under the workspace lock. Defaulting an absent field to the
    binding would skip exactly that comparison, so an absent or malformed value is a ``422``
    like any other malformed field -- a syntactic refusal, which answers nothing about any
    workspace.
    """
    value = _string(fields, "workspace_id", maximum=36)
    if not _UUID_PATTERN.match(value.lower()):
        raise ApiError(422, "invalid_request")
    return uuid.UUID(value)


def h_preferences_state(b: Boundary, request: Request, body: RequestBody) -> Response:
    """Replace this workspace's stated intent. A full replacement, so no idempotency key.

    Every other mutation on this boundary that creates something takes one. This one does
    not, and the absence is the design rather than an omission: ``PUT`` here writes the
    whole statement, so sending the same body twice leaves the same row and there is no
    duplicate to collapse. A key would be machinery that proved nothing.

    The body's ``workspace_id`` is the workspace the page loaded its form for; the database
    refuses the write with ``409 workspace_mismatch`` unless it is the workspace this
    session is bound to now.
    """
    with b.bind(request, mode="workspace", mutation=True) as (session, _context):
        fields = body.json()
        row = preferences.state(
            session,
            _expected_workspace(fields),
            region_policy=fields.get("region_policy"),
            excluded_provider_classes=fields.get("excluded_provider_classes"),
            model_profile_note=_string(fields, "model_profile_note", required=False, maximum=200),
            evaluation_intent=_string(fields, "evaluation_intent", maximum=32),
        )
    return _json(200, _preferences_payload(row))


def h_preferences_consent(b: Boundary, request: Request, body: RequestBody) -> Response:
    """Record assent to the consent statement currently published.

    The body names the version the portal displayed and the workspace the page loaded for,
    and nothing else. The version recorded is the database's own current one -- a displayed
    version that is no longer current is a ``409 conflict``, so assent is never recorded to
    text the customer was not shown. Who acknowledged and when are derived inside the
    database function from the bound account and ``clock_timestamp()``; there is no field
    for either, so there is nothing for a caller to state wrongly.
    """
    with b.bind(request, mode="workspace", mutation=True) as (session, _context):
        fields = body.json()
        version = _string(fields, "consent_version", maximum=64)
        row = preferences.acknowledge_consent(session, _expected_workspace(fields), version=version)
    return _json(200, _preferences_payload(row))


def h_consent(b: Boundary, request: Request, body: RequestBody) -> Response:
    """The consent and subprocessor statement. Unauthenticated, and deliberately so.

    A person deciding whether to sign up is entitled to read what they would be agreeing to
    before they have an account. The text is public, carries no customer data and no
    identifier, and is the same for everybody -- so there is nothing here for a credential to
    protect, and requiring one would only mean the portal had to show a version it had
    stored itself.

    A version may be requested by name so that a workspace which acknowledged an older
    statement can still display the text it actually agreed to.
    """
    requested = request.query_params.get("version") or CURRENT_CONSENT_VERSION
    document = CONSENT_DOCUMENTS.get(requested)
    if document is None:
        # The vocabulary is closed and public; an unknown name is simply absent.
        return _error(404, "not_found")
    payload = document.payload()
    payload["current_version"] = CURRENT_CONSENT_VERSION
    payload["versions"] = sorted(CONSENT_DOCUMENTS)
    return _json(200, payload)


# --------------------------------------------------------------------------- handlers: members


def h_members(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="workspace", mutation=False) as (session, context):
        rows = membership.workspace_memberships(session)
    return _json(
        200,
        {
            # The workspace this list describes, so a page can drop a list that arrives
            # after its workspace changed rather than render it under another.
            "workspace_id": str(context.workspace_id),
            "members": [
                {
                    "membership_id": str(row.membership_id),
                    "account_id": str(row.account_id),
                    "email": row.email,
                    "role": row.role,
                    "joined_at": _iso(row.created_at),
                }
                for row in rows
            ]
        },
    )


def h_member_remove(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="workspace", mutation=True) as (session, _context):
        key = _idempotency_key(request, required=False)
        target = _uuid_path(request.path_params["membership_id"])
        membership.remove_membership(session, target, idempotency_key=key)
    return Response(status_code=204, headers=_NO_STORE)


def h_member_role(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="workspace", mutation=True) as (session, _context):
        key = _idempotency_key(request, required=False)
        target = _uuid_path(request.path_params["membership_id"])
        role = _role(body.json())
        changed = membership.change_membership_role(session, target, role, idempotency_key=key)
    return _json(200, {"membership_id": str(changed.membership_id), "role": changed.role, "replayed": changed.replayed})


# --------------------------------------------------------------------------- handlers: invitations


def h_invitations(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="workspace", mutation=False) as (session, context):
        rows = membership.workspace_invitations(session)
    return _json(
        200,
        {
            "workspace_id": str(context.workspace_id),
            "invitations": [
                {
                    "invitation_id": str(row.invitation_id),
                    "email": row.email,
                    "role": row.role,
                    "created_at": _iso(row.created_at),
                    "expires_at": _iso(row.expires_at),
                    "status": row.status,
                }
                for row in rows
            ]
        },
    )


def h_invitation_create(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="workspace", mutation=True) as (session, context):
        key = _idempotency_key(request, required=True)
        fields = body.json()
        email = _string(fields, "email", maximum=300)
        role = _role(fields)
        created = membership.create_invitation(session, email=email, role=role, idempotency_key=key)
        workspace = WorkspaceRepository(session).get(context.workspace_id)
        workspace_name = workspace.name if workspace is not None else ""
    if created.secret is not None:
        b.send(
            OutboundEmail(
                kind="workspace_invitation",
                recipient=accounts.normalize_email(email),
                secret=created.secret,
                context={"workspace": workspace_name[:200], "role": role},
            )
        )
    return _json(
        200 if created.replayed else 201,
        {
            "invitation_id": str(created.invitation_id),
            "role": role,
            "expires_at": _iso(created.expires_at),
            "replayed": created.replayed,
        },
    )


def h_invitation_revoke(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="workspace", mutation=True) as (session, _context):
        key = _idempotency_key(request, required=False)
        target = _uuid_path(request.path_params["invitation_id"])
        result = membership.revoke_invitation(session, target, idempotency_key=key)
    if not result.revoked:
        return _error(404, "not_found")
    return Response(status_code=204, headers=_NO_STORE)


# --------------------------------------------------------------------------- handlers: credentials


def _credential_payload(row: credentials.CredentialSummary) -> dict[str, Any]:
    return {
        "credential_id": str(row.binding_id),
        "label": row.label,
        "scopes": list(row.scopes),
        "created_at": _iso(row.created_at),
        "expires_at": _iso(row.expires_at),
        "revoked_at": _iso(row.revoked_at),
        "last_used_at": _iso(row.last_used_at),
        "rotated_from_id": _ident(row.rotated_from_id),
        "membership_id": _ident(row.membership_id),
        "email": row.email,
        "active": row.active,
    }


def h_credentials(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="workspace", mutation=False) as (session, context):
        rows = credentials.list_credentials(session)
    return _json(
        200,
        {"workspace_id": str(context.workspace_id), "credentials": [_credential_payload(row) for row in rows]},
    )


def _issued_payload(issued: credentials.IssuedCredential) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "credential_id": str(issued.binding_id),
        "scopes": list(issued.scopes),
        "expires_at": _iso(issued.expires_at),
        "rotated_from_id": _ident(issued.rotated_from_id),
        "replayed": issued.replayed,
        # The one place a freshly minted credential is ever rendered, once. A replay
        # returns null here: the secret was displayed when it was minted.
        "credential": issued.credential.reveal() if issued.credential is not None else None,
    }
    return payload


def h_credential_issue(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="workspace", mutation=True) as (session, context):
        key = _idempotency_key(request, required=True)
        fields = body.json()
        scopes = _scopes(fields)
        label = _string(fields, "label", required=False, maximum=100)
        expires_at = _timestamp(fields, "expires_at")
        issued = credentials.issue(
            session, role=context.role or "", scopes=scopes, label=label, expires_at=expires_at, idempotency_key=key
        )
    return _json(200 if issued.replayed else 201, _issued_payload(issued))


def h_credential_rotate(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="workspace", mutation=True) as (session, _context):
        key = _idempotency_key(request, required=True)
        target = _uuid_path(request.path_params["credential_id"])
        expires_at = _timestamp(body.json(), "expires_at")
        issued = credentials.rotate(session, target, expires_at=expires_at, idempotency_key=key)
    return _json(200 if issued.replayed else 201, _issued_payload(issued))


def h_credential_revoke(b: Boundary, request: Request, body: RequestBody) -> Response:
    with b.bind(request, mode="workspace", mutation=True) as (session, _context):
        key = _idempotency_key(request, required=False)
        target = _uuid_path(request.path_params["credential_id"])
        result = credentials.revoke(session, target, idempotency_key=key)
    if not result.revoked:
        return _error(404, "not_found")
    return Response(status_code=204, headers=_NO_STORE)


def h_credential_history(b: Boundary, request: Request, body: RequestBody) -> Response:
    """The audit trail rows about one credential, for a session holding ``audit:read``.

    This is the one disclosure the boundary performs itself -- it reads the audit trail
    through ``db/audit.py`` rather than through an identity function -- so it makes the same
    membership revalidation those functions make, in the database, before it reads anything:
    a session demoted out of ``audit:read`` since it bound gets ``403`` here even though its
    cached context still carries the permission.
    """
    with b.bind(request, mode="workspace", mutation=False) as (session, context):
        target = _uuid_path(request.path_params["credential_id"])
        membership.require_membership(session, scope=Scope.AUDIT_READ.value)
        rows = [
            event
            for event in audit_events(session, limit=500)
            if event.resource_type == "api_credential" and event.resource_id == target
        ]
        payload = [
            {
                "audit_event_id": str(event.id),
                "action": event.action,
                "outcome": event.outcome,
                "actor_kind": event.actor_kind,
                "actor_account_id": _ident(event.actor_principal_id),
                "occurred_at": _iso(event.occurred_at),
                "details": dict(event.details),
            }
            for event in rows
        ]
    if not payload:
        # A credential this session may not see, or one with no history: one answer.
        return _error(404, "not_found")
    return _json(
        200, {"workspace_id": str(context.workspace_id), "credential_id": str(target), "history": payload}
    )


# --------------------------------------------------------------------------- handlers: bearer


def h_api_whoami(b: Boundary, request: Request, body: RequestBody) -> Response:
    credential = b.bearer_credential(request)
    with auth.authenticated_transaction(b.engine, credential) as session:
        context = auth.current_authenticated_context(session)
        credentials.record_use(session)
    return _json(
        200,
        {
            "tenant_id": str(context.tenant_id),
            "principal_id": _ident(context.principal_id),
            "credential_id": _ident(context.binding_id),
            "actor_kind": context.actor_kind,
            "scopes": sorted(context.scopes),
        },
    )


def h_api_workspaces(b: Boundary, request: Request, body: RequestBody) -> Response:
    credential = b.bearer_credential(request)
    with auth.authenticated_transaction(b.engine, credential) as session:
        context = auth.require_authenticated_context(session)
        context.require_scope(Scope.WORKSPACE_READ)
        credentials.record_use(session)
        rows = WorkspaceRepository(session).list()
        payload = [{"workspace_id": str(row.id), "slug": row.slug, "name": row.name} for row in rows]
    return _json(200, {"workspaces": payload})


def h_health(b: Boundary, request: Request, body: RequestBody) -> Response:
    return _json(200, {"status": "ok"})


# --------------------------------------------------------------------------- the application


def create_app(
    *,
    settings: ApiSettings,
    engine: Engine,
    email: EmailDelivery,
    authenticator_engine: Engine | None = None,
) -> Starlette:
    """Build the ASGI application.

    ``engine`` is the restricted application engine. ``authenticator_engine`` is the distinct
    trusted-issuer role that holds signup, email verification, login, session opening and
    recovery; the pre-authentication routes run on it, and the application engine holds none
    of those functions (Milestone 3.1 security correction). If omitted it falls back to the
    application engine, which a test may do but production wiring never does.
    """
    if not isinstance(settings, ApiSettings):
        raise config.ConfigurationError("create_app takes ApiSettings")
    boundary = Boundary(settings, engine, email, authenticator_engine=authenticator_engine)

    def route(path: str, handler, methods):
        return Route(path, _endpoint(boundary, handler), methods=methods)

    routes = [
        route("/v1/health", h_health, ["GET"]),
        # The consent and subprocessor statement: public, because somebody deciding whether
        # to sign up is entitled to read it first.
        route("/v1/consent", h_consent, ["GET"]),
        # --- accounts (browser boundary) -------------------------------------------
        route("/v1/account/signup", h_signup, ["POST"]),
        route("/v1/account/verification/request", h_verification_request, ["POST"]),
        route("/v1/account/verification/complete", h_verification_complete, ["POST"]),
        route("/v1/account/recovery/request", h_recovery_request, ["POST"]),
        route("/v1/account/recovery/complete", h_recovery_complete, ["POST"]),
        route("/v1/account/login", h_login, ["POST"]),
        route("/v1/account/logout", h_logout, ["POST"]),
        route("/v1/account", h_account, ["GET"]),
        route("/v1/account/password", h_change_password, ["POST"]),
        route("/v1/account/sessions", h_sessions, ["GET"]),
        route("/v1/account/sessions/revoke-all", h_sessions_revoke_all, ["POST"]),
        route("/v1/account/sessions/{session_id}", h_session_revoke, ["DELETE"]),
        route("/v1/account/workspaces", h_account_workspaces, ["GET"]),
        route("/v1/account/workspaces", h_create_workspace, ["POST"]),
        route("/v1/account/invitations/accept", h_accept_invitation, ["POST"]),
        route("/v1/account/workspace", h_bind_workspace, ["PUT"]),
        route("/v1/account/workspace", h_unbind_workspace, ["DELETE"]),
        # --- the bound workspace (browser boundary) --------------------------------
        route("/v1/workspace", h_workspace, ["GET"]),
        route("/v1/workspace", h_rename_workspace, ["PATCH"]),
        route("/v1/workspace/preferences", h_preferences, ["GET"]),
        route("/v1/workspace/preferences", h_preferences_state, ["PUT"]),
        route("/v1/workspace/preferences/consent", h_preferences_consent, ["POST"]),
        route("/v1/workspace/members", h_members, ["GET"]),
        route("/v1/workspace/members/{membership_id}", h_member_remove, ["DELETE"]),
        route("/v1/workspace/members/{membership_id}", h_member_role, ["PATCH"]),
        route("/v1/workspace/invitations", h_invitations, ["GET"]),
        route("/v1/workspace/invitations", h_invitation_create, ["POST"]),
        route("/v1/workspace/invitations/{invitation_id}", h_invitation_revoke, ["DELETE"]),
        route("/v1/workspace/credentials", h_credentials, ["GET"]),
        route("/v1/workspace/credentials", h_credential_issue, ["POST"]),
        route("/v1/workspace/credentials/{credential_id}/rotate", h_credential_rotate, ["POST"]),
        route("/v1/workspace/credentials/{credential_id}/history", h_credential_history, ["GET"]),
        route("/v1/workspace/credentials/{credential_id}", h_credential_revoke, ["DELETE"]),
        # --- API credentials (bearer boundary) --------------------------------------
        route("/v1/api/whoami", h_api_whoami, ["GET"]),
        route("/v1/api/workspaces", h_api_workspaces, ["GET"]),
    ]
    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=list(settings.allowed_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["content-type", CSRF_HEADER, IDEMPOTENCY_KEY_HEADER, "authorization"],
            max_age=600,
        )
    ]
    return Starlette(routes=routes, middleware=middleware)
