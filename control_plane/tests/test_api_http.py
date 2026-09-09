"""The native v1 HTTP boundary, driven end to end against PostgreSQL 16 through Starlette's test client.

What is asserted is the boundary's contract from ``api/app.py``: two credential types at
two boundaries that refuse each other; a session cookie with the flags the design names;
CSRF and origin checks on every cookie-authenticated mutation; an explicit CORS allow-list
and never a credentialed wildcard; bounded inputs; neutral errors with a one-field body;
secrets that reach the capture adapter and nothing else -- not a response body, not a log
line, not an error.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import timedelta

import pytest
from psycopg.errors import InsufficientPrivilege
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from starlette.testclient import TestClient

from firmbatch.control_plane.api import settings as api_settings
from firmbatch.control_plane.api.app import create_app
from firmbatch.control_plane.api.email import (
    CapturingEmailDelivery,
    EmailDeliveryUnavailable,
    OutboundEmail,
    UnavailableEmailDelivery,
)
from firmbatch.control_plane.api.settings import (
    CSRF_HEADER,
    IDEMPOTENCY_KEY_HEADER,
    MAX_BODY_BYTES,
    SESSION_COOKIE_NAME,
    ApiSettings,
    load_api_settings,
)
from firmbatch.control_plane.config import ConfigurationError, Environment
from firmbatch.control_plane.db import accounts
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.security import passwords
from firmbatch.control_plane.security.authorization import AuthorizationError
from firmbatch.control_plane.security.secrets import Secret, SecretError
from firmbatch.control_plane.tests.conftest import exception_chain
from firmbatch.control_plane.tests.identity_helpers import (
    PASSWORD,
    everything_stored,
    key,
    unique_email,
)

ORIGIN = "http://app.test"
FOREIGN_ORIGIN = "http://evil.test"


@dataclass
class Api:
    client: TestClient
    email: CapturingEmailDelivery
    settings: ApiSettings


@pytest.fixture()
def api(application_engine, authenticator_engine) -> Api:
    email = CapturingEmailDelivery(Environment.TEST)
    settings = ApiSettings(
        environment=Environment.TEST,
        allowed_origins=(ORIGIN,),
        cookie_secure=False,
        session_ttl=timedelta(hours=1),
    )
    app = create_app(
        settings=settings, engine=application_engine, email=email, authenticator_engine=authenticator_engine
    )
    with TestClient(app, base_url="http://api.test", raise_server_exceptions=False) as client:
        yield Api(client=client, email=email, settings=settings)


class Browser:
    """One signed-in browser: the cookie and the CSRF token from one login, sent by hand.

    Sent as explicit headers rather than through the client's cookie jar, so every test
    states exactly which credentials a request carries.
    """

    def __init__(self, api: Api, cookie: str | None = None, csrf: str | None = None, email: str | None = None):
        self.api = api
        self.cookie = cookie
        self.csrf = csrf
        self.email = email

    def headers(self, *, mutation: bool, origin: str | None = ORIGIN, csrf: str | None | bool = True) -> dict:
        headers = {}
        if self.cookie:
            headers["cookie"] = f"{SESSION_COOKIE_NAME}={self.cookie}"
        if mutation:
            if origin is not None:
                headers["origin"] = origin
            token = self.csrf if csrf is True else csrf
            if token:
                headers[CSRF_HEADER] = token
        return headers

    def get(self, path: str, **kw):
        return self.api.client.get(path, headers=self.headers(mutation=False, **kw))

    def send(self, method: str, path: str, body=None, *, idempotency_key: str | None = None, **kw):
        headers = self.headers(mutation=True, **kw)
        if idempotency_key is not None:
            headers[IDEMPOTENCY_KEY_HEADER] = idempotency_key
        return self.api.client.request(method, path, json=body, headers=headers)

    def post(self, path: str, body=None, **kw):
        return self.send("POST", path, body if body is not None else {}, **kw)


def signup_and_verify(api: Api, email: str | None = None) -> str:
    email = email or unique_email("http")
    response = api.client.post("/v1/account/signup", json={"email": email, "password": PASSWORD})
    assert response.status_code == 202 and response.json() == {"status": "accepted"}
    message = api.email.last("email_verification", email)
    assert message is not None and message.secret is not None
    response = api.client.post("/v1/account/verification/complete", json={"token": message.secret.reveal()})
    assert response.status_code == 200 and response.json() == {"verified": True}
    return email


def login(api: Api, email: str, password: str = PASSWORD) -> Browser:
    response = api.client.post(
        "/v1/account/login", json={"email": email, "password": password}, headers={"origin": ORIGIN}
    )
    assert response.status_code == 200, response.text
    cookie = response.cookies.get(SESSION_COOKIE_NAME)
    assert cookie
    api.client.cookies.clear()  # every later request states its own credentials
    return Browser(api, cookie=cookie, csrf=response.json()["csrf_token"], email=email)


def owner_with_workspace(api: Api, slug: str = "http") -> tuple[Browser, str]:
    browser = login(api, signup_and_verify(api))
    created = browser.post("/v1/account/workspaces", {"slug": slug, "name": "HTTP"}, idempotency_key=key("ws"))
    assert created.status_code == 201, created.text
    workspace_id = created.json()["workspace_id"]
    bound = browser.send("PUT", "/v1/account/workspace", {"workspace_id": workspace_id})
    assert bound.status_code == 200, bound.text
    return browser, workspace_id


def everything_rendered(*responses) -> str:
    return "\n".join(f"{r.status_code} {dict(r.headers)} {r.text}" for r in responses)


# --------------------------------------------------------------------------- accounts and sessions


def test_signup_verification_login_and_the_session_cookie(api: Api, caplog):
    caplog.set_level(logging.INFO, logger="firmbatch.api")
    email = unique_email("flow")
    signup = api.client.post("/v1/account/signup", json={"email": email, "password": PASSWORD})
    assert signup.status_code == 202
    # A second signup for the same address is the same answer, and a different message.
    again = api.client.post("/v1/account/signup", json={"email": email, "password": PASSWORD})
    assert again.status_code == 202 and again.json() == signup.json()
    assert api.email.last("account_exists", email) is not None
    verification = api.email.last("email_verification", email)
    token = verification.secret.reveal()
    assert token.startswith("fbv_") and token not in everything_rendered(signup, again)
    # Signing in before verification: the password is right, and the account is not ready.
    early = api.client.post("/v1/account/login", json={"email": email, "password": PASSWORD}, headers={"origin": ORIGIN})
    assert early.status_code == 403 and early.json() == {"error": "email_verification_required"}
    assert api.client.post("/v1/account/verification/complete", json={"token": token}).status_code == 200
    assert api.client.post("/v1/account/verification/complete", json={"token": token}).json() == {"error": "invalid_token"}

    login_response = api.client.post(
        "/v1/account/login", json={"email": email, "password": PASSWORD}, headers={"origin": ORIGIN}
    )
    assert login_response.status_code == 200
    payload = login_response.json()
    assert set(payload) == {"account_id", "session_id", "csrf_token", "expires_at"}
    assert payload["csrf_token"].startswith("fbc_")
    set_cookie = login_response.headers["set-cookie"]
    assert set_cookie.startswith(f"{SESSION_COOKIE_NAME}=fbs_")
    lowered = set_cookie.lower()
    assert "httponly" in lowered and "samesite=strict" in lowered and "path=/" in lowered
    assert "domain=" not in lowered  # host-only
    assert "max-age=3600" in lowered
    assert login_response.headers["cache-control"] == "no-store"
    session_secret = login_response.cookies[SESSION_COOKIE_NAME]
    assert session_secret not in login_response.text  # the cookie is the only place it travels
    api.client.cookies.clear()

    browser = Browser(api, cookie=session_secret, csrf=payload["csrf_token"])
    profile = browser.get("/v1/account")
    assert profile.status_code == 200
    assert profile.json()["email"] == email and profile.json()["email_verified"] is True
    assert profile.json()["session"]["workspace_id"] is None
    # No secret and no address reached the log.
    for secret in (token, session_secret, payload["csrf_token"], PASSWORD):
        assert secret not in caplog.text
    assert email not in caplog.text
    assert "/v1/account/login" in caplog.text


def test_the_mailbox_verification_secret_reaches_the_adapter_and_nothing_else(
    api: Api, application_engine, owner_engine, caplog
):
    """The raw verification secret goes to the configured email adapter and nowhere else.

    Not into a response body or header, not into a log line, not into an exception, not
    into audit metadata, and not into anything the **application** role can read: signup,
    reissue and verification are the authenticator's, and the one place the secret exists
    outside the transaction that minted it is the message the adapter captured.
    """
    caplog.set_level(logging.DEBUG)
    email = unique_email("mailbox")
    signup = api.client.post("/v1/account/signup", json={"email": email, "password": PASSWORD})
    reissue = api.client.post("/v1/account/verification/request", json={"email": email})
    assert signup.status_code == reissue.status_code == 202

    issued = [
        message.secret.reveal()
        for message in api.email.messages
        if message.kind == "email_verification" and message.recipient == email
    ]
    assert len(issued) == 2
    first, latest = issued
    assert first != latest, "a reissue supersedes the earlier token"

    completed = api.client.post("/v1/account/verification/complete", json={"token": latest})
    assert completed.status_code == 200 and completed.json() == {"verified": True}
    # The superseded one, and a replay of the consumed one, are the same neutral refusal.
    superseded = api.client.post("/v1/account/verification/complete", json={"token": first})
    replayed = api.client.post("/v1/account/verification/complete", json={"token": latest})
    assert superseded.json() == replayed.json() == {"error": "invalid_token"}
    assert superseded.status_code == replayed.status_code == 400

    rendered = everything_rendered(signup, reissue, completed, superseded, replayed)
    for secret in (first, latest, PASSWORD):
        assert secret not in rendered
        assert secret not in caplog.text
    # Nor anywhere the schema owner can see -- the token rows hold fingerprints -- which
    # covers the audit trail and the outbox as well, since they are tables of this schema.
    stored = everything_stored(owner_engine)
    assert first not in stored and latest not in stored

    # And the application role cannot obtain one at all: the three mailbox-verification
    # functions are the authenticator's, so raw SQL on the runtime engine is refused.
    with pytest.raises(ProgrammingError) as exc:
        with db_engine.transaction(application_engine) as session:
            session.execute(
                text(f"SELECT * FROM {SCHEMA}.request_email_verification(:e, interval '1 hour')"), {"e": email}
            )
    assert isinstance(exc.value.orig, InsufficientPrivilege)
    # Through the supported entry point the refusal carries no secret either: db/accounts.py
    # scrubs the parameters of any statement that carried one, and raises with `from None`,
    # so nothing psycopg rendered travels as a cause. (Raw SQL written by hand has no such
    # guarantee -- SQLAlchemy renders bound parameters into DBAPIError -- which is exactly
    # why the wrapper exists.)
    with pytest.raises(AuthorizationError) as refusal:
        with db_engine.transaction(application_engine) as session:
            accounts.verify_email(session, Secret(latest))
    assert latest not in exception_chain(refusal.value)
    with pytest.raises(AuthorizationError) as refusal:
        with db_engine.transaction(application_engine) as session:
            accounts.request_email_verification(session, email=email)
    assert email not in exception_chain(refusal.value)


def test_wrong_password_and_unknown_address_are_one_answer_and_origin_is_required(api: Api):
    email = signup_and_verify(api)
    wrong = api.client.post("/v1/account/login", json={"email": email, "password": "not the password"}, headers={"origin": ORIGIN})
    unknown = api.client.post(
        "/v1/account/login", json={"email": unique_email("nobody"), "password": PASSWORD}, headers={"origin": ORIGIN}
    )
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json() == {"error": "invalid_credentials"}
    assert "set-cookie" not in wrong.headers
    no_origin = api.client.post("/v1/account/login", json={"email": email, "password": PASSWORD})
    assert no_origin.status_code == 403 and no_origin.json() == {"error": "origin_not_allowed"}
    foreign = api.client.post("/v1/account/login", json={"email": email, "password": PASSWORD}, headers={"origin": FOREIGN_ORIGIN})
    assert foreign.status_code == 403 and foreign.json() == {"error": "origin_not_allowed"}
    with_bearer = api.client.post(
        "/v1/account/login", json={"email": email, "password": PASSWORD},
        headers={"origin": ORIGIN, "authorization": "Bearer fbk_" + "a" * 43},
    )
    assert with_bearer.status_code == 401


def test_recovery_issues_a_secret_to_the_adapter_only_and_changes_the_password(api: Api):
    email = signup_and_verify(api)
    known = api.client.post("/v1/account/recovery/request", json={"email": email})
    unknown = api.client.post("/v1/account/recovery/request", json={"email": unique_email("nobody")})
    assert known.status_code == unknown.status_code == 202 and known.json() == unknown.json()
    message = api.email.last("account_recovery", email)
    assert message is not None and message.secret.reveal().startswith("fbr_")
    assert api.email.last("account_recovery", unknown.request.headers.get("x-none", "nobody")) is None
    new_password = "a completely new password"
    done = api.client.post(
        "/v1/account/recovery/complete", json={"token": message.secret.reveal(), "password": new_password}
    )
    assert done.status_code == 200 and done.json() == {"recovered": True}
    reused = api.client.post(
        "/v1/account/recovery/complete", json={"token": message.secret.reveal(), "password": new_password}
    )
    assert reused.status_code == 400 and reused.json() == {"error": "invalid_token"}
    assert login(api, email, new_password).cookie
    old = api.client.post("/v1/account/login", json={"email": email, "password": PASSWORD}, headers={"origin": ORIGIN})
    assert old.status_code == 401


def test_the_cookie_boundary_refuses_a_missing_foreign_or_mixed_credential(api: Api):
    browser = login(api, signup_and_verify(api))
    anonymous = Browser(api)
    assert anonymous.get("/v1/account").status_code == 401
    assert anonymous.get("/v1/account").json() == {"error": "authentication_required"}
    unknown = Browser(api, cookie="fbs_" + "A" * 43)
    assert unknown.get("/v1/account").status_code == 401
    malformed = Browser(api, cookie="fbk_" + "a" * 43)
    assert malformed.get("/v1/account").status_code == 401
    # A browser route carrying an Authorization header is refused whatever the cookie says.
    mixed = api.client.get(
        "/v1/account", headers={"cookie": f"{SESSION_COOKIE_NAME}={browser.cookie}", "authorization": "Bearer x"}
    )
    assert mixed.status_code == 401 and mixed.json() == {"error": "authentication_required"}
    # And the good cookie still works: the refusals above changed nothing.
    assert browser.get("/v1/account").status_code == 200


def test_every_cookie_mutation_needs_the_origin_and_the_sessions_own_csrf_token(api: Api):
    browser = login(api, signup_and_verify(api))
    other = login(api, signup_and_verify(api))
    body = {"slug": "csrf", "name": "CSRF"}
    no_origin = browser.send("POST", "/v1/account/workspaces", body, idempotency_key=key("k"), origin=None)
    assert no_origin.status_code == 403 and no_origin.json() == {"error": "origin_not_allowed"}
    bad_origin = browser.send("POST", "/v1/account/workspaces", body, idempotency_key=key("k"), origin=FOREIGN_ORIGIN)
    assert bad_origin.status_code == 403 and bad_origin.json() == {"error": "origin_not_allowed"}
    no_token = browser.send("POST", "/v1/account/workspaces", body, idempotency_key=key("k"), csrf=None)
    assert no_token.status_code == 403 and no_token.json() == {"error": "csrf_token_required"}
    wrong_token = browser.send("POST", "/v1/account/workspaces", body, idempotency_key=key("k"), csrf=other.csrf)
    assert wrong_token.status_code == 401 and wrong_token.json() == {"error": "authentication_required"}
    malformed = browser.send("POST", "/v1/account/workspaces", body, idempotency_key=key("k"), csrf="fbc_short")
    assert malformed.status_code == 401
    # Reads need neither.
    assert browser.get("/v1/account/workspaces").status_code == 200
    # Nothing was created by any refused attempt.
    assert browser.get("/v1/account/workspaces").json() == {"workspaces": []}
    good = browser.send("POST", "/v1/account/workspaces", body, idempotency_key=key("k"))
    assert good.status_code == 201


#: What a body can be. Each case carries the bytes, the media type, and the status a
#: **signed-in** caller gets for it -- so the test asserts both halves: the refusal an
#: unauthenticated caller gets does not depend on the body, and the body error a signed-in
#: caller gets is still exactly the one the rule names.
_BODY_CASES = (
    pytest.param(
        {"content": b"{not json", "content_type": "application/json", "authenticated_status": 400},
        id="broken_json",
    ),
    pytest.param(
        {"content": b"[1, 2, 3]", "content_type": "application/json", "authenticated_status": 422},
        id="not_an_object",
    ),
    pytest.param(
        {
            "content": b"slug=x&name=y",
            "content_type": "application/x-www-form-urlencoded",
            "authenticated_status": 415,
        },
        id="wrong_media_type",
    ),
    pytest.param(
        {
            "content": b'{"slug": "wellformed", "name": "OK"}',
            "content_type": "application/json",
            "authenticated_status": 201,
        },
        id="well_formed",
    ),
)


@pytest.mark.parametrize("body_case", _BODY_CASES)
def test_a_protected_route_authenticates_before_it_interprets_the_body(api: Api, body_case):
    """Finding: authenticate the route, then interpret the body -- never the other way round.

    Absent, malformed, unknown-but-well-formed and mixed credentials are one ``401``, and the
    body cannot change that answer: broken JSON, a JSON array and an unsupported media type
    all get the same refusal as a perfectly good body would. A ``400 invalid_json`` or a
    ``415 unsupported_media_type`` handed to an unauthenticated caller would say that the
    boundary read what it sent and got as far as parsing it.
    """
    signed_in = login(api, signup_and_verify(api))
    credentials_under_test = {
        "absent": {},
        "malformed": {"cookie": f"{SESSION_COOKIE_NAME}=not-a-session-secret"},
        "unknown": {"cookie": f"{SESSION_COOKIE_NAME}=fbs_" + "A" * 43},
        "mixed": {
            "cookie": f"{SESSION_COOKIE_NAME}={signed_in.cookie}",
            "authorization": "Bearer fbk_" + "a" * 43,
        },
    }
    answers = {}
    for label, headers in credentials_under_test.items():
        # A GET, which needs no origin or CSRF header at all.
        read = api.client.get("/v1/account/workspaces", headers=headers)
        # And a mutation, sent exactly as a well-formed browser would send one, so that the
        # only thing varying across the four is the credential.
        mutation = api.client.request(
            "POST",
            "/v1/account/workspaces",
            content=body_case["content"],
            headers={
                **headers,
                "content-type": body_case["content_type"],
                "origin": ORIGIN,
                CSRF_HEADER: signed_in.csrf,
                IDEMPOTENCY_KEY_HEADER: key("b"),
            },
        )
        answers[label] = (read.status_code, read.json(), mutation.status_code, mutation.json())

    expected = (401, {"error": "authentication_required"}, 401, {"error": "authentication_required"})
    for label, answer in answers.items():
        assert answer == expected, f"{label} differs: {answer}"
    # The other half: for a signed-in caller the body error is still exactly the one the rule
    # names. Without this the test could pass on a boundary that had simply stopped parsing.
    parsed = api.client.request(
        "POST",
        "/v1/account/workspaces",
        content=body_case["content"],
        headers={
            "cookie": f"{SESSION_COOKIE_NAME}={signed_in.cookie}",
            "content-type": body_case["content_type"],
            "origin": ORIGIN,
            CSRF_HEADER: signed_in.csrf,
            IDEMPOTENCY_KEY_HEADER: key("b"),
        },
    )
    assert parsed.status_code == body_case["authenticated_status"], parsed.text


def test_an_oversized_body_is_refused_before_the_credential_is_considered(api: Api):
    """The one thing that still comes first: the streamed size limit.

    It has to -- refusing after buffering would mean the buffer had already happened -- and
    it is a refusal about the request's size, which the sender knows before it sends. So an
    anonymous oversized body is ``413``, not ``401``, and that is deliberate rather than a
    hole in the ordering above.
    """
    oversized = api.client.post(
        "/v1/account/workspaces",
        content=b"{" + b"x" * (MAX_BODY_BYTES + 1024),
        headers={"content-type": "application/json", "origin": ORIGIN},
    )
    assert oversized.status_code == 413 and oversized.json() == {"error": "request_too_large"}


def test_a_wrong_csrf_token_is_never_reclassified_as_workspace_required(api: Api):
    """Finding: ``_refused_bind`` must retry with the CSRF proof the request carried.

    The database answers a wrong CSRF token with the same neutral refusal it gives an unknown
    session, so the boundary re-binds in account mode to tell "refused" from "no workspace
    selected". Retrying **without** the token made that second bind an easier question than
    the one that just failed, and a forged mutation came back as ``412 workspace_required`` --
    which tells its sender the cookie was good and only a workspace was missing.
    """
    browser = login(api, signup_and_verify(api))
    other = login(api, signup_and_verify(api))
    created = browser.post("/v1/account/workspaces", {"slug": "csrfcls", "name": "C"}, idempotency_key=key("w"))
    assert created.status_code == 201

    # 1. Bound to no workspace, correct CSRF: this is what 412 is for, and it survives.
    unbound = browser.send("PATCH", "/v1/workspace", {"name": "New"}, idempotency_key=key("r"))
    assert unbound.status_code == 412 and unbound.json() == {"error": "workspace_required"}

    # 2. Bound to no workspace, *wrong* CSRF: the credential is refused, and the 412 that
    #    would have described the account's state is not offered.
    forged_unbound = browser.send(
        "PATCH", "/v1/workspace", {"name": "New"}, idempotency_key=key("r"), csrf=other.csrf
    )
    assert forged_unbound.status_code == 401
    assert forged_unbound.json() == {"error": "authentication_required"}

    # 3. Now select the workspace. A wrong CSRF on a workspace-mode mutation is still 401.
    bound = browser.send("PUT", "/v1/account/workspace", {"workspace_id": created.json()["workspace_id"]})
    assert bound.status_code == 200
    forged_bound = browser.send(
        "PATCH", "/v1/workspace", {"name": "New"}, idempotency_key=key("r"), csrf=other.csrf
    )
    assert forged_bound.status_code == 401 and forged_bound.json() == {"error": "authentication_required"}
    # 4. And the genuine article still works, so nothing above broke the ordinary path.
    assert browser.send("PATCH", "/v1/workspace", {"name": "New"}, idempotency_key=key("r")).status_code == 200


@pytest.mark.parametrize("value", ("true", "false", 1, 0, [], {}, None, "yes"))
def test_keep_current_accepts_only_a_json_boolean_and_changes_nothing_otherwise(api: Api, value):
    """Finding: ``bool(body.get(...))`` accepted every JSON type and meant something by each.

    ``"false"`` is truthy, ``0`` is falsy, ``null`` is falsy: three ways for a caller to keep
    or destroy its own sessions by accident. Only ``true`` and ``false`` are accepted now, the
    refusal is ``422 invalid_request``, and no session is touched by a refused request.
    """
    browser = login(api, signup_and_verify(api))
    second = login(api, browser.email)
    refused = browser.post("/v1/account/sessions/revoke-all", {"keep_current": value})
    assert refused.status_code == 422 and refused.json() == {"error": "invalid_request"}
    assert "set-cookie" not in refused.headers
    # Both sessions are untouched: the refusal changed nothing.
    listed = browser.get("/v1/account/sessions").json()["sessions"]
    assert len(listed) == 2
    assert second.get("/v1/account").status_code == 200


def test_keep_current_true_retains_the_session_and_false_revokes_and_clears_it(api: Api):
    """The two answers the field is allowed to give, and what each does."""
    browser = login(api, signup_and_verify(api))
    other = login(api, browser.email)
    third = login(api, browser.email)
    assert len(browser.get("/v1/account/sessions").json()["sessions"]) == 3

    kept = browser.post("/v1/account/sessions/revoke-all", {"keep_current": True})
    assert kept.status_code == 200 and kept.json() == {"revoked": 2}
    assert "set-cookie" not in kept.headers, "keeping the current session must not clear its cookie"
    assert browser.get("/v1/account").status_code == 200
    for gone in (other, third):
        assert gone.get("/v1/account").status_code == 401
    assert [row["current"] for row in browser.get("/v1/account/sessions").json()["sessions"]] == [True]

    # An absent field still defaults to false, and false revokes the caller's own session.
    revoked = browser.post("/v1/account/sessions/revoke-all", {"keep_current": False})
    assert revoked.status_code == 200 and revoked.json() == {"revoked": 1}
    cleared = revoked.headers["set-cookie"].lower()
    assert cleared.startswith(f"{SESSION_COOKIE_NAME}=") and "max-age=0" in cleared
    assert browser.get("/v1/account").status_code == 401


def test_sessions_are_listed_revoked_and_logged_out(api: Api):
    email = signup_and_verify(api)
    first = login(api, email)
    second = login(api, email)
    listed = first.get("/v1/account/sessions").json()["sessions"]
    assert len(listed) == 2 and sum(1 for row in listed if row["current"]) == 1
    other_id = next(row["session_id"] for row in listed if not row["current"])
    assert first.send("DELETE", f"/v1/account/sessions/{other_id}").status_code == 204
    assert second.get("/v1/account").status_code == 401
    assert first.send("DELETE", f"/v1/account/sessions/{other_id}").status_code == 404
    assert first.send("DELETE", f"/v1/account/sessions/{uuid.uuid4()}").status_code == 404
    assert first.send("DELETE", "/v1/account/sessions/not-a-uuid").status_code == 404
    logout = first.post("/v1/account/logout")
    assert logout.status_code == 204
    assert f"{SESSION_COOKIE_NAME}=" in logout.headers["set-cookie"]
    assert "max-age=0" in logout.headers["set-cookie"].lower() or "expires=" in logout.headers["set-cookie"].lower()
    assert first.get("/v1/account").status_code == 401
    third = login(api, email)
    fourth = login(api, email)
    revoked = third.post("/v1/account/sessions/revoke-all", {"keep_current": True})
    assert revoked.status_code == 200 and revoked.json() == {"revoked": 1}
    assert fourth.get("/v1/account").status_code == 401 and third.get("/v1/account").status_code == 200


# --------------------------------------------------------------------------- workspaces and members


def test_workspace_creation_is_keyed_replayed_and_bound(api: Api):
    browser = login(api, signup_and_verify(api))
    body = {"slug": "acme", "name": "Acme"}
    assert browser.post("/v1/account/workspaces", body).status_code == 428
    assert browser.post("/v1/account/workspaces", body).json() == {"error": "idempotency_key_required"}
    k = key("ws")
    created = browser.post("/v1/account/workspaces", body, idempotency_key=k)
    assert created.status_code == 201 and created.json()["role"] == "owner" and created.json()["replayed"] is False
    replayed = browser.post("/v1/account/workspaces", body, idempotency_key=k)
    assert replayed.status_code == 200 and replayed.json()["replayed"] is True
    assert replayed.json()["workspace_id"] == created.json()["workspace_id"]
    reused = browser.post("/v1/account/workspaces", {"slug": "other", "name": "Other"}, idempotency_key=k)
    assert reused.status_code == 409 and reused.json() == {"error": "idempotency_key_reuse"}
    assert browser.post("/v1/account/workspaces", body, idempotency_key="fbk_" + "a" * 43).status_code == 422
    # Workspace routes need a selected workspace; the session is fine, so it is told so.
    unbound = browser.get("/v1/workspace")
    assert unbound.status_code == 412 and unbound.json() == {"error": "workspace_required"}
    workspace_id = created.json()["workspace_id"]
    assert browser.send("PUT", "/v1/account/workspace", {"workspace_id": str(uuid.uuid4())}).status_code == 404
    bound = browser.send("PUT", "/v1/account/workspace", {"workspace_id": workspace_id})
    assert bound.status_code == 200 and bound.json()["role"] == "owner"
    workspace = browser.get("/v1/workspace")
    assert workspace.status_code == 200 and workspace.json()["slug"] == "acme" and workspace.json()["role"] == "owner"
    members = browser.get("/v1/workspace/members").json()["members"]
    assert len(members) == 1 and members[0]["role"] == "owner" and members[0]["email"] == browser.email
    renamed = browser.send("PATCH", "/v1/workspace", {"name": "Acme Ltd"}, idempotency_key=key("rn"))
    assert renamed.status_code == 200 and browser.get("/v1/workspace").json()["name"] == "Acme Ltd"
    assert browser.send("DELETE", "/v1/account/workspace").status_code == 204
    assert browser.get("/v1/workspace").status_code == 412
    listed = browser.get("/v1/account/workspaces").json()["workspaces"]
    assert [row["slug"] for row in listed] == ["acme"] and listed[0]["name"] == "Acme Ltd"


def test_invitations_travel_through_the_adapter_and_membership_follows(api: Api, caplog):
    caplog.set_level(logging.INFO, logger="firmbatch.api")
    owner, workspace_id = owner_with_workspace(api)
    invitee_email = signup_and_verify(api)
    invitee = login(api, invitee_email)
    created = owner.post(
        "/v1/workspace/invitations", {"email": invitee_email, "role": "member"}, idempotency_key=key("inv")
    )
    assert created.status_code == 201 and created.json()["role"] == "member"
    message = api.email.last("workspace_invitation", invitee_email)
    assert message is not None and message.secret.reveal().startswith("fbi_")
    assert message.context == {"workspace": "HTTP", "role": "member"}
    secret = message.secret.reveal()
    assert secret not in created.text and secret not in caplog.text
    assert owner.post("/v1/workspace/invitations", {"email": invitee_email, "role": "owner"}, idempotency_key=key("x")).status_code == 409
    assert owner.post("/v1/workspace/invitations", {"email": invitee_email, "role": "root"}, idempotency_key=key("x")).status_code == 422
    pending = owner.get("/v1/workspace/invitations").json()["invitations"]
    assert [row["status"] for row in pending] == ["pending"]
    # The wrong account cannot accept it; the right one can, once.
    stranger = login(api, signup_and_verify(api))
    assert stranger.post("/v1/account/invitations/accept", {"token": secret}).status_code == 404
    accepted = invitee.post("/v1/account/invitations/accept", {"token": secret})
    assert accepted.status_code == 200 and accepted.json()["workspace_id"] == workspace_id
    assert invitee.post("/v1/account/invitations/accept", {"token": secret}).status_code == 404
    assert invitee.post("/v1/account/invitations/accept", {"token": "fbi_" + "B" * 43}).status_code == 404
    # A bearer-shaped value is not an invitation token: the same neutral answer as an unknown one.
    assert invitee.post("/v1/account/invitations/accept", {"token": "fbk_" + "b" * 43}).status_code == 404
    assert invitee.send("PUT", "/v1/account/workspace", {"workspace_id": workspace_id}).status_code == 200
    assert invitee.get("/v1/workspace").json()["role"] == "member"
    members = owner.get("/v1/workspace/members").json()["members"]
    assert {row["role"] for row in members} == {"owner", "member"}
    membership_id = next(row["membership_id"] for row in members if row["role"] == "member")
    # A member may not manage; an owner may re-role and remove.
    assert invitee.get("/v1/workspace/invitations").status_code == 403
    assert invitee.send("PATCH", f"/v1/workspace/members/{membership_id}", {"role": "admin"}).status_code == 403
    promoted = owner.send("PATCH", f"/v1/workspace/members/{membership_id}", {"role": "admin"})
    assert promoted.status_code == 200 and promoted.json()["role"] == "admin"
    assert owner.send("DELETE", f"/v1/workspace/members/{uuid.uuid4()}").status_code == 404
    assert owner.send("DELETE", f"/v1/workspace/members/{membership_id}").status_code == 204
    assert invitee.get("/v1/workspace").status_code == 412  # unbound by the cascade
    assert owner.send("DELETE", f"/v1/workspace/members/{membership_id}").status_code == 404
    # Nothing secret in any of it.
    assert secret not in caplog.text and "fbs_" not in caplog.text and "fbc_" not in caplog.text


# --------------------------------------------------------------------------- credentials and the bearer boundary


def test_credentials_are_issued_once_and_authenticate_at_the_bearer_boundary_only(api: Api, caplog):
    caplog.set_level(logging.INFO, logger="firmbatch.api")
    owner, workspace_id = owner_with_workspace(api, slug="creds")
    k = key("cred")
    body = {"scopes": ["workspace:read", "audit:read"], "label": "ci"}
    assert owner.post("/v1/workspace/credentials", body).status_code == 428
    issued = owner.post("/v1/workspace/credentials", body, idempotency_key=k)
    assert issued.status_code == 201, issued.text
    credential = issued.json()["credential"]
    assert credential.startswith("fbk_") and issued.json()["scopes"] == ["audit:read", "workspace:read"]
    replayed = owner.post("/v1/workspace/credentials", body, idempotency_key=k)
    assert replayed.status_code == 200 and replayed.json()["credential"] is None and replayed.json()["replayed"]
    assert replayed.json()["credential_id"] == issued.json()["credential_id"]
    credential_id = issued.json()["credential_id"]
    # Scope refusals name the rule, not the value.
    too_much = owner.post("/v1/workspace/credentials", {"scopes": ["credential:manage"]}, idempotency_key=key("x"))
    assert too_much.status_code == 422 and too_much.json() == {"error": "invalid_request"}
    assert owner.post("/v1/workspace/credentials", {"scopes": ["fbk_" + "a" * 43]}, idempotency_key=key("x")).status_code == 422
    assert owner.post("/v1/workspace/credentials", {"scopes": "workspace:read"}, idempotency_key=key("x")).status_code == 422

    bearer = {"authorization": f"Bearer {credential}"}
    whoami = api.client.get("/v1/api/whoami", headers=bearer)
    assert whoami.status_code == 200, whoami.text
    assert whoami.json()["actor_kind"] == "credential" and whoami.json()["credential_id"] == credential_id
    assert whoami.json()["scopes"] == ["audit:read", "workspace:read"]
    workspaces = api.client.get("/v1/api/workspaces", headers=bearer)
    assert workspaces.status_code == 200 and [w["workspace_id"] for w in workspaces.json()["workspaces"]] == [workspace_id]
    # The session cookie is not a bearer token; a bearer route ignores and refuses cookies;
    # a browser route refuses bearer tokens.
    assert api.client.get("/v1/api/whoami", headers={"authorization": f"Bearer {owner.cookie}"}).status_code == 401
    assert api.client.get("/v1/api/whoami", headers={"authorization": f"Basic {credential}"}).status_code == 401
    assert api.client.get("/v1/api/whoami").status_code == 401
    assert api.client.get("/v1/api/whoami", headers={**bearer, "cookie": f"{SESSION_COOKIE_NAME}={owner.cookie}"}).status_code == 401
    assert api.client.get("/v1/workspace", headers=bearer).status_code == 401
    assert api.client.get("/v1/workspace/credentials", headers=bearer).status_code == 401
    assert api.client.post("/v1/workspace/credentials", json=body, headers={**bearer, "origin": ORIGIN}).status_code == 401

    listed = owner.get("/v1/workspace/credentials").json()["credentials"]
    assert [row["credential_id"] for row in listed] == [credential_id]
    assert listed[0]["last_used_at"] is not None and listed[0]["active"] is True
    assert "fingerprint" not in json.dumps(listed) and credential not in json.dumps(listed)

    rotated = owner.post(f"/v1/workspace/credentials/{credential_id}/rotate", {}, idempotency_key=key("rot"))
    assert rotated.status_code == 201 and rotated.json()["rotated_from_id"] == credential_id
    new_credential = rotated.json()["credential"]
    assert new_credential != credential
    assert api.client.get("/v1/api/whoami", headers=bearer).status_code == 401
    assert api.client.get("/v1/api/whoami", headers={"authorization": f"Bearer {new_credential}"}).status_code == 200
    assert owner.post(f"/v1/workspace/credentials/{credential_id}/rotate", {}, idempotency_key=key("rot")).status_code == 404
    assert owner.post(f"/v1/workspace/credentials/{uuid.uuid4()}/rotate", {}, idempotency_key=key("rot")).status_code == 404

    history = owner.get(f"/v1/workspace/credentials/{credential_id}/history")
    assert history.status_code == 200
    assert [row["action"] for row in history.json()["history"]] == ["credential.issued", "credential.rotated"] or (
        {row["action"] for row in history.json()["history"]} >= {"credential.issued"}
    )
    assert owner.get(f"/v1/workspace/credentials/{uuid.uuid4()}/history").status_code == 404

    new_id = rotated.json()["credential_id"]
    assert owner.send("DELETE", f"/v1/workspace/credentials/{new_id}").status_code == 204
    assert owner.send("DELETE", f"/v1/workspace/credentials/{new_id}").status_code == 404
    assert api.client.get("/v1/api/whoami", headers={"authorization": f"Bearer {new_credential}"}).status_code == 401
    for secret in (credential, new_credential, owner.cookie, owner.csrf):
        assert secret not in caplog.text


def test_a_member_issues_within_its_role_and_a_viewer_issues_nothing(api: Api):
    owner, workspace_id = owner_with_workspace(api, slug="roles")
    for role in ("member", "viewer"):
        email = signup_and_verify(api)
        person = login(api, email)
        owner.post("/v1/workspace/invitations", {"email": email, "role": role}, idempotency_key=key("i"))
        token = api.email.last("workspace_invitation", email).secret.reveal()
        assert person.post("/v1/account/invitations/accept", {"token": token}).status_code == 200
        assert person.send("PUT", "/v1/account/workspace", {"workspace_id": workspace_id}).status_code == 200
        beyond = person.post("/v1/workspace/credentials", {"scopes": ["audit:read"]}, idempotency_key=key("c"))
        within = person.post("/v1/workspace/credentials", {"scopes": ["workspace:read"]}, idempotency_key=key("c"))
        if role == "member":
            assert beyond.status_code == 422 and within.status_code == 201
            assert person.get(f"/v1/workspace/credentials/{within.json()['credential_id']}/history").status_code == 403
        else:
            assert beyond.status_code in (403, 422) and within.status_code in (403, 422)
            assert person.get("/v1/workspace/credentials").json() == {"credentials": []}


# --------------------------------------------------------------------------- CORS, inputs, errors


def test_cors_is_an_explicit_allow_list_with_credentials_and_never_a_wildcard(api: Api):
    preflight = api.client.options(
        "/v1/account/workspaces",
        headers={"origin": ORIGIN, "access-control-request-method": "POST", "access-control-request-headers": CSRF_HEADER},
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == ORIGIN
    assert preflight.headers["access-control-allow-credentials"] == "true"
    assert CSRF_HEADER in preflight.headers["access-control-allow-headers"].lower()
    foreign = api.client.options(
        "/v1/account/workspaces", headers={"origin": FOREIGN_ORIGIN, "access-control-request-method": "POST"}
    )
    assert "access-control-allow-origin" not in foreign.headers
    simple = api.client.get("/v1/health", headers={"origin": FOREIGN_ORIGIN})
    assert simple.status_code == 200 and "access-control-allow-origin" not in simple.headers
    allowed = api.client.get("/v1/health", headers={"origin": ORIGIN})
    assert allowed.headers["access-control-allow-origin"] == ORIGIN
    assert "*" not in allowed.headers.get("access-control-allow-origin", "")


def test_inputs_are_bounded_before_they_are_looked_at(api: Api):
    big = api.client.post(
        "/v1/account/signup", content=b"{" + b" " * (MAX_BODY_BYTES + 1) + b"}", headers={"content-type": "application/json"}
    )
    assert big.status_code == 413 and big.json() == {"error": "request_too_large"}
    assert api.client.post("/v1/account/signup", content=b"not json", headers={"content-type": "application/json"}).status_code == 400
    assert api.client.post("/v1/account/signup", content=b"email=x", headers={"content-type": "text/plain"}).status_code == 415
    assert api.client.post("/v1/account/signup", content=b"[1, 2]", headers={"content-type": "application/json"}).status_code == 422
    assert api.client.post("/v1/account/signup", json={"email": "x" * 600 + "@example.com", "password": PASSWORD}).status_code == 422
    assert api.client.post("/v1/account/signup", json={"email": "not an address", "password": PASSWORD}).status_code == 422
    assert api.client.post("/v1/account/signup", json={"email": unique_email(), "password": "short"}).status_code == 422
    assert api.client.post("/v1/account/signup", json={"email": unique_email()}).status_code == 422
    assert api.client.post("/v1/account/signup", json={"email": 42, "password": PASSWORD}).status_code == 422
    looks = api.client.post("/v1/account/signup", json={"email": "fbk_" + "a" * 43, "password": PASSWORD})
    assert looks.status_code == 422 and "fbk_" not in looks.text
    assert api.client.get("/v1/nope").status_code == 404
    assert api.client.delete("/v1/account/signup").status_code == 405


def test_the_body_reader_stops_at_the_limit_without_draining_the_whole_stream():
    """Finding 7 (report): the body limit is enforced as the ASGI receive stream is consumed,
    not only from Content-Length. Drive the reader directly with a receive that never signals
    end-of-body and offers unbounded chunks: it must reject at the cap after only a handful of
    reads, never draining a runaway stream. (The Starlette test client buffers a generator body
    itself, so server-side bounded consumption is asserted here rather than through it.)"""
    import asyncio

    from starlette.requests import Request

    from firmbatch.control_plane.api.app import ApiError, _read_body

    received = {"chunks": 0}

    async def receive():
        received["chunks"] += 1
        # No Content-Length was set; each chunk claims more_body, so a reader that did not
        # bound itself would loop forever.
        return {"type": "http.request", "body": b"a" * 4096, "more_body": True}

    async def run():
        request = Request(
            {"type": "http", "method": "POST", "headers": [(b"content-type", b"application/json")]},
            receive,
        )
        with pytest.raises(ApiError) as exc:
            await _read_body(request)
        assert exc.value.status == 413

    asyncio.run(run())
    # 16 KiB cap over 4 KiB chunks: the reader stops after ~5 reads, and never runs away.
    assert received["chunks"] <= 8, f"the reader consumed {received['chunks']} chunks before rejecting"


def test_a_chunked_body_without_content_length_is_rejected(api: Api):
    """Finding 7 (report), end to end: a body with no Content-Length header (a chunked stream)
    that exceeds the limit is still rejected -- the guard does not depend on Content-Length."""

    def stream():
        for _ in range(8):  # ~32 KiB, over the 16 KiB cap, sent without Content-Length
            yield b"a" * 4096

    response = api.client.post(
        "/v1/account/signup", content=stream(), headers={"content-type": "application/json"}
    )
    assert response.status_code == 413 and response.json() == {"error": "request_too_large"}


def test_login_under_kdf_saturation_is_503_for_known_and_unknown_alike(api: Api, monkeypatch):
    """Finding 8 (report): unauthenticated login work is admission-bounded. When the memory-hard
    gate is saturated, login is turned away with a deterministic 503 -- the same answer for a
    known and an unknown address, so overload discloses nothing about account existence."""
    email = signup_and_verify(api)
    gate = passwords.KDFAdmissionGate(max_concurrency=1, acquire_timeout=0.05)
    monkeypatch.setattr(passwords, "KDF_GATE", gate)
    with gate.admit():  # hold the only slot; every login in the threadpool is turned away
        known = api.client.post(
            "/v1/account/login", json={"email": email, "password": PASSWORD}, headers={"origin": ORIGIN}
        )
        unknown = api.client.post(
            "/v1/account/login",
            json={"email": unique_email("ghost"), "password": PASSWORD},
            headers={"origin": ORIGIN},
        )
    assert known.status_code == unknown.status_code == 503
    assert known.json() == unknown.json() == {"error": "service_unavailable"}
    # Released: login works again, and the answer to a wrong password is the ordinary 401.
    recovered = api.client.post(
        "/v1/account/login", json={"email": email, "password": PASSWORD}, headers={"origin": ORIGIN}
    )
    assert recovered.status_code == 200


def test_error_bodies_carry_one_field_and_no_value(api: Api):
    browser = login(api, signup_and_verify(api))
    responses = (
        api.client.get("/v1/account"),
        browser.get("/v1/workspace"),
        browser.send("PUT", "/v1/account/workspace", {"workspace_id": "zzz"}),
        browser.send("PUT", "/v1/account/workspace", {"workspace_id": str(uuid.uuid4())}),
        browser.post("/v1/account/workspaces", {"slug": "Bad Slug", "name": "x"}, idempotency_key=key("k")),
        browser.post("/v1/account/invitations/accept", {"token": "fbi_" + "C" * 43}),
        api.client.post("/v1/account/verification/complete", json={"token": "fbv_" + "D" * 43}),
    )
    for response in responses:
        assert response.status_code in (400, 401, 404, 412, 422), response.text
        body = response.json()
        assert set(body) == {"error"} and isinstance(body["error"], str)
        assert "Bad Slug" not in response.text and "zzz" not in response.text
        assert "CCCC" not in response.text and "DDDD" not in response.text
        assert response.headers["cache-control"] == "no-store"


def test_the_cookie_is_secure_outside_the_insecure_test_setting(application_engine, authenticator_engine):
    settings = ApiSettings(
        environment=Environment.TEST, allowed_origins=("https://app.firmbatch.com",), cookie_secure=True,
        session_ttl=timedelta(hours=2),
    )
    email_adapter = CapturingEmailDelivery(Environment.TEST)
    app = create_app(
        settings=settings, engine=application_engine, email=email_adapter, authenticator_engine=authenticator_engine
    )
    with TestClient(app, base_url="https://api.firmbatch.com", raise_server_exceptions=False) as client:
        api = Api(client=client, email=email_adapter, settings=settings)
        email = signup_and_verify(api)
        response = client.post(
            "/v1/account/login", json={"email": email, "password": PASSWORD}, headers={"origin": "https://app.firmbatch.com"}
        )
        assert response.status_code == 200
        cookie = response.headers["set-cookie"].lower()
        assert "secure" in cookie and "httponly" in cookie and "samesite=strict" in cookie
        assert "domain=" not in cookie and "max-age=7200" in cookie
        assert client.post(
            "/v1/account/login", json={"email": email, "password": PASSWORD}, headers={"origin": ORIGIN}
        ).status_code == 403


# --------------------------------------------------------------------------- settings and the adapters


def test_api_settings_fail_closed():
    base = {"FIRMBATCH_ENV": "test"}
    mixed = {**base, api_settings.ALLOWED_ORIGINS_VAR: "http://app.test, HTTPS://App.Example.com:8443"}
    assert load_api_settings(mixed).allowed_origins == ("http://app.test", "https://app.example.com:8443")
    for raw in ("", "*", "https://*.example.com", "app.test", "https://app.test/path"):
        with pytest.raises(ConfigurationError):
            load_api_settings({**base, api_settings.ALLOWED_ORIGINS_VAR: raw})
    good = {**base, api_settings.ALLOWED_ORIGINS_VAR: "http://app.test"}
    assert load_api_settings({**good, api_settings.COOKIE_SECURE_VAR: "false"}).cookie_secure is False
    assert load_api_settings(good).cookie_secure is True
    with pytest.raises(ConfigurationError):
        load_api_settings({**good, api_settings.COOKIE_SECURE_VAR: "maybe"})
    production = {"FIRMBATCH_ENV": "production", api_settings.ALLOWED_ORIGINS_VAR: "https://app.firmbatch.com"}
    assert load_api_settings(production).cookie_secure is True
    with pytest.raises(ConfigurationError):
        load_api_settings({**production, api_settings.COOKIE_SECURE_VAR: "false"})
    with pytest.raises(ConfigurationError):
        load_api_settings({**production, api_settings.ALLOWED_ORIGINS_VAR: "http://app.firmbatch.com"})
    assert load_api_settings({**good, api_settings.SESSION_TTL_VAR: "600"}).session_ttl == timedelta(minutes=10)
    for raw in ("0", "-1", "abc", str(31 * 24 * 3600)):
        with pytest.raises(ConfigurationError):
            load_api_settings({**good, api_settings.SESSION_TTL_VAR: raw})
    assert "fb_session" == SESSION_COOKIE_NAME and api_settings.SESSION_COOKIE_SAMESITE == "strict"


def test_the_email_adapters_hold_the_line():
    with pytest.raises(SecretError):
        CapturingEmailDelivery(Environment.PRODUCTION)
    message = OutboundEmail(kind="email_verification", recipient="x@example.com", secret=Secret("fbv_" + "a" * 43))
    assert "fbv_" not in repr(message) and "<redacted>" in repr(message)
    with pytest.raises(SecretError):
        OutboundEmail(kind="newsletter", recipient="x@example.com")
    with pytest.raises(SecretError):
        OutboundEmail(kind="email_verification", recipient="x@example.com", secret="fbv_" + "a" * 43)  # type: ignore[arg-type]
    with pytest.raises(EmailDeliveryUnavailable) as exc:
        UnavailableEmailDelivery().deliver(message)
    assert "fbv_" not in str(exc.value) and "no email delivery adapter is configured" in str(exc.value)
    capture = CapturingEmailDelivery(Environment.TEST)
    capture.deliver(message)
    assert capture.last("email_verification", "x@example.com") is message
    assert capture.last("account_recovery") is None
    assert "fbv_" not in repr(capture)
