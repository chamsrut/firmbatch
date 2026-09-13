"""The Milestone 3.2 HTTP surface, driven end to end against PostgreSQL 16.

This is the other half of the portal's coverage. ``portal/tests`` drives the real client, the
real components and the real cookie reads against a fake transport; this drives the **real
API** and holds it to the shapes that client depends on. Neither proves the system alone.

Three groups, and each exists because the property cannot be checked from the browser side:

* **the CSRF cookie** -- its attributes, its ``__Host-`` prefix, when it is set and cleared,
  and that the header is verified against the session's stored fingerprint rather than
  against the cookie;
* **the new routes** -- preferences, consent and the password change, including the statuses
  a client branches on;
* **the customer boundary** -- the complete route inventory, asserted to contain no supplier,
  operator, capacity, settlement or internal surface at all.
"""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import text
from starlette.testclient import TestClient

from firmbatch.control_plane.api.app import create_app
from firmbatch.control_plane.api.consent import CONSENT_DOCUMENTS, CURRENT_CONSENT_VERSION
from firmbatch.control_plane.api.email import CapturingEmailDelivery
from firmbatch.control_plane.api.settings import (
    CSRF_COOKIE_BASE_NAME,
    CSRF_COOKIE_HOST_PREFIX,
    MAX_BODY_BYTES,
    SESSION_COOKIE_NAME,
    ApiSettings,
    csrf_cookie_name,
)
from firmbatch.control_plane.config import Environment
from firmbatch.control_plane.db.models import CONSENT_VERSIONS, SCHEMA
from firmbatch.control_plane.tests.identity_helpers import PASSWORD, key, unique_email

ORIGIN = "http://portal.test"


@pytest.fixture()
def api(application_engine, authenticator_engine):
    """The portal's arrangement: **one origin** for the page and the API.

    Milestone 3.2 serves the portal same-origin with the API behind a proxy, so the browser's
    own cookie rules do the isolation: a host-only cookie belongs to exactly one host, and the
    ``__Host-`` prefix forbids a ``Domain`` attribute outright, which a two-subdomain
    arrangement could not satisfy.
    """
    email = CapturingEmailDelivery(Environment.TEST)
    settings = ApiSettings(
        environment=Environment.TEST,
        allowed_origins=(ORIGIN,),
        cookie_secure=False,
        session_ttl=__import__("datetime").timedelta(hours=1),
    )
    app = create_app(
        settings=settings, engine=application_engine, email=email, authenticator_engine=authenticator_engine
    )
    with TestClient(app, base_url=ORIGIN, raise_server_exceptions=False) as client:
        yield type("Api", (), {"client": client, "email": email, "settings": settings})()


class Browser:
    """One signed-in browser. Cookies are sent by the client's jar, as a browser would.

    ``workspace`` is the workspace the browser's *page* is showing: every mutation carries it
    as ``X-Workspace-Id``, the expected-workspace contract, unless a test overrides it per
    call (``workspace=...``) to play a stale page, a forged identifier or a missing header.
    """

    def __init__(self, api, csrf: str, email: str, workspace: str | None = None):
        self.api = api
        self.csrf = csrf
        self.email = email
        self.workspace = workspace

    def headers(
        self, *, mutation: bool, csrf: str | None | bool = True, workspace: str | None | bool = True
    ) -> dict:
        headers = {}
        if mutation:
            headers["origin"] = ORIGIN
            token = self.csrf if csrf is True else csrf
            if token:
                headers["x-csrf-token"] = token
            expected = self.workspace if workspace is True else workspace
            if expected:
                headers["x-workspace-id"] = expected
        return headers

    def get(self, path: str):
        return self.api.client.get(path)

    def send(self, method: str, path: str, body=None, *, idempotency_key=None, **kw):
        headers = self.headers(mutation=True, **kw)
        if idempotency_key is not None:
            headers["idempotency-key"] = idempotency_key
        return self.api.client.request(method, path, json=body, headers=headers)


def register(api) -> str:
    email = unique_email("portal")
    assert api.client.post("/v1/account/signup", json={"email": email, "password": PASSWORD}).status_code == 202
    message = api.email.last("email_verification", email)
    assert message is not None and message.secret is not None
    assert (
        api.client.post(
            "/v1/account/verification/complete", json={"token": message.secret.reveal()}
        ).status_code
        == 200
    )
    return email


def sign_in(api, email: str, password: str = PASSWORD) -> Browser:
    response = api.client.post(
        "/v1/account/login", json={"email": email, "password": password}, headers={"origin": ORIGIN}
    )
    assert response.status_code == 200, response.text
    return Browser(api, csrf=response.json()["csrf_token"], email=email)


def with_workspace(api) -> tuple[Browser, str]:
    browser = sign_in(api, register(api))
    created = browser.send(
        "POST", "/v1/account/workspaces", {"slug": f"ws-{uuid.uuid4().hex[:8]}", "name": "Acme"},
        idempotency_key=key("ws"),
    )
    assert created.status_code == 201, created.text
    workspace_id = created.json()["workspace_id"]
    bound = browser.send("PUT", "/v1/account/workspace", {"workspace_id": workspace_id})
    assert bound.status_code == 200, bound.text
    browser.workspace = workspace_id
    return browser, workspace_id


def set_cookie_headers(response) -> list[str]:
    return response.headers.get_list("set-cookie")


def cookie_directive(headers: list[str], name: str) -> str | None:
    for header in headers:
        if header.startswith(f"{name}="):
            return header
    return None


# --------------------------------------------------------------------------- the CSRF cookie


def test_login_sets_both_cookies_with_the_attributes_the_design_names(api):
    email = register(api)
    response = api.client.post(
        "/v1/account/login", json={"email": email, "password": PASSWORD}, headers={"origin": ORIGIN}
    )
    headers = set_cookie_headers(response)

    session = cookie_directive(headers, SESSION_COOKIE_NAME)
    assert session is not None
    # The credential. HttpOnly, so no script reads it.
    assert "httponly" in session.lower()
    assert "samesite=strict" in session.lower()
    assert "path=/" in session.lower()
    assert "domain=" not in session.lower()

    csrf = cookie_directive(headers, csrf_cookie_name(secure=False))
    assert csrf is not None
    # NOT the credential, and readable on purpose: the portal has to put its value in the
    # X-CSRF-Token header, and PostgreSQL verifies *that* against the stored fingerprint.
    assert "httponly" not in csrf.lower()
    assert "samesite=strict" in csrf.lower()
    assert "path=/" in csrf.lower()
    assert "domain=" not in csrf.lower()
    # It carries the session's own lifetime.
    assert "max-age=3600" in csrf.lower()
    # And it is the very secret the response body handed over.
    assert response.json()["csrf_token"] in csrf


def test_the_host_prefix_appears_exactly_when_the_cookie_is_secure():
    """A browser rejects a ``__Host-`` cookie that is not Secure, Path=/ and Domain-less.

    So the prefix is a property of the deployment rather than a second configuration knob,
    and the test environment -- which is permitted an insecure cookie for a plain-http local
    client -- must use the unprefixed name or the browser would drop it.
    """
    assert csrf_cookie_name(secure=True) == f"{CSRF_COOKIE_HOST_PREFIX}{CSRF_COOKIE_BASE_NAME}"
    assert csrf_cookie_name(secure=False) == CSRF_COOKIE_BASE_NAME

    secure = ApiSettings(
        environment=Environment.PRODUCTION,
        allowed_origins=("https://app.firmbatch.com",),
        cookie_secure=True,
        session_ttl=__import__("datetime").timedelta(hours=1),
    )
    assert secure.csrf_cookie == "__Host-fb_csrf"


def test_the_cookie_survives_a_reload_and_is_shared_by_a_second_tab(api):
    """The gap Milestone 3.1 left, closed.

    The CSRF secret is minted once and stored only as a fingerprint, so a portal that kept it
    in memory would lose it on every reload and could then read but never write -- with no
    route able to re-issue it. The cookie is what makes a reloaded tab, and a second tab, able
    to mutate without re-authenticating or rotating anything.
    """
    browser, workspace = with_workspace(api)
    first = api.client.cookies.get(csrf_cookie_name(secure=False))
    assert first is not None

    # A "reload" is a new page that reads the cookie jar. Nothing is re-issued.
    reloaded = api.client.cookies.get(csrf_cookie_name(secure=False))
    assert reloaded == first
    # A mutation from the reloaded page works, using the cookie's value and nothing else.
    assert browser.send("PATCH", "/v1/workspace", {"name": "Renamed"}, idempotency_key=key("rn")).status_code == 200
    # And a second tab, reading the same jar, works too -- no rotation, so neither tab breaks.
    assert Browser(api, csrf=first, email=browser.email, workspace=workspace).send(
        "PATCH", "/v1/workspace", {"name": "Renamed twice"}, idempotency_key=key("rn")
    ).status_code == 200
    assert api.client.cookies.get(csrf_cookie_name(secure=False)) == first


def test_logout_clears_both_cookies(api):
    browser = sign_in(api, register(api))
    response = browser.send("POST", "/v1/account/logout")
    assert response.status_code == 204
    headers = set_cookie_headers(response)
    for name in (SESSION_COOKIE_NAME, csrf_cookie_name(secure=False)):
        directive = cookie_directive(headers, name)
        assert directive is not None, name
        # Cleared the way a cookie is cleared: an empty value with an expiry in the past.
        assert 'expires=Thu, 01 Jan 1970' in directive or "max-age=0" in directive.lower(), directive


def test_the_header_is_verified_against_the_fingerprint_and_not_against_the_cookie(api):
    """**Cookie/header equality is insufficient, and is not what is checked.**

    A double-submit check that only proved "these two values match" would be satisfied by any
    value a caller could set on both sides. Here the header is compared inside PostgreSQL
    against ``browser_sessions.csrf_fingerprint``, so a caller must produce the session's
    *actual* secret. This sets both the cookie and the header to the same wrong value and the
    mutation is still refused.
    """
    browser, _workspace = with_workspace(api)
    forged = "fbc_" + "a" * 43
    api.client.cookies.set(csrf_cookie_name(secure=False), forged)
    response = browser.send("PATCH", "/v1/workspace", {"name": "Nope"}, csrf=forged, idempotency_key=key("rn"))
    assert response.status_code == 401
    assert response.json() == {"error": "authentication_required"}


def test_another_session_s_csrf_secret_is_refused(api):
    first, _workspace = with_workspace(api)
    second_email = register(api)
    second = sign_in(api, second_email)
    # The second login replaced the jar's cookies; re-sign the first browser to restore them.
    first = sign_in(api, first.email)
    response = first.send("POST", "/v1/account/logout", csrf=second.csrf)
    assert response.status_code == 401


def test_a_mutation_with_no_csrf_header_is_refused_even_with_a_valid_cookie(api):
    browser = sign_in(api, register(api))
    assert browser.send("POST", "/v1/account/logout", csrf=None).status_code == 403


def test_a_mutation_from_an_unlisted_origin_is_refused(api):
    browser = sign_in(api, register(api))
    response = api.client.post(
        "/v1/account/logout",
        headers={"origin": "http://evil.test", "x-csrf-token": browser.csrf},
    )
    assert response.status_code == 403
    assert response.json() == {"error": "origin_not_allowed"}


# --------------------------------------------------------------------------- preferences


def test_preferences_round_trip_through_the_api(api):
    browser, workspace_id = with_workspace(api)

    initial = browser.get("/v1/workspace/preferences")
    assert initial.status_code == 200
    body = initial.json()
    assert body["region_policy"] == []
    assert body["evaluation_intent"] == "undecided"
    assert body["consent_version"] is None
    assert body["current_consent_version"] == CURRENT_CONSENT_VERSION
    assert body["workspace_id"] == workspace_id

    stated = browser.send(
        "PUT",
        "/v1/workspace/preferences",
        {
            "workspace_id": workspace_id,
            "region_policy": ["EU"],
            "excluded_provider_classes": ["amazon"],
            "model_profile_note": "Qwen3-8B on vllm-fp8",
            "evaluation_intent": "planning_evaluation",
        },
    )
    assert stated.status_code == 200, stated.text
    assert stated.json()["region_policy"] == ["EU"]
    assert stated.json()["unservable_exclusion"] is True

    assert browser.get("/v1/workspace/preferences").json()["model_profile_note"] == "Qwen3-8B on vllm-fp8"


def test_a_preferences_write_needs_no_idempotency_key(api):
    """A full replacement is idempotent by construction, so a key would prove nothing."""
    browser, workspace_id = with_workspace(api)
    response = browser.send(
        "PUT", "/v1/workspace/preferences", {"workspace_id": workspace_id, "evaluation_intent": "undecided"}
    )
    assert response.status_code == 200


# --------------------------------------------------------------------------- the expected workspace
#
# Independent Milestone 3.2 review, finding 1. Every preference mutation names the workspace
# the page loaded its form for, and the database refuses the write unless it is the workspace
# the session is bound to at that moment.


@pytest.mark.parametrize(
    "body",
    (
        {"evaluation_intent": "undecided"},
        {"workspace_id": None, "evaluation_intent": "undecided"},
        {"workspace_id": "not-a-uuid", "evaluation_intent": "undecided"},
        {"workspace_id": 42, "evaluation_intent": "undecided"},
    ),
)
def test_a_preference_mutation_without_a_well_formed_expected_workspace_is_422(api, body):
    """Absent or malformed is a malformed request, never defaulted to the bound workspace --
    defaulting would skip exactly the comparison the field exists for."""
    browser, workspace_id = with_workspace(api)
    assert browser.send("PUT", "/v1/workspace/preferences", body).status_code == 422
    consent = {**body, "consent_version": CURRENT_CONSENT_VERSION}
    consent.pop("evaluation_intent")
    assert browser.send("POST", "/v1/workspace/preferences/consent", consent).status_code == 422
    assert browser.get("/v1/workspace/preferences").json()["workspace_id"] == workspace_id


def test_a_forged_or_another_tenant_s_expected_workspace_is_one_neutral_409(api):
    """A stale page, a forged identifier and another tenant's identifier: one answer."""
    browser, workspace_id = with_workspace(api)
    _other_browser, other_workspace = with_workspace(api)
    # The second sign-in replaced the jar's cookies; sign the first browser back in, which
    # is a new session, and select its workspace again.
    browser = sign_in(api, browser.email)
    assert browser.send("PUT", "/v1/account/workspace", {"workspace_id": workspace_id}).status_code == 200
    browser.workspace = workspace_id
    answers = set()
    for expected in (str(uuid.uuid4()), other_workspace):
        for method, path, body in (
            ("PUT", "/v1/workspace/preferences", {"workspace_id": expected, "region_policy": ["EU"], "evaluation_intent": "undecided"}),
            ("POST", "/v1/workspace/preferences/consent", {"workspace_id": expected, "consent_version": CURRENT_CONSENT_VERSION}),
        ):
            # The body's expectation and the header's, each wrong on its own.
            response = browser.send(method, path, body)
            answers.add((response.status_code, response.text))
            response = browser.send(method, path, {**body, "workspace_id": workspace_id}, workspace=expected)
            answers.add((response.status_code, response.text))
    assert answers == {(409, '{"error":"workspace_mismatch"}')}
    # And the bound workspace is untouched.
    current = browser.get("/v1/workspace/preferences").json()
    assert current["workspace_id"] == workspace_id
    assert current["region_policy"] == [] and current["consent_version"] is None


def test_a_form_loaded_for_one_workspace_is_refused_after_another_tab_switches(api):
    """The stale-form case, end to end: two tabs, one session, two workspaces."""
    browser, first = with_workspace(api)
    created = browser.send(
        "POST", "/v1/account/workspaces", {"slug": f"ws-{uuid.uuid4().hex[:8]}", "name": "Beta"},
        idempotency_key=key("ws2"),
    )
    assert created.status_code == 201, created.text
    second = created.json()["workspace_id"]
    # Tab one loads its form for the first workspace and saves it.
    assert browser.send(
        "PUT", "/v1/workspace/preferences",
        {"workspace_id": first, "region_policy": ["EU"], "model_profile_note": "A's form", "evaluation_intent": "undecided"},
    ).status_code == 200

    # Tab two switches the shared session to the second workspace.
    assert browser.send("PUT", "/v1/account/workspace", {"workspace_id": second}).status_code == 200

    # Tab one saves its stale form. Refused, and neither workspace changed.
    stale = browser.send(
        "PUT", "/v1/workspace/preferences",
        {"workspace_id": first, "region_policy": [], "model_profile_note": "edited on A", "evaluation_intent": "undecided"},
    )
    assert stale.status_code == 409 and stale.json() == {"error": "workspace_mismatch"}
    acknowledged = browser.send(
        "POST", "/v1/workspace/preferences/consent", {"workspace_id": first, "consent_version": CURRENT_CONSENT_VERSION}
    )
    assert acknowledged.status_code == 409 and acknowledged.json() == {"error": "workspace_mismatch"}
    now_bound = browser.get("/v1/workspace/preferences").json()
    assert now_bound["workspace_id"] == second
    assert now_bound["model_profile_note"] is None and now_bound["consent_version"] is None

    # A save that names the workspace the session is now bound to lands there, and nowhere else.
    saved = browser.send(
        "PUT", "/v1/workspace/preferences",
        {"workspace_id": second, "model_profile_note": "B's form", "evaluation_intent": "undecided"},
        workspace=second,
    )
    assert saved.status_code == 200 and saved.json()["model_profile_note"] == "B's form"
    assert browser.send("PUT", "/v1/account/workspace", {"workspace_id": first}).status_code == 200
    back = browser.get("/v1/workspace/preferences").json()
    assert back["workspace_id"] == first and back["model_profile_note"] == "A's form" and back["region_policy"] == ["EU"]


def test_a_login_whose_password_was_replaced_while_argon2_ran_is_401(api, monkeypatch):
    """The neutral mapping for the login side of the overlap the lock order serialises.

    ``open_browser_session`` refuses under the account row lock when the epoch moved -- a
    change or a recovery committed while the password was being verified. That refusal is
    rendered as the answer a wrong password gets, because the old password *is* wrong now,
    and never as the boundary's generic ``404``.
    """
    from firmbatch.control_plane.api import app as api_module
    from firmbatch.control_plane.db import accounts

    email = register(api)

    def refused(session, *, ttl):
        raise accounts.IdentityRefused(accounts.IDENTITY_REFUSED_MESSAGE)

    monkeypatch.setattr(api_module.accounts, "open_session", refused)
    response = api.client.post(
        "/v1/account/login", json={"email": email, "password": PASSWORD}, headers={"origin": ORIGIN}
    )
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_credentials"}
    assert not set_cookie_headers(response)


@pytest.mark.parametrize(
    "body",
    (
        {"region_policy": ["US"], "evaluation_intent": "undecided"},
        {"excluded_provider_classes": ["oracle"], "evaluation_intent": "undecided"},
        {"evaluation_intent": "whenever"},
        {"evaluation_intent": "undecided", "model_profile_note": "x" * 300},
        {"evaluation_intent": "undecided", "region_policy": "EU"},
    ),
)
def test_a_value_outside_the_vocabulary_is_422_and_names_no_value(api, body):
    browser, workspace_id = with_workspace(api)
    response = browser.send("PUT", "/v1/workspace/preferences", {"workspace_id": workspace_id, **body})
    assert response.status_code == 422
    # One field, and never the value that was refused.
    assert response.json() == {"error": "invalid_request"}


def test_consent_is_served_publicly_and_acknowledged_privately(api):
    # Readable with no account at all: somebody deciding whether to sign up is entitled to
    # read what they would be agreeing to.
    public = api.client.get("/v1/consent")
    assert public.status_code == 200
    document = public.json()
    assert document["version"] == CURRENT_CONSENT_VERSION
    assert document["versions"] == sorted(CONSENT_DOCUMENTS)

    browser, workspace_id = with_workspace(api)
    acknowledged = browser.send(
        "POST",
        "/v1/workspace/preferences/consent",
        {"workspace_id": workspace_id, "consent_version": document["version"]},
    )
    assert acknowledged.status_code == 200
    body = acknowledged.json()
    assert body["consent_version"] == document["version"]
    assert body["consent_acknowledged_at"] is not None
    assert body["consent_account_id"] is not None


def test_the_consent_text_states_the_rule_the_register_requires(api):
    """Register item D8: the customer-facing consent text "must match the rule"."""
    document = api.client.get("/v1/consent").json()
    prose = " ".join(
        paragraph for section in document["sections"] for paragraph in section["body"]
    ).lower()
    # `provider_policy` governs execution placement only ...
    assert "execution placement only" in prose
    assert "every retry" in prose and "hedge" in prose
    # ... the payload plane is S3 ...
    assert "amazon s3" in prose
    # ... and a customer who excludes Amazon altogether cannot be served in v1.
    assert "cannot be served" in prose
    # It grants no view of supplier capacity, pool identities, spend or settlement.
    assert "no view of" in prose
    # And it says what acknowledging does not create.
    assert "does not create a job" in prose


def test_an_unknown_consent_version_is_absent_rather_than_an_error(api):
    assert api.client.get("/v1/consent?version=made-up").status_code == 404
    assert CONSENT_VERSIONS == tuple(CONSENT_DOCUMENTS)


def test_acknowledging_an_unpublished_version_is_refused(api):
    browser, workspace_id = with_workspace(api)
    response = browser.send(
        "POST",
        "/v1/workspace/preferences/consent",
        {"workspace_id": workspace_id, "consent_version": "made-up-v9"},
    )
    assert response.status_code == 422


def test_preferences_need_a_selected_workspace(api):
    browser = sign_in(api, register(api))
    assert browser.get("/v1/workspace/preferences").status_code == 412


# --------------------------------------------------------------------------- password change


def test_the_password_change_replaces_the_session_and_sets_both_cookies(api):
    email = register(api)
    browser = sign_in(api, email)
    before = api.client.cookies.get(csrf_cookie_name(secure=False))

    response = browser.send(
        "POST",
        "/v1/account/password",
        {"current_password": PASSWORD, "new_password": "a replacement passphrase 12"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["other_sessions_revoked"] is True
    headers = set_cookie_headers(response)
    assert cookie_directive(headers, SESSION_COOKIE_NAME) is not None
    assert cookie_directive(headers, csrf_cookie_name(secure=False)) is not None

    after = api.client.cookies.get(csrf_cookie_name(secure=False))
    assert after != before
    assert after == body["csrf_token"]
    # The page carries on: a mutation on the replacement session works immediately.
    assert Browser(api, csrf=after, email=email).send("POST", "/v1/account/logout").status_code == 204


def test_a_wrong_current_password_is_401_and_names_no_field(api):
    browser = sign_in(api, register(api))
    response = browser.send(
        "POST",
        "/v1/account/password",
        {"current_password": "not it at all", "new_password": "a replacement passphrase 12"},
    )
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_credentials"}


def test_the_password_change_requires_csrf_and_an_allowed_origin(api):
    browser = sign_in(api, register(api))
    body = {"current_password": PASSWORD, "new_password": "a replacement passphrase 12"}
    assert browser.send("POST", "/v1/account/password", body, csrf=None).status_code == 403
    assert api.client.post(
        "/v1/account/password",
        json=body,
        headers={"origin": "http://evil.test", "x-csrf-token": browser.csrf},
    ).status_code == 403


def test_the_password_change_is_refused_without_a_session(api):
    response = api.client.post(
        "/v1/account/password",
        json={"current_password": PASSWORD, "new_password": "x" * 20},
        headers={"origin": ORIGIN, "x-csrf-token": "fbc_" + "a" * 43},
    )
    assert response.status_code == 401


def test_the_password_change_refuses_a_bearer_token_at_the_browser_boundary(api):
    browser, _workspace = with_workspace(api)
    issued = browser.send(
        "POST",
        "/v1/workspace/credentials",
        {"scopes": ["workspace:read"], "label": "test"},
        idempotency_key=key("iss"),
    )
    assert issued.status_code == 201
    secret = issued.json()["credential"]
    # An API credential presented where a session belongs: refused before either is read.
    response = api.client.post(
        "/v1/account/password",
        json={"current_password": PASSWORD, "new_password": "a replacement passphrase 12"},
        headers={"origin": ORIGIN, "x-csrf-token": browser.csrf, "authorization": f"Bearer {secret}"},
    )
    assert response.status_code == 401


def test_a_weak_new_password_is_refused_without_echoing_it(api):
    browser = sign_in(api, register(api))
    response = browser.send(
        "POST", "/v1/account/password", {"current_password": PASSWORD, "new_password": "short"}
    )
    assert response.status_code == 422
    assert response.json() == {"error": "invalid_request"}


# --------------------------------------------------------------------------- bounds


def test_an_oversized_body_is_refused_before_it_is_authenticated(api):
    """Read, then authenticate, then interpret. The size bound is the one thing that precedes
    the credential, because it is what stops an oversized body being buffered at all."""
    oversized = json.dumps({"model_profile_note": "x" * (MAX_BODY_BYTES + 1000)})
    response = api.client.request(
        "PUT",
        "/v1/workspace/preferences",
        content=oversized,
        headers={"origin": ORIGIN, "content-type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json() == {"error": "request_too_large"}


def test_a_malformed_body_on_a_protected_route_is_401_before_it_is_parsed(api):
    """An unauthenticated caller learns nothing about a route's body requirements."""
    response = api.client.request(
        "PUT",
        "/v1/workspace/preferences",
        content="{not json at all",
        headers={"origin": ORIGIN, "content-type": "application/json"},
    )
    assert response.status_code == 401
    assert response.json() == {"error": "authentication_required"}


def test_a_malformed_body_on_an_authenticated_route_is_400(api):
    browser, workspace = with_workspace(api)
    response = api.client.request(
        "PUT",
        "/v1/workspace/preferences",
        content="{not json at all",
        headers={
            "origin": ORIGIN,
            "content-type": "application/json",
            "x-csrf-token": browser.csrf,
            "x-workspace-id": workspace,
        },
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_json"}


def test_a_wrong_media_type_is_415_once_authenticated(api):
    browser, workspace = with_workspace(api)
    response = api.client.request(
        "PUT",
        "/v1/workspace/preferences",
        content="region_policy=EU",
        headers={
            "origin": ORIGIN,
            "content-type": "application/x-www-form-urlencoded",
            "x-csrf-token": browser.csrf,
            "x-workspace-id": workspace,
        },
    )
    assert response.status_code == 415


# --------------------------------------------------------------------------- the boundary


def test_the_route_inventory_is_customer_only(api):
    """Roadmap "Internal and supplier surfaces"; target §17 invariant 11.

    The complete list of paths this API serves, asserted to contain nothing that would reach
    supplier capacity, pool identities, bridge budgets, operator settlement, internal routing
    or certification administration -- and no operator surface of any kind. The operator
    capacity agent is separate operator-side software built in Phase P; it is not a customer
    feature and has no route here.
    """
    paths = sorted({route.path for route in api.client.app.routes})
    forbidden = (
        "supplier",
        "operator",
        "agent",
        "capacity",
        "pool",
        "bridge",
        "budget",
        "settlement",
        "window",
        "offer",
        "certification",
        "qualification",
        "reconcil",
        "provider",
        "spend",
        "internal",
        "admin",
    )
    for path in paths:
        for term in forbidden:
            assert term not in path.lower(), f"{path} names {term!r}"

    # Every path is under one of the three customer prefixes, and nothing else exists.
    for path in paths:
        assert path.startswith(("/v1/account", "/v1/workspace", "/v1/api", "/v1/health", "/v1/consent")), path


def test_the_milestone_3_2_routes_are_present_and_are_the_only_additions(api):
    paths = {(route.path, tuple(sorted(route.methods - {"HEAD"}))) for route in api.client.app.routes}
    added = {
        ("/v1/consent", ("GET",)),
        ("/v1/account/password", ("POST",)),
        ("/v1/workspace/preferences", ("GET",)),
        ("/v1/workspace/preferences", ("PUT",)),
        ("/v1/workspace/preferences/consent", ("POST",)),
    }
    assert added <= paths
    # Milestone 3.1 had thirty-two routes; 3.2 adds exactly these five and removes none.
    assert len(paths) == 32 + len(added)


def test_no_scope_this_api_can_issue_reaches_a_non_customer_domain():
    from firmbatch.control_plane.security.authorization import RESERVED_NON_CUSTOMER_DOMAINS
    from firmbatch.control_plane.security.permissions import API_ISSUABLE_SCOPES

    for scope in API_ISSUABLE_SCOPES:
        domain = scope.split(":", 1)[0]
        assert domain not in RESERVED_NON_CUSTOMER_DOMAINS, scope


def test_no_response_on_any_new_route_carries_a_secret(api):
    """Every Milestone 3.2 response, scanned for anything shaped like a secret."""
    from firmbatch.control_plane.security.secrets import looks_like_secret

    browser, workspace_id = with_workspace(api)
    responses = [
        api.client.get("/v1/consent"),
        browser.get("/v1/workspace/preferences"),
        browser.send(
            "PUT", "/v1/workspace/preferences", {"workspace_id": workspace_id, "evaluation_intent": "undecided"}
        ),
        browser.send(
            "POST",
            "/v1/workspace/preferences/consent",
            {"workspace_id": workspace_id, "consent_version": CURRENT_CONSENT_VERSION},
        ),
    ]
    for response in responses:
        assert response.status_code == 200, response.text
        rendered = response.text
        for prefix in ("fbs_", "fbc_", "fbk_", "fbv_", "fbr_", "fbi_", "$argon2id$"):
            assert prefix not in rendered, (response.request.url, prefix)
        assert looks_like_secret(rendered) is None or "fb" not in rendered


# --------------------------------------------------------------------------- the expected-workspace contract


def _audit_rows(owner_engine) -> int:
    """Every audit row, read by the owner with the forced policy lifted for the count only."""
    with owner_engine.connect() as connection:
        connection.execute(text(f"ALTER TABLE {SCHEMA}.audit_events NO FORCE ROW LEVEL SECURITY"))
        try:
            return int(connection.execute(text(f"SELECT count(*) FROM {SCHEMA}.audit_events")).scalar_one())
        finally:
            connection.execute(text(f"ALTER TABLE {SCHEMA}.audit_events FORCE ROW LEVEL SECURITY"))
            connection.commit()


def _workspace_mutations(workspace: str) -> list[tuple[str, str, dict | None, bool]]:
    """Every workspace-scoped mutation the portal makes: method, path, body, whether it is keyed.

    A target identifier that does not exist is deliberate: the expected-workspace comparison
    is made before any target is looked up, so a stale page is refused as a mismatch and not
    as a missing target -- and a missing target is what a stale page would usually name.
    """
    target = str(uuid.uuid4())
    return [
        ("PATCH", "/v1/workspace", {"name": "Renamed"}, True),
        ("POST", "/v1/workspace/invitations", {"email": "invitee@example.com", "role": "member"}, True),
        ("DELETE", f"/v1/workspace/invitations/{target}", None, False),
        ("PATCH", f"/v1/workspace/members/{target}", {"role": "viewer"}, False),
        ("DELETE", f"/v1/workspace/members/{target}", None, False),
        ("POST", "/v1/workspace/credentials", {"scopes": ["workspace:read"], "label": None, "expires_at": None}, True),
        ("POST", f"/v1/workspace/credentials/{target}/rotate", {"expires_at": None}, True),
        ("DELETE", f"/v1/workspace/credentials/{target}", None, False),
        (
            "PUT",
            "/v1/workspace/preferences",
            {"workspace_id": workspace, "region_policy": [], "evaluation_intent": "undecided"},
            False,
        ),
        (
            "POST",
            "/v1/workspace/preferences/consent",
            {"workspace_id": workspace, "consent_version": CURRENT_CONSENT_VERSION},
            False,
        ),
    ]


def _send(browser: Browser, method: str, path: str, body, keyed: bool, **kw):
    return browser.send(method, path, body, idempotency_key=key("wm") if keyed else None, **kw)


def _second_workspace(browser: Browser, name: str = "Beta") -> str:
    created = browser.send(
        "POST", "/v1/account/workspaces", {"slug": f"ws-{uuid.uuid4().hex[:8]}", "name": name},
        idempotency_key=key("ws2"),
    )
    assert created.status_code == 201, created.text
    return created.json()["workspace_id"]


def _snapshot(browser: Browser, workspace: str) -> dict:
    """What a workspace looks like from the outside: its name and its three lists."""
    assert browser.send("PUT", "/v1/account/workspace", {"workspace_id": workspace}).status_code == 200
    return {
        "name": browser.get("/v1/workspace").json()["name"],
        "members": [m["membership_id"] for m in browser.get("/v1/workspace/members").json()["members"]],
        "invitations": browser.get("/v1/workspace/invitations").json()["invitations"],
        "credentials": browser.get("/v1/workspace/credentials").json()["credentials"],
        "preferences": {
            k: v for k, v in browser.get("/v1/workspace/preferences").json().items() if k != "updated_at"
        },
    }


def test_every_workspace_mutation_requires_the_expected_workspace_header(api):
    """No header, or a malformed one, is the syntactic 422 -- after the session, never before."""
    browser, workspace = with_workspace(api)
    for method, path, body, keyed in _workspace_mutations(workspace):
        for absent in (None, "not-a-uuid", "  "):
            response = _send(browser, method, path, body, keyed, workspace=absent)
            assert (response.status_code, response.json()) == (422, {"error": "invalid_request"}), (method, path, absent)
    # And the header is read after the session: no session is 401, whatever the header says.
    api.client.cookies.clear()
    anonymous = Browser(api, csrf=browser.csrf, email=browser.email, workspace=None)
    response = anonymous.send("PATCH", "/v1/workspace", {"name": "x"}, idempotency_key=key("wm"))
    assert response.status_code == 401


def test_a_stale_page_s_mutation_is_refused_for_every_workspace_route_after_another_tab_switches(api, owner_engine):
    """Two tabs, one session, two workspaces: every action tab one takes for A after tab two
    switched the session to B is one neutral refusal, and neither workspace changed."""
    browser, first = with_workspace(api)
    second = _second_workspace(browser)
    before = {first: _snapshot(browser, first), second: _snapshot(browser, second)}
    # Tab two: the shared session is now bound to B.
    assert browser.send("PUT", "/v1/account/workspace", {"workspace_id": second}).status_code == 200
    audit_before = _audit_rows(owner_engine)

    # Tab one, still showing A, tries everything a page can do.
    for method, path, body, keyed in _workspace_mutations(first):
        response = _send(browser, method, path, body, keyed, workspace=first)
        assert (response.status_code, response.json()) == (409, {"error": "workspace_mismatch"}), (method, path)

    # Nothing was written to either workspace, and nothing was appended to the trail.
    assert _audit_rows(owner_engine) == audit_before
    after_second = _snapshot(browser, second)
    after_first = _snapshot(browser, first)
    assert after_first == before[first] and after_second == before[second]


def test_a_forged_or_another_tenant_s_expected_workspace_is_refused_on_every_workspace_route(api):
    """A forged identifier and another tenant's identifier get the same answer as a stale page,
    and a header naming the bound workspace lets the same requests through."""
    browser, workspace = with_workspace(api)
    _other, other_workspace = with_workspace(api)
    browser = sign_in(api, browser.email)
    assert browser.send("PUT", "/v1/account/workspace", {"workspace_id": workspace}).status_code == 200
    browser.workspace = workspace

    for expected in (str(uuid.uuid4()), other_workspace):
        for method, path, body, keyed in _workspace_mutations(workspace):
            response = _send(browser, method, path, body, keyed, workspace=expected)
            assert (response.status_code, response.json()) == (409, {"error": "workspace_mismatch"}), (method, path)

    # The right header: the rename lands, the invitation is created, the credential issued.
    assert browser.send("PATCH", "/v1/workspace", {"name": "Renamed"}, idempotency_key=key("rn")).status_code == 200
    assert browser.get("/v1/workspace").json()["name"] == "Renamed"
    invited = browser.send(
        "POST", "/v1/workspace/invitations", {"email": "invitee@example.com", "role": "member"},
        idempotency_key=key("inv"),
    )
    assert invited.status_code == 201, invited.text
    issued = browser.send(
        "POST", "/v1/workspace/credentials", {"scopes": ["workspace:read"], "label": None, "expires_at": None},
        idempotency_key=key("cred"),
    )
    assert issued.status_code == 201, issued.text
    # And the other tenant's workspace is exactly as it was: the identifier bought nothing.
    other = sign_in(api, _other.email)
    assert other.send("PUT", "/v1/account/workspace", {"workspace_id": other_workspace}).status_code == 200
    assert other.get("/v1/workspace").json()["name"] == "Acme"
    assert other.get("/v1/workspace/invitations").json()["invitations"] == []
    assert other.get("/v1/workspace/credentials").json()["credentials"] == []


def test_every_workspace_read_names_the_workspace_it_describes(api):
    """The envelope carries the authoritative workspace, so a portal can drop a late answer."""
    browser, first = with_workspace(api)
    issued = browser.send(
        "POST", "/v1/workspace/credentials", {"scopes": ["workspace:read"], "label": None, "expires_at": None},
        idempotency_key=key("cred"),
    )
    assert issued.status_code == 201, issued.text
    credential_id = issued.json()["credential_id"]
    second = _second_workspace(browser)

    def described(workspace: str) -> set:
        answers = set()
        for path in (
            "/v1/workspace",
            "/v1/workspace/members",
            "/v1/workspace/invitations",
            "/v1/workspace/credentials",
            "/v1/workspace/preferences",
        ):
            response = browser.get(path)
            assert response.status_code == 200, (path, response.text)
            answers.add(response.json()["workspace_id"])
        return answers

    assert described(first) == {first}
    history = browser.get(f"/v1/workspace/credentials/{credential_id}/history")
    assert history.status_code == 200 and history.json()["workspace_id"] == first
    assert browser.send("PUT", "/v1/account/workspace", {"workspace_id": second}).status_code == 200
    assert described(second) == {second}
    # The credential is A's; under B its history is not here, and says so neutrally.
    assert browser.get(f"/v1/workspace/credentials/{credential_id}/history").status_code == 404


def test_a_concurrent_switch_and_a_stale_mutation_never_apply_one_workspace_s_action_to_another(api):
    """The comparison is inside the mutation's own transaction, against that transaction's
    binding, under the workspace lock: whichever of a switch and a stale rename lands first,
    the rename either applies to the workspace it named or is refused. It never lands on
    the other one."""
    from concurrent.futures import ThreadPoolExecutor

    browser, first = with_workspace(api)
    second = _second_workspace(browser)
    outcomes = []
    for round_ in range(6):
        # Start each round bound to A, with the rename racing the switch to B.
        assert browser.send("PUT", "/v1/account/workspace", {"workspace_id": first}).status_code == 200
        name = f"Round {round_}"
        with ThreadPoolExecutor(max_workers=2) as pool:
            rename = pool.submit(
                browser.send, "PATCH", "/v1/workspace", {"name": name}, idempotency_key=key("rn"), workspace=first
            )
            switch = pool.submit(browser.send, "PUT", "/v1/account/workspace", {"workspace_id": second})
            renamed, switched = rename.result(), switch.result()
        assert switched.status_code == 200
        assert renamed.status_code in (200, 409), renamed.text
        outcomes.append(renamed.status_code)
        names = {w: _snapshot(browser, w)["name"] for w in (first, second)}
        # B is never renamed; A is renamed exactly when the rename succeeded.
        assert names[second] == "Beta"
        assert names[first] == (name if renamed.status_code == 200 else names[first])
        if renamed.status_code == 409:
            assert names[first] != name
    assert set(outcomes) <= {200, 409}
