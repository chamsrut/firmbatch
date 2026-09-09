"""The HTTP boundary's configuration: explicit, bounded, and fail-closed like ``config.py``.

Everything a request handler needs to know that is not the database: which browser
origins may call it with credentials, how the session cookie is attributed, and how long
sessions and tokens live. Read from the environment by :func:`load_api_settings`, with
**no production default that would weaken a control**: the origin allow-list must be
stated, the cookie is ``Secure`` unless the environment is ``test`` and says otherwise,
and a production process that asked for an insecure cookie or a wildcard origin does not
start.

The runtime database URL is not here. The API loads
:class:`~firmbatch.control_plane.config.ApplicationSettings` separately, which reads only
the application variable; this module cannot name a migration or bootstrap credential and
``scripts/check-runtime-imports.py`` will say so if it ever does.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Mapping
from urllib.parse import urlsplit

from ..config import ConfigurationError, Environment, load_environment

ALLOWED_ORIGINS_VAR = "FIRMBATCH_API_ALLOWED_ORIGINS"
COOKIE_SECURE_VAR = "FIRMBATCH_API_COOKIE_SECURE"
SESSION_TTL_VAR = "FIRMBATCH_API_SESSION_TTL_SECONDS"

#: The session cookie. Host-only (no ``Domain``), ``Path=/``, ``HttpOnly``, ``Secure``,
#: ``SameSite=Strict``. ``app.firmbatch.com`` and ``api.firmbatch.com`` are one *site*
#: (one registrable domain), so a credentialed ``fetch`` from the application to the API
#: carries the cookie under ``Strict``, and a request initiated by any other site does not.
SESSION_COOKIE_NAME = "fb_session"
SESSION_COOKIE_SAMESITE = "strict"

#: The header a cookie-authenticated mutation must carry, holding the CSRF secret the
#: login response handed to the client. Verified inside the database against the
#: session's own CSRF fingerprint; a request without it, or with another session's, is
#: refused before any handler runs.
CSRF_HEADER = "x-csrf-token"

#: The header a retry-safe mutation carries; parsed by the same rule as the Milestone 2.2
#: primitive's key.
IDEMPOTENCY_KEY_HEADER = "idempotency-key"

#: Request bodies are bounded before they are parsed. Every body this boundary accepts is
#: a small JSON object of identifiers, addresses and short strings.
MAX_BODY_BYTES = 16 * 1024

DEFAULT_SESSION_TTL = timedelta(hours=12)
MAX_SESSION_TTL = timedelta(days=30)

_ORIGIN = re.compile(r"^https?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?$")


@dataclass(frozen=True)
class ApiSettings:
    environment: Environment
    #: The exact origins that may call the API with browser credentials. Never ``*``.
    allowed_origins: tuple[str, ...]
    cookie_secure: bool
    session_ttl: timedelta

    @property
    def is_test(self) -> bool:
        return self.environment is Environment.TEST

    def __repr__(self) -> str:
        return (
            f"ApiSettings(environment={self.environment.value!r}, allowed_origins={list(self.allowed_origins)}, "
            f"cookie_secure={self.cookie_secure}, session_ttl={self.session_ttl})"
        )


def parse_allowed_origins(raw: str) -> tuple[str, ...]:
    """A comma-separated allow-list of exact origins. A wildcard is refused outright."""
    origins = []
    for item in (part.strip().lower() for part in raw.split(",")):
        if not item:
            continue
        if item == "*" or "*" in item:
            raise ConfigurationError(
                f"{ALLOWED_ORIGINS_VAR} contains a wildcard. Browser credentials are only ever shared "
                "with an explicit origin; a credentialed wildcard is refused by this boundary and by "
                "browsers alike."
            )
        if not _ORIGIN.match(item):
            raise ConfigurationError(
                f"{ALLOWED_ORIGINS_VAR} contains an entry that is not an origin (scheme://host[:port]). "
                "The value is deliberately not repeated."
            )
        parts = urlsplit(item)
        origins.append(f"{parts.scheme}://{parts.netloc}")
    if not origins:
        raise ConfigurationError(
            f"{ALLOWED_ORIGINS_VAR} is not set. The API shares browser credentials only with origins it "
            "was told about, so an empty allow-list means no browser may call it -- state the customer "
            "application's origin explicitly (for example https://app.firmbatch.com)."
        )
    return tuple(dict.fromkeys(origins))


def load_api_settings(env: Mapping[str, str]) -> ApiSettings:
    environment = load_environment(env)
    origins = parse_allowed_origins(env.get(ALLOWED_ORIGINS_VAR, ""))

    raw_secure = (env.get(COOKIE_SECURE_VAR) or "true").strip().lower()
    if raw_secure not in ("true", "false"):
        raise ConfigurationError(f"{COOKIE_SECURE_VAR} is 'true' or 'false'")
    cookie_secure = raw_secure == "true"
    if not cookie_secure and environment is not Environment.TEST:
        raise ConfigurationError(
            f"{COOKIE_SECURE_VAR}=false is permitted only with FIRMBATCH_ENV=test. A production session "
            "cookie is always Secure; there is no configuration that makes it otherwise."
        )
    if environment is not Environment.TEST and any(origin.startswith("http://") for origin in origins):
        raise ConfigurationError(
            f"{ALLOWED_ORIGINS_VAR} names an http:// origin outside the test environment. A session cookie "
            "is shared only with an https:// origin in production."
        )

    raw_ttl = (env.get(SESSION_TTL_VAR) or "").strip()
    session_ttl = DEFAULT_SESSION_TTL
    if raw_ttl:
        try:
            seconds = int(raw_ttl)
        except ValueError:
            raise ConfigurationError(f"{SESSION_TTL_VAR} is a whole number of seconds") from None
        session_ttl = timedelta(seconds=seconds)
        if session_ttl <= timedelta(0) or session_ttl > MAX_SESSION_TTL:
            raise ConfigurationError(
                f"{SESSION_TTL_VAR} is between 1 second and {int(MAX_SESSION_TTL.total_seconds())} seconds"
            )
    return ApiSettings(
        environment=environment,
        allowed_origins=origins,
        cookie_secure=cookie_secure,
        session_ttl=session_ttl,
    )
