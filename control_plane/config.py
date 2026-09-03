"""The configuration boundary for the Firmbatch v1 control plane.

Three rules this module exists to enforce, all of them fail-closed:

1. **The environment is chosen explicitly.** ``FIRMBATCH_ENV`` must be ``test`` or
   ``production``. There is no default. A process that has not said which environment it
   is running in does not get a database.

2. **No production credential and no usable production default lives in this
   repository.** Every URL comes from the environment. Nothing in this file, and nothing
   any test may add to it, may carry a host, a role, or a password that would connect to
   anything real. ``tests/test_configuration.py`` asserts this by scanning the package.

3. **Complete database URLs are never logged.** Everything that renders a URL for a
   human goes through :func:`redact_database_url`, and the settings objects render
   themselves the same way, so an accidental ``print(settings)`` or a traceback repr
   cannot spill a password.

Application access and migration/admin access are separate URLs on purpose. The
application connects as a restricted, non-owner role that cannot bypass row-level
security; migrations connect as the schema owner. Keeping them in one variable would
make the privilege split a convention rather than a configuration fact.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, replace
from enum import Enum
from typing import Mapping
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from sqlalchemy import URL

# --------------------------------------------------------------------------- names

ENVIRONMENT_VAR = "FIRMBATCH_ENV"
APPLICATION_URL_VAR = "FIRMBATCH_DATABASE_URL"
MIGRATION_URL_VAR = "FIRMBATCH_MIGRATION_DATABASE_URL"
TEST_ADMIN_URL_VAR = "FIRMBATCH_TEST_DATABASE_URL"

#: The only driver v1 speaks. PostgreSQL is the single metadata authority; there is no
#: SQLite fallback, so a URL naming any other backend is a configuration error rather
#: than a degraded mode.
DRIVER = "postgresql+psycopg"
_ACCEPTED_SCHEMES = ("postgresql+psycopg", "postgresql", "postgres")

#: A disposable test database is one this repository created and may therefore destroy.
#: The random suffix is what makes the name unmistakable: no human types this, and no
#: real database can collide with it by accident.
DISPOSABLE_DATABASE_PATTERN = re.compile(r"^firmbatch_test_[0-9a-f]{12}$")
#: app = restricted application role; prov = tenant provisioning; own = the per-run
#: database owner, which is also the migration principal and the deletion authority.
DISPOSABLE_ROLE_PATTERN = re.compile(r"^firmbatch_test_(?:app|prov|own)_[0-9a-f]{12}$")

#: Databases an admin test URL is allowed to point at. It is a *maintenance* connection,
#: used only to CREATE and DROP the disposable database and its roles; no Firmbatch table
#: is ever created here.
#:
#: This is the single allowlist. Configuration validation, the live ``current_database()``
#: check after connecting, the bootstrap and the teardown all consult it, so there is no
#: second opinion about what counts as a maintenance connection. An existing
#: ``firmbatch_test_<hex>`` database is deliberately **not** acceptable: it is a target the
#: bootstrap creates, never a place it connects from to create others.
ADMIN_MAINTENANCE_DATABASES = frozenset({"postgres", "template1", "template0"})

# --------------------------------------------------------------------- query parameters
#
# libpq takes connection parameters from the query string as well as from the URL, and
# they WIN. `postgresql://u@/postgres?dbname=customer_prod` passes any check that reads
# the URL path and then connects to `customer_prod`. The same trick redirects the server
# (`host`, `hostaddr`, `port`), the role (`user`), the whole connection definition
# (`service`, `servicefile`), and the session itself (`options=-c role=...`, which
# preselects a role, or `-c search_path=...`, which unpins the schema).
#
# libpq will also *fill in* whatever the URL omits, from PGUSER, PGHOST, PGPORT,
# PGDATABASE and friends -- so an omitted field is not a neutral default, it is an
# environment-supplied one that no amount of URL inspection can see. And a single URL can
# name several hosts (`h1:5432,h2:5433`, or a comma-separated `host=` list), in which case
# libpq picks one at connect time and may pick a different one on the next attempt.
#
# The answer to all of that is a CANONICAL SPECIFICATION: every field is required and
# explicit, exactly one endpoint is permitted, and the connection is then rebuilt from the
# parsed spec rather than from the string the caller supplied. What is validated and what
# is opened are the same thing by construction.
#
# The surviving query parameters are an ALLOWLIST. libpq gains parameters over time and a
# denylist would silently stop covering them; anything not named here is refused.
ALLOWED_QUERY_KEYS = frozenset(
    {
        "sslmode",
        "sslrootcert",
        "sslcert",
        "sslkey",
        "sslnegotiation",
        "connect_timeout",
        "application_name",
        "target_session_attrs",
    }
)

#: Endpoint keys the unix-socket form carries in the query, because there is no netloc to
#: put them in. Both are required together and neither may repeat.
SOCKET_ENDPOINT_KEYS = frozenset({"host", "port"})

#: Named individually so the error can say *why*, rather than "not allowed".
_ROUTING_OVERRIDE_REASONS = {
    "dbname": "redirects the connection to a different database than the URL path names",
    "database": "redirects the connection to a different database than the URL path names",
    "hostaddr": "redirects the connection to a different server",
    "user": "authenticates as a different role than the URL names",
    "service": "loads an entire connection definition from a service file",
    "servicefile": "loads an entire connection definition from a service file",
    "options": (
        "sets startup parameters, which can preselect a role, change search_path, or set "
        "the tenant context before any application code runs"
    ),
    "passfile": "loads credentials from a file outside this configuration boundary",
}

#: Anything that looks like a host list. libpq splits on commas; a percent-encoded comma
#: decodes to one before it gets there, so the check is on the decoded value.
_HOST_LIST = ","

#: Characters that must never appear in a **decoded** authority host. A comma would make
#: it a libpq host list; a slash or backslash would make it a socket directory, which may
#: only be reached through the canonical socket form; whitespace and the rest are not
#: legal in a hostname at all and would smuggle a second parameter past this check.
_FORBIDDEN_IN_HOST = frozenset(",/\\ \t\r\n\x00'\"?#@=&%:")

#: One DNS label: letters, digits and hyphens, not starting or ending with a hyphen.
#: A trailing dot (the absolute-root form) is accepted and stripped before matching.
_DNS_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

_PORT_RANGE = range(1, 65536)

# ------------------------------------------------------------- the ambient libpq environment
#
# An explicit URL does NOT neutralise the environment. libpq consults its own variables
# for every parameter the connection string leaves unset, and two of them override even a
# field that IS set:
#
#   PGHOSTADDR  supplies the IP to connect to. With a host name still used for
#               authentication and certificate checks, it silently sends the connection
#               to a different server than the URL names. Verified against a real server.
#   PGOPTIONS   is appended to the startup packet. `-c role=...` preselects a role,
#               `-c search_path=...` unpins the schema, and `-c app.tenant_id=...` would
#               seed the isolation context before a single line of application code runs.
#               Verified: PGOPTIONS='-c search_path=pg_temp,public' reached the server
#               through a fully explicit URL.
#
# The rest -- PGHOST, PGPORT, PGUSER, PGDATABASE, PGSERVICE, PGSERVICEFILE -- fill in
# omitted fields. `parse_connection_url` requires all of those explicitly, so they should
# have nothing to supply; they are still refused, because "should have nothing to supply"
# is an argument and a refusal is a fact.
#
# TLS and target-session variables are refused too. They are *optional* in a ConnectionSpec
# (they live in ALLOWED_QUERY_KEYS), so an unset `sslmode` really would be taken from
# PGSSLMODE -- an ambient downgrade from `verify-full` to `prefer` is invisible and total.
# PGTARGETSESSIONATTRS can send a connection to a read-only standby.
#
# **The response is to fail closed, never to mutate the environment.** Unsetting a
# variable around a connect() would race every other thread in the process, and the window
# is exactly where the connection happens.
#: Reasons for the variables an operator is most likely to have set, so the refusal can
#: say *what it would have done* rather than only that it was not allowed. This is a
#: message table, **not** the policy: the policy is the allowlist below, so a libpq
#: variable that does not appear here is still refused.
LIBPQ_ENVIRONMENT_REASONS = {
    "PGHOST": "supplies the server host",
    "PGHOSTADDR": "supplies the server IP and overrides the host in the URL",
    "PGPORT": "supplies the server port",
    "PGDATABASE": "supplies the database name",
    "PGUSER": "supplies the role the connection authenticates as",
    "PGSERVICE": "loads an entire connection definition from a service file",
    "PGSERVICEFILE": "chooses the service file a connection definition is loaded from",
    "PGSYSCONFDIR": "chooses the directory the system-wide service file is read from",
    "PGOPTIONS": (
        "is appended to the startup packet, so it can preselect a role, unpin search_path, "
        "or set the tenant context before any application code runs"
    ),
    "PGCLIENTENCODING": "changes the session's client encoding, which is session state",
    "PGSSLMODE": "decides whether the connection is encrypted or verified at all",
    "PGSSLNEGOTIATION": "decides how TLS is negotiated",
    "PGSSLCERTMODE": "decides whether a client certificate is sent, which is an identity",
    "PGSSLSNI": "decides whether the server name is sent, which routing front ends act on",
    "PGSSLMINPROTOCOLVERSION": "lowers the minimum acceptable TLS version",
    "PGSSLMAXPROTOCOLVERSION": "caps the TLS version that may be negotiated",
    "PGSSLROOTCERT": "chooses which authority the server certificate is checked against",
    "PGSSLCERT": "supplies the client certificate, which can be an identity",
    "PGSSLKEY": "supplies the client key, which can be an identity",
    "PGSSLCRL": "chooses the certificate revocation list",
    "PGSSLCRLDIR": "chooses the certificate revocation list directory",
    "PGREQUIRESSL": "is the legacy TLS switch",
    "PGGSSENCMODE": "decides whether GSSAPI encryption is used",
    "PGGSSDELEGATION": "forwards the client's Kerberos credentials to the server",
    "PGGSSLIB": "chooses the GSSAPI library",
    "PGKRBSRVNAME": "chooses the Kerberos service name, which is an identity",
    "PGCHANNELBINDING": "decides whether channel binding is required",
    "PGTARGETSESSIONATTRS": "can send the connection to a read-only standby",
    "PGLOADBALANCEHOSTS": "reorders a host list, which this configuration does not permit",
    "PGCONNECT_TIMEOUT": "changes connection timing outside this configuration boundary",
    "PGAPPNAME": "sets application_name, which is session state the server can act on",
}

#: **The policy is an allowlist, and everything else beginning with ``PG`` is refused.**
#:
#: A denylist was the first attempt and it was wrong in the way denylists are always
#: wrong: libpq gains variables between releases, and the ones it gained were exactly the
#: TLS and session controls that matter -- ``PGSSLMINPROTOCOLVERSION``, ``PGSSLCERTMODE``,
#: ``PGSSLSNI``, ``PGGSSDELEGATION``, ``PGCLIENTENCODING``. A list that has to be kept
#: current in order to be correct is a list that is silently incorrect between updates.
#:
#: So the question is inverted: a ``PG*`` variable is refused unless it has been shown it
#: cannot alter the connection's identity, endpoint, TLS policy, startup behaviour or
#: session state. Three have:
#:
#: ``PGPASSWORD``, ``PGPASSFILE``
#:     Credential-only. Both are consulted *after* user, host, port and database are
#:     fixed -- a passfile entry is keyed on exactly those four -- so neither can move a
#:     connection or change who it authenticates as. They can only decide whether
#:     authentication succeeds. A deployment must be able to keep the password out of the
#:     URL, and doing so must not be what breaks this check.
#:
#: ``PGDATA``
#:     Read by the *server* and by ``initdb``/``pg_ctl``. libpq never consults it, so it
#:     cannot affect a client connection at all. Allowed because a developer machine
#:     running a local cluster almost always has it exported, and refusing it would cost
#:     a real failure with no security value.
#:
#: Anything else -- including a variable that does not exist yet -- is refused, and the
#: fix is to unset it rather than to widen this set.
ALLOWED_LIBPQ_ENVIRONMENT = frozenset({"PGPASSWORD", "PGPASSFILE", "PGDATA"})

#: Kept as an alias: "the credential-only mechanisms" is the part of the allowlist that is
#: about libpq rather than about the server, and it is what the documentation refers to.
ALLOWED_CREDENTIAL_ENVIRONMENT = frozenset({"PGPASSWORD", "PGPASSFILE"})

#: What counts as a candidate. Every libpq environment variable is ``PG``-prefixed.
_LIBPQ_ENVIRONMENT_PREFIX = "PG"

#: Databases that may never be dropped, whatever else validates.
PROTECTED_DATABASES = frozenset({"postgres", "template0", "template1"})

# --------------------------------------------------------------------------- attestation
#
# A URL ending in `/postgres` is not evidence that a server is disposable -- every
# PostgreSQL cluster in the world has that database, production included. The test
# helpers therefore require a **server-side marker** that somebody had to create on
# purpose: a NOLOGIN role carrying an exact comment.
#
# It is checked before any CREATE ROLE / CREATE DATABASE and again before any DROP. It
# costs one catalogue query, works identically for a non-superuser local role and for the
# superuser in a CI service container, and cannot appear by accident.
#
#   CREATE ROLE firmbatch_disposable_test_cluster NOLOGIN;
#   COMMENT ON ROLE firmbatch_disposable_test_cluster IS 'firmbatch-disposable-test-cluster';
#
# or: python3 -m firmbatch.control_plane.testing.attestation --mark
DISPOSABLE_CLUSTER_MARKER_ROLE = "firmbatch_disposable_test_cluster"
DISPOSABLE_CLUSTER_MARKER_COMMENT = "firmbatch-disposable-test-cluster"

_SECRET_QUERY_KEYS = frozenset({"password", "passwd", "pwd", "sslpassword", "passfile"})


class ConfigurationError(RuntimeError):
    """Raised when configuration is missing, ambiguous, or unsafe. Never suppressed."""


class UnsafeTestDatabaseError(ConfigurationError):
    """Raised when a test helper is pointed at a database it may not create or destroy."""


class DisposableClusterAttestationError(UnsafeTestDatabaseError):
    """Raised when a server carries no disposable-cluster marker. Never bypassed."""


class PrivilegedPrincipalError(ConfigurationError):
    """Raised when an application connection authenticates as a privileged role."""


def scrub_secrets(message: str, secrets: "tuple[str, ...] | list[str]") -> str:
    """Replace generated secrets with ``***`` anywhere they appear in ``message``.

    Applied to every exception raised out of role provisioning. psycopg echoes the failing
    statement, and a ``CREATE ROLE ... PASSWORD '...'`` that fails would otherwise put a
    live password into a CI log, where it is retained for as long as the run is.
    """
    for secret in secrets:
        if secret:
            message = message.replace(secret, "***")
    return message


class Environment(str, Enum):
    TEST = "test"
    PRODUCTION = "production"


# --------------------------------------------------------------------------- redaction


def redact_database_url(url: str) -> str:
    """Render a database URL with every secret removed.

    Used by every log line, exception message, and ``repr`` in this package. The result
    keeps scheme, user, host, port and database name -- enough to tell two environments
    apart -- and drops the password and any secret-bearing query parameter.
    """
    if not url:
        return "<unset>"
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparseable database url>"

    if parts.password:
        userinfo = f"{parts.username or ''}:***@"
    elif parts.username:
        userinfo = f"{parts.username}@"
    else:
        userinfo = ""

    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"

    query = urlencode(
        [(k, "***" if k.lower() in _SECRET_QUERY_KEYS else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    )
    return urlunsplit((parts.scheme, f"{userinfo}{host}", parts.path, query, ""))


def database_name(url: str) -> str:
    """The database a URL points at, or ``""`` when the URL names none."""
    try:
        return urlsplit(url).path.lstrip("/")
    except ValueError:
        return ""


# --------------------------------------------------------------------------- validation


@dataclass(frozen=True)
class ConnectionSpec:
    """One fully explicit connection: who, where, and which database. Nothing implied.

    Built by :func:`parse_connection_url` and used everywhere afterwards -- validation,
    engine creation, database swapping, fingerprinting, and the expected-user check --
    so that the thing inspected and the thing opened cannot drift apart.
    """

    username: str
    password: str | None
    database: str
    #: A hostname/IP for TCP, or an absolute socket directory for a unix socket.
    host: str
    port: int
    is_socket: bool
    #: The surviving safe parameters, ordered and deduplicated.
    options: tuple[tuple[str, str], ...] = ()

    @property
    def endpoint(self) -> tuple[str, int]:
        return (self.host, self.port)

    def with_database(self, database: str) -> "ConnectionSpec":
        """The same identity and endpoint, pointed at another database."""
        return replace(self, database=database)

    def url(self) -> str:
        """Render canonically: every field explicit, nothing left for libpq to infer."""
        query = dict(self.options)
        if self.is_socket:
            # No netloc host is possible for a socket, so the endpoint travels in the
            # query -- but as the *only* host and port, both validated above.
            query["host"] = self.host
            query["port"] = str(self.port)
            url = URL.create(
                DRIVER,
                username=self.username,
                password=self.password,
                database=self.database,
                query=query,
            )
        else:
            url = URL.create(
                DRIVER,
                username=self.username,
                password=self.password,
                host=self.host,
                port=self.port,
                database=self.database,
                query=query,
            )
        return url.render_as_string(hide_password=False)

    def redacted(self) -> str:
        return redact_database_url(self.url())

    def __repr__(self) -> str:  # pragma: no cover - exercised through str()
        return f"ConnectionSpec({self.redacted()!r})"

    __str__ = __repr__


def require_clean_libpq_environment(
    env: "Mapping[str, str] | None" = None, *, context: str = "opening a database connection"
) -> None:
    """Raise unless the process environment can no longer influence a connection.

    Called immediately before **every** connection this package opens -- from the
    ``do_connect`` dialect event, so it runs after the engine has decided to connect and
    before libpq has read anything.

    Fail-closed, and deliberately not "fix it up": temporarily unsetting these variables
    around a connect would race every other thread in the process, and the race window is
    precisely the moment the connection is made. A dirty environment is a configuration
    error the operator resolves, not something this library papers over.

    **An allowlist, not a denylist.** Every ``PG``-prefixed variable is refused unless it
    appears in :data:`ALLOWED_LIBPQ_ENVIRONMENT`. libpq gains variables between releases
    and the ones it gained were precisely the TLS and session controls that matter, so a
    denylist would be silently incomplete for as long as it took somebody to notice.
    """
    env = os.environ if env is None else env
    offenders = sorted(
        name
        for name, value in env.items()
        if name.startswith(_LIBPQ_ENVIRONMENT_PREFIX)
        and value
        and name not in ALLOWED_LIBPQ_ENVIRONMENT
    )
    if not offenders:
        return
    detail = "; ".join(
        f"{name} {LIBPQ_ENVIRONMENT_REASONS.get(name, 'is a PG* variable this policy does not recognise')}"
        for name in offenders
    )
    raise ConfigurationError(
        f"refusing to connect while {context}: the environment sets {offenders}, which libpq "
        f"consults for every connection ({detail}). An explicit URL does not neutralise these -- "
        "PGHOSTADDR overrides the host that was validated, and PGOPTIONS reaches the server's "
        "startup packet. Unset them in the process that opens Firmbatch connections. "
        f"Only {sorted(ALLOWED_LIBPQ_ENVIRONMENT)} are permitted: the first two are credential-only "
        "and cannot change identity or routing, and the third is read by the server rather than "
        "by libpq. An unrecognised PG* variable is refused rather than assumed harmless."
    )


#: A percent escape: exactly ``%`` followed by two hex digits. Anything else in a value
#: that is about to be decoded is malformed, and ``unquote`` would silently pass it
#: through rather than complain.
_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _decode_user_info(value: str | None, *, field: str, variable: str) -> str | None:
    """Percent-decode a username or password **exactly once**.

    ``urlsplit`` does not decode user information -- it hands back the raw text between
    the scheme and the ``@``. So a password written ``p%40ss`` in a URL arrived at psycopg
    as the literal seven characters ``p%40ss`` and authentication failed with a password
    that was in fact correct. Every reserved character has the same problem, and a
    password containing ``@`` or ``:`` *has* to be encoded to be expressible at all.

    Decoding happens once, here, and :meth:`ConnectionSpec.url` hands the decoded value to
    ``URL.create``, which re-encodes it canonically. Decoding twice would be its own bug:
    a password legitimately containing ``%40`` would silently become ``@``.

    Malformed escapes are refused rather than passed through. ``unquote`` leaves ``%ZZ``
    alone, so without this check a typo in a URL becomes a password that is wrong in a way
    nothing reports.

    The decoded value is never placed in the error text: this function is used for the
    password too, and an exception is exactly where a secret would otherwise surface.
    """
    if value is None:
        return None
    if _PERCENT_ESCAPE.search(value):
        raise ConfigurationError(
            f"{variable} has a malformed percent escape in its {field}. Every '%' must introduce "
            "two hexadecimal digits; write a literal percent sign as '%25'."
        )
    try:
        return unquote(value, errors="strict")
    except UnicodeDecodeError:
        raise ConfigurationError(
            f"{variable} has a {field} whose percent escapes do not decode as UTF-8."
        ) from None


def _require_authority_host(raw_host: str, variable: str) -> str:
    """Validate a TCP host by its **decoded** semantics, not by the text in the URL.

    ``urlsplit`` does not percent-decode the host, so ``h1%2Ch2`` survives a raw check for
    commas and ``%2Fvar%2Frun%2Fpostgresql`` survives a raw check for slashes. Whether
    those decode before libpq sees them is a property of whichever URL library sits in
    between -- today SQLAlchemy passes the host through undecoded, which is luck rather
    than a guarantee, and it is the wrong thing to be relying on.

    So the decoded form is what gets validated, and it must be one of exactly three
    shapes: an IPv4 address, an IPv6 address (which arrives here already unbracketed),
    or a DNS name. A host list, a socket path, and anything carrying a delimiter are all
    outside that grammar and are refused by construction.
    """
    host = unquote(raw_host)
    if host != raw_host:
        raise ConfigurationError(
            f"{variable} percent-encodes its host ({raw_host!r} decodes to {host!r}). A host name "
            "has no legitimate need for percent-encoding, and an encoded delimiter can turn one "
            "endpoint into a libpq host list or a unix-socket path once it is decoded."
        )

    if not host:
        raise ConfigurationError(f"{variable} has an empty host")

    # IPv6 arrives unbracketed from urlsplit; accept it before the delimiter check, since
    # a literal address legitimately contains colons.
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    bad = sorted(set(host) & _FORBIDDEN_IN_HOST)
    if bad:
        raise ConfigurationError(
            f"{variable} has host {host!r}, which contains {bad}. Exactly one endpoint is "
            "required: a comma makes it a libpq host list, and a slash makes it a unix-socket "
            "directory, which may only be given in the canonical socket form (host=/dir&port=N)."
        )

    labels = host.rstrip(".").split(".")
    if not all(_DNS_LABEL.match(label) for label in labels):
        raise ConfigurationError(
            f"{variable} has host {host!r}, which is neither an IP address nor a valid DNS name."
        )
    return host


def _require_socket_directory(raw_host: str, variable: str) -> str:
    """Validate the canonical socket form, again on the decoded value."""
    host = unquote(raw_host)
    if _HOST_LIST in host:
        raise ConfigurationError(
            f"{variable} names more than one socket directory (host={host!r}). "
            "Exactly one endpoint is required."
        )
    if not host.startswith("/"):
        raise ConfigurationError(
            f"{variable} has host={host!r}, which must be an absolute unix-socket "
            "directory path; name a TCP host in the URL authority instead."
        )
    for character in ("\x00", "\n", "\r"):
        if character in host:
            raise ConfigurationError(f"{variable} has a socket directory containing a control character")
    return host


def _decoded_query(parts, variable: str) -> dict[str, str]:
    """Decode the query, rejecting duplicates. Comparison is on the decoded, folded key."""
    seen: dict[str, str] = {}
    for raw_key, value in parse_qsl(parts.query, keep_blank_values=True):
        key = raw_key.strip().lower()
        if key in seen:
            raise ConfigurationError(
                f"{variable} repeats the connection parameter {raw_key!r}. libpq takes the last "
                "occurrence, so a repeated parameter means the URL says two different things."
            )
        seen[key] = value
    return seen


def _require_port(value, variable: str, source: str) -> int:
    try:
        port = int(str(value))
    except (TypeError, ValueError):
        raise ConfigurationError(
            f"{variable} has a non-numeric {source} port {value!r}; one explicit numeric port is required"
        ) from None
    if port not in _PORT_RANGE:
        raise ConfigurationError(f"{variable} has an out-of-range {source} port {port}")
    return port


def parse_connection_url(url: str, *, variable: str) -> ConnectionSpec:
    """Parse and validate a URL into a canonical :class:`ConnectionSpec`, or raise.

    Every identity and endpoint field must be present and singular. An omitted field is
    not a default -- libpq fills it from ``PGUSER``/``PGHOST``/``PGPORT``/``PGDATABASE``,
    which means the environment, not this configuration, would decide where the connection
    goes and who it goes as.
    """
    if not url or not url.strip():
        raise ConfigurationError(f"{variable} is not set")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise ConfigurationError(f"{variable} is not a parseable URL: {exc}") from None

    if parts.scheme not in _ACCEPTED_SCHEMES:
        raise ConfigurationError(
            f"{variable} must be a PostgreSQL URL ({DRIVER}); got scheme {parts.scheme!r}. "
            "PostgreSQL is the only v1 metadata authority and there is no fallback backend."
        )

    query = _decoded_query(parts, variable)

    # --- forbidden parameters -------------------------------------------------------
    problems = []
    for key in sorted(query):
        if key in _ROUTING_OVERRIDE_REASONS:
            problems.append(f"{key!r} {_ROUTING_OVERRIDE_REASONS[key]}")
        elif key not in ALLOWED_QUERY_KEYS and key not in SOCKET_ENDPOINT_KEYS:
            problems.append(
                f"{key!r} is not an allowed connection parameter "
                f"(allowed: {sorted(ALLOWED_QUERY_KEYS)}, plus host/port for the socket form)"
            )
    if problems:
        raise ConfigurationError(
            f"{variable} carries connection parameters that override what the URL appears to say: "
            + "; ".join(problems)
            + ". libpq gives these precedence over the URL, so a check that read only the URL "
            "would be validating one connection and opening another."
        )

    # --- database -------------------------------------------------------------------
    # The path is not decoded by urlsplit either, and for the same reason it is decoded
    # once here rather than passed through.
    database = _decode_user_info(parts.path.lstrip("/"), field="database name", variable=variable) or ""
    if not database:
        raise ConfigurationError(
            f"{variable} names no database. The database must be in the URL path, where it can be "
            "validated, not left to a libpq default (PGDATABASE) to supply."
        )
    if "/" in database or _HOST_LIST in database:
        raise ConfigurationError(f"{variable} names more than one database ({database!r})")

    # --- username and password ------------------------------------------------------
    # Decoded exactly once, here. urlsplit hands back the raw text; URL.create re-encodes
    # it. Doing neither meant an encoded password reached psycopg still encoded.
    try:
        raw_username, raw_password = parts.username, parts.password
    except ValueError as exc:  # pragma: no cover - malformed percent-encoding
        raise ConfigurationError(f"{variable} has unparseable user information: {exc}") from None
    username = _decode_user_info(raw_username, field="username", variable=variable)
    password = _decode_user_info(raw_password, field="password", variable=variable)
    if not username:
        raise ConfigurationError(
            f"{variable} names no username. It must be explicit: an omitted user is supplied by "
            "PGUSER or by the operating-system account, neither of which this configuration controls."
        )
    if _HOST_LIST in username:
        raise ConfigurationError(f"{variable} names more than one username ({username!r})")

    # --- endpoint: exactly one, either TCP or socket, never both --------------------
    socket_host = query.get("host")
    socket_port = query.get("port")

    # The authority is inspected as raw text FIRST. `urlsplit(...).port` raises on a host
    # list before any of our own checks can run, which would report a confusing parse
    # error instead of the real problem.
    authority = parts.netloc.rsplit("@", 1)[-1]
    if _HOST_LIST in authority:
        raise ConfigurationError(
            f"{variable} names more than one host in its authority ({authority!r}). libpq would "
            "choose one at connect time and might choose a different one next time; exactly one "
            "endpoint is required."
        )

    try:
        netloc_host = parts.hostname
        netloc_port = parts.port
    except ValueError as exc:
        raise ConfigurationError(f"{variable} has an unparseable host or port: {exc}") from None

    if socket_host is not None and (netloc_host or netloc_port is not None):
        raise ConfigurationError(
            f"{variable} names an endpoint twice: {authority!r} in the authority and "
            f"host={socket_host!r} in the query. Use one or the other."
        )

    if socket_host is not None:
        socket_host = _require_socket_directory(socket_host, variable)
        if socket_port is None:
            raise ConfigurationError(
                f"{variable} gives a socket directory but no port. Add an explicit port "
                f"(&port=5432); otherwise PGPORT decides."
            )
        port = _require_port(socket_port, variable, "socket")
        host, is_socket = socket_host, True
    else:
        if socket_port is not None:
            raise ConfigurationError(
                f"{variable} gives port={socket_port!r} in the query but no socket directory. "
                "For a TCP connection the port belongs in the URL authority."
            )
        if not netloc_host:
            raise ConfigurationError(
                f"{variable} names no host. It must be explicit: an omitted host is supplied by "
                "PGHOST or defaults to a local socket, neither of which this configuration controls."
            )
        if netloc_port is None:
            raise ConfigurationError(
                f"{variable} names no port. It must be explicit: an omitted port is supplied by "
                "PGPORT or defaults to 5432, neither of which this configuration controls."
            )
        port = _require_port(netloc_port, variable, "authority")
        host, is_socket = _require_authority_host(netloc_host, variable), False

    options = tuple(sorted((k, v) for k, v in query.items() if k in ALLOWED_QUERY_KEYS))
    spec = ConnectionSpec(
        username=username,
        password=password,
        database=database,
        host=host,
        port=port,
        is_socket=is_socket,
        options=options,
    )
    _require_single_endpoint_round_trip(spec, variable)
    return spec


def _require_single_endpoint_round_trip(spec: ConnectionSpec, variable: str) -> None:
    """Re-parse the URL this spec renders and confirm it still says the same thing.

    Everything above validates the URL the *caller* supplied. This validates the URL that
    will actually be handed to SQLAlchemy and on to libpq -- the last representation
    change before the connection is made, and therefore the last place an endpoint could
    become two.

    It closes the gap between "we checked a string" and "the driver received one
    endpoint": rendering escapes, and a value that survived validation as one thing can
    be re-read as another. Cheap, and it is the only check here whose failure would mean
    the *rendering* is wrong rather than the input.
    """
    from sqlalchemy import make_url  # local: keeps the URL grammar above import-light

    rendered = spec.url()
    try:
        back = make_url(rendered)
    except Exception as exc:  # pragma: no cover - would mean URL.create emitted garbage
        raise ConfigurationError(
            f"{variable} could not be re-parsed after normalisation: {type(exc).__name__}: {exc}"
        ) from None

    query = {k.lower(): v for k, v in back.query.items()}
    if spec.is_socket:
        observed_host, observed_port = query.get("host"), query.get("port")
        observed_port = int(observed_port) if observed_port is not None else None
    else:
        observed_host, observed_port = back.host, back.port

    mismatches = [
        (label, expected, observed)
        for label, expected, observed in (
            ("username", spec.username, back.username),
            ("database", spec.database, back.database),
            ("host", spec.host, observed_host),
            ("port", spec.port, observed_port),
        )
        if expected != observed
    ]
    if mismatches:
        raise ConfigurationError(
            f"{variable} does not survive normalisation unchanged: "
            + "; ".join(f"{label} was {e!r}, re-parses as {o!r}" for label, e, o in mismatches)
            + ". The connection that would open is not the one that was validated."
        )

    for field, value in (("host", observed_host), ("username", back.username), ("database", back.database)):
        if value is not None and _HOST_LIST in str(value):
            raise ConfigurationError(
                f"{variable} normalises to a {field} containing a comma ({value!r}); libpq would "
                "read that as a list and this configuration permits exactly one endpoint."
            )


def require_postgresql_url(url: str, *, variable: str) -> str:
    """Return a canonical, fully explicit URL, or raise.

    The returned string is rebuilt from the parsed specification rather than passed
    through, so the connection that opens is the one that was validated.
    """
    return parse_connection_url(url, variable=variable).url()


def require_disposable_database(url: str) -> str:
    """Raise unless ``url`` names a database this repository created and may destroy.

    Every test helper that creates, migrates, connects to, or drops a database calls
    this first. It is the single reason a mistyped ``FIRMBATCH_TEST_DATABASE_URL``
    cannot take a real database with it.
    """
    name = database_name(url)
    if not DISPOSABLE_DATABASE_PATTERN.match(name):
        raise UnsafeTestDatabaseError(
            f"refusing to operate on database {name!r} ({redact_database_url(url)}): "
            f"test helpers only touch databases matching {DISPOSABLE_DATABASE_PATTERN.pattern}, "
            "which only this repository's bootstrap creates."
        )
    return name


def require_disposable_role(role: str) -> str:
    """Raise unless ``role`` is one of the throwaway roles the bootstrap created."""
    if not DISPOSABLE_ROLE_PATTERN.match(role):
        raise UnsafeTestDatabaseError(
            f"refusing to operate on role {role!r}: test helpers only touch roles matching "
            f"{DISPOSABLE_ROLE_PATTERN.pattern}."
        )
    return role


def require_maintenance_database_name(name: str, *, context: str) -> str:
    """The one place that decides whether a database name is a maintenance database.

    Used by configuration validation, by the live ``current_database()`` check after a
    connection opens, and by teardown. A disposable ``firmbatch_test_<hex>`` database is
    deliberately not acceptable here: it is something the bootstrap creates, never
    somewhere it connects from in order to create or drop others.
    """
    if name in ADMIN_MAINTENANCE_DATABASES:
        return name
    raise UnsafeTestDatabaseError(
        f"{context}: database {name!r} is not a maintenance database. "
        f"Expected one of {sorted(ADMIN_MAINTENANCE_DATABASES)}."
    )


def require_admin_maintenance_url(url: str) -> str:
    """Validate the admin URL the test bootstrap connects to.

    It must be a maintenance connection. Pointing it at a real application database would
    let ``CREATE DATABASE`` run from inside something that matters, and pointing it at a
    disposable database would let one throwaway database create and drop others.
    """
    url = require_postgresql_url(url, variable=TEST_ADMIN_URL_VAR)
    name = database_name(url)
    try:
        require_maintenance_database_name(name, context=f"{TEST_ADMIN_URL_VAR} ({redact_database_url(url)})")
    except UnsafeTestDatabaseError as exc:
        raise UnsafeTestDatabaseError(
            f"{exc} The bootstrap creates its own disposable database from a maintenance connection."
        ) from None
    return url


# --------------------------------------------------------------------------- settings


# Three settings types, three loaders, and **no combined one**.
#
# There used to be a single ``Settings`` carrying both the runtime URL and the migration
# URL, loaded by a single ``load_settings()``. Two things were wrong with that, and the
# second is the serious one:
#
# 1. An application process could not start without a migration URL in its environment,
#    because the combined loader required both. That is backwards -- the runtime is the
#    one deployment that must never be given owner credentials.
# 2. Any process that called it *received* the privileged URL whether it wanted one or
#    not. A credential that reaches a process is a credential that can leak from it: into
#    a traceback, a repr, a crash dump, a log line. The cheapest way not to leak the owner
#    password from the API server is for the API server never to have been told it.
#
# So the three audiences are separated by type, and each loader reads only its own
# variable. There is deliberately no wrapper that loads both -- a compatibility shim would
# reintroduce exactly the coupling this removes, quietly.
#
#   ApplicationSettings     the restricted runtime role. Loaded by the API, the
#                           controller, the validator. Reads FIRMBATCH_DATABASE_URL only.
#   MigrationSettings       the owner role. Loaded by the migration entry point only.
#                           Reads FIRMBATCH_MIGRATION_DATABASE_URL only.
#   TestBootstrapSettings   the disposable-cluster administrator. Loaded by test tooling
#                           only. Reads FIRMBATCH_TEST_DATABASE_URL only.
#
# ``scripts/check-runtime-imports.py --static`` enforces the module boundary that goes
# with this: runtime modules may not import the migration or test-bootstrap settings.


@dataclass(frozen=True)
class ApplicationSettings:
    """What the runtime service is allowed to know: one restricted URL, and nothing else.

    It has no attribute holding a migration, owner, provisioning, bootstrap or admin URL,
    and no loader that would fill one in. That is the point rather than an omission: this
    object is what a compromised or merely careless runtime process has access to.

    The ``repr`` does not render the URL at all -- not even redacted. Everything else in
    this package redacts and keeps the host, because knowing which environment you are
    looking at is worth something in a traceback; here it is not worth the risk of a
    rendering path that is one refactor away from including the password again.
    """

    environment: Environment
    application_url: str

    @property
    def is_test(self) -> bool:
        return self.environment is Environment.TEST

    def __repr__(self) -> str:  # pragma: no cover - exercised through str()
        return (
            f"ApplicationSettings(environment={self.environment.value!r}, "
            f"application_url={'<set>' if self.application_url else '<unset>'})"
        )

    __str__ = __repr__


@dataclass(frozen=True)
class MigrationSettings:
    """What the migration entry point needs. Loaded by migration code, and nowhere else."""

    environment: Environment
    migration_url: str

    def __repr__(self) -> str:  # pragma: no cover - exercised through str()
        return (
            f"MigrationSettings(environment={self.environment.value!r}, "
            f"migration_url={redact_database_url(self.migration_url)!r})"
        )

    __str__ = __repr__


@dataclass(frozen=True)
class TestBootstrapSettings:
    """The disposable-cluster administrator. Confined to test and bootstrap tooling.

    Only loadable with ``FIRMBATCH_ENV=test``: this credential creates and drops databases
    and roles, and there is no circumstance in which a production process should hold it.
    """

    environment: Environment
    admin_url: str

    def __repr__(self) -> str:  # pragma: no cover - exercised through str()
        return (
            f"TestBootstrapSettings(environment={self.environment.value!r}, "
            f"admin_url={redact_database_url(self.admin_url)!r})"
        )

    __str__ = __repr__


def load_environment(env: Mapping[str, str]) -> Environment:
    """Read ``FIRMBATCH_ENV``. There is deliberately no default."""
    raw = (env.get(ENVIRONMENT_VAR) or "").strip()
    if not raw:
        raise ConfigurationError(
            f"{ENVIRONMENT_VAR} is not set. Set it explicitly to one of "
            f"{[e.value for e in Environment]}; there is no default environment."
        )
    try:
        return Environment(raw)
    except ValueError:
        raise ConfigurationError(
            f"{ENVIRONMENT_VAR}={raw!r} is not a known environment; expected one of {[e.value for e in Environment]}"
        ) from None


def load_application_settings(env: Mapping[str, str]) -> ApplicationSettings:
    """The runtime configuration, and only the runtime configuration.

    Reads ``FIRMBATCH_ENV`` and ``FIRMBATCH_DATABASE_URL``. It does not read
    ``FIRMBATCH_MIGRATION_DATABASE_URL`` or ``FIRMBATCH_TEST_DATABASE_URL``, does not
    require them to be set, and does not retain them if they are.
    """
    return ApplicationSettings(
        environment=load_environment(env),
        application_url=require_postgresql_url(
            env.get(APPLICATION_URL_VAR, ""), variable=APPLICATION_URL_VAR
        ),
    )


def load_migration_settings(env: Mapping[str, str]) -> MigrationSettings:
    """The migration configuration. Loaded by ``migrate.py``, and nowhere else."""
    return MigrationSettings(
        environment=load_environment(env),
        migration_url=require_postgresql_url(
            env.get(MIGRATION_URL_VAR, ""), variable=MIGRATION_URL_VAR
        ),
    )


def load_test_bootstrap_settings(env: Mapping[str, str]) -> TestBootstrapSettings:
    """The disposable-cluster administrator. Loaded by test tooling, and nowhere else.

    Raises when the URL is absent. It never returns a default and it never signals "skip":
    a verification run without a test PostgreSQL server must FAIL, because a silently
    skipped isolation suite is indistinguishable from a passing one.
    """
    environment = load_environment(env)
    if environment is not Environment.TEST:
        raise UnsafeTestDatabaseError(
            f"test helpers require {ENVIRONMENT_VAR}={Environment.TEST.value!r}; got {environment.value!r}"
        )
    raw = (env.get(TEST_ADMIN_URL_VAR) or "").strip()
    if not raw:
        raise ConfigurationError(
            f"{TEST_ADMIN_URL_VAR} is not set. The PostgreSQL foundation suite runs against a real "
            "PostgreSQL 16 server and has no in-memory or SQLite substitute; it fails rather than "
            "skips so an absent database cannot look like a passing gate. Set it to a maintenance "
            f"connection, e.g. {DRIVER}://USER@HOST:5432/postgres"
        )
    return TestBootstrapSettings(environment=environment, admin_url=require_admin_maintenance_url(raw))


def load_migration_url(env: Mapping[str, str]) -> str:
    """The migration URL alone. A thin accessor over :func:`load_migration_settings`.

    Not a compatibility wrapper over a combined loader -- there is no combined loader. It
    reads one variable, the migration one, and is used where a bare URL is what the caller
    actually needs.
    """
    return load_migration_settings(env).migration_url


def load_test_admin_url(env: Mapping[str, str]) -> str:
    """The disposable-cluster admin URL alone, over :func:`load_test_bootstrap_settings`."""
    return load_test_bootstrap_settings(env).admin_url
