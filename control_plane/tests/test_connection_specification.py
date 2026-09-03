"""One explicit identity and one explicit endpoint, or nothing (finding 1).

Two ways a URL can describe a connection other than the one it appears to describe, both
confirmed against a real server before these checks existed:

* **Omission.** libpq fills whatever the URL leaves out from ``PGUSER``, ``PGHOST``,
  ``PGPORT`` and ``PGDATABASE``. An omitted field is not a neutral default; it is an
  environment-supplied one that no URL inspection can see.
* **Multiplicity.** ``h1:5432,h2:5433``, or a comma-separated ``host=`` list, is a
  failover set. libpq picks one at connect time and may pick a different one next time,
  so "the endpoint that was validated" is not a well-defined thing.

The answer to both is a canonical :class:`~firmbatch.control_plane.config.ConnectionSpec`:
every field required and singular, and the connection rebuilt from the parsed spec rather
than from the caller's string.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, make_url, text

from firmbatch.control_plane import config

TCP = "postgresql+psycopg://app:secret@db.example:5432/firmbatch"
SOCKET = "postgresql+psycopg://chams@/postgres?host=/var/run/postgresql&port=5432"


# --------------------------------------------------------------- multiplicity


def test_two_authority_hosts_are_rejected():
    with pytest.raises(config.ConfigurationError) as exc:
        config.parse_connection_url("postgresql+psycopg://u@h1:5432,h2:5433/db", variable="X")
    assert "more than one host" in str(exc.value)


def test_comma_separated_socket_hosts_are_rejected():
    url = "postgresql+psycopg://u@/db?host=/var/run/postgresql,/tmp&port=5432"
    with pytest.raises(config.ConfigurationError) as exc:
        config.parse_connection_url(url, variable="X")
    assert "more than one socket directory" in str(exc.value)


def test_an_encoded_comma_is_still_a_host_list():
    """The check is on the decoded value; libpq decodes before it splits."""
    url = "postgresql+psycopg://u@/db?host=/var/run/postgresql%2C/tmp&port=5432"
    with pytest.raises(config.ConfigurationError) as exc:
        config.parse_connection_url(url, variable="X")
    assert "more than one socket directory" in str(exc.value)


def test_an_authority_and_a_query_endpoint_together_are_rejected():
    url = "postgresql+psycopg://u@h:5432/db?host=/var/run/postgresql&port=5432"
    with pytest.raises(config.ConfigurationError) as exc:
        config.parse_connection_url(url, variable="X")
    assert "names an endpoint twice" in str(exc.value)


# ------------------------------------------------------------------ omission


@pytest.mark.parametrize(
    ("label", "url", "expected"),
    [
        ("username", "postgresql+psycopg://h:5432/db", "names no username"),
        ("host", "postgresql+psycopg://u@/db", "names no host"),
        ("port", "postgresql+psycopg://u@h/db", "names no port"),
        ("database", "postgresql+psycopg://u@h:5432/", "names no database"),
        ("socket port", "postgresql+psycopg://u@/db?host=/tmp", "no port"),
    ],
)
def test_every_identity_and_endpoint_field_is_required(label, url, expected):
    with pytest.raises(config.ConfigurationError) as exc:
        config.parse_connection_url(url, variable="X")
    assert expected in str(exc.value), label


def test_the_environment_cannot_fill_an_omitted_field(monkeypatch):
    """PGUSER/PGHOST/PGPORT must have nothing left to supply.

    Set to values that would work if they were consulted, so the test would pass for the
    wrong reason if the URL were incomplete and merely happened to fail.
    """
    monkeypatch.setenv("PGUSER", "somebody-else")
    monkeypatch.setenv("PGHOST", "/var/run/postgresql")
    monkeypatch.setenv("PGPORT", "5432")
    monkeypatch.setenv("PGDATABASE", "template1")
    for url in (
        "postgresql+psycopg:///postgres",
        "postgresql+psycopg://@/postgres",
        "postgresql+psycopg://u@/postgres",
    ):
        with pytest.raises(config.ConfigurationError):
            config.parse_connection_url(url, variable="X")


def test_a_complete_url_ignores_the_environment(monkeypatch, disposable_database):
    """And the canonical form actually connects where it says, environment notwithstanding."""
    monkeypatch.setenv("PGUSER", "somebody-else")
    monkeypatch.setenv("PGDATABASE", "template1")
    monkeypatch.setenv("PGPORT", "1")

    spec = config.parse_connection_url(disposable_database.application_url, variable="X")
    engine = create_engine(spec.url(), future=True)
    try:
        with engine.connect() as connection:
            user, database = connection.execute(
                text("SELECT current_user, current_database()")
            ).one()
        assert user == disposable_database.application_role
        assert database == disposable_database.database
    finally:
        engine.dispose()


# ------------------------------------------------------------- canonical form


def test_the_specification_round_trips_both_endpoint_forms():
    tcp = config.parse_connection_url(TCP, variable="X")
    assert tcp.username == "app" and tcp.database == "firmbatch"
    assert tcp.endpoint == ("db.example", 5432) and not tcp.is_socket
    assert config.parse_connection_url(tcp.url(), variable="X") == tcp

    socket = config.parse_connection_url(SOCKET, variable="X")
    assert socket.is_socket and socket.endpoint == ("/var/run/postgresql", 5432)
    assert config.parse_connection_url(socket.url(), variable="X") == socket


def test_with_database_keeps_the_identity_and_endpoint():
    spec = config.parse_connection_url(SOCKET, variable="X").with_database("firmbatch_test_0123456789ab")
    assert spec.database == "firmbatch_test_0123456789ab"
    assert spec.endpoint == ("/var/run/postgresql", 5432)
    assert spec.username == "chams"


def test_the_specification_never_renders_a_password_in_its_repr():
    spec = config.parse_connection_url(TCP, variable="X")
    for rendered in (repr(spec), str(spec), spec.redacted()):
        assert "secret" not in rendered
    # ... but the URL it builds does carry it, because that is what connects.
    assert "secret" in spec.url()


def test_a_non_numeric_or_out_of_range_port_is_rejected():
    for url in (
        "postgresql+psycopg://u@/db?host=/tmp&port=abc",
        "postgresql+psycopg://u@/db?host=/tmp&port=0",
        "postgresql+psycopg://u@/db?host=/tmp&port=70000",
    ):
        with pytest.raises(config.ConfigurationError):
            config.parse_connection_url(url, variable="X")


def test_a_tcp_url_may_not_smuggle_the_port_through_the_query():
    url = "postgresql+psycopg://u@h/db?port=5432"
    with pytest.raises(config.ConfigurationError) as exc:
        config.parse_connection_url(url, variable="X")
    assert "no socket directory" in str(exc.value)

# --------------------------------------------------------------------------------------
# Finding 1: the *decoded* authority, checked through real SQLAlchemy and psycopg parsing.
#
# ``urlsplit`` does not percent-decode the host, so a raw scan for commas and slashes
# misses ``h1%2Ch2`` and ``%2Fvar%2Frun%2Fpostgresql`` entirely -- both were accepted, and
# both were verified reaching psycopg. Whether they decode before libpq sees them is a
# property of whichever URL library sits in between rather than anything this repository
# guarantees: SQLAlchemy happens not to unquote hosts today (it does unquote username,
# password and database), which is luck, and luck is the wrong thing to be standing on.
#
# So the decoded host is what gets validated, against a closed grammar: an IPv4 address,
# an IPv6 address, or a DNS name. A host list, a socket path and every delimiter are all
# outside it. The assertions below go through ``create_connect_args`` -- what psycopg is
# actually handed -- rather than stopping at the string.
# --------------------------------------------------------------------------------------


def _psycopg_arguments(url: str) -> dict:
    """What the psycopg driver would actually be called with, for a rendered URL."""
    engine = create_engine(url, poolclass=None, future=True)
    try:
        _, kwargs = engine.dialect.create_connect_args(make_url(url))
    finally:
        engine.dispose()
    return kwargs


@pytest.mark.parametrize(
    "url, because",
    [
        ("postgresql+psycopg://u@h1%2Ch2:5432/db", "an encoded comma decodes to a libpq host list"),
        ("postgresql+psycopg://u@h1%2ch2:5432/db", "lowercase encoding is the same character"),
        (
            "postgresql+psycopg://u@%2Fvar%2Frun%2Fpostgresql:5432/db",
            "an encoded slash turns a TCP host into a socket directory",
        ),
        ("postgresql+psycopg://u@h%5C1:5432/db", "an encoded backslash is a path separator too"),
        ("postgresql+psycopg://u@h%20h:5432/db", "an encoded space is not a hostname character"),
    ],
)
def test_an_encoded_delimiter_in_the_authority_is_refused(url, because):
    with pytest.raises(config.ConfigurationError) as exc:
        config.parse_connection_url(url, variable="X")
    assert "percent-encode" in str(exc.value), because


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+psycopg://u@h1 h2:5432/db",
        "postgresql+psycopg://u@h1;h2:5432/db",
        "postgresql+psycopg://u@/var/run/postgresql:5432/db",
    ],
)
def test_a_host_outside_the_grammar_is_refused(url):
    """Whitespace, separators and bare paths are not hostnames."""
    with pytest.raises(config.ConfigurationError):
        config.parse_connection_url(url, variable="X")


@pytest.mark.parametrize(
    "url, expected_host",
    [
        ("postgresql+psycopg://u@10.0.0.1:5432/db", "10.0.0.1"),
        ("postgresql+psycopg://u@[::1]:5432/db", "::1"),
        ("postgresql+psycopg://u@[2001:db8::1]:5432/db", "2001:db8::1"),
        ("postgresql+psycopg://u@example.com:5432/db", "example.com"),
        ("postgresql+psycopg://u@db-primary.internal.example.com:5432/db", "db-primary.internal.example.com"),
        ("postgresql+psycopg://u@localhost:5432/db", "localhost"),
    ],
)
def test_a_valid_ipv4_ipv6_or_dns_host_is_accepted_unambiguously(url, expected_host):
    """The three legitimate shapes must all survive, and reach psycopg unchanged.

    A check strict enough to reject the attacks and too strict for a bracketed IPv6
    literal or a hyphenated DNS name would just get relaxed by the next person to
    deploy one.
    """
    spec = config.parse_connection_url(url, variable="X")
    assert spec.host == expected_host
    assert spec.is_socket is False
    assert _psycopg_arguments(spec.url())["host"] == expected_host


def test_a_socket_directory_only_arrives_through_the_canonical_form():
    """The socket form is ``host=/dir&port=N`` in the query, and nothing else."""
    spec = config.parse_connection_url(
        "postgresql+psycopg://u@/db?host=/var/run/postgresql&port=5432", variable="X"
    )
    assert (spec.host, spec.port, spec.is_socket) == ("/var/run/postgresql", 5432, True)
    arguments = _psycopg_arguments(spec.url())
    assert arguments["host"] == "/var/run/postgresql"
    # psycopg takes the socket port from the query, where it is a string.
    assert int(arguments["port"]) == 5432


def test_an_encoded_comma_in_the_socket_form_is_refused():
    """``%2C`` decodes to a comma before libpq splits on it."""
    with pytest.raises(config.ConfigurationError) as exc:
        config.parse_connection_url(
            "postgresql+psycopg://u@/db?host=/a%2C/b&port=5432", variable="X"
        )
    assert "more than one socket directory" in str(exc.value)


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+psycopg://u@h:5432/db",
        "postgresql+psycopg://u:pw@10.0.0.1:5432/db",
        "postgresql+psycopg://u@[::1]:5432/db?sslmode=verify-full",
        "postgresql+psycopg://u@/db?host=/var/run/postgresql&port=5432",
    ],
)
def test_the_normalised_url_still_names_exactly_one_endpoint(url):
    """The last representation change before the driver: re-parse and compare.

    Everything else validates the URL the caller supplied. This validates the URL that is
    actually handed to SQLAlchemy and on to libpq, which is the last place an endpoint
    could quietly become two.
    """
    spec = config.parse_connection_url(url, variable="X")
    arguments = _psycopg_arguments(spec.url())

    assert arguments["user"] == spec.username
    assert arguments["dbname"] == spec.database
    assert arguments["host"] == spec.host
    assert int(arguments["port"]) == spec.port
    for field in ("host", "dbname", "user"):
        assert "," not in str(arguments[field]), f"{field} reached psycopg as a list"
    assert "hostaddr" not in arguments

