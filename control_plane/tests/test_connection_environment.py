"""Finding 2: the ambient libpq environment must not be able to steer a connection.

An explicit URL is not enough, and this module exists because that was verified rather
than assumed. libpq consults its own environment variables for every connection, and two
of them beat a fully explicit connection string outright:

* ``PGHOSTADDR`` supplies the IP the socket actually goes to, with the URL's host name
  kept only for authentication and certificate checking. The URL says one server; the
  packets go to another.
* ``PGOPTIONS`` is appended to the startup packet. ``-c role=...`` preselects a role,
  ``-c search_path=...`` unpins the schema, ``-c app.tenant_id=...`` would seed the
  isolation context before any application code runs. Reproduced against a real server
  through a fully explicit socket URL: ``PGOPTIONS='-c search_path=pg_temp,public'``
  arrived intact.

The rest -- ``PGHOST``, ``PGPORT``, ``PGUSER``, ``PGDATABASE``, ``PGSERVICE``,
``PGSERVICEFILE`` -- fill in whatever a URL omits. ``parse_connection_url`` requires all
of those explicitly, so on a correct URL they have nothing to supply; they are refused
anyway, because "has nothing to supply" is an argument and a refusal is a fact.

**The response is to fail closed, never to unset them.** Mutating ``os.environ`` around a
connect would race every other thread in the process, and the race window is exactly the
moment the connection is made.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from firmbatch.control_plane import config, migrate
from firmbatch.control_plane.db import engine as db_engine

_CATEGORY_NAMES = (
    "application",
    "migration",
    "bootstrap admin",
    "bootstrap transactional",
    "attestation",
)


#: Every variable named in the review, plus the routing and identity set, plus one that
#: does not exist -- which is the point of an allowlist. Used to parameterise both the
#: policy test and the live per-engine tests below.
REJECTED = [
    ("PGHOSTADDR", "10.0.0.1"),
    ("PGOPTIONS", "-c role=postgres"),
    ("PGHOST", "evil.example.com"),
    ("PGPORT", "6543"),
    ("PGUSER", "postgres"),
    ("PGDATABASE", "customer_prod"),
    ("PGSERVICE", "production"),
    ("PGSERVICEFILE", "/tmp/pg_service.conf"),
    ("PGSYSCONFDIR", "/tmp"),
    ("PGSSLMODE", "disable"),
    ("PGSSLNEGOTIATION", "direct"),
    ("PGSSLCERTMODE", "require"),
    ("PGSSLSNI", "0"),
    ("PGSSLMINPROTOCOLVERSION", "TLSv1"),
    ("PGSSLMAXPROTOCOLVERSION", "TLSv1.1"),
    ("PGSSLROOTCERT", "/tmp/attacker-ca.crt"),
    ("PGSSLCERT", "/tmp/attacker.crt"),
    ("PGSSLKEY", "/tmp/attacker.key"),
    ("PGCLIENTENCODING", "LATIN1"),
    ("PGGSSDELEGATION", "1"),
    ("PGGSSENCMODE", "disable"),
    ("PGCHANNELBINDING", "disable"),
    ("PGTARGETSESSIONATTRS", "any"),
    ("PGAPPNAME", "not-firmbatch"),
    ("PGCONNECT_TIMEOUT", "1"),
    # Not a real libpq variable. An allowlist refuses it anyway, which is the whole
    # argument for inverting the question: libpq gains variables between releases.
    ("PGSOMETHINGINVENTEDLATER", "x"),
]


@pytest.mark.parametrize("variable, value", REJECTED)
def test_a_connection_affecting_variable_is_refused(variable, value):
    """Each can move a connection, downgrade its TLS, or change its identity or session.

    The last entry is deliberately fictional: under the denylist this replaced, a variable
    that PostgreSQL had not shipped yet was silently permitted, and the ones it did ship
    were exactly the TLS and session controls that matter.
    """
    with pytest.raises(config.ConfigurationError) as exc:
        config.require_clean_libpq_environment({variable: value}, context="test")
    assert variable in str(exc.value)


def test_the_refusal_explains_what_each_variable_does():
    """A refusal that does not say why gets suppressed by the next person who hits it."""
    with pytest.raises(config.ConfigurationError) as exc:
        config.require_clean_libpq_environment(
            {"PGHOSTADDR": "10.0.0.1", "PGOPTIONS": "-c role=postgres"}, context="test"
        )
    message = str(exc.value)
    assert "overrides the host" in message
    assert "startup packet" in message


@pytest.mark.parametrize("variable", sorted(config.ALLOWED_CREDENTIAL_ENVIRONMENT))
def test_a_credential_only_variable_is_permitted(variable):
    """``PGPASSWORD`` and ``PGPASSFILE`` cannot change identity or routing.

    Both are consulted only after the user, host, port and database are already fixed --
    a passfile entry is keyed on exactly those four -- so neither can move a connection or
    change who it authenticates as. They can only decide whether authentication succeeds.
    A deployment must be able to keep the password out of the URL, and doing so must not
    be the thing that breaks this check.
    """
    config.require_clean_libpq_environment({variable: "secret"}, context="test")


def test_an_empty_variable_is_not_treated_as_set():
    """``PGHOST=`` supplies nothing, and refusing it would fail every shell that exports it blank."""
    config.require_clean_libpq_environment({"PGHOST": "", "PGOPTIONS": ""}, context="test")


def test_the_check_never_mutates_the_environment():
    """Fail closed, do not "fix up". Unsetting around a connect would race other threads."""
    supplied = {"PGHOSTADDR": "10.0.0.1"}
    with pytest.raises(config.ConfigurationError):
        config.require_clean_libpq_environment(supplied, context="test")
    assert supplied == {"PGHOSTADDR": "10.0.0.1"}, "the check edited the mapping it was given"


def test_pgdata_is_permitted_because_libpq_never_reads_it():
    """A server-side variable, allowed only after confirming it cannot reach a client.

    ``PGDATA`` is consulted by the server, ``initdb`` and ``pg_ctl``. libpq does not look
    at it, so it cannot change identity, endpoint, TLS or session state. It is allowed
    because a developer machine running a local cluster almost always exports it, and
    refusing it would buy a real failure and no security.
    """
    config.require_clean_libpq_environment({"PGDATA": "/var/lib/postgresql/16/main"}, context="test")


def test_the_policy_is_an_allowlist_not_a_denylist():
    """The message table may lag libpq; the allowlist may not.

    Every name in the reasons table must be refused, and nothing may be allowed merely by
    being absent from it.
    """
    assert config.ALLOWED_LIBPQ_ENVIRONMENT == {"PGPASSWORD", "PGPASSFILE", "PGDATA"}
    assert config.ALLOWED_CREDENTIAL_ENVIRONMENT <= config.ALLOWED_LIBPQ_ENVIRONMENT
    assert config.ALLOWED_LIBPQ_ENVIRONMENT.isdisjoint(config.LIBPQ_ENVIRONMENT_REASONS)
    for name in config.LIBPQ_ENVIRONMENT_REASONS:
        assert name.startswith("PG"), name
        with pytest.raises(config.ConfigurationError):
            config.require_clean_libpq_environment({name: "x"}, context="test")


def test_a_non_pg_variable_is_ignored():
    """The policy is about libpq, not about the environment in general."""
    config.require_clean_libpq_environment(
        {"PATH": "/usr/bin", "HOME": "/home/x", "POSTGRES_USER": "postgres"}, context="test"
    )


# ------------------------------------------------------- and it is enforced at connect time


def test_an_application_engine_refuses_to_connect_with_pghostaddr_set(
    disposable_database, monkeypatch
):
    """The engine must refuse *before* libpq reads the variable, not after.

    This is the whole point of hooking ``do_connect`` rather than checking at engine
    construction: an engine can be built long before it connects, and the environment can
    change in between.
    """
    engine = db_engine.create_application_engine(disposable_database.application_url)
    try:
        # Prove the engine works before the environment is dirtied.
        with engine.connect() as connection:
            assert connection.execute(text("SELECT 1")).scalar() == 1

        monkeypatch.setenv("PGHOSTADDR", "127.0.0.1")
        with pytest.raises(config.ConfigurationError) as exc:
            engine.connect()
        assert "PGHOSTADDR" in str(exc.value)
    finally:
        engine.dispose()


def test_pgoptions_cannot_reach_the_server_through_a_firmbatch_engine(
    disposable_database, monkeypatch
):
    """Reproduced defect: PGOPTIONS reached the startup packet of an explicit socket URL.

    Without the guard this connection opens and ``search_path`` is whatever PGOPTIONS
    said, which is the shadowing route ``db/base.py`` exists to close.
    """
    monkeypatch.setenv("PGOPTIONS", "-c search_path=pg_temp,public")
    engine = db_engine.create_application_engine(disposable_database.application_url)
    try:
        with pytest.raises(config.ConfigurationError) as exc:
            engine.connect()
        assert "PGOPTIONS" in str(exc.value)
    finally:
        engine.dispose()


def test_a_service_file_cannot_be_injected(disposable_database, monkeypatch, tmp_path):
    """``PGSERVICE``/``PGSERVICEFILE`` load an entire connection definition from disk."""
    service_file = tmp_path / "pg_service.conf"
    service_file.write_text("[production]\nhost=10.0.0.1\nport=5432\ndbname=customer_prod\n")
    monkeypatch.setenv("PGSERVICEFILE", str(service_file))
    monkeypatch.setenv("PGSERVICE", "production")

    engine = db_engine.create_application_engine(disposable_database.application_url)
    try:
        with pytest.raises(config.ConfigurationError) as exc:
            engine.connect()
        message = str(exc.value)
        assert "PGSERVICE" in message and "PGSERVICEFILE" in message
    finally:
        engine.dispose()


def test_the_migration_engine_is_guarded_too(disposable_database, monkeypatch):
    """Privileged connections are not exempt; they are the ones worth redirecting."""
    monkeypatch.setenv("PGHOSTADDR", "127.0.0.1")
    engine = migrate.create_migration_engine(disposable_database.migration_url)
    try:
        with pytest.raises(config.ConfigurationError):
            engine.connect()
    finally:
        engine.dispose()


def test_the_migration_entry_point_refuses_a_dirty_environment(
    disposable_database, monkeypatch
):
    """``migration_connection`` checks before it opens anything at all."""
    from firmbatch.control_plane import migrate

    monkeypatch.setenv("PGOPTIONS", "-c role=postgres")
    with pytest.raises(config.ConfigurationError) as exc:
        with migrate.migration_connection(disposable_database.migration_url):
            pass  # pragma: no cover - the context manager must not be entered
    assert "PGOPTIONS" in str(exc.value)


# --------------------------------------------------------------------------------------
# Finding 7, live: every Firmbatch engine category must refuse before it opens a socket.
#
# "Before" is the load-bearing word. The guard is a ``do_connect`` handler, which fires
# after the pool has decided to open a connection and before libpq is handed anything, so
# a refusal aborts the connect rather than validating one endpoint and opening another.
# --------------------------------------------------------------------------------------


def _engine_categories(handle):
    """One engine of every kind this package builds, by the constructor it really uses."""
    from firmbatch.control_plane.testing import attestation, bootstrap

    return {
        "application": lambda: db_engine.create_application_engine(handle.application_url),
        "migration": lambda: migrate.create_migration_engine(handle.migration_url),
        "bootstrap admin": lambda: bootstrap._admin_engine(handle.admin_url),
        "bootstrap transactional": lambda: bootstrap._transactional_engine(handle.admin_url),
        "attestation": lambda: attestation._admin_engine(
            {"FIRMBATCH_ENV": "test", config.TEST_ADMIN_URL_VAR: handle.admin_url}
        ),
    }


@pytest.mark.parametrize("category", sorted(_CATEGORY_NAMES))
@pytest.mark.parametrize("variable", ["PGHOSTADDR", "PGOPTIONS", "PGSERVICE", "PGSSLMODE"])
def test_every_engine_category_refuses_before_connecting(
    disposable_database, monkeypatch, category, variable
):
    build = _engine_categories(disposable_database)[category]
    engine = build()
    try:
        monkeypatch.setenv(variable, "1" if variable != "PGOPTIONS" else "-c role=postgres")
        with pytest.raises(config.ConfigurationError) as exc:
            engine.connect()
        assert variable in str(exc.value)
    finally:
        engine.dispose()


def test_the_guard_reads_the_environment_at_connect_not_at_construction(
    disposable_database, monkeypatch
):
    """Finding 4: a one-time check before ``connect()`` has a race window.

    The engine is built while the environment is clean and only then dirtied. A check
    that ran at construction would have passed and the connection would open anyway.
    """
    engine = db_engine.create_application_engine(disposable_database.application_url)
    try:
        monkeypatch.setenv("PGHOSTADDR", "127.0.0.1")
        with pytest.raises(config.ConfigurationError) as exc:
            engine.connect()
        assert "PGHOSTADDR" in str(exc.value)
    finally:
        engine.dispose()
