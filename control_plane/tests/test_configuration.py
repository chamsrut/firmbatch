"""The configuration boundary. No database needed -- these are pure-function tests.

They exist to keep three properties from eroding: the environment is explicit, no usable
production default lives in the repository, and no complete URL reaches a log.
"""

from __future__ import annotations

import pathlib
import re

import pytest
from sqlalchemy import make_url

from firmbatch.control_plane import config

PACKAGE_ROOT = pathlib.Path(config.__file__).resolve().parent
REPO_ROOT = PACKAGE_ROOT.parent
ENV_EXAMPLE = REPO_ROOT / ".env.example"


def test_environment_must_be_stated_explicitly():
    with pytest.raises(config.ConfigurationError) as exc:
        config.load_environment({})
    assert config.ENVIRONMENT_VAR in str(exc.value)


def test_unknown_environment_is_rejected():
    with pytest.raises(config.ConfigurationError):
        config.load_environment({config.ENVIRONMENT_VAR: "staging"})


def test_known_environments_load():
    assert config.load_environment({config.ENVIRONMENT_VAR: "test"}) is config.Environment.TEST
    assert config.load_environment({config.ENVIRONMENT_VAR: "production"}) is config.Environment.PRODUCTION


def test_production_has_no_default_database_urls():
    """The whole point of the boundary: production configures, it does not inherit."""
    with pytest.raises(config.ConfigurationError):
        config.load_application_settings({config.ENVIRONMENT_VAR: "production"})
    with pytest.raises(config.ConfigurationError):
        config.load_migration_settings({config.ENVIRONMENT_VAR: "production"})


def test_application_and_migration_urls_are_separate():
    """Two loaders, two variables, and neither reads the other's."""
    environment = {
        config.ENVIRONMENT_VAR: "production",
        config.APPLICATION_URL_VAR: "postgresql://app@db.example:5432/firmbatch",
        config.MIGRATION_URL_VAR: "postgresql://owner@db.example:5432/firmbatch",
    }
    application = config.load_application_settings(environment)
    migration = config.load_migration_settings(environment)
    assert application.application_url != migration.migration_url
    # Both normalised onto the one driver v1 speaks.
    assert application.application_url.startswith(config.DRIVER)
    assert migration.migration_url.startswith(config.DRIVER)


def test_non_postgresql_urls_are_rejected():
    """There is no SQLite fallback; a URL asking for one is an error, not a mode."""
    for url in ("sqlite:///firmbatch.db", "mysql://user@host/db", "not-a-url"):
        with pytest.raises(config.ConfigurationError):
            config.require_postgresql_url(url, variable=config.APPLICATION_URL_VAR)


def test_redaction_removes_the_password():
    url = "postgresql+psycopg://app:sup3r-s3cret@db.example:5432/firmbatch"
    redacted = config.redact_database_url(url)
    assert "sup3r-s3cret" not in redacted
    assert "app" in redacted and "firmbatch" in redacted


def test_redaction_removes_secret_query_parameters():
    redacted = config.redact_database_url("postgresql://app@db.example/firmbatch?sslmode=require&password=hunter2")
    assert "hunter2" not in redacted
    assert "sslmode=require" in redacted


def test_settings_repr_never_carries_a_password():
    environment = {
        config.ENVIRONMENT_VAR: "production",
        config.APPLICATION_URL_VAR: "postgresql://app:app-secret@db.example:5432/firmbatch",
        config.MIGRATION_URL_VAR: "postgresql://owner:owner-secret@db.example:5432/firmbatch",
    }
    application = config.load_application_settings(environment)
    migration = config.load_migration_settings(environment)
    for rendered in (repr(application), str(application), repr(migration), str(migration)):
        assert "app-secret" not in rendered
        assert "owner-secret" not in rendered


def test_only_unmistakably_disposable_databases_are_accepted():
    ok = "postgresql+psycopg://u@h/firmbatch_test_0123456789ab"
    assert config.require_disposable_database(ok) == "firmbatch_test_0123456789ab"
    for url in (
        "postgresql+psycopg://u@h/firmbatch",
        "postgresql+psycopg://u@h/firmbatch_production",
        "postgresql+psycopg://u@h/postgres",
        "postgresql+psycopg://u@h/firmbatch_test",
        "postgresql+psycopg://u@h/firmbatch_test_notlowerhex",
    ):
        with pytest.raises(config.UnsafeTestDatabaseError):
            config.require_disposable_database(url)


def test_only_disposable_roles_are_accepted():
    assert config.require_disposable_role("firmbatch_test_app_0123456789ab")
    assert config.require_disposable_role("firmbatch_test_prov_0123456789ab")
    assert config.require_disposable_role("firmbatch_test_own_0123456789ab")
    assert config.require_disposable_role("firmbatch_test_lcw_0123456789ab")
    # Milestone 3.1: the authenticator, the fifth per-run role.
    assert config.require_disposable_role("firmbatch_test_auth_0123456789ab")
    for role in ("postgres", "firmbatch_app", "firmbatch_test_app_", "app"):
        with pytest.raises(config.UnsafeTestDatabaseError):
            config.require_disposable_role(role)


def test_admin_test_url_must_be_a_maintenance_connection():
    assert config.require_admin_maintenance_url("postgresql://u@h:5432/postgres")
    with pytest.raises(config.UnsafeTestDatabaseError):
        config.require_admin_maintenance_url("postgresql://u@h:5432/firmbatch")


def test_missing_test_url_fails_rather_than_skips():
    """The gate must fail without a database. A skip would look like a pass."""
    with pytest.raises(config.ConfigurationError) as exc:
        config.load_test_admin_url({config.ENVIRONMENT_VAR: "test"})
    assert config.TEST_ADMIN_URL_VAR in str(exc.value)


def test_test_helpers_refuse_a_non_test_environment():
    with pytest.raises(config.UnsafeTestDatabaseError):
        config.load_test_admin_url(
            {config.ENVIRONMENT_VAR: "production", config.TEST_ADMIN_URL_VAR: "postgresql://u@h/postgres"}
        )


def test_no_credential_bearing_url_is_committed_in_the_package():
    """No production credential or usable production default may exist in the repository.

    Scans the package for a URL carrying userinfo with a password. Example URLs in
    docstrings and tests are placeholders, so this looks only at the shipped modules
    outside ``tests/``.
    """
    pattern = re.compile(r"postgres(?:ql)?(?:\+\w+)?://[^\s\"']*:[^\s\"'/@]+@")
    offenders = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        if "tests" in path.parts:
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if pattern.search(line):
                offenders.append(f"{path.relative_to(PACKAGE_ROOT)}:{lineno}")
    assert offenders == [], f"credential-bearing database URL committed at: {offenders}"


# ------------------------------- the documented template loads every API database URL
#
# Milestone 3.1 security correction. The API process builds **two** restricted engines: the
# application role, and the distinct authenticator role that alone may execute the
# pre-authentication identity functions (login lookup, browser-session opening, account
# recovery request and completion). A template that documented only the first left the API
# unable to start at all -- ``load_authenticator_url`` refuses an unset variable -- which is
# exactly how the authenticator variable came to be missing from ``.env.example``. These
# tests make the template's completeness a checked fact rather than a habit.


def _documented_environment() -> "dict[str, str]":
    """The uncommented assignments in ``.env.example``, as a mapping.

    Only the live lines: a commented-out alternative is documentation about another
    deployment shape, not the value this template hands a reader.
    """
    values: dict[str, str] = {}
    for line in ENV_EXAMPLE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        values[name.strip()] = value.split("#", 1)[0].strip()
    return values


def test_the_documented_template_loads_every_api_database_url():
    """Both database URLs the API needs are documented and load through the real loaders.

    Loading is itself the proof that no connection field is implicit: both loaders go
    through ``require_postgresql_url``, which refuses a URL that omits a field libpq would
    then take from ``PGUSER``/``PGHOST``/``PGPORT``/``PGDATABASE``, refuses a routing
    override in the query string, and refuses a multi-host failover list. The explicit
    assertions below say the same thing out loud so a reader does not have to infer it.
    """
    documented = _documented_environment()
    for variable in (
        config.ENVIRONMENT_VAR,
        config.APPLICATION_URL_VAR,
        config.AUTHENTICATOR_URL_VAR,
    ):
        assert variable in documented, f"{variable} is not documented in .env.example"

    environment = {
        config.ENVIRONMENT_VAR: documented[config.ENVIRONMENT_VAR],
        config.APPLICATION_URL_VAR: documented[config.APPLICATION_URL_VAR],
        config.AUTHENTICATOR_URL_VAR: documented[config.AUTHENTICATOR_URL_VAR],
    }
    application = config.load_application_settings(environment).application_url
    authenticator = config.load_authenticator_url(environment)

    for label, url in (("application", application), ("authenticator", authenticator)):
        parsed = make_url(url)
        assert parsed.username, f"the {label} URL names no user; libpq would take PGUSER"
        assert parsed.host, f"the {label} URL names no host; libpq would take PGHOST"
        assert parsed.port, f"the {label} URL names no port; libpq would take PGPORT"
        assert parsed.database, f"the {label} URL names no database; libpq would take PGDATABASE"

    # The whole point of the split: two different login roles, not one credential reused.
    # An authenticator that connected as the application role would collapse the
    # trusted-issuer boundary back into the principal it exists to be separate from.
    assert make_url(application).username != make_url(authenticator).username, (
        "the authenticator URL must name its own role, not the application role"
    )


def test_the_documented_api_urls_carry_no_secret():
    """Every value in the template is a non-secret placeholder, as its own header promises."""
    documented = _documented_environment()
    placeholder = re.compile(r"^[A-Z][A-Z0-9_]*$")
    for variable in (config.APPLICATION_URL_VAR, config.AUTHENTICATOR_URL_VAR):
        parsed = make_url(documented[variable])
        for field, value in (("user", parsed.username), ("password", parsed.password)):
            assert value is not None, f"{variable} documents no {field}"
            assert placeholder.match(value), (
                f"{variable} carries a {field} that is not an obvious placeholder; the "
                "template must never commit a real credential"
            )


def test_the_api_refuses_to_start_without_the_authenticator_url():
    """The variable is required, not optional: omitting it is a refusal, never a fallback
    onto the application role's credential."""
    environment = {
        config.ENVIRONMENT_VAR: "production",
        config.APPLICATION_URL_VAR: "postgresql://app@db.example:5432/firmbatch",
    }
    # The application URL still loads on its own ...
    assert config.load_application_settings(environment).application_url
    # ... and the authenticator URL is its own requirement.
    with pytest.raises(config.ConfigurationError) as exc:
        config.load_authenticator_url(environment)
    assert config.AUTHENTICATOR_URL_VAR in str(exc.value)


# ------------------------------------- connection-parameter overrides (finding 1)


def test_a_query_string_database_override_is_rejected():
    """libpq takes ``dbname`` from the query string in preference to the URL path.

    Verified against a real server: ``/postgres?dbname=template1`` validated as
    ``postgres`` and connected to ``template1``. Anything that reads only the path is
    validating one connection and opening another.
    """
    for override in ("dbname", "database", "DBNAME", "DbName"):
        url = (
            "postgresql+psycopg://u@/postgres?host=/var/run/postgresql&port=5432"
            f"&{override}=customer_prod"
        )
        with pytest.raises(config.ConfigurationError) as exc:
            config.require_postgresql_url(url, variable=config.APPLICATION_URL_VAR)
        assert "redirects the connection" in str(exc.value)


def test_a_percent_encoded_override_is_rejected():
    """The comparison is on the decoded key, so encoding it changes nothing."""
    url = (
        "postgresql+psycopg://u@/postgres?host=/var/run/postgresql&port=5432"
        "&%64bname=customer_prod"
    )
    with pytest.raises(config.ConfigurationError):
        config.require_postgresql_url(url, variable=config.APPLICATION_URL_VAR)


def test_a_duplicate_parameter_is_rejected():
    """A second occurrence of an allowed key is still parsed; a bad one is still caught."""
    url = "postgresql+psycopg://u@h:5432/db?sslmode=require&sslmode=disable&dbname=other"
    with pytest.raises(config.ConfigurationError):
        config.require_postgresql_url(url, variable=config.APPLICATION_URL_VAR)


def test_server_and_identity_overrides_are_rejected():
    for key, value in (
        ("hostaddr", "10.0.0.1"),
        ("user", "postgres"),
        ("service", "prod"),
        ("servicefile", "/tmp/pgservice.conf"),
        ("passfile", "/tmp/pgpass"),
        ("options", "-c role=postgres"),
    ):
        url = f"postgresql+psycopg://u@h:5432/db?{key}={value}"
        with pytest.raises(config.ConfigurationError) as exc:
            config.require_postgresql_url(url, variable=config.APPLICATION_URL_VAR)
        assert key in str(exc.value)


def test_an_unknown_connection_parameter_is_rejected():
    """An allowlist, not a denylist: libpq gains parameters and a denylist would rot."""
    url = "postgresql+psycopg://u@h:5432/db?some_future_libpq_option=1"
    with pytest.raises(config.ConfigurationError) as exc:
        config.require_postgresql_url(url, variable=config.APPLICATION_URL_VAR)
    assert "not an allowed connection parameter" in str(exc.value)


def test_the_unix_socket_idiom_is_still_accepted():
    """``host`` as a socket directory is how the local setup connects; it must keep working.

    The port is required here too. Omitted, it would come from ``PGPORT`` or a compiled-in
    default -- an endpoint this configuration does not control.
    """
    url = "postgresql+psycopg://chams@/postgres?host=/var/run/postgresql&port=5432"
    assert config.require_postgresql_url(url, variable=config.TEST_ADMIN_URL_VAR)
    assert config.require_admin_maintenance_url(url)
    spec = config.parse_connection_url(url, variable="X")
    assert spec.is_socket and spec.endpoint == ("/var/run/postgresql", 5432)


def test_a_hostname_in_the_query_is_not_the_socket_idiom():
    url = "postgresql+psycopg://u@/postgres?host=evil.example&port=5432"
    with pytest.raises(config.ConfigurationError) as exc:
        config.require_postgresql_url(url, variable=config.APPLICATION_URL_VAR)
    assert "absolute unix-socket directory path" in str(exc.value)


def test_a_query_host_alongside_a_url_host_is_rejected():
    url = "postgresql+psycopg://u@real.example:5432/db?host=/var/run/postgresql&port=5432"
    with pytest.raises(config.ConfigurationError) as exc:
        config.require_postgresql_url(url, variable=config.APPLICATION_URL_VAR)
    assert "names an endpoint twice" in str(exc.value)


def test_a_url_naming_no_database_is_rejected():
    """A missing path would leave the database to a libpq default, which cannot be checked."""
    with pytest.raises(config.ConfigurationError) as exc:
        config.require_postgresql_url("postgresql+psycopg://u@h:5432/", variable=config.APPLICATION_URL_VAR)
    assert "names no database" in str(exc.value)


# ------------------------------------- one maintenance allowlist (finding 7)


def test_a_disposable_database_is_not_an_acceptable_maintenance_url():
    """A throwaway database is something the bootstrap creates, not a place it works from."""
    url = "postgresql+psycopg://u@h:5432/firmbatch_test_0123456789ab"
    with pytest.raises(config.UnsafeTestDatabaseError) as exc:
        config.require_admin_maintenance_url(url)
    assert "not a maintenance database" in str(exc.value)


def test_the_maintenance_allowlist_has_one_definition():
    for name in sorted(config.ADMIN_MAINTENANCE_DATABASES):
        assert config.require_maintenance_database_name(name, context="test") == name
    for name in ("firmbatch", "firmbatch_test_0123456789ab", "customer_prod", ""):
        with pytest.raises(config.UnsafeTestDatabaseError):
            config.require_maintenance_database_name(name, context="test")
