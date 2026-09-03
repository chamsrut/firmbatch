"""Finding 1: the runtime process must never be handed a privileged credential.

There used to be one ``Settings`` carrying both the runtime URL and the migration URL,
loaded by one ``load_settings()``. Two things were wrong, and the second is the serious
one:

1. An application process could not start without a migration URL in its environment,
   because the combined loader required both. That is backwards — the runtime is the one
   deployment that must never be given owner credentials.
2. Any caller *received* the privileged URL whether it wanted one or not. A credential
   that reaches a process is a credential that can leak from it: into a traceback, a repr,
   a crash dump, a log line. The cheapest way not to leak the owner password from the API
   server is for the API server never to have been told it.

So there are three settings types, three loaders reading one variable each, and no
combined one. There is deliberately no compatibility wrapper either: a shim would
reintroduce the coupling quietly, which is worse than reintroducing it loudly.

The module boundary that goes with this is enforced statically by
``scripts/check-runtime-imports.py --static`` — runtime modules may not import the
migration entry point or the test bootstrap, and may not reach for a privileged loader.
That check runs as its own gate, and is asserted here too so a failure names *this*
property rather than an import-closure one.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

from firmbatch.control_plane import config

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

RUNTIME_ONLY = {
    config.ENVIRONMENT_VAR: "production",
    config.APPLICATION_URL_VAR: "postgresql+psycopg://app:app-secret@db.example:5432/firmbatch",
}

PRIVILEGED = {
    config.MIGRATION_URL_VAR: "postgresql+psycopg://owner:owner-secret@db.example:5432/firmbatch",
    config.TEST_ADMIN_URL_VAR: "postgresql+psycopg://admin:admin-secret@db.example:5432/postgres",
}


# ------------------------------------------------------------------ the runtime settings


def test_application_settings_load_with_only_the_runtime_url():
    """The deployment shape that matters: an API server with one credential."""
    settings = config.load_application_settings(RUNTIME_ONLY)
    assert settings.application_url.startswith(config.DRIVER)
    assert settings.environment is config.Environment.PRODUCTION


def test_application_startup_succeeds_without_any_privileged_variable(monkeypatch):
    """Startup, not merely construction: build the runtime engine with nothing else set.

    ``os.environ`` is cleared of every Firmbatch variable except the runtime one, so a
    loader that reached for a privileged variable would fail here rather than pass on a
    developer machine that happens to have them all exported.
    """
    for variable in (config.MIGRATION_URL_VAR, config.TEST_ADMIN_URL_VAR):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv(config.ENVIRONMENT_VAR, "production")
    monkeypatch.setenv(config.APPLICATION_URL_VAR, RUNTIME_ONLY[config.APPLICATION_URL_VAR])

    import os

    from firmbatch.control_plane.db import engine as db_engine

    settings = config.load_application_settings(os.environ)
    built = db_engine.create_application_engine(settings, pool_size=1)
    try:
        assert built.url.database == "firmbatch"
    finally:
        built.dispose()


def test_application_settings_have_no_privileged_attribute():
    """Not "does not populate" — does not *have*. There is no field to fill in."""
    settings = config.load_application_settings(RUNTIME_ONLY)
    fields = set(vars(settings))
    assert fields == {"environment", "application_url"}
    for forbidden in ("migration", "owner", "provisioning", "bootstrap", "admin"):
        assert not any(forbidden in field for field in fields), forbidden


def test_application_settings_ignore_a_migration_url_in_the_environment():
    """A privileged URL that is present must not be read, and must not be retained."""
    polluted = dict(RUNTIME_ONLY, **PRIVILEGED)
    settings = config.load_application_settings(polluted)
    rendered = f"{settings!r} {settings!s} {vars(settings)}"
    assert "owner-secret" not in rendered
    assert "admin-secret" not in rendered
    assert settings.application_url == config.load_application_settings(RUNTIME_ONLY).application_url


def test_application_settings_repr_exposes_no_url_or_password():
    """Not even a redacted URL: the only rendering that cannot leak is the one that omits it."""
    settings = config.load_application_settings(RUNTIME_ONLY)
    for rendered in (repr(settings), str(settings)):
        assert "app-secret" not in rendered
        assert "postgresql" not in rendered
        assert "db.example" not in rendered
        assert "production" in rendered, "the environment is still worth seeing"


# ------------------------------------------------------------------ the privileged settings


def test_migration_settings_fail_clearly_without_their_own_url():
    with pytest.raises(config.ConfigurationError) as exc:
        config.load_migration_settings({config.ENVIRONMENT_VAR: "production"})
    assert config.MIGRATION_URL_VAR in str(exc.value)


def test_migration_settings_do_not_read_the_runtime_url():
    """Having the runtime URL is not a substitute for having the migration one."""
    with pytest.raises(config.ConfigurationError):
        config.load_migration_settings(RUNTIME_ONLY)


def test_test_bootstrap_settings_are_confined_to_the_test_environment():
    """This credential creates and drops databases. Production must not be able to load it."""
    with pytest.raises(config.UnsafeTestDatabaseError):
        config.load_test_bootstrap_settings(
            {config.ENVIRONMENT_VAR: "production", **PRIVILEGED}
        )


def test_test_bootstrap_settings_fail_clearly_without_their_own_url():
    with pytest.raises(config.ConfigurationError) as exc:
        config.load_test_bootstrap_settings({config.ENVIRONMENT_VAR: "test"})
    assert config.TEST_ADMIN_URL_VAR in str(exc.value)


# ------------------------------------------------------------------ no combined API


@pytest.mark.parametrize("name", ["load_settings", "Settings", "DatabaseSettings", "load_database_settings"])
def test_the_combined_settings_api_is_gone(name):
    """Removed rather than deprecated: a shim would reintroduce the coupling quietly."""
    assert not hasattr(config, name), (
        f"config.{name} still exists. A combined loader hands privileged credentials to "
        "callers that did not ask for them, which is the defect this removed."
    )


def test_no_loader_returns_both_a_runtime_and_a_privileged_url():
    """Whatever the loaders are called, none may return both."""
    everything = dict(RUNTIME_ONLY, **PRIVILEGED)
    everything[config.ENVIRONMENT_VAR] = "test"
    for loader in (
        config.load_application_settings,
        config.load_migration_settings,
        config.load_test_bootstrap_settings,
    ):
        settings = loader(everything)
        urls = [value for value in vars(settings).values() if isinstance(value, str) and "://" in value]
        assert len(urls) <= 1, f"{loader.__name__} returned {len(urls)} URLs"


# ------------------------------------------------------------------ the module boundary


def test_the_runtime_engine_refuses_privileged_settings():
    """The type is the cheapest place to say "not here"."""
    from firmbatch.control_plane.db import engine as db_engine

    everything = dict(RUNTIME_ONLY, **PRIVILEGED)
    everything[config.ENVIRONMENT_VAR] = "test"
    for privileged in (
        config.load_migration_settings(everything),
        config.load_test_bootstrap_settings(everything),
    ):
        with pytest.raises(config.ConfigurationError) as exc:
            db_engine.create_application_engine(privileged)
        assert "must never reach" in str(exc.value)


def test_runtime_modules_do_not_import_migration_or_test_tooling():
    """Static, because the property is "cannot ask", not "did not ask"."""
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "check-runtime-imports.py"), "--static"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "runtime module boundary" in result.stdout


def test_the_boundary_check_catches_a_violation(tmp_path, monkeypatch):
    """A check nobody has seen fail is a check nobody should trust.

    A runtime module is temporarily given a forbidden import, and the checker must say so.
    """
    checker = _load_checker()
    target = REPO_ROOT / "control_plane" / "db" / "models.py"
    original = target.read_text()
    try:
        target.write_text(original + "\nfrom firmbatch.control_plane import migrate  # violation\n")
        problems = checker.check_runtime_boundary()
        assert any("models.py" in problem and "migrate" in problem for problem in problems), problems
    finally:
        target.write_text(original)

    assert checker.check_runtime_boundary() == [], "the violation was not fully reverted"


RUNTIME_IMPORTS = (
    "firmbatch.control_plane.config",
    "firmbatch.control_plane.db.base",
    "firmbatch.control_plane.db.models",
    "firmbatch.control_plane.db.engine",
    "firmbatch.control_plane.db.identity",
    "firmbatch.control_plane.db.principal",
    "firmbatch.control_plane.db.repositories",
    "firmbatch.control_plane.db.roles",
)


def test_importing_runtime_modules_reads_no_privileged_variable():
    """Import must not be the moment a credential is read.

    Run in a **subprocess** with an environment stripped of every Firmbatch variable. The
    obvious in-process version -- ``importlib.reload`` over the same modules -- was written
    first and was wrong in a way worth recording: reloading redefines ``Workspace`` and
    ``TenantContextMismatch``, so later tests compared against classes that were no longer
    the ones the reloaded code raised, and two unrelated isolation tests failed. A fresh
    interpreter is both correct and a stronger statement: nothing carried over.

    It also asserts the modules import *at all* without the variables, which is the
    deployment property -- an API server starts with one credential and no others.
    """
    program = "import " + ", ".join(RUNTIME_IMPORTS) + '\nprint("imported")'
    clean = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("FIRMBATCH_") and not key.startswith("PG")
    }
    clean["PYTHONPATH"] = str(REPO_ROOT.parent)
    result = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, env=clean
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "imported" in result.stdout


def _load_checker():
    """Import the checker by path: ``scripts/`` is not a package."""
    import importlib.util

    path = REPO_ROOT / "scripts" / "check-runtime-imports.py"
    spec = importlib.util.spec_from_file_location("firmbatch_check_runtime_imports", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
