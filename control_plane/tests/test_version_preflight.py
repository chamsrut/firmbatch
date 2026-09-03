"""Finding 4: PostgreSQL 16 is required *before* anything is provisioned.

The version check used to live in an autouse pytest fixture that depended on
``disposable_database``. That ordering is backwards in a way that only shows on the servers
it exists to reject: on PostgreSQL 15 or 17 the suite created a database and three roles,
ran the migrations, applied the grants, and *then* announced the server was unsupported --
leaving the objects behind on a cluster it had just decided it should not have touched.

The check that decides whether to provision cannot be downstream of provisioning. It now
runs in the bootstrap preflight, and the order is:

1. parse and validate the canonical maintenance URL;
2. validate the connection environment (per physical connection, at ``do_connect``);
3. connect and check the disposable-cluster attestation -- a catalogue read;
4. read ``server_version_num``;
5. require major version 16;
6. only then create anything.

Steps 3 and 4 are reads. The attestation marker may already exist -- checking it changes
nothing, and it has to come first because it is what makes reading anything else on this
server permissible at all.

``server_version_num`` rather than ``version()``: it is an integer the server computes, so
16.1 and 16.15 both give major 16 and no string parsing can disagree.
"""

from __future__ import annotations

import dataclasses
import secrets

import pytest
from sqlalchemy import create_engine, text

from firmbatch.control_plane import config
from firmbatch.control_plane.testing import bootstrap
from firmbatch.control_plane.testing.attestation import ClusterFingerprint

#: 15.13 and 17.2 -- one either side, both as the integer the server would report.
UNSUPPORTED = {"PostgreSQL 15": 150013, "PostgreSQL 17": 170002}


def _admin(environment):
    return create_engine(
        config.load_test_admin_url(environment), isolation_level="AUTOCOMMIT", future=True
    )


def _cluster_state(environment) -> tuple[list[str], list[str], bool]:
    """``(disposable databases, per-run roles, marker present)`` -- the whole footprint."""
    engine = _admin(environment)
    try:
        with engine.connect() as connection:
            databases = [
                row[0]
                for row in connection.execute(
                    text(
                        "SELECT datname FROM pg_database "
                        "WHERE datname ~ '^firmbatch_test_[0-9a-f]{12}$' ORDER BY 1"
                    )
                )
            ]
            roles = [
                row[0]
                for row in connection.execute(
                    text(
                        "SELECT rolname FROM pg_roles "
                        "WHERE rolname ~ '^firmbatch_test_(own|app|prov)_[0-9a-f]{12}$' ORDER BY 1"
                    )
                )
            ]
            marker = bool(
                connection.execute(
                    text("SELECT 1 FROM pg_roles WHERE rolname = :r"),
                    {"r": config.DISPOSABLE_CLUSTER_MARKER_ROLE},
                ).scalar()
            )
    finally:
        engine.dispose()
    return databases, roles, marker


def _pin_suffix(monkeypatch, suffix: str) -> None:
    original = bootstrap.secrets.token_hex

    def fixed(size: int = 32) -> str:
        return suffix if size == 6 else original(size)

    monkeypatch.setattr(bootstrap.secrets, "token_hex", fixed)


# ------------------------------------------------------------------ the check in isolation


@pytest.mark.parametrize("version_num", [150013, 170002, 140020, 180000])
def test_an_unsupported_major_version_is_refused(version_num):
    with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
        bootstrap.require_supported_server_version(version_num)
    message = str(exc.value)
    assert str(version_num) in message
    assert "Nothing has been created" in message


@pytest.mark.parametrize("version_num", [160000, 160001, 160015, 169999])
def test_every_postgresql_16_patch_release_is_accepted(version_num):
    """Patch releases are not a compatibility question; only the major version is."""
    assert bootstrap.require_supported_server_version(version_num) == version_num


def test_the_suite_constant_comes_from_the_bootstrap():
    """One definition. A fixture constant that could drift is a second opinion."""
    from firmbatch.control_plane.tests import conftest

    assert conftest.REQUIRED_SERVER_VERSION_MAJOR is bootstrap.REQUIRED_SERVER_VERSION_MAJOR
    assert bootstrap.REQUIRED_SERVER_VERSION_MAJOR == 16


# ------------------------------------------------------ nothing is provisioned on 15 or 17


@pytest.mark.parametrize("label, version_num", sorted(UNSUPPORTED.items()))
def test_an_unsupported_server_provisions_nothing(environment, monkeypatch, label, version_num):
    """Simulated by reporting another version from the fingerprint read, which is step 4.

    Everything before that point is read-only, so the simulation is faithful: the refusal
    has to happen on the same connection, at the same moment, with nothing created.
    """
    before_databases, before_roles, marker_before = _cluster_state(environment)
    assert marker_before, "the cluster is not attested; this test would prove nothing"

    suffix = secrets.token_hex(6)
    _pin_suffix(monkeypatch, suffix)

    real_read = bootstrap.read_fingerprint
    observed: dict[str, object] = {}

    def pretend(connection) -> ClusterFingerprint:
        real = real_read(connection)
        observed["called"] = True
        return dataclasses.replace(real, server_version_num=version_num)

    monkeypatch.setattr(bootstrap, "read_fingerprint", pretend)

    # Alembic and the grants must never be reached.
    def unreachable(*args, **kwargs):  # pragma: no cover - the point is that it is not called
        raise AssertionError("migrations ran on an unsupported server")

    monkeypatch.setattr(bootstrap, "upgrade_to_head", unreachable)
    monkeypatch.setattr(bootstrap.roles, "grant_application_role", unreachable)

    with pytest.raises(bootstrap.DisposableDatabaseError) as exc:
        bootstrap.create_disposable_database(environment)

    assert observed.get("called"), "the fingerprint was never read, so nothing was simulated"
    assert str(version_num) in str(exc.value), label
    assert "requires PostgreSQL 16" in str(exc.value)

    after_databases, after_roles, marker_after = _cluster_state(environment)
    assert after_databases == before_databases, f"{label}: a database was created"
    assert after_roles == before_roles, f"{label}: roles were created"
    assert f"firmbatch_test_{suffix}" not in after_databases
    for kind in ("own", "app", "prov"):
        assert f"firmbatch_test_{kind}_{suffix}" not in after_roles, f"{label}: {kind} role created"
    assert marker_after, f"{label}: the attestation marker was altered"


@pytest.mark.parametrize("label, version_num", sorted(UNSUPPORTED.items()))
def test_an_unsupported_server_grants_no_membership(environment, monkeypatch, label, version_num):
    """The temporary SET grant is a mutation too, and must not happen either."""
    suffix = secrets.token_hex(6)
    _pin_suffix(monkeypatch, suffix)

    real_read = bootstrap.read_fingerprint
    monkeypatch.setattr(
        bootstrap,
        "read_fingerprint",
        lambda connection: dataclasses.replace(
            real_read(connection), server_version_num=version_num
        ),
    )

    def unreachable(*args, **kwargs):  # pragma: no cover - must not be called
        raise AssertionError("a membership grant was issued on an unsupported server")

    monkeypatch.setattr(bootstrap, "_grant_set_option", unreachable)
    monkeypatch.setattr(bootstrap, "_create_login_role", unreachable)

    with pytest.raises(bootstrap.DisposableDatabaseError):
        bootstrap.create_disposable_database(environment)


def test_the_version_check_runs_after_attestation_and_before_any_create():
    """Asserted on the source, because the ordering *is* the property.

    A test that only exercised the refusal would pass just as well with the check in the
    wrong place on a server that happens to be 16.
    """
    import inspect

    source = inspect.getsource(bootstrap.create_disposable_database)
    attest = source.index("require_disposable_cluster(connection)")
    version = source.index("require_supported_server_version(")
    create_role = source.index("_create_login_role(")
    create_database = source.index('f"CREATE DATABASE {quoted_db}')

    assert attest < version, "the version is read before the server is attested"
    assert version < create_role, "a role is created before the version is checked"
    assert version < create_database, "the database is created before the version is checked"
