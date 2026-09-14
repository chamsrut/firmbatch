"""Migration ``0007`` and the password-hash contract: structural validation, in Python and in
every database entry point that accepts a hash.

An incidental reliability and security correction found by Milestone 3.3b's verification (ADR
0012; the migration's docstring describes the defect). A valid Argon2id PHC hash has a random
base64 salt and digest. The generic secret-shape recogniser names an AWS access-key-id shape
wherever one occurs -- correctly, for the values it exists to scan -- so a hash whose encoded
material happened to contain one was refused. These tests make that case deterministic instead
of waiting for a salt to produce it: :func:`_regression_salt` chooses the salt.

They hold four things:

* A structurally valid hash carrying the formerly refused shape is accepted by
  ``security/passwords`` and by ``signup_account``, ``complete_account_recovery`` and
  ``change_account_password``.
* Every malformed, unsupported, oversized or NULL hash is still refused at each of those
  boundaries.
* The recogniser still names a raw access key id, in Python and in the database, and every
  other function that applied it still does.
* ``0007`` replaces and restores in the ``0006`` manner. Its legacy texts are the earlier
  migrations' verbatim, and the downgrade puts them back with owner, ACL and hardening intact,
  so a database taken back to ``0006`` has the catalogue a fresh migration to ``0006`` produces.
"""

from __future__ import annotations

import base64
import dataclasses
import functools
import importlib.util
import logging
import pathlib
import re

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from firmbatch.control_plane import migrate
from firmbatch.control_plane.db import accounts, models, roles
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.security import passwords
from firmbatch.control_plane.security.secrets import Secret, looks_like_secret
from firmbatch.control_plane.testing.bootstrap import (
    create_disposable_database,
    drop_disposable_database,
    wire_handle_roles,
)
from firmbatch.control_plane.tests import identity_helpers

REVISION = "0007_password_hash_contract"

REGRESSION_PASSWORD = "a regression passphrase for 0007"

#: The two prefixes the recogniser's access-key-id shape names, and sixteen letters and digits
#: to follow them.
ACCESS_KEY_PREFIXES = ("AKIA", "ASIA")
_ACCESS_KEY_BODY = "IOSFODNN7EXAMPLE"
RAW_ACCESS_KEY_IDS = tuple(prefix + _ACCESS_KEY_BODY for prefix in ACCESS_KEY_PREFIXES)

#: The function each database entry point's hash parameter belongs to.
REPLACED = {
    "signup_account": "p_password_hash",
    "complete_account_recovery": "p_new_password_hash",
    "change_account_password": "p_new_password_hash",
}

ENTRY_POINTS = {
    "signup_account": (
        f"SELECT outcome, account_id FROM {SCHEMA}.signup_account(:email, :hash, CAST('1 hour' AS interval))"
    ),
    "complete_account_recovery": f"SELECT {SCHEMA}.complete_account_recovery(:secret, :hash)",
    "change_account_password": (
        "SELECT session_id FROM "
        f"{SCHEMA}.change_account_password(:secret, :hash, CAST('1 hour' AS interval))"
    ),
}

#: PostgreSQL's ``invalid_parameter_value``, which every entry point raises for a hash that is
#: not the stored form.
INVALID_PARAMETER_VALUE = "22023"

_REAL_HASHER = passwords._HASHER


# --------------------------------------------------------------------------- the regression hash


def _regression_salt(prefix: str) -> bytes:
    """Sixteen salt bytes whose unpadded base64 is ``<prefix><16 letters and digits>/A``.

    The ``$`` before and the ``/`` after both lie outside ``[0-9a-z_]``, so after the
    recogniser's case fold the run is an access key id by its word-boundary rule. The final
    ``A`` carries the four zero bits sixteen bytes leave over, so the encoding round-trips
    exactly and the rendered hash contains it verbatim.
    """
    encoded = prefix + _ACCESS_KEY_BODY + "/A"
    salt = base64.b64decode(encoded + "==")
    assert len(salt) == passwords.ARGON2_SALT_LENGTH
    assert base64.b64encode(salt).decode("ascii").rstrip("=") == encoded
    return salt


@functools.lru_cache(maxsize=None)
def _regression_hash(prefix: str) -> str:
    """A real Argon2id hash of :data:`REGRESSION_PASSWORD` at the current parameters, whose
    encoded salt carries the formerly refused shape. Deterministic: the salt is chosen."""
    return _REAL_HASHER.hash(REGRESSION_PASSWORD, salt=_regression_salt(prefix))


class _ChosenSaltHasher:
    """The module's hasher with one change: :meth:`hash` uses a chosen salt."""

    def __init__(self, salt: bytes) -> None:
        self._salt = salt

    def hash(self, password, *, salt=None):
        return _REAL_HASHER.hash(password, salt=self._salt)

    def __getattr__(self, name):
        return getattr(_REAL_HASHER, name)


def _choose_salt(monkeypatch, prefix: str) -> str:
    """From here on, ``hash_password(REGRESSION_PASSWORD)`` renders the regression hash."""
    monkeypatch.setattr(passwords, "_HASHER", _ChosenSaltHasher(_regression_salt(prefix)))
    return _regression_hash(prefix)


@pytest.fixture(params=ACCESS_KEY_PREFIXES)
def prefix(request) -> str:
    return request.param


# --------------------------------------------------------------------------- what is refused


def _phc(salt="A" * 22, digest="B" * 43, *, variant="argon2id", version="v=19", params="m=65536,t=3,p=4"):
    return f"${variant}${version}${params}${salt}${digest}"


_PHC_PREFIX = _phc(digest="")
#: Valid in every respect but length: the pattern matches, and only the bound refuses it.
OVERSIZED = _PHC_PREFIX + "B" * (passwords.PASSWORD_HASH_MAX_LENGTH + 1 - len(_PHC_PREFIX))

REFUSED_HASHES = {
    "a plaintext": "correct horse battery staple 42",
    "an empty string": "",
    "a bcrypt hash": "$2b$12$" + "a" * 53,
    "argon2i": _phc(variant="argon2i"),
    "argon2d": _phc(variant="argon2d"),
    "version 16": _phc(version="v=16"),
    "no version": "$argon2id$m=65536,t=3,p=4$" + "A" * 22 + "$" + "B" * 43,
    "an unbounded memory parameter": _phc(params="m=1234567890,t=3,p=4"),
    "parameters out of order": _phc(params="t=3,m=65536,p=4"),
    "a short salt": _phc(salt="A" * 15),
    "a short digest": _phc(digest="B" * 15),
    "the url-safe alphabet": _phc(salt="A" * 21 + "-"),
    "base64 padding": _phc(digest="B" * 42 + "="),
    "a trailing field": _phc() + "$" + "C" * 16,
    "a trailing newline": _phc() + "\n",
    "a leading space": " " + _phc(),
    "an oversized hash": OVERSIZED,
    "a raw access key id": RAW_ACCESS_KEY_IDS[0],
    "a bearer credential": "fbk_" + "A" * 43,
}


def test_the_refusal_table_refuses_what_it_says():
    """The oversized case is refused by the bound alone, and the valid baseline is valid."""
    assert len(OVERSIZED) == passwords.PASSWORD_HASH_MAX_LENGTH + 1
    assert re.fullmatch(passwords.PASSWORD_HASH_REGEX, OVERSIZED)
    assert re.fullmatch(passwords.PASSWORD_HASH_REGEX, _phc())
    assert passwords.is_well_formed_password_hash(_phc()) is True


# --------------------------------------------------------------------------- Python


def test_the_regression_hash_is_valid_and_carries_the_formerly_refused_shape(prefix):
    stored = _regression_hash(prefix)
    assert f"${prefix}{_ACCESS_KEY_BODY}/A$" in stored
    assert stored.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert re.fullmatch(passwords.PASSWORD_HASH_REGEX, stored)
    assert len(stored) <= passwords.PASSWORD_HASH_MAX_LENGTH
    # What the generic recogniser says about it is unchanged, and was the defect's cause.
    assert looks_like_secret(stored) == "an AWS access key id"


def test_a_valid_hash_carrying_the_shape_is_well_formed_verifies_and_needs_no_rehash(prefix):
    stored = _regression_hash(prefix)
    assert passwords.is_well_formed_password_hash(stored) is True
    assert passwords.verify_password(stored, Secret(REGRESSION_PASSWORD)) is True
    assert passwords.verify_password(stored, Secret(REGRESSION_PASSWORD + "!")) is False
    assert passwords.needs_rehash(stored) is False


def test_hash_password_returns_its_own_output_when_the_salt_encodes_the_shape(monkeypatch, prefix):
    expected = _choose_salt(monkeypatch, prefix)
    assert passwords.hash_password(Secret(REGRESSION_PASSWORD)) == expected


def test_ordinary_hashing_and_verification_are_unchanged():
    secret = Secret(REGRESSION_PASSWORD)
    rendered = {passwords.hash_password(secret) for _ in range(3)}
    assert len(rendered) == 3
    for stored in rendered:
        assert stored.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
        assert passwords.is_well_formed_password_hash(stored)
        assert passwords.verify_password(stored, secret) is True
        assert passwords.verify_password(stored, Secret(REGRESSION_PASSWORD + "!")) is False
        assert passwords.needs_rehash(stored) is False
    assert passwords.is_well_formed_password_hash(passwords.DUMMY_HASH)


def test_the_pre_hash_boundary_still_validates_the_password_before_any_kdf_work():
    """The input is validated before it is hashed: by type, by the byte bounds and for NUL."""
    with pytest.raises(passwords.PasswordPolicyError):
        passwords.hash_password(RAW_ACCESS_KEY_IDS[0])  # type: ignore[arg-type]
    for refused in ("q7#Zp", "x" * (passwords.PASSWORD_MAX_BYTES + 1), "twelve bytes\x00 and more"):
        with pytest.raises(passwords.PasswordPolicyError) as exc:
            passwords.hash_password(Secret(refused))
        assert refused not in str(exc.value)


@pytest.mark.parametrize("label", sorted(REFUSED_HASHES))
def test_python_still_refuses_every_malformed_unsupported_or_oversized_hash(label):
    value = REFUSED_HASHES[label]
    assert passwords.is_well_formed_password_hash(value) is False
    assert passwords.verify_password(value, Secret(REGRESSION_PASSWORD)) is False
    assert passwords.needs_rehash(value) is True


@pytest.mark.parametrize("value", (None, 42, _phc().encode("ascii")))
def test_a_value_that_is_not_text_is_not_a_hash(value):
    assert passwords.is_well_formed_password_hash(value) is False


@pytest.mark.parametrize("raw", RAW_ACCESS_KEY_IDS)
def test_the_recogniser_still_names_a_raw_access_key_id(raw):
    """The scan is removed from password-hash parameters only. The recogniser is untouched."""
    assert looks_like_secret(raw) == "an AWS access key id"
    assert looks_like_secret(raw.lower()) == "an AWS access key id"
    assert looks_like_secret(f"rotated key {raw} yesterday") == "an AWS access key id"


# --------------------------------------------------------------------------- the database


def _params(entry: str, value: str | None) -> dict:
    if entry == "signup_account":
        return {"email": identity_helpers.unique_email("hash0007"), "hash": value}
    return {"secret": "not-a-live-token", "hash": value}


def test_the_database_recogniser_still_names_a_raw_access_key_id(owner_engine, prefix):
    # Read as the schema owner: the recogniser is internal, and no runtime role may execute it.
    with owner_engine.connect() as connection:
        for raw in RAW_ACCESS_KEY_IDS:
            assert connection.execute(text(f"SELECT {SCHEMA}.secret_shape(:v)"), {"v": raw}).scalar_one() is not None
        # And it still names the shape inside the regression hash: the recogniser did not
        # change, only the three functions stopped applying it to a hash.
        assert (
            connection.execute(text(f"SELECT {SCHEMA}.secret_shape(:v)"), {"v": _regression_hash(prefix)}).scalar_one()
            is not None
        )


@pytest.mark.parametrize("entry", sorted(ENTRY_POINTS))
@pytest.mark.parametrize("label", sorted(REFUSED_HASHES) + ["NULL"])
def test_every_entry_point_still_refuses_what_is_not_the_stored_form(authenticator_engine, entry, label):
    value = None if label == "NULL" else REFUSED_HASHES[label]
    with pytest.raises(DBAPIError) as exc:
        with db_engine.transaction(authenticator_engine) as session:
            session.execute(text(ENTRY_POINTS[entry]), _params(entry, value))
    assert exc.value.orig.sqlstate == INVALID_PARAMETER_VALUE
    server = str(exc.value.orig)
    assert "the password hash is not in the stored form" in server
    if value:
        assert value.strip() not in server


def test_every_entry_point_passes_the_regression_hash_on_to_its_next_check(authenticator_engine, prefix):
    """The format check is where each function refused it; each now proceeds past that check."""
    stored = _regression_hash(prefix)
    with db_engine.transaction(authenticator_engine) as session:
        signed_up = session.execute(text(ENTRY_POINTS["signup_account"]), _params("signup_account", stored)).one()
    assert signed_up.outcome == "created"
    with db_engine.transaction(authenticator_engine) as session:
        completed = session.execute(
            text(ENTRY_POINTS["complete_account_recovery"]), _params("complete_account_recovery", stored)
        ).scalar_one()
    # Past the format check, and refused only because the token is not a live one.
    assert completed is False
    with pytest.raises(DBAPIError) as exc:
        with db_engine.transaction(authenticator_engine) as session:
            session.execute(text(ENTRY_POINTS["change_account_password"]), _params("change_account_password", stored))
    # Past the format check, and stopped at the challenge this transaction never made.
    assert exc.value.orig.sqlstate == accounts.IDENTITY_CONTEXT_SQLSTATE


def _stored_hash(owner_engine, account_id) -> list[str]:
    rows = identity_helpers.owner_rows(owner_engine, "account_passwords", account_id=account_id)
    return [row["password_hash"] for row in rows]


def test_signup_stores_the_regression_hash_and_login_verifies_it(application_engine, owner_engine, monkeypatch, prefix):
    expected = _choose_salt(monkeypatch, prefix)
    email, account_id = identity_helpers.signup_verified(
        application_engine, identity_helpers.unique_email("signup0007"), password=REGRESSION_PASSWORD
    )
    assert _stored_hash(owner_engine, account_id) == [expected]
    opened = identity_helpers.login_session(application_engine, email, password=REGRESSION_PASSWORD)
    assert opened.account_id == account_id


def test_recovery_stores_the_regression_hash_and_login_verifies_it(application_engine, owner_engine, monkeypatch, prefix):
    who = identity_helpers.person(application_engine, "recovery0007")
    authenticator = identity_helpers.authenticator_engine_for(application_engine)
    with db_engine.transaction(authenticator) as session:
        token = accounts.request_recovery(session, email=who.email).secret
    assert token is not None
    expected = _choose_salt(monkeypatch, prefix)
    with db_engine.transaction(authenticator) as session:
        assert accounts.complete_recovery(session, secret=token, new_password=Secret(REGRESSION_PASSWORD)) is True
    assert _stored_hash(owner_engine, who.account_id) == [expected]
    opened = identity_helpers.login_session(application_engine, who.email, password=REGRESSION_PASSWORD)
    assert opened.account_id == who.account_id


def test_a_signed_in_password_change_stores_the_regression_hash_and_login_verifies_it(
    application_engine, owner_engine, monkeypatch, prefix
):
    who = identity_helpers.person(application_engine, "change0007")
    expected = _choose_salt(monkeypatch, prefix)
    with db_engine.transaction(identity_helpers.authenticator_engine_for(application_engine)) as session:
        opened = accounts.change_password(
            session,
            account_id=who.account_id,
            session_id=who.session_id,
            current_password=Secret(identity_helpers.PASSWORD),
            new_password=Secret(REGRESSION_PASSWORD),
        )
    assert opened is not None and opened.account_id == who.account_id
    assert _stored_hash(owner_engine, who.account_id) == [expected]
    relogged = identity_helpers.login_session(application_engine, who.email, password=REGRESSION_PASSWORD)
    assert relogged.account_id == who.account_id


def test_neither_the_password_nor_the_hash_is_logged_or_echoed(application_engine, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    expected = _choose_salt(monkeypatch, "AKIA")
    email, _account_id = identity_helpers.signup_verified(
        application_engine, identity_helpers.unique_email("log0007"), password=REGRESSION_PASSWORD
    )
    identity_helpers.login_session(application_engine, email, password=REGRESSION_PASSWORD)
    refused = REFUSED_HASHES["argon2i"]
    with pytest.raises(accounts.IdentityError) as exc:
        with db_engine.transaction(identity_helpers.authenticator_engine_for(application_engine)) as session:
            accounts._execute(
                session,
                text(ENTRY_POINTS["signup_account"]),
                _params("signup_account", refused),
                scrub=(refused,),
            )
    assert refused not in str(exc.value)
    salt = _regression_salt("AKIA")
    for leaked in (REGRESSION_PASSWORD, expected, expected.rsplit("$", 1)[1], base64.b64encode(salt).decode("ascii")[:20]):
        assert leaked not in caplog.text
        for record in caplog.records:
            assert leaked not in repr(record.args), record.name


# --------------------------------------------------------------------------- the migration


def _migration(revision: str = REVISION):
    path = pathlib.Path(models.__file__).parent / "migrations" / "versions" / f"{revision}.py"
    spec = importlib.util.spec_from_file_location(f"firmbatch_migration_{revision}_hash_contract", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _body(constant: str) -> str:
    """The text between the dollar quotes, which is what ``pg_proc.prosrc`` stores."""
    return constant.split("AS $function$", 1)[1].rsplit("$function$", 1)[0]


def test_the_revision_is_the_head_and_follows_0006():
    migration = _migration()
    assert migration.revision == REVISION == roles.M3_3B_REVISION == migrate.head_revision()
    assert migration.down_revision == roles.M3_2_REVISION
    assert len(migration.revision) <= 32
    # It adds no object and moves no grant, so its plan is 0006's with the revision changed.
    assert roles.REVISION_PLANS[REVISION] == dataclasses.replace(
        roles.REVISION_PLANS[roles.M3_2_REVISION], revision=REVISION
    )
    assert REVISION in roles.SUPPORTED_REVISIONS


def test_the_constants_have_not_drifted():
    migration = _migration()
    fifth = _migration(roles.M3_1_REVISION)
    sixth = _migration(roles.M3_2_REVISION)
    assert (
        migration.PASSWORD_HASH_REGEX
        == passwords.PASSWORD_HASH_REGEX
        == models.PASSWORD_HASH_REGEX
        == fifth.PASSWORD_HASH_REGEX
        == sixth.PASSWORD_HASH_REGEX
    )
    assert (
        migration.PASSWORD_HASH_MAX_LENGTH
        == passwords.PASSWORD_HASH_MAX_LENGTH
        == models.PASSWORD_HASH_MAX_LENGTH
        == sixth.PASSWORD_HASH_MAX_LENGTH
    )
    for name in ("MAX_TOKEN_TTL", "ASCII_WHITESPACE_SQL"):
        assert getattr(migration, name) == getattr(fifth, name), name
    for name in (
        "MAX_SESSION_TTL",
        "IDENTITY_SECRET_PREFIXES",
        "IDENTITY_REFUSED_SQLSTATE",
        "IDENTITY_CONFLICT_SQLSTATE",
        "IDENTITY_CONTEXT_SQLSTATE",
        "IDENTITY_REFUSED_MESSAGE",
    ):
        assert getattr(migration, name) == getattr(sixth, name), name


_SIGNUP_COMMENT_LEGACY = (
    "    -- The stored form and nothing else: not a plaintext, not another algorithm. Shape\n"
    "    -- before format, so a credential handed over as a hash is refused without an echo.\n"
)
_SIGNUP_COMMENT_HEAD = (
    "    -- The stored form and nothing else: not a plaintext, not another algorithm. Structure\n"
    "    -- alone decides it (0007): the salt and digest are random base64, which a generic shape\n"
    "    -- scan refuses by chance, and nothing but an Argon2id PHC hash matches this pattern.\n"
)


def test_the_legacy_texts_are_the_earlier_bodies_verbatim_and_each_head_drops_only_the_scan():
    migration = _migration()
    fifth = _migration(roles.M3_1_REVISION)
    sixth = _migration(roles.M3_2_REVISION)

    # What the database holds at 0006, verbatim.
    assert migration._LEGACY_SIGNUP_ACCOUNT == fifth._SIGNUP_ACCOUNT
    assert migration._LEGACY_COMPLETE_ACCOUNT_RECOVERY == sixth._COMPLETE_ACCOUNT_RECOVERY_HEAD
    assert migration._LEGACY_CHANGE_ACCOUNT_PASSWORD == sixth._CHANGE_ACCOUNT_PASSWORD
    for restore, legacy in (
        (migration._LEGACY_SIGNUP_ACCOUNT_RESTORE, migration._LEGACY_SIGNUP_ACCOUNT),
        (migration._LEGACY_CHANGE_ACCOUNT_PASSWORD_RESTORE, migration._LEGACY_CHANGE_ACCOUNT_PASSWORD),
    ):
        assert restore != legacy
        assert restore.replace("CREATE OR REPLACE FUNCTION", "CREATE FUNCTION", 1) == legacy
    # 0006 already wrote this one as a replacement, so it is its own restore.
    assert migration._LEGACY_COMPLETE_ACCOUNT_RECOVERY_RESTORE == migration._LEGACY_COMPLETE_ACCOUNT_RECOVERY
    assert migration._LEGACY_COMPLETE_ACCOUNT_RECOVERY.startswith("\nCREATE OR REPLACE FUNCTION")

    heads = {
        "signup_account": (migration._SIGNUP_ACCOUNT_HEAD, migration._LEGACY_SIGNUP_ACCOUNT_RESTORE),
        "complete_account_recovery": (
            migration._COMPLETE_ACCOUNT_RECOVERY_HEAD,
            migration._LEGACY_COMPLETE_ACCOUNT_RECOVERY_RESTORE,
        ),
        "change_account_password": (
            migration._CHANGE_ACCOUNT_PASSWORD_HEAD,
            migration._LEGACY_CHANGE_ACCOUNT_PASSWORD_RESTORE,
        ),
    }
    for name, (head, restore) in heads.items():
        parameter = REPLACED[name]
        scan = f"       OR {SCHEMA}.secret_shape({parameter}) IS NOT NULL\n"
        assert restore.count(scan) == 1, name
        assert head.startswith("\nCREATE OR REPLACE FUNCTION"), name
        assert "secret_shape" not in head, name
        # The NULL, length and pattern checks and the value-free refusal are all still there.
        assert f"IF {parameter} IS NULL\n" in head, name
        assert f"pg_catalog.length({parameter}) > {migration.PASSWORD_HASH_MAX_LENGTH}\n" in head, name
        assert f"{parameter} !~ '{migration.PASSWORD_HASH_REGEX}' THEN\n" in head, name
        assert "RAISE EXCEPTION 'firmbatch: the password hash is not in the stored form'" in head, name
        assert "DETAIL = 'the value is deliberately not shown'" in head, name
        expected = restore.replace(scan, "", 1)
        if name == "signup_account":
            assert expected.count(_SIGNUP_COMMENT_LEGACY) == 1
            expected = expected.replace(_SIGNUP_COMMENT_LEGACY, _SIGNUP_COMMENT_HEAD, 1)
        assert head == expected, name

    # Exactly these three, each in its earlier inventory on the authenticator's grant.
    assert {name for name, _signature in migration.REPLACED_FUNCTIONS} == set(REPLACED)
    assert set(migration.REPLACED_FUNCTIONS) <= set(
        roles.IDENTITY_AUTHENTICATOR_FUNCTIONS + roles.IDENTITY_PASSWORD_CHANGE_FUNCTIONS
    )


def _grantees(acl) -> set[str]:
    found = set()
    for entry in acl or ():
        grantee, _, rest = entry.partition("=")
        if "X" in rest.split("/")[0]:
            found.add(grantee)
    return found


def _function_rows(connection) -> dict:
    """Every function in the schema, with what a replacement has to keep and a downgrade has to
    put back. ACL entries are compared as a set: their order records grant history, not access."""
    rows = connection.execute(
        text(
            "SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS arguments, "
            "       pg_get_userbyid(p.proowner) AS owner, p.prosecdef, p.provolatile, p.proconfig, "
            "       p.proacl::text[] AS acl, p.prosrc "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = :s"
        ),
        {"s": SCHEMA},
    ).mappings()
    return {
        (row["proname"], row["arguments"]): {**row, "acl": frozenset(row["acl"] or ())}
        for row in rows
    }


def _scanners(rows: dict) -> set[str]:
    """The functions whose body applies the shape recogniser."""
    return {name for (name, _arguments), row in rows.items() if f"{SCHEMA}.secret_shape(" in row["prosrc"]}


def _differences(left: dict, right: dict) -> dict:
    return {
        key: (left.get(key), right.get(key))
        for key in set(left) | set(right)
        if left.get(key) != right.get(key)
    }


def test_the_replaced_functions_keep_owner_acl_and_hardening_with_the_head_bodies(owner_engine, disposable_database):
    migration = _migration()
    heads = {
        "signup_account": migration._SIGNUP_ACCOUNT_HEAD,
        "complete_account_recovery": migration._COMPLETE_ACCOUNT_RECOVERY_HEAD,
        "change_account_password": migration._CHANGE_ACCOUNT_PASSWORD_HEAD,
    }
    with owner_engine.connect() as connection:
        rows = _function_rows(connection)
    for name, signature in migration.REPLACED_FUNCTIONS:
        row = rows[(name, _signature_arguments(rows, name, signature))]
        assert row["prosrc"] == _body(heads[name]), name
        assert row["owner"] == disposable_database.owner_role, name
        assert row["prosecdef"] is True, name
        assert row["proconfig"] == ["search_path=pg_catalog"], name
        grantees = _grantees(row["acl"])
        assert disposable_database.authenticator_role in grantees, name
        for other in (
            disposable_database.application_role,
            disposable_database.provisioning_role,
            disposable_database.lifecycle_writer_role,
            "PUBLIC",
            "",
        ):
            assert other not in grantees, (name, other)
    # The recogniser is still applied everywhere it was, except to the three hash parameters.
    scanners = _scanners(rows)
    assert scanners and not scanners & set(REPLACED)


def _signature_arguments(rows: dict, name: str, signature: str) -> str:
    """The catalogue's rendering of ``name``'s arguments (it names them; the inventory does not)."""
    matches = [arguments for (proname, arguments) in rows if proname == name]
    assert len(matches) == 1, (name, matches)
    types = ", ".join(part.strip().split(" ")[-1] for part in matches[0].split(","))
    assert types == signature, (name, matches[0], signature)
    return matches[0]


def test_the_downgrade_to_0006_restores_the_earlier_bodies_with_owner_acl_and_hardening_exactly(environment):
    """head -> 0006 by downgrade equals base -> 0006 by upgrade, and back up equals the head.

    Owner, ACL, ``SECURITY DEFINER``, volatility and ``search_path`` are compared for every
    function in the schema, not only the three: a downgrade that disturbed anything else would
    differ here too.
    """
    migration = _migration()
    legacy = {
        "signup_account": migration._LEGACY_SIGNUP_ACCOUNT,
        "complete_account_recovery": migration._LEGACY_COMPLETE_ACCOUNT_RECOVERY,
        "change_account_password": migration._LEGACY_CHANGE_ACCOUNT_PASSWORD,
    }
    handle = create_disposable_database(environment)
    try:
        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            assert roles.schema_revision(connection) == REVISION
            wire_handle_roles(connection, handle)
            connection.commit()
            head = _function_rows(connection)
            scanners_at_head = _scanners(head)

            migrate.downgrade_to(connection, roles.M3_2_REVISION, expected=expected)
            connection.commit()
            assert roles.schema_revision(connection) == roles.M3_2_REVISION
            downgraded = _function_rows(connection)
            assert set(downgraded) == set(head)
            for key, row in downgraded.items():
                name = key[0]
                if name in REPLACED:
                    assert row["prosrc"] == _body(legacy[name]), name
                    assert {k: v for k, v in row.items() if k != "prosrc"} == {
                        k: v for k, v in head[key].items() if k != "prosrc"
                    }, name
                else:
                    assert row == head[key], name
            # The scan returns to exactly the three, and to nothing else.
            assert _scanners(downgraded) == scanners_at_head | set(REPLACED)

            migrate.downgrade_to(connection, "base", expected=expected)
            connection.commit()
            command.upgrade(
                migrate.alembic_config(connection=connection, expected=expected), roles.M3_2_REVISION
            )
            connection.commit()
            wire_handle_roles(connection, handle)
            connection.commit()
            fresh = _function_rows(connection)
            assert fresh == downgraded, _differences(fresh, downgraded)

            assert migrate.upgrade_to_head(connection, expected=expected) == REVISION
            connection.commit()
            wire_handle_roles(connection, handle)
            connection.commit()
            back_up = _function_rows(connection)
            assert back_up == head, _differences(back_up, head)
    finally:
        drop_disposable_database(handle)


def test_a_stored_hash_survives_the_downgrade_and_the_reupgrade(environment):
    """A hash written at ``0007`` stays stored and verifiable at ``0006`` and back at ``0007``.

    The downgrade restores ``0006``'s behaviour, the defect included -- a new signup with the
    regression hash is refused again -- which is what proves the restored body is the one
    running rather than merely the one in ``prosrc``. An ordinary hash is still accepted there.
    """
    stored = _regression_hash("AKIA")
    # Deterministic, and free of every shape, so 0006 accepts it on every run.
    ordinary = _REAL_HASHER.hash(REGRESSION_PASSWORD, salt=bytes(passwords.ARGON2_SALT_LENGTH))
    assert looks_like_secret(ordinary) is None

    def signup(handle, value):
        engine = db_engine.create_application_engine(handle.authenticator_url)
        try:
            with db_engine.transaction(engine) as session:
                return session.execute(text(ENTRY_POINTS["signup_account"]), _params("signup_account", value)).one()
        finally:
            engine.dispose()

    def stored_for(handle, account_id):
        engine = migrate.create_migration_engine(handle.migration_url)
        try:
            return _stored_hash(engine, account_id)
        finally:
            engine.dispose()

    handle = create_disposable_database(environment)
    try:
        created = signup(handle, stored)
        assert created.outcome == "created"

        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            migrate.downgrade_to(connection, roles.M3_2_REVISION, expected=expected)
            connection.commit()
            wire_handle_roles(connection, handle)
            connection.commit()

        assert stored_for(handle, created.account_id) == [stored]
        assert passwords.verify_password(stored, Secret(REGRESSION_PASSWORD)) is True
        with pytest.raises(DBAPIError) as exc:
            signup(handle, stored)
        assert exc.value.orig.sqlstate == INVALID_PARAMETER_VALUE
        assert signup(handle, ordinary).outcome == "created"

        with migrate.migration_connection(handle.migration_url) as (connection, expected):
            assert migrate.upgrade_to_head(connection, expected=expected) == REVISION
            connection.commit()
            wire_handle_roles(connection, handle)
            connection.commit()

        assert stored_for(handle, created.account_id) == [stored]
        assert signup(handle, stored).outcome == "created"
    finally:
        drop_disposable_database(handle)
