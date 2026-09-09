"""The closed role model, the password module and the address normaliser -- in Python and in SQL.

``security/permissions.py`` is the role table the API and the HTTP boundary consult;
``firmbatch.membership_role_scopes`` is the same table as the database applies it. The two
are compared here role by role. The password module is a thin, policy-bearing wrapper over
argon2-cffi; what is asserted is the policy and the shape, not the algorithm. The address
normaliser is walked through a corpus on both sides.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from firmbatch.control_plane.db import accounts
from firmbatch.control_plane.db import engine as db_engine
from firmbatch.control_plane.db.base import SCHEMA
from firmbatch.control_plane.security import authorization, passwords, permissions
from firmbatch.control_plane.security.secrets import Secret

# --------------------------------------------------------------------------- roles


def test_the_role_table_is_closed_sorted_and_layered():
    assert permissions.MEMBERSHIP_ROLES == ("admin", "member", "owner", "viewer")
    assert set(permissions.ROLE_PERMISSIONS) == set(permissions.MEMBERSHIP_ROLES)
    for role, scopes in permissions.ROLE_PERMISSIONS.items():
        assert scopes == tuple(sorted(set(scopes))), role
        assert scopes == permissions.effective_permissions(role)
        assert scopes == permissions.effective_permissions(permissions.MembershipRole(role))
    viewer, member = set(permissions.ROLE_PERMISSIONS["viewer"]), set(permissions.ROLE_PERMISSIONS["member"])
    admin, owner = set(permissions.ROLE_PERMISSIONS["admin"]), set(permissions.ROLE_PERMISSIONS["owner"])
    assert viewer < member < admin == owner
    # Owner and admin differ by rule, not by scope: the owner-only rules are enforced by
    # the functions that read the target membership, and they are named here so a reader
    # can find them.
    assert permissions.MANAGING_ROLES == frozenset({"admin", "owner"})
    assert len(permissions.OWNER_ONLY_RULES) >= 2
    with pytest.raises(ValueError):
        permissions.effective_permissions("superuser")


def test_no_role_grants_the_untied_minter_and_the_membership_permissions_are_not_catalogue_scopes():
    for scopes in permissions.ROLE_PERMISSIONS.values():
        assert "credential:manage" not in scopes
        assert "tenant:provision" not in scopes
    for permission in permissions.MEMBERSHIP_PERMISSIONS:
        assert permission not in authorization.KNOWN_SCOPES, permission
    assert set(permissions.MEMBERSHIP_PERMISSIONS) == {"credential:issue", "membership:manage", "membership:read"}
    assert set(permissions.API_ISSUABLE_SCOPES) == set(authorization.DELEGABLE_SCOPES) - {"credential:manage"}
    assert "credential:manage" in authorization.DELEGABLE_SCOPES  # the M2.3 minter may delegate it; M3.1 does not
    assert permissions.API_ISSUABLE_SCOPES == tuple(sorted(permissions.API_ISSUABLE_SCOPES))


def test_the_issuable_subset_and_the_bounding_check():
    for role in permissions.MEMBERSHIP_ROLES:
        issuable = permissions.issuable_scopes_for(role)
        assert set(issuable) == set(permissions.effective_permissions(role)) & set(permissions.API_ISSUABLE_SCOPES)
        assert issuable == tuple(sorted(issuable))
    assert permissions.issuable_scopes_for("viewer") == ("tenant:read", "workspace:read")
    assert permissions.api_scopes_within("member", ["workspace:read", "workspace:read"]) == ("workspace:read",)
    assert permissions.api_scopes_within("owner", [authorization.Scope.AUDIT_READ, "workspace:write"]) == (
        "audit:read", "workspace:write",
    )
    for role, requested in (
        ("member", ["audit:read"]),
        ("owner", ["credential:manage"]),
        ("owner", ["membership:manage"]),
        ("owner", ["tenant:provision"]),
        ("owner", ["not:a-scope"]),
        ("owner", [42]),
    ):
        with pytest.raises(ValueError) as exc:
            permissions.api_scopes_within(role, requested)
        assert str(requested[0]) not in str(exc.value)
    with pytest.raises(ValueError) as exc:
        permissions.api_scopes_within("owner", ["fbk_" + "a" * 43])
    assert "looks like" in str(exc.value) and "fbk_" not in str(exc.value)


def test_the_database_role_table_is_the_python_one(application_engine):
    with db_engine.transaction(application_engine) as session:
        for role in permissions.MEMBERSHIP_ROLES:
            scopes = session.execute(
                text(f"SELECT {SCHEMA}.membership_role_scopes(:r)"), {"r": role}
            ).scalar_one()
            assert tuple(scopes) == permissions.effective_permissions(role), role
        assert session.execute(text(f"SELECT {SCHEMA}.membership_role_scopes('superuser')")).scalar_one() is None
        assert session.execute(text(f"SELECT {SCHEMA}.membership_role_scopes(NULL)")).scalar_one() is None


# --------------------------------------------------------------------------- passwords


def test_the_password_module_hashes_with_argon2id_and_never_stores_the_password():
    secret = Secret("correct horse battery staple")
    stored = passwords.hash_password(secret)
    assert stored.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert passwords.is_well_formed_password_hash(stored)
    assert len(stored) <= passwords.PASSWORD_HASH_MAX_LENGTH
    assert "correct horse" not in stored
    assert passwords.verify_password(stored, secret) is True
    assert passwords.verify_password(stored, Secret("correct horse battery stapl")) is False
    assert passwords.needs_rehash(stored) is False
    # Two hashes of one password differ: the salt is fresh each time.
    assert passwords.hash_password(secret) != stored
    # The dummy hash used to equalise a failed lookup is well-formed and matches nothing useful.
    assert passwords.is_well_formed_password_hash(passwords.DUMMY_HASH)
    assert passwords.verify_password(passwords.DUMMY_HASH, secret) is False
    # A malformed stored hash verifies nothing rather than raising something that names it.
    assert passwords.verify_password("not a hash", secret) is False
    assert passwords.is_well_formed_password_hash("$2b$12$" + "a" * 53) is False


@pytest.mark.parametrize(
    "password",
    ("tiny1", "x" * 11, "x" * 257, "   ", "é" * 5),
)
def test_the_password_policy_refuses_the_bounds_without_repeating_the_value(password):
    with pytest.raises(passwords.PasswordPolicyError) as exc:
        passwords.hash_password(Secret(password))
    assert password.strip() == "" or password not in str(exc.value)
    assert "bytes" in str(exc.value) or "password" in str(exc.value)
    assert str(len(password.encode("utf-8"))) not in str(exc.value).replace("12-byte", "").replace("256-byte", "")


def test_an_empty_password_is_refused_by_the_secret_wrapper_itself():
    from firmbatch.control_plane.security.secrets import SecretHandlingError

    with pytest.raises(SecretHandlingError):
        Secret("")


def test_the_password_module_takes_a_secret_and_not_a_string():
    with pytest.raises(passwords.PasswordPolicyError):
        passwords.hash_password("a plain string that is long enough")  # type: ignore[arg-type]
    with pytest.raises(passwords.PasswordPolicyError):
        passwords.verify_password(passwords.DUMMY_HASH, "a plain string that is long enough")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- addresses


CORPUS = (
    ("user@example.com", "user@example.com"),
    ("  User@Example.COM  ", "user@example.com"),
    ("first.last+tag@sub.example.co.uk", "first.last+tag@sub.example.co.uk"),
    ("\tUSER@EXAMPLE.COM\n", "user@example.com"),
    ("a@b.co", "a@b.co"),
)

REFUSED = (
    "not an address",
    "\u00a0user@example.com",  # Unicode whitespace is not trimmed on either side
    "user@example.com\u2028",
    "user@",
    "@example.com",
    "user@localhost",
    "user@@example.com",
    "user@example.com extra",
    "user@exa mple.com",
    "x" * 65 + "@example.com",
    "user@" + "a" * 64 + ".com",
    "",
    "user@example.c",
)


def test_the_address_normaliser_agrees_in_python_and_sql(owner_engine):
    """The SQL normaliser is internal (executable by nobody), so it is read as the owner."""
    with owner_engine.connect() as connection:
        for raw, expected in CORPUS:
            assert accounts.normalize_email(raw) == expected, raw
            assert connection.execute(
                text(f"SELECT {SCHEMA}.identity_normalize_email(:v)"), {"v": raw}
            ).scalar_one() == expected, raw
        for raw in REFUSED:
            with pytest.raises(accounts.IdentityError) as exc:
                accounts.normalize_email(raw)
            assert raw == "" or raw not in str(exc.value)
            assert connection.execute(
                text(f"SELECT {SCHEMA}.identity_normalize_email(:v)"), {"v": raw}
            ).scalar_one() is None, raw
        assert connection.execute(text(f"SELECT {SCHEMA}.identity_normalize_email(NULL)")).scalar_one() is None


def test_an_address_that_looks_like_a_secret_is_refused_by_name_and_not_by_value():
    with pytest.raises(accounts.IdentityError) as exc:
        accounts.normalize_email("fbk_" + "a" * 43)
    assert "looks like a Firmbatch bearer credential" in str(exc.value)
    assert "fbk_" not in str(exc.value)
