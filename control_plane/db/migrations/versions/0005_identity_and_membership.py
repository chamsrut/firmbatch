"""Customer identity, workspace membership, browser sessions and membership-bound issuance.

Revision ID: 0005_identity_and_membership
Revises: 0004_lifecycle_state_machines
Create Date: 2026-09-07

The fifth v1 migration, and the first of Milestone 3. It gives the system **people**: an
account that exists before any workspace does, a browser session that belongs to that
account, a membership that ties the account to one workspace at one role, an invitation
that creates a membership when its intended recipient accepts it, and an API credential
that is issued **from** a membership and dies with it.

What it establishes, in one sentence each
-----------------------------------------

1. **The identity plane is protected, not policed.** Every relation this migration adds --
   ``accounts``, ``account_passwords``, ``account_tokens``, ``browser_sessions``,
   ``memberships``, ``workspace_invitations``, ``account_idempotency_records`` and the
   transaction-scoped ``identity_transaction_context`` -- carries **no grant for any
   runtime or provisioning role**, exactly like ``auth_bindings``. The only way in is a
   hardened ``SECURITY DEFINER`` function owned by the schema owner, and every one of those
   derives the account, the tenant, the workspace and the membership from a secret the
   caller presents or from the context a secret already established. No function takes a
   tenant, an account id, a membership id **as the thing that decides what it acts on**;
   the ones that take an identifier use it only to select within what the context already
   reaches, and refuse an absent, hidden, cross-tenant, revoked or expired one with a single
   indistinguishable message.

2. **A browser session and an API credential are different credential types.** A session
   secret (``fbs_``) is accepted only by ``bind_session_context``; a bearer credential
   (``fbk_``) only by Milestone 2.3's ``bind_authenticated_context``. Neither function
   recognises the other's secret -- the two fingerprints live in different tables -- and
   nothing here turns one into the other. A session may **authorize** the issuance of a
   new API credential through ``issue_api_credential``, which rechecks the membership and
   the requested scopes and mints a new secret; it never returns the session's own secret
   in another shape.

3. **Membership is derived at the boundary, every time.** A session binds to a workspace
   only after ``bind_session_workspace`` finds an active membership for its account, and
   **every later request re-derives it**: ``bind_session_context`` rechecks the membership
   before it establishes a tenant context, and a stale binding is simply not honoured. An
   API credential issued from a membership carries ``membership_id``, and a ``BEFORE``
   trigger on ``memberships`` revokes every such credential and unbinds every such session
   in the same statement sequence that revokes the membership -- so revocation is observed
   by the very next bind, on the linearisation terms ADR 0006 decision 3c states.

4. **A session context is a third actor kind.** ``auth_transaction_context`` is written
   with ``actor_kind = 'session'``, the account as principal and no binding, and the
   session's scope set is exactly its membership role's permission set as
   ``membership_role_scopes()`` states it. The ``actor_kind`` constraints on
   ``audit_events`` and ``lifecycle_transitions`` are widened to admit it; nothing else in
   the Milestone 2 mechanism changes.

5. **No role a session can hold grants ``credential:manage``.** That is the capability
   behind ``register_auth_binding``, which mints an untied credential for a caller-named
   principal. Sessions hold ``credential:issue`` instead, which only ``issue_api_credential``
   honours, and which cannot be placed on an API credential because it is not in the
   Milestone 2.3 catalogue. Migration ``0003``'s functions are **not modified** by this
   revision; the one Milestone 2.3 function this file touches is ``secret_shape``, whose
   shape list gains one entry so the metadata policy recognises the five new secret kinds,
   and whose ``0003`` text is restored exactly by the downgrade.

Hand-written like ``0001`` to ``0004``. ``tests/test_migrations.py`` asserts with
``compare_metadata`` that what this file builds still matches ``db/models.py``, and
``tests/test_identity_protection.py`` asserts the ownership, ``search_path``, ``PUBLIC``,
grant and dynamic-SQL properties of every function below from the catalogue.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP, UUID

revision: str = "0005_identity_and_membership"
down_revision: str | None = "0004_lifecycle_state_machines"
branch_labels: str | None = None
depends_on: str | None = None

SCHEMA = "firmbatch"

# Mirrors db/models.py, security/authorization.py, security/permissions.py,
# security/passwords.py and security/secrets.py. A migration must not import them -- one
# that follows the models stops being a record of what was applied -- so the constants are
# duplicated and tests/test_identity_migration.py asserts the duplicates have not drifted.
SLUG_REGEX = r"^[a-z0-9]([a-z0-9-]{0,60}[a-z0-9])?$"
DOTTED_NAME_REGEX = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$"
SIMPLE_NAME_REGEX = r"^[a-z][a-z0-9_]{0,62}$"
IDEMPOTENCY_KEY_REGEX = r"^[A-Za-z0-9._:@=+-]{8,200}$"
FINGERPRINT_REGEX = r"^[0-9a-f]{64}$"
IDEMPOTENCY_STATUS_COMPLETED = "completed"
MAX_METADATA_BYTES = 4096

#: A normalised email address: lower-cased, trimmed, one ``@``, a bounded local part and a
#: dotted domain. ASCII-explicit, like every other pattern in this schema, so Python and
#: PostgreSQL agree without consulting a locale. Mirrors ``models.EMAIL_REGEX``.
EMAIL_REGEX = r"^[a-z0-9._%+-]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
EMAIL_MAX_LENGTH = 254
#: The whitespace an address is trimmed of before it is checked: ASCII, and the same six
#: characters ``db/accounts.py`` strips, so the two sides agree on every input. Unicode
#: whitespace is not trimmed by either and fails the grammar on both.
ASCII_WHITESPACE_SQL = r"E' \t\n\r\f\v'"

#: The stored password form: Argon2id, version 19, the three parameters, salt and hash.
#: Mirrors ``security/passwords.PASSWORD_HASH_REGEX``. The check constraint is what stops a
#: writer that reached the table another way storing a plaintext or a weaker hash.
PASSWORD_HASH_REGEX = (
    r"^\$argon2id\$v=19\$m=[0-9]{1,9},t=[0-9]{1,4},p=[0-9]{1,3}"
    r"\$[A-Za-z0-9+/]{16,}\$[A-Za-z0-9+/]{16,}$"
)
PASSWORD_HASH_MAX_LENGTH = 512

#: The closed role model, sorted. Mirrors ``security/permissions.MEMBERSHIP_ROLES``.
MEMBERSHIP_ROLES = ("admin", "member", "owner", "viewer")

#: ``role -> effective permissions``, each sorted. Mirrors ``permissions.ROLE_PERMISSIONS``
#: character for character; ``membership_role_scopes()`` below is this table as SQL.
ROLE_SCOPES = {
    "viewer": ("membership:read", "tenant:read", "workspace:read"),
    "member": (
        "credential:issue",
        "membership:read",
        "mutation:execute",
        "tenant:read",
        "workspace:read",
        "workspace:write",
    ),
    "admin": (
        "audit:read",
        "credential:issue",
        "membership:manage",
        "membership:read",
        "mutation:execute",
        "tenant:read",
        "workspace:read",
        "workspace:write",
    ),
    "owner": (
        "audit:read",
        "credential:issue",
        "membership:manage",
        "membership:read",
        "mutation:execute",
        "tenant:read",
        "workspace:read",
        "workspace:write",
    ),
}

#: The Milestone 2.3 catalogue, unchanged; an API credential may carry nothing else.
KNOWN_SCOPES = (
    "audit:read",
    "credential:manage",
    "mutation:execute",
    "tenant:provision",
    "tenant:read",
    "workspace:read",
    "workspace:write",
)
#: What ``issue_api_credential`` may place on a credential: the delegable Milestone 2.3
#: scopes minus ``credential:manage``. Mirrors ``permissions.API_ISSUABLE_SCOPES``.
API_ISSUABLE_SCOPES = (
    "audit:read",
    "mutation:execute",
    "tenant:read",
    "workspace:read",
    "workspace:write",
)
MAX_SCOPES_PER_BINDING = 16

TOKEN_KINDS = ("account_recovery", "email_verification")
ACCOUNT_STATUSES = ("active", "unverified")
SESSION_ACTOR_KIND = "session"
#: The actor vocabulary from this revision on. Mirrors ``models.ACTOR_KINDS``.
ACTOR_KINDS = ("credential", "provisioning", "session")
#: What ``0003`` and ``0004`` wrote, carried so the downgrade restores it exactly.
LEGACY_AUDIT_ACTOR_KINDS = ("credential", "provisioning")
LEGACY_ACTOR_SHAPE = (
    "(actor_kind = 'credential' AND actor_principal_id IS NOT NULL AND actor_binding_id IS NOT NULL)"
    " OR (actor_kind = 'provisioning' AND actor_principal_id IS NULL AND actor_binding_id IS NULL)"
)
#: The widened shape: a session actor has a principal (the account) and no binding.
ACTOR_SHAPE = (
    LEGACY_ACTOR_SHAPE
    + " OR (actor_kind = 'session' AND actor_principal_id IS NOT NULL AND actor_binding_id IS NULL)"
)

#: Bounds the functions enforce on caller-supplied lifetimes. Configuration decides the
#: value inside the bound; the bound is what stops a misconfiguration issuing a session
#: that never expires.
MAX_SESSION_TTL = "30 days"
MAX_TOKEN_TTL = "7 days"
MAX_INVITATION_TTL = "30 days"
MIN_TTL = "1 minute"
LABEL_MAX_LENGTH = 100
NAME_MAX_LENGTH = 200

#: The five secret kinds this revision mints, each with its own prefix. Mirrors
#: ``secrets.IDENTITY_SECRET_PREFIXES``. All five share the bearer credential's 244-bit
#: construction and 43-character rendering, and are stored only as fingerprints.
IDENTITY_SECRET_PREFIXES = {
    "session": "fbs_",
    "csrf": "fbc_",
    "email_verification": "fbv_",
    "account_recovery": "fbr_",
    "invitation": "fbi_",
}

#: The SQLSTATEs this revision raises, in the user-defined ``FB`` class Milestone 2.4
#: opened (``FB001``-``FB006`` are its). Mirrored in ``db/accounts.py`` and translated there.
#:
#: ``FB010`` is the **one neutral refusal**: absent, hidden, cross-tenant, revoked,
#: expired, wrong-recipient and not-yet-bound all raise it from a single raise site per
#: function, with one message, so that the refusal cannot be used to ask whether an
#: identifier exists outside what the caller may see. ``FB011`` is a conflict inside the
#: caller's own visible scope that is safe to name (the last owner, an existing member).
#: ``FB012`` is an idempotency key reused for a different request, the Milestone 2.2
#: outcome. ``FB013`` is a context problem -- no bound session, a CSRF token that was not
#: verified, the wrong bind mode -- which is a caller-side programming error and is
#: therefore specific.
IDENTITY_REFUSED_SQLSTATE = "FB010"
IDENTITY_CONFLICT_SQLSTATE = "FB011"
IDENTITY_KEY_REUSE_SQLSTATE = "FB012"
IDENTITY_CONTEXT_SQLSTATE = "FB013"
IDENTITY_REFUSED_MESSAGE = "firmbatch: the identity operation was refused"

# --------------------------------------------------------- the secret-shape recogniser
#
# Migration 0003 installed ``firmbatch.secret_shape`` over six shapes. This revision adds
# five secret kinds, all recognisable by one seventh shape, and the metadata policy --
# which calls ``secret_shape`` from inside the database -- must recognise them too. So the
# function is replaced with the same template over seven shapes, and restored to the same
# template over the original six by the downgrade. The template, the whitespace fold, the
# case fold and the word boundary are character-for-character copies of 0003's, and
# tests/test_identity_migration.py asserts that the legacy text this file renders equals
# 0003's ``_SECRET_SHAPE`` exactly.
WHITESPACE_CODE_POINTS = (
    0x0009, 0x000A, 0x000B, 0x000C, 0x000D,
    0x001C, 0x001D, 0x001E, 0x001F, 0x0020,
    0x0085, 0x00A0, 0x1680,
    0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
    0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
)
ASCII_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ASCII_LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
ASCII_WORD_BOUNDARY_BEFORE = "(?<![0-9a-z_])"
ASCII_WORD_BOUNDARY_AFTER = "(?![0-9a-z_])"

LEGACY_SECRET_SHAPES = (
    ("a Firmbatch bearer credential", r"fbk_[a-z0-9_-]{43}"),
    ("a PEM-encoded key block", r"-----begin [a-z ]*private key-----"),
    ("an HTTP authorization header value", r"^ *(bearer|basic) +[^ ]"),
    ("a database URL carrying a password", r"^[a-z][a-z0-9+.-]*://[^/ :@]+:[^/ @]+@"),
    (
        "an AWS access key id",
        ASCII_WORD_BOUNDARY_BEFORE + r"(akia|asia)[0-9a-z]{16}" + ASCII_WORD_BOUNDARY_AFTER,
    ),
    (
        "a private key or token assignment",
        ASCII_WORD_BOUNDARY_BEFORE + r"(secret|password|token|api[_-]?key) *[=:] *[^ ]",
    ),
)
#: The full list: 0003's six, then the one this revision appends. Mirrors
#: ``secrets.SECRET_SHAPE_PATTERNS``.
SECRET_SHAPES = LEGACY_SECRET_SHAPES + (
    (
        "a Firmbatch session, CSRF, verification, recovery or invitation secret",
        r"fb[cirsv]_[a-z0-9_-]{43}",
    ),
)

_UUID = UUID(as_uuid=True)
_TIMESTAMPTZ = TIMESTAMP(timezone=True)
_JSONB = JSONB(none_as_null=True)


def _quoted_list(values) -> str:
    return ", ".join(f"'{value}'" for value in values)


def _sql_literal(value: str) -> str:
    escaped = value.replace("'", "''")
    return f"'{escaped}'"


def _metadata_checks(column: str) -> list[sa.CheckConstraint]:
    return [
        sa.CheckConstraint(f"jsonb_typeof({column}) = 'object'", name=f"{column}_object"),
        sa.CheckConstraint(
            f"octet_length({column}::text) <= {MAX_METADATA_BYTES}", name=f"{column}_bounded"
        ),
    ]


def _secret_shape_values(shapes) -> str:
    return ",\n        ".join(
        f"({rank}, {_sql_literal(name)}, {_sql_literal(pattern)})"
        for rank, (name, pattern) in enumerate(shapes)
    )


def _whitespace_literal() -> str:
    escapes = "".join(f"\\{code:04X}" for code in WHITESPACE_CODE_POINTS)
    return f"U&'{escapes}'"


def _whitespace_replacement_literal() -> str:
    return "'" + " " * len(WHITESPACE_CODE_POINTS) + "'"


def _normalized_scan_expression(column: str) -> str:
    return (
        "pg_catalog.translate(\n"
        "            pg_catalog.translate(\n"
        f"                {column},\n"
        f"                {_whitespace_literal()},\n"
        f"                {_whitespace_replacement_literal()}\n"
        "            ),\n"
        f"            {_sql_literal(ASCII_UPPERCASE)},\n"
        f"            {_sql_literal(ASCII_LOWERCASE)}\n"
        "        )"
    )


def _secret_shape_sql(shapes, *, replace: bool) -> str:
    """0003's ``_SECRET_SHAPE`` template, over ``shapes``.

    ``replace`` selects ``CREATE OR REPLACE`` for the upgrade and the downgrade alike; the
    body between the dollar quotes is what ``prosrc`` stores, and it is byte-identical to
    0003's when ``shapes`` is the legacy six -- which is what makes a database taken from
    head down to 0004 or 0003 indistinguishable from one migrated freshly to it.
    """
    verb = "CREATE OR REPLACE FUNCTION" if replace else "CREATE FUNCTION"
    return f"""
{verb} {SCHEMA}.secret_shape(p_value text) RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
    WITH folded AS (
        -- The one normalisation pipeline, identical to
        -- security/secrets.normalize_for_shape_scan: whitespace to ASCII space, then
        -- A-Z to a-z, and nothing else. translate() maps code point to code point and
        -- consults no locale -- which [[:space:]], lower() and ~* all do, and which is
        -- how this function and the Python one came to disagree twice.
        SELECT {_normalized_scan_expression("p_value")} AS scanned
    )
    SELECT shapes.name
    FROM (VALUES
        {_secret_shape_values(shapes)}
    ) AS shapes(rank, name, pattern)
    CROSS JOIN folded
    WHERE p_value IS NOT NULL
      -- ``~`` and never ``~*``. The case fold above has already happened, so a
      -- case-insensitive operator would add a second, locale-dependent one.
      AND folded.scanned OPERATOR(pg_catalog.~) shapes.pattern
    ORDER BY shapes.rank
    LIMIT 1
$function$
"""


#: What this revision installs, and what the downgrade puts back. The legacy text is
#: rendered with ``CREATE FUNCTION`` so a test can compare it to 0003's constant verbatim;
#: the downgrade applies it with ``CREATE OR REPLACE`` because the function still exists.
SECRET_SHAPE_SQL = _secret_shape_sql(SECRET_SHAPES, replace=True)
LEGACY_SECRET_SHAPE_SQL = _secret_shape_sql(LEGACY_SECRET_SHAPES, replace=False)
LEGACY_SECRET_SHAPE_RESTORE_SQL = _secret_shape_sql(LEGACY_SECRET_SHAPES, replace=True)

#: Every function this migration creates, with its argument signature and its audience,
#: so that the grants, the downgrade and the tests all work from one list.
#:
#: ``application`` -- granted to the application role and to nobody else. The provisioning
#: role receives **no** identity authority: it creates tenants out of band and mints their
#: first credential; it does not sign people in.
#:
#: ``internal`` -- executable by nobody. Reached only from inside the definer functions,
#: where the current user is the schema owner and the privilege is implicit.
FUNCTIONS = (
    ("membership_role_scopes", "text", "application"),
    ("auth_session", "", "application"),
    # --- the trusted-issuer boundary (Milestone 3.1 security correction) ------------
    # These pre-authentication functions verify a password (login), mint and consume a
    # recovery secret, open a session from a login challenge, or mint and consume a
    # **mailbox-verification** secret. They are granted to a distinct **authenticator**
    # role and to the ordinary application role NOT AT ALL, so that raw SQL as the
    # application role can neither harvest a hash, mint a victim session, reset a victim
    # password, nor issue-and-consume a mailbox-verification token to mark an address it
    # does not control verified. See ADR 0009 (revised) and db/roles.py.
    ("signup_account", "text, text, interval", "authenticator"),
    ("request_email_verification", "text, interval", "authenticator"),
    ("verify_account_email", "text", "authenticator"),
    ("request_account_recovery", "text, interval", "authenticator"),
    ("complete_account_recovery", "text, text", "authenticator"),
    ("account_recovery_token_valid", "text", "authenticator"),
    ("login_lookup", "text", "authenticator"),
    ("open_browser_session", "interval", "authenticator"),
    ("bind_session_context", "text, text, text", "application"),
    # The one membership revalidation, called by every workspace-mode function and by the
    # HTTP boundary for the audit disclosure it performs itself.
    ("workspace_membership_authority", "text, boolean", "application"),
    ("account_profile", "", "application"),
    ("account_sessions", "", "application"),
    ("revoke_browser_session", "uuid", "application"),
    ("revoke_all_browser_sessions", "boolean", "application"),
    ("account_workspaces", "", "application"),
    ("create_workspace", "text, text, text", "application"),
    ("bind_session_workspace", "uuid", "application"),
    ("unbind_session_workspace", "", "application"),
    ("rename_workspace", "text, text", "application"),
    ("workspace_memberships", "", "application"),
    ("remove_membership", "uuid, text", "application"),
    ("change_membership_role", "uuid, text, text", "application"),
    ("create_invitation", "text, text, interval, text", "application"),
    ("revoke_invitation", "uuid, text", "application"),
    ("workspace_invitations", "", "application"),
    ("accept_invitation", "text, text", "application"),
    ("issue_api_credential", "text[], timestamptz, text, text", "application"),
    ("rotate_api_credential", "uuid, timestamptz, text", "application"),
    ("revoke_api_credential", "uuid, text", "application"),
    ("workspace_api_credentials", "", "application"),
    ("record_api_credential_use", "", "application"),
    ("identity_normalize_email", "text", "internal"),
    ("identity_mint_secret", "text", "internal"),
    ("identity_fingerprint", "text", "internal"),
    ("identity_request_fingerprint", "jsonb", "internal"),
    ("identity_context", "", "internal"),
    ("identity_context_write", "text, uuid, uuid, uuid, uuid, uuid, text, boolean, integer", "internal"),
    ("identity_context_narrow", "text[]", "internal"),
    ("identity_require_session", "text, boolean", "internal"),
    ("identity_require_ttl", "interval, interval", "internal"),
    ("identity_issue_token", "uuid, text, interval", "internal"),
    ("identity_replay", "text, text, text", "internal"),
    ("identity_claim", "text, text, text, jsonb, text, text, uuid, jsonb", "internal"),
    ("identity_active_owner_count", "uuid, uuid", "internal"),
    ("memberships_revocation_cascade", "", "internal"),
    ("workspace_directory_sync", "", "internal"),
    ("account_tokens_append_only", "", "internal"),
    ("account_idempotency_records_append_only", "", "internal"),
    ("purge_expired_unverified_accounts", "interval", "internal"),
)

#: The relations this revision adds. All protected: no runtime role holds anything.
PROTECTED_TABLES = (
    "accounts",
    "account_passwords",
    "account_tokens",
    "browser_sessions",
    "memberships",
    "workspace_invitations",
    "workspace_directory",
    "account_idempotency_records",
    "identity_transaction_context",
)

_TENANT = f"{SCHEMA}.auth_tenant_id()"

# ------------------------------------------------------------------------ helpers
#
# Every function below is created with a fixed, safe ``search_path``, refers to every
# object by its schema, contains no dynamic SQL, and looks nothing up by a name the caller
# supplied. tests/test_identity_protection.py asserts each of those from the catalogue.

_IDENTITY_NORMALIZE_EMAIL = f"""
CREATE FUNCTION {SCHEMA}.identity_normalize_email(p_email text) RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
    -- Trimmed and lower-cased, then required to match the bounded ASCII grammar. NULL for
    -- anything else, so a caller gets one answer ("not acceptable") and never an echo of
    -- what was refused. lower() on an already-ASCII-checked value consults no locale that
    -- could change the answer: the grammar admits no character the fold could alter
    -- except A-Z, and those are checked after folding.
    SELECT CASE
        WHEN p_email IS NULL THEN NULL
        WHEN pg_catalog.length(p_email) > {EMAIL_MAX_LENGTH + 32} THEN NULL
        WHEN pg_catalog.length(pg_catalog.lower(pg_catalog.btrim(p_email, {ASCII_WHITESPACE_SQL}))) > {EMAIL_MAX_LENGTH} THEN NULL
        WHEN pg_catalog.lower(pg_catalog.btrim(p_email, {ASCII_WHITESPACE_SQL})) !~ '{EMAIL_REGEX}' THEN NULL
        ELSE pg_catalog.lower(pg_catalog.btrim(p_email, {ASCII_WHITESPACE_SQL}))
    END
$function$
"""

#: The one generator for every identity secret. Two ``gen_random_uuid()`` values -- 244
#: bits from PostgreSQL's strong RNG -- rendered as the same 43 URL-safe characters
#: ``register_auth_binding`` renders, behind the prefix that names the kind. The caller
#: never chooses a value and so never learns whether a candidate exists.
_IDENTITY_MINT_SECRET = f"""
CREATE FUNCTION {SCHEMA}.identity_mint_secret(p_prefix text) RETURNS text
LANGUAGE sql
VOLATILE
SET search_path = pg_catalog
AS $function$
    SELECT p_prefix || pg_catalog.translate(
        pg_catalog.encode(
            pg_catalog.decode(pg_catalog.replace(pg_catalog.gen_random_uuid()::text, '-', ''), 'hex')
            || pg_catalog.decode(pg_catalog.replace(pg_catalog.gen_random_uuid()::text, '-', ''), 'hex'),
            'base64'
        ),
        E'+/=\\n', '-_'
    )
$function$
"""

_IDENTITY_FINGERPRINT = f"""
CREATE FUNCTION {SCHEMA}.identity_fingerprint(p_secret text) RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
    -- The one digest every identity table stores in place of a secret: the same
    -- expression migration 0003 uses for a bearer credential.
    SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_secret, 'UTF8')), 'hex')
$function$
"""

#: The canonical request descriptor for an identity mutation, hashed where it is built.
#: ``jsonb`` normalises key order and collapses duplicates, so the digest is a property of
#: the request and not of how a caller spelled it. Python computes no identity fingerprint.
_IDENTITY_REQUEST_FINGERPRINT = f"""
CREATE FUNCTION {SCHEMA}.identity_request_fingerprint(p_descriptor jsonb) RETURNS text
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.encode(
        pg_catalog.sha256(pg_catalog.convert_to(p_descriptor::text, 'UTF8')), 'hex'
    )
$function$
"""

#: The transaction-scoped identity context: what session, if any, this transaction bound,
#: or which account it challenged at login. The same shape as
#: ``auth_transaction_context`` and for the same reasons (ADR 0006 decision 2): an ordinary
#: unlogged relation ``DISCARD`` does not reach, keyed by backend pid, readable only by the
#: transaction whose id it carries, replaced in place, cleared by nothing.
_IDENTITY_CONTEXT = f"""
CREATE FUNCTION {SCHEMA}.identity_context() RETURNS {SCHEMA}.identity_context_row
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT c.kind, c.account_id, c.session_id, c.workspace_id, c.tenant_id, c.membership_id,
           c.role, c.csrf_verified, c.security_epoch
    FROM {SCHEMA}.identity_transaction_context c
    WHERE c.backend_pid = pg_catalog.pg_backend_pid()
      AND c.xact_id = pg_catalog.pg_current_xact_id_if_assigned()
$function$
"""

_IDENTITY_CONTEXT_WRITE = f"""
CREATE FUNCTION {SCHEMA}.identity_context_write(
    p_kind text,
    p_account_id uuid,
    p_session_id uuid,
    p_workspace_id uuid,
    p_tenant_id uuid,
    p_membership_id uuid,
    p_role text,
    p_csrf_verified boolean,
    p_security_epoch integer
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_written integer;
BEGIN
    -- Executable by nobody: a role that could call this could name any account and any
    -- session. The ON CONFLICT predicate is the whole of "a transaction carries one
    -- identity": a row already carrying this transaction's id is not replaced, and there
    -- is no statement anywhere that removes one.
    INSERT INTO {SCHEMA}.identity_transaction_context AS existing
        (backend_pid, xact_id, kind, account_id, session_id, workspace_id, tenant_id,
         membership_id, role, csrf_verified, security_epoch, bound_at)
    VALUES (
        pg_catalog.pg_backend_pid(), pg_catalog.pg_current_xact_id(), p_kind, p_account_id,
        p_session_id, p_workspace_id, p_tenant_id, p_membership_id, p_role,
        COALESCE(p_csrf_verified, false), p_security_epoch, pg_catalog.clock_timestamp()
    )
    ON CONFLICT (backend_pid) DO UPDATE
        SET xact_id        = excluded.xact_id,
            kind           = excluded.kind,
            account_id     = excluded.account_id,
            session_id     = excluded.session_id,
            workspace_id   = excluded.workspace_id,
            tenant_id      = excluded.tenant_id,
            membership_id  = excluded.membership_id,
            role           = excluded.role,
            csrf_verified  = excluded.csrf_verified,
            security_epoch = excluded.security_epoch,
            bound_at       = excluded.bound_at
        WHERE existing.xact_id <> excluded.xact_id;
    GET DIAGNOSTICS v_written = ROW_COUNT;
    IF v_written = 0 THEN
        RAISE EXCEPTION 'firmbatch: this transaction already carries an identity context'
            USING ERRCODE = 'invalid_transaction_state',
                  DETAIL = 'a transaction binds one session, or challenges one login, and keeps it; '
                           'open a new transaction for another';
    END IF;
END;
$function$
"""

#: **Narrowing, never widening.** Two identity operations write framework rows under an
#: authority the resulting membership does not itself hold: creating a workspace provisions
#: a tenant (``tenant:provision``), and accepting an invitation records a claim and an
#: outbox event for a membership whose role may be read-only (``mutation:execute``). The
#: writes are the trusted function's own -- they are what the operation *is* -- and the
#: row-security policies on those tables still evaluate against the transaction's context,
#: so the context is established with the extra capability for exactly those statements.
#:
#: What the caller's transaction holds after the function returns must be the member's
#: own permissions and nothing more, or a viewer that accepted an invitation could go on
#: to append arbitrary outbox events with raw SQL for the rest of the transaction. So the
#: context row is narrowed here before control returns: the tenant, the principal and the
#: actor kind are untouched -- a transaction still binds one tenant once -- and only the
#: scope array shrinks. The predicate that the transaction id matches is what makes this
#: unable to touch a context that is not this transaction's. Executable by nobody.
_IDENTITY_CONTEXT_NARROW = f"""
CREATE FUNCTION {SCHEMA}.identity_context_narrow(p_scopes text[]) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_written integer;
BEGIN
    UPDATE {SCHEMA}.auth_transaction_context
    SET scopes = COALESCE(p_scopes, ARRAY[]::text[])
    WHERE backend_pid = pg_catalog.pg_backend_pid()
      AND xact_id = pg_catalog.pg_current_xact_id()
      AND scopes @> COALESCE(p_scopes, ARRAY[]::text[]);
    GET DIAGNOSTICS v_written = ROW_COUNT;
    IF v_written <> 1 THEN
        RAISE EXCEPTION 'firmbatch: narrowing an authenticated context requires one this transaction holds'
            USING ERRCODE = 'internal_error';
    END IF;
END;
$function$
"""

#: The public reader. What a bound session is, for the current transaction, and nothing
#: for a transaction that bound none or that only challenged a login.
_AUTH_SESSION = f"""
CREATE FUNCTION {SCHEMA}.auth_session() RETURNS {SCHEMA}.identity_session_row
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT c.session_id, c.account_id, c.workspace_id, c.tenant_id, c.membership_id, c.role,
           c.csrf_verified
    FROM {SCHEMA}.identity_transaction_context c
    WHERE c.backend_pid = pg_catalog.pg_backend_pid()
      AND c.xact_id = pg_catalog.pg_current_xact_id_if_assigned()
      AND c.kind = 'session'
$function$
"""

#: What every session-driven function calls first. ``account`` mode requires that no tenant
#: context has been established in this transaction; ``workspace`` mode requires that the
#: bound session's tenant is exactly the authenticated tenant. The CSRF requirement is a
#: property of the mutation, stated by the caller and checked here against what the bind
#: recorded, so a raw-SQL caller cannot claim it for a bind that never verified a token.
_IDENTITY_REQUIRE_SESSION = f"""
CREATE FUNCTION {SCHEMA}.identity_require_session(p_mode text, p_require_csrf boolean)
RETURNS {SCHEMA}.identity_session_row
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_tenant uuid;
BEGIN
    v_session := {SCHEMA}.auth_session();
    IF v_session.session_id IS NULL THEN
        RAISE EXCEPTION 'firmbatch: this transaction has no bound browser session'
            USING ERRCODE = '{IDENTITY_CONTEXT_SQLSTATE}',
                  DETAIL = 'present a session secret with bind_session_context() first';
    END IF;
    IF p_require_csrf AND NOT v_session.csrf_verified THEN
        RAISE EXCEPTION 'firmbatch: this operation requires a verified CSRF token'
            USING ERRCODE = '{IDENTITY_CONTEXT_SQLSTATE}',
                  DETAIL = 'the session was bound without its CSRF secret, and a cookie-authenticated '
                           'mutation must present one';
    END IF;
    v_tenant := {SCHEMA}.auth_tenant_id();
    IF p_mode = 'workspace' THEN
        IF v_session.workspace_id IS NULL OR v_tenant IS NULL
           OR v_tenant IS DISTINCT FROM v_session.tenant_id THEN
            RAISE EXCEPTION 'firmbatch: this operation requires a workspace-bound session context'
                USING ERRCODE = '{IDENTITY_CONTEXT_SQLSTATE}',
                      DETAIL = 'bind the session in workspace mode; the tenant context it establishes '
                               'is the one the operation acts in';
        END IF;
    ELSIF p_mode = 'account' THEN
        IF v_tenant IS NOT NULL THEN
            RAISE EXCEPTION 'firmbatch: this operation requires an account-level session context'
                USING ERRCODE = '{IDENTITY_CONTEXT_SQLSTATE}',
                      DETAIL = 'this transaction already holds a tenant context; account-level '
                               'operations run in a transaction bound in account mode';
        END IF;
    ELSE
        RAISE EXCEPTION 'firmbatch: the session mode is account or workspace'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    RETURN v_session;
END;
$function$
"""

#: **The one membership revalidation** (Milestone 3.1 security correction, stale-scope
#: finding). Every workspace-mode operation -- mutation, manager listing and audit
#: disclosure alike -- decides what the caller may do from the scope set
#: ``bind_session_context`` cached in the transaction context. That set is a **cache of an
#: authorization decision made at bind time**, and a transaction that binds, waits, and
#: then acts is acting on authority its account may no longer hold. Re-reading the
#: membership in each function separately is how three of them came to skip it.
#:
#: So there is one mechanism, and it is this. In order:
#:
#: 1. the transaction must carry a workspace-mode session whose tenant is the authenticated
#:    tenant (``identity_require_session``);
#: 2. the **serialisation point** is taken -- the workspace row ``FOR UPDATE`` for a caller
#:    that is about to mutate, the caller's own membership row ``FOR SHARE`` for one that is
#:    about to disclose (the body says why the two differ). Either way a demotion or a
#:    removal of this membership cannot commit between the check and what the caller does
#:    with the answer, and a workspace that is gone is the neutral refusal;
#: 3. the tenant, the workspace, the account, the membership's identity, its active status
#:    and the account's active status are re-read **under that lock**, as one row;
#: 4. the current role's permission set -- not the session's cached one -- must contain
#:    ``p_scope``, when one is asked for.
#:
#: What it returns is the caller's own session row with ``role`` replaced by the freshly
#: read role, so a caller that needs the role for a later decision uses that one. Callers
#: run this **before** the replay lookup, so a demoted caller cannot replay its way to a
#: result it may no longer ask for, and before any disclosure or mutation.
#:
#: Granted to the application role because the HTTP boundary calls it directly for the one
#: audit disclosure it performs itself (credential history), and it discloses nothing the
#: caller's own bind did not already return. **A caller that will mutate must ask for the
#: ``FOR UPDATE`` form first**: taking the share form and later upgrading is the one way to
#: deadlock two transactions here, and no call path in this revision does it.
_IDENTITY_REQUIRE_MEMBERSHIP = f"""
CREATE FUNCTION {SCHEMA}.workspace_membership_authority(p_scope text, p_lock boolean)
RETURNS {SCHEMA}.identity_session_row
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_role text;
BEGIN
    v_session := {SCHEMA}.identity_require_session('workspace', false);
    -- The serialisation point, before anything is read or decided.
    --
    -- A **mutator** takes the workspace row, exclusively: it is about to change a fact the
    -- whole workspace shares (a name, a membership, an invitation, a credential), and that
    -- is the lock every other mutation takes, in this order.
    --
    -- A **reader** takes its own membership row, in share mode, and not the workspace row.
    -- Two reasons, and both matter. The workspace row is under forced row-level security
    -- whose UPDATE policy requires ``workspace:write``, and PostgreSQL evaluates the UPDATE
    -- policies for any ``SELECT ... FOR SHARE``/``FOR UPDATE`` -- so a viewer, which holds
    -- ``membership:read`` and no write scope, would find no row to lock and be refused for
    -- a listing it is entitled to. And a reader's decision depends on **its own** authority
    -- and nothing else, so its own membership is the precise thing to hold still: a
    -- concurrent demotion or removal of this membership is exactly the write that would
    -- invalidate the disclosure, and a share lock on the row makes that write wait.
    IF COALESCE(p_lock, false) THEN
        PERFORM 1 FROM {SCHEMA}.workspaces w
        WHERE w.id = v_session.workspace_id AND w.tenant_id = v_session.tenant_id
        FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION '{IDENTITY_REFUSED_MESSAGE}'
                USING ERRCODE = '{IDENTITY_REFUSED_SQLSTATE}';
        END IF;
        -- Tenant, workspace, account, membership identity and both active states, re-read
        -- under the workspace lock. READ COMMITTED gives this statement its own snapshot,
        -- so what it sees is committed state as of now, and the lock is what stops it
        -- changing before the caller acts.
        SELECT m.role INTO v_role
        FROM {SCHEMA}.memberships m
        JOIN {SCHEMA}.accounts a ON a.id = m.account_id
        WHERE m.id = v_session.membership_id
          AND m.tenant_id = v_session.tenant_id
          AND m.workspace_id = v_session.workspace_id
          AND m.account_id = v_session.account_id
          AND m.revoked_at IS NULL
          AND a.status = 'active';
    ELSE
        -- The same row, the same conditions, and the share lock taken by the read itself.
        SELECT m.role INTO v_role
        FROM {SCHEMA}.memberships m
        JOIN {SCHEMA}.accounts a ON a.id = m.account_id
        WHERE m.id = v_session.membership_id
          AND m.tenant_id = v_session.tenant_id
          AND m.workspace_id = v_session.workspace_id
          AND m.account_id = v_session.account_id
          AND m.revoked_at IS NULL
          AND a.status = 'active'
        FOR SHARE OF m;
    END IF;
    -- A membership revoked, an account deactivated, or a workspace gone since the bind is
    -- simply not here, and all of them are the one neutral refusal.
    IF NOT FOUND THEN
        RAISE EXCEPTION '{IDENTITY_REFUSED_MESSAGE}'
            USING ERRCODE = '{IDENTITY_REFUSED_SQLSTATE}';
    END IF;
    -- The authority check, against the role as it is now. Naming the permission is safe:
    -- it is the caller's own membership, and the caller may read its own role.
    IF p_scope IS NOT NULL
       AND NOT (p_scope = ANY ({SCHEMA}.membership_role_scopes(v_role))) THEN
        RAISE EXCEPTION 'firmbatch: this operation requires the % permission', p_scope
            USING ERRCODE = 'insufficient_privilege',
                  DETAIL = 'the membership behind this session does not hold it now';
    END IF;
    v_session.role := v_role;
    RETURN v_session;
END;
$function$
"""

_IDENTITY_REQUIRE_TTL = f"""
CREATE FUNCTION {SCHEMA}.identity_require_ttl(p_ttl interval, p_maximum interval) RETURNS void
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
BEGIN
    -- Configuration chooses the lifetime; this bounds it. A lifetime the configuration got
    -- wrong -- zero, negative, or a year -- is refused rather than issued.
    IF p_ttl IS NULL OR p_ttl < INTERVAL '{MIN_TTL}' OR p_ttl > p_maximum THEN
        RAISE EXCEPTION 'firmbatch: the requested lifetime is outside the permitted bound'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
END;
$function$
"""

#: One token per account per kind at a time: issuing a new one supersedes every unconsumed
#: one of the same kind, so a stale verification link stops working the moment a fresh one
#: is sent. The secret is minted here and returned once; the row holds its fingerprint.
_IDENTITY_ISSUE_TOKEN = f"""
CREATE FUNCTION {SCHEMA}.identity_issue_token(p_account_id uuid, p_kind text, p_ttl interval)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_secret text;
    v_prefix text;
BEGIN
    PERFORM {SCHEMA}.identity_require_ttl(p_ttl, INTERVAL '{MAX_TOKEN_TTL}');
    v_prefix := CASE p_kind
        WHEN 'email_verification' THEN '{IDENTITY_SECRET_PREFIXES["email_verification"]}'
        WHEN 'account_recovery' THEN '{IDENTITY_SECRET_PREFIXES["account_recovery"]}'
    END;
    IF v_prefix IS NULL THEN
        RAISE EXCEPTION 'firmbatch: unknown account token kind'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    UPDATE {SCHEMA}.account_tokens
    SET superseded_at = pg_catalog.clock_timestamp()
    WHERE account_id = p_account_id
      AND kind = p_kind
      AND consumed_at IS NULL
      AND superseded_at IS NULL;
    v_secret := {SCHEMA}.identity_mint_secret(v_prefix);
    INSERT INTO {SCHEMA}.account_tokens (account_id, kind, fingerprint, expires_at)
    VALUES (
        p_account_id, p_kind, {SCHEMA}.identity_fingerprint(v_secret),
        pg_catalog.clock_timestamp() + p_ttl
    );
    RETURN v_secret;
END;
$function$
"""

#: The tenant-scoped replay lookup for a workspace-mode mutation, on Milestone 2.2's table
#: and by Milestone 2.2's rules: the claim is read under FORCE row security in the
#: authenticated tenant, a matching fingerprint replays, a different one is the caller's
#: bug and is refused. Internal, because "is this key taken" is an answer only the
#: mutation that owns the key should be able to ask for.
_IDENTITY_REPLAY = f"""
CREATE FUNCTION {SCHEMA}.identity_replay(p_operation text, p_key text, p_fingerprint text)
RETURNS TABLE (found boolean, record_id uuid, event_id uuid, result jsonb)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_record record;
    v_event uuid;
BEGIN
    IF p_key IS NULL THEN
        RETURN QUERY SELECT false, NULL::uuid, NULL::uuid, NULL::jsonb;
        RETURN;
    END IF;
    SELECT r.id, r.request_fingerprint, r.result INTO v_record
    FROM {SCHEMA}.idempotency_records r
    WHERE r.operation = p_operation AND r.idempotency_key = p_key;
    IF NOT FOUND THEN
        RETURN QUERY SELECT false, NULL::uuid, NULL::uuid, NULL::jsonb;
        RETURN;
    END IF;
    IF v_record.request_fingerprint <> p_fingerprint THEN
        RAISE EXCEPTION 'firmbatch: the idempotency key was already used for a different request'
            USING ERRCODE = '{IDENTITY_KEY_REUSE_SQLSTATE}',
                  DETAIL = 'reusing a key for a changed request is a caller bug; nothing about the '
                           'existing request is disclosed';
    END IF;
    SELECT e.id INTO v_event FROM {SCHEMA}.outbox_events e WHERE e.idempotency_record_id = v_record.id;
    RETURN QUERY SELECT true, v_record.id, v_event, v_record.result;
END;
$function$
"""

#: The claim and the event a workspace-mode mutation commits with itself. With a key: one
#: claim carrying the result, one event linked to it. Without: one unlinked event, which is
#: the internal form ADR 0005 decision 7a built. Both rows are written here, in the same
#: statement sequence as the mutation, so no caller and no ordering produces a subset.
_IDENTITY_CLAIM = f"""
CREATE FUNCTION {SCHEMA}.identity_claim(
    p_operation text,
    p_key text,
    p_fingerprint text,
    p_result jsonb,
    p_event_type text,
    p_aggregate_type text,
    p_aggregate_id uuid,
    p_attributes jsonb
) RETURNS TABLE (record_id uuid, event_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_tenant uuid;
    v_record uuid;
    v_event uuid;
BEGIN
    v_tenant := {SCHEMA}.auth_tenant_id();
    IF v_tenant IS NULL THEN
        RAISE EXCEPTION 'firmbatch: an identity claim requires an authenticated tenant context'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_key IS NOT NULL THEN
        v_record := pg_catalog.gen_random_uuid();
        INSERT INTO {SCHEMA}.idempotency_records
            (id, tenant_id, operation, idempotency_key, request_fingerprint, status, result)
        VALUES (v_record, v_tenant, p_operation, p_key, p_fingerprint,
                '{IDEMPOTENCY_STATUS_COMPLETED}', COALESCE(p_result, '{{}}'::jsonb));
    END IF;
    v_event := pg_catalog.gen_random_uuid();
    INSERT INTO {SCHEMA}.outbox_events
        (id, tenant_id, idempotency_record_id, event_type, aggregate_type, aggregate_id, attributes)
    VALUES (v_event, v_tenant, v_record, p_event_type, p_aggregate_type, p_aggregate_id,
            COALESCE(p_attributes, '{{}}'::jsonb));
    RETURN QUERY SELECT v_record, v_event;
END;
$function$
"""

_IDENTITY_ACTIVE_OWNER_COUNT = f"""
CREATE FUNCTION {SCHEMA}.identity_active_owner_count(p_workspace_id uuid, p_tenant_id uuid)
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.count(*)::integer
    FROM {SCHEMA}.memberships m
    WHERE m.workspace_id = p_workspace_id
      AND m.tenant_id = p_tenant_id
      AND m.role = 'owner'
      AND m.revoked_at IS NULL
$function$
"""

#: The closed role model as SQL. ``SECURITY INVOKER`` and ``IMMUTABLE``: a pure mapping
#: over its argument, granted to the application role so a caller can read what a role
#: means, which discloses nothing about any tenant. NULL for an unknown role, and every
#: consumer treats NULL as "no permission at all".
_MEMBERSHIP_ROLE_SCOPES = f"""
CREATE FUNCTION {SCHEMA}.membership_role_scopes(p_role text) RETURNS text[]
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
    SELECT CASE p_role
        WHEN 'viewer' THEN ARRAY[{_quoted_list(ROLE_SCOPES["viewer"])}]::text[]
        WHEN 'member' THEN ARRAY[{_quoted_list(ROLE_SCOPES["member"])}]::text[]
        WHEN 'admin' THEN ARRAY[{_quoted_list(ROLE_SCOPES["admin"])}]::text[]
        WHEN 'owner' THEN ARRAY[{_quoted_list(ROLE_SCOPES["owner"])}]::text[]
        ELSE NULL
    END
$function$
"""

# ------------------------------------------------------------------------ accounts

_SIGNUP_ACCOUNT = f"""
CREATE FUNCTION {SCHEMA}.signup_account(p_email text, p_password_hash text, p_token_ttl interval)
RETURNS TABLE (outcome text, account_id uuid, verification_secret text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_email text;
    v_id uuid;
    v_secret text;
BEGIN
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();
    v_email := {SCHEMA}.identity_normalize_email(p_email);
    IF v_email IS NULL THEN
        RAISE EXCEPTION 'firmbatch: the email address is not acceptable'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the value is deliberately not shown';
    END IF;
    -- The stored form and nothing else: not a plaintext, not another algorithm. Shape
    -- before format, so a credential handed over as a hash is refused without an echo.
    IF p_password_hash IS NULL
       OR pg_catalog.length(p_password_hash) > {PASSWORD_HASH_MAX_LENGTH}
       OR {SCHEMA}.secret_shape(p_password_hash) IS NOT NULL
       OR p_password_hash !~ '{PASSWORD_HASH_REGEX}' THEN
        RAISE EXCEPTION 'firmbatch: the password hash is not in the stored form'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the value is deliberately not shown';
    END IF;
    PERFORM {SCHEMA}.identity_require_ttl(p_token_ttl, INTERVAL '{MAX_TOKEN_TTL}');

    -- An address that is already registered gets the same outcome shape as one that is
    -- not, so that the HTTP boundary can answer both identically; the runtime learns which
    -- notice to send and nothing more. The race -- two signups of one address -- lands on
    -- the unique constraint and is folded into the same answer.
    IF EXISTS (SELECT 1 FROM {SCHEMA}.accounts a WHERE a.email_normalized = v_email) THEN
        RETURN QUERY SELECT 'existing'::text, NULL::uuid, NULL::text;
        RETURN;
    END IF;
    BEGIN
        v_id := pg_catalog.gen_random_uuid();
        INSERT INTO {SCHEMA}.accounts (id, email_normalized, email_display, status)
        VALUES (v_id, v_email, pg_catalog.btrim(p_email, {ASCII_WHITESPACE_SQL}), 'unverified');
        INSERT INTO {SCHEMA}.account_passwords (account_id, password_hash)
        VALUES (v_id, p_password_hash);
        v_secret := {SCHEMA}.identity_issue_token(v_id, 'email_verification', p_token_ttl);
    EXCEPTION WHEN unique_violation THEN
        RETURN QUERY SELECT 'existing'::text, NULL::uuid, NULL::text;
        RETURN;
    END;
    RETURN QUERY SELECT 'created'::text, v_id, v_secret;
END;
$function$
"""

_REQUEST_EMAIL_VERIFICATION = f"""
CREATE FUNCTION {SCHEMA}.request_email_verification(p_email text, p_token_ttl interval)
RETURNS TABLE (outcome text, account_id uuid, verification_secret text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_email text;
    v_account record;
    v_secret text;
BEGIN
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();
    v_email := {SCHEMA}.identity_normalize_email(p_email);
    IF v_email IS NULL THEN
        RETURN QUERY SELECT 'unknown'::text, NULL::uuid, NULL::text;
        RETURN;
    END IF;
    PERFORM {SCHEMA}.identity_require_ttl(p_token_ttl, INTERVAL '{MAX_TOKEN_TTL}');
    SELECT a.id, a.status INTO v_account FROM {SCHEMA}.accounts a WHERE a.email_normalized = v_email;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'unknown'::text, NULL::uuid, NULL::text;
        RETURN;
    END IF;
    IF v_account.status = 'active' THEN
        RETURN QUERY SELECT 'already_verified'::text, NULL::uuid, NULL::text;
        RETURN;
    END IF;
    v_secret := {SCHEMA}.identity_issue_token(v_account.id, 'email_verification', p_token_ttl);
    RETURN QUERY SELECT 'issued'::text, v_account.id, v_secret;
END;
$function$
"""

_VERIFY_ACCOUNT_EMAIL = f"""
CREATE FUNCTION {SCHEMA}.verify_account_email(p_secret text) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_token record;
    v_now timestamptz;
BEGIN
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();
    IF p_secret IS NULL OR pg_catalog.length(p_secret) = 0 THEN
        RETURN false;
    END IF;
    v_now := pg_catalog.clock_timestamp();
    -- Locked, so two presentations of one token serialise and exactly one consumes it.
    -- Unknown, consumed, superseded and expired all answer false: the caller holds the
    -- token or does not, and which of the four it was tells it nothing it should learn.
    SELECT t.id, t.account_id, t.consumed_at, t.superseded_at, t.expires_at INTO v_token
    FROM {SCHEMA}.account_tokens t
    WHERE t.fingerprint = {SCHEMA}.identity_fingerprint(p_secret)
      AND t.kind = 'email_verification'
    FOR UPDATE;
    IF NOT FOUND OR v_token.consumed_at IS NOT NULL OR v_token.superseded_at IS NOT NULL
       OR v_token.expires_at <= v_now THEN
        RETURN false;
    END IF;
    UPDATE {SCHEMA}.account_tokens SET consumed_at = v_now WHERE id = v_token.id;
    UPDATE {SCHEMA}.accounts
    SET status = 'active',
        email_verified_at = COALESCE(email_verified_at, v_now),
        updated_at = v_now
    WHERE id = v_token.account_id;
    RETURN true;
END;
$function$
"""

_REQUEST_ACCOUNT_RECOVERY = f"""
CREATE FUNCTION {SCHEMA}.request_account_recovery(p_email text, p_token_ttl interval)
RETURNS TABLE (outcome text, account_id uuid, recovery_secret text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_email text;
    v_id uuid;
    v_secret text;
BEGIN
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();
    v_email := {SCHEMA}.identity_normalize_email(p_email);
    IF v_email IS NULL THEN
        RETURN QUERY SELECT 'unknown'::text, NULL::uuid, NULL::text;
        RETURN;
    END IF;
    PERFORM {SCHEMA}.identity_require_ttl(p_token_ttl, INTERVAL '{MAX_TOKEN_TTL}');
    SELECT a.id INTO v_id FROM {SCHEMA}.accounts a WHERE a.email_normalized = v_email;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'unknown'::text, NULL::uuid, NULL::text;
        RETURN;
    END IF;
    -- Recovery is offered to unverified accounts too: completing it proves control of the
    -- mailbox, which is exactly what verification proves, and it is how the real owner of
    -- an address takes back an account somebody else registered with it.
    v_secret := {SCHEMA}.identity_issue_token(v_id, 'account_recovery', p_token_ttl);
    RETURN QUERY SELECT 'issued'::text, v_id, v_secret;
END;
$function$
"""

_COMPLETE_ACCOUNT_RECOVERY = f"""
CREATE FUNCTION {SCHEMA}.complete_account_recovery(p_secret text, p_new_password_hash text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_token record;
    v_now timestamptz;
BEGIN
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();
    IF p_new_password_hash IS NULL
       OR pg_catalog.length(p_new_password_hash) > {PASSWORD_HASH_MAX_LENGTH}
       OR {SCHEMA}.secret_shape(p_new_password_hash) IS NOT NULL
       OR p_new_password_hash !~ '{PASSWORD_HASH_REGEX}' THEN
        RAISE EXCEPTION 'firmbatch: the password hash is not in the stored form'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the value is deliberately not shown';
    END IF;
    IF p_secret IS NULL OR pg_catalog.length(p_secret) = 0 THEN
        RETURN false;
    END IF;
    v_now := pg_catalog.clock_timestamp();
    SELECT t.id, t.account_id, t.consumed_at, t.superseded_at, t.expires_at INTO v_token
    FROM {SCHEMA}.account_tokens t
    WHERE t.fingerprint = {SCHEMA}.identity_fingerprint(p_secret)
      AND t.kind = 'account_recovery'
    FOR UPDATE;
    IF NOT FOUND OR v_token.consumed_at IS NOT NULL OR v_token.superseded_at IS NOT NULL
       OR v_token.expires_at <= v_now THEN
        RETURN false;
    END IF;
    UPDATE {SCHEMA}.account_tokens SET consumed_at = v_now WHERE id = v_token.id;
    -- Every other outstanding token of either kind dies with the recovery: the mailbox
    -- owner has just proven control, and nothing issued before that proof should still
    -- be able to act on the account.
    UPDATE {SCHEMA}.account_tokens
    SET superseded_at = v_now
    WHERE account_id = v_token.account_id AND consumed_at IS NULL AND superseded_at IS NULL;
    UPDATE {SCHEMA}.account_passwords
    SET password_hash = p_new_password_hash, updated_at = v_now
    WHERE account_id = v_token.account_id;
    -- The security epoch advances with the recovery. Every API credential this account
    -- issued from any membership was stamped with the old epoch, so bind_authenticated_context
    -- now rejects all of them -- including any minted in a transaction racing this one, which
    -- carries an epoch that is stale the instant this UPDATE commits. This is the durable
    -- eviction the compromise-recovery contract needs, not a best-effort sweep of the rows
    -- that happen to be visible now.
    UPDATE {SCHEMA}.accounts
    SET status = 'active',
        email_verified_at = COALESCE(email_verified_at, v_now),
        security_epoch = security_epoch + 1,
        updated_at = v_now
    WHERE id = v_token.account_id;
    -- The visible bindings are also marked revoked, so a credential listing reflects the
    -- eviction rather than showing an active row the bind will nonetheless refuse. The
    -- epoch is what makes the eviction complete; this makes it legible.
    UPDATE {SCHEMA}.auth_bindings
    SET revoked_at = v_now
    WHERE principal_id = v_token.account_id AND membership_id IS NOT NULL AND revoked_at IS NULL;
    -- And every browser session: a recovered password is the standard moment to end
    -- whatever was signed in with the old one.
    UPDATE {SCHEMA}.browser_sessions
    SET revoked_at = v_now
    WHERE account_id = v_token.account_id AND revoked_at IS NULL;
    RETURN true;
END;
$function$
"""

#: Whether an unconsumed, unsuperseded, unexpired account-recovery token matches the
#: presented secret -- **without consuming it**. The recovery-completion path calls this
#: before it performs the new password's Argon2 hash, so a malformed or non-existent token
#: costs nothing memory-hard; the atomic consume in complete_account_recovery re-checks and
#: is what actually serialises two completions. Granted to the authenticator role alone,
#: like the rest of the recovery path: it reveals only what the completion result reveals
#: (a 244-bit secret is present or it is not), and never whether an account exists.
_ACCOUNT_RECOVERY_TOKEN_VALID = f"""
CREATE FUNCTION {SCHEMA}.account_recovery_token_valid(p_secret text) RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (
        SELECT 1 FROM {SCHEMA}.account_tokens t
        WHERE p_secret IS NOT NULL
          AND pg_catalog.length(p_secret) > 0
          AND t.fingerprint = {SCHEMA}.identity_fingerprint(p_secret)
          AND t.kind = 'account_recovery'
          AND t.consumed_at IS NULL
          AND t.superseded_at IS NULL
          AND t.expires_at > pg_catalog.clock_timestamp()
    )
$function$
"""

#: Reclaim persistent identity state that never completed verification. An unverified
#: account older than the cutoff, holding no active membership, is deleted along with its
#: tokens, passwords and sessions (all ``ON DELETE CASCADE``). This is the explicit expiry
#: control against unbounded unverified-account and verification-token growth from a signup
#: flood: a maintenance operation, run by the schema owner (executable by nobody at
#: runtime), returning how many accounts it reclaimed. A verified account, and an unverified
#: one that somehow holds an active membership, are left untouched.
_PURGE_EXPIRED_UNVERIFIED_ACCOUNTS = f"""
CREATE FUNCTION {SCHEMA}.purge_expired_unverified_accounts(p_older_than interval)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_cutoff timestamptz;
    v_count integer;
BEGIN
    PERFORM {SCHEMA}.auth_require_writable_primary();
    IF p_older_than IS NULL OR p_older_than < INTERVAL '{MIN_TTL}' THEN
        RAISE EXCEPTION 'firmbatch: the reclaim age is a positive interval'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    v_cutoff := pg_catalog.clock_timestamp() - p_older_than;
    WITH doomed AS (
        DELETE FROM {SCHEMA}.accounts a
        WHERE a.status = 'unverified'
          AND a.created_at < v_cutoff
          AND NOT EXISTS (
              SELECT 1 FROM {SCHEMA}.memberships m
              WHERE m.account_id = a.id AND m.revoked_at IS NULL
          )
        RETURNING a.id
    )
    SELECT pg_catalog.count(*)::integer INTO v_count FROM doomed;
    RETURN v_count;
END;
$function$
"""

#: The password step is the runtime's: PostgreSQL has no Argon2. What the database does is
#: hand back one account's stored hash per call and record **which** account was
#: challenged in this transaction, so that ``open_browser_session`` can open a session for
#: that account and no other. A unknown address returns one row of NULLs, so the caller
#: verifies against a dummy hash and the request costs the same either way.
#:
#: **The challenge also carries the account's security version** (Milestone 3.1 security
#: correction, recovery/login race). ``security_epoch`` is the password version: the only
#: statement sequence that ever replaces ``account_passwords.password_hash`` after signup is
#: ``complete_account_recovery``, and it advances the epoch in the same sequence. Reading
#: the hash and the epoch in one statement makes the pair coherent, and
#: ``open_browser_session`` refuses unless the account still carries that epoch when it
#: takes the account row lock. Without it, a password verified against a hash a concurrent
#: recovery has already replaced could still open a session that the recovery -- which
#: revoked the sessions that existed when it ran -- would never see.
_LOGIN_LOOKUP = f"""
CREATE FUNCTION {SCHEMA}.login_lookup(p_email text)
RETURNS TABLE (account_id uuid, password_hash text, email_verified boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_email text;
    v_account_id uuid;
    v_status text;
    v_hash text;
    v_epoch integer;
BEGIN
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();
    v_email := {SCHEMA}.identity_normalize_email(p_email);
    IF v_email IS NOT NULL THEN
        -- The hash and the epoch in one statement, so the challenge records the version
        -- of the very hash the runtime is about to verify against.
        SELECT a.id, a.status, p.password_hash, a.security_epoch
        INTO v_account_id, v_status, v_hash, v_epoch
        FROM {SCHEMA}.accounts a
        JOIN {SCHEMA}.account_passwords p ON p.account_id = a.id
        WHERE a.email_normalized = v_email;
    END IF;
    PERFORM {SCHEMA}.identity_context_write(
        'login_challenge', v_account_id, NULL, NULL, NULL, NULL, NULL, false, v_epoch
    );
    RETURN QUERY SELECT v_account_id, v_hash, COALESCE(v_status = 'active', false);
END;
$function$
"""

_OPEN_BROWSER_SESSION = f"""
CREATE FUNCTION {SCHEMA}.open_browser_session(p_ttl interval)
RETURNS TABLE (session_id uuid, account_id uuid, session_secret text, csrf_secret text,
               expires_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_context {SCHEMA}.identity_context_row;
    v_status text;
    v_epoch integer;
    v_id uuid;
    v_session text;
    v_csrf text;
    v_expires timestamptz;
    v_refuse boolean := false;
BEGIN
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();
    PERFORM {SCHEMA}.identity_require_ttl(p_ttl, INTERVAL '{MAX_SESSION_TTL}');
    -- Only for the account this transaction challenged. There is no account parameter:
    -- the runtime cannot open a session for an account whose stored hash it never asked
    -- for, and it cannot open one in a transaction that looked nothing up.
    v_context := {SCHEMA}.identity_context();
    IF v_context.kind IS DISTINCT FROM 'login_challenge' THEN
        RAISE EXCEPTION 'firmbatch: a browser session is opened only for the account this transaction challenged'
            USING ERRCODE = '{IDENTITY_CONTEXT_SQLSTATE}',
                  DETAIL = 'call login_lookup() in this transaction first';
    END IF;
    IF v_context.account_id IS NULL THEN
        v_refuse := true;
    ELSE
        -- **The recovery/login race is closed here** (Milestone 3.1 security correction).
        -- FOR UPDATE, not a bare read: the lock conflicts with the row-exclusive lock
        -- ``complete_account_recovery`` takes when it advances the epoch, so this either
        -- waits for a recovery in flight and then observes it, or holds the row against
        -- one that starts now. READ COMMITTED re-reads the row this statement locks, so
        -- the epoch compared below is the committed one, not the transaction's snapshot.
        -- The lock is not released here: PostgreSQL holds a row lock to end of
        -- transaction, so a recovery cannot slip between this check and the INSERT.
        SELECT a.status, a.security_epoch INTO v_status, v_epoch
        FROM {SCHEMA}.accounts a WHERE a.id = v_context.account_id FOR UPDATE;
        IF NOT FOUND OR v_status <> 'active' THEN
            v_refuse := true;
        ELSIF v_context.security_epoch IS NULL OR v_epoch IS DISTINCT FROM v_context.security_epoch THEN
            -- The password was verified against a hash this account no longer has. The
            -- refusal is the neutral one: a caller holding the old password learns only
            -- that it cannot sign in, which is what a changed password means.
            v_refuse := true;
        END IF;
    END IF;
    IF v_refuse THEN
        RAISE EXCEPTION '{IDENTITY_REFUSED_MESSAGE}'
            USING ERRCODE = '{IDENTITY_REFUSED_SQLSTATE}';
    END IF;
    v_id := pg_catalog.gen_random_uuid();
    v_session := {SCHEMA}.identity_mint_secret('{IDENTITY_SECRET_PREFIXES["session"]}');
    v_csrf := {SCHEMA}.identity_mint_secret('{IDENTITY_SECRET_PREFIXES["csrf"]}');
    v_expires := pg_catalog.clock_timestamp() + p_ttl;
    INSERT INTO {SCHEMA}.browser_sessions (id, account_id, fingerprint, csrf_fingerprint, expires_at)
    VALUES (v_id, v_context.account_id, {SCHEMA}.identity_fingerprint(v_session),
            {SCHEMA}.identity_fingerprint(v_csrf), v_expires);
    RETURN QUERY SELECT v_id, v_context.account_id, v_session, v_csrf, v_expires;
END;
$function$
"""

# ------------------------------------------------------------------------ sessions

#: The one way a browser session acquires a context, and the mirror image of Milestone
#: 2.3's ``bind_authenticated_context``: it hashes what it is given, looks the digest up in
#: a table no runtime role can read, refuses an unknown, revoked or expired session with one
#: message, and only then decides what the transaction is. The two functions read two
#: different tables, so a bearer credential presented here and a session secret presented
#: there each fail the lookup -- the credential types are distinct by construction.
#:
#: ``workspace`` mode is where membership is derived, and it is derived **every time**: the
#: binding on the session row is a cache of an earlier authorization decision, and the
#: decision is remade here against the membership as it is now. A membership revoked since
#: the session was bound is simply not there, the binding is dropped, and no tenant context
#: is established.
_BIND_SESSION_CONTEXT = f"""
CREATE FUNCTION {SCHEMA}.bind_session_context(p_session_secret text, p_csrf_secret text, p_mode text)
RETURNS TABLE (
    session_id uuid, account_id uuid, email text, email_verified boolean,
    workspace_id uuid, tenant_id uuid, membership_id uuid, role text,
    expires_at timestamptz, csrf_verified boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session record;
    v_role text;
    v_workspace uuid;
    v_tenant uuid;
    v_membership uuid;
    v_csrf boolean := false;
    v_refuse boolean := false;
    v_now timestamptz;
BEGIN
    -- The FIRST executed operations, deliberately, and asserted from the catalogue: the
    -- standby and read-only diagnostic comes before the lookup, before the isolation-level
    -- check, and before anything touches an unlogged relation.
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();
    IF p_mode IS NULL OR p_mode NOT IN ('account', 'workspace') THEN
        RAISE EXCEPTION 'firmbatch: the session bind mode is account or workspace'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    v_now := pg_catalog.clock_timestamp();
    IF p_session_secret IS NULL OR pg_catalog.length(p_session_secret) = 0 THEN
        v_refuse := true;
    ELSE
        SELECT s.id, s.account_id, s.csrf_fingerprint, s.expires_at, s.revoked_at,
               s.workspace_id, s.tenant_id, s.membership_id,
               a.status, a.email_display
        INTO v_session
        FROM {SCHEMA}.browser_sessions s
        JOIN {SCHEMA}.accounts a ON a.id = s.account_id
        WHERE s.fingerprint = {SCHEMA}.identity_fingerprint(p_session_secret);
        IF NOT FOUND OR v_session.revoked_at IS NOT NULL OR v_session.expires_at <= v_now THEN
            v_refuse := true;
        END IF;
    END IF;
    -- A CSRF secret, when presented, must be this session's. A wrong one is refused with
    -- the same message as a wrong session: both say "not this session".
    IF NOT v_refuse AND p_csrf_secret IS NOT NULL THEN
        IF pg_catalog.length(p_csrf_secret) = 0
           OR v_session.csrf_fingerprint <> {SCHEMA}.identity_fingerprint(p_csrf_secret) THEN
            v_refuse := true;
        ELSE
            v_csrf := true;
        END IF;
    END IF;
    -- The membership behind the binding, re-derived now. A binding whose membership is
    -- gone is dropped here, belt to the cascade trigger's braces.
    IF NOT v_refuse AND v_session.workspace_id IS NOT NULL THEN
        SELECT m.role INTO v_role
        FROM {SCHEMA}.memberships m
        WHERE m.id = v_session.membership_id
          AND m.tenant_id = v_session.tenant_id
          AND m.workspace_id = v_session.workspace_id
          AND m.account_id = v_session.account_id
          AND m.revoked_at IS NULL;
        IF FOUND THEN
            v_workspace := v_session.workspace_id;
            v_tenant := v_session.tenant_id;
            v_membership := v_session.membership_id;
        ELSE
            UPDATE {SCHEMA}.browser_sessions
            SET workspace_id = NULL, tenant_id = NULL, membership_id = NULL, bound_at = NULL
            WHERE id = v_session.id;
        END IF;
    END IF;
    IF NOT v_refuse AND p_mode = 'workspace'
       AND (v_workspace IS NULL OR v_session.status <> 'active') THEN
        v_refuse := true;
    END IF;
    -- One raise site, one message: an unknown secret, a revoked or expired session, a
    -- wrong CSRF token and an unbound session asked for in workspace mode are all this.
    IF v_refuse THEN
        RAISE EXCEPTION '{IDENTITY_REFUSED_MESSAGE}'
            USING ERRCODE = '{IDENTITY_REFUSED_SQLSTATE}';
    END IF;
    IF p_mode = 'workspace' THEN
        PERFORM {SCHEMA}.auth_context_begin(
            NULL, v_tenant, v_session.account_id, '{SESSION_ACTOR_KIND}',
            {SCHEMA}.membership_role_scopes(v_role)
        );
    END IF;
    PERFORM {SCHEMA}.identity_context_write(
        'session', v_session.account_id, v_session.id, v_workspace, v_tenant, v_membership,
        v_role, v_csrf, NULL
    );
    UPDATE {SCHEMA}.browser_sessions SET last_seen_at = v_now WHERE id = v_session.id;
    RETURN QUERY SELECT v_session.id, v_session.account_id, v_session.email_display,
                        v_session.status = 'active', v_workspace, v_tenant, v_membership,
                        v_role, v_session.expires_at, v_csrf;
END;
$function$
"""

_ACCOUNT_PROFILE = f"""
CREATE FUNCTION {SCHEMA}.account_profile()
RETURNS TABLE (account_id uuid, email text, email_verified boolean, created_at timestamptz)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
BEGIN
    v_session := {SCHEMA}.identity_require_session('account', false);
    RETURN QUERY SELECT a.id, a.email_display, a.status = 'active', a.created_at
                 FROM {SCHEMA}.accounts a WHERE a.id = v_session.account_id;
END;
$function$
"""

_ACCOUNT_SESSIONS = f"""
CREATE FUNCTION {SCHEMA}.account_sessions()
RETURNS TABLE (
    session_id uuid, created_at timestamptz, last_seen_at timestamptz, expires_at timestamptz,
    workspace_id uuid, is_current boolean
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
BEGIN
    v_session := {SCHEMA}.identity_require_session('account', false);
    -- Live sessions only, and only this account's. Fingerprints are not among the columns
    -- this returns, and there is no function that returns one.
    RETURN QUERY SELECT s.id, s.created_at, s.last_seen_at, s.expires_at, s.workspace_id,
                        s.id = v_session.session_id
                 FROM {SCHEMA}.browser_sessions s
                 WHERE s.account_id = v_session.account_id
                   AND s.revoked_at IS NULL
                   AND s.expires_at > pg_catalog.clock_timestamp()
                 ORDER BY s.created_at, s.id;
END;
$function$
"""

_REVOKE_BROWSER_SESSION = f"""
CREATE FUNCTION {SCHEMA}.revoke_browser_session(p_session_id uuid) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_count integer;
BEGIN
    v_session := {SCHEMA}.identity_require_session('account', true);
    -- This account's sessions and no other's. Another account's, an unknown id and an
    -- already-revoked session all return false, indistinguishably.
    UPDATE {SCHEMA}.browser_sessions
    SET revoked_at = pg_catalog.clock_timestamp()
    WHERE id = p_session_id AND account_id = v_session.account_id AND revoked_at IS NULL;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count > 0;
END;
$function$
"""

_REVOKE_ALL_BROWSER_SESSIONS = f"""
CREATE FUNCTION {SCHEMA}.revoke_all_browser_sessions(p_keep_current boolean) RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_count integer;
BEGIN
    v_session := {SCHEMA}.identity_require_session('account', true);
    UPDATE {SCHEMA}.browser_sessions
    SET revoked_at = pg_catalog.clock_timestamp()
    WHERE account_id = v_session.account_id
      AND revoked_at IS NULL
      AND (NOT COALESCE(p_keep_current, false) OR id <> v_session.session_id);
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$function$
"""

# ------------------------------------------------------------------------ workspaces

#: The workspaces this account may choose from -- derived at the boundary from its active
#: memberships, which is the question ``AUTH-MEMBERSHIP-BOUND-IDENTITY`` said nothing
#: answered. Reads ``workspaces`` across tenants as the schema owner, which FORCE row
#: security would refuse with no context, so the join is written against ``memberships``
#: first and the workspace row is fetched by its composite key.
_ACCOUNT_WORKSPACES = f"""
CREATE FUNCTION {SCHEMA}.account_workspaces()
RETURNS TABLE (workspace_id uuid, tenant_id uuid, slug text, name text, role text,
               membership_id uuid, joined_at timestamptz)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
BEGIN
    v_session := {SCHEMA}.identity_require_session('account', false);
    RETURN QUERY
        SELECT m.workspace_id, m.tenant_id, w.slug, w.name, m.role, m.id, m.created_at
        FROM {SCHEMA}.memberships m
        JOIN {SCHEMA}.workspace_directory w
          ON w.id = m.workspace_id AND w.tenant_id = m.tenant_id
        WHERE m.account_id = v_session.account_id
          AND m.revoked_at IS NULL
        ORDER BY m.created_at, m.id;
END;
$function$
"""

#: The first-workspace operation, and in Milestone 3.1 every workspace operation: a
#: workspace is created with its own tenant, so the customer-visible unit of membership is
#: also the database's unit of isolation. Tenant, workspace and owner membership are
#: written by this one call or none of them are.
#:
#: The tenant id is generated here, exactly as ``begin_tenant_provisioning()`` generates
#: it, and the transaction acquires that tenant's context with the owner permission set plus
#: ``tenant:provision`` for the tenant row's own insert policy -- the Milestone 2.3
#: provisioning transaction's shape, confined the same way. The tenant slug is generated
#: too: a tenant slug is globally unique, so a customer-chosen one would be a cross-tenant
#: existence oracle, and the customer's slug is the workspace's, which is tenant-local.
_CREATE_WORKSPACE = f"""
CREATE FUNCTION {SCHEMA}.create_workspace(p_slug text, p_name text, p_idempotency_key text)
RETURNS TABLE (workspace_id uuid, tenant_id uuid, membership_id uuid, event_id uuid,
               record_id uuid, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_status text;
    v_fingerprint text;
    v_existing record;
    v_tenant uuid;
    v_workspace uuid;
    v_membership uuid;
    v_claim record;
    v_result jsonb;
    v_shape text;
BEGIN
    v_session := {SCHEMA}.identity_require_session('account', true);
    SELECT a.status INTO v_status FROM {SCHEMA}.accounts a WHERE a.id = v_session.account_id;
    IF v_status IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION 'firmbatch: creating a workspace requires a verified account'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- Shape before format, and neither echoes.
    v_shape := {SCHEMA}.secret_shape(p_slug);
    IF v_shape IS NOT NULL THEN
        RAISE EXCEPTION 'firmbatch: the workspace slug looks like %', v_shape
            USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
    END IF;
    IF p_slug IS NULL OR p_slug !~ '{SLUG_REGEX}' THEN
        RAISE EXCEPTION 'firmbatch: the workspace slug is not a lowercase DNS-safe identifier'
            USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
    END IF;
    v_shape := {SCHEMA}.secret_shape(p_name);
    IF v_shape IS NOT NULL THEN
        RAISE EXCEPTION 'firmbatch: the workspace name looks like %', v_shape
            USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
    END IF;
    IF p_name IS NULL OR pg_catalog.length(p_name) < 1 OR pg_catalog.length(p_name) > {NAME_MAX_LENGTH} THEN
        RAISE EXCEPTION 'firmbatch: the workspace name is between 1 and % characters', {NAME_MAX_LENGTH}
            USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
    END IF;
    IF p_idempotency_key IS NOT NULL THEN
        v_shape := {SCHEMA}.secret_shape(p_idempotency_key);
        IF v_shape IS NOT NULL OR p_idempotency_key !~ '{IDEMPOTENCY_KEY_REGEX}' THEN
            RAISE EXCEPTION 'firmbatch: the idempotency key is not acceptable'
                USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
        END IF;
        v_fingerprint := {SCHEMA}.identity_request_fingerprint(pg_catalog.jsonb_build_object(
            'account', v_session.account_id, 'operation', 'workspace.create',
            'slug', p_slug, 'name', p_name
        ));
        SELECT r.request_fingerprint, r.result INTO v_existing
        FROM {SCHEMA}.account_idempotency_records r
        WHERE r.account_id = v_session.account_id
          AND r.operation = 'workspace.create'
          AND r.idempotency_key = p_idempotency_key;
        IF FOUND THEN
            IF v_existing.request_fingerprint <> v_fingerprint THEN
                RAISE EXCEPTION 'firmbatch: the idempotency key was already used for a different request'
                    USING ERRCODE = '{IDENTITY_KEY_REUSE_SQLSTATE}';
            END IF;
            RETURN QUERY SELECT (v_existing.result->>'workspace_id')::uuid,
                                (v_existing.result->>'tenant_id')::uuid,
                                (v_existing.result->>'membership_id')::uuid,
                                (v_existing.result->>'event_id')::uuid,
                                (v_existing.result->>'record_id')::uuid, true;
            RETURN;
        END IF;
    END IF;

    BEGIN
        v_tenant := pg_catalog.gen_random_uuid();
        v_workspace := pg_catalog.gen_random_uuid();
        v_membership := pg_catalog.gen_random_uuid();
        PERFORM {SCHEMA}.auth_context_begin(
            NULL, v_tenant, v_session.account_id, '{SESSION_ACTOR_KIND}',
            {SCHEMA}.membership_role_scopes('owner') || ARRAY['tenant:provision']::text[]
        );
        INSERT INTO {SCHEMA}.tenants (id, slug, name)
        VALUES (v_tenant,
                'ws-' || pg_catalog.left(pg_catalog.replace(pg_catalog.gen_random_uuid()::text, '-', ''), 20),
                p_name);
        INSERT INTO {SCHEMA}.workspaces (id, tenant_id, slug, name)
        VALUES (v_workspace, v_tenant, p_slug, p_name);
        INSERT INTO {SCHEMA}.memberships (id, tenant_id, workspace_id, account_id, role)
        VALUES (v_membership, v_tenant, v_workspace, v_session.account_id, 'owner');
        v_result := pg_catalog.jsonb_build_object(
            'workspace_id', v_workspace::text, 'tenant_id', v_tenant::text,
            'membership_id', v_membership::text
        );
        SELECT * INTO v_claim FROM {SCHEMA}.identity_claim(
            'workspace.create', p_idempotency_key, v_fingerprint, v_result,
            'workspace.created', 'workspace', v_workspace,
            pg_catalog.jsonb_build_object('slug', p_slug, 'membership_id', v_membership::text)
        );
        IF p_idempotency_key IS NOT NULL THEN
            INSERT INTO {SCHEMA}.account_idempotency_records
                (account_id, operation, idempotency_key, request_fingerprint, result)
            VALUES (v_session.account_id, 'workspace.create', p_idempotency_key, v_fingerprint,
                    v_result || pg_catalog.jsonb_build_object(
                        'event_id', v_claim.event_id::text, 'record_id', v_claim.record_id::text));
        END IF;
        PERFORM {SCHEMA}.append_audit_event(
            'workspace.created', 'succeeded', 'workspace', v_workspace, NULL,
            pg_catalog.jsonb_build_object('slug', p_slug, 'membership_id', v_membership::text,
                                          'role', 'owner', 'session_id', v_session.session_id::text)
        );
        -- The provisioning capability was for the three inserts above. What the caller's
        -- transaction holds from here on is the owner membership's own permissions.
        PERFORM {SCHEMA}.identity_context_narrow({SCHEMA}.membership_role_scopes('owner'));
        RETURN QUERY SELECT v_workspace, v_tenant, v_membership, v_claim.event_id, v_claim.record_id, false;
        RETURN;
    EXCEPTION WHEN unique_violation THEN
        -- A lost race on the account-level claim: everything above, the tenant context
        -- included, is rolled back with this block, and the winner's result is returned.
        -- Any other unique violation keeps the refusal it earned.
        IF p_idempotency_key IS NULL THEN
            RAISE;
        END IF;
        SELECT r.request_fingerprint, r.result INTO v_existing
        FROM {SCHEMA}.account_idempotency_records r
        WHERE r.account_id = v_session.account_id
          AND r.operation = 'workspace.create'
          AND r.idempotency_key = p_idempotency_key;
        IF NOT FOUND THEN
            RAISE;
        END IF;
        IF v_existing.request_fingerprint <> v_fingerprint THEN
            RAISE EXCEPTION 'firmbatch: the idempotency key was already used for a different request'
                USING ERRCODE = '{IDENTITY_KEY_REUSE_SQLSTATE}';
        END IF;
        RETURN QUERY SELECT (v_existing.result->>'workspace_id')::uuid,
                            (v_existing.result->>'tenant_id')::uuid,
                            (v_existing.result->>'membership_id')::uuid,
                            (v_existing.result->>'event_id')::uuid,
                            (v_existing.result->>'record_id')::uuid, true;
        RETURN;
    END;
END;
$function$
"""

#: Selecting a workspace: the session binds only through an active membership of its own
#: account, found here, and the transaction acquires that tenant's context so the binding
#: is recorded in the tenant's audit trail. An absent workspace, another tenant's, and one
#: the account is not a member of are the same refusal.
_BIND_SESSION_WORKSPACE = f"""
CREATE FUNCTION {SCHEMA}.bind_session_workspace(p_workspace_id uuid)
RETURNS TABLE (workspace_id uuid, tenant_id uuid, membership_id uuid, role text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_status text;
    v_member record;
    v_refuse boolean := false;
BEGIN
    v_session := {SCHEMA}.identity_require_session('account', true);
    SELECT a.status INTO v_status FROM {SCHEMA}.accounts a WHERE a.id = v_session.account_id;
    IF v_status IS DISTINCT FROM 'active' THEN
        v_refuse := true;
    ELSIF p_workspace_id IS NULL THEN
        v_refuse := true;
    ELSE
        SELECT m.id, m.tenant_id, m.role INTO v_member
        FROM {SCHEMA}.memberships m
        WHERE m.workspace_id = p_workspace_id
          AND m.account_id = v_session.account_id
          AND m.revoked_at IS NULL;
        IF NOT FOUND THEN
            v_refuse := true;
        END IF;
    END IF;
    IF v_refuse THEN
        RAISE EXCEPTION '{IDENTITY_REFUSED_MESSAGE}'
            USING ERRCODE = '{IDENTITY_REFUSED_SQLSTATE}';
    END IF;
    UPDATE {SCHEMA}.browser_sessions
    SET workspace_id = p_workspace_id, tenant_id = v_member.tenant_id,
        membership_id = v_member.id, bound_at = pg_catalog.clock_timestamp()
    WHERE id = v_session.session_id AND revoked_at IS NULL;
    PERFORM {SCHEMA}.auth_context_begin(
        NULL, v_member.tenant_id, v_session.account_id, '{SESSION_ACTOR_KIND}',
        {SCHEMA}.membership_role_scopes(v_member.role)
    );
    PERFORM {SCHEMA}.append_audit_event(
        'session.bound', 'succeeded', 'browser_session', v_session.session_id, NULL,
        pg_catalog.jsonb_build_object('workspace_id', p_workspace_id::text,
                                      'membership_id', v_member.id::text, 'role', v_member.role)
    );
    RETURN QUERY SELECT p_workspace_id, v_member.tenant_id, v_member.id, v_member.role;
END;
$function$
"""

_UNBIND_SESSION_WORKSPACE = f"""
CREATE FUNCTION {SCHEMA}.unbind_session_workspace() RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_count integer;
BEGIN
    v_session := {SCHEMA}.identity_require_session('account', true);
    UPDATE {SCHEMA}.browser_sessions
    SET workspace_id = NULL, tenant_id = NULL, membership_id = NULL, bound_at = NULL
    WHERE id = v_session.session_id AND revoked_at IS NULL AND workspace_id IS NOT NULL;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count > 0;
END;
$function$
"""

_RENAME_WORKSPACE = f"""
CREATE FUNCTION {SCHEMA}.rename_workspace(p_name text, p_idempotency_key text)
RETURNS TABLE (workspace_id uuid, name text, event_id uuid, record_id uuid, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_fingerprint text;
    v_replay record;
    v_claim record;
    v_shape text;
    v_count integer;
BEGIN
    v_session := {SCHEMA}.identity_require_session('workspace', true);
    -- A cheap pre-filter on the cached context; the authoritative check is remade under
    -- the workspace lock below against the caller's membership as it is now.
    IF NOT {SCHEMA}.auth_has_scope('workspace:write') THEN
        RAISE EXCEPTION 'firmbatch: renaming a workspace requires the workspace:write scope'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    v_shape := {SCHEMA}.secret_shape(p_name);
    IF v_shape IS NOT NULL THEN
        RAISE EXCEPTION 'firmbatch: the workspace name looks like %', v_shape
            USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
    END IF;
    IF p_name IS NULL OR pg_catalog.length(p_name) < 1 OR pg_catalog.length(p_name) > {NAME_MAX_LENGTH} THEN
        RAISE EXCEPTION 'firmbatch: the workspace name is between 1 and % characters', {NAME_MAX_LENGTH}
            USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
    END IF;
    IF p_idempotency_key IS NOT NULL THEN
        v_shape := {SCHEMA}.secret_shape(p_idempotency_key);
        IF v_shape IS NOT NULL OR p_idempotency_key !~ '{IDEMPOTENCY_KEY_REGEX}' THEN
            RAISE EXCEPTION 'firmbatch: the idempotency key is not acceptable'
                USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
        END IF;
        v_fingerprint := {SCHEMA}.identity_request_fingerprint(pg_catalog.jsonb_build_object(
            'tenant', v_session.tenant_id, 'operation', 'workspace.rename',
            'workspace', v_session.workspace_id, 'name', p_name
        ));
    END IF;
    -- The workspace row lock is the serialisation point for every workspace-mode mutation
    -- that reads a fact it is about to change, and the caller's authority is re-derived
    -- under it: a session demoted below workspace:write since it bound cannot rename,
    -- whatever its cached context says. The replay check runs after both, so that two
    -- identical concurrent requests both come back with the winner's result and a demoted
    -- caller cannot replay its way past the authority check.
    v_session := {SCHEMA}.workspace_membership_authority('workspace:write', true);
    SELECT * INTO v_replay FROM {SCHEMA}.identity_replay('workspace.rename', p_idempotency_key, v_fingerprint);
    IF v_replay.found THEN
        RETURN QUERY SELECT v_session.workspace_id, (v_replay.result->>'name')::text,
                            v_replay.event_id, v_replay.record_id, true;
        RETURN;
    END IF;
    UPDATE {SCHEMA}.workspaces w
    SET name = p_name, updated_at = pg_catalog.clock_timestamp()
    WHERE w.id = v_session.workspace_id AND w.tenant_id = v_session.tenant_id;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    IF v_count = 0 THEN
        RAISE EXCEPTION '{IDENTITY_REFUSED_MESSAGE}'
            USING ERRCODE = '{IDENTITY_REFUSED_SQLSTATE}';
    END IF;
    SELECT * INTO v_claim FROM {SCHEMA}.identity_claim(
        'workspace.rename', p_idempotency_key, v_fingerprint,
        pg_catalog.jsonb_build_object('workspace_id', v_session.workspace_id::text, 'name', p_name),
        'workspace.renamed', 'workspace', v_session.workspace_id,
        pg_catalog.jsonb_build_object('name', p_name)
    );
    PERFORM {SCHEMA}.append_audit_event(
        'workspace.renamed', 'succeeded', 'workspace', v_session.workspace_id, NULL,
        pg_catalog.jsonb_build_object('name', p_name, 'session_id', v_session.session_id::text)
    );
    RETURN QUERY SELECT v_session.workspace_id, p_name, v_claim.event_id, v_claim.record_id, false;
END;
$function$
"""

# ------------------------------------------------------------------------ memberships

_WORKSPACE_MEMBERSHIPS = f"""
CREATE FUNCTION {SCHEMA}.workspace_memberships()
RETURNS TABLE (membership_id uuid, account_id uuid, email text, role text, created_at timestamptz)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
BEGIN
    -- The disclosure is decided by the membership as it is now, under the workspace lock,
    -- and not by the scope set the session cached at bind time. VOLATILE because it takes
    -- that lock.
    v_session := {SCHEMA}.workspace_membership_authority('membership:read', false);
    RETURN QUERY
        SELECT m.id, m.account_id, a.email_display, m.role, m.created_at
        FROM {SCHEMA}.memberships m
        JOIN {SCHEMA}.accounts a ON a.id = m.account_id
        WHERE m.workspace_id = v_session.workspace_id
          AND m.tenant_id = v_session.tenant_id
          AND m.revoked_at IS NULL
        ORDER BY m.created_at, m.id;
END;
$function$
"""

#: Removing a member. Serialised on the workspace row lock so that "is this the last
#: owner" is answered against committed state; the cascade trigger on ``memberships``
#: revokes every API credential the membership issued and unbinds every session bound
#: through it in the same statement sequence.
_REMOVE_MEMBERSHIP = f"""
CREATE FUNCTION {SCHEMA}.remove_membership(p_membership_id uuid, p_idempotency_key text)
RETURNS TABLE (membership_id uuid, event_id uuid, record_id uuid, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_caller_role text;
    v_fingerprint text;
    v_replay record;
    v_target record;
    v_claim record;
    v_shape text;
    v_refuse boolean := false;
BEGIN
    v_session := {SCHEMA}.identity_require_session('workspace', true);
    -- A cheap pre-filter on the cached context; the authoritative check is remade under the
    -- workspace lock below against the caller's membership as it is now.
    IF NOT {SCHEMA}.auth_has_scope('membership:manage') THEN
        RAISE EXCEPTION 'firmbatch: removing a membership requires the membership:manage scope'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_idempotency_key IS NOT NULL THEN
        v_shape := {SCHEMA}.secret_shape(p_idempotency_key);
        IF v_shape IS NOT NULL OR p_idempotency_key !~ '{IDEMPOTENCY_KEY_REGEX}' THEN
            RAISE EXCEPTION 'firmbatch: the idempotency key is not acceptable'
                USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
        END IF;
        v_fingerprint := {SCHEMA}.identity_request_fingerprint(pg_catalog.jsonb_build_object(
            'tenant', v_session.tenant_id, 'operation', 'membership.remove',
            'workspace', v_session.workspace_id, 'membership', p_membership_id
        ));
    END IF;
    -- The workspace lock, and the caller's OWN membership and role re-read under it. A
    -- caller demoted below a manager by a concurrent owner cannot remove anyone, whatever
    -- its session cached; the replay check runs after, so it cannot replay past this.
    v_session := {SCHEMA}.workspace_membership_authority('membership:manage', true);
    v_caller_role := v_session.role;
    SELECT * INTO v_replay FROM {SCHEMA}.identity_replay('membership.remove', p_idempotency_key, v_fingerprint);
    IF v_replay.found THEN
        RETURN QUERY SELECT p_membership_id, v_replay.event_id, v_replay.record_id, true;
        RETURN;
    END IF;
    SELECT m.id, m.role, m.account_id INTO v_target
    FROM {SCHEMA}.memberships m
    WHERE m.id = p_membership_id
      AND m.workspace_id = v_session.workspace_id
      AND m.tenant_id = v_session.tenant_id
      AND m.revoked_at IS NULL;
    IF NOT FOUND THEN
        v_refuse := true;
    END IF;
    -- One raise site for the neutral refusal: absent, another workspace's, another
    -- tenant's and already-revoked are one answer.
    IF v_refuse THEN
        RAISE EXCEPTION '{IDENTITY_REFUSED_MESSAGE}'
            USING ERRCODE = '{IDENTITY_REFUSED_SQLSTATE}';
    END IF;
    -- The owner-only rules. Both are about a membership the caller can already see, so
    -- they may say what they refuse.
    IF v_target.role = 'owner' AND v_caller_role <> 'owner' THEN
        RAISE EXCEPTION 'firmbatch: only an owner may remove an owner membership'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF v_target.role = 'owner'
       AND {SCHEMA}.identity_active_owner_count(v_session.workspace_id, v_session.tenant_id) <= 1 THEN
        RAISE EXCEPTION 'firmbatch: the last active owner of a workspace cannot be removed'
            USING ERRCODE = '{IDENTITY_CONFLICT_SQLSTATE}',
                  DETAIL = 'promote another member to owner first';
    END IF;
    UPDATE {SCHEMA}.memberships
    SET revoked_at = pg_catalog.clock_timestamp(), revoked_by_account_id = v_session.account_id
    WHERE id = v_target.id AND tenant_id = v_session.tenant_id AND revoked_at IS NULL;
    SELECT * INTO v_claim FROM {SCHEMA}.identity_claim(
        'membership.remove', p_idempotency_key, v_fingerprint,
        pg_catalog.jsonb_build_object('membership_id', v_target.id::text),
        'membership.revoked', 'membership', v_target.id,
        pg_catalog.jsonb_build_object('role', v_target.role)
    );
    PERFORM {SCHEMA}.append_audit_event(
        'membership.revoked', 'succeeded', 'membership', v_target.id, NULL,
        pg_catalog.jsonb_build_object('role', v_target.role, 'account_id', v_target.account_id::text,
                                      'session_id', v_session.session_id::text)
    );
    RETURN QUERY SELECT v_target.id, v_claim.event_id, v_claim.record_id, false;
END;
$function$
"""

_CHANGE_MEMBERSHIP_ROLE = f"""
CREATE FUNCTION {SCHEMA}.change_membership_role(p_membership_id uuid, p_role text, p_idempotency_key text)
RETURNS TABLE (membership_id uuid, role text, event_id uuid, record_id uuid, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_caller_role text;
    v_fingerprint text;
    v_replay record;
    v_target record;
    v_claim record;
    v_shape text;
    v_refuse boolean := false;
BEGIN
    v_session := {SCHEMA}.identity_require_session('workspace', true);
    -- A cheap pre-filter on the cached context; the authoritative authority check is remade
    -- under the workspace lock below against the caller's membership as it is now.
    IF NOT {SCHEMA}.auth_has_scope('membership:manage') THEN
        RAISE EXCEPTION 'firmbatch: changing a membership role requires the membership:manage scope'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_role IS NULL OR NOT (p_role = ANY (ARRAY[{_quoted_list(MEMBERSHIP_ROLES)}]::text[])) THEN
        RAISE EXCEPTION 'firmbatch: the membership role is not in the closed model'
            USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
    END IF;
    IF p_idempotency_key IS NOT NULL THEN
        v_shape := {SCHEMA}.secret_shape(p_idempotency_key);
        IF v_shape IS NOT NULL OR p_idempotency_key !~ '{IDEMPOTENCY_KEY_REGEX}' THEN
            RAISE EXCEPTION 'firmbatch: the idempotency key is not acceptable'
                USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
        END IF;
        v_fingerprint := {SCHEMA}.identity_request_fingerprint(pg_catalog.jsonb_build_object(
            'tenant', v_session.tenant_id, 'operation', 'membership.change_role',
            'workspace', v_session.workspace_id, 'membership', p_membership_id, 'role', p_role
        ));
    END IF;
    -- The workspace lock, and the caller's OWN membership and role re-read under it. A
    -- caller demoted by a concurrent owner between its bind and this statement acts on the
    -- role it holds now, never the one its session cached -- so a demoted owner cannot
    -- promote itself back, and a caller demoted below a manager cannot manage.
    v_session := {SCHEMA}.workspace_membership_authority('membership:manage', true);
    v_caller_role := v_session.role;
    SELECT * INTO v_replay FROM {SCHEMA}.identity_replay('membership.change_role', p_idempotency_key, v_fingerprint);
    IF v_replay.found THEN
        RETURN QUERY SELECT p_membership_id, p_role, v_replay.event_id, v_replay.record_id, true;
        RETURN;
    END IF;
    SELECT m.id, m.role, m.account_id INTO v_target
    FROM {SCHEMA}.memberships m
    WHERE m.id = p_membership_id
      AND m.workspace_id = v_session.workspace_id
      AND m.tenant_id = v_session.tenant_id
      AND m.revoked_at IS NULL;
    IF NOT FOUND THEN
        v_refuse := true;
    END IF;
    IF v_refuse THEN
        RAISE EXCEPTION '{IDENTITY_REFUSED_MESSAGE}'
            USING ERRCODE = '{IDENTITY_REFUSED_SQLSTATE}';
    END IF;
    IF (v_target.role = 'owner' OR p_role = 'owner') AND v_caller_role <> 'owner' THEN
        RAISE EXCEPTION 'firmbatch: only an owner may change a membership role to or from owner'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF v_target.role = 'owner' AND p_role <> 'owner'
       AND {SCHEMA}.identity_active_owner_count(v_session.workspace_id, v_session.tenant_id) <= 1 THEN
        RAISE EXCEPTION 'firmbatch: the last active owner of a workspace cannot be demoted'
            USING ERRCODE = '{IDENTITY_CONFLICT_SQLSTATE}',
                  DETAIL = 'promote another member to owner first';
    END IF;
    UPDATE {SCHEMA}.memberships
    SET role = p_role, updated_at = pg_catalog.clock_timestamp()
    WHERE id = v_target.id AND tenant_id = v_session.tenant_id AND revoked_at IS NULL;
    -- A role change is a change of authority for every session bound through this
    -- membership and every credential it issued. Sessions re-derive their scopes at the
    -- next bind; credentials keep the scopes they were issued with, which the new role may
    -- no longer permit -- so a demotion revokes them, and a promotion leaves them as the
    -- narrower set they were.
    IF NOT (pg_catalog.array_length({SCHEMA}.membership_role_scopes(v_target.role), 1) <=
            pg_catalog.array_length({SCHEMA}.membership_role_scopes(p_role), 1)
            AND {SCHEMA}.membership_role_scopes(v_target.role) <@ {SCHEMA}.membership_role_scopes(p_role)) THEN
        UPDATE {SCHEMA}.auth_bindings
        SET revoked_at = pg_catalog.clock_timestamp()
        WHERE membership_id = v_target.id AND tenant_id = v_session.tenant_id AND revoked_at IS NULL;
    END IF;
    SELECT * INTO v_claim FROM {SCHEMA}.identity_claim(
        'membership.change_role', p_idempotency_key, v_fingerprint,
        pg_catalog.jsonb_build_object('membership_id', v_target.id::text, 'role', p_role),
        'membership.role_changed', 'membership', v_target.id,
        pg_catalog.jsonb_build_object('role', p_role, 'previous_role', v_target.role)
    );
    PERFORM {SCHEMA}.append_audit_event(
        'membership.role_changed', 'succeeded', 'membership', v_target.id, NULL,
        pg_catalog.jsonb_build_object('role', p_role, 'previous_role', v_target.role,
                                      'account_id', v_target.account_id::text,
                                      'session_id', v_session.session_id::text)
    );
    RETURN QUERY SELECT v_target.id, p_role, v_claim.event_id, v_claim.record_id, false;
END;
$function$
"""

# ------------------------------------------------------------------------ invitations

#: An invitation is bound to a workspace, a tenant, a recipient address, a role and an
#: expiry, and it is one-time: acceptance locks the row and consumes it. The secret is
#: minted here and returned once, for the email-delivery boundary to carry; the row holds
#: its fingerprint. A replay of the creating request returns the invitation and no secret.
_CREATE_INVITATION = f"""
CREATE FUNCTION {SCHEMA}.create_invitation(p_email text, p_role text, p_ttl interval, p_idempotency_key text)
RETURNS TABLE (invitation_id uuid, invitation_secret text, expires_at timestamptz,
               event_id uuid, record_id uuid, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_caller_role text;
    v_email text;
    v_fingerprint text;
    v_replay record;
    v_claim record;
    v_shape text;
    v_id uuid;
    v_secret text;
    v_expires timestamptz;
BEGIN
    v_session := {SCHEMA}.identity_require_session('workspace', true);
    -- A cheap pre-filter on the cached context; the authoritative authority check, including
    -- the owner-only rule on inviting at the owner role, is remade under the workspace lock.
    IF NOT {SCHEMA}.auth_has_scope('membership:manage') THEN
        RAISE EXCEPTION 'firmbatch: inviting a member requires the membership:manage scope'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    v_email := {SCHEMA}.identity_normalize_email(p_email);
    IF v_email IS NULL THEN
        RAISE EXCEPTION 'firmbatch: the email address is not acceptable'
            USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
    END IF;
    IF p_role IS NULL OR NOT (p_role = ANY (ARRAY[{_quoted_list(MEMBERSHIP_ROLES)}]::text[])) THEN
        RAISE EXCEPTION 'firmbatch: the membership role is not in the closed model'
            USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
    END IF;
    PERFORM {SCHEMA}.identity_require_ttl(p_ttl, INTERVAL '{MAX_INVITATION_TTL}');
    IF p_idempotency_key IS NOT NULL THEN
        v_shape := {SCHEMA}.secret_shape(p_idempotency_key);
        IF v_shape IS NOT NULL OR p_idempotency_key !~ '{IDEMPOTENCY_KEY_REGEX}' THEN
            RAISE EXCEPTION 'firmbatch: the idempotency key is not acceptable'
                USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
        END IF;
        v_fingerprint := {SCHEMA}.identity_request_fingerprint(pg_catalog.jsonb_build_object(
            'tenant', v_session.tenant_id, 'operation', 'invitation.create',
            'workspace', v_session.workspace_id, 'email', v_email, 'role', p_role
        ));
    END IF;
    -- The workspace lock, and the caller's OWN membership and role re-read under it. A
    -- caller demoted below a manager cannot invite, and only a *current* owner may invite
    -- at the owner role.
    v_session := {SCHEMA}.workspace_membership_authority('membership:manage', true);
    v_caller_role := v_session.role;
    IF p_role = 'owner' AND v_caller_role <> 'owner' THEN
        RAISE EXCEPTION 'firmbatch: only an owner may invite at the owner role'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT * INTO v_replay FROM {SCHEMA}.identity_replay('invitation.create', p_idempotency_key, v_fingerprint);
    IF v_replay.found THEN
        RETURN QUERY SELECT (v_replay.result->>'invitation_id')::uuid, NULL::text,
                            (v_replay.result->>'expires_at')::timestamptz,
                            v_replay.event_id, v_replay.record_id, true;
        RETURN;
    END IF;
    -- Already a member: a conflict the caller can see in the member list, so it is named.
    IF EXISTS (
        SELECT 1 FROM {SCHEMA}.memberships m
        JOIN {SCHEMA}.accounts a ON a.id = m.account_id
        WHERE m.workspace_id = v_session.workspace_id AND m.tenant_id = v_session.tenant_id
          AND m.revoked_at IS NULL AND a.email_normalized = v_email
    ) THEN
        RAISE EXCEPTION 'firmbatch: that address already belongs to an active member of this workspace'
            USING ERRCODE = '{IDENTITY_CONFLICT_SQLSTATE}';
    END IF;
    -- One pending invitation per address per workspace. An expired one is revoked here so
    -- it does not block a fresh one; a live one is a conflict the inviter can see.
    UPDATE {SCHEMA}.workspace_invitations
    SET revoked_at = pg_catalog.clock_timestamp()
    WHERE workspace_id = v_session.workspace_id AND tenant_id = v_session.tenant_id
      AND email_normalized = v_email AND accepted_at IS NULL AND revoked_at IS NULL
      AND expires_at <= pg_catalog.clock_timestamp();
    IF EXISTS (
        SELECT 1 FROM {SCHEMA}.workspace_invitations i
        WHERE i.workspace_id = v_session.workspace_id AND i.tenant_id = v_session.tenant_id
          AND i.email_normalized = v_email AND i.accepted_at IS NULL AND i.revoked_at IS NULL
    ) THEN
        RAISE EXCEPTION 'firmbatch: that address already holds a pending invitation to this workspace'
            USING ERRCODE = '{IDENTITY_CONFLICT_SQLSTATE}',
                  DETAIL = 'revoke it first';
    END IF;
    v_id := pg_catalog.gen_random_uuid();
    v_secret := {SCHEMA}.identity_mint_secret('{IDENTITY_SECRET_PREFIXES["invitation"]}');
    v_expires := pg_catalog.clock_timestamp() + p_ttl;
    INSERT INTO {SCHEMA}.workspace_invitations
        (id, tenant_id, workspace_id, email_normalized, role, fingerprint, invited_by_account_id, expires_at)
    VALUES (v_id, v_session.tenant_id, v_session.workspace_id, v_email, p_role,
            {SCHEMA}.identity_fingerprint(v_secret), v_session.account_id, v_expires);
    SELECT * INTO v_claim FROM {SCHEMA}.identity_claim(
        'invitation.create', p_idempotency_key, v_fingerprint,
        pg_catalog.jsonb_build_object('invitation_id', v_id::text, 'role', p_role,
                                      'expires_at', v_expires::text),
        'invitation.created', 'workspace_invitation', v_id,
        pg_catalog.jsonb_build_object('role', p_role)
    );
    PERFORM {SCHEMA}.append_audit_event(
        'invitation.created', 'succeeded', 'workspace_invitation', v_id, NULL,
        pg_catalog.jsonb_build_object('role', p_role, 'session_id', v_session.session_id::text)
    );
    RETURN QUERY SELECT v_id, v_secret, v_expires, v_claim.event_id, v_claim.record_id, false;
END;
$function$
"""

_REVOKE_INVITATION = f"""
CREATE FUNCTION {SCHEMA}.revoke_invitation(p_invitation_id uuid, p_idempotency_key text)
RETURNS TABLE (revoked boolean, event_id uuid, record_id uuid, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_fingerprint text;
    v_replay record;
    v_claim record;
    v_shape text;
    v_count integer;
BEGIN
    v_session := {SCHEMA}.identity_require_session('workspace', true);
    -- A cheap pre-filter on the cached context; the authoritative check is remade under
    -- the workspace lock below against the caller's membership as it is now.
    IF NOT {SCHEMA}.auth_has_scope('membership:manage') THEN
        RAISE EXCEPTION 'firmbatch: revoking an invitation requires the membership:manage scope'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_idempotency_key IS NOT NULL THEN
        v_shape := {SCHEMA}.secret_shape(p_idempotency_key);
        IF v_shape IS NOT NULL OR p_idempotency_key !~ '{IDEMPOTENCY_KEY_REGEX}' THEN
            RAISE EXCEPTION 'firmbatch: the idempotency key is not acceptable'
                USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
        END IF;
        v_fingerprint := {SCHEMA}.identity_request_fingerprint(pg_catalog.jsonb_build_object(
            'tenant', v_session.tenant_id, 'operation', 'invitation.revoke',
            'workspace', v_session.workspace_id, 'invitation', p_invitation_id
        ));
    END IF;
    -- The lock and the membership revalidation, before the replay lookup: a caller demoted
    -- below a manager since it bound may neither revoke nor replay a revocation.
    v_session := {SCHEMA}.workspace_membership_authority('membership:manage', true);
    SELECT * INTO v_replay FROM {SCHEMA}.identity_replay('invitation.revoke', p_idempotency_key, v_fingerprint);
    IF v_replay.found THEN
        RETURN QUERY SELECT (v_replay.result->>'revoked')::boolean, v_replay.event_id, v_replay.record_id, true;
        RETURN;
    END IF;
    -- Absent, another workspace's, already accepted and already revoked all answer false.
    UPDATE {SCHEMA}.workspace_invitations
    SET revoked_at = pg_catalog.clock_timestamp()
    WHERE id = p_invitation_id AND workspace_id = v_session.workspace_id
      AND tenant_id = v_session.tenant_id AND accepted_at IS NULL AND revoked_at IS NULL;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    SELECT * INTO v_claim FROM {SCHEMA}.identity_claim(
        'invitation.revoke', p_idempotency_key, v_fingerprint,
        pg_catalog.jsonb_build_object('revoked', v_count > 0),
        'invitation.revoked', 'workspace_invitation', p_invitation_id,
        pg_catalog.jsonb_build_object('revoked', v_count > 0)
    );
    PERFORM {SCHEMA}.append_audit_event(
        'invitation.revoked', CASE WHEN v_count > 0 THEN 'succeeded' ELSE 'failed' END,
        'workspace_invitation', CASE WHEN v_count > 0 THEN p_invitation_id ELSE NULL END, NULL,
        pg_catalog.jsonb_build_object('session_id', v_session.session_id::text)
    );
    RETURN QUERY SELECT v_count > 0, v_claim.event_id, v_claim.record_id, false;
END;
$function$
"""

_WORKSPACE_INVITATIONS = f"""
CREATE FUNCTION {SCHEMA}.workspace_invitations()
RETURNS TABLE (invitation_id uuid, email text, role text, created_at timestamptz,
               expires_at timestamptz, status text)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
BEGIN
    -- The manager-only listing is decided by the membership as it is now, under the
    -- workspace lock: a session demoted out of management since it bound sees nothing.
    -- VOLATILE because it takes that lock.
    v_session := {SCHEMA}.workspace_membership_authority('membership:manage', false);
    RETURN QUERY
        SELECT i.id, i.email_normalized, i.role, i.created_at, i.expires_at,
               CASE
                   WHEN i.accepted_at IS NOT NULL THEN 'accepted'
                   WHEN i.revoked_at IS NOT NULL THEN 'revoked'
                   WHEN i.expires_at <= pg_catalog.clock_timestamp() THEN 'expired'
                   ELSE 'pending'
               END
        FROM {SCHEMA}.workspace_invitations i
        WHERE i.workspace_id = v_session.workspace_id AND i.tenant_id = v_session.tenant_id
        ORDER BY i.created_at, i.id;
END;
$function$
"""

#: Acceptance: the intended recipient, holding the secret, signed in and verified. The
#: invitation row is locked before anything is decided, so two acceptances serialise and
#: exactly one consumes it; the replay check runs after the lock so that the second of two
#: identical requests comes back with the first's result rather than a refusal. A wrong
#: recipient, an expired, revoked or consumed invitation, and a secret nobody issued are one
#: answer. The transaction acquires the invitation's tenant context as the new member --
#: the same shape as ``create_workspace`` -- so the membership is recorded in that tenant's
#: audit trail and outbox; the session itself stays account-level until it selects the
#: workspace.
_ACCEPT_INVITATION = f"""
CREATE FUNCTION {SCHEMA}.accept_invitation(p_secret text, p_idempotency_key text)
RETURNS TABLE (workspace_id uuid, tenant_id uuid, membership_id uuid, role text,
               event_id uuid, record_id uuid, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_account record;
    v_fingerprint text;
    v_existing record;
    v_invitation record;
    v_membership uuid;
    v_claim record;
    v_result jsonb;
    v_shape text;
    v_refuse boolean := false;
    v_now timestamptz;
    v_scopes text[];
BEGIN
    v_session := {SCHEMA}.identity_require_session('account', true);
    SELECT a.status, a.email_normalized INTO v_account
    FROM {SCHEMA}.accounts a WHERE a.id = v_session.account_id;
    IF v_account.status IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION 'firmbatch: accepting an invitation requires a verified account'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_idempotency_key IS NOT NULL THEN
        v_shape := {SCHEMA}.secret_shape(p_idempotency_key);
        IF v_shape IS NOT NULL OR p_idempotency_key !~ '{IDEMPOTENCY_KEY_REGEX}' THEN
            RAISE EXCEPTION 'firmbatch: the idempotency key is not acceptable'
                USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
        END IF;
        -- The descriptor carries the secret's fingerprint, never the secret.
        v_fingerprint := {SCHEMA}.identity_request_fingerprint(pg_catalog.jsonb_build_object(
            'account', v_session.account_id, 'operation', 'invitation.accept',
            'invitation_fingerprint', {SCHEMA}.identity_fingerprint(COALESCE(p_secret, ''))
        ));
    END IF;
    v_now := pg_catalog.clock_timestamp();
    IF p_secret IS NULL OR pg_catalog.length(p_secret) = 0 THEN
        v_refuse := true;
    ELSE
        SELECT i.id, i.tenant_id, i.workspace_id, i.email_normalized, i.role,
               i.expires_at, i.accepted_at, i.revoked_at
        INTO v_invitation
        FROM {SCHEMA}.workspace_invitations i
        WHERE i.fingerprint = {SCHEMA}.identity_fingerprint(p_secret)
        FOR UPDATE;
        IF NOT FOUND THEN
            v_refuse := true;
        END IF;
    END IF;
    -- The replay check, after the lock and before the validity check: a retry of the
    -- acceptance that consumed this invitation replays rather than being refused.
    IF p_idempotency_key IS NOT NULL THEN
        SELECT r.request_fingerprint, r.result INTO v_existing
        FROM {SCHEMA}.account_idempotency_records r
        WHERE r.account_id = v_session.account_id
          AND r.operation = 'invitation.accept'
          AND r.idempotency_key = p_idempotency_key;
        IF FOUND THEN
            IF v_existing.request_fingerprint <> v_fingerprint THEN
                RAISE EXCEPTION 'firmbatch: the idempotency key was already used for a different request'
                    USING ERRCODE = '{IDENTITY_KEY_REUSE_SQLSTATE}';
            END IF;
            RETURN QUERY SELECT (v_existing.result->>'workspace_id')::uuid,
                                (v_existing.result->>'tenant_id')::uuid,
                                (v_existing.result->>'membership_id')::uuid,
                                (v_existing.result->>'role')::text,
                                (v_existing.result->>'event_id')::uuid,
                                (v_existing.result->>'record_id')::uuid, true;
            RETURN;
        END IF;
    END IF;
    IF NOT v_refuse AND (
        v_invitation.email_normalized <> v_account.email_normalized
        OR v_invitation.accepted_at IS NOT NULL
        OR v_invitation.revoked_at IS NOT NULL
        OR v_invitation.expires_at <= v_now
    ) THEN
        v_refuse := true;
    END IF;
    IF v_refuse THEN
        RAISE EXCEPTION '{IDENTITY_REFUSED_MESSAGE}'
            USING ERRCODE = '{IDENTITY_REFUSED_SQLSTATE}';
    END IF;
    IF EXISTS (
        SELECT 1 FROM {SCHEMA}.memberships m
        WHERE m.workspace_id = v_invitation.workspace_id AND m.tenant_id = v_invitation.tenant_id
          AND m.account_id = v_session.account_id AND m.revoked_at IS NULL
    ) THEN
        RAISE EXCEPTION 'firmbatch: this account is already an active member of that workspace'
            USING ERRCODE = '{IDENTITY_CONFLICT_SQLSTATE}';
    END IF;
    BEGIN
        v_membership := pg_catalog.gen_random_uuid();
        -- The claim and the event below are the acceptance's own writes, and the policies
        -- on those tables ask the context for mutation:execute -- which a viewer does not
        -- hold. The capability is added for these statements and taken away again before
        -- control returns; see identity_context_narrow.
        v_scopes := {SCHEMA}.membership_role_scopes(v_invitation.role);
        PERFORM {SCHEMA}.auth_context_begin(
            NULL, v_invitation.tenant_id, v_session.account_id, '{SESSION_ACTOR_KIND}',
            CASE WHEN 'mutation:execute' = ANY (v_scopes) THEN v_scopes
                 ELSE v_scopes || ARRAY['mutation:execute']::text[] END
        );
        INSERT INTO {SCHEMA}.memberships (id, tenant_id, workspace_id, account_id, role, invited_by_account_id)
        SELECT v_membership, v_invitation.tenant_id, v_invitation.workspace_id, v_session.account_id,
               v_invitation.role, i.invited_by_account_id
        FROM {SCHEMA}.workspace_invitations i WHERE i.id = v_invitation.id;
        UPDATE {SCHEMA}.workspace_invitations
        SET accepted_at = v_now, accepted_membership_id = v_membership
        WHERE id = v_invitation.id;
        v_result := pg_catalog.jsonb_build_object(
            'workspace_id', v_invitation.workspace_id::text, 'tenant_id', v_invitation.tenant_id::text,
            'membership_id', v_membership::text, 'role', v_invitation.role
        );
        SELECT * INTO v_claim FROM {SCHEMA}.identity_claim(
            'invitation.accept', p_idempotency_key, v_fingerprint, v_result,
            'membership.created', 'membership', v_membership,
            pg_catalog.jsonb_build_object('role', v_invitation.role, 'invitation_id', v_invitation.id::text)
        );
        IF p_idempotency_key IS NOT NULL THEN
            INSERT INTO {SCHEMA}.account_idempotency_records
                (account_id, operation, idempotency_key, request_fingerprint, result)
            VALUES (v_session.account_id, 'invitation.accept', p_idempotency_key, v_fingerprint,
                    v_result || pg_catalog.jsonb_build_object(
                        'event_id', v_claim.event_id::text, 'record_id', v_claim.record_id::text));
        END IF;
        PERFORM {SCHEMA}.append_audit_event(
            'membership.created', 'succeeded', 'membership', v_membership, NULL,
            pg_catalog.jsonb_build_object('role', v_invitation.role, 'invitation_id', v_invitation.id::text,
                                          'session_id', v_session.session_id::text)
        );
        PERFORM {SCHEMA}.identity_context_narrow(v_scopes);
        RETURN QUERY SELECT v_invitation.workspace_id, v_invitation.tenant_id, v_membership,
                            v_invitation.role, v_claim.event_id, v_claim.record_id, false;
        RETURN;
    EXCEPTION WHEN unique_violation THEN
        IF p_idempotency_key IS NULL THEN
            RAISE;
        END IF;
        SELECT r.request_fingerprint, r.result INTO v_existing
        FROM {SCHEMA}.account_idempotency_records r
        WHERE r.account_id = v_session.account_id
          AND r.operation = 'invitation.accept'
          AND r.idempotency_key = p_idempotency_key;
        IF NOT FOUND THEN
            RAISE;
        END IF;
        IF v_existing.request_fingerprint <> v_fingerprint THEN
            RAISE EXCEPTION 'firmbatch: the idempotency key was already used for a different request'
                USING ERRCODE = '{IDENTITY_KEY_REUSE_SQLSTATE}';
        END IF;
        RETURN QUERY SELECT (v_existing.result->>'workspace_id')::uuid,
                            (v_existing.result->>'tenant_id')::uuid,
                            (v_existing.result->>'membership_id')::uuid,
                            (v_existing.result->>'role')::text,
                            (v_existing.result->>'event_id')::uuid,
                            (v_existing.result->>'record_id')::uuid, true;
        RETURN;
    END;
END;
$function$
"""

# ------------------------------------------------------------------------ credentials

#: The issuer. A verified, workspace-bound session holding ``credential:issue`` explicitly
#: authorizes a new API credential for **its own membership**: the membership is re-read
#: and must be active, every requested scope must be in the closed Milestone 2.3 catalogue,
#: in the issuable subset and in the member's own effective permissions, and what comes
#: back is a freshly minted secret -- not the session's secret in another shape. The
#: binding carries the membership it was issued from, which is what the revocation cascade
#: acts on.
_ISSUE_API_CREDENTIAL = f"""
CREATE FUNCTION {SCHEMA}.issue_api_credential(
    p_scopes text[], p_expires_at timestamptz, p_label text, p_idempotency_key text
) RETURNS TABLE (binding_id uuid, credential text, scopes text[], expires_at timestamptz,
                 event_id uuid, record_id uuid, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_role text;
    v_permitted text[];
    v_requested text[];
    v_scope text;
    v_fingerprint text;
    v_replay record;
    v_claim record;
    v_shape text;
    v_id uuid;
    v_credential text;
    v_epoch integer;
    v_attempt integer := 0;
BEGIN
    v_session := {SCHEMA}.identity_require_session('workspace', true);
    -- A cheap pre-filter on the bound (cached) context. The authoritative capability check
    -- is remade under the workspace lock below against the membership as it is *now*, so a
    -- caller demoted since it bound is refused even though its cached context still says
    -- credential:issue.
    IF NOT {SCHEMA}.auth_has_scope('credential:issue') THEN
        RAISE EXCEPTION 'firmbatch: issuing an API credential requires the credential:issue permission'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- Input shape validation that needs no membership. Done before the lock so the lock is
    -- held for as little as possible; the scope *authority* check waits for the fresh role.
    v_requested := COALESCE(p_scopes, ARRAY[]::text[]);
    IF pg_catalog.array_ndims(v_requested) > 1 THEN
        RAISE EXCEPTION 'firmbatch: a scope set is a one-dimensional array'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF pg_catalog.cardinality(v_requested) > {MAX_SCOPES_PER_BINDING}
       OR pg_catalog.cardinality(v_requested)
          <> (SELECT pg_catalog.count(DISTINCT s) FROM pg_catalog.unnest(v_requested) AS s) THEN
        RAISE EXCEPTION 'firmbatch: the requested scope set is bounded and repeats nothing'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the rejected values are deliberately not shown';
    END IF;
    IF p_label IS NOT NULL THEN
        v_shape := {SCHEMA}.secret_shape(p_label);
        IF v_shape IS NOT NULL THEN
            RAISE EXCEPTION 'firmbatch: the credential label looks like %', v_shape
                USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
        END IF;
        IF pg_catalog.length(p_label) < 1 OR pg_catalog.length(p_label) > {LABEL_MAX_LENGTH} THEN
            RAISE EXCEPTION 'firmbatch: the credential label is between 1 and % characters', {LABEL_MAX_LENGTH}
                USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
        END IF;
    END IF;
    IF p_expires_at IS NOT NULL AND p_expires_at <= pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION 'firmbatch: an API credential expiry is in the future'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_idempotency_key IS NOT NULL THEN
        v_shape := {SCHEMA}.secret_shape(p_idempotency_key);
        IF v_shape IS NOT NULL OR p_idempotency_key !~ '{IDEMPOTENCY_KEY_REGEX}' THEN
            RAISE EXCEPTION 'firmbatch: the idempotency key is not acceptable'
                USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
        END IF;
    END IF;
    -- The workspace serialiser is taken **before** the membership is read, so that issuance
    -- and every membership mutation (removal, demotion, rotation) share one lock and one
    -- order. A concurrent removal or demotion either commits before this lock -- in which
    -- case the re-read finds no active membership and refuses -- or after it, in which case
    -- its revocation cascade sees the binding this call commits. The credential-issuance
    -- race is closed by the lock ordering, not by hoping the snapshots align. The
    -- authoritative capability check is against the freshly read role: a membership demoted
    -- below credential:issue since the bind cannot issue, whatever its cached context said.
    v_session := {SCHEMA}.workspace_membership_authority('credential:issue', true);
    v_role := v_session.role;
    v_permitted := {SCHEMA}.membership_role_scopes(v_role);
    -- Unknown scopes are refused here rather than left to the scopes_known constraint,
    -- because a constraint violation renders the failing row in its DETAIL.
    FOREACH v_scope IN ARRAY v_requested LOOP
        IF v_scope IS NULL OR NOT (v_scope = ANY (ARRAY[{_quoted_list(KNOWN_SCOPES)}]::text[])) THEN
            RAISE EXCEPTION 'firmbatch: the requested scope set names a scope that is not in the catalogue'
                USING ERRCODE = 'invalid_parameter_value',
                      DETAIL = 'the rejected value is deliberately not shown';
        END IF;
        IF NOT (v_scope = ANY (ARRAY[{_quoted_list(API_ISSUABLE_SCOPES)}]::text[])) THEN
            RAISE EXCEPTION 'firmbatch: the requested scope set names a scope that may not be placed on an API credential'
                USING ERRCODE = 'insufficient_privilege',
                      DETAIL = 'credential:manage and the membership permissions are session-only; the '
                               'rejected value is deliberately not shown';
        END IF;
        IF NOT (v_scope = ANY (v_permitted)) THEN
            RAISE EXCEPTION 'firmbatch: the requested scope set exceeds what this membership may issue'
                USING ERRCODE = 'insufficient_privilege',
                      DETAIL = 'an API credential carries a subset of the issuing member''s own effective '
                               'permissions; the rejected value is deliberately not shown';
        END IF;
    END LOOP;
    SELECT pg_catalog.array_agg(s ORDER BY s) INTO v_requested FROM pg_catalog.unnest(v_requested) AS s;
    v_requested := COALESCE(v_requested, ARRAY[]::text[]);
    IF p_idempotency_key IS NOT NULL THEN
        v_fingerprint := {SCHEMA}.identity_request_fingerprint(pg_catalog.jsonb_build_object(
            'tenant', v_session.tenant_id, 'operation', 'credential.issue',
            'membership', v_session.membership_id, 'scopes', pg_catalog.to_jsonb(v_requested),
            'label', p_label, 'expires_at', p_expires_at
        ));
    END IF;
    SELECT * INTO v_replay FROM {SCHEMA}.identity_replay('credential.issue', p_idempotency_key, v_fingerprint);
    IF v_replay.found THEN
        -- The secret was displayed once, when it was minted. A replay says so by returning
        -- the binding and no credential.
        RETURN QUERY SELECT (v_replay.result->>'binding_id')::uuid, NULL::text, v_requested,
                            (v_replay.result->>'expires_at')::timestamptz,
                            v_replay.event_id, v_replay.record_id, true;
        RETURN;
    END IF;
    -- The account's current security epoch, stamped on the binding so that a later account
    -- recovery -- which increments it -- invalidates this credential at bearer authentication.
    SELECT a.security_epoch INTO v_epoch FROM {SCHEMA}.accounts a WHERE a.id = v_session.account_id;
    LOOP
        v_attempt := v_attempt + 1;
        v_id := pg_catalog.gen_random_uuid();
        v_credential := {SCHEMA}.identity_mint_secret('fbk_');
        INSERT INTO {SCHEMA}.auth_bindings
            (id, tenant_id, principal_id, fingerprint, scopes, expires_at, membership_id, workspace_id,
             label, principal_epoch)
        VALUES (v_id, v_session.tenant_id, v_session.account_id,
                {SCHEMA}.identity_fingerprint(v_credential), v_requested, p_expires_at,
                v_session.membership_id, v_session.workspace_id, p_label, v_epoch)
        ON CONFLICT (fingerprint) DO NOTHING;
        EXIT WHEN FOUND;
        IF v_attempt >= 3 THEN
            RAISE EXCEPTION 'firmbatch: could not mint a distinct API credential'
                USING ERRCODE = 'internal_error';
        END IF;
    END LOOP;
    SELECT * INTO v_claim FROM {SCHEMA}.identity_claim(
        'credential.issue', p_idempotency_key, v_fingerprint,
        pg_catalog.jsonb_build_object('binding_id', v_id::text, 'scope_count', pg_catalog.cardinality(v_requested),
                                      'expires_at', p_expires_at::text),
        'credential.issued', 'api_credential', v_id,
        pg_catalog.jsonb_build_object('membership_id', v_session.membership_id::text,
                                      'scope_count', pg_catalog.cardinality(v_requested))
    );
    PERFORM {SCHEMA}.append_audit_event(
        'credential.issued', 'succeeded', 'api_credential', v_id, NULL,
        pg_catalog.jsonb_build_object('membership_id', v_session.membership_id::text,
                                      'scope_count', pg_catalog.cardinality(v_requested),
                                      'expires', p_expires_at IS NOT NULL,
                                      'session_id', v_session.session_id::text)
    );
    RETURN QUERY SELECT v_id, v_credential, v_requested, p_expires_at, v_claim.event_id, v_claim.record_id, false;
END;
$function$
"""

#: Rotation is an atomic cutover: the old binding is locked, a new one is minted with the
#: same scopes, label and membership, and the old one is revoked in the same statement
#: sequence. Only the member whose membership issued the credential may rotate it -- a
#: rotated credential authenticates as that member, and handing its secret to anybody else
#: would be impersonation dressed as administration. A manager revokes; it does not rotate.
_ROTATE_API_CREDENTIAL = f"""
CREATE FUNCTION {SCHEMA}.rotate_api_credential(p_binding_id uuid, p_expires_at timestamptz, p_idempotency_key text)
RETURNS TABLE (binding_id uuid, credential text, scopes text[], expires_at timestamptz,
               rotated_from_id uuid, event_id uuid, record_id uuid, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_old record;
    v_fingerprint text;
    v_replay record;
    v_claim record;
    v_shape text;
    v_id uuid;
    v_credential text;
    v_expires timestamptz;
    v_epoch integer;
    v_attempt integer := 0;
    v_count integer;
    v_refuse boolean := false;
BEGIN
    v_session := {SCHEMA}.identity_require_session('workspace', true);
    -- A cheap pre-filter on the cached context; the authoritative check is remade under
    -- the workspace lock below against the membership as it is now.
    IF NOT {SCHEMA}.auth_has_scope('credential:issue') THEN
        RAISE EXCEPTION 'firmbatch: rotating an API credential requires the credential:issue permission'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_expires_at IS NOT NULL AND p_expires_at <= pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION 'firmbatch: an API credential expiry is in the future'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_idempotency_key IS NOT NULL THEN
        v_shape := {SCHEMA}.secret_shape(p_idempotency_key);
        IF v_shape IS NOT NULL OR p_idempotency_key !~ '{IDEMPOTENCY_KEY_REGEX}' THEN
            RAISE EXCEPTION 'firmbatch: the idempotency key is not acceptable'
                USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
        END IF;
        v_fingerprint := {SCHEMA}.identity_request_fingerprint(pg_catalog.jsonb_build_object(
            'tenant', v_session.tenant_id, 'operation', 'credential.rotate',
            'membership', v_session.membership_id, 'binding', p_binding_id, 'expires_at', p_expires_at
        ));
    END IF;
    -- The workspace serialiser, taken before the membership is read and the successor is
    -- inserted, is the same lock every membership mutation takes and in the same order.
    -- Rotation and a concurrent removal or demotion therefore serialise: if the mutation
    -- commits first, the membership revalidation refuses; if rotation commits first, the
    -- mutation's revocation cascade sees -- and revokes -- the successor this call inserts.
    -- Without it a successor minted under an earlier statement snapshot could outlive the
    -- membership it belongs to. A membership demoted below credential:issue since the bind
    -- cannot rotate, whatever its cached context claimed.
    PERFORM {SCHEMA}.workspace_membership_authority('credential:issue', true);
    -- Then the old binding, locked. It is selected by the session's membership, so a
    -- manager may revoke another member's credential and rotate none but its own.
    IF p_binding_id IS NULL THEN
        v_refuse := true;
    ELSE
        SELECT b.id, b.scopes, b.label, b.expires_at, b.revoked_at INTO v_old
        FROM {SCHEMA}.auth_bindings b
        WHERE b.id = p_binding_id AND b.tenant_id = v_session.tenant_id
          AND b.workspace_id = v_session.workspace_id AND b.membership_id = v_session.membership_id
        FOR UPDATE;
        IF NOT FOUND THEN
            v_refuse := true;
        END IF;
    END IF;
    IF NOT v_refuse THEN
        SELECT * INTO v_replay FROM {SCHEMA}.identity_replay('credential.rotate', p_idempotency_key, v_fingerprint);
        IF v_replay.found THEN
            RETURN QUERY SELECT (v_replay.result->>'binding_id')::uuid, NULL::text, v_old.scopes,
                                (v_replay.result->>'expires_at')::timestamptz, p_binding_id,
                                v_replay.event_id, v_replay.record_id, true;
            RETURN;
        END IF;
        -- **A dead credential is not rotated** (Milestone 3.1 security correction,
        -- credential-expiry finding). Revoked and expired are one state here, exactly as
        -- they are at ``bind_authenticated_context``: rotation is the atomic cutover of a
        -- *live* credential, and it carries the predecessor's scope set forward without
        -- rebounding it by the member's current role -- so letting an elapsed credential
        -- rotate would revive a scope set the member may no longer hold. The narrowest
        -- fail-closed rule consistent with decision 5 is therefore that an expired
        -- credential is refused rotation and must be re-issued, which is the audited
        -- operation that does rebound the scopes. ADR 0009 records it.
        IF v_old.revoked_at IS NOT NULL
           OR (v_old.expires_at IS NOT NULL AND v_old.expires_at <= pg_catalog.clock_timestamp()) THEN
            v_refuse := true;
        END IF;
    END IF;
    IF v_refuse THEN
        RAISE EXCEPTION '{IDENTITY_REFUSED_MESSAGE}'
            USING ERRCODE = '{IDENTITY_REFUSED_SQLSTATE}';
    END IF;
    -- The successor's expiry: the one supplied, else the predecessor's, which the refusal
    -- above has already established is absent or in the future. An elapsed expiry is
    -- **never** turned into NULL -- that silently promoted a dying credential into one
    -- that never expires. The guard is kept as a refusal rather than removed, so that a
    -- future edit which admits an elapsed predecessor cannot reintroduce the promotion.
    v_expires := COALESCE(p_expires_at, v_old.expires_at);
    IF v_expires IS NOT NULL AND v_expires <= pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION '{IDENTITY_REFUSED_MESSAGE}'
            USING ERRCODE = '{IDENTITY_REFUSED_SQLSTATE}';
    END IF;
    -- The account's current security epoch, stamped on the successor as on any issuance.
    SELECT a.security_epoch INTO v_epoch FROM {SCHEMA}.accounts a WHERE a.id = v_session.account_id;
    LOOP
        v_attempt := v_attempt + 1;
        v_id := pg_catalog.gen_random_uuid();
        v_credential := {SCHEMA}.identity_mint_secret('fbk_');
        INSERT INTO {SCHEMA}.auth_bindings
            (id, tenant_id, principal_id, fingerprint, scopes, expires_at, membership_id, workspace_id,
             label, rotated_from_id, principal_epoch)
        VALUES (v_id, v_session.tenant_id, v_session.account_id,
                {SCHEMA}.identity_fingerprint(v_credential), v_old.scopes, v_expires,
                v_session.membership_id, v_session.workspace_id, v_old.label, v_old.id, v_epoch)
        ON CONFLICT (fingerprint) DO NOTHING;
        EXIT WHEN FOUND;
        IF v_attempt >= 3 THEN
            RAISE EXCEPTION 'firmbatch: could not mint a distinct API credential'
                USING ERRCODE = 'internal_error';
        END IF;
    END LOOP;
    UPDATE {SCHEMA}.auth_bindings
    SET revoked_at = pg_catalog.clock_timestamp()
    WHERE id = v_old.id AND tenant_id = v_session.tenant_id AND revoked_at IS NULL;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    IF v_count <> 1 THEN
        RAISE EXCEPTION 'firmbatch: the credential being rotated changed underneath the rotation'
            USING ERRCODE = 'internal_error';
    END IF;
    SELECT * INTO v_claim FROM {SCHEMA}.identity_claim(
        'credential.rotate', p_idempotency_key, v_fingerprint,
        pg_catalog.jsonb_build_object('binding_id', v_id::text, 'rotated_from_id', v_old.id::text,
                                      'expires_at', v_expires::text),
        'credential.rotated', 'api_credential', v_id,
        pg_catalog.jsonb_build_object('rotated_from_id', v_old.id::text,
                                      'membership_id', v_session.membership_id::text)
    );
    PERFORM {SCHEMA}.append_audit_event(
        'credential.rotated', 'succeeded', 'api_credential', v_id, NULL,
        pg_catalog.jsonb_build_object('rotated_from_id', v_old.id::text,
                                      'membership_id', v_session.membership_id::text,
                                      'session_id', v_session.session_id::text)
    );
    RETURN QUERY SELECT v_id, v_credential, v_old.scopes, v_expires, v_old.id, v_claim.event_id, v_claim.record_id, false;
END;
$function$
"""

_REVOKE_API_CREDENTIAL = f"""
CREATE FUNCTION {SCHEMA}.revoke_api_credential(p_binding_id uuid, p_idempotency_key text)
RETURNS TABLE (revoked boolean, event_id uuid, record_id uuid, replayed boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_fingerprint text;
    v_replay record;
    v_claim record;
    v_shape text;
    v_manage boolean;
    v_count integer;
BEGIN
    v_session := {SCHEMA}.identity_require_session('workspace', true);
    -- A cheap pre-filter on the cached context; the authoritative check is remade under
    -- the workspace lock below against the caller's membership as it is now.
    IF NOT {SCHEMA}.auth_has_scope('credential:issue') THEN
        RAISE EXCEPTION 'firmbatch: revoking an API credential requires the credential:issue permission'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_idempotency_key IS NOT NULL THEN
        v_shape := {SCHEMA}.secret_shape(p_idempotency_key);
        IF v_shape IS NOT NULL OR p_idempotency_key !~ '{IDEMPOTENCY_KEY_REGEX}' THEN
            RAISE EXCEPTION 'firmbatch: the idempotency key is not acceptable'
                USING ERRCODE = 'invalid_parameter_value', DETAIL = 'the value is deliberately not shown';
        END IF;
        v_fingerprint := {SCHEMA}.identity_request_fingerprint(pg_catalog.jsonb_build_object(
            'tenant', v_session.tenant_id, 'operation', 'credential.revoke',
            'workspace', v_session.workspace_id, 'binding', p_binding_id
        ));
    END IF;
    -- The lock and the membership revalidation, before the replay lookup. The manager
    -- reach below is decided by the role read **here**, not by the session's cached scope
    -- set: a caller demoted out of management since it bound may revoke its own
    -- credentials and nobody else's.
    v_session := {SCHEMA}.workspace_membership_authority('credential:issue', true);
    v_manage := 'membership:manage' = ANY ({SCHEMA}.membership_role_scopes(v_session.role));
    SELECT * INTO v_replay FROM {SCHEMA}.identity_replay('credential.revoke', p_idempotency_key, v_fingerprint);
    IF v_replay.found THEN
        RETURN QUERY SELECT (v_replay.result->>'revoked')::boolean, v_replay.event_id, v_replay.record_id, true;
        RETURN;
    END IF;
    -- One's own credentials, or any credential of the workspace with membership:manage.
    -- Absent, another workspace's, another member's without that permission, and
    -- already revoked all answer false.
    UPDATE {SCHEMA}.auth_bindings b
    SET revoked_at = pg_catalog.clock_timestamp()
    WHERE b.id = p_binding_id AND b.tenant_id = v_session.tenant_id
      AND b.workspace_id = v_session.workspace_id AND b.membership_id IS NOT NULL
      AND (b.membership_id = v_session.membership_id OR v_manage)
      AND b.revoked_at IS NULL;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    SELECT * INTO v_claim FROM {SCHEMA}.identity_claim(
        'credential.revoke', p_idempotency_key, v_fingerprint,
        pg_catalog.jsonb_build_object('revoked', v_count > 0),
        'credential.revoked', 'api_credential', p_binding_id,
        pg_catalog.jsonb_build_object('revoked', v_count > 0)
    );
    PERFORM {SCHEMA}.append_audit_event(
        'credential.revoked', CASE WHEN v_count > 0 THEN 'succeeded' ELSE 'failed' END,
        'api_credential', CASE WHEN v_count > 0 THEN p_binding_id ELSE NULL END, NULL,
        pg_catalog.jsonb_build_object('session_id', v_session.session_id::text)
    );
    RETURN QUERY SELECT v_count > 0, v_claim.event_id, v_claim.record_id, false;
END;
$function$
"""

#: The safe listing: no fingerprint, no secret, and never a column that could hold one.
#: One's own credentials always; every credential of the workspace with
#: ``membership:manage``. Credentials provisioned out of band (Milestone 2.3's, with no
#: membership) are not workspace credentials and do not appear.
_WORKSPACE_API_CREDENTIALS = f"""
CREATE FUNCTION {SCHEMA}.workspace_api_credentials()
RETURNS TABLE (binding_id uuid, label text, scopes text[], created_at timestamptz,
               expires_at timestamptz, revoked_at timestamptz, last_used_at timestamptz,
               rotated_from_id uuid, membership_id uuid, account_id uuid, email text,
               active boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_manage boolean;
BEGIN
    -- The membership as it is now, under the workspace lock, and the manager reach derived
    -- from **that** role rather than from the session's cached scope set: a caller demoted
    -- out of management since it bound sees only its own credentials. VOLATILE because it
    -- takes the lock.
    v_session := {SCHEMA}.workspace_membership_authority(NULL, false);
    v_manage := 'membership:manage' = ANY ({SCHEMA}.membership_role_scopes(v_session.role));
    RETURN QUERY
        SELECT b.id, b.label, b.scopes, b.created_at, b.expires_at, b.revoked_at, b.last_used_at,
               b.rotated_from_id, b.membership_id, b.principal_id, a.email_display,
               -- **The lifecycle state is computed here, by the database** (Milestone 3.1
               -- security correction, credential-expiry finding): a credential is active
               -- only while it is neither revoked nor expired, and the clock that decides
               -- is PostgreSQL's, the same clock_timestamp() bind_authenticated_context
               -- compares against. A listing that derived "active" from revoked_at alone,
               -- or from an application clock, would show as usable a credential the
               -- bearer boundary already refuses.
               b.revoked_at IS NULL
                 AND (b.expires_at IS NULL OR b.expires_at > pg_catalog.clock_timestamp())
        FROM {SCHEMA}.auth_bindings b
        JOIN {SCHEMA}.accounts a ON a.id = b.principal_id
        WHERE b.tenant_id = v_session.tenant_id AND b.workspace_id = v_session.workspace_id
          AND b.membership_id IS NOT NULL
          AND (b.membership_id = v_session.membership_id OR v_manage)
        ORDER BY b.created_at, b.id;
END;
$function$
"""

#: Last-use tracking, recorded by the API-credential boundary after a successful bind. A
#: convenience metric rather than a security property: a raw-SQL caller that skips it
#: gains nothing, and a credential that never calls it merely shows no last use.
_RECORD_API_CREDENTIAL_USE = f"""
CREATE FUNCTION {SCHEMA}.record_api_credential_use() RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_context {SCHEMA}.auth_context_row;
BEGIN
    v_context := {SCHEMA}.auth_context();
    IF v_context.tenant_id IS NULL OR v_context.actor_kind <> 'credential' OR v_context.binding_id IS NULL THEN
        RAISE EXCEPTION 'firmbatch: recording credential use requires a credential-authenticated context'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    UPDATE {SCHEMA}.auth_bindings
    SET last_used_at = pg_catalog.clock_timestamp()
    WHERE id = v_context.binding_id AND tenant_id = v_context.tenant_id;
END;
$function$
"""


# --------------------------------------------- bind_authenticated_context (M2.3), revised
#
# Milestone 3.1 REPLACES migration 0003's bind_authenticated_context to add a membership and
# account-security-epoch recheck at bearer authentication -- the defence in depth the
# credential-race and recovery-persistence findings call for. ADR 0009 (revised) records the
# change; migration 0003 is unedited, and the downgrade restores its function body exactly, so
# a database taken back to 0004 is byte-for-byte what a fresh migration to 0004 produces.
# tests/test_identity_migration.py asserts the restore text equals 0003's constant verbatim.
_LEGACY_BIND_AUTHENTICATED_CONTEXT = f"""
CREATE FUNCTION {SCHEMA}.bind_authenticated_context(p_credential text) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_fingerprint text;
    v_binding record;
BEGIN
    -- The FIRST executed operation of this function, deliberately, and asserted from the
    -- catalogue by tests/test_authenticated_context.py. A caller reaching this function
    -- through raw SQL gets the same ordering the Python entry path gets: the standby and
    -- read-only diagnostic comes before the registry lookup, before the isolation-level
    -- check, and before anything touches the unlogged context relation.
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();

    IF p_credential IS NULL OR pg_catalog.length(p_credential) = 0 THEN
        RAISE EXCEPTION 'firmbatch: authentication failed'
            USING ERRCODE = 'invalid_password';
    END IF;

    -- The one place a credential is hashed, and the reason a raw one is never stored: the
    -- value arrives as a bound parameter, becomes a digest here, and is not referenced
    -- again. Nothing in this function returns, logs, or stores it.
    v_fingerprint := pg_catalog.encode(
        pg_catalog.sha256(pg_catalog.convert_to(p_credential, 'UTF8')), 'hex'
    );

    -- Read under this statement's own snapshot, which READ COMMITTED guarantees is taken
    -- now rather than when the transaction opened. That is the linearisation point: a
    -- revocation or an expiry committed before this statement began is observed; one
    -- committed while it runs is not.
    SELECT b.id, b.tenant_id, b.principal_id, b.scopes, b.expires_at, b.revoked_at
    INTO v_binding
    FROM {SCHEMA}.auth_bindings b
    WHERE b.fingerprint = v_fingerprint;

    -- One error for unknown, revoked and expired alike. Distinguishing them would tell a
    -- caller holding a wrong credential whether it was ever a right one. clock_timestamp()
    -- and not now(): now() is transaction-start time, so a long transaction would extend
    -- a credential's life by its own duration.
    IF NOT FOUND
       OR v_binding.revoked_at IS NOT NULL
       OR (v_binding.expires_at IS NOT NULL AND v_binding.expires_at <= pg_catalog.clock_timestamp())
    THEN
        RAISE EXCEPTION 'firmbatch: authentication failed'
            USING ERRCODE = 'invalid_password',
                  DETAIL = 'the presented authentication binding is unknown, revoked, or expired';
    END IF;

    PERFORM {SCHEMA}.auth_context_begin(
        v_binding.id, v_binding.tenant_id, v_binding.principal_id, 'credential', v_binding.scopes
    );
    RETURN v_binding.id;
END;
$function$
"""

_LEGACY_BIND_AUTHENTICATED_CONTEXT_RESTORE = f"""
CREATE OR REPLACE FUNCTION {SCHEMA}.bind_authenticated_context(p_credential text) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_fingerprint text;
    v_binding record;
BEGIN
    -- The FIRST executed operation of this function, deliberately, and asserted from the
    -- catalogue by tests/test_authenticated_context.py. A caller reaching this function
    -- through raw SQL gets the same ordering the Python entry path gets: the standby and
    -- read-only diagnostic comes before the registry lookup, before the isolation-level
    -- check, and before anything touches the unlogged context relation.
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();

    IF p_credential IS NULL OR pg_catalog.length(p_credential) = 0 THEN
        RAISE EXCEPTION 'firmbatch: authentication failed'
            USING ERRCODE = 'invalid_password';
    END IF;

    -- The one place a credential is hashed, and the reason a raw one is never stored: the
    -- value arrives as a bound parameter, becomes a digest here, and is not referenced
    -- again. Nothing in this function returns, logs, or stores it.
    v_fingerprint := pg_catalog.encode(
        pg_catalog.sha256(pg_catalog.convert_to(p_credential, 'UTF8')), 'hex'
    );

    -- Read under this statement's own snapshot, which READ COMMITTED guarantees is taken
    -- now rather than when the transaction opened. That is the linearisation point: a
    -- revocation or an expiry committed before this statement began is observed; one
    -- committed while it runs is not.
    SELECT b.id, b.tenant_id, b.principal_id, b.scopes, b.expires_at, b.revoked_at
    INTO v_binding
    FROM {SCHEMA}.auth_bindings b
    WHERE b.fingerprint = v_fingerprint;

    -- One error for unknown, revoked and expired alike. Distinguishing them would tell a
    -- caller holding a wrong credential whether it was ever a right one. clock_timestamp()
    -- and not now(): now() is transaction-start time, so a long transaction would extend
    -- a credential's life by its own duration.
    IF NOT FOUND
       OR v_binding.revoked_at IS NOT NULL
       OR (v_binding.expires_at IS NOT NULL AND v_binding.expires_at <= pg_catalog.clock_timestamp())
    THEN
        RAISE EXCEPTION 'firmbatch: authentication failed'
            USING ERRCODE = 'invalid_password',
                  DETAIL = 'the presented authentication binding is unknown, revoked, or expired';
    END IF;

    PERFORM {SCHEMA}.auth_context_begin(
        v_binding.id, v_binding.tenant_id, v_binding.principal_id, 'credential', v_binding.scopes
    );
    RETURN v_binding.id;
END;
$function$
"""

_BIND_AUTHENTICATED_CONTEXT_HEAD = f"""
CREATE OR REPLACE FUNCTION {SCHEMA}.bind_authenticated_context(p_credential text) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_fingerprint text;
    v_binding record;
BEGIN
    -- The FIRST executed operation of this function, deliberately, and asserted from the
    -- catalogue by tests/test_authenticated_context.py. A caller reaching this function
    -- through raw SQL gets the same ordering the Python entry path gets: the standby and
    -- read-only diagnostic comes before the registry lookup, before the isolation-level
    -- check, and before anything touches the unlogged context relation.
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();

    IF p_credential IS NULL OR pg_catalog.length(p_credential) = 0 THEN
        RAISE EXCEPTION 'firmbatch: authentication failed'
            USING ERRCODE = 'invalid_password';
    END IF;

    -- The one place a credential is hashed, and the reason a raw one is never stored: the
    -- value arrives as a bound parameter, becomes a digest here, and is not referenced
    -- again. Nothing in this function returns, logs, or stores it.
    v_fingerprint := pg_catalog.encode(
        pg_catalog.sha256(pg_catalog.convert_to(p_credential, 'UTF8')), 'hex'
    );

    -- Read under this statement's own snapshot, which READ COMMITTED guarantees is taken
    -- now rather than when the transaction opened. That is the linearisation point: a
    -- revocation or an expiry committed before this statement began is observed; one
    -- committed while it runs is not.
    SELECT b.id, b.tenant_id, b.principal_id, b.scopes, b.expires_at, b.revoked_at,
           b.membership_id, b.principal_epoch
    INTO v_binding
    FROM {SCHEMA}.auth_bindings b
    WHERE b.fingerprint = v_fingerprint;

    -- One error for unknown, revoked and expired alike. Distinguishing them would tell a
    -- caller holding a wrong credential whether it was ever a right one. clock_timestamp()
    -- and not now(): now() is transaction-start time, so a long transaction would extend
    -- a credential's life by its own duration.
    IF NOT FOUND
       OR v_binding.revoked_at IS NOT NULL
       OR (v_binding.expires_at IS NOT NULL AND v_binding.expires_at <= pg_catalog.clock_timestamp())
    THEN
        RAISE EXCEPTION 'firmbatch: authentication failed'
            USING ERRCODE = 'invalid_password',
                  DETAIL = 'the presented authentication binding is unknown, revoked, or expired';
    END IF;

    -- Milestone 3.1 defence in depth (security correction). A credential issued from a
    -- membership carries that membership and the account's security epoch as it stood when
    -- the credential was minted. It authenticates only while the membership is still active
    -- AND that epoch still matches -- so a membership revoked between issuance and this bind,
    -- and every credential an account held before a password recovery advanced its epoch, are
    -- refused here even if a revocation cascade or a visible-row sweep had not yet reached the
    -- binding. An out-of-band credential (no membership, NULL epoch) is unaffected.
    IF v_binding.membership_id IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM {SCHEMA}.memberships m
            WHERE m.id = v_binding.membership_id AND m.tenant_id = v_binding.tenant_id
              AND m.revoked_at IS NULL
        ) OR NOT EXISTS (
            SELECT 1 FROM {SCHEMA}.accounts a
            WHERE a.id = v_binding.principal_id AND a.security_epoch = v_binding.principal_epoch
        ) THEN
            RAISE EXCEPTION 'firmbatch: authentication failed'
                USING ERRCODE = 'invalid_password',
                      DETAIL = 'the presented authentication binding is unknown, revoked, or expired';
        END IF;
    END IF;

    PERFORM {SCHEMA}.auth_context_begin(
        v_binding.id, v_binding.tenant_id, v_binding.principal_id, 'credential', v_binding.scopes
    );
    RETURN v_binding.id;
END;
$function$
"""

# ------------------------------------------------------------------------ triggers

#: **Membership revocation invalidates what the membership issued, structurally.** A
#: ``BEFORE`` trigger, so it binds every writer of the row -- the identity functions, the
#: schema owner's DML, and the referential cascade of a workspace or tenant deletion --
#: and ``SECURITY DEFINER``, so it holds the privileges to act on the protected tables
#: whoever fired it. On revocation: every API credential issued from the membership is
#: revoked and every session bound through it is unbound, in the revoking statement's own
#: sequence, so the next bind of either observes it. On deletion the same, plus the links
#: are cleared so the foreign keys are satisfied. Un-revoking is refused, and so is any
#: change to the columns that say what the membership *is*.
_MEMBERSHIPS_REVOCATION_CASCADE = f"""
CREATE FUNCTION {SCHEMA}.memberships_revocation_cascade() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_now timestamptz;
BEGIN
    v_now := pg_catalog.clock_timestamp();
    IF TG_OP = 'DELETE' THEN
        UPDATE {SCHEMA}.auth_bindings
        SET revoked_at = COALESCE(revoked_at, v_now), membership_id = NULL, workspace_id = NULL
        WHERE membership_id = OLD.id AND tenant_id = OLD.tenant_id;
        UPDATE {SCHEMA}.browser_sessions
        SET workspace_id = NULL, tenant_id = NULL, membership_id = NULL, bound_at = NULL
        WHERE membership_id = OLD.id;
        UPDATE {SCHEMA}.workspace_invitations
        SET accepted_membership_id = NULL
        WHERE accepted_membership_id = OLD.id AND tenant_id = OLD.tenant_id;
        RETURN OLD;
    END IF;
    IF NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.workspace_id <> OLD.workspace_id
       OR NEW.account_id <> OLD.account_id OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'firmbatch: a membership''s identity, tenant, workspace, account and creation time are immutable'
            USING ERRCODE = '{IDENTITY_CONFLICT_SQLSTATE}';
    END IF;
    IF OLD.revoked_at IS NOT NULL THEN
        IF NEW.revoked_at IS NULL OR NEW.role <> OLD.role THEN
            RAISE EXCEPTION 'firmbatch: a revoked membership cannot be reinstated or re-roled'
                USING ERRCODE = '{IDENTITY_CONFLICT_SQLSTATE}',
                      DETAIL = 'invite the account again; revocation is final for the row it names';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.revoked_at IS NULL THEN
        RETURN NEW;
    END IF;
    NEW.revoked_at := v_now;
    NEW.updated_at := v_now;
    UPDATE {SCHEMA}.auth_bindings
    SET revoked_at = v_now
    WHERE membership_id = OLD.id AND tenant_id = OLD.tenant_id AND revoked_at IS NULL;
    UPDATE {SCHEMA}.browser_sessions
    SET workspace_id = NULL, tenant_id = NULL, membership_id = NULL, bound_at = NULL
    WHERE membership_id = OLD.id;
    RETURN NEW;
END;
$function$
"""

#: A protected directory of workspaces, maintained by a trigger on ``workspaces`` for every
#: writer, so that an account can be told the slug and name of each workspace it belongs
#: to across tenants -- which FORCE row security on ``workspaces`` would refuse to a
#: transaction that holds no tenant context yet. It carries nothing a workspace row does
#: not, no runtime role holds anything on it, and only ``account_workspaces()`` reads it.
_WORKSPACE_DIRECTORY_SYNC = f"""
CREATE FUNCTION {SCHEMA}.workspace_directory_sync() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM {SCHEMA}.workspace_directory WHERE id = OLD.id AND tenant_id = OLD.tenant_id;
        RETURN OLD;
    END IF;
    IF TG_OP = 'UPDATE' AND (NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id) THEN
        DELETE FROM {SCHEMA}.workspace_directory WHERE id = OLD.id AND tenant_id = OLD.tenant_id;
    END IF;
    INSERT INTO {SCHEMA}.workspace_directory (id, tenant_id, slug, name)
    VALUES (NEW.id, NEW.tenant_id, NEW.slug, NEW.name)
    ON CONFLICT (id) DO UPDATE SET tenant_id = excluded.tenant_id, slug = excluded.slug, name = excluded.name;
    RETURN NEW;
END;
$function$
"""

_ACCOUNT_TOKENS_APPEND_ONLY = f"""
CREATE FUNCTION {SCHEMA}.account_tokens_append_only() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
BEGIN
    -- A token row is written once and never mutated in place: what may change is that it is
    -- consumed or superseded, each exactly once and never undone. DELETE is deliberately
    -- **not** guarded here -- no runtime role holds DELETE on this protected table, so the
    -- only deletions are the schema owner's, and the one that exists is the cascade from
    -- purge_expired_unverified_accounts reclaiming an expired unverified account. Guarding
    -- DELETE would block that maintenance path without adding a boundary the absent grant
    -- does not already provide.
    IF NEW.id <> OLD.id OR NEW.account_id <> OLD.account_id OR NEW.kind <> OLD.kind
       OR NEW.fingerprint <> OLD.fingerprint OR NEW.created_at <> OLD.created_at
       OR NEW.expires_at <> OLD.expires_at
       OR (OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at)
       OR (OLD.superseded_at IS NOT NULL AND NEW.superseded_at IS DISTINCT FROM OLD.superseded_at) THEN
        RAISE EXCEPTION 'firmbatch: an account token may only be consumed or superseded, once'
            USING ERRCODE = '{IDENTITY_CONFLICT_SQLSTATE}';
    END IF;
    RETURN NEW;
END;
$function$
"""

_ACCOUNT_IDEMPOTENCY_RECORDS_APPEND_ONLY = f"""
CREATE FUNCTION {SCHEMA}.account_idempotency_records_append_only() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
BEGIN
    RAISE EXCEPTION 'firmbatch: account idempotency records are append-only'
        USING ERRCODE = '{IDENTITY_CONFLICT_SQLSTATE}';
END;
$function$
"""


def _alter_actor_constraints(kinds, shape: str) -> None:
    """Re-state the two actor constraints on both actor-carrying tables.

    Dropped and re-added under their existing names rather than added beside: two check
    constraints on one column would both have to pass, so the widening has to replace the
    narrower one. The names are the ones ``0003`` and ``0004`` produced through the naming
    convention, written out here because ``op.drop_constraint`` would re-apply the
    convention to a name that already carries it.
    """
    for table in ("audit_events", "lifecycle_transitions"):
        op.execute(f"ALTER TABLE {SCHEMA}.{table} DROP CONSTRAINT ck_{table}_actor_kind_known")
        op.execute(f"ALTER TABLE {SCHEMA}.{table} DROP CONSTRAINT ck_{table}_actor_shape")
        op.execute(
            f"ALTER TABLE {SCHEMA}.{table} ADD CONSTRAINT ck_{table}_actor_kind_known "
            f"CHECK (actor_kind IN ({_quoted_list(kinds)}))"
        )
        op.execute(
            f"ALTER TABLE {SCHEMA}.{table} ADD CONSTRAINT ck_{table}_actor_shape CHECK ({shape})"
        )


def upgrade() -> None:
    # --- the two context types --------------------------------------------------------
    op.execute(
        f"""
        CREATE TYPE {SCHEMA}.identity_context_row AS (
            kind text, account_id uuid, session_id uuid, workspace_id uuid, tenant_id uuid,
            membership_id uuid, role text, csrf_verified boolean, security_epoch integer
        )
        """
    )
    op.execute(
        f"""
        CREATE TYPE {SCHEMA}.identity_session_row AS (
            session_id uuid, account_id uuid, workspace_id uuid, tenant_id uuid,
            membership_id uuid, role text, csrf_verified boolean
        )
        """
    )

    # --- accounts ---------------------------------------------------------------------
    op.create_table(
        "accounts",
        sa.Column("id", _UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("email_normalized", sa.Text(), nullable=False),
        sa.Column("email_display", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'unverified'")),
        sa.Column("email_verified_at", _TIMESTAMPTZ, nullable=True),
        # The account security epoch (Milestone 3.1 security correction). Incremented by
        # complete_account_recovery so that every credential issued before the recovery --
        # including any raced with it -- is rejected at bearer authentication, which checks
        # the epoch it was stamped with. A durable mechanism, not a best-effort revoke.
        sa.Column("security_epoch", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_accounts"),
        # Global, like a tenant slug: an account is the outermost identity there is.
        sa.UniqueConstraint("email_normalized", name="uq_accounts_email_normalized"),
        sa.CheckConstraint(f"email_normalized ~ '{EMAIL_REGEX}'", name="email_normalized_format"),
        # The grammar alone does not bound the total: its domain group repeats labels without
        # an upper limit, so a 255-character address matches the regex. The canonical maximum
        # is stated here as its own constraint, mirroring the bound `identity_normalize_email`
        # and `db/accounts.normalize_email` already apply, so a writer that reached this table
        # by another route cannot store an address longer than the normalisers would produce.
        sa.CheckConstraint(
            f"length(email_normalized) <= {EMAIL_MAX_LENGTH}", name="email_normalized_length"
        ),
        sa.CheckConstraint(
            f"length(email_display) BETWEEN 3 AND {EMAIL_MAX_LENGTH}", name="email_display_length"
        ),
        sa.CheckConstraint(f"status IN ({_quoted_list(ACCOUNT_STATUSES)})", name="status_known"),
        sa.CheckConstraint(
            "(status = 'active') = (email_verified_at IS NOT NULL)", name="verified_status_consistent"
        ),
        schema=SCHEMA,
    )
    op.create_table(
        "account_passwords",
        sa.Column("account_id", _UUID, primary_key=True),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("algorithm", sa.Text(), nullable=False, server_default=sa.text("'argon2id'")),
        sa.Column("updated_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("account_id", name="pk_account_passwords"),
        sa.ForeignKeyConstraint(
            ["account_id"], [f"{SCHEMA}.accounts.id"],
            name="fk_account_passwords_account_id_accounts", ondelete="CASCADE",
        ),
        sa.CheckConstraint(f"password_hash ~ '{PASSWORD_HASH_REGEX}'", name="password_hash_format"),
        sa.CheckConstraint(
            f"length(password_hash) <= {PASSWORD_HASH_MAX_LENGTH}", name="password_hash_bounded"
        ),
        sa.CheckConstraint("algorithm = 'argon2id'", name="algorithm_known"),
        schema=SCHEMA,
    )
    op.create_table(
        "account_tokens",
        sa.Column("id", _UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("account_id", _UUID, nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.Text(), nullable=False),
        sa.Column("created_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("now()")),
        sa.Column("expires_at", _TIMESTAMPTZ, nullable=False),
        sa.Column("consumed_at", _TIMESTAMPTZ, nullable=True),
        sa.Column("superseded_at", _TIMESTAMPTZ, nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_account_tokens"),
        sa.ForeignKeyConstraint(
            ["account_id"], [f"{SCHEMA}.accounts.id"],
            name="fk_account_tokens_account_id_accounts", ondelete="CASCADE",
        ),
        sa.UniqueConstraint("fingerprint", name="uq_account_tokens_fingerprint"),
        sa.CheckConstraint(f"kind IN ({_quoted_list(TOKEN_KINDS)})", name="kind_known"),
        sa.CheckConstraint(f"fingerprint ~ '{FINGERPRINT_REGEX}'", name="fingerprint_format"),
        sa.CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        schema=SCHEMA,
    )
    op.create_index("ix_account_tokens_account_id", "account_tokens", ["account_id"], schema=SCHEMA)

    # --- memberships and the workspace directory --------------------------------------
    op.create_table(
        "memberships",
        sa.Column("id", _UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", _UUID, nullable=False),
        sa.Column("workspace_id", _UUID, nullable=False),
        sa.Column("account_id", _UUID, nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("invited_by_account_id", _UUID, nullable=True),
        sa.Column("created_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("now()")),
        sa.Column("revoked_at", _TIMESTAMPTZ, nullable=True),
        sa.Column("revoked_by_account_id", _UUID, nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_memberships"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], [f"{SCHEMA}.tenants.id"],
            name="fk_memberships_tenant_id_tenants", ondelete="CASCADE",
        ),
        # Composite, because referential integrity is checked with row security bypassed
        # and a single-column reference would accept a workspace in another tenant.
        sa.ForeignKeyConstraint(
            ["workspace_id", "tenant_id"], [f"{SCHEMA}.workspaces.id", f"{SCHEMA}.workspaces.tenant_id"],
            name="fk_memberships_workspace_id_tenant_id_workspaces", ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["account_id"], [f"{SCHEMA}.accounts.id"],
            name="fk_memberships_account_id_accounts", ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["invited_by_account_id"], [f"{SCHEMA}.accounts.id"],
            name="fk_memberships_invited_by_account_id_accounts", ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["revoked_by_account_id"], [f"{SCHEMA}.accounts.id"],
            name="fk_memberships_revoked_by_account_id_accounts", ondelete="SET NULL",
        ),
        sa.UniqueConstraint("id", "tenant_id", name="uq_memberships_id_tenant_id"),
        # The key sessions and bindings reference: a binding names its membership together
        # with the workspace and tenant, so the three cannot disagree.
        sa.UniqueConstraint(
            "id", "workspace_id", "tenant_id", name="uq_memberships_id_workspace_id_tenant_id"
        ),
        sa.CheckConstraint(f"role IN ({_quoted_list(MEMBERSHIP_ROLES)})", name="role_known"),
        schema=SCHEMA,
    )
    op.create_index("ix_memberships_tenant_id", "memberships", ["tenant_id"], schema=SCHEMA)
    op.create_index("ix_memberships_account_id", "memberships", ["account_id"], schema=SCHEMA)
    # One active membership per account per workspace. Revoked rows stay, so a re-invited
    # account gets a new row and the history of the old one is kept.
    op.create_index(
        "uq_memberships_active_workspace_id_account_id",
        "memberships",
        ["workspace_id", "account_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
        schema=SCHEMA,
    )
    op.create_table(
        "workspace_directory",
        sa.Column("id", _UUID, primary_key=True),
        sa.Column("tenant_id", _UUID, nullable=False),
        sa.Column("slug", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_workspace_directory"),
        sa.ForeignKeyConstraint(
            ["id", "tenant_id"], [f"{SCHEMA}.workspaces.id", f"{SCHEMA}.workspaces.tenant_id"],
            name="fk_workspace_directory_id_tenant_id_workspaces", ondelete="CASCADE",
        ),
        schema=SCHEMA,
    )

    # --- browser sessions -------------------------------------------------------------
    op.create_table(
        "browser_sessions",
        sa.Column("id", _UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("account_id", _UUID, nullable=False),
        sa.Column("fingerprint", sa.Text(), nullable=False),
        sa.Column("csrf_fingerprint", sa.Text(), nullable=False),
        sa.Column("created_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("now()")),
        sa.Column("expires_at", _TIMESTAMPTZ, nullable=False),
        sa.Column("last_seen_at", _TIMESTAMPTZ, nullable=True),
        sa.Column("revoked_at", _TIMESTAMPTZ, nullable=True),
        sa.Column("workspace_id", _UUID, nullable=True),
        sa.Column("tenant_id", _UUID, nullable=True),
        sa.Column("membership_id", _UUID, nullable=True),
        sa.Column("bound_at", _TIMESTAMPTZ, nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_browser_sessions"),
        sa.ForeignKeyConstraint(
            ["account_id"], [f"{SCHEMA}.accounts.id"],
            name="fk_browser_sessions_account_id_accounts", ondelete="CASCADE",
        ),
        # The binding is one membership, named with its workspace and tenant so that the
        # three columns cannot describe a membership of another workspace or tenant.
        sa.ForeignKeyConstraint(
            ["membership_id", "workspace_id", "tenant_id"],
            [f"{SCHEMA}.memberships.id", f"{SCHEMA}.memberships.workspace_id", f"{SCHEMA}.memberships.tenant_id"],
            name="fk_browser_sessions_membership_memberships",
        ),
        sa.UniqueConstraint("fingerprint", name="uq_browser_sessions_fingerprint"),
        sa.CheckConstraint(f"fingerprint ~ '{FINGERPRINT_REGEX}'", name="fingerprint_format"),
        sa.CheckConstraint(f"csrf_fingerprint ~ '{FINGERPRINT_REGEX}'", name="csrf_fingerprint_format"),
        sa.CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        sa.CheckConstraint(
            "((workspace_id IS NULL) = (tenant_id IS NULL)) AND ((workspace_id IS NULL) = (membership_id IS NULL))",
            name="binding_complete",
        ),
        schema=SCHEMA,
    )
    op.create_index("ix_browser_sessions_account_id", "browser_sessions", ["account_id"], schema=SCHEMA)

    # --- invitations ------------------------------------------------------------------
    op.create_table(
        "workspace_invitations",
        sa.Column("id", _UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", _UUID, nullable=False),
        sa.Column("workspace_id", _UUID, nullable=False),
        sa.Column("email_normalized", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.Text(), nullable=False),
        sa.Column("invited_by_account_id", _UUID, nullable=True),
        sa.Column("created_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("now()")),
        sa.Column("expires_at", _TIMESTAMPTZ, nullable=False),
        sa.Column("accepted_at", _TIMESTAMPTZ, nullable=True),
        sa.Column("accepted_membership_id", _UUID, nullable=True),
        sa.Column("revoked_at", _TIMESTAMPTZ, nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_workspace_invitations"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], [f"{SCHEMA}.tenants.id"],
            name="fk_workspace_invitations_tenant_id_tenants", ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id", "tenant_id"], [f"{SCHEMA}.workspaces.id", f"{SCHEMA}.workspaces.tenant_id"],
            name="fk_workspace_invitations_workspace_id_tenant_id_workspaces", ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["accepted_membership_id", "tenant_id"],
            [f"{SCHEMA}.memberships.id", f"{SCHEMA}.memberships.tenant_id"],
            name="fk_workspace_invitations_accepted_membership_memberships",
        ),
        sa.ForeignKeyConstraint(
            ["invited_by_account_id"], [f"{SCHEMA}.accounts.id"],
            name="fk_workspace_invitations_invited_by_account_id_accounts", ondelete="SET NULL",
        ),
        sa.UniqueConstraint("fingerprint", name="uq_workspace_invitations_fingerprint"),
        sa.UniqueConstraint("id", "tenant_id", name="uq_workspace_invitations_id_tenant_id"),
        sa.CheckConstraint(f"email_normalized ~ '{EMAIL_REGEX}'", name="email_normalized_format"),
        sa.CheckConstraint(f"role IN ({_quoted_list(MEMBERSHIP_ROLES)})", name="role_known"),
        sa.CheckConstraint(f"fingerprint ~ '{FINGERPRINT_REGEX}'", name="fingerprint_format"),
        sa.CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_workspace_invitations_tenant_id", "workspace_invitations", ["tenant_id"], schema=SCHEMA
    )
    # One pending invitation per address per workspace.
    op.create_index(
        "uq_workspace_invitations_pending_workspace_id_email",
        "workspace_invitations",
        ["workspace_id", "email_normalized"],
        unique=True,
        postgresql_where=sa.text("accepted_at IS NULL AND revoked_at IS NULL"),
        schema=SCHEMA,
    )

    # --- account-level idempotency ----------------------------------------------------
    #
    # Milestone 2.2's claims are tenant-scoped, and an account creating its first workspace
    # or accepting an invitation has no tenant context until the operation has run. So the
    # replay lookup for those two operations is keyed by account, here, and the tenant-scoped
    # claim and linked event are written as well once the tenant context exists.
    op.create_table(
        "account_idempotency_records",
        sa.Column("id", _UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("account_id", _UUID, nullable=False),
        sa.Column("operation", sa.Text(), nullable=False),
        sa.Column("idempotency_key", sa.Text(), nullable=False),
        sa.Column("request_fingerprint", sa.Text(), nullable=False),
        sa.Column("result", _JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id", name="pk_account_idempotency_records"),
        sa.ForeignKeyConstraint(
            ["account_id"], [f"{SCHEMA}.accounts.id"],
            name="fk_account_idempotency_records_account_id_accounts", ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "account_id", "operation", "idempotency_key",
            name="uq_account_idempotency_records_account_id_operation_key",
        ),
        sa.CheckConstraint(f"operation ~ '{DOTTED_NAME_REGEX}'", name="operation_format"),
        sa.CheckConstraint(f"idempotency_key ~ '{IDEMPOTENCY_KEY_REGEX}'", name="idempotency_key_format"),
        sa.CheckConstraint(
            f"request_fingerprint ~ '{FINGERPRINT_REGEX}'", name="request_fingerprint_format"
        ),
        *_metadata_checks("result"),
        schema=SCHEMA,
    )

    # --- the transaction-scoped identity context --------------------------------------
    #
    # UNLOGGED, one row per backend pid, replaced in place, readable only by the
    # transaction whose id it carries: the shape ``auth_transaction_context`` has, for the
    # reasons ADR 0006 decision 2 gives. ``DISCARD`` does not reach it and nothing clears it.
    op.execute(
        f"""
        CREATE UNLOGGED TABLE {SCHEMA}.identity_transaction_context (
            backend_pid    integer PRIMARY KEY,
            xact_id        xid8 NOT NULL,
            kind           text NOT NULL,
            account_id     uuid,
            session_id     uuid,
            workspace_id   uuid,
            tenant_id      uuid,
            membership_id  uuid,
            role           text,
            csrf_verified  boolean NOT NULL DEFAULT false,
            -- The account's security (password) version as ``login_lookup`` read it, in
            -- the same statement that handed the runtime the stored hash it is about to
            -- verify. ``open_browser_session`` compares it against the account row under
            -- a lock that conflicts with recovery, so a password verified against a hash
            -- a concurrent recovery has since replaced opens no session. NULL for every
            -- context kind but ``login_challenge``, and for a challenge that matched no
            -- address.
            security_epoch integer,
            bound_at       timestamptz NOT NULL
        )
        """
    )

    # --- the credential registry learns which membership issued a credential ----------
    op.add_column("auth_bindings", sa.Column("membership_id", _UUID, nullable=True), schema=SCHEMA)
    op.add_column("auth_bindings", sa.Column("workspace_id", _UUID, nullable=True), schema=SCHEMA)
    op.add_column("auth_bindings", sa.Column("label", sa.Text(), nullable=True), schema=SCHEMA)
    op.add_column("auth_bindings", sa.Column("last_used_at", _TIMESTAMPTZ, nullable=True), schema=SCHEMA)
    op.add_column("auth_bindings", sa.Column("rotated_from_id", _UUID, nullable=True), schema=SCHEMA)
    # The account security epoch stamped on a membership-bound credential at issue/rotate
    # (Milestone 3.1 security correction). NULL for a credential provisioned out of band,
    # whose principal is not an account. bind_authenticated_context rejects a membership-
    # bound credential whose stamped epoch no longer matches the account's current one.
    op.add_column("auth_bindings", sa.Column("principal_epoch", sa.Integer(), nullable=True), schema=SCHEMA)
    op.create_foreign_key(
        "fk_auth_bindings_membership_memberships",
        "auth_bindings",
        "memberships",
        ["membership_id", "workspace_id", "tenant_id"],
        ["id", "workspace_id", "tenant_id"],
        source_schema=SCHEMA,
        referent_schema=SCHEMA,
    )
    op.create_foreign_key(
        "fk_auth_bindings_rotated_from_auth_bindings",
        "auth_bindings",
        "auth_bindings",
        ["rotated_from_id", "tenant_id"],
        ["id", "tenant_id"],
        source_schema=SCHEMA,
        referent_schema=SCHEMA,
    )
    op.execute(
        f"ALTER TABLE {SCHEMA}.auth_bindings ADD CONSTRAINT ck_auth_bindings_membership_binding_complete "
        "CHECK ((membership_id IS NULL) = (workspace_id IS NULL))"
    )
    op.execute(
        f"ALTER TABLE {SCHEMA}.auth_bindings ADD CONSTRAINT ck_auth_bindings_label_bounded "
        f"CHECK (label IS NULL OR length(label) BETWEEN 1 AND {LABEL_MAX_LENGTH})"
    )
    op.create_index(
        "ix_auth_bindings_tenant_id_workspace_id", "auth_bindings", ["tenant_id", "workspace_id"], schema=SCHEMA
    )

    # --- a third actor kind -----------------------------------------------------------
    _alter_actor_constraints(ACTOR_KINDS, ACTOR_SHAPE)

    # --- the shape recogniser learns the five new secret kinds ------------------------
    op.execute(SECRET_SHAPE_SQL)

    # --- functions, in dependency order -----------------------------------------------
    op.execute(_IDENTITY_NORMALIZE_EMAIL)
    op.execute(_IDENTITY_MINT_SECRET)
    op.execute(_IDENTITY_FINGERPRINT)
    op.execute(_IDENTITY_REQUEST_FINGERPRINT)
    op.execute(_IDENTITY_CONTEXT)
    op.execute(_IDENTITY_CONTEXT_WRITE)
    op.execute(_IDENTITY_CONTEXT_NARROW)
    op.execute(_AUTH_SESSION)
    op.execute(_IDENTITY_REQUIRE_SESSION)
    op.execute(_IDENTITY_REQUIRE_TTL)
    op.execute(_IDENTITY_ISSUE_TOKEN)
    op.execute(_IDENTITY_REPLAY)
    op.execute(_IDENTITY_CLAIM)
    op.execute(_IDENTITY_ACTIVE_OWNER_COUNT)
    op.execute(_MEMBERSHIP_ROLE_SCOPES)
    # After membership_role_scopes, which it calls, and before every workspace-mode
    # function, all of which call it.
    op.execute(_IDENTITY_REQUIRE_MEMBERSHIP)
    op.execute(_SIGNUP_ACCOUNT)
    op.execute(_REQUEST_EMAIL_VERIFICATION)
    op.execute(_VERIFY_ACCOUNT_EMAIL)
    op.execute(_REQUEST_ACCOUNT_RECOVERY)
    op.execute(_COMPLETE_ACCOUNT_RECOVERY)
    op.execute(_ACCOUNT_RECOVERY_TOKEN_VALID)
    op.execute(_PURGE_EXPIRED_UNVERIFIED_ACCOUNTS)
    op.execute(_LOGIN_LOOKUP)
    op.execute(_OPEN_BROWSER_SESSION)
    op.execute(_BIND_SESSION_CONTEXT)
    op.execute(_ACCOUNT_PROFILE)
    op.execute(_ACCOUNT_SESSIONS)
    op.execute(_REVOKE_BROWSER_SESSION)
    op.execute(_REVOKE_ALL_BROWSER_SESSIONS)
    op.execute(_ACCOUNT_WORKSPACES)
    op.execute(_CREATE_WORKSPACE)
    op.execute(_BIND_SESSION_WORKSPACE)
    op.execute(_UNBIND_SESSION_WORKSPACE)
    op.execute(_RENAME_WORKSPACE)
    op.execute(_WORKSPACE_MEMBERSHIPS)
    op.execute(_REMOVE_MEMBERSHIP)
    op.execute(_CHANGE_MEMBERSHIP_ROLE)
    op.execute(_CREATE_INVITATION)
    op.execute(_REVOKE_INVITATION)
    op.execute(_WORKSPACE_INVITATIONS)
    op.execute(_ACCEPT_INVITATION)
    op.execute(_ISSUE_API_CREDENTIAL)
    op.execute(_ROTATE_API_CREDENTIAL)
    op.execute(_REVOKE_API_CREDENTIAL)
    op.execute(_WORKSPACE_API_CREDENTIALS)
    op.execute(_RECORD_API_CREDENTIAL_USE)
    op.execute(_BIND_AUTHENTICATED_CONTEXT_HEAD)
    op.execute(_MEMBERSHIPS_REVOCATION_CASCADE)
    op.execute(_WORKSPACE_DIRECTORY_SYNC)
    op.execute(_ACCOUNT_TOKENS_APPEND_ONLY)
    op.execute(_ACCOUNT_IDEMPOTENCY_RECORDS_APPEND_ONLY)

    # --- triggers ---------------------------------------------------------------------
    op.execute(
        f"""
        CREATE TRIGGER memberships_revocation_cascade
        BEFORE UPDATE OR DELETE ON {SCHEMA}.memberships
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.memberships_revocation_cascade()
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER workspaces_directory_sync
        AFTER INSERT OR UPDATE OR DELETE ON {SCHEMA}.workspaces
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.workspace_directory_sync()
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER account_tokens_append_only
        BEFORE UPDATE ON {SCHEMA}.account_tokens
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.account_tokens_append_only()
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER account_idempotency_records_append_only
        BEFORE UPDATE OR DELETE ON {SCHEMA}.account_idempotency_records
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.account_idempotency_records_append_only()
        """
    )

    # --- and state the access control rather than inheriting it ----------------------
    #
    # The ownership-aware sanitiser 0004 installed, called rather than copied: eight more
    # relations and forty-odd more functions, and ALTER DEFAULT PRIVILEGES applies at the
    # instant each is created.
    op.execute(f"SELECT {SCHEMA}.sanitize_schema_privileges()")


def downgrade() -> None:
    """Back to the Milestone 2.4 shape exactly.

    Ordered by dependency: the trigger on ``workspaces`` before the function it fires, the
    actor constraints back to their ``0003``/``0004`` text, the credential registry's five
    columns and two constraints, every function, then the tables in reverse reference
    order, the two types, and finally ``secret_shape`` back to its ``0003`` text.
    """
    # Every trigger before the function it fires: PostgreSQL refuses to drop a function a
    # trigger depends on, and the tables the other three triggers sit on are dropped below,
    # after their functions.
    op.execute(f"DROP TRIGGER workspaces_directory_sync ON {SCHEMA}.workspaces")
    op.execute(f"DROP TRIGGER memberships_revocation_cascade ON {SCHEMA}.memberships")
    op.execute(f"DROP TRIGGER account_tokens_append_only ON {SCHEMA}.account_tokens")
    op.execute(
        f"DROP TRIGGER account_idempotency_records_append_only ON {SCHEMA}.account_idempotency_records"
    )
    # Reconcile populated data before the actor vocabulary narrows. Milestone 3.1 activity
    # records 'session'-actor rows in audit_events (and, if any session ever drove one, in
    # lifecycle_transitions); the narrowed 0003/0004 CHECK constraint re-added just below
    # admits only 'credential' and 'provisioning', so re-adding it while a session row
    # survives fails with a check violation (SQLSTATE 23514) and strands the downgrade. The
    # identity plane -- accounts, memberships, sessions -- is being dropped by this same
    # downgrade, so the session-actor rows describe a world the reverted schema no longer
    # has; removing them is the deterministic reconciliation. No delete trigger guards
    # either table, and no runtime role can reach this path: it runs as the schema owner
    # inside the migration.
    # Both tables carry FORCE ROW LEVEL SECURITY, which applies to the schema owner too, so
    # a plain DELETE with no tenant context would match zero rows while the CHECK re-add
    # below still sees every row and fails. NO FORCE lets the owner -- who runs this
    # migration -- reach the rows; FORCE is restored immediately after, so the reverted
    # catalogue is byte-for-byte a fresh migration to 0004. Both tables are known to be
    # FORCE ROW LEVEL SECURITY at head (asserted by the migration round-trip test).
    for _table in ("audit_events", "lifecycle_transitions"):
        op.execute(f"ALTER TABLE {SCHEMA}.{_table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"DELETE FROM {SCHEMA}.{_table} WHERE actor_kind = 'session'")
        op.execute(f"ALTER TABLE {SCHEMA}.{_table} FORCE ROW LEVEL SECURITY")
    _alter_actor_constraints(LEGACY_AUDIT_ACTOR_KINDS, LEGACY_ACTOR_SHAPE)

    op.drop_index("ix_auth_bindings_tenant_id_workspace_id", table_name="auth_bindings", schema=SCHEMA)
    op.execute(f"ALTER TABLE {SCHEMA}.auth_bindings DROP CONSTRAINT ck_auth_bindings_label_bounded")
    op.execute(
        f"ALTER TABLE {SCHEMA}.auth_bindings DROP CONSTRAINT ck_auth_bindings_membership_binding_complete"
    )
    op.execute(
        f"ALTER TABLE {SCHEMA}.auth_bindings DROP CONSTRAINT fk_auth_bindings_rotated_from_auth_bindings"
    )
    op.execute(
        f"ALTER TABLE {SCHEMA}.auth_bindings DROP CONSTRAINT fk_auth_bindings_membership_memberships"
    )
    for column in ("principal_epoch", "rotated_from_id", "last_used_at", "label", "workspace_id", "membership_id"):
        op.drop_column("auth_bindings", column, schema=SCHEMA)

    for name, signature, _audience in reversed(FUNCTIONS):
        op.execute(f"DROP FUNCTION {SCHEMA}.{name}({signature})")

    op.drop_index(
        "uq_workspace_invitations_pending_workspace_id_email",
        table_name="workspace_invitations", schema=SCHEMA,
    )
    op.drop_index("ix_workspace_invitations_tenant_id", table_name="workspace_invitations", schema=SCHEMA)
    op.drop_table("workspace_invitations", schema=SCHEMA)
    op.drop_index("ix_browser_sessions_account_id", table_name="browser_sessions", schema=SCHEMA)
    op.drop_table("browser_sessions", schema=SCHEMA)
    op.drop_table("workspace_directory", schema=SCHEMA)
    op.drop_index("uq_memberships_active_workspace_id_account_id", table_name="memberships", schema=SCHEMA)
    op.drop_index("ix_memberships_account_id", table_name="memberships", schema=SCHEMA)
    op.drop_index("ix_memberships_tenant_id", table_name="memberships", schema=SCHEMA)
    op.drop_table("memberships", schema=SCHEMA)
    op.drop_table("account_idempotency_records", schema=SCHEMA)
    op.drop_index("ix_account_tokens_account_id", table_name="account_tokens", schema=SCHEMA)
    op.drop_table("account_tokens", schema=SCHEMA)
    op.drop_table("account_passwords", schema=SCHEMA)
    op.drop_table("accounts", schema=SCHEMA)
    op.execute(f"DROP TABLE {SCHEMA}.identity_transaction_context")

    op.execute(f"DROP TYPE {SCHEMA}.identity_session_row")
    op.execute(f"DROP TYPE {SCHEMA}.identity_context_row")

    op.execute(_LEGACY_BIND_AUTHENTICATED_CONTEXT_RESTORE)
    op.execute(LEGACY_SECRET_SHAPE_RESTORE_SQL)
