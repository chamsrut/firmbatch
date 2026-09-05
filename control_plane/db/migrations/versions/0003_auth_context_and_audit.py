"""Bind tenant context to an authenticated credential; add scopes and the audit trail.

Revision ID: 0003_auth_context_and_audit
Revises: 0002_idempotency_and_outbox
Create Date: 2026-09-04

The third v1 migration, and the one that closes the database half of
``AUTH-BOUND-TENANT-CONTEXT``.

**What was wrong, precisely.** Migrations ``0001`` and ``0002`` scoped every policy on
``app_current_tenant_id()``, which read the ``app.tenant_id`` setting. Any role holding
the connection could execute ``set_config('app.tenant_id', <any uuid>, true)`` and row
security would then evaluate faithfully against whatever tenant it had been told. The
application service was a *trusted setter* of tenant context: an assumption, not an
enforced property. That is a sound place for a shared foundation to stand and an unsound
place from which to serve customers (ADR 0004 section 8g).

**What replaces it.** Four pieces, and none of them works without the others:

1. **A protected credential registry.** ``firmbatch.auth_bindings`` maps a one-way
   SHA-256 fingerprint of a bearer credential to one tenant, one principal, and one set
   of scopes. No role but the schema owner holds any privilege on it, so no connection can
   read it, write it, or discover whether a row exists. The raw credential is never
   stored, and since the credential is **generated inside** ``register_auth_binding`` a
   caller cannot even choose a candidate to probe with.

2. **A protected transaction-scoped context.** ``firmbatch.auth_transaction_context`` is
   an ordinary (unlogged) table in the ``firmbatch`` schema, keyed by the backend's pid
   and carrying the ``xid8`` of the transaction that wrote it.
   ``firmbatch.auth_context_begin`` -- a ``SECURITY DEFINER`` function **no role may
   execute** -- writes it; ``firmbatch.auth_context()`` reads it back only when
   ``xact_id = pg_current_xact_id_if_assigned()``.

   That comparison is what makes the context transaction-scoped, and it is not a
   convention: a row written by transaction T is invisible to everyone else until T
   commits, and once T has committed its transaction id can never equal a future
   ``pg_current_xact_id()``. A rollback removes it like any other uncommitted write. So a
   committed row grants nothing to anybody, ever, and nothing has to clear it.

   **This replaced a temporary table, and the reason is worth reading before the code.**
   The first version of this migration put the context in
   ``pg_temp.firmbatch_auth_context`` with ``ON COMMIT DELETE ROWS``. That is defeated by
   one statement: ``DISCARD TEMP`` is legal for any role, needs no privilege, drops every
   temporary table in the session including one owned by somebody else, and left the
   caller free to bind a *second* identity in the same transaction. Measured against a
   real server. Ownership checks did not help, because the relation was not forged -- it
   was destroyed. There is no privilege to revoke and no check to add: the fix is to keep
   the context somewhere ``DISCARD`` does not reach. See ADR 0006 decision 2.

3. **One way in.** ``firmbatch.bind_authenticated_context(credential)`` hashes what it is
   given, looks the digest up, refuses an unknown, revoked or expired binding with a
   single indistinguishable error, and otherwise establishes the context. It takes no
   tenant, no principal, no binding id and no scope from the caller. Binding twice, or
   binding a second identity, is refused by the primary key: the row for this backend
   already carries this transaction's id, and there is no path that removes it.

   It also **refuses any isolation level but READ COMMITTED**, in the database rather than
   in Python. Under ``REPEATABLE READ`` or ``SERIALIZABLE`` the registry lookup would run
   against a snapshot taken before the statement, so a revocation committed in between
   would be invisible and a revoked credential would still authenticate.

   Expiry is evaluated with ``clock_timestamp()`` and not ``now()``, because ``now()`` is
   transaction-start time: a long transaction would otherwise extend the life of a
   credential by its own duration.

   ``firmbatch.begin_tenant_provisioning()`` is the one other entry, for the path that
   creates a tenant before any credential for it can exist. It takes **no arguments** and
   generates the tenant id itself, so even the provisioning role cannot name an existing
   tenant to act on.

4. **Policies that read the context, not a setting.** Every policy on every tenant-owned
   table is replaced. The predicates are ``tenant matches the authenticated context AND
   the context holds the required scope``, with one policy per command, so a command with
   no policy reaches no row for any role -- including the owner, because row security is
   ``FORCE``d. ``firmbatch.app_current_tenant_id()`` is **dropped**: leaving it in place
   would leave a function that looks like the mechanism and is not.

**Access control is stated, not inherited.** Revoking from ``PUBLIC`` is not enough:
``ALTER DEFAULT PRIVILEGES FOR ROLE <owner>`` can grant a table or a function to a named
role at the instant it is created, and no amount of revoking from ``PUBLIC`` removes that.
So this migration ends by **sanitizing the whole schema's access control** -- every
relation, function and type in ``firmbatch`` loses every privilege held by anybody except
its owner -- and ``db/roles.py`` then grants back exactly the allowlist it names, and
sanitizes again first for the same reason. Role names are never written here; the grantees
are enumerated from the catalogue and quoted with ``format('%I', ...)``.

Also added here: ``firmbatch.audit_events``, tenant-scoped and append-only, whose tenant
and actor come from the authenticated context by column default and are re-checked by the
insert policy, and whose ``occurred_at`` is written by a ``BEFORE INSERT`` trigger from
``clock_timestamp()`` -- so a caller can neither supply one nor keep the transaction's
start time by opening the transaction early.

**No runtime role may write it directly.** ``firmbatch.append_audit_event`` is the only way
in, and it applies the whole bounded-metadata policy inside the database against the values
it is about to write. ``db/metadata.py`` applies the same rules at the Python boundary so a
caller gets a usable error; this is what holds when there is no Python. The function takes
no tenant, no actor, no principal, no binding and no timestamp, so nothing derived is a
parameter.

Two further properties enforced here rather than above the database:

* **Scope delegation is bounded.** ``register_auth_binding`` refuses any scope outside
  ``DELEGABLE_SCOPES``, and -- for a *credential* issuer -- any scope the issuer does not
  already hold. ``credential:manage`` authorises creating a credential; it does not imply
  the permissions that credential carries. See ADR 0006 decision 5b.
* **Acquiring a context requires a writable primary.** It writes one row, so
  ``auth_require_writable_primary()`` refuses a standby and a read-only transaction
  *before* the write, testing ``pg_is_in_recovery()`` first so a replica is not misreported
  as a stray ``SET``. Read-replica routing is Milestone 8; ADR 0006 decision 8a.

Hand-written like ``0001`` and ``0002``: ``op.create_table`` cannot emit RLS DDL, function
definitions, triggers or policies. ``tests/test_migrations.py`` asserts with
``compare_metadata`` that what this file builds still matches ``db/models.py``, and
``tests/test_protected_auth_state.py`` asserts the ownership, ``search_path``, ``PUBLIC``
and grant properties of every function below.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TIMESTAMP, UUID

revision: str = "0003_auth_context_and_audit"
down_revision: str | None = "0002_idempotency_and_outbox"
branch_labels: str | None = None
depends_on: str | None = None

SCHEMA = "firmbatch"

# Mirrors db/models.py and security/authorization.py. The migration cannot import them --
# a migration that follows the models stops being a record of what was applied -- so the
# constants are duplicated and tests/test_migrations.py asserts the duplicate has not
# drifted.
DOTTED_NAME_REGEX = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$"
SIMPLE_NAME_REGEX = r"^[a-z][a-z0-9_]{0,62}$"
FINGERPRINT_REGEX = r"^[0-9a-f]{64}$"
MAX_METADATA_BYTES = 4096
MAX_SCOPES_PER_BINDING = 16

#: The closed scope catalogue, sorted. Adding one is a migration, on purpose.
KNOWN_SCOPES = (
    "audit:read",
    "credential:manage",
    "mutation:execute",
    "tenant:provision",
    "tenant:read",
    "workspace:read",
    "workspace:write",
)

#: Scopes that may be placed on a credential issued through ``register_auth_binding``.
#: Every known scope except ``tenant:provision``, which belongs to the bootstrap path and
#: is acquired from ``begin_tenant_provisioning()`` rather than carried by a credential.
#: Mirrors ``security/authorization.DELEGABLE_SCOPES``.
DELEGABLE_SCOPES = tuple(scope for scope in KNOWN_SCOPES if scope != "tenant:provision")

AUDIT_OUTCOMES = ("attempted", "succeeded", "failed", "denied")
AUDIT_ACTOR_KINDS = ("credential", "provisioning")

#: The bounded-metadata policy, in the database. Mirrors ``db/metadata.py``; the shared
#: corpus in ``tests/test_audit_events.py`` asserts the two answer alike on every example.
#:
#: The document bound is the *rendered* one: PostgreSQL prints ``jsonb::text`` with spaces
#: that the canonical Python form omits, so the database bound is twice the Python one and
#: is the backstop rather than the boundary.
MAX_METADATA_KEYS = 32
MAX_METADATA_STRING_LENGTH = 256
MAX_METADATA_SEQUENCE_LENGTH = 16

#: Key names that mean the content itself rather than a reference to it, matched **whole**.
#: Mirrors ``metadata.DENIED_METADATA_KEYS``.
DENIED_METADATA_KEYS = (
    "payload", "raw_payload", "payload_bytes", "body", "request_body", "response_body",
    "content", "blob", "bytes", "data", "text", "input", "input_text", "input_bytes",
    "output", "output_text", "output_bytes", "prompt", "prompt_text", "completion",
    "completion_text", "message", "messages", "ciphertext", "plaintext",
    "password", "passwd", "secret", "client_secret", "secret_key", "private_key",
    "api_key", "apikey", "access_key", "token", "access_token", "refresh_token",
    "bearer_token", "session_token", "auth_token", "id_token", "credential",
    "credentials", "authorization", "auth", "cookie", "connection_string",
    "database_url", "dsn",
)

#: Every code point the shape recogniser treats as whitespace, folded to an ASCII space
#: before any pattern is applied. The identical list is
#: ``security/secrets.WHITESPACE_CODE_POINTS``; a test compares the two answers on every
#: one of them.
#:
#: This exists because ``[[:space:]]`` is **not** the same set as Python's ``\s``.
#: ``[[:space:]]`` is decided by the server's ``lc_ctype``, and on a real PostgreSQL 16
#: server it matched none of U+0085, U+00A0, U+2007 or U+202F -- all four of which Python
#: matches. ``' Bearer example'`` was therefore refused by ``db/metadata.py`` and
#: accepted here, and here is the half that holds when a runtime role writes the call
#: itself. ``translate()`` works on code points and asks no locale anything, so the fold
#: below is the same fold in both languages.
#:
#: A migration is a historical record and must not import application code, so the list is
#: duplicated rather than shared. The test is what keeps the copies identical.
WHITESPACE_CODE_POINTS = (
    0x0009, 0x000A, 0x000B, 0x000C, 0x000D,
    0x001C, 0x001D, 0x001E, 0x001F, 0x0020,
    0x0085, 0x00A0, 0x1680,
    0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
    0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
)

#: ASCII case folding, written out. The **only** case mapping this migration performs.
#:
#: Not ``lower()``, not ``upper()``, and not the ``~*`` operator: all three are decided by
#: the server's ``lc_ctype``, and Python's ``re.IGNORECASE`` is Unicode. They disagreed.
#: Measured on a real PostgreSQL 16 server: ``ſecret=x`` (U+017F) and ``apiKey=x`` (U+212A)
#: were refused by ``db/metadata.py`` and **accepted here**, which is the half that holds
#: when a runtime role calls ``append_audit_event`` itself. ``translate()`` maps code point
#: to code point and asks no locale anything.
#:
#: Mirrors ``security/secrets.ASCII_UPPERCASE`` / ``ASCII_LOWERCASE``.
ASCII_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ASCII_LOWERCASE = "abcdefghijklmnopqrstuvwxyz"

#: The secret shapes ``security/secrets.SECRET_SHAPE_PATTERNS`` recognises -- as a
#: **character-for-character copy** of that pattern text, not a translation of it.
#:
#: That is the change worth noticing. These used to be Python patterns rewritten into
#: PostgreSQL's dialect (``\b`` to ``\y``, an inline ``(?i)`` to the ``~*`` operator), and
#: a rewrite is a place where two rules drift apart in ways no reader can see. Every
#: construct either engine has to *look up* is gone instead:
#:
#: * no ``[[:space:]]`` and no ``\s`` -- values are whitespace-folded first, so ``[ ]`` and
#:   ``[^ ]`` say it exactly;
#: * no ``~*`` and no ``(?i)`` -- values are ASCII-case-folded first, so lowercase
#:   case-sensitive patterns say it exactly;
#: * no ``\y`` and no ``\b`` -- an ASCII word boundary is spelled with lookaround, which
#:   both engines evaluate without consulting a locale or a Unicode table.
#:
#: A test asserts this tuple equals the application module's, character for character. Only
#: the *name* is ever reported, never the value.
ASCII_WORD_BOUNDARY_BEFORE = "(?<![0-9a-z_])"
ASCII_WORD_BOUNDARY_AFTER = "(?![0-9a-z_])"

SECRET_SHAPES = (
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

#: The shape of a bearer credential. Generated **inside** ``register_auth_binding`` from
#: two ``gen_random_uuid()`` values -- 244 bits from PostgreSQL's strong RNG, rendered as
#: 43 URL-safe characters -- so a caller never chooses one and never learns whether a
#: candidate exists. ``security/secrets.py`` mints the same shape for tests and for the
#: recogniser that keeps one out of metadata.
CREDENTIAL_FORMAT_REGEX = r"^fbk_[A-Za-z0-9_-]{43}$"

#: The only isolation level the binding path is correct under. Enforced in the database:
#: a stricter level reads the registry through a snapshot older than the statement, so a
#: revocation committed in between would not be seen.
REQUIRED_ISOLATION_LEVEL = "read committed"

#: The table holding one transaction's authenticated context. A real relation in the
#: pinned schema, not a temporary one -- see the module docstring.
CONTEXT_RELATION = "auth_transaction_context"

#: Every function this migration creates, with its argument signature, so that the
#: revokes, the grants, the downgrade and the tests all work from one list rather than
#: four that can disagree.
#:
#: ``internal`` functions are executable by **nobody**: ``auth_context_begin`` writes the
#: context, so a role that could call it could forge one.
FUNCTIONS = (
    ("auth_context_begin", "uuid, uuid, uuid, text, text[]", "internal"),
    ("auth_require_read_committed", "", "internal"),
    ("auth_require_writable_primary", "", "internal"),
    ("secret_shape", "text", "internal"),
    ("audit_require_acceptable_details", "jsonb", "internal"),
    ("auth_context", "", "runtime"),
    ("auth_tenant_id", "", "runtime"),
    ("auth_principal_id", "", "runtime"),
    ("auth_binding_id", "", "runtime"),
    ("auth_actor_kind", "", "runtime"),
    ("auth_scopes", "", "runtime"),
    ("auth_has_scope", "text", "runtime"),
    ("bind_authenticated_context", "text", "runtime"),
    ("register_auth_binding", "uuid, text[], timestamptz", "runtime"),
    ("revoke_auth_binding", "uuid", "runtime"),
    ("append_audit_event", "text, text, text, uuid, uuid, jsonb", "runtime"),
    ("begin_tenant_provisioning", "", "provisioning"),
    ("audit_events_set_occurred_at", "", "internal"),
)

#: table -> (command, policy suffix, using, with check). The complete authorization
#: catalogue as the database enforces it. A command absent from a table's list has **no**
#: policy, which under FORCE ROW LEVEL SECURITY means it reaches no row for any role.
_TENANT = f"{SCHEMA}.auth_tenant_id()"


def _scope(name: str) -> str:
    return f"{SCHEMA}.auth_has_scope('{name}')"


POLICIES: "dict[str, tuple[tuple[str, str, str | None, str | None], ...]]" = {
    "tenants": (
        # tenant:provision is included in the read rule because PostgreSQL applies SELECT
        # policies to INSERT ... RETURNING, which is how the ORM writes a row carrying
        # server-side defaults. Without it, provisioning could insert a tenant and not
        # read back the row it had just written.
        (
            "SELECT",
            "read",
            f"id = {_TENANT} AND ({_scope('tenant:read')} OR {_scope('tenant:provision')})",
            None,
        ),
        ("INSERT", "append", None, f"id = {_TENANT} AND {_scope('tenant:provision')}"),
        (
            "UPDATE",
            "amend",
            f"id = {_TENANT} AND {_scope('tenant:provision')}",
            f"id = {_TENANT} AND {_scope('tenant:provision')}",
        ),
        # No DELETE policy: removing a tenant is not a runtime operation.
    ),
    "workspaces": (
        ("SELECT", "read", f"tenant_id = {_TENANT} AND {_scope('workspace:read')}", None),
        ("INSERT", "append", None, f"tenant_id = {_TENANT} AND {_scope('workspace:write')}"),
        (
            "UPDATE",
            "amend",
            f"tenant_id = {_TENANT} AND {_scope('workspace:write')}",
            f"tenant_id = {_TENANT} AND {_scope('workspace:write')}",
        ),
        ("DELETE", "remove", f"tenant_id = {_TENANT} AND {_scope('workspace:write')}", None),
    ),
    "idempotency_records": (
        ("SELECT", "read", f"tenant_id = {_TENANT} AND {_scope('mutation:execute')}", None),
        ("INSERT", "append", None, f"tenant_id = {_TENANT} AND {_scope('mutation:execute')}"),
    ),
    "outbox_events": (
        ("SELECT", "read", f"tenant_id = {_TENANT} AND {_scope('mutation:execute')}", None),
        ("INSERT", "append", None, f"tenant_id = {_TENANT} AND {_scope('mutation:execute')}"),
    ),
    "audit_events": (
        ("SELECT", "read", f"tenant_id = {_TENANT} AND {_scope('audit:read')}", None),
        # Appending requires a valid context and no scope beyond it, so that no credential
        # can act without leaving a trail. What it does require is that every derived
        # column agrees with the context: a caller that names another tenant, another
        # principal or another binding is refused rather than silently corrected.
        #
        # ``occurred_at`` is deliberately **not** compared here. A ``BEFORE INSERT``
        # trigger overwrites it with ``clock_timestamp()``, and WITH CHECK is evaluated
        # after BEFORE triggers -- so a comparison against a fresh ``clock_timestamp()``
        # would be a race against itself, and one against ``now()`` would be false for
        # every row the trigger touched. The trigger is the control; there is nothing left
        # for a policy to check.
        (
            "INSERT",
            "append",
            None,
            " AND ".join(
                (
                    f"tenant_id = {_TENANT}",
                    f"actor_kind = {SCHEMA}.auth_actor_kind()",
                    f"actor_principal_id IS NOT DISTINCT FROM {SCHEMA}.auth_principal_id()",
                    f"actor_binding_id IS NOT DISTINCT FROM {SCHEMA}.auth_binding_id()",
                )
            ),
        ),
    ),
}

#: The policies ``0001`` and ``0002`` created, so the downgrade can put them back exactly.
_LEGACY_POLICIES = {
    "tenants": (("tenants_tenant_isolation", "ALL", "id"),),
    "workspaces": (("workspaces_tenant_isolation", "ALL", "tenant_id"),),
    "idempotency_records": (
        ("idempotency_records_tenant_read", "SELECT", "tenant_id"),
        ("idempotency_records_tenant_append", "INSERT", "tenant_id"),
    ),
    "outbox_events": (
        ("outbox_events_tenant_read", "SELECT", "tenant_id"),
        ("outbox_events_tenant_append", "INSERT", "tenant_id"),
    ),
}

_UUID = UUID(as_uuid=True)
_TIMESTAMPTZ = TIMESTAMP(timezone=True)
_JSONB = JSONB(none_as_null=True)


def _metadata_checks(column: str) -> list[sa.CheckConstraint]:
    """Bare names: Alembic applies the ``ck_%(table_name)s_%(constraint_name)s``
    convention from ``db/base.py``."""
    return [
        sa.CheckConstraint(f"jsonb_typeof({column}) = 'object'", name=f"{column}_object"),
        sa.CheckConstraint(
            f"octet_length({column}::text) <= {MAX_METADATA_BYTES}", name=f"{column}_bounded"
        ),
    ]


def _quoted_list(values) -> str:
    return ", ".join(f"'{value}'" for value in values)


def _sql_literal(value: str) -> str:
    """A single-quoted SQL string literal. Every input here is a constant in this file."""
    escaped = value.replace("'", "''")
    return f"'{escaped}'"


def _secret_shape_values() -> str:
    """The ``VALUES`` list behind ``firmbatch.secret_shape``, one row per shape.

    Each row carries its own rank, and the query orders by it. Before that the query
    relied on ``VALUES`` order surviving to ``LIMIT 1``, which is true in practice and is
    not something the planner promises -- and *which* shape is reported is the whole
    output of this function.
    """
    return ",\n        ".join(
        f"({rank}, {_sql_literal(name)}, {_sql_literal(pattern)})"
        for rank, (name, pattern) in enumerate(SECRET_SHAPES)
    )


def _whitespace_literal() -> str:
    """The folded-from set as a PostgreSQL ``U&'...'`` literal.

    Rendered from code points rather than written out as characters: a no-break space in a
    migration file is indistinguishable from a space to every reader and to most diffs.
    """
    escapes = "".join(f"\\{code:04X}" for code in WHITESPACE_CODE_POINTS)
    return f"U&'{escapes}'"


def _whitespace_replacement_literal() -> str:
    """One ASCII space per folded code point, which is what ``translate`` maps them to."""
    return "'" + " " * len(WHITESPACE_CODE_POINTS) + "'"


def _normalized_scan_expression(column: str) -> str:
    """``column``, whitespace-folded and then ASCII-case-folded, in that order.

    The order is fixed to match ``security/secrets.normalize_for_shape_scan`` exactly. The
    two mappings touch disjoint code points so the order cannot change the answer; it is
    pinned anyway, because "the same pipeline" is easier to keep true than "an equivalent
    pipeline", and a reader comparing the two implementations should not have to prove
    disjointness first.
    """
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


def _policy_name(table: str, suffix: str) -> str:
    return f"{table}_authenticated_{suffix}"


# --------------------------------------------------------------- access-control hygiene
#
# Revoking from PUBLIC removes the privilege PostgreSQL hands out by default. It does not
# remove one an operator arranged with
#
#     ALTER DEFAULT PRIVILEGES FOR ROLE <owner> IN SCHEMA firmbatch
#         GRANT SELECT ON TABLES TO <some role>;
#
# which is applied at the instant an object is created, by the *creator*, and is therefore
# already on ``auth_bindings`` before the next statement of this migration runs. So the
# grantees are enumerated from the catalogue and every one of them is revoked, leaving the
# owner's inherent rights and nothing else.
#
# Column ACLs need their own pass, and the reason is the enumeration rather than the verb.
# PostgreSQL keeps column grants in ``pg_attribute.attacl``, and a role holding only column
# privileges never appears in ``pg_class.relacl`` -- so the relation loop above, which
# takes its grantee list from ``relacl``, never named such a role and never revoked
# anything from it. A single ``GRANT SELECT (backend_pid), UPDATE (tenant_id)`` on the
# transaction-context relation survived that pass intact and is a complete bypass of the
# isolation boundary on its own.
#
# The role and object names come from ``pg_catalog`` and are rendered with ``format('%I')``
# and ``regclass``/``regprocedure``, which quote them. No name in this block comes from a
# caller, and none is written out here: the migration must not know what an environment
# calls its roles.
_SANITIZE_SCHEMA_ACL = f"""
DO $sanitize$
DECLARE
    entry record;
BEGIN
    EXECUTE 'REVOKE ALL ON SCHEMA {SCHEMA} FROM PUBLIC';
    FOR entry IN
        SELECT pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_namespace n
        CROSS JOIN LATERAL pg_catalog.aclexplode(n.nspacl) acl
        WHERE n.nspname = '{SCHEMA}'
          AND acl.grantee <> 0
          AND acl.grantee <> n.nspowner
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON SCHEMA {SCHEMA} FROM %I', entry.grantee);
    END LOOP;

    FOR entry IN
        SELECT c.oid::pg_catalog.regclass AS obj,
               CASE WHEN c.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END AS kind,
               c.relowner
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = '{SCHEMA}' AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON %s %s FROM PUBLIC', entry.kind, entry.obj);
    END LOOP;

    FOR entry IN
        SELECT c.oid::pg_catalog.regclass AS obj,
               CASE WHEN c.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END AS kind,
               pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) acl
        WHERE n.nspname = '{SCHEMA}'
          AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
          AND acl.grantee <> 0
          AND acl.grantee <> c.relowner
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL ON %s %s FROM %I', entry.kind, entry.obj, entry.grantee
        );
    END LOOP;

    FOR entry IN
        SELECT DISTINCT c.oid::pg_catalog.regclass AS obj,
               a.attname AS column_name
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
        CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
        WHERE n.nspname = '{SCHEMA}'
          AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND a.attnum > 0
          AND NOT a.attisdropped
          AND acl.grantee = 0
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL (%I) ON TABLE %s FROM PUBLIC', entry.column_name, entry.obj
        );
    END LOOP;

    FOR entry IN
        SELECT DISTINCT c.oid::pg_catalog.regclass AS obj,
               a.attname AS column_name,
               pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
        CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
        WHERE n.nspname = '{SCHEMA}'
          AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND a.attnum > 0
          AND NOT a.attisdropped
          AND acl.grantee <> 0
          AND acl.grantee <> c.relowner
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL (%I) ON TABLE %s FROM %I',
            entry.column_name, entry.obj, entry.grantee
        );
    END LOOP;

    FOR entry IN
        SELECT p.oid::pg_catalog.regprocedure AS obj
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = '{SCHEMA}'
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', entry.obj);
    END LOOP;

    FOR entry IN
        SELECT p.oid::pg_catalog.regprocedure AS obj,
               pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl
        WHERE n.nspname = '{SCHEMA}'
          AND acl.grantee <> 0
          AND acl.grantee <> p.proowner
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM %I', entry.obj, entry.grantee);
    END LOOP;

    FOR entry IN
        SELECT t.oid::pg_catalog.regtype AS obj
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = '{SCHEMA}' AND t.typtype IN ('c', 'd', 'e', 'r')
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON TYPE %s FROM PUBLIC', entry.obj);
    END LOOP;

    FOR entry IN
        SELECT t.oid::pg_catalog.regtype AS obj,
               pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(t.typacl) acl
        WHERE n.nspname = '{SCHEMA}'
          AND t.typtype IN ('c', 'd', 'e', 'r')
          AND acl.grantee <> 0
          AND acl.grantee <> t.typowner
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON TYPE %s FROM %I', entry.obj, entry.grantee);
    END LOOP;
END;
$sanitize$
"""


# --------------------------------------------------------------------------- functions
#
# Every function below is created with a fixed, safe ``search_path``, refers to every
# object by its schema, contains no dynamic SQL, and looks nothing up by a name the
# caller supplied. Those four properties are what make a ``SECURITY DEFINER`` function
# something other than a standing privilege escalation, and
# ``tests/test_protected_auth_state.py`` asserts each of them from the catalogue rather
# than from this file.

_AUTH_REQUIRE_READ_COMMITTED = f"""
CREATE FUNCTION {SCHEMA}.auth_require_read_committed() RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    -- In the database rather than in Python, because the property is about the snapshot
    -- the *registry lookup* runs under and Python cannot make that true. Under REPEATABLE
    -- READ or SERIALIZABLE every statement in the transaction reads the snapshot taken at
    -- the first one, so a revocation or an expiry committed after the transaction opened
    -- would be invisible and a dead credential would still authenticate.
    IF pg_catalog.current_setting('transaction_isolation') <> '{REQUIRED_ISOLATION_LEVEL}' THEN
        RAISE EXCEPTION 'firmbatch: acquiring an authenticated context requires the % isolation level',
            '{REQUIRED_ISOLATION_LEVEL}'
            USING ERRCODE = '0A000',
                  DETAIL = 'a stricter level reads the credential registry through a snapshot older '
                           'than the statement, so a revocation committed in between would not be seen';
    END IF;
END;
$function$
"""

_AUTH_REQUIRE_WRITABLE_PRIMARY = f"""
CREATE FUNCTION {SCHEMA}.auth_require_writable_primary() RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    -- Acquiring a context writes one row. That is the design (ADR 0006 decision 2) and it
    -- has a consequence worth failing deliberately on rather than discovering as a
    -- confusing permission error: an authenticated transaction cannot run on a standby or
    -- inside a read-only transaction.
    --
    -- Recovery is tested FIRST, and the order is the diagnostic. On a standby
    -- ``transaction_read_only`` is always ``on``, so checking it first would report every
    -- standby as "somebody set the transaction read-only" and send the reader looking for
    -- a SET that nobody wrote.
    IF pg_catalog.pg_is_in_recovery() THEN
        RAISE EXCEPTION 'firmbatch: an authenticated context requires a writable primary'
            USING ERRCODE = 'read_only_sql_transaction',
                  DETAIL = 'this server is in recovery (a standby); acquiring a context writes one '
                           'row of protected transaction state, and read-replica routing is '
                           'Milestone 8 work';
    END IF;
    IF pg_catalog.current_setting('transaction_read_only') = 'on' THEN
        RAISE EXCEPTION 'firmbatch: an authenticated context requires a writable transaction'
            USING ERRCODE = 'read_only_sql_transaction',
                  DETAIL = 'this transaction is read-only; acquiring a context writes one row of '
                           'protected transaction state';
    END IF;
END;
$function$
"""

#: The value-shape recogniser, in the database, so that the metadata policy holds under
#: arbitrary runtime SQL rather than only when Python was asked first. It returns the
#: **name** of the shape and never any part of the value, so every refusal built on it can
#: be raised, logged and captured without becoming the leak it prevents.
#:
#: Executable by nobody: it is called only from inside the definer functions below.
_SECRET_SHAPE = f"""
CREATE FUNCTION {SCHEMA}.secret_shape(p_value text) RETURNS text
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
        {_secret_shape_values()}
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

#: The bounded-metadata policy, in the database. ``db/metadata.py`` applies the same rules
#: at the boundary so a caller gets a usable error; this is what holds when a runtime role
#: writes raw SQL instead.
#:
#: Every refusal names the rule and the position -- "entry 3", "entry 3, item 5" -- and
#: never the key, the value or its length, for the reason ``db/metadata.py`` gives at
#: length: a rejected key is unvetted input, and an error message is exactly where one ends
#: up being retained. That includes not letting a check constraint refuse the row instead,
#: because PostgreSQL renders the failing row in the constraint violation's DETAIL.
_AUDIT_REQUIRE_ACCEPTABLE_DETAILS = f"""
CREATE FUNCTION {SCHEMA}.audit_require_acceptable_details(p_details jsonb) RETURNS void
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_key text;
    v_value jsonb;
    v_entry jsonb;
    v_index integer := -1;
    v_position integer;
    v_type text;
    v_string text;
    v_shape text;
    v_where text;
BEGIN
    IF p_details IS NULL THEN
        RETURN;
    END IF;
    IF pg_catalog.jsonb_typeof(p_details) <> 'object' THEN
        RAISE EXCEPTION 'firmbatch: audit details must be a JSON object'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'these columns hold bounded metadata; the offending value is '
                           'deliberately not shown';
    END IF;
    IF (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(p_details)) > {MAX_METADATA_KEYS} THEN
        RAISE EXCEPTION 'firmbatch: audit details carry more than the % keys allowed', {MAX_METADATA_KEYS}
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    FOR v_key, v_value IN SELECT * FROM pg_catalog.jsonb_each(p_details) LOOP
        v_index := v_index + 1;
        v_where := 'entry ' || v_index::text;

        -- Shape before format, on keys as well as values: the format test is the one that
        -- would otherwise be tempted to quote what it refused.
        v_shape := {SCHEMA}.secret_shape(v_key);
        IF v_shape IS NOT NULL THEN
            RAISE EXCEPTION 'firmbatch: audit details have a key at % that looks like %', v_where, v_shape
                USING ERRCODE = 'invalid_parameter_value',
                      DETAIL = 'the offending key is deliberately not shown';
        END IF;
        IF v_key !~ '{SIMPLE_NAME_REGEX}' THEN
            RAISE EXCEPTION 'firmbatch: audit details have a key at % that is not a lowercase identifier '
                            'of at most 63 characters', v_where
                USING ERRCODE = 'invalid_parameter_value',
                      DETAIL = 'the offending key is deliberately not shown';
        END IF;
        IF v_key = ANY (ARRAY[{_quoted_list(DENIED_METADATA_KEYS)}]::text[]) THEN
            RAISE EXCEPTION 'firmbatch: audit details have a key at % that names content or a credential '
                            'rather than a reference to one', v_where
                USING ERRCODE = 'invalid_parameter_value',
                      DETAIL = 'the offending key is deliberately not shown';
        END IF;

        v_type := pg_catalog.jsonb_typeof(v_value);
        IF v_type = 'object' THEN
            RAISE EXCEPTION 'firmbatch: audit details nest an object at %', v_where
                USING ERRCODE = 'invalid_parameter_value',
                      DETAIL = 'metadata is flat: one level of scalars, or an array of them';
        ELSIF v_type = 'array' THEN
            IF pg_catalog.jsonb_array_length(v_value) > {MAX_METADATA_SEQUENCE_LENGTH} THEN
                RAISE EXCEPTION 'firmbatch: audit details store more than the % entries allowed at %',
                    {MAX_METADATA_SEQUENCE_LENGTH}, v_where
                    USING ERRCODE = 'invalid_parameter_value';
            END IF;
            v_position := -1;
            FOR v_entry IN SELECT * FROM pg_catalog.jsonb_array_elements(v_value) LOOP
                v_position := v_position + 1;
                DECLARE
                    v_item_where text := v_where || ', item ' || v_position::text;
                    v_item_type text := pg_catalog.jsonb_typeof(v_entry);
                BEGIN
                    IF v_item_type IN ('object', 'array') THEN
                        RAISE EXCEPTION 'firmbatch: audit details nest a % at %', v_item_type, v_item_where
                            USING ERRCODE = 'invalid_parameter_value',
                                  DETAIL = 'metadata is flat: one level of scalars, or an array of them';
                    END IF;
                    IF v_item_type = 'string' THEN
                        v_string := v_entry #>> '{{}}';
                        v_shape := {SCHEMA}.secret_shape(v_string);
                        IF v_shape IS NOT NULL THEN
                            RAISE EXCEPTION 'firmbatch: audit details store what looks like % at %',
                                v_shape, v_item_where
                                USING ERRCODE = 'invalid_parameter_value',
                                      DETAIL = 'metadata carries references to secrets, never the '
                                               'secrets themselves; the value is not shown';
                        END IF;
                        IF pg_catalog.length(v_string) > {MAX_METADATA_STRING_LENGTH} THEN
                            RAISE EXCEPTION 'firmbatch: audit details store a string at % longer than '
                                            'the % allowed', v_item_where, {MAX_METADATA_STRING_LENGTH}
                                USING ERRCODE = 'invalid_parameter_value';
                        END IF;
                    END IF;
                END;
            END LOOP;
        ELSIF v_type = 'string' THEN
            v_string := v_value #>> '{{}}';
            v_shape := {SCHEMA}.secret_shape(v_string);
            IF v_shape IS NOT NULL THEN
                RAISE EXCEPTION 'firmbatch: audit details store what looks like % at %', v_shape, v_where
                    USING ERRCODE = 'invalid_parameter_value',
                          DETAIL = 'metadata carries references to secrets, never the secrets '
                                   'themselves; the value is not shown';
            END IF;
            IF pg_catalog.length(v_string) > {MAX_METADATA_STRING_LENGTH} THEN
                RAISE EXCEPTION 'firmbatch: audit details store a string at % longer than the % allowed',
                    v_where, {MAX_METADATA_STRING_LENGTH}
                    USING ERRCODE = 'invalid_parameter_value';
            END IF;
        ELSIF v_type NOT IN ('number', 'boolean', 'null') THEN
            -- Unreachable through jsonb, which has exactly six types. Stated anyway: a
            -- policy whose else-branch is "accept" is a policy that accepts whatever a
            -- future type turns out to be.
            RAISE EXCEPTION 'firmbatch: audit details store an unsupported JSON type at %', v_where
                USING ERRCODE = 'invalid_parameter_value';
        END IF;
    END LOOP;

    IF pg_catalog.octet_length(p_details::text) > {MAX_METADATA_BYTES} THEN
        RAISE EXCEPTION 'firmbatch: audit details render to more than the % bytes allowed',
            {MAX_METADATA_BYTES}
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
END;
$function$
"""

_AUTH_CONTEXT_BEGIN = f"""
CREATE FUNCTION {SCHEMA}.auth_context_begin(
    p_binding_id uuid,
    p_tenant_id uuid,
    p_principal_id uuid,
    p_actor_kind text,
    p_scopes text[]
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_written integer;
BEGIN
    -- Executable by nobody. A role that could call this could name any tenant it liked,
    -- which is the whole property this migration exists to establish. The schema-wide ACL
    -- sanitisation below leaves it granted to the owner alone, and db/roles.py grants it
    -- to no runtime role.
    IF p_tenant_id IS NULL OR p_actor_kind IS NULL THEN
        RAISE EXCEPTION 'firmbatch: an authentication context needs a tenant and an actor kind'
            USING ERRCODE = 'internal_error';
    END IF;

    -- Before the write, not after it. A standby or a read-only transaction cannot hold an
    -- authenticated context at this milestone, and saying so deliberately is better than
    -- letting the INSERT below fail as an unexplained "cannot execute INSERT in a
    -- read-only transaction" from inside a SECURITY DEFINER function.
    PERFORM {SCHEMA}.auth_require_writable_primary();

    -- One row per backend, replaced when the backend starts a new transaction and left
    -- alone when it does not. ``pg_current_xact_id()`` assigns a transaction id if this
    -- transaction has none, which it is about to need anyway for this write.
    --
    -- The ON CONFLICT predicate is the whole of "a transaction binds once": if the row
    -- already carries *this* transaction's id the update matches nothing, and there is no
    -- statement anywhere that removes it. A row left by an earlier transaction of this
    -- backend, or by a backend that has since exited and whose pid was reused, carries a
    -- different id and is replaced.
    INSERT INTO {SCHEMA}.{CONTEXT_RELATION} AS existing
        (backend_pid, xact_id, binding_id, tenant_id, principal_id, actor_kind, scopes, bound_at)
    VALUES (
        pg_catalog.pg_backend_pid(),
        pg_catalog.pg_current_xact_id(),
        p_binding_id,
        p_tenant_id,
        p_principal_id,
        p_actor_kind,
        COALESCE(p_scopes, ARRAY[]::text[]),
        pg_catalog.clock_timestamp()
    )
    ON CONFLICT (backend_pid) DO UPDATE
        SET xact_id      = excluded.xact_id,
            binding_id   = excluded.binding_id,
            tenant_id    = excluded.tenant_id,
            principal_id = excluded.principal_id,
            actor_kind   = excluded.actor_kind,
            scopes       = excluded.scopes,
            bound_at     = excluded.bound_at
        WHERE existing.xact_id <> excluded.xact_id;

    GET DIAGNOSTICS v_written = ROW_COUNT;
    IF v_written = 0 THEN
        RAISE EXCEPTION 'firmbatch: this transaction already has an authenticated context'
            USING ERRCODE = 'invalid_transaction_state',
                  DETAIL = 'a transaction acquires context once; open a new transaction for a '
                           'different identity';
    END IF;
END;
$function$
"""

_AUTH_CONTEXT = f"""
CREATE FUNCTION {SCHEMA}.auth_context() RETURNS {SCHEMA}.auth_context_row
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    -- ``pg_current_xact_id_if_assigned`` and not ``pg_current_xact_id``: the second would
    -- *assign* a transaction id, and this function runs inside every policy predicate on
    -- every read. A read-only transaction that consumed an xid per query would be burning
    -- the wraparound budget to answer "who are you". NULL means no id has been assigned,
    -- which means nothing wrote a context, which fails closed.
    SELECT ctx.binding_id, ctx.tenant_id, ctx.principal_id, ctx.actor_kind, ctx.scopes
    FROM {SCHEMA}.{CONTEXT_RELATION} ctx
    WHERE ctx.backend_pid = pg_catalog.pg_backend_pid()
      AND ctx.xact_id = pg_catalog.pg_current_xact_id_if_assigned()
$function$
"""

#: The accessors every policy and every caller uses. Thin, ``STABLE``, and
#: SECURITY INVOKER: they add no privilege of their own, they only read the context the
#: definer function above is willing to hand back.
_ACCESSORS = (
    ("auth_tenant_id", "uuid", f"SELECT ({SCHEMA}.auth_context()).tenant_id"),
    ("auth_principal_id", "uuid", f"SELECT ({SCHEMA}.auth_context()).principal_id"),
    ("auth_binding_id", "uuid", f"SELECT ({SCHEMA}.auth_context()).binding_id"),
    ("auth_actor_kind", "text", f"SELECT ({SCHEMA}.auth_context()).actor_kind"),
    ("auth_scopes", "text[]", f"SELECT ({SCHEMA}.auth_context()).scopes"),
)

#: Scope tests fail closed by construction: with no context the scope array is NULL,
#: ``= ANY(NULL)`` is NULL, and ``coalesce`` turns that into false rather than into a
#: policy predicate that is neither true nor false.
_AUTH_HAS_SCOPE = f"""
CREATE FUNCTION {SCHEMA}.auth_has_scope(p_scope text) RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT COALESCE(p_scope = ANY (({SCHEMA}.auth_context()).scopes), false)
$function$
"""

_BIND_AUTHENTICATED_CONTEXT = f"""
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

_BEGIN_TENANT_PROVISIONING = f"""
CREATE FUNCTION {SCHEMA}.begin_tenant_provisioning() RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_tenant_id uuid;
BEGIN
    -- First, for the same reason as in bind_authenticated_context: both entry points
    -- write the same row of protected transaction state, so both owe the same diagnostic
    -- before anything else happens.
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();
    -- Takes NO arguments, deliberately. A tenant has no credential until it exists, so
    -- this is the one path that establishes context without one -- and the way it avoids
    -- becoming "provisioning may select any tenant" is that the tenant id is generated
    -- here. The caller cannot name an existing tenant, because it cannot name a tenant
    -- at all.
    v_tenant_id := pg_catalog.gen_random_uuid();
    PERFORM {SCHEMA}.auth_context_begin(
        NULL, v_tenant_id, NULL, 'provisioning',
        ARRAY['tenant:provision', 'credential:manage']::text[]
    );
    RETURN v_tenant_id;
END;
$function$
"""

_REGISTER_AUTH_BINDING = f"""
CREATE FUNCTION {SCHEMA}.register_auth_binding(
    p_principal_id uuid,
    p_scopes text[],
    p_expires_at timestamptz
) RETURNS TABLE (binding_id uuid, credential text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_context {SCHEMA}.auth_context_row;
    v_credential text;
    v_id uuid;
    v_attempt integer := 0;
    v_scope text;
    v_requested text[];
BEGIN
    v_context := {SCHEMA}.auth_context();
    -- The tenant is NOT an argument. It is whatever the current context authenticated as,
    -- so no caller -- runtime or provisioning -- can mint a capability into a tenant it
    -- does not already hold.
    IF v_context.tenant_id IS NULL THEN
        RAISE EXCEPTION 'firmbatch: registering an authentication binding requires an authenticated context'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT COALESCE('credential:manage' = ANY (v_context.scopes), false) THEN
        RAISE EXCEPTION 'firmbatch: registering an authentication binding requires the credential:manage scope'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_principal_id IS NULL THEN
        RAISE EXCEPTION 'firmbatch: an authentication binding needs a principal'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- ------------------------------------------------------------------ delegation
    --
    -- ``credential:manage`` authorises *creating* a credential. It does not imply the
    -- permissions the new credential carries, and without this block it did: a leaked
    -- credential holding only ``credential:manage`` could mint itself a successor holding
    -- ``workspace:write`` and ``audit:read``, which is privilege escalation inside the
    -- tenant performed entirely through the supported interface.
    --
    -- The rule, in the database because that is the only place it holds under arbitrary
    -- runtime SQL:
    --
    -- * every requested scope must be **delegable** -- ``tenant:provision`` is not, because
    --   it belongs to the bootstrap path and is acquired from begin_tenant_provisioning()
    --   rather than carried by any credential;
    -- * a **credential** issuer may grant only scopes it holds itself. Including
    --   ``credential:manage``: delegating it is permitted because it is a subset of what
    --   the issuer already has, it is confined to the issuer's own tenant, and refusing it
    --   would only mean credential rotation could not be delegated. There is deliberately
    --   no administrator wildcard -- no scope, and no value of any scope, means "all";
    -- * a **provisioning** issuer may grant any delegable scope, and that is the one
    --   exemption. It is not an escalation: it holds no credential to inherit from, the
    --   tenant it is acting in was generated inside this same transaction by
    --   begin_tenant_provisioning(), so it cannot reach an existing one, and it is
    --   reachable only by the separate provisioning database role. Bootstrapping a
    --   tenant's first credential has to come from somewhere, and this is the somewhere.
    --
    -- Unknown scopes are refused here rather than left to the ``scopes_known`` check
    -- constraint, because a constraint violation renders the failing row -- including the
    -- rejected value -- in its DETAIL.
    v_requested := COALESCE(p_scopes, ARRAY[]::text[]);
    IF pg_catalog.array_ndims(v_requested) > 1 THEN
        RAISE EXCEPTION 'firmbatch: a scope set is a one-dimensional array'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF pg_catalog.cardinality(v_requested)
       <> (SELECT pg_catalog.count(DISTINCT s) FROM pg_catalog.unnest(v_requested) AS s) THEN
        RAISE EXCEPTION 'firmbatch: the requested scope set repeats a scope'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'a scope set is a set; the rejected values are deliberately not shown';
    END IF;
    FOREACH v_scope IN ARRAY v_requested LOOP
        IF v_scope IS NULL THEN
            RAISE EXCEPTION 'firmbatch: a scope set contains no nulls'
                USING ERRCODE = 'invalid_parameter_value';
        END IF;
        IF NOT (v_scope = ANY (ARRAY[{_quoted_list(KNOWN_SCOPES)}]::text[])) THEN
            RAISE EXCEPTION 'firmbatch: the requested scope set names a scope that is not in the catalogue'
                USING ERRCODE = 'invalid_parameter_value',
                      DETAIL = 'the catalogue is closed and adding to it is a migration; the rejected '
                               'value is deliberately not shown';
        END IF;
        IF NOT (v_scope = ANY (ARRAY[{_quoted_list(DELEGABLE_SCOPES)}]::text[])) THEN
            RAISE EXCEPTION 'firmbatch: the requested scope set names a scope that may not be placed on '
                            'an issued credential'
                USING ERRCODE = 'insufficient_privilege',
                      DETAIL = 'that capability belongs to the provisioning path and is acquired from '
                               'begin_tenant_provisioning(); the rejected value is not shown';
        END IF;
        IF v_context.actor_kind <> 'provisioning'
           AND NOT COALESCE(v_scope = ANY (v_context.scopes), false) THEN
            RAISE EXCEPTION 'firmbatch: a credential may not be issued a scope its issuer does not hold'
                USING ERRCODE = 'insufficient_privilege',
                      DETAIL = 'credential:manage authorises creating a credential; it does not imply '
                               'the permissions that credential carries. The rejected value is not shown';
        END IF;
    END LOOP;

    -- The credential is generated HERE and returned once. It is not a parameter, and that
    -- is the point: a caller that could submit a candidate could submit somebody else's
    -- and learn from the outcome whether it already existed -- across tenants, in a table
    -- it cannot read. Translating the unique violation into another error would not help,
    -- because success versus failure is the oracle. Removing the caller's choice does.
    --
    -- Two gen_random_uuid() values are 244 bits from PostgreSQL's strong RNG, rendered as
    -- 43 URL-safe characters so the result matches the one credential format this system
    -- has. The loop is for form: a collision at this width will not happen, and if it did
    -- the caller would see a retry rather than an error carrying somebody else's secret.
    LOOP
        v_attempt := v_attempt + 1;
        v_credential := 'fbk_' || pg_catalog.translate(
            pg_catalog.encode(
                pg_catalog.decode(pg_catalog.replace(pg_catalog.gen_random_uuid()::text, '-', ''), 'hex')
                || pg_catalog.decode(pg_catalog.replace(pg_catalog.gen_random_uuid()::text, '-', ''), 'hex'),
                'base64'
            ),
            E'+/=\\n', '-_'
        );

        INSERT INTO {SCHEMA}.auth_bindings (tenant_id, principal_id, fingerprint, scopes, expires_at)
        VALUES (
            v_context.tenant_id,
            p_principal_id,
            pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_credential, 'UTF8')), 'hex'),
            v_requested,
            p_expires_at
        )
        ON CONFLICT (fingerprint) DO NOTHING
        RETURNING id INTO v_id;

        EXIT WHEN v_id IS NOT NULL;
        IF v_attempt >= 3 THEN
            RAISE EXCEPTION 'firmbatch: could not mint a distinct authentication binding'
                USING ERRCODE = 'internal_error';
        END IF;
    END LOOP;

    binding_id := v_id;
    credential := v_credential;
    RETURN NEXT;
END;
$function$
"""

_REVOKE_AUTH_BINDING = f"""
CREATE FUNCTION {SCHEMA}.revoke_auth_binding(p_binding_id uuid) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_context {SCHEMA}.auth_context_row;
    v_revoked integer;
BEGIN
    v_context := {SCHEMA}.auth_context();
    IF v_context.tenant_id IS NULL
       OR NOT COALESCE('credential:manage' = ANY (v_context.scopes), false)
    THEN
        RAISE EXCEPTION 'firmbatch: revoking an authentication binding requires the credential:manage scope'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Scoped to the context's tenant, so a binding in another tenant is not revocable and
    -- is not distinguishable from one that does not exist: both return false.
    -- clock_timestamp() so the revocation instant is when this ran, not when the
    -- transaction opened.
    UPDATE {SCHEMA}.auth_bindings
    SET revoked_at = pg_catalog.clock_timestamp()
    WHERE id = p_binding_id
      AND tenant_id = v_context.tenant_id
      AND revoked_at IS NULL;
    GET DIAGNOSTICS v_revoked = ROW_COUNT;
    RETURN v_revoked > 0;
END;
$function$
"""

#: The one way a runtime role writes an audit row. No role holds ``INSERT`` on
#: ``firmbatch.audit_events``, so this is not the polite path -- it is the only path.
#:
#: That matters because the Python boundary in ``db/audit.py`` is Python: a runtime role
#: could always have opened a connection and written a row itself, and the check
#: constraints on the table bound only its size and its shape, not its content. Every rule
#: the boundary applies is applied here as well, on the values as they are about to be
#: written.
#:
#: **Nothing derived is a parameter.** The tenant, the actor kind, the principal, the
#: binding and the timestamp are not arguments this function has, so there is no value a
#: caller can supply for any of them and nothing to compare against the context. The
#: insert policy still evaluates -- row security is ``FORCE``d, and a ``SECURITY DEFINER``
#: function runs as the owner, whom FORCE binds too -- so the derivation is checked twice.
#:
#: No ``RETURNING``: PostgreSQL applies ``SELECT`` policies to ``INSERT ... RETURNING``,
#: which would make appending to the trail require ``audit:read``. The id is generated
#: here and returned as the function's own result instead.
_APPEND_AUDIT_EVENT = f"""
CREATE FUNCTION {SCHEMA}.append_audit_event(
    p_action text,
    p_outcome text,
    p_resource_type text,
    p_resource_id uuid,
    p_correlation_id uuid,
    p_details jsonb
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_context {SCHEMA}.auth_context_row;
    v_id uuid;
    v_shape text;
BEGIN
    v_context := {SCHEMA}.auth_context();
    IF v_context.tenant_id IS NULL THEN
        RAISE EXCEPTION 'firmbatch: appending an audit event requires an authenticated context'
            USING ERRCODE = 'insufficient_privilege',
                  DETAIL = 'present a credential with bind_authenticated_context(); appending needs '
                           'no scope beyond one, so that no credential can act without leaving a trail';
    END IF;

    -- Shape first, then format, and neither echoes: an action name is caller-supplied text
    -- like any other, so a credential pasted into one would otherwise be quoted by the
    -- check that refused it.
    v_shape := {SCHEMA}.secret_shape(p_action);
    IF v_shape IS NOT NULL THEN
        RAISE EXCEPTION 'firmbatch: the audit action looks like %', v_shape
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the value is deliberately not shown';
    END IF;
    IF p_action IS NULL OR p_action !~ '{DOTTED_NAME_REGEX}' THEN
        RAISE EXCEPTION 'firmbatch: the audit action is not a dotted lowercase name'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the value is deliberately not shown';
    END IF;

    v_shape := {SCHEMA}.secret_shape(p_resource_type);
    IF v_shape IS NOT NULL THEN
        RAISE EXCEPTION 'firmbatch: the audit resource type looks like %', v_shape
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the value is deliberately not shown';
    END IF;
    IF p_resource_type IS NULL OR p_resource_type !~ '{SIMPLE_NAME_REGEX}' THEN
        RAISE EXCEPTION 'firmbatch: the audit resource type is not a lowercase name'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the value is deliberately not shown';
    END IF;

    IF p_outcome IS NULL OR NOT (p_outcome = ANY (ARRAY[{_quoted_list(AUDIT_OUTCOMES)}]::text[])) THEN
        RAISE EXCEPTION 'firmbatch: the audit outcome is not one of the four this system records'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the set is closed; the rejected value is deliberately not shown';
    END IF;

    PERFORM {SCHEMA}.audit_require_acceptable_details(p_details);

    v_id := pg_catalog.gen_random_uuid();
    INSERT INTO {SCHEMA}.audit_events (
        id, tenant_id, actor_kind, actor_principal_id, actor_binding_id,
        action, outcome, resource_type, resource_id, correlation_id, details
    )
    VALUES (
        v_id, v_context.tenant_id, v_context.actor_kind, v_context.principal_id, v_context.binding_id,
        p_action, p_outcome, p_resource_type, p_resource_id, p_correlation_id,
        COALESCE(p_details, '{{}}'::jsonb)
    );
    RETURN v_id;
END;
$function$
"""

_AUDIT_TIMESTAMP_TRIGGER = f"""
CREATE FUNCTION {SCHEMA}.audit_events_set_occurred_at() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    -- Overwritten unconditionally, so there is no value a caller can supply and no value
    -- it can preserve. ``clock_timestamp()`` and not ``now()``: ``now()`` is
    -- transaction-start time, so a caller that opened its transaction an hour ago could
    -- otherwise date an event an hour into the past without supplying anything at all.
    --
    -- A BEFORE trigger rather than a column default, because a default only applies when
    -- the column is omitted. Row-level security's WITH CHECK runs after BEFORE triggers,
    -- so this is also what the insert policy sees.
    NEW.occurred_at := pg_catalog.clock_timestamp();
    RETURN NEW;
END;
$function$
"""

_LEGACY_TENANT_HELPER = f"""
CREATE FUNCTION {SCHEMA}.app_current_tenant_id() RETURNS uuid
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT nullif(current_setting('app.tenant_id', true), '')::uuid
$function$
"""


def _accessor_sql(name: str, returns: str, body: str) -> str:
    return f"""
CREATE FUNCTION {SCHEMA}.{name}() RETURNS {returns}
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    {body}
$function$
"""


def upgrade() -> None:
    # --- the protected registry ------------------------------------------------------
    op.create_table(
        "auth_bindings",
        sa.Column("id", _UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", _UUID, nullable=False),
        sa.Column("principal_id", _UUID, nullable=False),
        sa.Column("fingerprint", sa.Text(), nullable=False),
        sa.Column("scopes", ARRAY(sa.Text()), nullable=False),
        sa.Column("created_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("now()")),
        sa.Column("expires_at", _TIMESTAMPTZ, nullable=True),
        sa.Column("revoked_at", _TIMESTAMPTZ, nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_auth_bindings"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            [f"{SCHEMA}.tenants.id"],
            name="fk_auth_bindings_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        # Global rather than tenant-local, and that is correct: the fingerprint space is
        # global, a cross-tenant collision would be a SHA-256 collision, and no role can
        # observe this constraint because no role can query the table -- and since the
        # credential is generated inside register_auth_binding, no caller can submit a
        # candidate to probe it with either.
        sa.UniqueConstraint("fingerprint", name="uq_auth_bindings_fingerprint"),
        sa.UniqueConstraint("id", "tenant_id", name="uq_auth_bindings_id_tenant_id"),
        sa.CheckConstraint(f"fingerprint ~ '{FINGERPRINT_REGEX}'", name="fingerprint_format"),
        sa.CheckConstraint("array_ndims(scopes) = 1", name="scopes_one_dimension"),
        sa.CheckConstraint(f"cardinality(scopes) <= {MAX_SCOPES_PER_BINDING}", name="scopes_bounded"),
        sa.CheckConstraint("array_position(scopes, NULL) IS NULL", name="scopes_not_null"),
        # The closed catalogue, in the database. An unknown scope cannot be stored and so
        # cannot become meaningful later when somebody adds a policy that reads it.
        sa.CheckConstraint(
            f"scopes <@ ARRAY[{_quoted_list(KNOWN_SCOPES)}]::text[]", name="scopes_known"
        ),
        sa.CheckConstraint("expires_at IS NULL OR expires_at > created_at", name="expiry_after_creation"),
        schema=SCHEMA,
    )
    op.create_index("ix_auth_bindings_tenant_id", "auth_bindings", ["tenant_id"], schema=SCHEMA)

    # --- the protected transaction context --------------------------------------------
    #
    # UNLOGGED because every row is dead the moment its transaction ends: a crash that
    # truncates this table destroys nothing that survived the crash anyway, and the WAL it
    # saves is written on every authenticated request.
    #
    # One row per backend pid, replaced in place, so the table is bounded by the pid space
    # and never grows. There is deliberately no pruning job: there is nothing to prune.
    op.execute(
        f"""
        CREATE UNLOGGED TABLE {SCHEMA}.{CONTEXT_RELATION} (
            backend_pid  integer PRIMARY KEY,
            xact_id      xid8 NOT NULL,
            binding_id   uuid,
            tenant_id    uuid NOT NULL,
            principal_id uuid,
            actor_kind   text NOT NULL,
            scopes       text[] NOT NULL,
            bound_at     timestamptz NOT NULL
        )
        """
    )

    # --- the context type and the functions -------------------------------------------
    #
    # Before the audit table, because its column defaults call these.
    op.execute(
        f"""
        CREATE TYPE {SCHEMA}.auth_context_row AS (
            binding_id uuid,
            tenant_id uuid,
            principal_id uuid,
            actor_kind text,
            scopes text[]
        )
        """
    )
    op.execute(_AUTH_REQUIRE_READ_COMMITTED)
    op.execute(_AUTH_REQUIRE_WRITABLE_PRIMARY)
    op.execute(_SECRET_SHAPE)
    op.execute(_AUDIT_REQUIRE_ACCEPTABLE_DETAILS)
    op.execute(_AUTH_CONTEXT_BEGIN)
    op.execute(_AUTH_CONTEXT)
    for name, returns, body in _ACCESSORS:
        op.execute(_accessor_sql(name, returns, body))
    op.execute(_AUTH_HAS_SCOPE)
    op.execute(_BIND_AUTHENTICATED_CONTEXT)
    op.execute(_BEGIN_TENANT_PROVISIONING)
    op.execute(_REGISTER_AUTH_BINDING)
    op.execute(_REVOKE_AUTH_BINDING)
    op.execute(_AUDIT_TIMESTAMP_TRIGGER)

    # --- the audit trail --------------------------------------------------------------
    op.create_table(
        "audit_events",
        sa.Column("id", _UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "tenant_id", _UUID, nullable=False, server_default=sa.text(f"{SCHEMA}.auth_tenant_id()")
        ),
        sa.Column(
            "actor_kind", sa.Text(), nullable=False, server_default=sa.text(f"{SCHEMA}.auth_actor_kind()")
        ),
        sa.Column(
            "actor_principal_id", _UUID, nullable=True, server_default=sa.text(f"{SCHEMA}.auth_principal_id()")
        ),
        sa.Column(
            "actor_binding_id", _UUID, nullable=True, server_default=sa.text(f"{SCHEMA}.auth_binding_id()")
        ),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("resource_type", sa.Text(), nullable=False),
        sa.Column("resource_id", _UUID, nullable=True),
        sa.Column("correlation_id", _UUID, nullable=True),
        sa.Column("details", _JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        # The default is a formality: the BEFORE INSERT trigger overwrites this on every
        # row. It is kept so the column has one if the trigger is ever dropped by mistake,
        # and so that ``NOT NULL`` never fires in place of an explanation.
        sa.Column("occurred_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("clock_timestamp()")),
        sa.PrimaryKeyConstraint("id", name="pk_audit_events"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            [f"{SCHEMA}.tenants.id"],
            name="fk_audit_events_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        # Composite, because referential integrity is checked with row security bypassed
        # and a single-column reference would happily attribute an action to a binding in
        # another tenant. MATCH SIMPLE exempts the provisioning case, whose binding is
        # NULL, rather than leaving it dangling.
        sa.ForeignKeyConstraint(
            ["actor_binding_id", "tenant_id"],
            [f"{SCHEMA}.auth_bindings.id", f"{SCHEMA}.auth_bindings.tenant_id"],
            name="fk_audit_events_actor_binding_id_tenant_id",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("id", "tenant_id", name="uq_audit_events_id_tenant_id"),
        sa.CheckConstraint(f"action ~ '{DOTTED_NAME_REGEX}'", name="action_format"),
        sa.CheckConstraint(f"resource_type ~ '{SIMPLE_NAME_REGEX}'", name="resource_type_format"),
        sa.CheckConstraint(f"outcome IN ({_quoted_list(AUDIT_OUTCOMES)})", name="outcome_known"),
        sa.CheckConstraint(f"actor_kind IN ({_quoted_list(AUDIT_ACTOR_KINDS)})", name="actor_kind_known"),
        sa.CheckConstraint(
            "(actor_kind = 'credential' AND actor_principal_id IS NOT NULL AND actor_binding_id IS NOT NULL)"
            " OR (actor_kind = 'provisioning' AND actor_principal_id IS NULL AND actor_binding_id IS NULL)",
            name="actor_shape",
        ),
        *_metadata_checks("details"),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_audit_events_tenant_id_occurred_at", "audit_events", ["tenant_id", "occurred_at"], schema=SCHEMA
    )
    op.execute(
        f"""
        CREATE TRIGGER audit_events_occurred_at
        BEFORE INSERT ON {SCHEMA}.audit_events
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.audit_events_set_occurred_at()
        """
    )
    op.execute(f"ALTER TABLE {SCHEMA}.audit_events ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {SCHEMA}.audit_events FORCE ROW LEVEL SECURITY")
    # After the table it writes into, so the reader meets them in the order they depend on
    # one another. plpgsql resolves names at execution, so the order is legibility rather
    # than a requirement -- which is exactly why it is worth keeping honest.
    op.execute(_APPEND_AUDIT_EVENT)

    # --- replace every policy ----------------------------------------------------------
    #
    # The old ones read a setting any holder of the connection could write. They are
    # dropped rather than left beside the new ones: two policies for one command are
    # combined with OR, so leaving one in place would mean the weaker one still decided.
    for table, policies in _LEGACY_POLICIES.items():
        for policy_name, _command, _column in policies:
            op.execute(f"DROP POLICY {policy_name} ON {SCHEMA}.{table}")

    for table, policies in POLICIES.items():
        for command, suffix, using, with_check in policies:
            clauses = [f"CREATE POLICY {_policy_name(table, suffix)} ON {SCHEMA}.{table}"]
            clauses.append(f"FOR {command}")
            clauses.append("TO PUBLIC")
            if using is not None:
                clauses.append(f"USING ({using})")
            if with_check is not None:
                clauses.append(f"WITH CHECK ({with_check})")
            op.execute("\n".join(clauses))

    # The helper the old policies called. Dropped, not deprecated: a function that looks
    # like the tenant-context mechanism and is not one is worse than no function at all,
    # and nothing may be able to set a tenant by writing a GUC.
    op.execute(f"DROP FUNCTION {SCHEMA}.app_current_tenant_id()")

    # --- and finally, state the access control rather than inheriting it ---------------
    #
    # Last, so it covers every object this migration created *and* everything 0001 and
    # 0002 left behind. db/roles.py runs the same sanitisation before its grants, so an
    # environment provisioned later gets the same answer.
    op.execute(_SANITIZE_SCHEMA_ACL)


def downgrade() -> None:
    """Back to the M2.2 shape exactly: the caller-set setting, and the policies reading it.

    Ordered by dependency rather than by narrative. The new policies call the accessor
    functions and ``audit_events`` column defaults call them too, so both have to go
    before the functions do; the functions return the composite type, so it goes after
    them; and the legacy policies cannot be created until the legacy helper exists.
    """
    for table, policies in POLICIES.items():
        for _command, suffix, _using, _with_check in policies:
            op.execute(f"DROP POLICY IF EXISTS {_policy_name(table, suffix)} ON {SCHEMA}.{table}")

    op.drop_index("ix_audit_events_tenant_id_occurred_at", table_name="audit_events", schema=SCHEMA)
    op.drop_table("audit_events", schema=SCHEMA)

    for name, signature, _audience in reversed(FUNCTIONS):
        op.execute(f"DROP FUNCTION {SCHEMA}.{name}({signature})")
    op.execute(f"DROP TYPE {SCHEMA}.auth_context_row")

    op.execute(f"DROP TABLE {SCHEMA}.{CONTEXT_RELATION}")
    op.drop_index("ix_auth_bindings_tenant_id", table_name="auth_bindings", schema=SCHEMA)
    op.drop_table("auth_bindings", schema=SCHEMA)

    op.execute(_LEGACY_TENANT_HELPER)
    op.execute(f"REVOKE ALL ON FUNCTION {SCHEMA}.app_current_tenant_id() FROM PUBLIC")

    legacy_predicate = f"{SCHEMA}.app_current_tenant_id()"
    for table, policies in _LEGACY_POLICIES.items():
        for policy_name, command, column in policies:
            clauses = [f"CREATE POLICY {policy_name} ON {SCHEMA}.{table}", f"FOR {command}", "TO PUBLIC"]
            if command in ("ALL", "SELECT"):
                clauses.append(f"USING ({column} = {legacy_predicate})")
            if command in ("ALL", "INSERT"):
                clauses.append(f"WITH CHECK ({column} = {legacy_predicate})")
            op.execute("\n".join(clauses))
