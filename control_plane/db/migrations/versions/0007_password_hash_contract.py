"""The password-hash contract: structural validation in every entry point that accepts a hash.

Revision ID: 0007_password_hash_contract
Revises: 0006_preferences_and_password
Create Date: 2026-09-14

An **incidental reliability and security correction**, found by Milestone 3.3b's verification
rather than planned by it. It takes migration number ``0007``, so the Milestone 3.3c identity
mapping that ADR 0011 and ``docs/architecture/m3-3-aws-staging-topology.md`` assign to ``0007``
moves to ``0008``. Those records are not rewritten; ADR 0012 and ``docs/STATE.md`` record the
renumbering. Migrations ``0001``-``0006`` are untouched history.

**The defect.** Three ``SECURITY DEFINER`` entry points accept an Argon2id PHC hash from the
runtime -- ``signup_account`` (``0005``'s body), ``complete_account_recovery`` (``0006``'s body)
and ``change_account_password`` (``0006``) -- and each refused the hash when
``firmbatch.secret_shape`` named a shape anywhere in it. ``security/passwords`` did the same in
Python, and ``hash_password`` applies that check to its own output. The salt and digest of a
PHC hash are random unpadded base64. Of the recogniser's shapes, the AWS access-key-id shape is
the one that alphabet can form: after the case fold, ``akia`` or ``asia``, sixteen letters or
digits, and a ``+``, ``/``, ``$`` or the end of the value on either side. So a valid hash of a
valid password was refused at random -- rarely per hash, but with certainty across enough of
them. A canonical verification run during Milestone 3.3b failed once in the PostgreSQL suite
with ``PasswordPolicyError`` from exactly that output check. A customer who met it would have
been told that a signup, a recovery or a password change had failed.

**The contract now.** A value is a stored password hash if and only if it is not NULL, is at
most ``PASSWORD_HASH_MAX_LENGTH`` characters, and matches ``PASSWORD_HASH_REGEX`` exactly:
Argon2id, version 19, three bounded parameters, then a salt and a digest in the standard base64
alphabet. Only the ``secret_shape(<hash>)`` term is removed from the three bodies. The NULL,
length and pattern checks, the refusal's SQLSTATE and its value-free message, and every other
statement are unchanged. The recogniser itself is unchanged, and every other caller still
applies it: metadata, audit fields, labels, names, slugs and idempotency keys are scanned
exactly as before. Raw passwords never reach the database; ``security/passwords`` validates
them before hashing, as it always has.

**Replace and restore.** The three bodies are replaced with ``CREATE OR REPLACE``, which keeps
each function's identity, owner, ACL, ``SECURITY DEFINER`` and pinned ``search_path``. Nothing
is granted or revoked, and the ACL sanitiser is deliberately not called, so the downgrade has
only the bodies to put back. It restores them byte-for-byte: ``0005``'s ``signup_account``
text, and ``0006``'s ``complete_account_recovery`` and ``change_account_password`` texts. A hash
stored at this revision stays storable after a downgrade, because the column's check constraints
are the pattern and the length and never the scan.

``tests/test_password_hash_contract.py`` asserts the constants have not drifted; that the
legacy texts are the earlier migrations' verbatim; that each head differs from its legacy text
only by the removed scan (and, in ``signup_account``, the comment that described it); that the
replaced functions keep owner, ACL and hardening; and that a downgrade to ``0006`` produces the
catalogue a fresh migration to ``0006`` produces. It also asserts that signup, recovery and a
signed-in password change all accept a valid hash whose encoded material carries the formerly
refused shape.
"""

from __future__ import annotations

from alembic import op

revision: str = "0007_password_hash_contract"
down_revision: str | None = "0006_preferences_and_password"
branch_labels: str | None = None
depends_on: str | None = None

SCHEMA = "firmbatch"

# Mirrors security/passwords.py, db/models.py and the constants 0005 and 0006 render into the
# bodies below. A migration must not import them, so they are duplicated, and
# tests/test_password_hash_contract.py asserts the duplicates have not drifted.

#: The stored password form. Mirrors ``security/passwords.PASSWORD_HASH_REGEX``.
PASSWORD_HASH_REGEX = (
    r"^\$argon2id\$v=19\$m=[0-9]{1,9},t=[0-9]{1,4},p=[0-9]{1,3}"
    r"\$[A-Za-z0-9+/]{16,}\$[A-Za-z0-9+/]{16,}$"
)
PASSWORD_HASH_MAX_LENGTH = 512
MAX_SESSION_TTL = "30 days"
MAX_TOKEN_TTL = "7 days"
ASCII_WHITESPACE_SQL = r"E' \t\n\r\f\v'"
IDENTITY_SECRET_PREFIXES = {"session": "fbs_", "csrf": "fbc_"}
IDENTITY_REFUSED_SQLSTATE = "FB010"
IDENTITY_CONFLICT_SQLSTATE = "FB011"
IDENTITY_CONTEXT_SQLSTATE = "FB013"
IDENTITY_REFUSED_MESSAGE = "firmbatch: the identity operation was refused"

# ------------------------------------------------------------- the three bodies it replaces
#
# Each legacy constant is the body the database holds at 0006, verbatim, and each restore is
# the form a downgrade executes. tests/test_password_hash_contract.py asserts both.

#: ``0005``'s ``signup_account``, verbatim. ``0006`` did not replace it.
_LEGACY_SIGNUP_ACCOUNT = f"""
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

_LEGACY_SIGNUP_ACCOUNT_RESTORE = _LEGACY_SIGNUP_ACCOUNT.replace(
    "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1
)

#: ``0006``'s ``complete_account_recovery`` head body, verbatim. ``0006`` already wrote it as
#: ``CREATE OR REPLACE``, so it is its own restore.
_LEGACY_COMPLETE_ACCOUNT_RECOVERY = f"""
CREATE OR REPLACE FUNCTION {SCHEMA}.complete_account_recovery(p_secret text, p_new_password_hash text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_account_id uuid;
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
    -- The account-plane lock order: the account row first. The token is read unlocked here
    -- only to learn WHICH account row to lock; it is re-read, locked and re-validated under
    -- that lock below, so nothing decided here rests on this read.
    SELECT t.account_id INTO v_account_id
    FROM {SCHEMA}.account_tokens t
    WHERE t.fingerprint = {SCHEMA}.identity_fingerprint(p_secret)
      AND t.kind = 'account_recovery';
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    -- The serialisation point every account-plane writer shares: open_browser_session,
    -- password_change_lookup, change_account_password and verify_account_email take this
    -- row first too, so two of them can only ever wait for each other here, in one
    -- direction, and never deadlock.
    PERFORM 1 FROM {SCHEMA}.accounts a WHERE a.id = v_account_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    v_now := pg_catalog.clock_timestamp();
    -- Re-read, locked, under the account row: READ COMMITTED gives this statement a fresh
    -- snapshot, so a consumption or a supersession that committed while this transaction
    -- waited for the account row -- a password change that ended every token, another
    -- completion of this same link -- is observed, and the token stays one-time exactly.
    SELECT t.id, t.consumed_at, t.superseded_at, t.expires_at INTO v_token
    FROM {SCHEMA}.account_tokens t
    WHERE t.fingerprint = {SCHEMA}.identity_fingerprint(p_secret)
      AND t.kind = 'account_recovery'
      AND t.account_id = v_account_id
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
    WHERE account_id = v_account_id AND consumed_at IS NULL AND superseded_at IS NULL;
    UPDATE {SCHEMA}.account_passwords
    SET password_hash = p_new_password_hash, updated_at = v_now
    WHERE account_id = v_account_id;
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
    WHERE id = v_account_id;
    -- The visible bindings are also marked revoked, so a credential listing reflects the
    -- eviction rather than showing an active row the bind will nonetheless refuse. The
    -- epoch is what makes the eviction complete; this makes it legible.
    UPDATE {SCHEMA}.auth_bindings
    SET revoked_at = v_now
    WHERE principal_id = v_account_id AND membership_id IS NOT NULL AND revoked_at IS NULL;
    -- And every browser session: a recovered password is the standard moment to end
    -- whatever was signed in with the old one.
    UPDATE {SCHEMA}.browser_sessions
    SET revoked_at = v_now
    WHERE account_id = v_account_id AND revoked_at IS NULL;
    RETURN true;
END;
$function$
"""

_LEGACY_COMPLETE_ACCOUNT_RECOVERY_RESTORE = _LEGACY_COMPLETE_ACCOUNT_RECOVERY

#: ``0006``'s ``change_account_password``, verbatim.
_LEGACY_CHANGE_ACCOUNT_PASSWORD = f"""
CREATE FUNCTION {SCHEMA}.change_account_password(
    p_expected_hash text, p_new_password_hash text, p_ttl interval
)
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
    v_now timestamptz;
    v_updated integer;
    v_id uuid;
    v_session text;
    v_csrf text;
    v_expires timestamptz;
BEGIN
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();
    PERFORM {SCHEMA}.identity_require_ttl(p_ttl, INTERVAL '{MAX_SESSION_TTL}');
    IF p_new_password_hash IS NULL
       OR pg_catalog.length(p_new_password_hash) > {PASSWORD_HASH_MAX_LENGTH}
       OR {SCHEMA}.secret_shape(p_new_password_hash) IS NOT NULL
       OR p_new_password_hash !~ '{PASSWORD_HASH_REGEX}' THEN
        RAISE EXCEPTION 'firmbatch: the password hash is not in the stored form'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the value is deliberately not shown';
    END IF;
    -- Only for the account this transaction challenged. There is no account parameter, for
    -- open_browser_session's reason: the runtime cannot change the password of an account
    -- whose stored hash it never asked for.
    v_context := {SCHEMA}.identity_context();
    IF v_context.kind IS DISTINCT FROM 'password_change_challenge'
       OR v_context.account_id IS NULL THEN
        RAISE EXCEPTION 'firmbatch: a password is changed only for the account this transaction challenged'
            USING ERRCODE = '{IDENTITY_CONTEXT_SQLSTATE}',
                  DETAIL = 'call password_change_lookup() in this transaction first';
    END IF;
    v_now := pg_catalog.clock_timestamp();
    -- Still locked from the lookup; re-read under it so the epoch compared is the committed
    -- one rather than this transaction's snapshot.
    SELECT a.status, a.security_epoch INTO v_status, v_epoch
    FROM {SCHEMA}.accounts a WHERE a.id = v_context.account_id FOR UPDATE;
    IF NOT FOUND OR v_status <> 'active'
       OR v_context.security_epoch IS NULL OR v_epoch IS DISTINCT FROM v_context.security_epoch THEN
        RAISE EXCEPTION '{IDENTITY_REFUSED_MESSAGE}'
            USING ERRCODE = '{IDENTITY_REFUSED_SQLSTATE}';
    END IF;
    -- The account-plane lock order from here: tokens, then the password row, then the
    -- account's own update, the bindings and the sessions.
    UPDATE {SCHEMA}.account_tokens
    SET superseded_at = v_now
    WHERE account_id = v_context.account_id AND consumed_at IS NULL AND superseded_at IS NULL;
    -- The compare-and-swap. A concurrent change or recovery that replaced the hash between
    -- the lookup and here matches nothing, and this transaction loses -- and everything
    -- above rolls back with it.
    UPDATE {SCHEMA}.account_passwords
    SET password_hash = p_new_password_hash, updated_at = v_now
    WHERE account_id = v_context.account_id
      AND password_hash IS NOT DISTINCT FROM p_expected_hash;
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    IF v_updated <> 1 THEN
        RAISE EXCEPTION 'firmbatch: the password changed while this change was being prepared'
            USING ERRCODE = '{IDENTITY_CONFLICT_SQLSTATE}',
                  DETAIL = 'nothing was changed; verify the current password again';
    END IF;
    UPDATE {SCHEMA}.accounts
    SET security_epoch = security_epoch + 1, updated_at = v_now
    WHERE id = v_context.account_id;
    UPDATE {SCHEMA}.auth_bindings
    SET revoked_at = v_now
    WHERE principal_id = v_context.account_id AND membership_id IS NOT NULL AND revoked_at IS NULL;
    UPDATE {SCHEMA}.browser_sessions
    SET revoked_at = v_now
    WHERE account_id = v_context.account_id AND revoked_at IS NULL;
    -- The replacement, minted after the sweep so it is not caught by it. Identical in every
    -- property to what open_browser_session mints; see this migration's docstring for why it
    -- is written here rather than called.
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

_LEGACY_CHANGE_ACCOUNT_PASSWORD_RESTORE = _LEGACY_CHANGE_ACCOUNT_PASSWORD.replace(
    "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1
)

# --------------------------------------------------------------------------- the head bodies
#
# Each is its legacy restore with the one ``secret_shape(<hash>)`` line removed -- and, in
# ``signup_account``, the two-line comment that described it replaced by one that describes
# the structural check. Nothing else differs.

#: ``signup_account``: the email, then the hash by structure alone, then the TTL.
_SIGNUP_ACCOUNT_HEAD = f"""
CREATE OR REPLACE FUNCTION {SCHEMA}.signup_account(p_email text, p_password_hash text, p_token_ttl interval)
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
    -- The stored form and nothing else: not a plaintext, not another algorithm. Structure
    -- alone decides it (0007): the salt and digest are random base64, which a generic shape
    -- scan refuses by chance, and nothing but an Argon2id PHC hash matches this pattern.
    IF p_password_hash IS NULL
       OR pg_catalog.length(p_password_hash) > {PASSWORD_HASH_MAX_LENGTH}
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

#: ``complete_account_recovery``: the ``0006`` lock order, with the hash checked by structure.
_COMPLETE_ACCOUNT_RECOVERY_HEAD = f"""
CREATE OR REPLACE FUNCTION {SCHEMA}.complete_account_recovery(p_secret text, p_new_password_hash text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_account_id uuid;
    v_token record;
    v_now timestamptz;
BEGIN
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();
    IF p_new_password_hash IS NULL
       OR pg_catalog.length(p_new_password_hash) > {PASSWORD_HASH_MAX_LENGTH}
       OR p_new_password_hash !~ '{PASSWORD_HASH_REGEX}' THEN
        RAISE EXCEPTION 'firmbatch: the password hash is not in the stored form'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the value is deliberately not shown';
    END IF;
    IF p_secret IS NULL OR pg_catalog.length(p_secret) = 0 THEN
        RETURN false;
    END IF;
    -- The account-plane lock order: the account row first. The token is read unlocked here
    -- only to learn WHICH account row to lock; it is re-read, locked and re-validated under
    -- that lock below, so nothing decided here rests on this read.
    SELECT t.account_id INTO v_account_id
    FROM {SCHEMA}.account_tokens t
    WHERE t.fingerprint = {SCHEMA}.identity_fingerprint(p_secret)
      AND t.kind = 'account_recovery';
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    -- The serialisation point every account-plane writer shares: open_browser_session,
    -- password_change_lookup, change_account_password and verify_account_email take this
    -- row first too, so two of them can only ever wait for each other here, in one
    -- direction, and never deadlock.
    PERFORM 1 FROM {SCHEMA}.accounts a WHERE a.id = v_account_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    v_now := pg_catalog.clock_timestamp();
    -- Re-read, locked, under the account row: READ COMMITTED gives this statement a fresh
    -- snapshot, so a consumption or a supersession that committed while this transaction
    -- waited for the account row -- a password change that ended every token, another
    -- completion of this same link -- is observed, and the token stays one-time exactly.
    SELECT t.id, t.consumed_at, t.superseded_at, t.expires_at INTO v_token
    FROM {SCHEMA}.account_tokens t
    WHERE t.fingerprint = {SCHEMA}.identity_fingerprint(p_secret)
      AND t.kind = 'account_recovery'
      AND t.account_id = v_account_id
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
    WHERE account_id = v_account_id AND consumed_at IS NULL AND superseded_at IS NULL;
    UPDATE {SCHEMA}.account_passwords
    SET password_hash = p_new_password_hash, updated_at = v_now
    WHERE account_id = v_account_id;
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
    WHERE id = v_account_id;
    -- The visible bindings are also marked revoked, so a credential listing reflects the
    -- eviction rather than showing an active row the bind will nonetheless refuse. The
    -- epoch is what makes the eviction complete; this makes it legible.
    UPDATE {SCHEMA}.auth_bindings
    SET revoked_at = v_now
    WHERE principal_id = v_account_id AND membership_id IS NOT NULL AND revoked_at IS NULL;
    -- And every browser session: a recovered password is the standard moment to end
    -- whatever was signed in with the old one.
    UPDATE {SCHEMA}.browser_sessions
    SET revoked_at = v_now
    WHERE account_id = v_account_id AND revoked_at IS NULL;
    RETURN true;
END;
$function$
"""

#: ``change_account_password``: the ``0006`` compare-and-swap, with the hash checked by structure.
_CHANGE_ACCOUNT_PASSWORD_HEAD = f"""
CREATE OR REPLACE FUNCTION {SCHEMA}.change_account_password(
    p_expected_hash text, p_new_password_hash text, p_ttl interval
)
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
    v_now timestamptz;
    v_updated integer;
    v_id uuid;
    v_session text;
    v_csrf text;
    v_expires timestamptz;
BEGIN
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();
    PERFORM {SCHEMA}.identity_require_ttl(p_ttl, INTERVAL '{MAX_SESSION_TTL}');
    IF p_new_password_hash IS NULL
       OR pg_catalog.length(p_new_password_hash) > {PASSWORD_HASH_MAX_LENGTH}
       OR p_new_password_hash !~ '{PASSWORD_HASH_REGEX}' THEN
        RAISE EXCEPTION 'firmbatch: the password hash is not in the stored form'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the value is deliberately not shown';
    END IF;
    -- Only for the account this transaction challenged. There is no account parameter, for
    -- open_browser_session's reason: the runtime cannot change the password of an account
    -- whose stored hash it never asked for.
    v_context := {SCHEMA}.identity_context();
    IF v_context.kind IS DISTINCT FROM 'password_change_challenge'
       OR v_context.account_id IS NULL THEN
        RAISE EXCEPTION 'firmbatch: a password is changed only for the account this transaction challenged'
            USING ERRCODE = '{IDENTITY_CONTEXT_SQLSTATE}',
                  DETAIL = 'call password_change_lookup() in this transaction first';
    END IF;
    v_now := pg_catalog.clock_timestamp();
    -- Still locked from the lookup; re-read under it so the epoch compared is the committed
    -- one rather than this transaction's snapshot.
    SELECT a.status, a.security_epoch INTO v_status, v_epoch
    FROM {SCHEMA}.accounts a WHERE a.id = v_context.account_id FOR UPDATE;
    IF NOT FOUND OR v_status <> 'active'
       OR v_context.security_epoch IS NULL OR v_epoch IS DISTINCT FROM v_context.security_epoch THEN
        RAISE EXCEPTION '{IDENTITY_REFUSED_MESSAGE}'
            USING ERRCODE = '{IDENTITY_REFUSED_SQLSTATE}';
    END IF;
    -- The account-plane lock order from here: tokens, then the password row, then the
    -- account's own update, the bindings and the sessions.
    UPDATE {SCHEMA}.account_tokens
    SET superseded_at = v_now
    WHERE account_id = v_context.account_id AND consumed_at IS NULL AND superseded_at IS NULL;
    -- The compare-and-swap. A concurrent change or recovery that replaced the hash between
    -- the lookup and here matches nothing, and this transaction loses -- and everything
    -- above rolls back with it.
    UPDATE {SCHEMA}.account_passwords
    SET password_hash = p_new_password_hash, updated_at = v_now
    WHERE account_id = v_context.account_id
      AND password_hash IS NOT DISTINCT FROM p_expected_hash;
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    IF v_updated <> 1 THEN
        RAISE EXCEPTION 'firmbatch: the password changed while this change was being prepared'
            USING ERRCODE = '{IDENTITY_CONFLICT_SQLSTATE}',
                  DETAIL = 'nothing was changed; verify the current password again';
    END IF;
    UPDATE {SCHEMA}.accounts
    SET security_epoch = security_epoch + 1, updated_at = v_now
    WHERE id = v_context.account_id;
    UPDATE {SCHEMA}.auth_bindings
    SET revoked_at = v_now
    WHERE principal_id = v_context.account_id AND membership_id IS NOT NULL AND revoked_at IS NULL;
    UPDATE {SCHEMA}.browser_sessions
    SET revoked_at = v_now
    WHERE account_id = v_context.account_id AND revoked_at IS NULL;
    -- The replacement, minted after the sweep so it is not caught by it. Identical in every
    -- property to what open_browser_session mints; see this migration's docstring for why it
    -- is written here rather than called.
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

#: ``(name, signature)`` for every function this revision replaces and restores. It adds none,
#: so ``db/roles.py``'s plan for this revision is ``0006``'s with the revision changed. Each stays
#: in its earlier inventory, on the authenticator's grant; only the body moves.
REPLACED_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("signup_account", "text, text, interval"),
    ("complete_account_recovery", "text, text"),
    ("change_account_password", "text, text, interval"),
)


def upgrade() -> None:
    # CREATE OR REPLACE keeps each function's identity, owner, ACL and hardening; only the body
    # changes. No sanitiser call: nothing new exists to sanitise, and a downgrade could not undo one.
    op.execute(_SIGNUP_ACCOUNT_HEAD)
    op.execute(_COMPLETE_ACCOUNT_RECOVERY_HEAD)
    op.execute(_CHANGE_ACCOUNT_PASSWORD_HEAD)


def downgrade() -> None:
    """Back to the Milestone 3.2 bodies exactly, in the reverse order of the upgrade."""
    op.execute(_LEGACY_CHANGE_ACCOUNT_PASSWORD_RESTORE)
    op.execute(_LEGACY_COMPLETE_ACCOUNT_RECOVERY_RESTORE)
    op.execute(_LEGACY_SIGNUP_ACCOUNT_RESTORE)
