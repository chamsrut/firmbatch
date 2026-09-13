"""Workspace preferences and consent, a signed-in password change, and the account-plane lock order.

Revision ID: 0006_preferences_and_password
Revises: 0005_identity_and_membership
Create Date: 2026-09-09

The sixth v1 migration, and Milestone 3.2's only schema change. Migrations ``0001``-``0005``
are untouched history. This revision adds two relations, a trigger and six functions, and
**replaces the bodies of three ``0005`` functions** with ``CREATE OR REPLACE`` -- the device
``0005`` itself used on ``0003``'s ``bind_authenticated_context`` -- restoring ``0005``'s
text byte-for-byte on downgrade, so that a database taken back to ``0005`` is exactly what
a fresh migration to ``0005`` produces. ``tests/test_portal_migration.py`` asserts both the
restore text and the restored catalogue.

Four things. The third is what the independent Milestone 3.2 review added, and the fourth
is what its clean-context follow-up added.

1. **`workspace_preferences`** -- an ordinary tenant-plane relation, on the Milestone 2.3
   authorization model, holding what the customer has *told us they intend*: the region
   groups they want, the provider classes they exclude, a note about the model and runtime
   profile they expect to run, whether they intend to try the free evaluation, and their
   acknowledgement of the consent and subprocessor statement. The roadmap's M3.2 line is
   "capture the customer's desired policy, profile and preferences for later use **without
   claiming a quote or an execution**", and that qualification is load-bearing: a row here
   is a statement of intent. It is not a `JobSpec`, it does not reserve capacity, it does
   not price anything, and no admission path reads it. M5 owns the `JobSpec` field that
   carries the same idea into a contract.

   It carries `tenant_id`, it is `FORCE` row-secured, and its policies are the ordinary
   "the tenant matches the authenticated context **and** the context holds the scope" pair
   that `0003` established for every customer relation. **The application role holds
   `SELECT` on it and nothing else.** It reads the row under the `SELECT` policy; it cannot
   `INSERT`, `UPDATE` or `DELETE` a row by any statement it writes itself. Every write goes
   through one of two `SECURITY DEFINER` functions -- `state_workspace_preferences` and
   `acknowledge_workspace_consent`, below -- which are the authorization and audit boundary
   for the relation, exactly as `append_audit_event` is for `audit_events`. The `INSERT` and
   `UPDATE` policies remain and still evaluate inside those functions (`FORCE` binds the
   owner too), as the defence in depth they always were. There is no `DELETE` policy and no
   `DELETE` grant: preferences are amended, and they leave when the workspace does, through
   the composite foreign key's `ON DELETE CASCADE`.

   **The composite key is the isolation control**, not a convenience. `(workspace_id,
   tenant_id)` references `workspaces (id, tenant_id)`, so a row cannot name a workspace
   in one tenant while claiming another's `tenant_id` -- the pair either exists in
   `workspaces` or the write is refused. Foreign-key checks bypass row security, which is
   exactly why the *pair* is referenced rather than the id alone.

   **What each mutation function does, in order, and why the order is the design.**
   It requires a browser session bound in workspace mode **with its CSRF secret verified**
   (`identity_require_session('workspace', true)`), so a transaction a `GET` opened cannot
   reach a write however its SQL is spelled. It validates its inputs against the closed
   vocabularies without echoing them. It takes the workspace row `FOR UPDATE` and
   re-derives the caller's membership and role under that lock
   (`workspace_membership_authority`), so a member demoted or removed since the session
   bound is refused whatever the bind cached. It compares the workspace the **caller's page
   state expected** (`p_workspace_id`) with the workspace **this transaction is bound to**
   -- a form loaded for workspace A whose shared session another tab has since re-bound to
   workspace B is refused with one neutral code (`FB014`), and so is a forged or another
   tenant's identifier, indistinguishably; A's values are never applied to B. It decides,
   under the lock, whether anything changes: re-stating the statement in force, or
   re-acknowledging the version in force, is a true no-op that writes nothing and appends
   nothing. And a transition appends its audit event and writes the row inside one function
   call, so the two commit together or not at all; the actor and the tenant on the event are
   derived by `append_audit_event` from the context, and the consent actor and timestamp are
   derived here from `auth_principal_id()` and `clock_timestamp()` -- there is no parameter
   for either, so there is nothing for a caller to state wrongly.

   **The version recorded by an acknowledgement is the server's**
   (:data:`CURRENT_CONSENT_VERSION`), never the caller's. The parameter a caller passes is
   the version the portal *displayed*; if it is not the one currently published the
   acknowledgement is refused as a conflict, so assent is never recorded to text the
   customer was not shown, and never to a version other than the one in force. **Nothing
   clears an acknowledgement.** The row carries the acknowledgement in force; the only
   transition the architecture names is to a newer published statement, and no function
   -- and no grant -- offers a path to a row that says nobody consented after somebody did.
   The history of acknowledgements is in `audit_events`, which is append-only.

   The `BEFORE INSERT OR UPDATE` trigger from the first draft of this revision is kept as
   **defence in depth and nothing more**: it re-derives the same two consent columns for
   any writer that reaches the table, which after this revision is the schema owner alone.
   It is not the authorization boundary and it is not the audit boundary; the functions
   are. `tests/test_portal_preferences.py` proves the functions stamp the actor and the
   timestamp correctly with the trigger disabled.

2. **A signed-in password change**, which Milestone 3.1 deliberately did not build --
   `api/app.py` says a change flow "needs the re-authentication design Milestone 3.2 owns".
   Two functions on the **authenticator** (trusted-issuer) boundary, granted to that role
   alone and to the application role not at all, exactly like the rest of the password
   path:

   * `password_change_lookup(account_id, session_id)` locks the account row, proves the
     named session is live for the named account, writes the transaction's identity
     context as a `password_change_challenge`, and returns the stored Argon2id hash for the
     caller to verify in Python (PostgreSQL 16 has no memory-hard KDF -- ADR 0009 decision
     6).
   * `change_account_password(expected_hash, new_hash, ttl)` requires that challenge,
     re-checks the security epoch under the lock it still holds, supersedes every
     outstanding token, replaces the password by **compare-and-swap against the very hash
     that was verified**, advances the security epoch, revokes every membership-bound
     credential and **every** browser session, and mints the replacement session in the
     same statement sequence.

   The whole change is therefore one transaction: verify, replace, revoke, re-establish, or
   none of it. The compare-and-swap is what makes two concurrent changes -- or a change
   racing a recovery -- resolve to exactly one winner; the epoch check is what makes the
   loser's credentials and sessions dead rather than merely stale.

   `change_account_password` mints its replacement session inline rather than calling
   `open_browser_session`. That is not duplication for its own sake:
   `identity_context_write` refuses to re-point a context inside one transaction (it is
   what "a transaction carries one identity" means), so a function that had already written
   a `password_change_challenge` cannot then write the `login_challenge` that
   `open_browser_session` requires. Rewriting `open_browser_session` to accept a second
   challenge kind would edit a Milestone 3.1 function three security reviews settled, to
   save nine lines. `tests/test_portal_password_change.py` asserts the two paths produce
   sessions with identical properties, which is the drift control.

3. **The account-plane lock order** (independent review, finding 3). Five relations make up
   the account plane: `accounts`, `account_tokens`, `account_passwords`, `auth_bindings` and
   `browser_sessions`. Every function that writes more than one of them acquires its row
   locks **in that order**, and takes the `accounts` row `FOR UPDATE` **first** -- before it
   reads, locks or writes anything else about the account. That one rule is what makes a
   deadlock between two account-plane writers impossible: two of them can only ever wait
   for each other at the account row, in one direction.

   At ``0005`` two functions did not follow it. `complete_account_recovery` and
   `verify_account_email` each locked their **token row first** and only then updated
   `accounts`, while the password change locks the account row first and then supersedes
   every token. Overlapped, the change held the account row and waited for the token row,
   the recovery held the token row and waited for the account row, and PostgreSQL resolved
   it by killing one of them with ``40P01`` -- a transient, undocumented outcome that a
   customer saw as a 500. This revision replaces both bodies: each now reads the token
   **unlocked** only to learn which account row to lock, locks that row, and then re-reads,
   locks and re-validates the token under it. The re-read is what keeps the token's
   one-time property exact: a consumption or a supersession that committed while the
   function waited for the account row is observed, because READ COMMITTED gives the
   re-read a fresh snapshot. `change_account_password` is written to the same order
   (tokens, then the password compare-and-swap, then the account, the bindings and the
   sessions). The single-table token writer, `identity_issue_token`, takes no account lock:
   it never waits on anything another writer holds while holding anything that writer
   wants, because at most one unconsumed, unsuperseded token exists per account and kind
   -- and that invariant is stated here so that relaxing it means moving the issuer under
   the account lock too.

   What the order guarantees, and ``tests/test_portal_password_change.py`` proves against
   real overlap: no ``40P01``; exactly one winner; the loser sees a neutral refusal it can
   act on rather than a server error; no partial password, session or token state; and no
   connection or lock outlives its transaction.

4. **The expected-workspace contract, for every workspace mutation** (clean-context review,
   finding 4). The two preference mutations compared the workspace the caller's page
   expected with the workspace the transaction is bound to; the eight other workspace
   mutations ``0005`` defined -- rename, member removal and role change, invitation creation
   and revocation, credential issue, rotation and revocation -- did not, so a page loaded
   for workspace A whose shared session another tab had re-bound to B applied A's action to
   B. This revision adds the transaction-scoped ``identity_expected_workspace`` relation and
   its writer ``identity_expect_workspace``, and **replaces the body of
   ``workspace_membership_authority``** -- the one revalidation every one of those mutations
   makes, under the workspace lock, before it writes -- to compare the recorded expectation
   with the binding and refuse a mismatch with the same neutral ``FB014``. The HTTP boundary
   records the expectation from the request's ``X-Workspace-Id`` header, once per
   transaction, after the bind and before the handler; a mutation without one is a ``422``.
   The check is therefore atomic with the mutation it guards: one transaction, one binding,
   one lock, and nothing written or appended before the comparison. ``0005``'s body is
   restored verbatim on downgrade, like the two above.

Hand-written like ``0001`` to ``0005``. ``tests/test_migrations.py`` asserts with
``compare_metadata`` that what this file builds matches ``db/models.py``, and
``tests/test_portal_migration.py`` asserts the constants below have not drifted from the
Python modules they mirror, that the legacy texts are ``0005``'s verbatim, and that the
inventories agree with ``db/roles.py``.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, TIMESTAMP, UUID

revision: str = "0006_preferences_and_password"
down_revision: str | None = "0005_identity_and_membership"
branch_labels: str | None = None
depends_on: str | None = None

SCHEMA = "firmbatch"

# Mirrors db/preferences.py, api/consent.py, db/accounts.py and security/passwords.py. A
# migration must not import them -- one that follows the models stops being a record of what
# was applied -- so the constants are duplicated and tests/test_portal_migration.py asserts the
# duplicates have not drifted.

#: The stored password form: Argon2id, version 19, the three parameters, salt and hash.
#: Mirrors ``security/passwords.PASSWORD_HASH_REGEX`` and ``0005``'s copy of it.
PASSWORD_HASH_REGEX = (
    r"^\$argon2id\$v=19\$m=[0-9]{1,9},t=[0-9]{1,4},p=[0-9]{1,3}"
    r"\$[A-Za-z0-9+/]{16,}\$[A-Za-z0-9+/]{16,}$"
)
PASSWORD_HASH_MAX_LENGTH = 512
FINGERPRINT_REGEX = r"^[0-9a-f]{64}$"
MAX_SESSION_TTL = "30 days"

#: What a free-text note is trimmed of. ASCII only, and the same literal ``0005`` uses for an
#: address, so the Python side (``str.strip(ASCII_WHITESPACE)``) and this side agree.
ASCII_WHITESPACE_SQL = r"E' \t\n\r\f\v'"

IDENTITY_SECRET_PREFIXES = {"session": "fbs_", "csrf": "fbc_"}

IDENTITY_REFUSED_SQLSTATE = "FB010"
IDENTITY_CONFLICT_SQLSTATE = "FB011"
IDENTITY_CONTEXT_SQLSTATE = "FB013"
#: New in this revision, mirrored by ``db/accounts.IDENTITY_BINDING_SQLSTATE``: the workspace a
#: mutation names is not the workspace the session is bound to. One code for a stale page, a
#: forged identifier and another tenant's identifier alike, so the refusal answers nothing about
#: whether the identifier exists.
IDENTITY_BINDING_SQLSTATE = "FB014"
IDENTITY_REFUSED_MESSAGE = "firmbatch: the identity operation was refused"
IDENTITY_BINDING_MESSAGE = (
    "firmbatch: the workspace this request names is not the one this session is bound to"
)

#: The region groups a customer may state. **Closed, and deliberately short.** The target
#: architecture's canonical JobSpec (§5.2) names exactly one region group, ``EU``, in
#: ``region_policy``; the register records that regions quoted from the sources "require
#: fresh verification before use and are never spending authority". Adding ``US`` or ``APAC``
#: here would be inventing configuration the authorities do not state. A later forward
#: migration extends the set when a certified region list exists; an empty array is the
#: default and means "no region constraint stated".
REGION_GROUPS = ("EU",)

#: The provider classes a customer may exclude. Every one is named by the target as a Phase 0
#: execution provider: §5.4 ("Phase 0 runs on Google, Microsoft and Amazon, all three on the
#: subprocessor list from the first paid job"), §4.4's four spot drivers, and the roadmap's
#: hosting paragraph (Google Cloud first, then Azure and AWS, and Verda as qualified).
#:
#: ``amazon`` is on the list and is the one whose exclusion **cannot be honoured in v1**.
#: `provider_policy` governs execution placement only; the payload plane is S3 for every
#: tenant until a bucket per supplier cloud region exists (target §3.3, §5.4, §17 invariant
#: 13), so a customer who excludes Amazon altogether cannot be served. The portal states
#: that in the consent text and beside the control rather than accepting the exclusion and
#: quietly failing to honour it, and `state_workspace_preferences()` does not police it:
#: refusing the value would deny the customer the ability to record the requirement that
#: makes them unservable, which is a fact the business needs recorded.
PROVIDER_CLASSES = ("amazon", "google", "microsoft", "verda")

#: Whether the customer intends to run the free 1,000-request evaluation (target §5.3).
#: Recorded intent and nothing else: an evaluation job, its caps, its corpus rule and its
#: report are M4.1 and M5, and no row here admits, quotes or schedules anything.
EVALUATION_INTENTS = ("undecided", "planning_evaluation", "evaluation_not_needed")

#: The consent and subprocessor statements this schema knows. A row may acknowledge only a
#: version named here, so assent cannot be recorded to text that does not exist. Mirrors
#: ``api/consent.CONSENT_DOCUMENTS``; the text itself is served by ``GET /v1/consent`` so the
#: portal cannot render a version the API does not hold.
CONSENT_VERSIONS = ("provider-policy-v1-d.1",)

#: The version an acknowledgement records. **The server's, never the caller's**: mirrors
#: ``api/consent.CURRENT_CONSENT_VERSION``, and a forward migration that publishes a new
#: statement replaces ``acknowledge_workspace_consent`` with the new constant in the same
#: revision that extends the check constraint.
CURRENT_CONSENT_VERSION = "provider-policy-v1-d.1"

MODEL_PROFILE_NOTE_MAX_LENGTH = 200

#: An upper bound on the arrays a caller may send, checked before anything is sorted. Mirrors
#: ``db/preferences.MAX_ARRAY_LENGTH``: the closed vocabularies are shorter than this, and the
#: bound exists so a caller cannot make the database sort a huge array before refusing it.
MAX_ARRAY_LENGTH = 16

_UUID = UUID(as_uuid=True)
_TIMESTAMPTZ = TIMESTAMP(timezone=True)
_TEXT_ARRAY = ARRAY(sa.Text())


def _quoted_list(values) -> str:
    return ", ".join("'" + value.replace("'", "''") + "'" for value in values)


def _subset_check(column: str, values) -> str:
    """``column`` holds only values from the closed set, no null, and no more than the set.

    Three conditions rather than one: ``<@`` alone says nothing about a null element, and a
    check constraint admits a row whose predicate is NULL. The length bound stands in for
    "no duplicates", which cannot be written without a subquery and which PostgreSQL refuses
    in a check constraint. Mirrors ``models._closed_array_check``, whose docstring records
    the trade.
    """
    return (
        f"{column} <@ ARRAY[{_quoted_list(values)}]::text[] "
        f"AND array_position({column}, NULL) IS NULL "
        f"AND cardinality({column}) <= {len(values)}"
    )


# --------------------------------------------------------------------------- policies

_TENANT = f"{SCHEMA}.auth_tenant_id()"


def _scope(name: str) -> str:
    return f"{SCHEMA}.auth_has_scope('{name}')"


def _policy_name(table: str, suffix: str) -> str:
    """``0003``'s convention, reproduced so the new relation's policies are named like
    every other relation's."""
    return f"{table}_authenticated_{suffix}"


#: The authorization rule for the one new relation, in the form the database enforces it.
#: Mirrors the ``ResourceRule`` for ``workspace_preferences`` in ``security/authorization.py``.
#:
#: ``workspace:read`` to see it, ``workspace:write`` to state it -- the same pair
#: ``workspaces`` itself carries, because a preference is a property of the workspace and a
#: viewer that may not rename a workspace may not restate its provider policy either. No
#: ``DELETE`` policy: under ``FORCE`` row security a command with no policy reaches no row,
#: for any role, the owner included.
#:
#: The ``INSERT`` and ``UPDATE`` policies bind the **schema owner**, which is the identity the
#: two mutation functions run as. They are the second check on every write, after the
#: function's own membership revalidation; the application role, which holds ``SELECT`` alone,
#: never reaches them with a statement of its own.
POLICIES: tuple[tuple[str, str, str | None, str | None], ...] = (
    ("SELECT", "read", f"tenant_id = {_TENANT} AND {_scope('workspace:read')}", None),
    ("INSERT", "append", None, f"tenant_id = {_TENANT} AND {_scope('workspace:write')}"),
    (
        "UPDATE",
        "amend",
        f"tenant_id = {_TENANT} AND {_scope('workspace:write')}",
        f"tenant_id = {_TENANT} AND {_scope('workspace:write')}",
    ),
)

# --------------------------------------------------------------------------- functions

#: The columns every mutation function returns: the row as the reader sees it.
_PREFERENCES_COLUMNS = (
    "id uuid, workspace_id uuid, tenant_id uuid, region_policy text[], "
    "excluded_provider_classes text[], model_profile_note text, evaluation_intent text, "
    "consent_version text, consent_acknowledged_at timestamptz, consent_account_id uuid, "
    "created_at timestamptz, updated_at timestamptz"
)
_PREFERENCES_SELECT = (
    "p.id, p.workspace_id, p.tenant_id, p.region_policy, p.excluded_provider_classes, "
    "p.model_profile_note, p.evaluation_intent, p.consent_version, p.consent_acknowledged_at, "
    "p.consent_account_id, p.created_at, p.updated_at"
)

#: The trigger that derives what a caller must not state. **Defence in depth**, after this
#: revision, and not the boundary: the two mutation functions below derive the same two
#: columns themselves and are the only writers any runtime role can reach.
_WORKSPACE_PREFERENCES_SET_CONSENT = f"""
CREATE FUNCTION {SCHEMA}.workspace_preferences_set_consent() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    -- Always, on every write: the row's own modification time is the server's, not the
    -- writer's, and not transaction-start time either. clock_timestamp() rather than now()
    -- for 0003's reason -- a caller that opened its transaction an hour ago would otherwise
    -- date the write an hour ago.
    NEW.updated_at := pg_catalog.clock_timestamp();

    IF NEW.consent_version IS NULL THEN
        -- Clearing the acknowledgement clears who and when with it. A row carrying an
        -- actor and a timestamp for no version would assert that somebody consented to
        -- nothing. No runtime path writes this shape; the owner's own maintenance could.
        NEW.consent_acknowledged_at := NULL;
        NEW.consent_account_id := NULL;
    ELSIF TG_OP = 'INSERT'
          OR NEW.consent_version IS DISTINCT FROM OLD.consent_version THEN
        -- A newly acknowledged version is stamped here as well as in the function that
        -- wrote it. Both values are overwritten unconditionally, so a writer that supplied
        -- them is not corrected -- it is ignored, which is the only outcome that cannot be
        -- raced.
        NEW.consent_acknowledged_at := pg_catalog.clock_timestamp();
        NEW.consent_account_id := {SCHEMA}.auth_principal_id();
    ELSE
        -- Re-stating the version already in force changes nothing about the acknowledgement.
        -- Carrying the old values forward is what stops an unrelated preference edit from
        -- silently re-dating a consent nobody re-gave.
        NEW.consent_acknowledged_at := OLD.consent_acknowledged_at;
        NEW.consent_account_id := OLD.consent_account_id;
    END IF;
    RETURN NEW;
END;
$function$
"""

#: Replace this workspace's stated intent. Granted to the **application** role; the one way
#: a runtime role writes the four preference columns. The docstring at the top of this file
#: walks the seven steps; the numbered comments below are the same seven.
_STATE_WORKSPACE_PREFERENCES = f"""
CREATE FUNCTION {SCHEMA}.state_workspace_preferences(
    p_workspace_id uuid,
    p_region_policy text[],
    p_excluded_provider_classes text[],
    p_model_profile_note text,
    p_evaluation_intent text
)
RETURNS TABLE ({_PREFERENCES_COLUMNS})
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_regions text[];
    v_excluded text[];
    v_note text;
    v_shape text;
    v_current record;
    v_id uuid;
BEGIN
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();
    -- 1. The authenticated browser context, and the CSRF proof the bind recorded. A
    --    transaction bound without its CSRF secret -- the one a GET opens -- cannot reach
    --    past this line, whatever the caller's SQL says.
    v_session := {SCHEMA}.identity_require_session('workspace', true);
    -- 2. A cheap pre-filter on the cached context; the authoritative check is remade under
    --    the workspace lock below against the caller's membership as it is now.
    IF NOT {SCHEMA}.auth_has_scope('workspace:write') THEN
        RAISE EXCEPTION 'firmbatch: stating workspace preferences requires the workspace:write scope'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- 3. The inputs, against the closed vocabularies, before any lock is taken. No refusal
    --    repeats the value: an entry that reached the wrong argument may be a secret.
    IF p_region_policy IS NOT NULL AND (
        pg_catalog.cardinality(p_region_policy) > {MAX_ARRAY_LENGTH}
        OR pg_catalog.array_position(p_region_policy, NULL) IS NOT NULL
        OR NOT (p_region_policy <@ ARRAY[{_quoted_list(REGION_GROUPS)}]::text[])
    ) THEN
        RAISE EXCEPTION 'firmbatch: the region policy is not within the closed vocabulary'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the value is deliberately not shown';
    END IF;
    IF p_excluded_provider_classes IS NOT NULL AND (
        pg_catalog.cardinality(p_excluded_provider_classes) > {MAX_ARRAY_LENGTH}
        OR pg_catalog.array_position(p_excluded_provider_classes, NULL) IS NOT NULL
        OR NOT (p_excluded_provider_classes <@ ARRAY[{_quoted_list(PROVIDER_CLASSES)}]::text[])
    ) THEN
        RAISE EXCEPTION 'firmbatch: the provider exclusion is not within the closed vocabulary'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the value is deliberately not shown';
    END IF;
    -- Sorted and deduplicated, so the stored array is canonical and two equivalent
    -- statements compare equal -- which the no-op decision below depends on.
    SELECT COALESCE(pg_catalog.array_agg(DISTINCT v ORDER BY v), ARRAY[]::text[]) INTO v_regions
    FROM pg_catalog.unnest(COALESCE(p_region_policy, ARRAY[]::text[])) AS v;
    SELECT COALESCE(pg_catalog.array_agg(DISTINCT v ORDER BY v), ARRAY[]::text[]) INTO v_excluded
    FROM pg_catalog.unnest(COALESCE(p_excluded_provider_classes, ARRAY[]::text[])) AS v;
    -- NULLIF is a SQL construct like COALESCE, not a pg_catalog function, so it is unqualified.
    v_note := NULLIF(pg_catalog.btrim(p_model_profile_note, {ASCII_WHITESPACE_SQL}), '');
    IF v_note IS NOT NULL THEN
        v_shape := {SCHEMA}.secret_shape(v_note);
        IF v_shape IS NOT NULL THEN
            RAISE EXCEPTION 'firmbatch: the model and profile note looks like %', v_shape
                USING ERRCODE = 'invalid_parameter_value',
                      DETAIL = 'the value is deliberately not shown';
        END IF;
        IF pg_catalog.length(v_note) > {MODEL_PROFILE_NOTE_MAX_LENGTH} THEN
            RAISE EXCEPTION 'firmbatch: the model and profile note is at most % characters',
                            {MODEL_PROFILE_NOTE_MAX_LENGTH}
                USING ERRCODE = 'invalid_parameter_value',
                      DETAIL = 'the value is deliberately not shown';
        END IF;
    END IF;
    IF p_evaluation_intent IS NULL
       OR NOT (p_evaluation_intent = ANY (ARRAY[{_quoted_list(EVALUATION_INTENTS)}]::text[])) THEN
        RAISE EXCEPTION 'firmbatch: the evaluation intent is not in the closed set'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the value is deliberately not shown';
    END IF;
    -- 4. The serialisation point -- the workspace row FOR UPDATE, the lock every workspace
    --    mutation takes -- and the caller's authority re-derived under it. A session demoted
    --    below workspace:write, or removed, since it bound is refused here, whatever its
    --    cached context says.
    v_session := {SCHEMA}.workspace_membership_authority('workspace:write', true);
    -- 5. The workspace the caller's page state expected, against the workspace this
    --    transaction is bound to. A page loaded for workspace A whose shared session another
    --    tab has since re-bound to B is refused here rather than applied to B; a forged
    --    identifier and another tenant's identifier get the same code, so the refusal answers
    --    nothing about whether the identifier exists.
    IF p_workspace_id IS NULL OR p_workspace_id IS DISTINCT FROM v_session.workspace_id THEN
        RAISE EXCEPTION '{IDENTITY_BINDING_MESSAGE}'
            USING ERRCODE = '{IDENTITY_BINDING_SQLSTATE}';
    END IF;
    -- 6. The decision, under the lock. The row lock is belt to the workspace lock's braces:
    --    every writer of this row already holds the workspace row.
    SELECT p.id, p.region_policy, p.excluded_provider_classes, p.model_profile_note,
           p.evaluation_intent
    INTO v_current
    FROM {SCHEMA}.workspace_preferences p
    WHERE p.workspace_id = v_session.workspace_id AND p.tenant_id = v_session.tenant_id
    FOR UPDATE;
    IF v_current.id IS NOT NULL
       AND v_current.region_policy = v_regions
       AND v_current.excluded_provider_classes = v_excluded
       AND v_current.model_profile_note IS NOT DISTINCT FROM v_note
       AND v_current.evaluation_intent = p_evaluation_intent THEN
        -- Re-stating the statement in force: nothing changes, nothing is written, and no
        -- audit event is appended, because nothing happened.
        RETURN QUERY SELECT {_PREFERENCES_SELECT}
                     FROM {SCHEMA}.workspace_preferences p WHERE p.id = v_current.id;
        RETURN;
    END IF;
    IF v_current.id IS NULL
       AND pg_catalog.cardinality(v_regions) = 0
       AND pg_catalog.cardinality(v_excluded) = 0
       AND v_note IS NULL
       AND p_evaluation_intent = 'undecided' THEN
        -- The empty statement, on a workspace that has stated nothing: there is no row to
        -- write and nothing to record, and the answer has the shape the reader gives an
        -- absent row, so "absent" stays indistinguishable from "stated nothing".
        RETURN QUERY SELECT NULL::uuid, v_session.workspace_id, v_session.tenant_id,
                            ARRAY[]::text[], ARRAY[]::text[], NULL::text, 'undecided'::text,
                            NULL::text, NULL::timestamptz, NULL::uuid, NULL::timestamptz,
                            NULL::timestamptz;
        RETURN;
    END IF;
    -- 7. The transition. The trail first and the row second, inside one function call: an
    --    exception from either aborts the statement and rolls both back, so the row cannot
    --    exist without its event and the event cannot exist without its row. The details are
    --    bounded metadata about what was stated, never the customer's own free text.
    PERFORM {SCHEMA}.append_audit_event(
        'workspace.preferences_stated', 'succeeded', 'workspace_preferences',
        v_session.workspace_id, NULL,
        pg_catalog.jsonb_build_object(
            'region_policy', pg_catalog.to_jsonb(v_regions),
            'excluded_provider_classes', pg_catalog.to_jsonb(v_excluded),
            'evaluation_intent', p_evaluation_intent,
            'model_profile_note_present', (v_note IS NOT NULL),
            'unservable_exclusion', ('amazon' = ANY (v_excluded)),
            'session_id', v_session.session_id::text
        )
    );
    IF v_current.id IS NOT NULL THEN
        -- The consent columns are not in the SET list: an ordinary preference edit never
        -- re-dates or clears an acknowledgement, and the trigger carries them forward.
        UPDATE {SCHEMA}.workspace_preferences p
        SET region_policy = v_regions,
            excluded_provider_classes = v_excluded,
            model_profile_note = v_note,
            evaluation_intent = p_evaluation_intent
        WHERE p.id = v_current.id AND p.tenant_id = v_session.tenant_id;
        v_id := v_current.id;
    ELSE
        v_id := pg_catalog.gen_random_uuid();
        -- tenant_id is the bound session's, never a parameter: the INSERT policy would
        -- refuse any other value, and there is no argument through which to send one.
        INSERT INTO {SCHEMA}.workspace_preferences
            (id, workspace_id, tenant_id, region_policy, excluded_provider_classes,
             model_profile_note, evaluation_intent)
        VALUES (v_id, v_session.workspace_id, v_session.tenant_id, v_regions, v_excluded,
                v_note, p_evaluation_intent);
    END IF;
    RETURN QUERY SELECT {_PREFERENCES_SELECT}
                 FROM {SCHEMA}.workspace_preferences p WHERE p.id = v_id;
END;
$function$
"""

#: Record assent to the consent statement currently published. Granted to the
#: **application** role; the one way a runtime role writes the three consent columns.
_ACKNOWLEDGE_WORKSPACE_CONSENT = f"""
CREATE FUNCTION {SCHEMA}.acknowledge_workspace_consent(p_workspace_id uuid, p_displayed_version text)
RETURNS TABLE ({_PREFERENCES_COLUMNS})
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_shape text;
    v_current record;
    v_id uuid;
    v_now timestamptz;
    v_actor uuid;
BEGIN
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();
    -- 1. The authenticated, CSRF-verified browser context.
    v_session := {SCHEMA}.identity_require_session('workspace', true);
    -- 2. The pre-filter on the cached context; the authoritative check is under the lock.
    IF NOT {SCHEMA}.auth_has_scope('workspace:write') THEN
        RAISE EXCEPTION 'firmbatch: acknowledging the consent statement requires the workspace:write scope'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- 3. The version the portal displayed. It is checked and it is NOT what is recorded: the
    --    recorded version is the server's constant below, so assent is never written to a
    --    version the customer was not shown, and never to one other than the one in force.
    v_shape := {SCHEMA}.secret_shape(p_displayed_version);
    IF v_shape IS NOT NULL THEN
        RAISE EXCEPTION 'firmbatch: the consent version looks like %', v_shape
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the value is deliberately not shown';
    END IF;
    IF p_displayed_version IS NULL
       OR NOT (p_displayed_version = ANY (ARRAY[{_quoted_list(CONSENT_VERSIONS)}]::text[])) THEN
        RAISE EXCEPTION 'firmbatch: that is not a consent version this system published'
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'the value is deliberately not shown';
    END IF;
    IF p_displayed_version <> '{CURRENT_CONSENT_VERSION}' THEN
        RAISE EXCEPTION 'firmbatch: the statement acknowledged is not the one currently published'
            USING ERRCODE = '{IDENTITY_CONFLICT_SQLSTATE}',
                  DETAIL = 'reload the consent statement and acknowledge the version it shows';
    END IF;
    -- 4. The serialisation point and the authority, re-derived under it.
    v_session := {SCHEMA}.workspace_membership_authority('workspace:write', true);
    -- 5. The expected binding, against the binding this transaction acts in.
    IF p_workspace_id IS NULL OR p_workspace_id IS DISTINCT FROM v_session.workspace_id THEN
        RAISE EXCEPTION '{IDENTITY_BINDING_MESSAGE}'
            USING ERRCODE = '{IDENTITY_BINDING_SQLSTATE}';
    END IF;
    -- 6. The decision, under the lock: two simultaneous acknowledgements serialise on the
    --    workspace row, the first records, and the second finds the version in force and
    --    does nothing -- one row, one event, and no second timestamp.
    SELECT p.id, p.consent_version INTO v_current
    FROM {SCHEMA}.workspace_preferences p
    WHERE p.workspace_id = v_session.workspace_id AND p.tenant_id = v_session.tenant_id
    FOR UPDATE;
    IF v_current.id IS NOT NULL AND v_current.consent_version = '{CURRENT_CONSENT_VERSION}' THEN
        RETURN QUERY SELECT {_PREFERENCES_SELECT}
                     FROM {SCHEMA}.workspace_preferences p WHERE p.id = v_current.id;
        RETURN;
    END IF;
    -- 7. The transition. Who and when are derived here -- the bound account, the server's
    --    clock -- and the trigger derives the same two values again behind this write.
    v_now := pg_catalog.clock_timestamp();
    v_actor := {SCHEMA}.auth_principal_id();
    IF v_actor IS NULL OR v_actor IS DISTINCT FROM v_session.account_id THEN
        RAISE EXCEPTION 'firmbatch: the acknowledging principal is not the bound session''s account'
            USING ERRCODE = 'internal_error';
    END IF;
    PERFORM {SCHEMA}.append_audit_event(
        'workspace.consent_acknowledged', 'succeeded', 'workspace_preferences',
        v_session.workspace_id, NULL,
        pg_catalog.jsonb_build_object(
            'consent_version', '{CURRENT_CONSENT_VERSION}',
            'superseded_version', v_current.consent_version,
            'session_id', v_session.session_id::text
        )
    );
    IF v_current.id IS NOT NULL THEN
        UPDATE {SCHEMA}.workspace_preferences p
        SET consent_version = '{CURRENT_CONSENT_VERSION}',
            consent_acknowledged_at = v_now,
            consent_account_id = v_actor
        WHERE p.id = v_current.id AND p.tenant_id = v_session.tenant_id;
        v_id := v_current.id;
    ELSE
        v_id := pg_catalog.gen_random_uuid();
        INSERT INTO {SCHEMA}.workspace_preferences
            (id, workspace_id, tenant_id, consent_version, consent_acknowledged_at,
             consent_account_id)
        VALUES (v_id, v_session.workspace_id, v_session.tenant_id, '{CURRENT_CONSENT_VERSION}',
                v_now, v_actor);
    END IF;
    RETURN QUERY SELECT {_PREFERENCES_SELECT}
                 FROM {SCHEMA}.workspace_preferences p WHERE p.id = v_id;
END;
$function$
"""

#: The stored hash for one account, for a caller that already holds a live browser session
#: for it. Granted to the **authenticator** role alone.
#:
#: Three things happen here and the order matters. The account row is locked ``FOR UPDATE``
#: first -- the account-plane lock order's first step -- so a recovery or a second password
#: change either completed before this call or waits behind it: the epoch recorded in the
#: challenge is then the committed one, on exactly the terms ``open_browser_session`` states
#: for the recovery/login race. The session is then proved live **for that account**, which
#: is what stops this being a second route to any account's hash: the caller must already
#: hold a session id the identity plane issued, and the identity plane issued it to somebody
#: who knew the password. Finally the challenge is written, so ``change_account_password``
#: acts on the account this transaction looked up rather than one it names.
#:
#: The refusal is the neutral one for every failure -- unknown account, foreign session,
#: revoked session, expired session, suspended account -- from one raise site.
_PASSWORD_CHANGE_LOOKUP = f"""
CREATE FUNCTION {SCHEMA}.password_change_lookup(p_account_id uuid, p_session_id uuid)
RETURNS TABLE (password_hash text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_status text;
    v_epoch integer;
    v_hash text;
    v_session_ok boolean := false;
BEGIN
    PERFORM {SCHEMA}.auth_require_writable_primary();
    PERFORM {SCHEMA}.auth_require_read_committed();
    IF p_account_id IS NULL OR p_session_id IS NULL THEN
        RAISE EXCEPTION '{IDENTITY_REFUSED_MESSAGE}'
            USING ERRCODE = '{IDENTITY_REFUSED_SQLSTATE}';
    END IF;
    SELECT a.status, a.security_epoch INTO v_status, v_epoch
    FROM {SCHEMA}.accounts a WHERE a.id = p_account_id FOR UPDATE;
    IF FOUND AND v_status = 'active' THEN
        SELECT true INTO v_session_ok
        FROM {SCHEMA}.browser_sessions s
        WHERE s.id = p_session_id
          AND s.account_id = p_account_id
          AND s.revoked_at IS NULL
          AND s.expires_at > pg_catalog.clock_timestamp();
    END IF;
    IF NOT COALESCE(v_session_ok, false) THEN
        RAISE EXCEPTION '{IDENTITY_REFUSED_MESSAGE}'
            USING ERRCODE = '{IDENTITY_REFUSED_SQLSTATE}';
    END IF;
    SELECT p.password_hash INTO v_hash
    FROM {SCHEMA}.account_passwords p WHERE p.account_id = p_account_id;
    PERFORM {SCHEMA}.identity_context_write(
        'password_change_challenge', p_account_id, p_session_id, NULL, NULL, NULL, NULL,
        false, v_epoch
    );
    RETURN QUERY SELECT v_hash;
END;
$function$
"""

#: Replace the password of the account this transaction challenged, end everything the old
#: one authorised, and hand back a new session. Granted to the **authenticator** role alone.
#:
#: ``p_expected_hash`` is the hash ``password_change_lookup`` returned and the caller
#: verified the current password against. It is not decoration: the ``UPDATE`` on the
#: password row is a **compare-and-swap** on it, so two concurrent changes cannot both
#: succeed and a change cannot overwrite a recovery that committed while the caller was
#: running Argon2. The epoch comparison catches the same race one layer up and makes the
#: loser's credentials dead rather than merely stale; both are kept, because they fail on
#: different things -- the epoch moves for a recovery that did not touch the password row's
#: value, and the hash moves for a change that did.
#:
#: What ends, and it is deliberately everything: every outstanding token of either kind
#: (the old password is gone, so a recovery link minted under it should not still work),
#: every membership-bound API credential this account issued (through the epoch, which
#: ``bind_authenticated_context`` compares, and visibly through ``revoked_at``), and **every**
#: browser session including the one that asked. The replacement session is minted after
#: that sweep, so it survives it.
#:
#: The statements run in the account-plane lock order -- the account row is already held
#: from the lookup; then the token rows, the password row, the account row's update, the
#: bindings and the sessions -- so this function and ``complete_account_recovery`` acquire
#: their locks in one sequence and can only ever wait for each other at the account row.
_CHANGE_ACCOUNT_PASSWORD = f"""
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

# ------------------------------------------- the two 0005 functions this revision replaces
#
# Both are replaced with CREATE OR REPLACE and restored to 0005's text by the downgrade;
# migration 0005 is unedited. tests/test_portal_migration.py asserts each legacy constant
# equals 0005's constant verbatim, that each restore differs from it by the one word a
# downgrade needs, and that a database downgraded to 0005 has the catalogue a fresh migration
# to 0005 produces.

#: ``0005``'s ``verify_account_email``, verbatim: the token row first, the account row second.
_LEGACY_VERIFY_ACCOUNT_EMAIL = f"""
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

_LEGACY_VERIFY_ACCOUNT_EMAIL_RESTORE = _LEGACY_VERIFY_ACCOUNT_EMAIL.replace(
    "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1
)

#: The head body: the account row first, then the token row re-read and locked under it.
_VERIFY_ACCOUNT_EMAIL_HEAD = f"""
CREATE OR REPLACE FUNCTION {SCHEMA}.verify_account_email(p_secret text) RETURNS boolean
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
    IF p_secret IS NULL OR pg_catalog.length(p_secret) = 0 THEN
        RETURN false;
    END IF;
    -- The account-plane lock order: the account row first. The token is read unlocked here
    -- only to learn WHICH account row to lock; nothing decided below rests on this read.
    SELECT t.account_id INTO v_account_id
    FROM {SCHEMA}.account_tokens t
    WHERE t.fingerprint = {SCHEMA}.identity_fingerprint(p_secret)
      AND t.kind = 'email_verification';
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    PERFORM 1 FROM {SCHEMA}.accounts a WHERE a.id = v_account_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    v_now := pg_catalog.clock_timestamp();
    -- Re-read, locked, under the account row: READ COMMITTED gives this statement a fresh
    -- snapshot, so a consumption or a supersession that committed while this transaction
    -- waited for the account row is observed, and the token stays one-time exactly.
    -- Unknown, consumed, superseded and expired all answer false: the caller holds the
    -- token or does not, and which of the four it was tells it nothing it should learn.
    SELECT t.id, t.consumed_at, t.superseded_at, t.expires_at INTO v_token
    FROM {SCHEMA}.account_tokens t
    WHERE t.fingerprint = {SCHEMA}.identity_fingerprint(p_secret)
      AND t.kind = 'email_verification'
      AND t.account_id = v_account_id
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
    WHERE id = v_account_id;
    RETURN true;
END;
$function$
"""

#: ``0005``'s ``complete_account_recovery``, verbatim: the token row first, the account second.
_LEGACY_COMPLETE_ACCOUNT_RECOVERY = f"""
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

_LEGACY_COMPLETE_ACCOUNT_RECOVERY_RESTORE = _LEGACY_COMPLETE_ACCOUNT_RECOVERY.replace(
    "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1
)

#: The head body: the account row first, then the token row re-read and locked under it,
#: then the password, the account's own update, the bindings and the sessions -- the same
#: sequence ``change_account_password`` follows.
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

#: ``(name, signature, audience)`` for every function this revision **adds**, in creation
#: order. The downgrade drops them in reverse. ``audience`` mirrors ``db/roles.py``'s
#: inventories -- ``application`` for the three the runtime role holds (the two mutation
#: entry points and the expected-workspace writer), ``authenticator`` for the trusted-issuer
#: boundary, ``internal`` for what no role may execute -- and ``tests/test_portal_migration.py``
#: holds the two halves equal, exactly as ``0005`` does for its fifty-one.

# ------------------------------------------------------------- the expected-workspace contract
#
# Every workspace-scoped mutation the portal makes carries the workspace its page or action
# began under (``X-Workspace-Id``). The boundary records it in the transaction, once, before
# the handler runs; ``workspace_membership_authority`` -- the one revalidation every
# workspace mutation ``0005`` defined makes, under the workspace lock -- compares it with the
# workspace the transaction is bound to and refuses a mismatch with ``FB014`` before anything
# is written. The expectation lives in its own transaction-scoped unlogged relation, keyed
# like ``identity_transaction_context`` and read only by that function, so a pooled backend
# reused by a later transaction cannot inherit an expectation: the row carries the
# transaction id it belongs to, and the read requires it to be this transaction's.

#: The transaction-scoped expectation. Protected like the context relation: no runtime role
#: holds anything on it, and the two definer functions below are its only readers and writer.
_IDENTITY_EXPECTED_WORKSPACE_TABLE = f"""
CREATE UNLOGGED TABLE {SCHEMA}.identity_expected_workspace (
    backend_pid  integer PRIMARY KEY,
    xact_id      xid8 NOT NULL,
    workspace_id uuid NOT NULL,
    recorded_at  timestamptz NOT NULL DEFAULT clock_timestamp()
)
"""

#: The writer, granted to the application role: the boundary calls it once per workspace
#: mutation, after the bind and before the handler. It requires a workspace-bound session
#: (nothing else has a binding to hold the expectation against), refuses a null, and refuses
#: to re-point an expectation this transaction already recorded -- a transaction expects one
#: workspace, as it binds one session.
_IDENTITY_EXPECT_WORKSPACE = f"""
CREATE FUNCTION {SCHEMA}.identity_expect_workspace(p_workspace_id uuid) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_written integer;
BEGIN
    v_session := {SCHEMA}.identity_require_session('workspace', false);
    IF p_workspace_id IS NULL THEN
        RAISE EXCEPTION 'firmbatch: an expected workspace is a UUID'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO {SCHEMA}.identity_expected_workspace AS existing
        (backend_pid, xact_id, workspace_id, recorded_at)
    VALUES (
        pg_catalog.pg_backend_pid(), pg_catalog.pg_current_xact_id(), p_workspace_id,
        pg_catalog.clock_timestamp()
    )
    ON CONFLICT (backend_pid) DO UPDATE
        SET xact_id      = excluded.xact_id,
            workspace_id = excluded.workspace_id,
            recorded_at  = excluded.recorded_at
        WHERE existing.xact_id <> excluded.xact_id;
    GET DIAGNOSTICS v_written = ROW_COUNT;
    IF v_written = 0 THEN
        RAISE EXCEPTION 'firmbatch: this transaction already expects a workspace'
            USING ERRCODE = 'invalid_transaction_state',
                  DETAIL = 'a transaction is made for one workspace; open a new transaction for another';
    END IF;
END;
$function$
"""

#: ``0005``'s ``workspace_membership_authority``, verbatim, for the downgrade.
_LEGACY_WORKSPACE_MEMBERSHIP_AUTHORITY = f"""
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

_LEGACY_WORKSPACE_MEMBERSHIP_AUTHORITY_RESTORE = _LEGACY_WORKSPACE_MEMBERSHIP_AUTHORITY.replace(
    "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1
)

#: The head body: ``0005``'s text with the expected-workspace comparison added after the
#: permission check and before the role is returned. Nothing else moves.
_WORKSPACE_MEMBERSHIP_AUTHORITY_HEAD = f"""
CREATE OR REPLACE FUNCTION {SCHEMA}.workspace_membership_authority(p_scope text, p_lock boolean)
RETURNS {SCHEMA}.identity_session_row
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_column
DECLARE
    v_session {SCHEMA}.identity_session_row;
    v_role text;
    v_expected uuid;
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
    -- (0006) The workspace the caller's request was made **for**, when this transaction
    -- recorded one (``identity_expect_workspace``), against the workspace this transaction
    -- is bound to. The same comparison the two preference mutations make with their own
    -- parameter, made here for every workspace mutation ``0005`` defined -- under the lock
    -- this function already takes, after the membership and the permission it re-reads,
    -- and before any of them has written or appended anything. A page whose shared session
    -- another tab has since re-bound to another workspace is refused with one neutral code,
    -- and so is a forged or another tenant's identifier, indistinguishably; neither
    -- workspace changes.
    SELECT e.workspace_id INTO v_expected
    FROM {SCHEMA}.identity_expected_workspace e
    WHERE e.backend_pid = pg_catalog.pg_backend_pid()
      AND e.xact_id = pg_catalog.pg_current_xact_id_if_assigned();
    IF FOUND AND v_expected IS DISTINCT FROM v_session.workspace_id THEN
        RAISE EXCEPTION '{IDENTITY_BINDING_MESSAGE}'
            USING ERRCODE = '{IDENTITY_BINDING_SQLSTATE}';
    END IF;
    v_session.role := v_role;
    RETURN v_session;
END;
$function$
"""

FUNCTIONS: tuple[tuple[str, str, str], ...] = (
    ("workspace_preferences_set_consent", "", "internal"),
    ("state_workspace_preferences", "uuid, text[], text[], text, text", "application"),
    ("acknowledge_workspace_consent", "uuid, text", "application"),
    ("identity_expect_workspace", "uuid", "application"),
    ("password_change_lookup", "uuid, uuid", "authenticator"),
    ("change_account_password", "text, text, interval", "authenticator"),
)

#: ``(name, signature)`` for every ``0005`` function this revision **replaces** and restores.
#: All three stay in ``0005``'s inventory and on their audience's grant; only the body moves.
REPLACED_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("verify_account_email", "text"),
    ("complete_account_recovery", "text, text"),
    ("workspace_membership_authority", "text, boolean"),
)


def upgrade() -> None:
    op.create_table(
        "workspace_preferences",
        sa.Column("id", _UUID, primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("workspace_id", _UUID, nullable=False),
        sa.Column("tenant_id", _UUID, nullable=False),
        sa.Column(
            "region_policy", _TEXT_ARRAY, nullable=False, server_default=sa.text("'{}'::text[]")
        ),
        sa.Column(
            "excluded_provider_classes",
            _TEXT_ARRAY,
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
        sa.Column("model_profile_note", sa.Text(), nullable=True),
        sa.Column(
            "evaluation_intent", sa.Text(), nullable=False, server_default=sa.text("'undecided'")
        ),
        sa.Column("consent_version", sa.Text(), nullable=True),
        sa.Column("consent_acknowledged_at", _TIMESTAMPTZ, nullable=True),
        sa.Column("consent_account_id", _UUID, nullable=True),
        sa.Column("created_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", _TIMESTAMPTZ, nullable=False, server_default=sa.text("now()")),
        # The isolation control. The PAIR is referenced, not the id: a foreign-key check
        # bypasses row security, so a predicate that trusted the writer's tenant_id alone
        # would be trusting a column the writer supplies.
        sa.ForeignKeyConstraint(
            ["workspace_id", "tenant_id"],
            [f"{SCHEMA}.workspaces.id", f"{SCHEMA}.workspaces.tenant_id"],
            ondelete="CASCADE",
            name="fk_workspace_preferences_workspace_id_tenant_id_workspaces",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            [f"{SCHEMA}.tenants.id"],
            ondelete="CASCADE",
            name="fk_workspace_preferences_tenant_id_tenants",
        ),
        # One row per workspace: preferences are amended, never accumulated.
        sa.UniqueConstraint("workspace_id", name="uq_workspace_preferences_workspace_id"),
        # The composite key a future child table would reference, by the convention every
        # tenant-owned relation in this schema follows.
        sa.UniqueConstraint("id", "tenant_id", name="uq_workspace_preferences_id_tenant_id"),
        sa.CheckConstraint(_subset_check("region_policy", REGION_GROUPS), name="region_policy_known"),
        sa.CheckConstraint(
            _subset_check("excluded_provider_classes", PROVIDER_CLASSES),
            name="excluded_provider_classes_known",
        ),
        sa.CheckConstraint(
            f"evaluation_intent IN ({_quoted_list(EVALUATION_INTENTS)})",
            name="evaluation_intent_known",
        ),
        sa.CheckConstraint(
            f"model_profile_note IS NULL OR length(model_profile_note) "
            f"BETWEEN 1 AND {MODEL_PROFILE_NOTE_MAX_LENGTH}",
            name="model_profile_note_bounded",
        ),
        # Assent is recorded only to text this schema knows.
        sa.CheckConstraint(
            f"consent_version IS NULL OR consent_version IN ({_quoted_list(CONSENT_VERSIONS)})",
            name="consent_version_known",
        ),
        # The three consent columns move together. The functions and the trigger keep them
        # consistent; this is what makes an inconsistent row unstorable even without either.
        sa.CheckConstraint(
            "(consent_version IS NULL AND consent_acknowledged_at IS NULL "
            "AND consent_account_id IS NULL) "
            "OR (consent_version IS NOT NULL AND consent_acknowledged_at IS NOT NULL "
            "AND consent_account_id IS NOT NULL)",
            name="consent_complete_or_absent",
        ),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_workspace_preferences_tenant_id", "workspace_preferences", ["tenant_id"], schema=SCHEMA
    )

    # Row security, enabled and FORCEd. FORCE is what makes the policies bind the table's
    # owner too, so "no policy for this command" means "no row for anybody" -- and so the
    # INSERT and UPDATE policies evaluate inside the two definer functions as well.
    op.execute(f"ALTER TABLE {SCHEMA}.workspace_preferences ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {SCHEMA}.workspace_preferences FORCE ROW LEVEL SECURITY")
    for command, suffix, using, with_check in POLICIES:
        clauses = [
            f"CREATE POLICY {_policy_name('workspace_preferences', suffix)} "
            f"ON {SCHEMA}.workspace_preferences",
            f"FOR {command}",
            "TO PUBLIC",
        ]
        if using is not None:
            clauses.append(f"USING ({using})")
        if with_check is not None:
            clauses.append(f"WITH CHECK ({with_check})")
        op.execute("\n".join(clauses))

    op.execute(_WORKSPACE_PREFERENCES_SET_CONSENT)
    op.execute(_STATE_WORKSPACE_PREFERENCES)
    op.execute(_ACKNOWLEDGE_WORKSPACE_CONSENT)
    op.execute(_PASSWORD_CHANGE_LOOKUP)
    op.execute(_CHANGE_ACCOUNT_PASSWORD)

    op.execute(
        f"""
        CREATE TRIGGER workspace_preferences_set_consent
        BEFORE INSERT OR UPDATE ON {SCHEMA}.workspace_preferences
        FOR EACH ROW EXECUTE FUNCTION {SCHEMA}.workspace_preferences_set_consent()
        """
    )

    # The two 0005 bodies brought under the account-plane lock order. CREATE OR REPLACE keeps
    # each function's identity, owner and ACL; only the body changes.
    op.execute(_VERIFY_ACCOUNT_EMAIL_HEAD)
    op.execute(_COMPLETE_ACCOUNT_RECOVERY_HEAD)

    # The expected-workspace contract: the transaction-scoped expectation, its writer, and
    # the one revalidation every workspace mutation makes brought to compare against it.
    op.execute(_IDENTITY_EXPECTED_WORKSPACE_TABLE)
    op.execute(_IDENTITY_EXPECT_WORKSPACE)
    op.execute(_WORKSPACE_MEMBERSHIP_AUTHORITY_HEAD)

    # The ownership-aware sanitiser 0004 installed, called rather than copied, so the two new
    # relations and the six new functions carry exactly the access control this schema
    # states rather than whatever ALTER DEFAULT PRIVILEGES happened to confer.
    op.execute(f"SELECT {SCHEMA}.sanitize_schema_privileges()")


def downgrade() -> None:
    """Back to the Milestone 3.1 shape exactly.

    The trigger, the six functions, the policies and the two relations are dropped, in
    dependency order, and the three replaced ``0005`` bodies are put back verbatim, so the
    catalogue is what a fresh migration to ``0005`` produces.
    """
    op.execute(
        f"DROP TRIGGER workspace_preferences_set_consent ON {SCHEMA}.workspace_preferences"
    )
    for name, signature, _audience in reversed(FUNCTIONS):
        op.execute(f"DROP FUNCTION {SCHEMA}.{name}({signature})")
    op.execute(_LEGACY_WORKSPACE_MEMBERSHIP_AUTHORITY_RESTORE)
    op.execute(f"DROP TABLE {SCHEMA}.identity_expected_workspace")
    op.execute(_LEGACY_COMPLETE_ACCOUNT_RECOVERY_RESTORE)
    op.execute(_LEGACY_VERIFY_ACCOUNT_EMAIL_RESTORE)
    for _command, suffix, _using, _with_check in POLICIES:
        op.execute(
            f"DROP POLICY IF EXISTS {_policy_name('workspace_preferences', suffix)} "
            f"ON {SCHEMA}.workspace_preferences"
        )
    op.drop_index(
        "ix_workspace_preferences_tenant_id", table_name="workspace_preferences", schema=SCHEMA
    )
    op.drop_table("workspace_preferences", schema=SCHEMA)
