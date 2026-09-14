"""Grants that separate application access from privileged provisioning.

Deliberately **not** part of the Alembic migration. Role names differ per environment
(and per disposable test database), so putting them in a migration would either hard-code
an environment into the schema history or make that history non-deterministic. The schema
migration is role-agnostic; role wiring is an explicit admin action, run here by the test
bootstrap and by an operator runbook in production.

Three roles, three jobs:

``owner``
    Owns the schema and runs migrations. Privileged by definition. Not used at runtime.

``application``
    What the API, controller and validator connect as. Non-owner, ``NOSUPERUSER``,
    ``NOBYPASSRLS``, no DDL, **no TEMP**, and **no role membership of any kind** -- see
    ``db/principal.py``, which refuses a connection that can ``SET ROLE`` to anything. It
    gets DML on tenant-scoped tables and is fully subject to the isolation policies --
    including on ``tenants``, where it may read only its own row and may not INSERT at all,
    and on ``idempotency_records`` and ``outbox_events``, where it may read and append but
    never update or delete.

    On ``audit_events`` it holds ``SELECT`` and **not** ``INSERT``. Appending goes through
    ``firmbatch.append_audit_event()``, which applies the whole bounded-metadata policy
    inside the database; an ``INSERT`` privilege here would make that policy advisory,
    because the table's check constraints bound a details document's size and shape and say
    nothing about its content.

``provisioning``
    Creates tenants. Also non-owner, non-superuser and non-``BYPASSRLS``: it is
    privileged only in the narrow sense that it holds INSERT on ``tenants``, and it holds
    no privilege whatsoever on tenant data. Since Milestone 2.3 it cannot even name the
    tenant it is creating: ``firmbatch.begin_tenant_provisioning()`` generates the id.

``lifecycle writer``
    **A fourth role, and not a runtime one.** ``NOLOGIN``, no credential, no membership,
    ``NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS NOINHERIT``, and nobody
    -- not the application role, not provisioning, not the schema owner -- may ``SET ROLE``
    to it. It owns exactly two objects: the ``SECURITY DEFINER`` lifecycle entry points,
    which therefore *execute as it*. That is the whole of its purpose. The guards on the
    lifecycle tags, on ``lifecycle_claim_provenance`` and on linking an outbox event to a
    lifecycle claim require ``current_user`` to be this role, so "this row was written by
    the lifecycle boundary" is a fact about who is executing rather than a convention about
    who owns the schema. See :func:`install_lifecycle_writer`.

    It holds the minimum the two entry points need and nothing more: ``USAGE`` on the
    schema, ``EXECUTE`` on the helpers the bodies and the policies call, ``SELECT`` where the
    replay reads, and column-level ``INSERT``/``UPDATE`` on exactly the columns the bodies
    write. It owns no table and no schema, and row security stays ``FORCE``d against it.

Every one of those roles remains under RLS. Nothing here hands out ``BYPASSRLS``, and
nothing may: the point of forcing row security is that no role can turn it off.

**Neither runtime role holds anything at all on the protected tables.** The credential
registry ``auth_bindings``, the transaction-context relation ``auth_transaction_context``
and Milestone 2.4's three lifecycle definition tables are protected by the absence of
grants rather than by a policy, so "the runtime cannot enumerate credential fingerprints or
their tenant mappings", "the runtime cannot write itself a context" and "the runtime cannot
add an edge to a state machine" are privilege facts rather than predicates that have to be
got right. The same applies to every internal function, ``auth_context_begin`` above all:
it is granted to nobody, because a role that could call it could name any tenant it liked.

**And the two runtime roles are no longer symmetric.** Milestone 2.4's lifecycle functions
are granted to the application role and **not** to provisioning, which receives no lifecycle
authority of any kind. Provisioning creates a tenant and mints its first credential; moving
a job through its lifecycle is not that, and no documented requirement asks for it.

**And the wiring is revision-aware.** Every statement below names a table or a function,
and which of those exist depends on the schema revision. See ``RevisionPlan``: four
supported revisions, an explicit plan for each, and a refusal for anything else.

**Milestone 3.1 adds functions and protected relations, and no role.** The identity plane
-- accounts, passwords, tokens, sessions, memberships, invitations -- is protected by the
absence of grants exactly as ``auth_bindings`` is, and reached only through ``SECURITY
DEFINER`` functions the schema owner owns, granted to the application role alone. The
application role's table grants are unchanged from Milestone 2.4.

**Nothing is inherited from a PostgreSQL default.** PUBLIC loses ``CREATE`` on every
schema, ``TEMP`` on the database, ``EXECUTE`` on every authentication function, and all
table privileges; each runtime role is then granted back only what it needs. Defaults
change between major versions and differ between a stock server and a hardened one, so a
grant that is only correct because of a default is a grant that is only correct here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from sqlalchemy import Connection, text

from .base import SCHEMA, VERSION_TABLE

_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


class UnsupportedSchemaRevision(RuntimeError):
    """The database's schema revision is not one this module knows how to wire.

    Raised rather than worked around. The grants below name tables and functions, so a
    revision that does not have them is a revision whose grant set this module has not
    been told. Guessing -- by catching ``UndefinedTable`` and continuing -- would leave a
    half-wired database that looks provisioned, which is the failure mode worth spending
    an explicit error to avoid.
    """


#: The functions every isolation policy calls, and the ones a caller uses to acquire and
#: inspect its own context. Policies are evaluated with the privileges of the querying
#: role, so a role without EXECUTE here cannot read a tenant-scoped table at all -- which
#: is the correct failure direction.
#:
#: ``bind_authenticated_context`` is here because presenting a credential is what a
#: runtime connection does; ``register_auth_binding`` and ``revoke_auth_binding`` are here
#: because Milestone 3's credential lifecycle runs on the application role. Neither
#: confers authority by being callable: both derive the tenant from the context and refuse
#: without ``credential:manage``.
RUNTIME_AUTH_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("auth_context", ""),
    ("auth_tenant_id", ""),
    ("auth_principal_id", ""),
    ("auth_binding_id", ""),
    ("auth_actor_kind", ""),
    ("auth_scopes", ""),
    ("auth_has_scope", "text"),
    ("bind_authenticated_context", "text"),
    ("register_auth_binding", "uuid, text[], timestamptz"),
    ("revoke_auth_binding", "uuid"),
    # The only way any role writes an audit row. No role holds INSERT on audit_events, so
    # this is not the polite path but the only one -- which is what makes the bounded
    # metadata policy hold under arbitrary runtime SQL rather than only when the Python
    # boundary was asked first.
    ("append_audit_event", "text, text, text, uuid, uuid, jsonb"),
)

#: Establishing context without a credential. Only the provisioning role, and only
#: because a tenant has no credential until it exists. It takes no arguments and
#: generates the tenant id itself, so it cannot be pointed at an existing tenant.
PROVISIONING_AUTH_FUNCTIONS: tuple[tuple[str, str], ...] = (("begin_tenant_provisioning", ""),)

#: Executable by **nobody**.
#:
#: ``auth_context_begin`` writes the authentication context: a role that could call it
#: could name any tenant and any scope set it liked, which is precisely the property
#: migration ``0003`` exists to remove. ``auth_require_read_committed`` is the isolation
#: guard it and the binding function share. Both are called only from inside
#: ``SECURITY DEFINER`` functions, where the current user is the schema owner and the
#: privilege is implicit.
#:
#: ``audit_events_set_occurred_at`` is a trigger function. PostgreSQL does not check
#: ``EXECUTE`` when firing a trigger, so it needs no grant to do its job -- and granting
#: one would only make it callable as an ordinary function, which nothing needs.
#: ``auth_require_writable_primary`` is the standby and read-only guard the context writer
#: calls before its write. ``secret_shape`` and ``audit_require_acceptable_details`` are
#: the metadata policy the audit append function applies; they are internal so that the
#: policy has exactly one caller and cannot be probed as an oracle in its own right.
INTERNAL_AUTH_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("auth_context_begin", "uuid, uuid, uuid, text, text[]"),
    ("auth_require_read_committed", ""),
    ("auth_require_writable_primary", ""),
    ("secret_shape", "text"),
    ("audit_require_acceptable_details", "jsonb"),
    ("audit_events_set_occurred_at", ""),
)

ALL_AUTH_FUNCTIONS: tuple[tuple[str, str], ...] = (
    RUNTIME_AUTH_FUNCTIONS + PROVISIONING_AUTH_FUNCTIONS + INTERNAL_AUTH_FUNCTIONS
)

#: Milestone 2.4's lifecycle kernel, granted to the **application role only**.
#:
#: Not to provisioning, and the omission is a decision rather than an oversight: the
#: provisioning role exists to create a tenant and mint that tenant's first credential.
#: Moving a job through its lifecycle is not a provisioning act, no documented requirement
#: asks for one, and a role that could do both would be a second path into tenant data.
#:
#: ``lifecycle_required_scope`` is here because **every policy on both tenant-owned
#: lifecycle tables calls it**: a policy is evaluated with the querying role's privileges,
#: so a role without ``EXECUTE`` here could not read its own instances at all. What it
#: discloses is which capability a global, immutable machine version requires -- a fact
#: about the closed scope catalogue, not about any tenant.
APPLICATION_LIFECYCLE_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("lifecycle_required_scope", "text, integer, text"),
    # Answers which role is the lifecycle writer, from the catalogue. The outbox-link guard
    # calls it while running as whoever inserted the event, and for a generic event that is
    # the application role. It discloses a role name ``pg_proc`` and ``pg_roles`` already
    # show to every role, and knowing the name confers nothing: nobody can SET ROLE to it.
    ("lifecycle_writer_role", ""),
)

#: **Owned by the lifecycle writer**, and granted to the application role *by the writer*.
#:
#: The migration creates these owned by the schema owner, like everything it creates, and
#: :func:`install_lifecycle_writer` hands them over. From then on they execute as the writer,
#: which is what every lifecycle-derived guard checks for -- and the schema owner can no
#: longer ``GRANT`` or ``REVOKE`` on them (PostgreSQL requires the owner or a grant option
#: for either), so their ``EXECUTE`` grant is written under ``SET ROLE`` to the writer.
#:
#: Seven parameters on the transition, not nine: the operation name and the request
#: fingerprint are derived inside the function, from the machine the instance pins and from
#: the arguments the call executed. A caller that could supply either could bind a claim to
#: a request it did not make.
LIFECYCLE_WRITER_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("create_lifecycle_instance", "text, integer"),
    (
        "transition_lifecycle_instance",
        "uuid, text, integer, text, text, jsonb, text",
    ),
)

#: What the two entry points call while executing as the writer, and therefore what the
#: writer must hold ``EXECUTE`` on. Enumerated from the bodies rather than granted as "all
#: functions": the writer receives no ``bind_authenticated_context``, no credential
#: registration or revocation, no generic audit append and no provisioning, because the
#: bodies call none of them.
#:
#: The policies are in here too. A policy is evaluated with the querying role's privileges,
#: and every lifecycle-table policy calls the context accessors and
#: ``lifecycle_required_scope``; the framework-table policies the writer's inserts meet call
#: ``auth_has_scope`` and the tag-aware reader. The trigger functions are not here: PostgreSQL
#: checks no ``EXECUTE`` when firing a trigger, and the functions *those* call
#: (``lifecycle_initial_state``, ``lifecycle_state_is_terminal``, ``lifecycle_edge_exists``,
#: ``lifecycle_writer_role``) are.
LIFECYCLE_WRITER_HELPER_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("auth_context", ""),
    ("auth_tenant_id", ""),
    ("auth_principal_id", ""),
    ("auth_binding_id", ""),
    ("auth_actor_kind", ""),
    ("auth_has_scope", "text"),
    ("auth_require_read_committed", ""),
    ("secret_shape", "text"),
    ("audit_require_acceptable_details", "jsonb"),
    ("lifecycle_required_scope", "text, integer, text"),
    ("lifecycle_writer_role", ""),
    ("lifecycle_initial_state", "text, integer"),
    ("lifecycle_state_is_terminal", "text, integer, text"),
    ("lifecycle_edge_exists", "text, integer, text, text"),
    (
        "lifecycle_request_fingerprint",
        "uuid, text, uuid, text, integer, text, integer, text, text, jsonb",
    ),
    ("lifecycle_replay_claim", "text, text, text, integer, text"),
    ("append_lifecycle_audit_event", "text, text, text, uuid, jsonb, text, integer"),
)

#: Executable by **nobody**.
#:
#: The three definition readers, because a role that could call them could enumerate every
#: registered machine and its scopes, and nothing needs to; ``publish_lifecycle_machine``,
#: because publication is the last step of registration and registration is an owner action,
#: and a runtime role that could publish could make a half-built graph consumable; and the
#: seven trigger functions, because PostgreSQL does not check ``EXECUTE`` when firing a
#: trigger, so granting one would only make it callable as an ordinary function.
#: ``lifecycle_definition_is_immutable`` in particular exists to raise, and a role that could
#: call it directly would gain nothing but a confusing error.
#: ``lifecycle_request_fingerprint`` and ``lifecycle_replay_claim`` are internal for the
#: same reason ``secret_shape`` is: the fingerprint is what a claim is matched on, so a role
#: that could compute one outside a transition could work out which request a stored claim
#: was for by guessing candidates against it; and the replay reader answers "is this key
#: taken, and by what" for an operation namespace the caller would otherwise have to be
#: authorised for a machine to reach. ``append_lifecycle_audit_event`` is internal because it
#: is the only writer permitted to tag an audit row, and a role that could call it could tag
#: a row of its own -- or, worse, write a ``lifecycle.`` action about an instance it invented.
INTERNAL_LIFECYCLE_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("lifecycle_initial_state", "text, integer"),
    ("lifecycle_state_is_terminal", "text, integer, text"),
    ("lifecycle_edge_exists", "text, integer, text, text"),
    (
        "lifecycle_request_fingerprint",
        "uuid, text, uuid, text, integer, text, integer, text, text, jsonb",
    ),
    ("lifecycle_replay_claim", "text, text, text, integer, text"),
    ("append_lifecycle_audit_event", "text, text, text, uuid, jsonb, text, integer"),
    ("publish_lifecycle_machine", "text, integer"),
    ("lifecycle_definition_is_immutable", ""),
    ("lifecycle_machines_before_insert", ""),
    ("lifecycle_machines_before_update", ""),
    ("lifecycle_definition_rows_before_insert", ""),
    ("lifecycle_edges_check_source", ""),
    ("lifecycle_instances_before_insert", ""),
    ("lifecycle_instances_before_update", ""),
    ("lifecycle_transitions_before_insert", ""),
    ("lifecycle_framework_tag_is_derived", ""),
    ("lifecycle_claim_provenance_guard", ""),
    # The outbox-link guard: a trigger function, so it needs no grant to fire, and it fires
    # as whoever inserted the event -- which is how a generic writer's link is checked under
    # that writer's own row-security view of the claims.
    ("outbox_events_link_is_authorized", ""),
)

ALL_LIFECYCLE_FUNCTIONS: tuple[tuple[str, str], ...] = (
    APPLICATION_LIFECYCLE_FUNCTIONS + LIFECYCLE_WRITER_FUNCTIONS + INTERNAL_LIFECYCLE_FUNCTIONS
)

#: Executable by **nobody**: the ownership-aware ACL sanitiser ``0004`` installs, whose body is
#: :data:`SCHEMA_ACL_SANITIZER_BODY`. Called by the migration that creates it and by any later
#: migration, which then carries no fourth copy; the runtime runs the same body as a ``DO``
#: block. Kept out of the lifecycle inventory because it is maintenance rather than lifecycle
#: -- and because it builds statements by design, from catalogue names only, which the
#: lifecycle functions are asserted never to do.
INTERNAL_MAINTENANCE_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("sanitize_schema_privileges", ""),
)

#: Milestone 3.1's identity, membership, session and issuance functions, granted to the
#: **application role only**. The provisioning role receives none of them: it creates
#: tenants out of band and mints their first credential; it does not sign people in.
#:
#: Every one is a hardened ``SECURITY DEFINER`` function over protected relations (or, for
#: ``membership_role_scopes``, a pure ``SECURITY INVOKER`` mapping). None takes a tenant,
#: an account or a membership as the thing that decides what it acts on: the session
#: secret, the challenge in this transaction, or the context an earlier bind established
#: decides that, and an identifier a caller supplies only selects within what the context
#: already reaches.
IDENTITY_APPLICATION_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("membership_role_scopes", "text"),
    ("auth_session", ""),
    ("bind_session_context", "text, text, text"),
    # The one membership revalidation (Milestone 3.1 security correction, stale-scope
    # finding): the workspace serialisation lock, then tenant, workspace, account,
    # membership identity, both active states and the current role, re-read under it. Every
    # workspace-mode function calls it, and so does the HTTP boundary for the one audit
    # disclosure it performs itself. It discloses nothing the caller's own bind did not.
    ("workspace_membership_authority", "text, boolean"),
    ("account_profile", ""),
    ("account_sessions", ""),
    ("revoke_browser_session", "uuid"),
    ("revoke_all_browser_sessions", "boolean"),
    ("account_workspaces", ""),
    ("create_workspace", "text, text, text"),
    ("bind_session_workspace", "uuid"),
    ("unbind_session_workspace", ""),
    ("rename_workspace", "text, text"),
    ("workspace_memberships", ""),
    ("remove_membership", "uuid, text"),
    ("change_membership_role", "uuid, text, text"),
    ("create_invitation", "text, text, interval, text"),
    ("revoke_invitation", "uuid, text"),
    ("workspace_invitations", ""),
    ("accept_invitation", "text, text"),
    ("issue_api_credential", "text[], timestamptz, text, text"),
    ("rotate_api_credential", "uuid, timestamptz, text"),
    ("revoke_api_credential", "uuid, text"),
    ("workspace_api_credentials", ""),
    ("record_api_credential_use", ""),
)

#: The **trusted-issuer boundary** (Milestone 3.1 security correction). These pre-
#: authentication functions verify a password (login), open a browser session from a login
#: challenge, or mint and consume the two **mailbox-proof** secrets -- account recovery and
#: email verification. They are granted to a **distinct authenticator role** and to the
#: ordinary application role NOT AT ALL. The application role is the large runtime attack
#: surface -- every workspace, credential and API request passes through it -- and this
#: split means raw SQL as that role can neither harvest a stored password hash, mint a
#: session for a victim account, request-and-consume a recovery secret to reset a victim
#: password, nor issue-and-consume a verification token to mark an address it does not
#: control verified.
#:
#: **Mailbox verification is a mailbox proof, exactly as recovery is** (this correction).
#: ``signup_account`` and ``request_email_verification`` mint a verification secret and
#: **return it in the result row**, and ``verify_account_email`` consumes one and flips the
#: account to ``active``; a role holding all three can register an address it does not
#: control, read the secret out of its own result, consume it, and hold a verified account
#: -- which is the whole of the mailbox-control proof, and which then satisfies the
#: verified-account precondition on workspace creation and invitation acceptance. Only the
#: principal trusted to hand a raw secret to the email adapter may hold that authority, and
#: that principal is the authenticator. Password verification still runs in the application
#: process (PostgreSQL has no Argon2, ADR 0009 decision 6), but the authority to turn a
#: verified password or a mailbox-proven secret into account state is now held by a narrow
#: principal, not by the runtime that serves ordinary requests. ADR 0009 (revised) records
#: this and the M3.3 process-separation it advances.
IDENTITY_AUTHENTICATOR_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("signup_account", "text, text, interval"),
    ("request_email_verification", "text, interval"),
    ("verify_account_email", "text"),
    ("login_lookup", "text"),
    ("open_browser_session", "interval"),
    ("request_account_recovery", "text, interval"),
    ("account_recovery_token_valid", "text"),
    ("complete_account_recovery", "text, text"),
)

#: The two Milestone 3.2 additions to the trusted-issuer boundary, granted to the
#: authenticator role alone and to the application role not at all -- the same split, for
#: the same reason, as the eight above. A signed-in password change reads a stored Argon2id
#: hash and replaces it, which is precisely the authority the M3.1 correction moved off the
#: large runtime surface.
#:
#: This grants the authenticator **no capability it did not already have**: it already holds
#: ``request_account_recovery`` and ``complete_account_recovery``, so it could already mint
#: and consume a recovery secret and replace any account's password. What these add is a
#: path that additionally requires proof of the *current* password (verified in Python
#: against the hash ``password_change_lookup`` returns) and a live browser session for the
#: account, which is strictly narrower than the recovery path beside it.
IDENTITY_PASSWORD_CHANGE_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("password_change_lookup", "uuid, uuid"),
    ("change_account_password", "text, text, interval"),
)

#: The read-side functions the authenticator needs beyond its own entry points (eight at
#: ``0005``, ten from ``0006``), derived from the call graph rather than assumed, and closed
#: over invoker-rights calls.
#:
#: ``db/engine.transaction()`` opens every transaction by asserting it inherited no context,
#: and that assertion is ``current_tenant_context()`` executing
#: ``SELECT firmbatch.auth_tenant_id()``. ``auth_tenant_id`` is one of migration ``0003``'s
#: **SECURITY INVOKER** accessors -- its whole body is
#: ``SELECT (firmbatch.auth_context()).tenant_id`` -- so the inner call runs as the *caller*
#: and the caller needs ``EXECUTE`` on ``auth_context`` as well. ``auth_context`` is
#: ``SECURITY DEFINER`` and reads the protected context relation as the schema owner, so the
#: chain terminates there: two functions, both read-only, neither conferring any authority
#: to establish a context. For the authenticator the answer is always "no context", because
#: nothing on its path ever writes one.
#:
#: Nothing else on that path executes a Firmbatch function from Python: the writable-primary
#: preflight reads ``pg_catalog.pg_is_in_recovery()`` and a GUC, the connect-time hardening
#: sets ``search_path`` and inspects ``pg_catalog``, and the eight pre-authentication entry
#: points are ``SECURITY DEFINER``, so the helpers *they* call
#: (``auth_require_writable_primary``, ``identity_context_write``, ``identity_issue_token``,
#: ``auth_context_begin`` and the rest) execute as the schema owner and need no grant here.
#:
#: Deliberately **not** the common runtime set: that tuple also carries
#: ``bind_authenticated_context``, ``register_auth_binding``, ``revoke_auth_binding`` and
#: ``append_audit_event``, none of which any authenticator call path reaches. Granting them
#: would hand the trusted-issuer principal the ability to bind a bearer context and to reach
#: the untied credential minter, which is the opposite of what this role exists to be.
AUTHENTICATOR_READ_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("auth_context", ""),
    ("auth_tenant_id", ""),
)

#: Executable by **nobody**. ``identity_context_write`` writes the transaction's identity
#: context, so a role that could call it could name any account and any session;
#: ``identity_claim`` writes claims and events as the schema owner; the replay reader, the
#: token issuer, the secret minter and the fingerprint helpers are reached only from inside
#: the entry points; the four trigger functions need no grant to fire.
IDENTITY_INTERNAL_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("identity_normalize_email", "text"),
    ("identity_mint_secret", "text"),
    ("identity_fingerprint", "text"),
    ("identity_request_fingerprint", "jsonb"),
    ("identity_context", ""),
    ("identity_context_write", "text, uuid, uuid, uuid, uuid, uuid, text, boolean, integer"),
    ("identity_context_narrow", "text[]"),
    ("identity_require_session", "text, boolean"),
    ("identity_require_ttl", "interval, interval"),
    ("identity_issue_token", "uuid, text, interval"),
    ("identity_replay", "text, text, text"),
    ("identity_claim", "text, text, text, jsonb, text, text, uuid, jsonb"),
    ("identity_active_owner_count", "uuid, uuid"),
    ("memberships_revocation_cascade", ""),
    ("workspace_directory_sync", ""),
    ("account_tokens_append_only", ""),
    ("account_idempotency_records_append_only", ""),
    ("purge_expired_unverified_accounts", "interval"),
)

#: Milestone 3.2's three functions for the application role: the two **mutation entry
#: points** for ``workspace_preferences`` and the expected-workspace writer. The entry points
#: are granted to the application role alone -- the same shape as ``append_audit_event``, and
#: for the same reason. The application role holds ``SELECT`` on the relation and nothing
#: else, so the only way a runtime role writes a preference or an acknowledgement is through
#: these, and each one requires a CSRF-verified workspace-bound session, re-derives the
#: caller's membership under the workspace lock, checks the workspace the caller's page
#: expected against the one the session is bound to, decides no-op or transition under that
#: lock, and appends its audit event and writes the row in one call (independent Milestone
#: 3.2 review, findings 2-4 and 9).
PORTAL_APPLICATION_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("state_workspace_preferences", "uuid, text[], text[], text, text"),
    ("acknowledge_workspace_consent", "uuid, text"),
    # The expected-workspace contract's writer: the boundary records, once per workspace
    # mutation, the workspace the page or action began under, and every ``0005`` workspace
    # mutation compares it with the binding inside ``workspace_membership_authority``.
    ("identity_expect_workspace", "uuid"),
)

#: Milestone 3.2's one trigger function, executable by nobody like the four above it: a
#: trigger fires as the table owner and needs no grant, and a role that could call this one
#: directly could stamp a consent record with any actor. After the review it is defence in
#: depth behind the two functions above, not the boundary.
PORTAL_INTERNAL_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("workspace_preferences_set_consent", ""),
)

#: Every function migration ``0005`` defines, and **only** those. Milestone 3.2's six live
#: in :data:`ALL_PORTAL_FUNCTIONS` instead, so that ``tests/test_identity_migration.py`` can
#: keep asserting that ``0005``'s own inventory equals this one exactly -- an assertion that
#: would have had to be loosened to "is a subset of" if a later milestone's functions were
#: folded in here, and a subset assertion would no longer catch a function dropped from
#: ``0005``. Migration ``0006`` **replaces the bodies** of three of these
#: (``verify_account_email`` and ``complete_account_recovery``, to bring them under the
#: account-plane lock order, and ``workspace_membership_authority``, to compare the recorded
#: expected workspace with the binding) and restores all three on downgrade; their names,
#: signatures and audience are unchanged, so they stay here.
ALL_IDENTITY_FUNCTIONS: tuple[tuple[str, str], ...] = (
    IDENTITY_APPLICATION_FUNCTIONS + IDENTITY_AUTHENTICATOR_FUNCTIONS + IDENTITY_INTERNAL_FUNCTIONS
)

#: Every function migration ``0006`` **adds** -- six: the two password-change entry points on
#: the trusted-issuer boundary, the three the application role holds (the two preference
#: mutations and the expected-workspace writer), and the one trigger function nobody may
#: execute.
ALL_PORTAL_FUNCTIONS: tuple[tuple[str, str], ...] = (
    IDENTITY_PASSWORD_CHANGE_FUNCTIONS + PORTAL_APPLICATION_FUNCTIONS + PORTAL_INTERNAL_FUNCTIONS
)

#: Every function this package's schema defines at head, and every one that no role may
#: execute. Two inventories rather than six, so that the ACL sanitisation, the principal
#: check and the hardening tests all walk the same list.
ALL_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ALL_AUTH_FUNCTIONS
    + ALL_LIFECYCLE_FUNCTIONS
    + INTERNAL_MAINTENANCE_FUNCTIONS
    + ALL_IDENTITY_FUNCTIONS
    + ALL_PORTAL_FUNCTIONS
)
INTERNAL_FUNCTIONS: tuple[tuple[str, str], ...] = (
    INTERNAL_AUTH_FUNCTIONS
    + INTERNAL_LIFECYCLE_FUNCTIONS
    + INTERNAL_MAINTENANCE_FUNCTIONS
    + IDENTITY_INTERNAL_FUNCTIONS
    + PORTAL_INTERNAL_FUNCTIONS
)


# ------------------------------------------------------------------ revision awareness
#
# Role wiring lives outside Alembic (see the module docstring) but it is not
# schema-independent: every statement below names a table or a function, and which ones
# exist depends on the revision the database is at.
#
# Before this was explicit, ``grant_application_role`` at revision ``0002`` failed on
# ``REVOKE ALL ON TABLE firmbatch.auth_bindings FROM PUBLIC`` -- ``UndefinedTable`` --
# because the wiring assumed the Milestone 2.3 objects. Measured, not inferred: migrate to
# ``0003``, provision, downgrade to ``0002``, provision again. Two supported revisions and
# an explicit refusal for everything else is the correction; catching the undefined-object
# error and continuing would have been a half-wired database that reported success.
#
# **Application code at head does not run against schema ``0002``.** The revision is
# supported here so that a controlled rollback can still provision and validate its roles,
# and so that the round trip is testable. Nothing else in this package targets it: the
# authenticated context, the audit trail and every Milestone 2.3 policy are ``0003``
# objects, and a runtime process pointed at ``0002`` would fail at its first bind.

M2_2_REVISION = "0002_idempotency_and_outbox"
M2_3_REVISION = "0003_auth_context_and_audit"
M2_4_REVISION = "0004_lifecycle_state_machines"
M3_1_REVISION = "0005_identity_and_membership"
M3_2_REVISION = "0006_preferences_and_password"
M3_3B_REVISION = "0007_password_hash_contract"

#: The protected relations each revision actually has. Written out per revision rather than
#: derived from :data:`PROTECTED_TABLES`, which describes **head**: deriving it is what made
#: the ``0002`` plan name ``auth_bindings`` and fail after a rollback, and deriving it again
#: would make the ``0003`` plan name the lifecycle definition tables that ``0003`` does not
#: create. A test asserts the head list equals the catalogue.
_M2_3_PROTECTED_TABLES: tuple[str, ...] = ("auth_bindings", "auth_transaction_context")
_M2_4_PROTECTED_TABLES: tuple[str, ...] = _M2_3_PROTECTED_TABLES + (
    "lifecycle_machines",
    "lifecycle_states",
    "lifecycle_transition_edges",
    "lifecycle_claim_provenance",
)
#: Milestone 3.1's identity plane: nine more protected relations, and the head list.
_M3_1_PROTECTED_TABLES: tuple[str, ...] = _M2_4_PROTECTED_TABLES + (
    "accounts",
    "account_passwords",
    "account_tokens",
    "memberships",
    "workspace_directory",
    "browser_sessions",
    "workspace_invitations",
    "account_idempotency_records",
    "identity_transaction_context",
)
#: Milestone 3.2: the transaction-scoped expected-workspace relation, protected like the
#: context relation it is keyed like -- no runtime role holds anything on it.
_M3_2_PROTECTED_TABLES: tuple[str, ...] = _M3_1_PROTECTED_TABLES + ("identity_expected_workspace",)

#: The columns of a framework table the application role may write, at ``0004`` and not
#: before.
#:
#: **The identifier is not among them, and that is the point.** A caller that could name a
#: row's primary key could submit one it had guessed or read elsewhere and learn from the
#: uniqueness conflict whether it exists -- an existence oracle over rows the read policies
#: hide. A column-level ``INSERT`` grant is refused at permission-check time, before the
#: executor inserts anything, so naming an id that exists and naming one that does not fail
#: **identically** and neither reaches an index. The ids these tables carry are generated by
#: ``gen_random_uuid()`` as a column default, or by the trusted database code that writes the
#: row, so nothing legitimate needs the privilege.
#:
#: The derived lifecycle tag is excluded for the same reason it has a trigger: it is written
#: by the lifecycle entry points, which run as the schema owner. So is every server-generated
#: timestamp. ``audit_events`` is absent because the application role holds no ``INSERT`` on
#: it at all -- appending goes through ``firmbatch.append_audit_event()``.
_M2_4_APPLICATION_COLUMN_GRANTS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "idempotency_records",
        "INSERT",
        ("tenant_id", "operation", "idempotency_key", "request_fingerprint", "status", "result"),
    ),
    (
        "outbox_events",
        "INSERT",
        (
            "tenant_id",
            "idempotency_record_id",
            "event_type",
            "aggregate_type",
            "aggregate_id",
            "attributes",
        ),
    ),
)

#: What the lifecycle writer reads, table-level. ``SELECT`` and nothing else here: the
#: transition resolves the instance, re-reads the revision it wrote, and the replay walks
#: the claim, the provenance, the history, the instance and the event. ``audit_events`` is
#: absent -- the writer appends to the trail and never reads it back.
_M2_4_LIFECYCLE_WRITER_GRANTS: tuple[tuple[str, str], ...] = (
    ("lifecycle_instances", "SELECT"),
    ("lifecycle_transitions", "SELECT"),
    ("idempotency_records", "SELECT"),
    ("outbox_events", "SELECT"),
    ("lifecycle_claim_provenance", "SELECT"),
)

#: What the lifecycle writer writes, column by column: exactly the columns the two entry
#: points name in their ``INSERT`` and ``UPDATE`` statements. Server-derived columns that a
#: ``BEFORE`` trigger overwrites -- ``occurred_at``, ``created_at``, ``updated_at``,
#: ``revision`` at creation -- are not here, because a trigger assignment needs no
#: privilege and a grant would only make them nameable.
_M2_4_LIFECYCLE_WRITER_COLUMN_GRANTS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "lifecycle_instances",
        "INSERT",
        ("id", "tenant_id", "machine_key", "machine_version", "current_state"),
    ),
    ("lifecycle_instances", "UPDATE", ("current_state", "revision")),
    (
        "lifecycle_transitions",
        "INSERT",
        (
            "id",
            "tenant_id",
            "lifecycle_instance_id",
            "machine_key",
            "machine_version",
            "from_state",
            "to_state",
            "from_revision",
            "to_revision",
            "actor_kind",
            "actor_principal_id",
            "actor_binding_id",
            "reason",
            "details",
        ),
    ),
    (
        "idempotency_records",
        "INSERT",
        (
            "id",
            "tenant_id",
            "operation",
            "idempotency_key",
            "request_fingerprint",
            "status",
            "result",
            "lifecycle_machine_key",
            "lifecycle_machine_version",
        ),
    ),
    (
        "outbox_events",
        "INSERT",
        (
            "id",
            "tenant_id",
            "idempotency_record_id",
            "event_type",
            "aggregate_type",
            "aggregate_id",
            "attributes",
            "lifecycle_machine_key",
            "lifecycle_machine_version",
        ),
    ),
    (
        "audit_events",
        "INSERT",
        (
            "id",
            "tenant_id",
            "actor_kind",
            "actor_principal_id",
            "actor_binding_id",
            "action",
            "outcome",
            "resource_type",
            "resource_id",
            "correlation_id",
            "details",
            "lifecycle_machine_key",
            "lifecycle_machine_version",
        ),
    ),
    (
        "lifecycle_claim_provenance",
        "INSERT",
        (
            "idempotency_record_id",
            "tenant_id",
            "lifecycle_transition_id",
            "lifecycle_instance_id",
            "machine_key",
            "machine_version",
            "from_revision",
            "to_revision",
            "outbox_event_id",
        ),
    ),
)

#: The one function the ``0001``/``0002`` policies called: the caller-set tenant setting
#: that Milestone 2.3 removed. Named here only so the ``0002`` grant set can be reproduced
#: exactly during a rollback.
_LEGACY_TENANT_CONTEXT_FUNCTION: tuple[tuple[str, str], ...] = (("app_current_tenant_id", ""),)


@dataclass(frozen=True)
class RevisionPlan:
    """Exactly what this module grants, at one schema revision.

    Data rather than branching code, so that "what does the application role hold at
    ``0002``?" is a value a test can read and compare, and so that re-upgrading restores
    the same grant set it had before rather than whatever the current code happens to do.
    """

    revision: str
    #: Every relation this plan touches. Checked to exist before anything is granted.
    tables: tuple[str, ...]
    #: Functions granted to both runtime roles.
    common_functions: tuple[tuple[str, str], ...]
    #: Functions granted to the provisioning role alone.
    provisioning_functions: tuple[tuple[str, str], ...]
    #: Functions granted to nobody, checked to exist and asserted to stay ungranted.
    internal_functions: tuple[tuple[str, str], ...]
    #: ``(table, privileges)`` for the application role.
    application_grants: tuple[tuple[str, str], ...]
    #: ``(table, privileges)`` for the provisioning role.
    provisioning_grants: tuple[tuple[str, str], ...]
    #: Functions granted to the **application** role alone. Milestone 2.4's lifecycle
    #: kernel, which provisioning deliberately receives no part of. Defaulted so the two
    #: earlier plans stay exactly what they were.
    application_functions: tuple[tuple[str, str], ...] = ()
    #: Functions granted to the **authenticator** role alone (Milestone 3.1 security
    #: correction). The pre-authentication trusted-issuer boundary -- login, session opening,
    #: recovery request and completion -- which no other runtime role receives. Empty before
    #: ``0005``, so every earlier plan is exactly what it was.
    authenticator_functions: tuple[tuple[str, str], ...] = ()
    #: The read-side functions the authenticator additionally needs to open a transaction at
    #: all. A named, minimal set rather than the common runtime tuple: see
    #: :data:`AUTHENTICATOR_READ_FUNCTIONS` for the call-graph derivation.
    authenticator_common_functions: tuple[tuple[str, str], ...] = ()
    #: ``(table, privileges, columns)`` for the application role, applied after
    #: :attr:`application_grants`. Column-level rather than table-level so that the columns
    #: *not* named are unwritable -- primary keys above all. Defaulted empty, so ``0002``
    #: and ``0003`` keep exactly the table-level grants they had.
    application_column_grants: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
    #: The ``SECURITY DEFINER`` entry points the **lifecycle writer** owns at this revision,
    #: and grants ``EXECUTE`` on to the application role. Empty before ``0004``, where the
    #: writer owns nothing and holds nothing -- which :func:`install_lifecycle_writer`
    #: enforces by revoking rather than by assuming.
    lifecycle_writer_functions: tuple[tuple[str, str], ...] = ()
    #: Functions the writer needs ``EXECUTE`` on, because the entry-point bodies, the
    #: triggers they fire and the policies they meet call them.
    lifecycle_writer_helper_functions: tuple[tuple[str, str], ...] = ()
    #: ``(table, privileges)`` for the writer, table-level -- ``SELECT`` only, where the
    #: entry points or the replay read.
    lifecycle_writer_grants: tuple[tuple[str, str], ...] = ()
    #: ``(table, privileges, columns)`` for the writer: exactly the columns the bodies
    #: write, so a column they do not name stays unwritable even for the boundary itself.
    lifecycle_writer_column_grants: tuple[tuple[str, str, tuple[str, ...]], ...] = ()


_M2_2_PLAN = RevisionPlan(
    revision=M2_2_REVISION,
    tables=("tenants", "workspaces", "idempotency_records", "outbox_events"),
    common_functions=_LEGACY_TENANT_CONTEXT_FUNCTION,
    provisioning_functions=(),
    internal_functions=(),
    application_grants=(
        ("tenants", "SELECT"),
        ("workspaces", "SELECT, INSERT, UPDATE, DELETE"),
        ("idempotency_records", "SELECT, INSERT"),
        ("outbox_events", "SELECT, INSERT"),
    ),
    provisioning_grants=(("tenants", "SELECT, INSERT, UPDATE"),),
)

_M2_3_PLAN = RevisionPlan(
    revision=M2_3_REVISION,
    tables=(
        "tenants",
        "workspaces",
        "idempotency_records",
        "outbox_events",
        "audit_events",
        *_M2_3_PROTECTED_TABLES,
    ),
    common_functions=RUNTIME_AUTH_FUNCTIONS,
    provisioning_functions=PROVISIONING_AUTH_FUNCTIONS,
    internal_functions=INTERNAL_AUTH_FUNCTIONS,
    application_grants=(
        # Read-only on tenants: an application resolves its own tenant, it never creates one.
        ("tenants", "SELECT"),
        ("workspaces", "SELECT, INSERT, UPDATE, DELETE"),
        # Append-only, and narrower than the tables above on purpose (Milestone 2.2). The
        # application claims idempotency keys and appends outbox events; it never revises a
        # committed claim or edits an event it has already published. UPDATE and DELETE are
        # not granted, so the attempt is an error rather than a silent no-op -- migration
        # 0002 additionally gives these tables no UPDATE or DELETE policy at all, which
        # binds every other role including the owner.
        ("idempotency_records", "SELECT, INSERT"),
        ("outbox_events", "SELECT, INSERT"),
        # SELECT and **not** INSERT. Reading the trail is a policed operation; writing one
        # goes through firmbatch.append_audit_event(), which is the only path that applies
        # the metadata policy to a row a runtime role composed. A direct INSERT privilege
        # would have made that boundary advisory: the check constraints on the table bound
        # a document's size and shape, never its content.
        ("audit_events", "SELECT"),
    ),
    # Provisioning gets tenants and nothing else. No INSERT on audit_events either: it
    # appends through the same hardened function, and it cannot read the trail back
    # because reading is the audit:read capability and a provisioning context has none.
    provisioning_grants=(("tenants", "SELECT, INSERT, UPDATE"),),
)

_M2_4_PLAN = RevisionPlan(
    revision=M2_4_REVISION,
    tables=(
        "tenants",
        "workspaces",
        "idempotency_records",
        "outbox_events",
        "audit_events",
        "lifecycle_instances",
        "lifecycle_transitions",
        *_M2_4_PROTECTED_TABLES,
    ),
    # NOTE: _M2_4_PROTECTED_TABLES now includes lifecycle_claim_provenance, which is
    # protected for the same reason the definition tables are: no role holds anything on
    # it, so "a generic writer cannot forge the link a replay rests on" is a privilege fact.
    common_functions=RUNTIME_AUTH_FUNCTIONS,
    provisioning_functions=PROVISIONING_AUTH_FUNCTIONS,
    application_functions=APPLICATION_LIFECYCLE_FUNCTIONS,
    internal_functions=(
        INTERNAL_AUTH_FUNCTIONS + INTERNAL_LIFECYCLE_FUNCTIONS + INTERNAL_MAINTENANCE_FUNCTIONS
    ),
    application_grants=(
        ("tenants", "SELECT"),
        ("workspaces", "SELECT, INSERT, UPDATE, DELETE"),
        # **SELECT at table level, and INSERT only on named columns** -- see
        # _M2_4_APPLICATION_COLUMN_GRANTS. The privilege set is otherwise exactly Milestone
        # 2.2's: what changed is that the row's identifier is no longer among the columns a
        # caller may name, so a chosen primary key is refused before any index sees it.
        ("idempotency_records", "SELECT"),
        ("outbox_events", "SELECT"),
        ("audit_events", "SELECT"),
        # **SELECT and nothing else, on both.** A direct INSERT on lifecycle_instances
        # could start an instance in any state; a direct UPDATE could move it to any state
        # at any revision, which is the compare-and-swap gone. A direct INSERT on
        # lifecycle_transitions could record a move that never happened, or attribute a
        # real one to somebody else. Both go through hardened SECURITY DEFINER functions
        # instead, and reading is what is left.
        ("lifecycle_instances", "SELECT"),
        ("lifecycle_transitions", "SELECT"),
    ),
    application_column_grants=_M2_4_APPLICATION_COLUMN_GRANTS,
    # Unchanged, deliberately: provisioning gains no lifecycle authority at all -- no table
    # privilege, and none of the lifecycle functions.
    provisioning_grants=(("tenants", "SELECT, INSERT, UPDATE"),),
    # The lifecycle writer: owns the two entry points, holds exactly what their bodies need.
    lifecycle_writer_functions=LIFECYCLE_WRITER_FUNCTIONS,
    lifecycle_writer_helper_functions=LIFECYCLE_WRITER_HELPER_FUNCTIONS,
    lifecycle_writer_grants=_M2_4_LIFECYCLE_WRITER_GRANTS,
    lifecycle_writer_column_grants=_M2_4_LIFECYCLE_WRITER_COLUMN_GRANTS,
)

#: Milestone 3.1. The Milestone 2.4 plan, plus the identity plane: nine protected
#: relations the runtime holds nothing on, and fifty-one identity functions -- twenty-five
#: granted to the application role alone (:data:`IDENTITY_APPLICATION_FUNCTIONS`), eight to
#: the authenticator role alone (:data:`IDENTITY_AUTHENTICATOR_FUNCTIONS`, the
#: trusted-issuer boundary: five before the M3.1 correction moved the three
#: mailbox-verification functions there), and eighteen executable by nobody
#: (:data:`IDENTITY_INTERNAL_FUNCTIONS`). The tuples are the authority for those counts;
#: if they disagree, the tuples are right and this comment is stale. The lifecycle writer's
#: ownership and grants are exactly Milestone 2.4's -- the identity functions are owned by
#: the schema owner, like Milestone 2.3's credential functions, and ADR 0009 records why a
#: second dedicated writer role was not introduced for them.
#:
#: The application role's **table** grants are unchanged: every identity relation is
#: reached through a function, and ``auth_bindings`` -- which gained six columns -- stays
#: as ungranted as it was.
_M3_1_PLAN = RevisionPlan(
    revision=M3_1_REVISION,
    tables=(
        "tenants",
        "workspaces",
        "idempotency_records",
        "outbox_events",
        "audit_events",
        "lifecycle_instances",
        "lifecycle_transitions",
        *_M3_1_PROTECTED_TABLES,
    ),
    common_functions=RUNTIME_AUTH_FUNCTIONS,
    provisioning_functions=PROVISIONING_AUTH_FUNCTIONS,
    application_functions=APPLICATION_LIFECYCLE_FUNCTIONS + IDENTITY_APPLICATION_FUNCTIONS,
    authenticator_functions=IDENTITY_AUTHENTICATOR_FUNCTIONS,
    authenticator_common_functions=AUTHENTICATOR_READ_FUNCTIONS,
    internal_functions=(
        INTERNAL_AUTH_FUNCTIONS
        + INTERNAL_LIFECYCLE_FUNCTIONS
        + INTERNAL_MAINTENANCE_FUNCTIONS
        + IDENTITY_INTERNAL_FUNCTIONS
    ),
    application_grants=_M2_4_PLAN.application_grants,
    application_column_grants=_M2_4_APPLICATION_COLUMN_GRANTS,
    provisioning_grants=_M2_4_PLAN.provisioning_grants,
    lifecycle_writer_functions=LIFECYCLE_WRITER_FUNCTIONS,
    lifecycle_writer_helper_functions=LIFECYCLE_WRITER_HELPER_FUNCTIONS,
    lifecycle_writer_grants=_M2_4_LIFECYCLE_WRITER_GRANTS,
    lifecycle_writer_column_grants=_M2_4_LIFECYCLE_WRITER_COLUMN_GRANTS,
)

#: Milestone 3.2. The Milestone 3.1 plan, plus one policed relation, one protected relation
#: and six functions.
#:
#: ``workspace_preferences`` is the first customer relation added since ``workspaces``
#: itself, and it is **policed, not protected**: it carries ``tenant_id``, it is ``FORCE``
#: row-secured, and the application role holds **``SELECT`` on it and nothing else**. Not
#: ``INSERT`` or ``UPDATE``: after the independent Milestone 3.2 review every write goes
#: through the two ``SECURITY DEFINER`` mutation functions in
#: :data:`PORTAL_APPLICATION_FUNCTIONS`, which are the authorization and audit boundary for
#: the relation -- the same arrangement ``audit_events`` has with ``append_audit_event`` --
#: and a runtime role that could ``INSERT`` or ``UPDATE`` the table itself could write a
#: preference with no audit event and a consent row with no revalidated membership behind
#: it. Not ``DELETE`` either: preferences are amended, and they leave with the workspace
#: through the composite foreign key's cascade. Migration ``0006`` gives the table no
#: ``DELETE`` policy, which binds the owner too -- both halves, exactly as the append-only
#: tables do it -- and keeps the ``INSERT`` and ``UPDATE`` policies, which now bind only the
#: owner running those two functions.
#:
#: ``identity_expected_workspace`` is the second relation, and it is **protected, not
#: policed**, like the transaction-context relation whose key it shares: no runtime role
#: holds anything on it, and its only writer and reader are the ``SECURITY DEFINER``
#: functions ``identity_expect_workspace`` and ``workspace_membership_authority``.
#:
#: The authenticator gains the two password-change functions and nothing else. The
#: application role gains the two mutation functions and the expected-workspace writer; the
#: trigger function needs no grant to fire and receives none.
_M3_2_PLAN = RevisionPlan(
    revision=M3_2_REVISION,
    tables=(
        "tenants",
        "workspaces",
        "workspace_preferences",
        "idempotency_records",
        "outbox_events",
        "audit_events",
        "lifecycle_instances",
        "lifecycle_transitions",
        *_M3_2_PROTECTED_TABLES,
    ),
    common_functions=RUNTIME_AUTH_FUNCTIONS,
    provisioning_functions=PROVISIONING_AUTH_FUNCTIONS,
    application_functions=(
        APPLICATION_LIFECYCLE_FUNCTIONS + IDENTITY_APPLICATION_FUNCTIONS + PORTAL_APPLICATION_FUNCTIONS
    ),
    authenticator_functions=IDENTITY_AUTHENTICATOR_FUNCTIONS + IDENTITY_PASSWORD_CHANGE_FUNCTIONS,
    authenticator_common_functions=AUTHENTICATOR_READ_FUNCTIONS,
    internal_functions=(
        INTERNAL_AUTH_FUNCTIONS
        + INTERNAL_LIFECYCLE_FUNCTIONS
        + INTERNAL_MAINTENANCE_FUNCTIONS
        + IDENTITY_INTERNAL_FUNCTIONS
        + PORTAL_INTERNAL_FUNCTIONS
    ),
    application_grants=_M2_4_PLAN.application_grants + (
        ("workspace_preferences", "SELECT"),
    ),
    application_column_grants=_M2_4_APPLICATION_COLUMN_GRANTS,
    provisioning_grants=_M2_4_PLAN.provisioning_grants,
    lifecycle_writer_functions=LIFECYCLE_WRITER_FUNCTIONS,
    lifecycle_writer_helper_functions=LIFECYCLE_WRITER_HELPER_FUNCTIONS,
    lifecycle_writer_grants=_M2_4_LIFECYCLE_WRITER_GRANTS,
    lifecycle_writer_column_grants=_M2_4_LIFECYCLE_WRITER_COLUMN_GRANTS,
)

#: ``0007``, the password-hash contract (an incidental correction found by Milestone 3.3b's
#: verification). It replaces three function bodies with ``CREATE OR REPLACE`` and adds no
#: relation, function or grant, so its plan is ``0006``'s with the revision changed.
_M3_3B_PLAN = replace(_M3_2_PLAN, revision=M3_3B_REVISION)

#: The revisions this module can wire. Anything else -- an older one, a newer one, a
#: database with no version table, or a version table carrying more than one row -- is
#: refused rather than guessed at.
REVISION_PLANS: dict[str, RevisionPlan] = {
    _M2_2_PLAN.revision: _M2_2_PLAN,
    _M2_3_PLAN.revision: _M2_3_PLAN,
    _M2_4_PLAN.revision: _M2_4_PLAN,
    _M3_1_PLAN.revision: _M3_1_PLAN,
    _M3_2_PLAN.revision: _M3_2_PLAN,
    _M3_3B_PLAN.revision: _M3_3B_PLAN,
}

SUPPORTED_REVISIONS: tuple[str, ...] = tuple(sorted(REVISION_PLANS))


def schema_revision(connection: Connection) -> str:
    """The single Alembic revision this database is at, or a refusal.

    Refuses a database with no version table, an empty one, and one carrying more than a
    single row -- the last being a branched or half-stamped history, which is precisely
    the state where guessing a grant set does the most damage.
    """
    present = connection.execute(
        text(
            "SELECT pg_catalog.to_regclass(:relation) IS NOT NULL"
        ),
        {"relation": f"{SCHEMA}.{VERSION_TABLE}"},
    ).scalar_one()
    if not present:
        raise UnsupportedSchemaRevision(
            f"{SCHEMA}.{VERSION_TABLE} does not exist, so this database has no schema revision to "
            "wire roles for. Run the migrations first; role wiring is a separate admin action and "
            "deliberately not part of them."
        )
    rows = connection.execute(
        text(f"SELECT version_num FROM {SCHEMA}.{VERSION_TABLE} ORDER BY version_num")
    ).scalars().all()
    if len(rows) != 1:
        raise UnsupportedSchemaRevision(
            f"{SCHEMA}.{VERSION_TABLE} holds {len(rows)} rows; role wiring requires exactly one "
            "revision. A branched or partially stamped history has no single grant set, and "
            "picking one would leave a database that looks provisioned and is not."
        )
    revision = rows[0]
    if revision not in REVISION_PLANS:
        raise UnsupportedSchemaRevision(
            f"schema revision {revision!r} has no role-wiring plan. Supported: "
            f"{list(SUPPORTED_REVISIONS)}. Upgrade to head, or add the plan -- do not let the "
            "grants fail object by object."
        )
    return revision


def revision_plan(connection: Connection) -> RevisionPlan:
    """The plan for this database's revision, after checking every object in it exists.

    The existence check is the other half of refusing to guess. At head this is what turns
    "a Milestone 2.3 object is unexpectedly missing" into an error naming it, rather than
    into an ``UndefinedTable`` from whichever statement happened to reach it first.
    """
    plan = REVISION_PLANS[schema_revision(connection)]
    missing = []
    for table in plan.tables:
        if not connection.execute(
            text("SELECT pg_catalog.to_regclass(:name) IS NOT NULL"),
            {"name": f"{SCHEMA}.{table}"},
        ).scalar_one():
            missing.append(f"table {table}")
    functions = (
        plan.common_functions
        + plan.provisioning_functions
        + plan.application_functions
        + plan.authenticator_functions
        + plan.authenticator_common_functions
        + plan.lifecycle_writer_functions
        + plan.lifecycle_writer_helper_functions
        + plan.internal_functions
    )
    for name, signature in functions:
        if not connection.execute(
            text("SELECT pg_catalog.to_regprocedure(:name) IS NOT NULL"),
            {"name": _function(name, signature)},
        ).scalar_one():
            missing.append(f"function {name}({signature})")
    if missing:
        raise UnsupportedSchemaRevision(
            f"the database reports schema revision {plan.revision!r} but {sorted(missing)} "
            "do not exist. The schema and its stamped revision disagree; wiring roles against it "
            "would produce a database that reports success and denies access at runtime."
        )
    return plan


def _function(name: str, signature: str) -> str:
    return f"{SCHEMA}.{name}({signature})"


def quote_identifier(name: str) -> str:
    """Validate then quote a SQL identifier.

    Role names reach this module from the environment, and ``GRANT`` takes no bind
    parameters. Validating against a strict pattern before quoting is what keeps that
    from being an injection point.
    """
    if not _IDENTIFIER.match(name or ""):
        raise ValueError(f"{name!r} is not an acceptable SQL identifier for a role or table")
    return f'"{name}"'


#: The one statement that makes the schema's access control a *stated* fact rather than an
#: inherited one, duplicated verbatim in migration ``0003``.
#:
#: ``REVOKE ... FROM PUBLIC`` removes what PostgreSQL hands out by default. It does not
#: remove what an operator arranged with
#:
#:     ALTER DEFAULT PRIVILEGES FOR ROLE <owner> IN SCHEMA firmbatch
#:         GRANT SELECT ON TABLES TO <some role>;
#:
#: which is applied by the *creator* at the instant each object is created -- so the grant
#: is already on ``auth_bindings`` before the next statement of the migration runs, and no
#: amount of revoking from PUBLIC touches it. The grantees are therefore enumerated from
#: the catalogue and every one of them is revoked, leaving the owner's inherent rights and
#: nothing else. The explicit grants below then put back exactly the allowlist, and only
#: that.
#:
#: **Column ACLs need their own pass, and the reason is the enumeration rather than the
#: verb.** PostgreSQL keeps column grants in ``pg_attribute.attacl``, and a role holding
#: only column privileges never appears in ``pg_class.relacl`` -- measured: after
#: ``GRANT SELECT (a) ON t TO r`` the relation ACL is still NULL. The relation loop above
#: takes its grantee list from ``relacl``, so such a role was never named and the
#: ``REVOKE`` that would have removed the grant was never issued. Measured against a real
#: server: ``GRANT SELECT (backend_pid), UPDATE (tenant_id) ON
#: firmbatch.auth_transaction_context`` survived this block intact -- a complete bypass of
#: the isolation boundary, because the grantee can then rewrite its own authenticated
#: tenant. ``db/principal.py`` condition 8 refuses such a connection; these two loops are
#: what stop one being left behind in the first place.
#:
#: The PUBLIC pass is deliberately kept even though the unconditional
#: ``REVOKE ALL ON <table> FROM PUBLIC`` above already clears a column grant to PUBLIC.
#: The column boundary is then self-contained: narrowing that other loop cannot silently
#: reopen this one.
#:
#: Run in **both** places on purpose. The migration leaves a clean database even if nobody
#: ever calls this module; this module leaves a clean database even if a later migration
#: inherits a default privilege that ``0003`` could not have known about. Neither is
#: sufficient alone: default-privilege rules outlive a migration, and a database can be
#: migrated without being wired.
#:
#: **The two function loops touch only functions the schema owner owns.** PostgreSQL lets
#: an object's owner, or a holder of a grant option, ``REVOKE`` on it, and nobody else: the
#: schema owner running ``REVOKE ALL ON FUNCTION ... FROM PUBLIC`` against a function the
#: lifecycle writer owns gets ``permission denied`` -- measured. At wiring time the two
#: writer-owned entry points are skipped here and sanitised by
#: :func:`install_lifecycle_writer` under ``SET ROLE`` to their owner, which is the one
#: identity that may. Relations and types carry no such predicate: nothing but the owner is
#: ever meant to own one, and a foreign-owned relation failing loudly here is the right
#: outcome.
#:
#: **Where the copies live now.** Migration ``0003`` carries the original text, without the
#: ownership predicate, and is history: it is not edited to suit objects ``0004`` introduced.
#: Migration ``0004`` installs this body as ``firmbatch.sanitize_schema_privileges()`` --
#: the ownership-aware sanitiser a database needs while writer-owned functions exist -- calls
#: it, and drops it again on downgrade after the writer's functions and grants are gone, so a
#: ``0003`` database has exactly what ``0003`` installed. This module carries the same body for
#: the runtime, and ``test_the_sanitiser_is_the_same_statement_everywhere`` asserts that the
#: two live copies are identical and that ``0003``'s differs from them by the predicate alone.
#:
#: Every identifier comes from ``pg_catalog`` and is rendered by ``format('%I')`` or by a
#: ``regclass``/``regprocedure``/``regtype`` cast, all of which quote. No name here comes
#: from a caller, and no environment's role names are written down.
#: The plpgsql body: what migration ``0004`` installs as ``firmbatch.sanitize_schema_privileges()``
#: and what :func:`sanitize_schema_privileges` runs as a ``DO`` block. One text, two carriers,
#: and a test that compares them.
SCHEMA_ACL_SANITIZER_BODY = """
DECLARE
    entry record;
BEGIN
    EXECUTE 'REVOKE ALL ON SCHEMA firmbatch FROM PUBLIC';
    FOR entry IN
        SELECT pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_namespace n
        CROSS JOIN LATERAL pg_catalog.aclexplode(n.nspacl) acl
        WHERE n.nspname = 'firmbatch'
          AND acl.grantee <> 0
          AND acl.grantee <> n.nspowner
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON SCHEMA firmbatch FROM %I', entry.grantee);
    END LOOP;

    FOR entry IN
        SELECT c.oid::pg_catalog.regclass AS obj,
               CASE WHEN c.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END AS kind,
               c.relowner
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'firmbatch' AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
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
        WHERE n.nspname = 'firmbatch'
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
        WHERE n.nspname = 'firmbatch'
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
        WHERE n.nspname = 'firmbatch'
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
        WHERE n.nspname = 'firmbatch'
          AND p.proowner = n.nspowner
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', entry.obj);
    END LOOP;

    FOR entry IN
        SELECT p.oid::pg_catalog.regprocedure AS obj,
               pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl
        WHERE n.nspname = 'firmbatch'
          AND p.proowner = n.nspowner
          AND acl.grantee <> 0
          AND acl.grantee <> p.proowner
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM %I', entry.obj, entry.grantee);
    END LOOP;

    FOR entry IN
        SELECT t.oid::pg_catalog.regtype AS obj
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = 'firmbatch' AND t.typtype IN ('c', 'd', 'e', 'r')
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON TYPE %s FROM PUBLIC', entry.obj);
    END LOOP;

    FOR entry IN
        SELECT t.oid::pg_catalog.regtype AS obj,
               pg_catalog.pg_get_userbyid(acl.grantee) AS grantee
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(t.typacl) acl
        WHERE n.nspname = 'firmbatch'
          AND t.typtype IN ('c', 'd', 'e', 'r')
          AND acl.grantee <> 0
          AND acl.grantee <> t.typowner
    LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON TYPE %s FROM %I', entry.obj, entry.grantee);
    END LOOP;
END;
"""

#: The runtime form: the body wrapped as an anonymous block, so it runs at every supported
#: revision without depending on an object only ``0004`` creates.
SCHEMA_ACL_SANITIZER_SQL = f"DO $sanitize$\n{SCHEMA_ACL_SANITIZER_BODY}\n$sanitize$\n"


def sanitize_schema_privileges(connection: Connection) -> None:
    """Strip every privilege on every object in the schema except the owner's own.

    Called before the grants, so what a role holds afterwards is exactly what
    :func:`grant_application_role` and :func:`grant_provisioning_role` gave it.
    """
    connection.execute(text(SCHEMA_ACL_SANITIZER_SQL))


def harden_database(connection: Connection, database: str) -> None:
    """Remove the implicit rights every role gets just by being able to connect.

    ``TEMP`` is the one that matters most. PostgreSQL grants it to PUBLIC by default, and
    a role holding it can ``CREATE TEMP TABLE workspaces (...)``; because the temporary
    schema is searched before ``search_path``, every later unqualified reference on that
    connection resolves to the forgery -- for the life of a pooled connection, and with
    row-level security attached to a table the query no longer reaches.

    ``CREATE`` on ``public`` is revoked for the same family of reasons. PostgreSQL 15+
    already does it; doing it explicitly means the guarantee does not depend on which
    server version an environment happens to run.
    """
    # Refuse an unsupported revision here, at the first of the four wiring calls, so that
    # a database this module cannot wire is reported before anything has been changed.
    schema_revision(connection)
    connection.execute(text(f"REVOKE TEMPORARY ON DATABASE {quote_identifier(database)} FROM PUBLIC"))
    connection.execute(text("REVOKE CREATE ON SCHEMA public FROM PUBLIC"))
    # Everything inside the pinned schema, from everybody but its owner -- not only from
    # PUBLIC, and not only the objects this module happens to name. See
    # SCHEMA_ACL_SANITIZER_SQL for why revoking from PUBLIC is not enough.
    sanitize_schema_privileges(connection)


def revoke_public_table_privileges(connection: Connection) -> None:
    """Belt and braces: no tenant-owned table is reachable by PUBLIC.

    Both categories, for different reasons. A tenant-scoped table is policed and must not
    additionally be reachable by a role nobody granted it to; a protected table has no
    grants at all and this is what keeps it that way.

    Walks the revision's own table list. At ``0002`` the protected tables do not exist yet,
    and naming them anyway is what made role provisioning fail after a rollback.
    """
    for table in revision_plan(connection).tables:
        connection.execute(
            text(f"REVOKE ALL ON TABLE {quote_identifier(SCHEMA)}.{quote_identifier(table)} FROM PUBLIC")
        )


def _grant_common(connection: Connection, quoted: str, plan: RevisionPlan) -> None:
    connection.execute(text(f"GRANT USAGE ON SCHEMA {quote_identifier(SCHEMA)} TO {quoted}"))
    # Required to evaluate the isolation policies at all, and to acquire a context in the
    # first place; granted explicitly because harden_database took it away from PUBLIC.
    #
    # **Not** granted here: auth_context_begin, which writes the context. A role that
    # could call it could forge any tenant and any scope set, so it is executable by
    # nobody and every path to it goes through a SECURITY DEFINER function that decided
    # what the context may be. See INTERNAL_AUTH_FUNCTIONS.
    for name, signature in plan.common_functions:
        connection.execute(text(f"GRANT EXECUTE ON FUNCTION {_function(name, signature)} TO {quoted}"))
    # No GRANT TEMPORARY, and no GRANT CREATE. A runtime role creates nothing.
    #
    # TEMPORARY still matters for the reason ADR 0004 gives -- a temporary relation can
    # shadow a Firmbatch table for an unqualified reference. It is no longer load-bearing
    # for the authentication context: that lived in pg_temp in the first version of
    # Milestone 2.3, until ``DISCARD TEMP`` turned out to drop it. It is an ordinary
    # protected table now, and no privilege of the runtime's reaches it at all.


def _grant_tables(connection: Connection, quoted: str, grants) -> None:
    schema = quote_identifier(SCHEMA)
    for table, privileges in grants:
        connection.execute(
            text(f"GRANT {privileges} ON TABLE {schema}.{quote_identifier(table)} TO {quoted}")
        )


def _grant_columns(connection: Connection, quoted: str, grants) -> None:
    """Grant a privilege on named columns, so the ones not named stay unwritable.

    A table-level ``GRANT INSERT`` would supersede this, so the plans that use it grant
    ``SELECT`` at table level and nothing more. Every column name is validated and quoted
    the same way a role name is: ``GRANT`` takes no bind parameters.
    """
    schema = quote_identifier(SCHEMA)
    for table, privileges, columns in grants:
        column_list = ", ".join(quote_identifier(column) for column in columns)
        connection.execute(
            text(
                f"GRANT {privileges} ({column_list}) "
                f"ON TABLE {schema}.{quote_identifier(table)} TO {quoted}"
            )
        )


def grant_application_role(connection: Connection, role: str) -> None:
    """Give ``role`` exactly what a tenant-scoped application needs, and nothing more.

    The set is :data:`RevisionPlan.application_grants` for the revision the database is
    actually at, so a rollback to ``0002`` restores exactly the Milestone 2.2 grants and a
    re-upgrade restores exactly the Milestone 2.3 ones.
    """
    quoted = quote_identifier(role)
    plan = revision_plan(connection)
    _grant_common(connection, quoted, plan)
    # The application-only functions, which provisioning does not receive. Milestone 2.4's
    # lifecycle kernel is the first thing in this schema that one runtime role may reach
    # and the other may not, and that asymmetry is the point rather than an oversight.
    for name, signature in plan.application_functions:
        connection.execute(text(f"GRANT EXECUTE ON FUNCTION {_function(name, signature)} TO {quoted}"))
    _grant_tables(connection, quoted, plan.application_grants)
    # And the column-level half, after the table-level one so nothing supersedes it. At
    # ``0004`` this is what withholds ``INSERT`` on the identifier columns of the two
    # framework tables: a chosen primary key is refused at permission-check time, before any
    # unique index could answer whether that key exists.
    _grant_columns(connection, quoted, plan.application_column_grants)
    # No privilege on alembic_version: the schema history is not application data.
    #
    # And **nothing at all** on auth_bindings or auth_transaction_context. The credential
    # registry is not application data either, and the application never reads a
    # fingerprint: it presents a credential to firmbatch.bind_authenticated_context() and
    # is told what context it got. The transaction context is the mechanism itself -- a
    # role that could write it would name its own tenant, and one that could delete from it
    # would bind again as somebody else inside one transaction. See PROTECTED_TABLES.


def grant_authenticator_role(connection: Connection, role: str) -> None:
    """Give ``role`` the trusted-issuer boundary, and the least privilege that reaches it.

    The grant is, exactly and exhaustively: ``USAGE`` on the schema, ``EXECUTE`` on
    :data:`AUTHENTICATOR_READ_FUNCTIONS` (``auth_tenant_id``, which
    ``db/engine.transaction()`` calls to assert a transaction inherited no context, and
    ``auth_context``, which that invoker-rights accessor calls as the caller), and
    ``EXECUTE`` on the revision's authenticator tuple: :data:`IDENTITY_AUTHENTICATOR_FUNCTIONS`,
    the eight pre-authentication identity entry points -- signup and the two mailbox-proof
    paths (email verification and account recovery), plus login and session opening -- and,
    from ``0006``, :data:`IDENTITY_PASSWORD_CHANGE_FUNCTIONS`, the two signed-in
    password-change functions. Ten functions at ``0005``, twelve at ``0006``. **No table privilege
    of any kind**, and no column privilege: every relation behind those functions is
    protected, and the entry points are hardened ``SECURITY DEFINER`` functions owned by the
    schema owner, so the helpers they call internally execute as the owner and need no grant
    here.

    It deliberately does **not** receive the common runtime set the application and
    provisioning roles hold. That tuple carries ``bind_authenticated_context``,
    ``register_auth_binding``, ``revoke_auth_binding`` and ``append_audit_event``, and no
    authenticator call path reaches any of them; granting them would let the trusted-issuer
    principal establish a bearer context and reach the untied credential minter, which is
    the opposite of what this role exists to be. It receives none of the application,
    provisioning or lifecycle functions either, and it is a member of no role, so nothing is
    reachable through ``SET ROLE``. ``tests/test_identity_protection.py`` asserts the whole
    of that from the catalogue, function by function, rather than trusting this paragraph.

    What the boundary buys: the **application** role holds none of the eight
    pre-authentication functions, so raw SQL as the runtime that serves ordinary requests
    can neither harvest a stored password hash, mint a browser session for a victim account,
    obtain and consume a recovery secret, nor issue and consume a mailbox-verification token
    for an address it does not control. That is the property the passwordless-session, the
    recovery-without-mailbox and the mailbox-verification-authority findings require, and it
    is a fact about grants rather than about what any Python caller remembers to check.
    """
    quoted = quote_identifier(role)
    plan = revision_plan(connection)
    # USAGE only -- harden_database took it from PUBLIC. Deliberately not _grant_common:
    # the authenticator gets the named minimal read set below, not the common runtime tuple.
    connection.execute(text(f"GRANT USAGE ON SCHEMA {quote_identifier(SCHEMA)} TO {quoted}"))
    for name, signature in plan.authenticator_common_functions:
        connection.execute(text(f"GRANT EXECUTE ON FUNCTION {_function(name, signature)} TO {quoted}"))
    # And the trusted-issuer functions, which no other runtime role holds.
    for name, signature in plan.authenticator_functions:
        connection.execute(text(f"GRANT EXECUTE ON FUNCTION {_function(name, signature)} TO {quoted}"))
    # Nothing else: no table grant, no column grant, and no application, provisioning,
    # lifecycle or common runtime function. At a revision that declares neither authenticator
    # tuple (every revision before 0005) this grants schema USAGE alone.


def grant_provisioning_role(connection: Connection, role: str) -> None:
    """Give ``role`` tenant provisioning, and no access to tenant data."""
    quoted = quote_identifier(role)
    plan = revision_plan(connection)
    _grant_common(connection, quoted, plan)
    for name, signature in plan.provisioning_functions:
        connection.execute(text(f"GRANT EXECUTE ON FUNCTION {_function(name, signature)} TO {quoted}"))
    _grant_tables(connection, quoted, plan.provisioning_grants)
    # Intentionally no grant on workspaces, on idempotency_records, on outbox_events, on
    # audit_events, or on auth_bindings. Provisioning creates the scope; it does not get to
    # look inside it, it has no business reading another role's idempotency keys or the
    # events they produced, and it may not enumerate credential fingerprints or their
    # tenant mappings. It records what it did through firmbatch.append_audit_event(), the
    # same hardened path the application uses, and it cannot read the trail back.


# --------------------------------------------------------------- the lifecycle writer
#
# The fourth role, and the one that turns "written by the lifecycle boundary" from a
# convention about the schema owner into a fact about the executing identity. It owns the
# two ``SECURITY DEFINER`` entry points and nothing else; the guards on the lifecycle tags,
# on ``lifecycle_claim_provenance`` and on the outbox link require ``current_user`` to be it.
#
# Installing it is a **two-party** act, and the split is deliberate. PostgreSQL hands a
# function to a new owner only if the current owner can ``SET ROLE`` to that owner and the
# new owner holds ``CREATE`` on the schema (measured, both ways round). The schema owner
# is ``NOCREATEROLE`` and holds no membership, so it cannot give itself either; the trusted
# bootstrap administrator grants the membership ``WITH SET TRUE, INHERIT FALSE, ADMIN FALSE``
# immediately before this runs and revokes it immediately after, exactly as it already does
# for the per-run owner. What this function needs, then, is an owner connection that can
# ``SET ROLE`` to the writer *for the duration of one call* -- and nothing afterwards.


class LifecycleWriterError(RuntimeError):
    """The lifecycle writer is not the role the boundary requires, or could not be installed.

    Raised rather than worked around, for the same reason :class:`UnsupportedSchemaRevision`
    is: a writer that holds one attribute too many, or that a runtime role can reach, is a
    writer whose identity proves nothing, and a database wired around one would report
    success while the guards it depends on were decorative.
    """


#: The attributes the writer must carry, as ``pg_roles`` reports them, and the values it
#: must report. Six of them are what ``firmbatch.lifecycle_writer_role()`` itself checks
#: before it will name a role; ``rolinherit`` is added here for hygiene, because a role that
#: is never meant to be a member of anything has nothing to inherit.
LIFECYCLE_WRITER_ATTRIBUTES: tuple[tuple[str, bool], ...] = (
    ("rolcanlogin", False),
    ("rolsuper", False),
    ("rolcreaterole", False),
    ("rolcreatedb", False),
    ("rolreplication", False),
    ("rolbypassrls", False),
    ("rolinherit", False),
)


@dataclass(frozen=True)
class LifecycleWriterInventory:
    """Everything the catalogue says about the writer, read back after installation.

    The report a test compares and an operator reads. Every field comes from ``pg_catalog``
    or ``information_schema`` on the connection that asked, so it describes what the
    database enforces rather than what this module intended.
    """

    role: str
    #: ``pg_roles`` attributes, by column name.
    attributes: "dict[str, bool]"
    #: Every object in the schema the writer owns, as ``"kind name"``. At ``0004`` exactly
    #: the two entry points; at every earlier revision nothing.
    owned_objects: tuple[str, ...]
    #: Privileges held directly on the schema.
    schema_privileges: frozenset[str]
    #: ``table -> privileges`` held at table level.
    table_privileges: "dict[str, frozenset[str]]"
    #: ``(table, column) -> privileges`` held at column level, from ``pg_attribute.attacl``.
    column_privileges: "dict[tuple[str, str], frozenset[str]]"
    #: Every function in the schema the writer may execute, as
    #: ``schema.name(identity arguments)``, owned ones included.
    executable_functions: frozenset[str]
    #: Every ``pg_auth_members`` row naming the writer, as
    #: ``(grantor, member, admin_option, inherit_option, set_option)``.
    memberships: tuple[tuple[str, str, bool, bool, bool], ...]
    #: Whether ``firmbatch.lifecycle_writer_role()`` answers with this role -- the one fact
    #: every guard depends on.
    recognised: bool


def _role_attributes(connection: Connection, role: str) -> "dict[str, bool] | None":
    columns = ", ".join(name for name, _expected in LIFECYCLE_WRITER_ATTRIBUTES)
    row = connection.execute(
        text(f"SELECT {columns} FROM pg_catalog.pg_roles WHERE rolname = :role"),
        {"role": role},
    ).one_or_none()
    if row is None:
        return None
    return {name: bool(value) for (name, _expected), value in zip(LIFECYCLE_WRITER_ATTRIBUTES, row)}


def _schema_owner(connection: Connection) -> str:
    return connection.execute(
        text(
            "SELECT pg_catalog.pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_namespace n "
            "WHERE n.nspname = :schema"
        ),
        {"schema": SCHEMA},
    ).scalar_one()


def _owned_by(connection: Connection, role: str) -> tuple[str, ...]:
    """Every relation, function and type in the schema owned by ``role``."""
    rows = connection.execute(
        text(
            "WITH target AS (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = :role) "
            "SELECT 'relation:' || c.relkind::text AS kind, c.relname AS name "
            "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = :schema AND c.relowner IN (SELECT oid FROM target) "
            "UNION ALL "
            "SELECT 'function', n.nspname || '.' || p.proname || '(' "
            "       || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' "
            "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = :schema AND p.proowner IN (SELECT oid FROM target) "
            "UNION ALL "
            "SELECT 'type', t.typname "
            "FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace "
            "WHERE n.nspname = :schema AND t.typtype IN ('c', 'd', 'e', 'r') "
            "  AND t.typowner IN (SELECT oid FROM target) "
            "UNION ALL "
            "SELECT 'schema', n.nspname FROM pg_catalog.pg_namespace n "
            "WHERE n.nspname = :schema AND n.nspowner IN (SELECT oid FROM target) "
            "ORDER BY 1, 2"
        ),
        {"role": role, "schema": SCHEMA},
    ).all()
    return tuple(f"{kind} {name}" for kind, name in rows)


def _function_owner(connection: Connection, name: str, signature: str) -> "str | None":
    return connection.execute(
        text(
            "SELECT pg_catalog.pg_get_userbyid(p.proowner) FROM pg_catalog.pg_proc p "
            "WHERE p.oid = pg_catalog.to_regprocedure(:function)"
        ),
        {"function": _function(name, signature)},
    ).scalar_one_or_none()


def _function_grantees(connection: Connection, name: str, signature: str) -> "list[str]":
    """Every non-owner grantee in one function's ACL; ``PUBLIC`` is rendered as such."""
    rows = connection.execute(
        text(
            "SELECT CASE WHEN acl.grantee = 0 THEN 'PUBLIC' "
            "            ELSE pg_catalog.pg_get_userbyid(acl.grantee) END "
            "FROM pg_catalog.pg_proc p "
            "CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl "
            "WHERE p.oid = pg_catalog.to_regprocedure(:function) AND acl.grantee <> p.proowner"
        ),
        {"function": _function(name, signature)},
    ).scalars()
    return sorted(set(rows))


def _revoke_everything_from(connection: Connection, role: str) -> None:
    """Strip every grant ``role`` holds on an object the schema owner owns.

    The sanitiser does this for every non-owner grantee; this does it for one role,
    standalone, so that installing the writer never depends on the sanitiser having run
    first and a stale grant from an earlier wiring cannot survive into the new one.
    Enumerated from the catalogue -- the schema, relations and their columns, functions,
    types -- and restricted to objects the schema owner owns, because those are the ones
    the schema owner may revoke on.
    """
    quoted = quote_identifier(role)
    parameters = {"role": role, "schema": SCHEMA}
    if connection.execute(
        text(
            "SELECT count(*) FROM pg_catalog.pg_namespace n "
            "CROSS JOIN LATERAL pg_catalog.aclexplode(n.nspacl) acl "
            "WHERE n.nspname = :schema "
            "  AND acl.grantee = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :role)"
        ),
        parameters,
    ).scalar_one():
        connection.execute(text(f"REVOKE ALL ON SCHEMA {quote_identifier(SCHEMA)} FROM {quoted}"))
    for kind, obj in connection.execute(
        text(
            "SELECT DISTINCT CASE WHEN c.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END, "
            "       c.oid::pg_catalog.regclass::text "
            "FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "LEFT JOIN pg_catalog.pg_attribute a "
            "  ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped "
            "CROSS JOIN LATERAL pg_catalog.aclexplode("
            "  COALESCE(c.relacl, '{}'::aclitem[]) || COALESCE(a.attacl, '{}'::aclitem[])) acl "
            "WHERE n.nspname = :schema AND c.relowner = n.nspowner "
            "  AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') "
            "  AND acl.grantee = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :role) "
            "ORDER BY 2"
        ),
        parameters,
    ).all():
        connection.execute(text(f"REVOKE ALL ON {kind} {obj} FROM {quoted}"))
    for (obj,) in connection.execute(
        text(
            "SELECT p.oid::pg_catalog.regprocedure::text "
            "FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
            "CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl "
            "WHERE n.nspname = :schema AND p.proowner = n.nspowner "
            "  AND acl.grantee = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :role) "
            "ORDER BY 1"
        ),
        parameters,
    ).all():
        connection.execute(text(f"REVOKE ALL ON FUNCTION {obj} FROM {quoted}"))
    for (obj,) in connection.execute(
        text(
            "SELECT t.oid::pg_catalog.regtype::text "
            "FROM pg_catalog.pg_type t "
            "JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace "
            "CROSS JOIN LATERAL pg_catalog.aclexplode(t.typacl) acl "
            "WHERE n.nspname = :schema AND t.typtype IN ('c', 'd', 'e', 'r') "
            "  AND t.typowner = n.nspowner "
            "  AND acl.grantee = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :role) "
            "ORDER BY 1"
        ),
        parameters,
    ).all():
        connection.execute(text(f"REVOKE ALL ON TYPE {obj} FROM {quoted}"))


def lifecycle_writer_inventory(connection: Connection, role: str) -> LifecycleWriterInventory:
    """What the catalogue says the writer is, owns, holds and can be reached through."""
    attributes = _role_attributes(connection, role)
    if attributes is None:
        raise LifecycleWriterError(f"there is no role named {role!r} to inventory")
    parameters = {"role": role, "schema": SCHEMA}
    schema_privileges = frozenset(
        connection.execute(
            text(
                "SELECT acl.privilege_type FROM pg_catalog.pg_namespace n "
                "CROSS JOIN LATERAL pg_catalog.aclexplode(n.nspacl) acl "
                "WHERE n.nspname = :schema "
                "  AND acl.grantee = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :role)"
            ),
            parameters,
        ).scalars()
    )
    table_privileges: "dict[str, set[str]]" = {}
    for table, privilege in connection.execute(
        text(
            "SELECT c.relname, acl.privilege_type FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) acl "
            "WHERE n.nspname = :schema AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') "
            "  AND acl.grantee = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :role)"
        ),
        parameters,
    ).all():
        table_privileges.setdefault(table, set()).add(privilege)
    column_privileges: "dict[tuple[str, str], set[str]]" = {}
    for table, column, privilege in connection.execute(
        text(
            "SELECT c.relname, a.attname, acl.privilege_type FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid "
            "CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl "
            "WHERE n.nspname = :schema AND a.attnum > 0 AND NOT a.attisdropped "
            "  AND acl.grantee = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :role)"
        ),
        parameters,
    ).all():
        column_privileges.setdefault((table, column), set()).add(privilege)
    # Rendered from the catalogue rather than through ``regprocedure::text``, which omits
    # the schema whenever the schema is on the connection's search_path -- and a migration
    # changes that path, so two inventories of one database would otherwise compare unequal.
    executable = frozenset(
        connection.execute(
            text(
                "SELECT n.nspname || '.' || p.proname || '(' "
                "       || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' "
                "FROM pg_catalog.pg_proc p "
                "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = :schema "
                "  AND pg_catalog.has_function_privilege(:role, p.oid, 'EXECUTE')"
            ),
            parameters,
        ).scalars()
    )
    memberships = tuple(
        (grantor, member, bool(admin), bool(inherit), bool(set_option))
        for grantor, member, admin, inherit, set_option in connection.execute(
            text(
                "SELECT pg_catalog.pg_get_userbyid(m.grantor), pg_catalog.pg_get_userbyid(m.member), "
                "       m.admin_option, m.inherit_option, m.set_option "
                "FROM pg_catalog.pg_auth_members m "
                "JOIN pg_catalog.pg_roles r ON r.oid = m.roleid "
                "WHERE r.rolname = :role ORDER BY 1, 2"
            ),
            {"role": role},
        ).all()
    )
    # Only a 0004 database has the identity function; at an earlier revision the writer is
    # recognised by nothing, which is the correct answer rather than an error.
    recognised = False
    if connection.execute(
        text("SELECT pg_catalog.to_regprocedure(:name) IS NOT NULL"),
        {"name": _function("lifecycle_writer_role", "")},
    ).scalar_one():
        recognised = connection.execute(
            text(
                f"SELECT {SCHEMA}.lifecycle_writer_role() IS NOT DISTINCT FROM CAST(:role AS name)"
            ),
            {"role": role},
        ).scalar_one()
    return LifecycleWriterInventory(
        role=role,
        attributes=attributes,
        owned_objects=_owned_by(connection, role),
        schema_privileges=schema_privileges,
        table_privileges={table: frozenset(privileges) for table, privileges in table_privileges.items()},
        column_privileges={
            key: frozenset(privileges) for key, privileges in column_privileges.items()
        },
        executable_functions=executable,
        memberships=memberships,
        recognised=bool(recognised),
    )


def install_lifecycle_writer(
    connection: Connection, writer_role: str, application_role: str
) -> LifecycleWriterInventory:
    """Reconcile the lifecycle writer to this revision's plan, on the owner connection.

    At ``0004``: hand the two entry points to the writer, give the writer exactly the
    privileges their bodies need, write the entry points' ``EXECUTE`` grant to the
    application role as the writer, and prove that ``firmbatch.lifecycle_writer_role()``
    now answers with it. At every earlier revision: strip everything and prove it owns
    nothing. Idempotent, so re-wiring a database that was already wired reaches the same
    state rather than failing on the ownership it already has.

    **Requires, for the duration of this call, that the connected schema owner can
    ``SET ROLE`` to the writer.** The ownership hand-over needs it (PostgreSQL will not
    give a function to a role its current owner cannot become), and so does resetting the
    entry points' ACL afterwards, which only their owner may do. The trusted bootstrap
    administrator grants that membership ``WITH SET TRUE, INHERIT FALSE, ADMIN FALSE``
    immediately before and revokes it immediately after -- see
    ``testing/bootstrap.temporary_set_membership`` -- and nothing here leaves a membership
    behind: ``RESET ROLE`` runs in a ``finally``.

    Refuses, with :class:`LifecycleWriterError`, a writer that can log in, that holds any
    privileged attribute, that is the schema owner or the application role, that any role
    other than the connected owner can ``SET ROLE`` to or inherit from, or that owns anything
    in the schema other than the two entry points.
    """
    quoted = quote_identifier(writer_role)
    application = quote_identifier(application_role)
    plan = revision_plan(connection)
    owner = _schema_owner(connection)
    current = connection.execute(text("SELECT current_user")).scalar_one()

    attributes = _role_attributes(connection, writer_role)
    if attributes is None:
        raise LifecycleWriterError(
            f"the lifecycle writer role {writer_role!r} does not exist. It is created by the "
            "bootstrap administrator alongside the per-run roles; role wiring never creates one."
        )
    wrong = [
        f"{name}={attributes[name]}"
        for name, expected in LIFECYCLE_WRITER_ATTRIBUTES
        if attributes[name] != expected
    ]
    if wrong:
        raise LifecycleWriterError(
            f"the lifecycle writer role {writer_role!r} carries {wrong}. It must be NOLOGIN, "
            "NOSUPERUSER, NOCREATEROLE, NOCREATEDB, NOREPLICATION, NOBYPASSRLS and NOINHERIT: an "
            "identity that can log in or reach anything on its own proves nothing about who "
            "wrote a row."
        )
    if writer_role in (owner, application_role, current):
        raise LifecycleWriterError(
            f"the lifecycle writer role {writer_role!r} must be distinct from the schema owner, "
            "the application role and the connected role; the whole point is that none of them "
            "is it."
        )
    reachable = [
        (member, grantor)
        for grantor, member, _admin, inherit, set_option in lifecycle_writer_inventory(
            connection, writer_role
        ).memberships
        if member != current and (inherit or set_option)
    ]
    if reachable:
        raise LifecycleWriterError(
            f"the lifecycle writer role {writer_role!r} can be reached by {sorted(reachable)} "
            "through a membership carrying SET or INHERIT. Only the connected owner may hold "
            "such a membership, and only for the duration of this call."
        )

    # --- what the writer held before is gone; what it holds after is exactly the plan -------
    _revoke_everything_from(connection, writer_role)

    if not plan.lifecycle_writer_functions:
        owned = _owned_by(connection, writer_role)
        if owned:
            raise LifecycleWriterError(
                f"schema revision {plan.revision!r} has no lifecycle writer, yet {writer_role!r} "
                f"owns {sorted(owned)}. The downgrade to this revision drops the entry points; "
                "an object it still owns was not created by this repository's migrations."
            )
        return lifecycle_writer_inventory(connection, writer_role)

    # --- the hand-over ---------------------------------------------------------------------
    pending = []
    for name, signature in plan.lifecycle_writer_functions:
        holder = _function_owner(connection, name, signature)
        if holder == writer_role:
            continue
        if holder != owner:
            raise LifecycleWriterError(
                f"{_function(name, signature)} is owned by {holder!r}, which is neither the schema "
                f"owner nor the lifecycle writer {writer_role!r}. The schema owner cannot hand over "
                "a function it does not own; this is not a state the migrations produce."
            )
        pending.append((name, signature))
    if pending:
        # PostgreSQL's two conditions for ALTER ... OWNER TO: the new owner must hold CREATE
        # on the schema (granted for these statements and revoked straight after), and the
        # current owner must be able to SET ROLE to it (the temporary membership).
        connection.execute(
            text(f"GRANT CREATE ON SCHEMA {quote_identifier(SCHEMA)} TO {quoted}")
        )
        try:
            for name, signature in pending:
                try:
                    connection.execute(
                        text(f"ALTER FUNCTION {_function(name, signature)} OWNER TO {quoted}")
                    )
                except Exception as exc:
                    raise LifecycleWriterError(
                        f"could not hand {_function(name, signature)} to the lifecycle writer "
                        f"{writer_role!r}: {type(exc).__name__}: {str(exc).splitlines()[0]}. "
                        "The connected schema owner must be able to SET ROLE to the writer for "
                        "the duration of install_lifecycle_writer(); the bootstrap administrator "
                        "grants that membership WITH SET TRUE, INHERIT FALSE, ADMIN FALSE "
                        "immediately before and revokes it immediately after."
                    ) from None
        finally:
            connection.execute(
                text(f"REVOKE CREATE ON SCHEMA {quote_identifier(SCHEMA)} FROM {quoted}")
            )
    # Compared by object identity rather than by rendered name: how a regprocedure renders
    # depends on the connection's search_path, and what matters is which objects they are.
    expected_owned = {
        connection.execute(
            text("SELECT pg_catalog.to_regprocedure(:name)::pg_catalog.oid"),
            {"name": _function(name, signature)},
        ).scalar_one()
        for name, signature in plan.lifecycle_writer_functions
    }
    owned = set(
        connection.execute(
            text(
                "SELECT p.oid FROM pg_catalog.pg_proc p "
                "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
                "WHERE n.nspname = :schema "
                "  AND p.proowner = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = :role)"
            ),
            {"schema": SCHEMA, "role": writer_role},
        ).scalars()
    )
    other = [
        entry for entry in _owned_by(connection, writer_role) if not entry.startswith("function ")
    ]
    if owned != expected_owned or other:
        raise LifecycleWriterError(
            f"the lifecycle writer {writer_role!r} owns "
            f"{sorted(_owned_by(connection, writer_role))} but must own exactly the two entry "
            "points and nothing else: not a table, not a type, not the schema, not a third "
            "function."
        )

    # --- the minimum the bodies need ------------------------------------------------------
    connection.execute(text(f"GRANT USAGE ON SCHEMA {quote_identifier(SCHEMA)} TO {quoted}"))
    for name, signature in plan.lifecycle_writer_helper_functions:
        connection.execute(
            text(f"GRANT EXECUTE ON FUNCTION {_function(name, signature)} TO {quoted}")
        )
    _grant_tables(connection, quoted, plan.lifecycle_writer_grants)
    _grant_columns(connection, quoted, plan.lifecycle_writer_column_grants)

    # --- the entry points' own ACL, written by their owner ---------------------------------
    #
    # The schema owner may neither GRANT nor REVOKE on a function it does not own, so this
    # runs under SET ROLE to the writer: every grantee but the owner is removed, PUBLIC's
    # default is removed, and the application role -- and only it -- is granted EXECUTE.
    try:
        connection.execute(text(f"SET ROLE {quoted}"))
    except Exception as exc:
        raise LifecycleWriterError(
            f"the connected schema owner cannot SET ROLE to the lifecycle writer {writer_role!r} "
            f"({type(exc).__name__}: {str(exc).splitlines()[0]}), so it cannot reset the entry "
            "points' privileges. The bootstrap administrator grants that membership WITH SET "
            "TRUE, INHERIT FALSE, ADMIN FALSE for the duration of install_lifecycle_writer() "
            "and revokes it afterwards."
        ) from None
    try:
        for name, signature in plan.lifecycle_writer_functions:
            function = _function(name, signature)
            for grantee in _function_grantees(connection, name, signature):
                target = "PUBLIC" if grantee == "PUBLIC" else quote_identifier(grantee)
                connection.execute(text(f"REVOKE ALL ON FUNCTION {function} FROM {target}"))
            connection.execute(text(f"REVOKE ALL ON FUNCTION {function} FROM PUBLIC"))
            connection.execute(text(f"GRANT EXECUTE ON FUNCTION {function} TO {application}"))
    finally:
        connection.execute(text("RESET ROLE"))

    inventory = lifecycle_writer_inventory(connection, writer_role)
    if not inventory.recognised:
        raise LifecycleWriterError(
            f"after installation firmbatch.lifecycle_writer_role() does not answer "
            f"{writer_role!r}, so no lifecycle-derived write would be accepted. The function "
            "requires both entry points to be SECURITY DEFINER, owned by one non-owner role "
            "that cannot log in and holds no privileged attribute; one of those is not true."
        )
    return inventory
