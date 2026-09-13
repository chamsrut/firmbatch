"""The permission catalogue: deny by default, tenant-scoped, and closed.

Milestone 2.3. Every tenant-owned table in the v1 control plane is listed here with the
scope a caller must hold to read it and the scope it must hold to write it. Nothing is
permitted that is not named, in three independent places:

1. **PostgreSQL.** Migration ``0003`` writes one policy per command per table, and every
   predicate is ``tenant matches the authenticated context AND the context holds the
   scope``. A command with no policy reaches no row, for any role, because row security
   is ``FORCE``d -- so "no rule" means "no access" rather than "unconstrained access".
2. **The credential registry.** ``auth_bindings.scopes`` carries a check constraint that
   refuses any scope not in :data:`KNOWN_SCOPES`, so an unknown scope cannot be stored
   and later become meaningful when somebody adds a policy for it.
3. **This module.** :func:`require_scope` is what the Python primitives call so that a
   caller gets an explanatory refusal instead of an empty result set or a policy
   violation several frames later.

The database is the one that counts. The other two exist so that a missing scope is a
clear error rather than a silent nothing.

Extensibility, and its price
----------------------------

The catalogue is **closed**: adding a scope means editing :class:`Scope`, the check
constraint in a new migration, and the policy that consumes it. That is the honest cost of
deny-by-default -- a scope vocabulary that can be extended at runtime is a scope
vocabulary that cannot be audited. ``tests/test_authorization.py`` asserts that the
database constraint and this enumeration agree, so the three places cannot drift.

The customer boundary
---------------------

Customer authorization never reaches supplier, operator, provider-credential, routing,
settlement, certification, or internal-control capability (roadmap "Internal and supplier
surfaces"; target architecture invariant 11). That is enforced here by *absence*: no such
scope exists, so no credential can carry one, and there is no policy that would honour one
if it did. :data:`RESERVED_NON_CUSTOMER_DOMAINS` records the domains that must never
appear in this catalogue, and a test asserts that none of them has.

The operator capacity agent is separate software with its own identity, credential and
protocol (ADR 0003 decision 8). It is not a scope in this catalogue and must not become
one.

Scopes a lifecycle machine requires
-----------------------------------

Milestone 2.4 adds tables whose required scope is **not** a constant of the table: a
lifecycle machine version declares which capability its instances take, and the policies
read it from the protected definition through ``firmbatch.lifecycle_required_scope()``.
That looks like an exception to "the catalogue decides" and is not one. A definition may
name only a scope that already exists here (:data:`LIFECYCLE_ELIGIBLE_SCOPES`), enforced by
a check constraint; there is no ``lifecycle:*`` capability, and M2.4 adds no scope at all.
A machine reuses an existing customer scope, which keeps "who may move this job" the same
question as "who may write this job" rather than making it a second, parallel one.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# One direction only: shape recognition knows nothing about capabilities, and this module
# needs it so that a refusal never quotes the value it refused.
from .secrets import looks_like_secret


class AuthorizationError(RuntimeError):
    """Raised when an authenticated context does not hold a required scope.

    Distinct from an authentication failure: the caller is who they say they are and is
    not allowed to do this. Both fail closed; only the explanation differs.
    """


class Scope(str, Enum):
    """Every capability a customer credential may carry. There are no others.

    A ``str`` enum so that a scope can be passed straight to PostgreSQL as the ``text``
    it is stored as, without a conversion step that could disagree with itself.
    """

    #: Read the tenant's own record. Not "read tenants": the policy on ``tenants`` is
    #: ``id = the authenticated tenant``, so this scope grants exactly one row.
    TENANT_READ = "tenant:read"

    #: Create and amend a tenant record. Held by the provisioning path only, and even
    #: there it applies to a tenant id PostgreSQL generated inside the same transaction
    #: -- see ``firmbatch.begin_tenant_provisioning()``. It is not a scope any customer
    #: credential is issued.
    TENANT_PROVISION = "tenant:provision"

    #: Read workspaces belonging to the authenticated tenant.
    WORKSPACE_READ = "workspace:read"

    #: Create, amend and remove workspaces belonging to the authenticated tenant.
    WORKSPACE_WRITE = "workspace:write"

    #: Claim idempotency keys and append outbox events. The minimal capability the
    #: mutation framework needs; it grants nothing about any customer resource, and a
    #: credential holding only this can record that a mutation happened without being
    #: able to perform one.
    MUTATION_EXECUTE = "mutation:execute"

    #: Read this tenant's audit trail. Appending to it requires no scope -- see
    #: :data:`AUDIT_APPEND_REQUIRES_NO_SCOPE`.
    AUDIT_READ = "audit:read"

    #: Register and revoke authentication bindings **within the authenticated tenant**.
    #: The credential-lifecycle surface Milestone 3 builds on. It cannot reach another
    #: tenant: the database functions derive the tenant from the context rather than
    #: taking it as an argument.
    CREDENTIAL_MANAGE = "credential:manage"


#: Every scope, as the plain strings PostgreSQL stores, sorted so the check constraint
#: this generates is deterministic across environments and diffs.
KNOWN_SCOPES: tuple[str, ...] = tuple(sorted(scope.value for scope in Scope))

#: Upper bound on the scope set of one binding. Not a security property on its own -- the
#: closed catalogue is -- but a bound on a caller-supplied array is worth having where the
#: array is written by a function a customer credential can reach.
MAX_SCOPES_PER_BINDING = 16

#: Domains that belong to the supplier, operator and internal control surfaces. None of
#: them may ever appear in :class:`Scope`: those capabilities require a separate identity,
#: credential and interface, and a customer credential that could name one would be the
#: boundary failure the roadmap's product-surface separation exists to prevent.
RESERVED_NON_CUSTOMER_DOMAINS: frozenset[str] = frozenset(
    {
        "operator",
        "supplier",
        "provider",
        "routing",
        "settlement",
        "certification",
        "capacity",
        "ledger",
        "internal",
        "admin",
    }
)

#: Appending an audit event requires a valid authenticated context in the event's tenant
#: and **no scope beyond that**, deliberately.
#:
#: The alternative -- an ``audit:append`` scope -- means a credential can be issued that
#: acts without leaving a trail, which is the one outcome an audit trail exists to
#: prevent. Recording what you did in your own tenant is inherent in being authenticated;
#: *reading* the trail is a privilege, and that is what ``audit:read`` is.
#:
#: The cost is named rather than hidden: a credential with no scopes at all can still
#: append audit rows in its own tenant. Those rows are bounded metadata, they are scoped
#: to that tenant, and the alternative is worse.
AUDIT_APPEND_REQUIRES_NO_SCOPE = True


@dataclass(frozen=True)
class ResourceRule:
    """The authorization rule for one table, in the form the database enforces it."""

    #: The table name inside the ``firmbatch`` schema.
    table: str
    #: ``customer`` -- a resource the customer owns and asks about.
    #: ``framework`` -- machinery the platform writes on the customer's behalf.
    #: ``lifecycle`` -- a tenant-owned table whose required scope is a property of the
    #: *row*, read from protected machine-definition data rather than fixed here.
    #: ``protected`` -- state no runtime role may reach at all.
    kind: str
    #: The column the isolation predicate compares against the authenticated tenant.
    #: ``None`` for a protected table, which has no policy because it has no grants.
    tenant_column: str | None
    #: Scopes, any one of which permits ``SELECT``. Empty means "a valid context is
    #: enough"; ``None`` means the scope is not fixed here -- either because there is no
    #: read path at all (``protected``) or because it is read from the machine definition
    #: (``lifecycle``). :attr:`scope_source` is what distinguishes those two.
    read: tuple[Scope, ...] | None
    #: Scopes, any one of which permits a write. Empty means "a valid context is enough";
    #: ``None`` carries the same two meanings as :attr:`read`.
    write: tuple[Scope, ...] | None
    #: ``True`` when the table carries no ``UPDATE`` and no ``DELETE`` policy, so a
    #: committed row cannot be changed or removed by any role, the owner included.
    append_only: bool
    #: Why the rule is what it is. Read this before changing one.
    note: str
    #: Where the required scope comes from.
    #:
    #: ``catalogue`` -- the :attr:`read`/:attr:`write` tuples above, which is every rule
    #: this catalogue could state as a constant.
    #:
    #: ``definition`` -- protected per-machine-version data, read by
    #: ``firmbatch.lifecycle_required_scope()``. A lifecycle machine declares which
    #: capability its instances take, so the scope is a property of the row and not of
    #: the table; the *catalogue* still bounds it, because a definition may only name a
    #: scope in :data:`LIFECYCLE_ELIGIBLE_SCOPES`.
    #:
    #: ``none`` -- protected. There is no scope that reaches it, by construction.
    scope_source: str = "catalogue"


#: The catalogue. Every tenant-owned table in the schema appears exactly once, and
#: ``tests/test_authorization.py`` asserts that the set of tables here is the set of
#: tenant-owned tables the models declare -- so a table added without a rule fails the
#: suite rather than quietly inheriting somebody else's.
RESOURCE_RULES: tuple[ResourceRule, ...] = (
    ResourceRule(
        table="tenants",
        kind="customer",
        tenant_column="id",
        read=(Scope.TENANT_READ, Scope.TENANT_PROVISION),
        write=(Scope.TENANT_PROVISION,),
        append_only=False,
        note=(
            "A tenant row is visible to exactly the tenant it is: the predicate is on the primary "
            "key. The provisioning path is included in the read rule because PostgreSQL applies "
            "SELECT policies to INSERT ... RETURNING, which is how the ORM writes a row with "
            "server-side defaults. There is no DELETE policy: removing a tenant is not a runtime "
            "operation, and no runtime role holds DELETE on it either."
        ),
    ),
    ResourceRule(
        table="workspaces",
        kind="customer",
        tenant_column="tenant_id",
        read=(Scope.WORKSPACE_READ,),
        write=(Scope.WORKSPACE_WRITE,),
        append_only=False,
        note=(
            "The first customer resource, and the one that carries the read/write distinction. "
            "A read-only credential can list workspaces and cannot create, rename or remove one."
        ),
    ),
    ResourceRule(
        table="workspace_preferences",
        kind="customer",
        tenant_column="tenant_id",
        read=(Scope.WORKSPACE_READ,),
        write=(Scope.WORKSPACE_WRITE,),
        append_only=False,
        note=(
            "Milestone 3.2. What the customer says they intend for this workspace: region "
            "groups, excluded provider classes, a model and profile note, whether they mean to "
            "run the free evaluation, and the consent version in force. The same read/write "
            "pair workspaces carries, because a preference is a property of the workspace -- a "
            "viewer who may not rename a workspace may not restate its provider policy either. "
            "The write scope is exercised only through two SECURITY DEFINER functions, "
            "state_workspace_preferences and acknowledge_workspace_consent; the application "
            "role holds SELECT on the relation and no write privilege, so the INSERT and UPDATE "
            "policies bind the owner running those functions and nobody else. No DELETE policy: "
            "preferences are amended, and they leave with the workspace through the composite "
            "foreign key's cascade. Nothing here is a JobSpec, a quote or an admission input; "
            "see the model's docstring."
        ),
    ),
    ResourceRule(
        table="idempotency_records",
        kind="framework",
        tenant_column="tenant_id",
        read=(Scope.MUTATION_EXECUTE,),
        write=(Scope.MUTATION_EXECUTE,),
        append_only=True,
        note=(
            "Framework state, so it takes the minimal framework capability rather than any "
            "customer-resource scope: claiming a key says nothing about what the mutation did. "
            "Append-only in the schema, so a committed claim cannot be rewritten."
        ),
    ),
    ResourceRule(
        table="outbox_events",
        kind="framework",
        tenant_column="tenant_id",
        read=(Scope.MUTATION_EXECUTE,),
        write=(Scope.MUTATION_EXECUTE,),
        append_only=True,
        note=(
            "Same capability as the claim it is committed with, for the same reason. A future "
            "dispatcher reads these with its own identity and its own grant, not with a customer "
            "credential."
        ),
    ),
    ResourceRule(
        table="audit_events",
        kind="framework",
        tenant_column="tenant_id",
        read=(Scope.AUDIT_READ,),
        write=(),
        append_only=True,
        note=(
            "Appending requires a valid context and nothing more, so that no credential can act "
            "without leaving a trail; reading the trail requires audit:read. Tenant and actor are "
            "taken from the authenticated context by column default and re-checked by the policy, "
            "so a caller cannot write an event about somebody else."
        ),
    ),
    ResourceRule(
        table="auth_bindings",
        kind="protected",
        tenant_column=None,
        read=None,
        write=None,
        append_only=False,
        scope_source="none",
        note=(
            "The credential-fingerprint registry. No role but the schema owner holds any "
            "privilege on it, and the only paths in are the hardened SECURITY DEFINER functions "
            "in migration 0003. It is protected by privilege rather than by a policy: a policy "
            "constrains a role that has privileges, and here none does."
        ),
    ),
    ResourceRule(
        table="auth_transaction_context",
        kind="protected",
        tenant_column=None,
        read=None,
        write=None,
        append_only=False,
        scope_source="none",
        note=(
            "One transaction's authenticated identity, keyed by backend pid and carrying the "
            "xid8 of the transaction that wrote it. It is the mechanism, not a record of it: a "
            "role that could write here would name its own tenant, principal and scope set, and "
            "a role that could DELETE from it would clear the context and bind again as somebody "
            "else in the same transaction. It is listed beside auth_bindings rather than treated "
            "as a special case, because an inventory with one entry is an inventory that gets a "
            "second object added next to it without being updated."
        ),
    ),
    # --------------------------------------------------------------- Milestone 2.4
    #
    # The lifecycle definition tables are **global** rather than tenant-owned: a machine
    # version is one immutable graph shared by every tenant, in the same way the target
    # architecture's certification registry is explicitly global (section 3.1). They are
    # listed here because this catalogue is the one inventory of "what may a runtime role
    # reach", and a table that is global is not thereby unprotected -- a role that could
    # write one could add an edge to every tenant's state machine at once.
    ResourceRule(
        table="lifecycle_machines",
        kind="protected",
        tenant_column=None,
        read=None,
        write=None,
        append_only=False,
        scope_source="none",
        note=(
            "One row per (machine key, version): the initial-state marker's home, and the three "
            "scopes an instance of that version requires. Protected rather than policed, for the "
            "same reason auth_bindings is: the required scope is derived from this row, so a role "
            "that could write one could lower the capability its own instances demand. Registration "
            "is an owner-run admin action outside Alembic, like db/roles.py; a registered version is "
            "immutable and a change is a new version."
        ),
    ),
    ResourceRule(
        table="lifecycle_states",
        kind="protected",
        tenant_column=None,
        read=None,
        write=None,
        append_only=False,
        scope_source="none",
        note=(
            "The explicit state set of one machine version, with the initial marker and the "
            "terminal marker. A role that could write here could mark a terminal state "
            "non-terminal, or move the initial state, which is the graph itself."
        ),
    ),
    ResourceRule(
        table="lifecycle_transition_edges",
        kind="protected",
        tenant_column=None,
        read=None,
        write=None,
        append_only=False,
        scope_source="none",
        note=(
            "The allowed edges of one machine version. A role that could insert one could make "
            "any transition legal, including out of a terminal state -- which is the whole of what "
            "a lifecycle kernel exists to prevent."
        ),
    ),
    ResourceRule(
        table="lifecycle_instances",
        kind="lifecycle",
        tenant_column="tenant_id",
        read=None,
        write=None,
        append_only=False,
        scope_source="definition",
        note=(
            "One tenant-owned instance of one pinned machine version. The scope its policies "
            "require is not a constant here: it is read from the machine definition by "
            "firmbatch.lifecycle_required_scope(), so a machine declares the capability its own "
            "instances take. The runtime holds SELECT and nothing else -- creating one and moving "
            "one go through hardened SECURITY DEFINER functions, because a direct INSERT could "
            "start an instance in any state and a direct UPDATE could move it along an edge that "
            "does not exist."
        ),
    ),
    ResourceRule(
        table="lifecycle_transitions",
        kind="lifecycle",
        tenant_column="tenant_id",
        read=None,
        write=None,
        append_only=True,
        scope_source="definition",
        note=(
            "The append-only history of one instance's moves. Same data-driven scope as the "
            "instance it belongs to: reading a machine's history is reading that machine. The "
            "actor comes from the authenticated context like an audit event's, and the runtime "
            "holds SELECT and not INSERT, so a row cannot be composed by hand."
        ),
    ),
    ResourceRule(
        table="lifecycle_claim_provenance",
        kind="protected",
        tenant_column=None,
        read=None,
        write=None,
        append_only=False,
        scope_source="none",
        note=(
            "What ties one idempotency claim to the exact lifecycle transition, instance, "
            "revisions and outbox event it stands for. A replay hands back the result a claim "
            "stored, so a claim with no verifiable transition behind it must never replay -- and "
            "a machine tag alone is not that link, because it says which machine a row belongs to "
            "and not which move it records. Written only by firmbatch.transition_lifecycle_instance(), "
            "which runs as the schema owner; no role holds any privilege on it, and a trigger "
            "refuses every UPDATE and DELETE including the owner's. It carries a tenant column but "
            "no policy of its own: nothing reaches it except through the four FORCE-RLS tables its "
            "foreign keys point at, and those apply the tenant filter."
        ),
    ),
    # --------------------------------------------------------------- Milestone 3.1
    #
    # The identity plane. Every one of these is **protected**: no runtime or provisioning
    # role holds anything on it, and the only way in is a SECURITY DEFINER function in
    # migration 0005 that derives the account, tenant, workspace and membership from a
    # secret the caller presents or from the context a secret established. They carry no
    # policy for the reason auth_bindings carries none. The membership-domain permissions
    # (security/permissions.py) are read by those functions, never by a policy.
    *(
        ResourceRule(
            table=table,
            kind="protected",
            tenant_column=None,
            read=None,
            write=None,
            append_only=False,
            scope_source="none",
            note=note,
        )
        for table, note in (
            (
                "accounts",
                "One customer identity, existing before any workspace. Global, like a tenant slug; "
                "its uniqueness is never observable by a runtime role, and signup_account() answers "
                "the same shape for a new address and an existing one.",
            ),
            (
                "account_passwords",
                "The Argon2id hash of one account's password, fetched by login_lookup() for one "
                "account per call and verified in Python. A check constraint refuses any other stored form.",
            ),
            (
                "account_tokens",
                "Email-verification and recovery tokens as fingerprints: written once, consumed or "
                "superseded once, never deleted. The secret exists only in the result row that minted it.",
            ),
            (
                "memberships",
                "One account's role in one workspace of one tenant -- the row that decides which "
                "workspaces a person may choose from, re-read on every session bind and every "
                "issuance. Revocation is a state a trigger makes final, and the same trigger revokes "
                "every credential the membership issued and unbinds every session bound through it.",
            ),
            (
                "workspace_directory",
                "A protected copy of each workspace's slug and name, maintained by a trigger on "
                "workspaces for every writer and read only by account_workspaces(), which has to name "
                "an account's workspaces across tenants before any tenant context exists.",
            ),
            (
                "browser_sessions",
                "One browser session as two fingerprints (session, CSRF) and an optional workspace "
                "binding that names its membership with the workspace and tenant. A session secret is "
                "accepted only by bind_session_context(); a bearer credential is not, and vice versa.",
            ),
            (
                "workspace_invitations",
                "An invitation bound to a workspace, tenant, recipient address, role and expiry, "
                "consumed once under a row lock by the recipient it names.",
            ),
            (
                "account_idempotency_records",
                "The account-scoped replay record for the two mutations that run before a tenant "
                "context exists: creating a workspace and accepting an invitation. Append-only.",
            ),
            (
                "identity_transaction_context",
                "One transaction's bound session, or the account it challenged at login: keyed by "
                "backend pid, readable only by the transaction whose id it carries. The mechanism, "
                "beside auth_transaction_context, and protected for the same reasons.",
            ),
            (
                "identity_expected_workspace",
                "One transaction's expected workspace -- the workspace the page or action that "
                "made the request began under -- keyed like identity_transaction_context and read "
                "only by workspace_membership_authority, which refuses a mutation whose expectation "
                "is not the transaction's binding. Milestone 3.2's expected-workspace contract.",
            ),
        )
    ),
)

#: The scopes that may be placed on a credential minted through ``register_auth_binding``.
#:
#: Everything except :attr:`Scope.TENANT_PROVISION`, which belongs to the bootstrap path:
#: it is acquired from ``firmbatch.begin_tenant_provisioning()``, applies to a tenant id
#: PostgreSQL generated inside that same transaction, and is not a capability any
#: credential is issued. Excluding it here is what makes that sentence enforced rather
#: than merely documented.
#:
#: **Delegation is bounded by the issuer.** The database function additionally requires
#: that a *credential* issuer already hold every scope it grants, so ``credential:manage``
#: authorises creating a credential without implying the permissions that credential
#: carries. ``credential:manage`` is itself delegable -- it is a subset of what such an
#: issuer holds, it is confined to the issuer's own tenant, and refusing it would only mean
#: rotation could not be delegated. There is no wildcard and no administrator scope: the
#: only issuer that may grant a scope it does not hold is the *provisioning* context, which
#: has no credential to inherit from and can only act in the tenant it just created.
DELEGABLE_SCOPES: tuple[str, ...] = tuple(
    value for value in KNOWN_SCOPES if value != Scope.TENANT_PROVISION.value
)

#: The scopes a lifecycle machine definition may name as its read, create or transition
#: capability.
#:
#: Everything except :attr:`Scope.TENANT_PROVISION`, and the reason is that a machine gated
#: on it would be unreachable rather than protected: ``tenant:provision`` is acquired from
#: ``firmbatch.begin_tenant_provisioning()``, is held only by a context that has just
#: created a tenant, and cannot be placed on any credential at all (see
#: :data:`DELEGABLE_SCOPES`). A definition naming it is therefore a definition mistake, and
#: catching it at registration is cheaper than discovering it when the first transition is
#: refused for a reason nobody can act on.
#:
#: This is a *bound*, not a vocabulary: M2.4 adds no scope, and there is deliberately no
#: ``lifecycle:*`` capability. A machine reuses an existing customer scope, which is what
#: keeps "who may move this job" the same question as "who may write this job".
LIFECYCLE_ELIGIBLE_SCOPES: tuple[str, ...] = tuple(
    value for value in KNOWN_SCOPES if value != Scope.TENANT_PROVISION.value
)

#: table -> rule, for the places that look one up by name.
RULES_BY_TABLE: dict[str, ResourceRule] = {rule.table: rule for rule in RESOURCE_RULES}

#: The tables that carry no grant and no policy, reachable only through definer functions.
PROTECTED_TABLES: frozenset[str] = frozenset(
    rule.table for rule in RESOURCE_RULES if rule.kind == "protected"
)

#: Tenant-owned tables whose required scope is read from protected machine-definition data
#: rather than fixed in this catalogue. Named so that a test can walk them, and so that
#: adding a third is a decision somebody writes down here.
DEFINITION_SCOPED_TABLES: frozenset[str] = frozenset(
    rule.table for rule in RESOURCE_RULES if rule.scope_source == "definition"
)


def scope_values(scopes) -> tuple[str, ...]:
    """Normalise an iterable of scopes to the plain strings PostgreSQL stores.

    Refuses anything not in the catalogue. A caller that could pass an arbitrary string
    would be inventing a capability, and the whole point of a closed catalogue is that
    inventing one requires a migration.
    """
    out: list[str] = []
    for index, scope in enumerate(scopes):
        value = scope.value if isinstance(scope, Scope) else scope
        # Shape before parse, and neither echoes. A scope arrives as caller-supplied text
        # like anything else, so a bearer credential passed where a scope belongs was
        # quoted by the very check that refused it -- into an exception, a traceback and a
        # retained log. The rejected value is named by position instead: an invalid value
        # is unvetted input whether or not a pattern recognises it as a secret, and there
        # is no version of "it was probably harmless" that is worth a leak.
        shape = looks_like_secret(value)
        if shape is not None:
            raise AuthorizationError(
                f"the scope at position {index} looks like {shape}. A scope names a capability "
                "from a closed catalogue; the value is deliberately not repeated here."
            )
        if not isinstance(value, str):
            raise AuthorizationError(
                f"the scope at position {index} is {type(value).__name__}, not a string or a Scope. "
                "The value is deliberately not repeated."
            )
        if value not in KNOWN_SCOPES:
            raise AuthorizationError(
                f"the scope at position {index} is not in the catalogue. It is closed and lives in "
                "control_plane/security/authorization.py; adding one means a new migration for the "
                f"check constraint and the policy that honours it. Known: {list(KNOWN_SCOPES)}. The "
                "rejected value is deliberately not repeated."
            )
        out.append(value)
    if len(out) > MAX_SCOPES_PER_BINDING:
        raise AuthorizationError(
            f"{len(out)} scopes, over the {MAX_SCOPES_PER_BINDING} a single binding may carry"
        )
    # Sorted and de-duplicated: two bindings with the same capability should not differ by
    # the order somebody happened to type them in.
    return tuple(sorted(set(out)))


def require_scope(context, scope: Scope) -> None:
    """Raise unless ``context`` holds ``scope``.

    The database refuses the operation anyway -- with an empty result or a policy
    violation. This turns that into a message that names the missing capability, at the
    boundary where the caller can do something about it.
    """
    if context is None:
        raise AuthorizationError(
            f"{scope.value!r} is required and this transaction has no authenticated context. "
            "Bind one with bind_authenticated_context() before doing tenant-scoped work."
        )
    if not context.has_scope(scope):
        raise AuthorizationError(
            f"the authenticated context for tenant {context.tenant_id} does not hold "
            f"{scope.value!r}; it holds {sorted(context.scopes)}. Authorization is deny-by-default: "
            "a capability that was not granted to the credential is refused."
        )
