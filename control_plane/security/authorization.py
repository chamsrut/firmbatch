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
    #: ``protected`` -- state no runtime role may reach at all.
    kind: str
    #: The column the isolation predicate compares against the authenticated tenant.
    #: ``None`` for a protected table, which has no policy because it has no grants.
    tenant_column: str | None
    #: Scopes, any one of which permits ``SELECT``. Empty means "a valid context is
    #: enough"; ``None`` means there is no read path at all.
    read: tuple[Scope, ...] | None
    #: Scopes, any one of which permits a write. Empty means "a valid context is enough";
    #: ``None`` means there is no write path at all.
    write: tuple[Scope, ...] | None
    #: ``True`` when the table carries no ``UPDATE`` and no ``DELETE`` policy, so a
    #: committed row cannot be changed or removed by any role, the owner included.
    append_only: bool
    #: Why the rule is what it is. Read this before changing one.
    note: str


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

#: table -> rule, for the places that look one up by name.
RULES_BY_TABLE: dict[str, ResourceRule] = {rule.table: rule for rule in RESOURCE_RULES}

#: The tables that carry no grant and no policy, reachable only through definer functions.
PROTECTED_TABLES: frozenset[str] = frozenset(
    rule.table for rule in RESOURCE_RULES if rule.kind == "protected"
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
