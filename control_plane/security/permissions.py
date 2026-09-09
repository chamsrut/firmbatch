"""The closed membership-role and permission model for Milestone 3.1.

Milestone 2.3 gave a credential a **scope set** from a closed catalogue
(:mod:`~firmbatch.control_plane.security.authorization`). Milestone 3.1 puts a *person*
behind a credential, and a person's authority in a workspace is a **role** on a
**membership**. This module says what each role is allowed to do, and it says it in one
place so that the browser-session bind in PostgreSQL, the API-credential issuer in
PostgreSQL and every Python caller derive the same answer. Migration ``0005`` carries a
character-for-character copy of :data:`ROLE_PERMISSIONS` as
``firmbatch.membership_role_scopes()``, and ``tests/test_identity_permissions.py`` walks
both and requires them to agree on every role.

Two vocabularies, deliberately distinct
---------------------------------------

* **Permissions** are what a *session* carries. A browser session bound to a workspace
  acquires a tenant context whose scope set is exactly its membership role's permission
  set -- the six Milestone 2.3 customer scopes the role includes, plus the three
  membership-domain permissions below. The policies on tenant-scoped tables read the
  Milestone 2.3 scopes as before; the membership-domain permissions are read only by the
  ``SECURITY DEFINER`` identity functions, which is where membership is managed.

* **API scopes** are what an *API credential* carries. They are, and remain, the closed
  Milestone 2.3 catalogue: an API credential issued in Milestone 3.1 may request only a
  scope that is **both** in the issuing member's effective permissions **and** in
  :data:`API_ISSUABLE_SCOPES`. The membership-domain permissions are never placeable on an
  API credential -- there is no route by which an API credential invites, removes or
  issues -- and neither is ``credential:manage``: see :data:`API_ISSUABLE_SCOPES`.

What no role grants
-------------------

**No role grants ``credential:manage``.** That is the Milestone 2.3 capability behind
``firmbatch.register_auth_binding``, which mints a credential for a caller-named principal
with no membership behind it. Milestone 3.1's rule is that every customer-issued API
credential is tied to the membership it was issued from, so that revoking the membership
invalidates the credential structurally; a session that could call the untied minting
function would be a way around that rule through the supported interface. Sessions
therefore hold ``credential:issue`` -- an M3.1 permission the issuer reads -- and never
``credential:manage``. ``register_auth_binding`` keeps its Milestone 2.3 meaning for the
provisioning path and for credentials provisioned out of band, and no session can reach it.

**No role grants ``tenant:provision``** on a session, except for the one transaction in
which ``firmbatch.create_workspace()`` creates the tenant that workspace lives in. That
is the same shape as Milestone 2.3's provisioning transaction, and it is confined the same
way: the tenant id is generated inside the database and the transaction ends with the
call.

The owner-only rules
--------------------

``owner`` and ``admin`` hold the same permission set. What separates them is not a scope
but a rule inside the membership functions: **only an owner may change or remove an owner
membership**, and **the last active owner of a workspace cannot be removed or demoted**.
Those are stated in :data:`OWNER_ONLY_RULES` so a reader finds them beside the roles they
qualify, and enforced in ``firmbatch.remove_membership()`` and
``firmbatch.change_membership_role()`` under a row lock on the workspace, which is what
makes "last owner" a deterministic question under concurrency.
"""

from __future__ import annotations

from enum import Enum

from .authorization import DELEGABLE_SCOPES, KNOWN_SCOPES, Scope


class MembershipRole(str, Enum):
    """Every role a membership may carry. There are no others."""

    #: Full authority, including over other owners, and the only role that may remove or
    #: demote an owner. A workspace always has at least one.
    OWNER = "owner"
    #: Everything an owner may do except act on owner memberships.
    ADMIN = "admin"
    #: Works in the workspace: reads and writes workspace resources, records mutations,
    #: issues API credentials bounded by its own permissions. Manages nobody.
    MEMBER = "member"
    #: Reads. Issues nothing, invites nobody.
    VIEWER = "viewer"


#: Every role, as the plain strings PostgreSQL stores, sorted so the check constraint this
#: generates is deterministic.
MEMBERSHIP_ROLES: tuple[str, ...] = tuple(sorted(role.value for role in MembershipRole))


class MembershipPermission(str, Enum):
    """The three membership-domain permissions Milestone 3.1 adds. Session-only."""

    #: List the members and pending invitations of the bound workspace.
    MEMBERSHIP_READ = "membership:read"
    #: Invite, remove and re-role members; revoke invitations; see every API credential in
    #: the workspace rather than only one's own.
    MEMBERSHIP_MANAGE = "membership:manage"
    #: Authorize an audited API-credential create, rotate or revoke for one's own
    #: membership. The issuer additionally requires that every requested scope is within
    #: the member's own effective permissions.
    CREDENTIAL_ISSUE = "credential:issue"


#: The membership-domain vocabulary, sorted. Disjoint from the Milestone 2.3 scope
#: catalogue by construction, and asserted disjoint by a test.
MEMBERSHIP_PERMISSIONS: tuple[str, ...] = tuple(
    sorted(permission.value for permission in MembershipPermission)
)

#: The scopes an API credential may be issued in Milestone 3.1.
#:
#: The Milestone 2.3 delegable catalogue **minus ``credential:manage``**. The omission is
#: the design: a credential holding ``credential:manage`` can call
#: ``firmbatch.register_auth_binding`` and mint a successor tied to no membership, which is
#: precisely the untied credential Milestone 3.1 exists to stop issuing. Rotation and
#: revocation are session operations, explicitly authorized and audited, and never a
#: capability an API credential carries.
API_ISSUABLE_SCOPES: tuple[str, ...] = tuple(
    scope for scope in DELEGABLE_SCOPES if scope != Scope.CREDENTIAL_MANAGE.value
)

_VIEWER: tuple[str, ...] = (
    MembershipPermission.MEMBERSHIP_READ.value,
    Scope.TENANT_READ.value,
    Scope.WORKSPACE_READ.value,
)
_MEMBER: tuple[str, ...] = _VIEWER + (
    MembershipPermission.CREDENTIAL_ISSUE.value,
    Scope.MUTATION_EXECUTE.value,
    Scope.WORKSPACE_WRITE.value,
)
_ADMIN: tuple[str, ...] = _MEMBER + (
    Scope.AUDIT_READ.value,
    MembershipPermission.MEMBERSHIP_MANAGE.value,
)

#: The closed model. ``role -> effective permissions``, each sorted and deduplicated so the
#: array a session context carries is canonical and comparable. Migration ``0005`` carries
#: the same table as ``firmbatch.membership_role_scopes()``.
ROLE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    MembershipRole.VIEWER.value: tuple(sorted(set(_VIEWER))),
    MembershipRole.MEMBER.value: tuple(sorted(set(_MEMBER))),
    MembershipRole.ADMIN.value: tuple(sorted(set(_ADMIN))),
    MembershipRole.OWNER.value: tuple(sorted(set(_ADMIN))),
}

#: Roles that may manage memberships and invitations at all.
MANAGING_ROLES: frozenset[str] = frozenset(
    role for role, permissions in ROLE_PERMISSIONS.items()
    if MembershipPermission.MEMBERSHIP_MANAGE.value in permissions
)

#: The rules that separate ``owner`` from ``admin``. Stated as data so that a reader finds
#: them beside the roles, and enforced inside the database functions.
OWNER_ONLY_RULES: tuple[str, ...] = (
    "only an owner may remove an owner membership",
    "only an owner may change a membership's role to or from owner",
    "only an owner may invite at the owner role",
    "the last active owner of a workspace cannot be removed or demoted",
)


def effective_permissions(role: str | MembershipRole) -> tuple[str, ...]:
    """The permission set one role carries, or a refusal for an unknown role."""
    value = role.value if isinstance(role, MembershipRole) else role
    try:
        return ROLE_PERMISSIONS[value]
    except KeyError:
        raise ValueError(
            "that membership role is not in the closed model; the rejected value is deliberately "
            "not repeated"
        ) from None


def issuable_scopes_for(role: str | MembershipRole) -> tuple[str, ...]:
    """The API scopes a member of ``role`` may place on a credential it issues.

    Effective permissions intersected with :data:`API_ISSUABLE_SCOPES`. A role that lacks
    ``credential:issue`` may still have a non-empty answer here -- the answer describes the
    bound, not the authority to issue, which the database checks separately.
    """
    held = set(effective_permissions(role))
    return tuple(scope for scope in API_ISSUABLE_SCOPES if scope in held)


def api_scopes_within(role: str | MembershipRole, requested) -> tuple[str, ...]:
    """Normalise a requested API scope set for a member of ``role``, or refuse it.

    Every requested value must be in the closed Milestone 2.3 catalogue, in
    :data:`API_ISSUABLE_SCOPES`, and in the member's effective permissions. The refusal
    names the position and never the value, for the reason every other refusal in this
    package gives.
    """
    from .secrets import looks_like_secret

    permitted = set(issuable_scopes_for(role))
    out: list[str] = []
    for index, scope in enumerate(requested):
        value = scope.value if isinstance(scope, Scope) else scope
        shape = looks_like_secret(value)
        if shape is not None:
            raise ValueError(
                f"the requested scope at position {index} looks like {shape}; the value is "
                "deliberately not repeated"
            )
        if not isinstance(value, str) or value not in KNOWN_SCOPES:
            raise ValueError(
                f"the requested scope at position {index} is not in the closed Milestone 2.3 "
                "catalogue; the value is deliberately not repeated"
            )
        if value not in permitted:
            raise ValueError(
                f"the requested scope at position {index} is not within what this membership may "
                "place on an API credential; the value is deliberately not repeated"
            )
        out.append(value)
    return tuple(sorted(set(out)))
