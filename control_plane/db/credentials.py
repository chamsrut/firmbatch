"""API credentials issued from a membership: the Python side of Milestone 3.1's issuance functions.

The trusted issuance path, as the roadmap names it: from a verified identity and an
active membership to the protected Milestone 2.3 credential registry. A browser session
bound to a workspace and holding ``credential:issue`` **explicitly authorizes** each
operation; ``firmbatch.issue_api_credential`` then re-reads the membership, bounds the
requested scopes by the member's own effective permissions and the closed Milestone 2.3
catalogue, and mints a **new** 244-bit secret. Nothing here exchanges, converts or redeems
the session's secret; the session is the authorizer and the credential is the product.

Rotation is an atomic cutover -- the old binding is locked, the new one minted with the
same scopes, label and membership, and the old one revoked in one statement sequence --
and only the member whose membership issued a credential may rotate it, because the
rotated credential authenticates as that member. A manager may revoke any credential in
the workspace and rotate none but its own.

**Revoked and expired are one state.** A credential is active only while it is neither, the
answer is computed in PostgreSQL against the same ``clock_timestamp()`` the bearer boundary
compares against, and an expired credential is refused rotation with the neutral refusal a
revoked one gets: rotation carries the predecessor's scopes forward without rebounding them
by the member's current role, so reviving a dead credential through it would revive a scope
set the member may no longer hold. Re-issuance is the way back, and it is the operation that
rebounds the scopes. An elapsed expiry is never turned into "does not expire".

Last use is recorded by :func:`record_use`, which the API-credential boundary calls after
a successful bind. Milestone 2.3's ``bind_authenticated_context`` is not modified: a
credential issued here authenticates through it exactly as an out-of-band one does, and
revocation -- by hand, by rotation, or by the membership cascade -- is observed on the
linearisation terms that function already states.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

from ..security.permissions import api_scopes_within
from ..security.secrets import Secret, looks_like_secret
from .accounts import IdentityError, _execute
from .base import SCHEMA
from .idempotency import _require_valid_key
from .models import CREDENTIAL_LABEL_MAX_LENGTH


@dataclass(frozen=True)
class IssuedCredential:
    """A newly minted API credential. ``credential`` is present on the first execution only."""

    binding_id: uuid.UUID
    credential: Secret | None
    scopes: tuple[str, ...]
    expires_at: datetime | None
    rotated_from_id: uuid.UUID | None
    event_id: uuid.UUID | None
    record_id: uuid.UUID | None
    replayed: bool

    def __repr__(self) -> str:
        return (
            f"IssuedCredential(binding_id={self.binding_id}, scopes={list(self.scopes)}, "
            f"replayed={self.replayed}, credential=<redacted>)"
        )


@dataclass(frozen=True)
class CredentialSummary:
    binding_id: uuid.UUID
    label: str | None
    scopes: tuple[str, ...]
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
    rotated_from_id: uuid.UUID | None
    membership_id: uuid.UUID | None
    account_id: uuid.UUID
    email: str
    #: **The lifecycle state, as PostgreSQL computed it** (Milestone 3.1 security
    #: correction). A credential is active only while it is neither revoked nor expired,
    #: and the comparison is made in the database against ``clock_timestamp()`` -- the same
    #: clock ``bind_authenticated_context`` uses -- rather than here against the
    #: application's. Deriving it from ``revoked_at`` alone once showed as usable a
    #: credential the bearer boundary already refuses; deriving it here from ``expires_at``
    #: would make the answer depend on whichever process rendered the row.
    active: bool


@dataclass(frozen=True)
class CredentialRevocation:
    revoked: bool
    event_id: uuid.UUID | None
    record_id: uuid.UUID | None
    replayed: bool


def _key(idempotency_key: str | None) -> str | None:
    if idempotency_key is None:
        return None
    _require_valid_key(idempotency_key)
    return idempotency_key


def _require_label(label: str | None) -> str | None:
    if label is None:
        return None
    shape = looks_like_secret(label)
    if shape is not None:
        raise IdentityError(f"the credential label looks like {shape}; the value is deliberately not repeated")
    if not isinstance(label, str) or not 1 <= len(label) <= CREDENTIAL_LABEL_MAX_LENGTH:
        raise IdentityError(
            f"a credential label is a string of 1 to {CREDENTIAL_LABEL_MAX_LENGTH} characters; the value is "
            "deliberately not repeated"
        )
    return label


def _require_uuid(value, *, what: str) -> uuid.UUID:
    if not isinstance(value, uuid.UUID):
        raise IdentityError(f"a {what} is a UUID; got {type(value).__name__}")
    return value


def _issued(row) -> IssuedCredential:
    return IssuedCredential(
        binding_id=row.binding_id,
        credential=Secret(row.credential) if row.credential else None,
        scopes=tuple(row.scopes or ()),
        expires_at=row.expires_at,
        rotated_from_id=getattr(row, "rotated_from_id", None),
        event_id=row.event_id,
        record_id=row.record_id,
        replayed=bool(row.replayed),
    )


def issue(
    session: Session,
    *,
    role: str,
    scopes,
    label: str | None = None,
    expires_at: datetime | None = None,
    idempotency_key: str | None = None,
) -> IssuedCredential:
    """Mint an API credential for this session's membership. Workspace mode, CSRF-verified, ``credential:issue``.

    ``role`` is the session's membership role as the bind reported it; the scopes are
    checked against it here so the caller gets the rule by name, and again inside the
    database against the membership as it is at the instant of issuance.
    """
    requested = api_scopes_within(role, scopes)
    row = _execute(
        session,
        text(
            "SELECT binding_id, credential, scopes, expires_at, event_id, record_id, replayed "
            f"FROM {SCHEMA}.issue_api_credential(CAST(:scopes AS text[]), :expires_at, :label, :key)"
        ),
        {
            "scopes": list(requested),
            "expires_at": expires_at,
            "label": _require_label(label),
            "key": _key(idempotency_key),
        },
    ).one()
    return _issued(row)


def rotate(
    session: Session,
    binding_id: uuid.UUID,
    *,
    expires_at: datetime | None = None,
    idempotency_key: str | None = None,
) -> IssuedCredential:
    """Replace one of this membership's credentials with a fresh secret, atomically. Workspace mode, CSRF-verified."""
    _require_uuid(binding_id, what="binding id")
    row = _execute(
        session,
        text(
            "SELECT binding_id, credential, scopes, expires_at, rotated_from_id, event_id, record_id, replayed "
            f"FROM {SCHEMA}.rotate_api_credential(:binding_id, :expires_at, :key)"
        ),
        {"binding_id": binding_id, "expires_at": expires_at, "key": _key(idempotency_key)},
    ).one()
    return _issued(row)


def revoke(session: Session, binding_id: uuid.UUID, *, idempotency_key: str | None = None) -> CredentialRevocation:
    """Revoke one's own credential, or any workspace credential with ``membership:manage``.

    ``revoked`` is ``False`` for an absent, foreign, unpermitted or already-revoked
    credential alike.
    """
    _require_uuid(binding_id, what="binding id")
    row = _execute(
        session,
        text(
            "SELECT revoked, event_id, record_id, replayed "
            f"FROM {SCHEMA}.revoke_api_credential(:binding_id, :key)"
        ),
        {"binding_id": binding_id, "key": _key(idempotency_key)},
    ).one()
    return CredentialRevocation(
        revoked=bool(row.revoked), event_id=row.event_id, record_id=row.record_id, replayed=bool(row.replayed)
    )


def list_credentials(session: Session) -> list[CredentialSummary]:
    """The safe listing: one's own credentials, or every workspace credential with ``membership:manage``."""
    rows = _execute(
        session,
        text(
            "SELECT binding_id, label, scopes, created_at, expires_at, revoked_at, last_used_at, "
            "rotated_from_id, membership_id, account_id, email, active "
            f"FROM {SCHEMA}.workspace_api_credentials()"
        ),
    ).all()
    return [
        CredentialSummary(
            binding_id=row.binding_id,
            label=row.label,
            scopes=tuple(row.scopes or ()),
            created_at=row.created_at,
            expires_at=row.expires_at,
            revoked_at=row.revoked_at,
            last_used_at=row.last_used_at,
            rotated_from_id=row.rotated_from_id,
            membership_id=row.membership_id,
            account_id=row.account_id,
            email=row.email,
            active=bool(row.active),
        )
        for row in rows
    ]


def record_use(session: Session) -> None:
    """Stamp ``last_used_at`` on the credential this transaction authenticated with."""
    _execute(session, text(f"SELECT {SCHEMA}.record_api_credential_use()"))
