"""Workspace preferences and consent: the Python side of Milestone 3.2's one relation.

Reads go to an **ordinary policed relation**: ``workspace_preferences`` carries no secret,
decides no authority and gates nothing, so a read needs the isolation every customer relation
gets -- forced row security, a tenant predicate and a scope predicate -- and the application
role holds ``SELECT`` on it for exactly that.

Writes do **not**. After the independent Milestone 3.2 review the application role holds no
``INSERT``, ``UPDATE`` or ``DELETE`` on the relation at all; every write goes through one of
two ``SECURITY DEFINER`` functions in migration ``0006``, which are the authorization and
audit boundary for it -- the same arrangement ``audit_events`` has with
``append_audit_event``. This module is therefore thin on the write side, like
``db/accounts.py`` and ``db/membership.py``: it checks the inputs so a caller gets a usable
error before a statement is sent, and it calls the function. Nothing decided here is
load-bearing, because the function decides all of it again.

What each mutation function enforces, in the database
-----------------------------------------------------

* **The caller holds a CSRF-verified, workspace-bound browser session.** A transaction a
  ``GET`` opened -- bound without its CSRF secret -- cannot reach a write, whatever SQL it
  runs.
* **The caller holds an active membership in this workspace, with ``workspace:write``,
  now.** The function takes the workspace serialisation lock and re-derives the membership
  and role under it (``workspace_membership_authority``). A session demoted from ``member``
  to ``viewer`` since it bound is refused even though its cached context still carries the
  scope; a removed member is refused neutrally.
* **The workspace the caller's page state expected is the workspace the session is bound
  to.** Every mutation carries ``expected_workspace_id`` -- the identifier the page loaded
  its form for -- and the function compares it with the bound workspace under the lock. A
  form loaded for workspace A whose shared session another tab has since re-bound to
  workspace B is refused with :class:`~firmbatch.control_plane.db.accounts.WorkspaceBindingMismatch`
  rather than having A's values applied to B; a forged identifier and another tenant's
  identifier get the same refusal.
* **The no-op / transition decision is serialised.** Re-stating the statement in force, or
  re-acknowledging the version in force, writes nothing and appends nothing. Two
  simultaneous acknowledgements of one version leave one row, one timestamp and exactly one
  audit event.
* **The row and its audit event commit together or not at all.** Both are written inside one
  function call, so a failure in either rolls back the other.
* **Who consented, and when, are the server's.** The function derives them from the bound
  account and ``clock_timestamp()``; a trigger derives them again behind it. Nothing here
  sends either value, and :func:`acknowledge_consent` has no parameter for one. The version
  recorded is the server's current one; the version this module passes is the one the
  portal *displayed*, and a stale display is refused as a conflict.

What this module is *not*
-------------------------

It is not a ``JobSpec``, a quote, an admission input or a routing constraint, and nothing in
the control plane reads it to decide anything. The roadmap asks Milestone 3.2 to capture the
customer's stated policy, profile and preferences "for later use **without claiming a quote
or an execution**"; M5 owns the contract fields that make the same ideas binding.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

from ..security.authorization import Scope
from ..security.secrets import looks_like_secret
from .accounts import IdentityError, _execute
from .base import SCHEMA
from .membership import require_membership
from .models import (
    CONSENT_VERSIONS,
    EVALUATION_INTENTS,
    MODEL_PROFILE_NOTE_MAX_LENGTH,
    PROVIDER_CLASSES,
    REGION_GROUPS,
)

#: An upper bound on the arrays a caller may send, checked before the statement. The closed
#: vocabularies are shorter than this; the bound exists so that a caller cannot make the
#: database sort a huge array before the check constraint refuses it. Mirrored by migration
#: ``0006``'s ``MAX_ARRAY_LENGTH``, and a test holds the copies equal.
MAX_ARRAY_LENGTH = 16

_COLUMNS = (
    "id, workspace_id, tenant_id, region_policy, excluded_provider_classes, "
    "model_profile_note, evaluation_intent, consent_version, consent_acknowledged_at, "
    "consent_account_id, created_at, updated_at"
)

#: The two mutation entry points, called with the row columns named so ``_row`` reads the
#: result exactly as it reads a ``SELECT`` from the relation.
_STATE_STATEMENT = text(
    f"SELECT {_COLUMNS} FROM {SCHEMA}.state_workspace_preferences("
    ":w, CAST(:regions AS text[]), CAST(:excluded AS text[]), :note, :intent)"
)
_ACKNOWLEDGE_STATEMENT = text(
    f"SELECT {_COLUMNS} FROM {SCHEMA}.acknowledge_workspace_consent(:w, :version)"
)


@dataclass(frozen=True)
class WorkspacePreferencesRow:
    """One workspace's stated intent, as PostgreSQL holds it."""

    workspace_id: uuid.UUID
    region_policy: tuple[str, ...]
    excluded_provider_classes: tuple[str, ...]
    model_profile_note: str | None
    evaluation_intent: str
    consent_version: str | None
    consent_acknowledged_at: datetime | None
    consent_account_id: uuid.UUID | None
    updated_at: datetime | None

    @property
    def unservable_exclusion(self) -> bool:
        """Whether the stated exclusions include one v1 cannot honour.

        Exactly one today: ``amazon``. The payload plane is S3 for every tenant, so a
        customer who excludes Amazon altogether cannot be served in v1 (target §3.3, §5.4,
        invariant 13). Derived here rather than stored, because it is a property of the
        current *architecture*, not of the row -- when a bucket per supplier cloud region
        exists, the same row stops being unservable and no data migration should be needed
        to say so.
        """
        return "amazon" in self.excluded_provider_classes


def _row(row) -> WorkspacePreferencesRow:
    return WorkspacePreferencesRow(
        workspace_id=row.workspace_id,
        region_policy=tuple(row.region_policy or ()),
        excluded_provider_classes=tuple(row.excluded_provider_classes or ()),
        model_profile_note=row.model_profile_note,
        evaluation_intent=row.evaluation_intent,
        consent_version=row.consent_version,
        consent_acknowledged_at=row.consent_acknowledged_at,
        consent_account_id=row.consent_account_id,
        updated_at=row.updated_at,
    )


def _default(workspace_id: uuid.UUID) -> WorkspacePreferencesRow:
    """What a workspace with no row has stated: nothing.

    Returned rather than inserted on read. A ``GET`` that wrote a row would need
    ``workspace:write``, so a viewer could not read preferences at all, and every workspace
    would carry a row whether or not anybody ever stated anything.
    """
    return WorkspacePreferencesRow(
        workspace_id=workspace_id,
        region_policy=(),
        excluded_provider_classes=(),
        model_profile_note=None,
        evaluation_intent="undecided",
        consent_version=None,
        consent_acknowledged_at=None,
        consent_account_id=None,
        updated_at=None,
    )


def _require_closed_array(values, *, allowed: tuple[str, ...], what: str) -> list[str]:
    """A caller-supplied array, checked against a closed vocabulary without echoing it.

    Sorted and deduplicated so the stored array is canonical and two equivalent statements
    compare equal. The refusal names the position and never the value, for the reason every
    other refusal in this package gives: a value that reached the wrong argument may be a
    secret, and quoting it puts it in a traceback and a log. The database function applies
    the same rule again to whatever it is handed.
    """
    if values is None:
        return []
    if not isinstance(values, (list, tuple)):
        raise IdentityError(f"the {what} is a list of short strings")
    if len(values) > MAX_ARRAY_LENGTH:
        raise IdentityError(f"the {what} carries more entries than this boundary accepts")
    out: set[str] = set()
    for index, value in enumerate(values):
        shape = looks_like_secret(value)
        if shape is not None:
            raise IdentityError(
                f"the {what} entry at position {index} looks like {shape}; the value is "
                "deliberately not repeated"
            )
        if not isinstance(value, str) or value not in allowed:
            raise IdentityError(
                f"the {what} entry at position {index} is not in the closed set; the value is "
                "deliberately not repeated"
            )
        out.add(value)
    return sorted(out)


def _require_note(value) -> str | None:
    if value is None:
        return None
    shape = looks_like_secret(value)
    if shape is not None:
        raise IdentityError(
            f"the model and profile note looks like {shape}. It is a short description of what "
            "you expect to run, not a place for a secret, and the value is deliberately not "
            "repeated."
        )
    if not isinstance(value, str):
        raise IdentityError("the model and profile note is text or absent")
    trimmed = value.strip()
    if not trimmed:
        return None
    if len(trimmed) > MODEL_PROFILE_NOTE_MAX_LENGTH:
        raise IdentityError(
            f"the model and profile note is at most {MODEL_PROFILE_NOTE_MAX_LENGTH} characters"
        )
    return trimmed


def _require_intent(value) -> str:
    if value not in EVALUATION_INTENTS:
        raise IdentityError(
            "the evaluation intent is not in the closed set; the value is deliberately not repeated"
        )
    return value


def _require_consent_version(value) -> str:
    shape = looks_like_secret(value)
    if shape is not None:
        raise IdentityError(
            f"the consent version looks like {shape}; the value is deliberately not repeated"
        )
    if value not in CONSENT_VERSIONS:
        raise IdentityError(
            "that is not a consent version this system published; the value is deliberately not "
            "repeated"
        )
    return value


def _require_workspace_id(value) -> uuid.UUID:
    """The workspace the caller's page state expects. A UUID, and nothing is inferred from it.

    Deliberately **not** defaulted to the bound workspace: the whole point of the parameter
    is that the page says which workspace it loaded its form for, and the database compares
    that with the workspace the session is bound to now. A caller that omitted it would be
    asking to skip the comparison.
    """
    if not isinstance(value, uuid.UUID):
        raise IdentityError("the expected workspace id is a UUID")
    return value


def read(session: Session, workspace_id: uuid.UUID) -> WorkspacePreferencesRow:
    """This workspace's stated intent, or the empty statement. Workspace mode.

    ``workspace:read`` through the membership as it is now, then the policy, then the row.
    A workspace that has stated nothing has no row, and the caller gets the same shape a
    stated-nothing row would have -- so a client never has to distinguish "absent" from
    "empty", and absence is not observable as a different answer.
    """
    require_membership(session, scope=Scope.WORKSPACE_READ.value)
    row = _execute(
        session,
        text(f"SELECT {_COLUMNS} FROM {SCHEMA}.workspace_preferences WHERE workspace_id = :w"),
        {"w": workspace_id},
    ).one_or_none()
    return _default(workspace_id) if row is None else _row(row)


def state(
    session: Session,
    expected_workspace_id: uuid.UUID,
    *,
    region_policy=None,
    excluded_provider_classes=None,
    model_profile_note=None,
    evaluation_intent: str = "undecided",
) -> WorkspacePreferencesRow:
    """Replace this workspace's stated intent. Workspace mode, CSRF-verified, ``workspace:write``.

    ``expected_workspace_id`` is the workspace the caller's page loaded its form for. The
    database compares it, under the workspace lock, with the workspace the bound session
    acts in, and refuses a mismatch with
    :class:`~firmbatch.control_plane.db.accounts.WorkspaceBindingMismatch` -- the same
    refusal for a stale page, a forged identifier and another tenant's identifier.

    A full replacement rather than a patch, which is what makes it naturally idempotent and
    why it needs no idempotency key: sending the same body twice leaves the same row, and
    the second call is a true no-op that appends no audit event. The consent columns are
    **not** touched here -- they move only through :func:`acknowledge_consent`, so an
    ordinary preference edit can never re-date or clear an acknowledgement.
    """
    params = {
        "w": _require_workspace_id(expected_workspace_id),
        "regions": _require_closed_array(region_policy, allowed=REGION_GROUPS, what="region policy"),
        "excluded": _require_closed_array(
            excluded_provider_classes, allowed=PROVIDER_CLASSES, what="provider exclusion"
        ),
        "note": _require_note(model_profile_note),
        "intent": _require_intent(evaluation_intent),
    }
    return _row(_execute(session, _STATE_STATEMENT, params).one())


def acknowledge_consent(
    session: Session, expected_workspace_id: uuid.UUID, *, version: str
) -> WorkspacePreferencesRow:
    """Record assent to the consent statement currently published. Workspace mode, CSRF-verified.

    ``version`` is the version the portal **displayed**, checked here against the published
    set and by the database against the version currently in force; the version *recorded*
    is the database's own constant. A stale display -- a published version that is no longer
    the current one -- is refused as :class:`~firmbatch.control_plane.db.accounts.IdentityConflict`,
    so assent is never recorded to text the customer was not shown.

    Idempotent by state rather than by key: re-acknowledging the version already in force is
    a no-op that returns the acknowledgement as it stands and appends no audit event, because
    nothing happened. Acknowledging when an earlier version is in force is a new
    acknowledgement -- stamped, recorded in the trail with the version it superseded.

    There is no parameter for who or when. Both are derived inside
    ``firmbatch.acknowledge_workspace_consent()``.
    """
    params = {
        "w": _require_workspace_id(expected_workspace_id),
        "version": _require_consent_version(version),
    }
    return _row(_execute(session, _ACKNOWLEDGE_STATEMENT, params).one())
