"""The one metadata policy: what may be stored in a bounded ``jsonb`` column, and what may not.

Extracted from ``db/idempotency.py`` at Milestone 2.3, unchanged in substance, because the
audit trail needs exactly the same rule and two copies of a denylist is how a denylist
stops being one. ``db/idempotency.py`` re-exports every public name here, so nothing that
imported it from there had to move.

Three columns are governed by this: ``idempotency_records.result``,
``outbox_events.attributes`` and ``audit_events.details``. All three hold the same kind of
thing -- identifiers, counts, digests, and references to objects that live elsewhere --
and none of them is a place for a request body, a customer payload, or a credential.

What is refused, and where the caller finds out
-----------------------------------------------

At the boundary, before any row is written and before any mutation runs: nested objects,
binary values, strings over 256 characters, documents over 2 KiB, more than 32 keys, keys
that are not lowercase identifiers, keys whose **whole name** means content or a
credential, and values that carry a recognisable secret shape. Check constraints in
migrations ``0002`` and ``0003`` bound the same documents in the database, as the backstop
for a writer that bypasses this module.

**None of it is a proof, and it must not be cited as one.** ``TEXT`` and ``JSONB`` hold
text, so an encoded payload fits; 256 characters is a short payload; a bound is a size
limit rather than a semantic filter; and no pattern can establish that a string is not a
secret. What these rules buy is that the obvious mistake is refused at a place where the
caller gets a usable error. The data-flow proof that customer payload never reaches the
API process or PostgreSQL (target architecture invariant 3) is Milestone 5's presigned S3
path. ADR 0005 decision 9 states this at length and it has not changed.

**Whole names, not substrings.** The first version of the key rule matched substrings and
was wrong in the direction that matters: it rejected ``input_manifest_id``,
``output_object_key`` and ``artifact_digest`` -- exactly the references these columns exist
to hold -- while doing nothing about a payload spelled under a name it had not thought of.

**And no refusal quotes what it refused.** An error names the rule and the position --
"entry 3", "entry 3, item 5" -- and never the key, the value, or its length. The first
version of these checks interpolated the offending key, which meant a bearer credential
used as a key was echoed by the very check that existed to catch that mistake, into an
exception that then travelled into a traceback and a retained CI log. The secret-shape
test now runs *before* the format test for the same reason, on keys as well as values, and
every refusal is raised outside any ``except`` block so nothing is attached as
``__cause__`` or ``__context__`` carrying the value instead.

**Whitespace and case are enumerated, not delegated.** The shape test applied to keys and
to string values is ``security/secrets.looks_like_secret``, which runs one explicit
normalization pipeline before matching -- an enumerated set of Unicode whitespace code
points folded to an ASCII space, then ``A``-``Z`` folded to ``a``-``z``, and nothing else
-- and ``firmbatch.secret_shape`` in migration ``0003`` performs the identical two folds in
the identical order.

Both halves of that were bypasses, and both were measured on a real server. Python's
``\\s`` and PostgreSQL's ``[[:space:]]`` are different sets, so ``"\\u00a0Bearer example"``
was refused here and accepted there. Python's ``re.IGNORECASE`` and PostgreSQL's ``~*`` are
Unicode and locale case folding respectively, so ``"\\u017Fecret=x"`` and
``"api\\u212Aey=x"`` were refused here and accepted there. In both cases the database is
the half that holds when a runtime role writes the call itself, which is the half a
disagreement actually costs something in.

The consequence worth knowing here: a **Unicode homoglyph of a marker is recognised by
neither implementation** now. That is deliberate and it is the honest trade -- see the
"what is deliberately not claimed" section of ``security/secrets.py``, and ADR 0006
decision 8c.
"""

from __future__ import annotations

import json
import math
import re
import uuid
from typing import Any, Mapping

from ..security.secrets import looks_like_secret

#: Boundary limits on a metadata document. The database's own check allows twice this,
#: because PostgreSQL renders ``jsonb::text`` with spaces that the canonical form here does
#: not -- the backstop has to leave room for the difference rather than reject documents
#: this module accepted.
MAX_METADATA_DOCUMENT_BYTES = 2048
MAX_METADATA_KEYS = 32
MAX_METADATA_STRING_LENGTH = 256
MAX_METADATA_SEQUENCE_LENGTH = 16

#: Metadata keys are identifiers, not free text. Applied with ``fullmatch``, so a trailing
#: newline cannot slip past ``$``.
METADATA_KEY_REGEX = re.compile(r"^[a-z][a-z0-9_]{0,62}$")

#: Key names that mean the content itself rather than a reference to it, matched **whole**
#: rather than as substrings. See the module docstring for why.
DENIED_METADATA_KEYS: frozenset[str] = frozenset(
    {
        # The content itself.
        "payload",
        "raw_payload",
        "payload_bytes",
        "body",
        "request_body",
        "response_body",
        "content",
        "blob",
        "bytes",
        "data",
        "text",
        "input",
        "input_text",
        "input_bytes",
        "output",
        "output_text",
        "output_bytes",
        "prompt",
        "prompt_text",
        "completion",
        "completion_text",
        "message",
        "messages",
        "ciphertext",
        "plaintext",
        # Credentials and the things that carry them.
        "password",
        "passwd",
        "secret",
        "client_secret",
        "secret_key",
        "private_key",
        "api_key",
        "apikey",
        "access_key",
        "token",
        "access_token",
        "refresh_token",
        "bearer_token",
        "session_token",
        "auth_token",
        "id_token",
        "credential",
        "credentials",
        "authorization",
        "auth",
        "cookie",
        "connection_string",
        "database_url",
        "dsn",
    }
)

_SCALARS = (str, int, float, bool, type(None), uuid.UUID)


class MetadataPolicyError(RuntimeError):
    """A result, event, identity or audit detail carried something that may not be stored."""


def canonical_json(value: Any) -> str:
    """A stable text rendering, so the same value always renders the same way.

    Sorted keys and no insignificant whitespace. ``allow_nan=False`` because ``NaN`` is
    not JSON, is not equal to itself, and would make a fingerprint that never matches.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False, default=_encode
    )


def _encode(value: Any) -> Any:
    if isinstance(value, uuid.UUID):
        return str(value)
    raise TypeError(
        f"{type(value).__name__} cannot be rendered deterministically. Give metadata JSON-native "
        "values (and UUIDs) so that the same document always produces the same digest."
    )


def _reject(where: str, why: str) -> None:
    """Refuse, naming the rule and the position and **never the content**.

    Raised directly rather than from inside an ``except`` block, so nothing is attached as
    ``__cause__`` or ``__context__`` that could carry the value this refused.
    """
    raise MetadataPolicyError(
        f"{where} {why}. These columns hold bounded metadata -- identifiers, counts, digests, and "
        "references to objects that live elsewhere. Customer payload belongs in S3; put its "
        "reference here. The offending value is deliberately not shown: a rejected key or value "
        "is unvetted input, and an error message is exactly the place a secret ends up being "
        "retained."
    )


def _at(index: int, item: "int | None" = None) -> str:
    """How a violation is located: by position, because the name may not be repeatable."""
    return f"entry {index}" if item is None else f"entry {index}, item {item}"


def _check_key(where: str, index: int, key: object) -> None:
    """Validate one key.

    The secret-shape test runs **first**, before the format test, because the format test
    is the one that used to interpolate the key into its message -- so a bearer credential
    used as a key was echoed by the very check that was supposed to catch a mistake. Now
    neither echoes, and the order is kept anyway: the more specific diagnosis is the more
    useful one.
    """
    shape = looks_like_secret(key)
    if shape is not None:
        _reject(where, f"has a key at {_at(index)} that looks like {shape}")
    if not isinstance(key, str) or not METADATA_KEY_REGEX.fullmatch(key):
        _reject(
            where,
            f"has a key at {_at(index)} that is not a lowercase identifier of at most 63 characters",
        )
    if key in DENIED_METADATA_KEYS:
        _reject(
            where,
            f"has a key at {_at(index)} that names content or a credential rather than a reference "
            "to one (a reference such as 'input_manifest_id', 'output_object_key' or "
            "'artifact_digest' is fine)",
        )


def _check_scalar(where: str, index: int, item: "int | None", value: object) -> None:
    where_at = _at(index, item)
    # Shape first, for the same reason as for keys, and because a value is the likelier
    # place for a credential to arrive.
    shape = looks_like_secret(value)
    if shape is not None:
        _reject(
            where,
            f"stores what looks like {shape} at {where_at}. Metadata carries references to secrets, "
            "never the secrets themselves; store a SecretReference or an opaque identifier instead",
        )
    if isinstance(value, (bytes, bytearray, memoryview)):
        _reject(where, f"stores raw bytes at {where_at}; binary values are refused outright")
    if not isinstance(value, _SCALARS):
        _reject(
            where,
            f"stores {type(value).__name__} at {where_at}; only strings, numbers, booleans, null "
            "and UUIDs fit",
        )
    if isinstance(value, str) and len(value) > MAX_METADATA_STRING_LENGTH:
        # The length is not reported either. It is a small leak on its own and a large one
        # for a short secret, where the length is most of what an attacker is missing.
        _reject(
            where,
            f"stores a string at {where_at} longer than the {MAX_METADATA_STRING_LENGTH} allowed",
        )
    # NaN and the infinities are not JSON. Caught here so the caller gets the policy
    # error that names the field, rather than a ValueError out of the encoder below.
    if isinstance(value, float) and not math.isfinite(value):
        _reject(where, f"stores a non-finite number at {where_at}, which is not representable in JSON")


def validated_metadata(value: Mapping[str, Any], *, where: str) -> dict[str, Any]:
    """Return ``value`` as a plain, storable dict, or refuse it.

    Flat by construction: one level of scalars is enough to name a row, count a thing, or
    reference an object, and a nested document is the shape a request body arrives in.
    """
    if not isinstance(value, Mapping):
        _reject(where, f"is {type(value).__name__}, not a mapping of names to values")
    if len(value) > MAX_METADATA_KEYS:
        _reject(where, f"has {len(value)} keys, over the {MAX_METADATA_KEYS} allowed")

    out: dict[str, Any] = {}
    for index, (key, item) in enumerate(value.items()):
        _check_key(where, index, key)
        if isinstance(item, (list, tuple)):
            if len(item) > MAX_METADATA_SEQUENCE_LENGTH:
                _reject(
                    where,
                    f"stores {len(item)} entries at {_at(index)}, over the "
                    f"{MAX_METADATA_SEQUENCE_LENGTH} allowed",
                )
            for position, entry in enumerate(item):
                _check_scalar(where, index, position, entry)
            out[key] = [str(e) if isinstance(e, uuid.UUID) else e for e in item]
            continue
        _check_scalar(where, index, None, item)
        out[key] = str(item) if isinstance(item, uuid.UUID) else item

    encoded = canonical_json(out).encode("utf-8")
    if len(encoded) > MAX_METADATA_DOCUMENT_BYTES:
        _reject(where, f"renders to {len(encoded)} bytes, over the {MAX_METADATA_DOCUMENT_BYTES} allowed")
    return out
