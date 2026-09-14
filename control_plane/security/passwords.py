"""Customer passwords: hashed with Argon2id in Python, verified in Python, stored as PHC text.

Milestone 3.1. This is the one place a customer's password is handled as a value, and the
one place the memory-hard key-derivation function is named. Everything about it is
deliberately conventional:

* **The implementation is ``argon2-cffi``**, the maintained binding to the reference
  Argon2 implementation. Firmbatch writes no cryptography of its own, here or anywhere
  (ADR 0006 decision 7); this module configures a library and calls it.
* **The algorithm is Argon2id** with the RFC 9106 second recommended parameter set: 64 MiB
  of memory, three passes, four lanes. Memory-hard, so that a leaked hash table costs an
  attacker memory bandwidth per guess rather than only compute.
* **Verification happens in Python, not in PostgreSQL.** PostgreSQL has no Argon2, and a
  ``crypt()`` bcrypt would not be memory-hard. So the runtime process is trusted for the
  password step -- it fetches the stored hash through ``firmbatch.login_lookup()`` and
  compares here -- and the database bounds what that trust buys: ``login_lookup`` looks up
  one account per call, records which account was challenged in a transaction-scoped row
  no runtime role can write, and ``firmbatch.open_browser_session()`` opens a session only
  for the account that was challenged in the same transaction. ADR 0009 states the
  limitation rather than implying the database verified the password.
* **A password is a :class:`~firmbatch.control_plane.security.secrets.Secret`** while it
  is a value at all: it arrives wrapped, is hashed or verified, and is not rendered, logged
  or stored by anything in this package. The only text that reaches a row is the PHC hash.
* **Unknown accounts cost the same as wrong passwords.** :func:`verify_password` is called
  against :data:`DUMMY_HASH` when there is no account, so the login path's duration does
  not depend on whether the email exists.

What is stored is the PHC string ``argon2-cffi`` renders (``$argon2id$v=19$m=...``), which
carries its own parameters, so a later parameter change is a readable fact per row and
:func:`needs_rehash` says which rows are behind.
"""

from __future__ import annotations

import os
import re
import threading
from contextlib import contextmanager

from argon2 import PasswordHasher
from argon2 import exceptions as _argon2_exceptions
from argon2.low_level import Type as _Argon2Type

from .secrets import Secret, SecretError

#: The RFC 9106 second recommended parameter set for Argon2id: 64 MiB, 3 passes, 4 lanes.
#: Stated as data so a test can read it and so a change is a diff rather than a surprise.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 65536
ARGON2_PARALLELISM = 4
ARGON2_HASH_LENGTH = 32
ARGON2_SALT_LENGTH = 16

#: Bounds on the password itself. The lower bound is a floor on guessability; the upper
#: bound is a denial-of-service bound, because a KDF's cost grows with input length and a
#: request body is caller-controlled. Measured in **bytes** of UTF-8, which is what the KDF
#: consumes, so a password of multi-byte characters is bounded the same way.
PASSWORD_MIN_BYTES = 12
PASSWORD_MAX_BYTES = 256

#: The stored form, and the only text this module lets reach a row. Argon2id, version 19,
#: the three parameters, then salt and hash in the unpadded base64 the library renders.
#: Mirrored in migration ``0005`` as the check constraint on the stored column, so a writer
#: that reached the table another way still cannot store a plaintext or a bcrypt hash.
PASSWORD_HASH_REGEX = (
    r"^\$argon2id\$v=19\$m=[0-9]{1,9},t=[0-9]{1,4},p=[0-9]{1,3}"
    r"\$[A-Za-z0-9+/]{16,}\$[A-Za-z0-9+/]{16,}$"
)
_PASSWORD_HASH_PATTERN = re.compile(PASSWORD_HASH_REGEX)
PASSWORD_HASH_MAX_LENGTH = 512

_HASHER = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST_KIB,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LENGTH,
    salt_len=ARGON2_SALT_LENGTH,
    type=_Argon2Type.ID,
)


class PasswordPolicyError(SecretError):
    """The password is outside the bounds this system accepts. Never carries the value."""


class KDFUnavailableError(SecretError):
    """The memory-hard admission gate is saturated, so this Argon2 work was not admitted.

    Milestone 3.1 security correction. Argon2id is memory-hard by design -- each call holds
    64 MiB -- so an unauthenticated flood of logins, signups or recovery completions could
    exhaust the process. This is raised when the bounded admission gate cannot be entered in
    time; the HTTP boundary renders it as a deterministic 503, the same answer whether or not
    the address exists, so it discloses nothing an attacker did not already hold. It never
    carries the password or any value.
    """


def _positive_int_env(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= 1 else default


def _positive_float_env(name: str, default: float) -> float:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value >= 0 else default


#: Environment knobs for the KDF admission gate. Bounded work, not unlimited: the maximum
#: number of Argon2 operations that may run at once, and how long a caller waits for a slot
#: before it is turned away. Defaults are conservative -- a handful of concurrent 64 MiB
#: hashes -- and every deployment may tighten them. A production edge or WAF rate limit is
#: additive to this, never a substitute: this gate holds even when the process is reached
#: directly, which is the failure the finding is about.
KDF_MAX_CONCURRENCY_VAR = "FIRMBATCH_KDF_MAX_CONCURRENCY"
KDF_ACQUIRE_TIMEOUT_VAR = "FIRMBATCH_KDF_ACQUIRE_TIMEOUT_SECONDS"
DEFAULT_KDF_MAX_CONCURRENCY = 8
DEFAULT_KDF_ACQUIRE_TIMEOUT_SECONDS = 5.0


class KDFAdmissionGate:
    """A bounded semaphore around memory-hard work, with a fail-closed wait.

    Every :func:`hash_password` and :func:`verify_password` call passes through this, so the
    number of Argon2 operations in flight is bounded regardless of how many requests arrive.
    A caller that cannot acquire a slot within the timeout is turned away with
    :class:`KDFUnavailableError` rather than piling on more allocation. Known and unknown
    accounts pass through the gate identically -- login verifies a dummy hash for an unknown
    address -- so saturation cannot be used to tell them apart.
    """

    def __init__(self, max_concurrency: int, acquire_timeout: float) -> None:
        self.max_concurrency = max(1, int(max_concurrency))
        self.acquire_timeout = max(0.0, float(acquire_timeout))
        self._semaphore = threading.BoundedSemaphore(self.max_concurrency)

    @contextmanager
    def admit(self):
        acquired = self._semaphore.acquire(timeout=self.acquire_timeout)
        if not acquired:
            raise KDFUnavailableError(
                "the authentication service is at capacity and did not admit this request; "
                "retry shortly. The value and whether any account exists are not disclosed."
            )
        try:
            yield
        finally:
            self._semaphore.release()


#: The process-wide gate. A module-level singleton so every caller shares one budget; a test
#: may replace it with a tighter one to prove saturation is turned away deterministically.
KDF_GATE = KDFAdmissionGate(
    max_concurrency=_positive_int_env(KDF_MAX_CONCURRENCY_VAR, DEFAULT_KDF_MAX_CONCURRENCY),
    acquire_timeout=_positive_float_env(KDF_ACQUIRE_TIMEOUT_VAR, DEFAULT_KDF_ACQUIRE_TIMEOUT_SECONDS),
)


def _require_password(password: object) -> str:
    if not isinstance(password, Secret):
        # Refused by type rather than by value: a plain string is exactly what ends up in
        # a log line, and the refusal must not be the thing that renders it.
        raise PasswordPolicyError("a password is handled as a Secret, never as a plain string")
    value = password.reveal()
    encoded = value.encode("utf-8")
    if len(encoded) < PASSWORD_MIN_BYTES:
        raise PasswordPolicyError(
            f"the password is shorter than the {PASSWORD_MIN_BYTES}-byte minimum. The value and "
            "its exact length are deliberately not repeated."
        )
    if len(encoded) > PASSWORD_MAX_BYTES:
        raise PasswordPolicyError(
            f"the password is longer than the {PASSWORD_MAX_BYTES}-byte maximum. The value and "
            "its exact length are deliberately not repeated."
        )
    if "\x00" in value:
        raise PasswordPolicyError("the password contains a NUL character, which no KDF input may")
    return value


def hash_password(password: Secret) -> str:
    """The PHC-encoded Argon2id hash of ``password``. The only stored form.

    The memory-hard work runs inside the admission gate, so a flood of signups or recovery
    completions cannot spawn unbounded concurrent 64 MiB allocations; the input is validated
    first, so a malformed password is refused without occupying a slot.
    """
    validated = _require_password(password)
    with KDF_GATE.admit():
        rendered = _HASHER.hash(validated)
    if not is_well_formed_password_hash(rendered):  # pragma: no cover - library invariant
        raise PasswordPolicyError("the password hasher rendered a hash in an unexpected format")
    return rendered


def verify_password(stored_hash: str, password: Secret) -> bool:
    """Whether ``password`` is the one ``stored_hash`` was derived from.

    ``False`` for a wrong password and for a malformed hash alike, and never an exception
    that carries either. A malformed stored hash is a data-integrity problem the caller
    cannot act on at login time, and distinguishing it from a wrong password would tell a
    caller something about the account.
    """
    if not isinstance(password, Secret):
        raise PasswordPolicyError("a password is handled as a Secret, never as a plain string")
    if not is_well_formed_password_hash(stored_hash):
        return False
    # The memory-hard verification runs inside the admission gate, so an unauthenticated
    # login flood -- including one against the dummy hash for unknown addresses -- cannot
    # spawn unbounded concurrent Argon2 work. The gate is entered the same way for a known
    # and an unknown account, so overload never becomes an existence oracle.
    with KDF_GATE.admit():
        try:
            return bool(_HASHER.verify(stored_hash, password.reveal()))
        except _argon2_exceptions.VerifyMismatchError:
            return False
        except _argon2_exceptions.Argon2Error:
            return False


def needs_rehash(stored_hash: str) -> bool:
    """Whether ``stored_hash`` was produced with parameters older than the current ones."""
    if not is_well_formed_password_hash(stored_hash):
        return True
    return bool(_HASHER.check_needs_rehash(stored_hash))


def is_well_formed_password_hash(value: object) -> bool:
    """Whether ``value`` has the stored shape. A plaintext, or a bcrypt hash, does not.

    Structure alone decides it: text, at most :data:`PASSWORD_HASH_MAX_LENGTH` characters,
    and an exact match of :data:`PASSWORD_HASH_REGEX`. The generic secret-shape recogniser is
    deliberately **not** applied here (migration ``0007``, found by Milestone 3.3b's
    verification). A PHC hash's salt and digest are random base64, which forms an AWS
    access-key-id shape by chance, so the scan refused valid hashes -- including
    :func:`hash_password`'s own output -- at random. Nothing but an Argon2id PHC hash matches
    the pattern. The raw password is validated before hashing (:func:`_require_password`), and
    the recogniser still applies to every other value it guards.
    """
    return (
        isinstance(value, str)
        and len(value) <= PASSWORD_HASH_MAX_LENGTH
        and _PASSWORD_HASH_PATTERN.fullmatch(value) is not None
    )


#: A real Argon2id hash of a value nobody knows, verified against when the login path finds
#: no account -- so that "no such account" costs the same as "wrong password". Computed
#: once at import from a random 32-byte value that is then discarded.
def _dummy_hash() -> str:
    import secrets as _stdlib_secrets

    return _HASHER.hash(_stdlib_secrets.token_urlsafe(32))


DUMMY_HASH = _dummy_hash()
