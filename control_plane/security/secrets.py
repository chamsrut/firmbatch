"""The four kinds of secret this system has, as types that cannot leak by accident.

Milestone 2.3 implements the *model* and not the infrastructure. There is no AWS SDK
here, no call to Secrets Manager, no KMS request, and no cryptography of Firmbatch's own
invention. What there is: a type for each class of secret, a boundary each one may not
cross, and a production path that **fails closed** rather than falling back to plaintext
or to a test double. The adapters that talk to AWS are Milestone 8's, and they are
declared here as explicitly unimplemented so that reaching for one in production raises
instead of silently doing something cheaper.

The four classes, and what distinguishes them
---------------------------------------------

1. **High-entropy bearer credentials** -- :class:`Secret`. A random token of the shape
   :data:`BEARER_CREDENTIAL_REGEX` describes, displayed **once** at creation and stored
   only as a one-way fingerprint computed *by the database*.

   The one that a running system issues is minted **inside**
   ``firmbatch.register_auth_binding``, not here: a caller that could submit a candidate
   could submit somebody else's and learn from the outcome whether it already existed.
   :func:`generate_bearer_credential` mints the same shape for tests and for anything that
   needs a value of this kind without a database, and it is deliberately *not* on the
   registration path.

   There is likewise no function here that turns a secret into the value stored, because a
   Python-side fingerprint is one refactor away from being written to a column. Revocable
   and rotatable: revoking sets ``revoked_at`` on the binding, rotating is a new binding
   plus a revocation.

2. **Reversible operational and provider secrets** -- :class:`SecretReference`. A provider
   API key has to be *used*, so it cannot be a one-way digest; it therefore never appears
   in an ordinary product table at all. What a product row may hold is an opaque
   reference: a backend, a name, and optionally a version. Resolution happens in the one
   service role that owns the secret (target architecture 2.1: provider credentials live
   with the controller/reconciler, not with the API, the validator or a worker), through
   a :class:`SecretResolver`.

3. **Encrypted values** -- :class:`EncryptedValue`. A versioned ciphertext envelope plus an
   opaque :class:`KeyReference`. The scheme version is inside the envelope so that a key
   rotation or an algorithm change is a readable fact about each stored value rather than
   a deployment note. The plaintext is never a field, never rendered, and never
   serialized.

4. **Migration-owner credentials** -- represented by the migration settings type in
   ``control_plane/config.py``, loaded by the migration entry point and by nothing else.
   There is no attribute on the application settings that could hold one and no loader
   that returns both, and ``scripts/check-runtime-imports.py --static`` asserts statically
   that no runtime module can even ask. That class of secret has no type in this module on
   purpose: giving it one here would put it in the import graph of every process that
   handles the other three.

:data:`SECRET_CLASSES` states all four as data, so the model is something a test can
check rather than a paragraph somebody has to keep true.

Redaction
---------

:class:`Secret`, :class:`EncryptedValue` and every exception this module raises render
nothing of the value they carry -- **not even its length**, because a length is
information about a short secret. ``repr``, ``str``, ``format``, ``pickle`` and ``copy``
are all closed off, so a secret cannot reach a log line, a traceback, an f-string, or a
captured test artifact without somebody writing ``.reveal()``, which is greppable.

:func:`looks_like_secret` is the other direction: a small set of shapes that mean
"somebody put a credential where a reference belongs", used by the audit and metadata
policies to refuse the obvious mistake **before** a row is written. It is defense in
depth and not a proof -- no pattern can tell a secret from a string that merely looks
ordinary -- but the one shape it recognises with certainty is Firmbatch's own credential
format, because this module defines it.

One normalization pipeline, and why every step of it is written out
-------------------------------------------------------------------

Several of the shapes below are separator- and case-sensitive: an authorization header is
a word, some whitespace and a token; an assignment is a name, optional whitespace, ``=``
and a value. The same rule runs **twice** -- here, and inside PostgreSQL as
``firmbatch.secret_shape`` -- and the database copy is the one that holds when a runtime
role writes the call itself, with no Python in front of it. Two implementations of one
rule only work if they answer alike, and twice they did not:

* **Whitespace.** ``\\s`` in Python is Unicode; ``[[:space:]]`` in PostgreSQL is decided by
  the server's ``lc_ctype``. Measured on a real PostgreSQL 16 server: U+0085, U+00A0,
  U+2007, U+202F and the four ASCII information separators are whitespace to Python and
  not to PostgreSQL. So ``"\\u00a0Bearer example"`` and ``"token\\u00a0=example"`` were
  refused here and **stored** there.
* **Case.** ``re.IGNORECASE`` in Python is Unicode case folding; ``~*`` in PostgreSQL is
  locale case folding. Measured the same way: ``"\\u017Fecret=x"`` (LATIN SMALL LETTER LONG
  S) and ``"api\\u212Aey=x"`` (KELVIN SIGN) were refused here and **accepted** there.

The correction is the same both times: stop asking either engine what a character *is*.
One pipeline, :func:`normalize_for_shape_scan`, applied before any pattern runs:

1. fold every code point in :data:`WHITESPACE_CODE_POINTS` -- all 29, enumerated, checked
   against Python's own ``\\s`` by a test -- to a plain ASCII space;
2. fold ``A``-``Z`` to ``a``-``z`` (:data:`ASCII_UPPERCASE`), and nothing else;
3. match **case-sensitive** lowercase patterns against the result.

``firmbatch.secret_shape`` performs those two folds in that order with nested
``translate()`` calls, which map code point to code point and consult no locale, and it
carries a character-for-character copy of the pattern text. No pattern in either place
contains ``\\s``, ``\\b``, ``\\y``, ``\\w``, ``[[:...:]]``, ``~*`` or ``(?i)`` -- an ASCII
word boundary is spelled :data:`ASCII_WORD_BOUNDARY_BEFORE` in both. The two agree by
construction rather than by coincidence, and tests assert the pattern text is identical
rather than merely that the answers matched on the samples somebody thought of.

What is deliberately preserved, and what is deliberately not claimed
--------------------------------------------------------------------

**Non-ASCII text is carried through unchanged.** Accented Latin, CJK, Cyrillic, Greek, an
emoji in a note, and Turkish ``İ``/``ı`` are all valid metadata and stay valid. Rejecting
non-ASCII would have closed both gaps and made a note in most of the world's scripts
unstorable.

**And therefore a homoglyph is not detected.** ``"\\u017Fecret=x"`` is now refused by
neither implementation, where before it was refused by one. That is the honest consequence
of an explicit ASCII fold, and it is the right trade: the alternative is a Unicode fold
that PostgreSQL cannot reproduce, which buys a detection in the half a caller can bypass
and loses the agreement in the half that cannot be. :func:`looks_like_secret` is **defense
in depth against the obvious mistake** -- a credential pasted where a reference belongs.
It has never claimed to recognise a semantic secret, and it does not claim to survive a
Unicode homoglyph attack. The proof that customer payload never reaches this database is
Milestone 5's data-flow path, not this denylist; ADR 0005 decision 9 says so at length.
"""

from __future__ import annotations

import hmac
import re
import secrets as _stdlib_secrets
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from ..config import Environment

# --------------------------------------------------------------------------- bearer

#: The prefix every Firmbatch bearer credential carries. It exists so that a credential is
#: recognisable on sight -- in a bug report, a log scan, or :func:`looks_like_secret` --
#: and so that a leaked one can be searched for.
CREDENTIAL_PREFIX = "fbk_"

#: 32 random bytes, rendered by ``secrets.token_urlsafe`` as 43 URL-safe characters.
#: **256 bits** of entropy, because that is what 32 random bytes are. Brute force is not a
#: threat model at this width, which is why the stored fingerprint is a plain digest rather
#: than a password-hashing function: a slow KDF defends a *guessable* secret, this one is
#: not guessable, and a per-request KDF on the authentication path would be a
#: denial-of-service surface bought for nothing.
#:
#: The database mints the same 43 characters from two ``gen_random_uuid()`` values, which
#: is **244 bits** -- 122 each -- from PostgreSQL's strong RNG, without requiring an
#: extension. The two numbers are different and are written down as they are. Neither is
#: the length of anything: 43 characters is what base64 of 32 bytes renders as, and the
#: rendering is not the entropy. Both are unguessable, and having one credential format is
#: worth more than having the larger number twice.
CREDENTIAL_ENTROPY_BYTES = 32

#: What the database's own generator produces, stated here so the number lives beside the
#: Python one rather than only in a migration comment. Two UUIDv4 values, 122 random bits
#: each. ``tests/test_secrets_model.py`` asserts the arithmetic rather than trusting the
#: sentence.
DATABASE_CREDENTIAL_ENTROPY_BITS = 244
UUID4_ENTROPY_BITS = 122

BEARER_CREDENTIAL_REGEX = re.compile(r"^fbk_[A-Za-z0-9_-]{43}$")

#: The digest PostgreSQL stores in place of a credential, named here so the three places
#: that care agree: migration ``0003`` computes it, ``db/auth.py`` documents it, and the
#: tests assert that no row anywhere contains the credential itself.
#:
#: The expression is, exactly:
#:
#:     encode(sha256(convert_to(secret, 'UTF8')), 'hex')
#:
#: computed **inside** ``firmbatch.register_auth_binding`` and
#: ``firmbatch.bind_authenticated_context``. It is never stored, never logged by this
#: package, and never returned by any query.
#:
#: On registration the credential does not travel at all: the database generates it and
#: returns it once, which is what removed the cross-tenant existence oracle a
#: caller-supplied candidate created. On authentication it travels once, as a bound
#: parameter -- out of line, so it is not in the statement text or in
#: ``pg_stat_activity`` -- and ``db/auth.py`` scrubs it from any unexpected error rather
#: than letting a ``DBAPIError`` render it with the rest of the parameters.
FINGERPRINT_ALGORITHM = "sha256"


class _Missing:
    """The sentinel every lookup in this module uses instead of catching ``KeyError``.

    A dict subscript that misses builds ``KeyError(key)``, and here the key is a
    ciphertext or a reference. Its own ``repr`` renders it, and raising from inside the
    handler attaches it to whatever is raised next. So nothing in this module subscripts a
    dict whose key it would not be willing to print.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return "<missing>"


_MISSING = _Missing()


class SecretError(RuntimeError):
    """Base class for every refusal in this module. Never carries a secret value."""


class SecretBackendUnavailable(SecretError):
    """The backend that would resolve or decrypt this value is not implemented here."""


class SecretHandlingError(SecretError):
    """A secret was about to be rendered, serialized, or copied somewhere it may not go."""


class Secret:
    """A high-entropy bearer value that must not be rendered by accident.

    The wrapper is the point. A plain ``str`` reaches a log line, an f-string, a
    traceback, a pytest fixture repr and a JSON body without anybody deciding that it
    should; this type makes every one of those a refusal or a redaction, and leaves
    exactly one way out -- :meth:`reveal` -- which is a word that can be grepped for in
    review.

    Not a dataclass: a dataclass would generate a ``repr`` containing the field, and the
    generated ``__eq__`` would compare with ``==`` rather than in constant time.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or not value:
            # The value is not interpolated: if it is the wrong type, saying so is enough,
            # and if it is a short string, echoing it here would be the leak.
            raise SecretHandlingError("a Secret wraps a non-empty string")
        self._value = value

    def reveal(self) -> str:
        """The value itself. The only way out, and deliberately conspicuous."""
        return self._value

    def __repr__(self) -> str:
        # No length, no prefix, no suffix. A four-character secret and a hundred-character
        # one render identically, because the length of a short secret is a large clue.
        return "Secret(<redacted>)"

    __str__ = __repr__

    def __format__(self, _spec: str) -> str:
        # f"{secret}" and "{}".format(secret) both land here.
        return repr(self)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        return hmac.compare_digest(self._value, other._value)

    #: Deliberately unhashable. A hashable secret ends up as a dict key, and dict keys end
    #: up in reprs of the dict.
    __hash__ = None  # type: ignore[assignment]

    def __reduce__(self, *_args):
        raise SecretHandlingError(
            "a Secret cannot be pickled or copied: serializing it is how it reaches a cache, a "
            "queue, or a crash dump. Pass the Secret object, or call reveal() at the one place "
            "that genuinely needs the value."
        )

    # Every route into pickle and copy, closed with the same explanation rather than with
    # a ``None`` attribute that would surface as an unhelpful TypeError.
    __reduce_ex__ = __getstate__ = __copy__ = __deepcopy__ = __reduce__


def generate_bearer_credential() -> Secret:
    """Mint one 256-bit credential. Shown once by the caller, then never again.

    256 bits because :data:`CREDENTIAL_ENTROPY_BYTES` is 32 random bytes. The credential
    PostgreSQL generates inside ``firmbatch.register_auth_binding`` shares this format and
    carries :data:`DATABASE_CREDENTIAL_ENTROPY_BITS` -- 244 -- instead. Both numbers are
    exact; neither is the 43-character length of the rendering.

    The caller is responsible for the "once": this module cannot enforce it, and says so
    rather than implying otherwise. What it does enforce is that the value never reaches
    a row -- ``firmbatch.register_auth_binding`` hashes it in the database and stores the
    digest.
    """
    return Secret(CREDENTIAL_PREFIX + _stdlib_secrets.token_urlsafe(CREDENTIAL_ENTROPY_BYTES))


def is_well_formed_credential(value: object) -> bool:
    """Whether ``value`` has the shape of a Firmbatch credential.

    Used to refuse a malformed credential **before** it reaches PostgreSQL, so that a
    typo, a truncated copy-paste or an entirely different kind of token produces an
    explanatory error rather than an authentication failure that looks like a revoked
    credential.
    """
    if isinstance(value, Secret):
        value = value.reveal()
    return isinstance(value, str) and BEARER_CREDENTIAL_REGEX.fullmatch(value) is not None


# ------------------------------------------------------------- shape recognition

#: Every code point this package treats as whitespace, stated as data rather than
#: delegated to a regular-expression dialect.
#:
#: It is exactly the set Python's ``\s`` matches for ``str`` -- the Unicode
#: ``White_Space`` property plus the four ASCII information separators U+001C..U+001F --
#: and ``tests/test_secrets_model.py`` asserts that equality rather than trusting this
#: comment, so a Python upgrade that widened ``\s`` would fail the suite instead of
#: silently reopening the gap.
#:
#: Written as integers, in ascending order, because the characters themselves are
#: invisible in a source file and a reviewer cannot tell U+00A0 from a space by looking.
#: ``db/migrations/versions/0003_auth_context_and_audit.py`` carries the identical list
#: and renders it as a PostgreSQL ``U&'...'`` literal; the corpus test in
#: ``tests/test_audit_events.py`` compares the two implementations' answers on every one
#: of them.
WHITESPACE_CODE_POINTS: tuple[int, ...] = (
    0x0009,  # CHARACTER TABULATION
    0x000A,  # LINE FEED
    0x000B,  # LINE TABULATION
    0x000C,  # FORM FEED
    0x000D,  # CARRIAGE RETURN
    0x001C,  # INFORMATION SEPARATOR FOUR
    0x001D,  # INFORMATION SEPARATOR THREE
    0x001E,  # INFORMATION SEPARATOR TWO
    0x001F,  # INFORMATION SEPARATOR ONE
    0x0020,  # SPACE
    0x0085,  # NEXT LINE
    0x00A0,  # NO-BREAK SPACE
    0x1680,  # OGHAM SPACE MARK
    0x2000,  # EN QUAD
    0x2001,  # EM QUAD
    0x2002,  # EN SPACE
    0x2003,  # EM SPACE
    0x2004,  # THREE-PER-EM SPACE
    0x2005,  # FOUR-PER-EM SPACE
    0x2006,  # SIX-PER-EM SPACE
    0x2007,  # FIGURE SPACE
    0x2008,  # PUNCTUATION SPACE
    0x2009,  # THIN SPACE
    0x200A,  # HAIR SPACE
    0x2028,  # LINE SEPARATOR
    0x2029,  # PARAGRAPH SEPARATOR
    0x202F,  # NARROW NO-BREAK SPACE
    0x205F,  # MEDIUM MATHEMATICAL SPACE
    0x3000,  # IDEOGRAPHIC SPACE
)

#: The one character every member of :data:`WHITESPACE_CODE_POINTS` is folded to. Plain
#: ASCII, so both dialects agree about it without consulting anything.
NORMALIZED_WHITESPACE = " "

#: The **only** case mapping this package performs, written out so that neither
#: implementation consults a Unicode table or a locale.
#:
#: Twenty-six pairs, and deliberately not one more. ``str.lower()`` and ``str.casefold()``
#: are Unicode operations -- ``casefold`` maps U+017F LATIN SMALL LETTER LONG S to ``s``
#: and U+212A KELVIN SIGN to ``k`` -- and PostgreSQL's ``lower()`` and ``~*`` are decided by
#: the server's ``lc_ctype``. Measured on a real PostgreSQL 16 server: with Python's
#: ``re.IGNORECASE``, ``ſecret=x`` (U+017F) and ``apiKey=x`` (U+212A) were **refused by
#: Python and accepted by the database**, which is the half that holds when a runtime role
#: writes the ``INSERT`` itself.
#:
#: So the fold is ASCII and explicit. A non-ASCII character is carried through unchanged by
#: both implementations, which means both give it the same answer -- see the honest
#: limitation in the module docstring.
ASCII_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ASCII_LOWERCASE = "abcdefghijklmnopqrstuvwxyz"

_WHITESPACE_TRANSLATION = {code: NORMALIZED_WHITESPACE for code in WHITESPACE_CODE_POINTS}
_ASCII_CASE_TRANSLATION = {
    ord(upper): lower for upper, lower in zip(ASCII_UPPERCASE, ASCII_LOWERCASE)
}


def normalize_whitespace(value: str) -> str:
    """Fold every code point in :data:`WHITESPACE_CODE_POINTS` to an ASCII space.

    Step one of :func:`normalize_for_shape_scan`. Everything that is not in that enumerated
    set is left exactly as it was -- this is a separator fold, not a normalisation of the
    string.
    """
    return value.translate(_WHITESPACE_TRANSLATION)


def fold_ascii_case(value: str) -> str:
    """Map ``A``-``Z`` to ``a``-``z``. Nothing else, in any script.

    Step two of :func:`normalize_for_shape_scan`. Explicitly **not** ``str.lower()`` or
    ``str.casefold()``: both are Unicode operations that fold characters PostgreSQL's
    ``translate()`` will not, and the disagreement is the defect this exists to remove.
    """
    return value.translate(_ASCII_CASE_TRANSLATION)


def normalize_for_shape_scan(value: str) -> str:
    """The one normalisation pipeline the shape patterns are matched against.

    Whitespace first, then ASCII case -- and the order is stated because
    ``firmbatch.secret_shape`` performs the identical two steps in the identical order with
    nested ``translate()`` calls. The two mappings touch disjoint code points, so the order
    does not change the result; it is fixed anyway, because "the same pipeline" is easier to
    keep true than "an equivalent pipeline".

    The result is used for **matching only**. It is never stored, returned, logged or
    reported: the caller gets the name of a shape, never the text that matched it.
    """
    return fold_ascii_case(normalize_whitespace(value))


#: An ASCII-only word boundary, spelled the same way in both implementations.
#:
#: Not ``\b`` and not PostgreSQL's ``\y``. ``\b`` follows Python's Unicode ``\w``,
#: ``\y`` follows PostgreSQL's locale-dependent ``[[:alnum:]]``, and there is no reason to
#: expect two different tables to classify the same character alike -- which is the same
#: shape of bug as the case fold, one clause over. The scanned text has already had ASCII
#: case folded, so ``[0-9a-z_]`` is the complete ASCII word-character class for it.
#:
#: The consequence is deliberate: a non-ASCII letter counts as a boundary, so
#: ``ıtoken=x`` is recognised where ``\b`` and ``\y`` both used to say nothing. That is the
#: stricter direction, and both implementations now say it together.
ASCII_WORD_BOUNDARY_BEFORE = "(?<![0-9a-z_])"
ASCII_WORD_BOUNDARY_AFTER = "(?![0-9a-z_])"


#: Shapes that mean "this is a credential, not a reference to one". Each entry is
#: ``(name, pattern)``; only the *name* is ever reported, so a refusal cannot echo the
#: value it refused.
#:
#: The first entry is the one this module can be certain about, because this module
#: defines the format. The rest are common shapes worth catching at the boundary.
#:
#: Matched against :func:`normalize_for_shape_scan` output, and that is why every pattern
#: here is **lowercase, case-sensitive, and free of every character-class shorthand**:
#:
#: * no ``\s``/``\S`` -- after the whitespace fold the only whitespace that can still be
#:   present is an ASCII space, so ``[ ]`` and ``[^ ]`` say it exactly, and say the same
#:   thing in PostgreSQL, which ``[[:space:]]`` did not;
#: * no ``re.IGNORECASE`` and no ``(?i)`` -- after the ASCII case fold there is no ASCII
#:   uppercase left to match, and Python's Unicode case-insensitivity disagreed with
#:   PostgreSQL's locale-dependent ``~*`` on U+017F and U+212A;
#: * no ``\b`` -- Python's boundary follows Unicode ``\w`` and PostgreSQL's ``\y`` follows
#:   the server's locale. :data:`ASCII_WORD_BOUNDARY_BEFORE` spells it out instead.
#:
#: What is left is pattern text that means the same thing in both engines because it
#: contains nothing either engine has to look up. :data:`SECRET_SHAPE_PATTERNS` below is
#: that text, and migration ``0003`` carries a character-for-character copy of it, which a
#: test compares rather than trusts.
#:
#: **Defense in depth, not proof.** No pattern can establish that a string is not a
#: secret; a credential spelled in a format nobody anticipated passes every one of these.
#: What they buy is that the obvious mistake is refused where the caller gets a clear
#: error, which is the same claim ADR 0005 makes about the metadata denylist.
SECRET_SHAPE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("a Firmbatch bearer credential", r"fbk_[a-z0-9_-]{43}"),
    ("a PEM-encoded key block", r"-----begin [a-z ]*private key-----"),
    ("an HTTP authorization header value", r"^ *(bearer|basic) +[^ ]"),
    ("a database URL carrying a password", r"^[a-z][a-z0-9+.-]*://[^/ :@]+:[^/ @]+@"),
    (
        "an AWS access key id",
        ASCII_WORD_BOUNDARY_BEFORE + r"(akia|asia)[0-9a-z]{16}" + ASCII_WORD_BOUNDARY_AFTER,
    ),
    (
        "a private key or token assignment",
        ASCII_WORD_BOUNDARY_BEFORE + r"(secret|password|token|api[_-]?key) *[=:] *[^ ]",
    ),
)

#: The compiled form. ``re.ASCII`` buys nothing today -- no pattern above uses a shorthand
#: it would affect -- and is set anyway, so that a future ``\w`` or ``\d`` added here is
#: ASCII by default rather than quietly Unicode.
SECRET_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern, re.ASCII)) for name, pattern in SECRET_SHAPE_PATTERNS
)


def looks_like_secret(value: object) -> str | None:
    """The name of the secret shape ``value`` matches, or ``None``.

    Returns a *description*, never the value or any part of it, so that the refusal it
    produces can be raised, logged and captured without becoming the leak it prevents.

    The value goes through :func:`normalize_for_shape_scan` first -- whitespace folded to
    ASCII space, then ``A``-``Z`` folded to ``a``-``z``, and nothing else touched. See the
    module docstring for the two measurements that made each step necessary. The
    normalised text is used for matching only and is never stored, returned, or reported.

    Defined **above** the reference types on purpose: they call it from
    ``__post_init__``, and one of them is constructed at class-definition time as a default.
    ``EncryptedValue`` is referenced from inside the body and so resolves when called,
    which is always after the module has finished importing.
    """
    if isinstance(value, (Secret, EncryptedValue)):
        return "a secret value object"
    if not isinstance(value, str):
        return None
    scanned = normalize_for_shape_scan(value)
    for name, pattern in SECRET_VALUE_PATTERNS:
        if pattern.search(scanned):
            return name
    return None


# ------------------------------------------------------------------- references

class SecretBackend(str, Enum):
    """Where a reversible secret actually lives. Never in a Firmbatch product table."""

    #: The production backend. Resolved by the owning service role at Milestone 8.
    AWS_SECRETS_MANAGER = "aws-secrets-manager"
    #: An in-process store used by tests only. Refused in production.
    IN_MEMORY = "in-memory"


_REFERENCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/_.-]{0,255}$")
_REFERENCE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _require_non_secret(value: object, *, field: str) -> None:
    """Refuse a value that carries a recognisable secret shape, without repeating it.

    Runs **before** any format validation, and that order is the correction rather than a
    detail. The format check is the one that used to interpolate its input, so a bearer
    credential handed to a reference field was echoed by the very check that existed to
    notice it -- into an exception, a traceback and a retained log. Now nothing echoes,
    and the shape test runs first anyway so the diagnosis names what was actually wrong.
    """
    shape = looks_like_secret(value)
    if shape is not None:
        raise SecretError(
            f"the {field} looks like {shape}. A reference names where a secret lives; it is not "
            "the secret. The value is deliberately not repeated here -- an error message is "
            "exactly where one ends up being retained."
        )


def _require_reference_field(value: object, pattern: "re.Pattern[str]", *, field: str) -> None:
    """Shape first, then format, and neither says what it was given."""
    _require_non_secret(value, field=field)
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise SecretError(
            f"the {field} is not acceptable; it must match {pattern.pattern}. A reference is an "
            "identifier, so it is bounded and printable -- if a value needs to be secret it is "
            "not a reference. The value is deliberately not repeated here."
        )


@dataclass(frozen=True, repr=False)
class SecretReference:
    """An opaque pointer to a reversible secret. Safe to store, log and audit.

    This is what a product row holds where a naive design would hold the API key: a
    backend, a name, and optionally a version. It is not sensitive -- knowing that a
    provider credential is called ``firmbatch/prod/verda-api-key`` grants nothing without
    the IAM identity that may read it -- which is exactly why the indirection is worth
    having.

    That safety depends on the name really being a name. A caller that puts a credential
    in this field would otherwise have put it somewhere this system treats as printable,
    so the constructor refuses a value that carries a secret shape before it validates the
    format, and neither refusal repeats what it was given. ``repr`` is written out for the
    same reason: a generated one is a promise about fields nobody re-reads when a field is
    added.
    """

    backend: SecretBackend
    name: str
    version: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.backend, SecretBackend):
            _require_non_secret(self.backend, field="secret backend")
            raise SecretError("the secret backend is not a SecretBackend")
        _require_reference_field(self.name, _REFERENCE_NAME, field="secret name")
        if self.version is not None:
            _require_reference_field(self.version, _REFERENCE_VERSION, field="secret version")

    def __repr__(self) -> str:
        # Every field here has been checked to be an identifier, so rendering it is the
        # point: a reference that could not be printed would be useless in a traceback.
        version = f", version={self.version!r}" if self.version is not None else ""
        return f"SecretReference(backend={self.backend.value!r}, name={self.name!r}{version})"

    __str__ = __repr__


class SecretResolver(Protocol):
    """Turns a reference into the value. Implemented once per backend, per service role."""

    def resolve(self, reference: SecretReference) -> Secret:  # pragma: no cover - protocol
        ...


@dataclass(frozen=True)
class UnimplementedSecretResolver:
    """The production resolver, and it does not resolve anything yet.

    Milestone 8 replaces the body with an AWS Secrets Manager call made by the owning
    service role. Until then the production path **raises**, which is the whole point:
    a resolver that fell back to an environment variable, a file, or a test double would
    make the absence of the real one invisible until something leaked.
    """

    backend: SecretBackend = SecretBackend.AWS_SECRETS_MANAGER

    def resolve(self, reference: SecretReference) -> Secret:
        raise SecretBackendUnavailable(
            f"resolving {reference.backend.value}:{reference.name} is not implemented in this "
            "milestone. The AWS Secrets Manager adapter is Milestone 8 work and belongs to the "
            "service role that owns the secret. There is deliberately no fallback: a resolver "
            "that quietly read a plaintext value from somewhere else would hide the fact that "
            "the real one does not exist yet."
        )


class InMemorySecretResolver:
    """A test double. Refuses to exist in production.

    Not "encryption" and not a vault: a dictionary. It is here so that code which *uses* a
    resolver can be tested without inventing one per test, and the environment check is
    what stops it becoming the thing production accidentally runs.
    """

    def __init__(self, environment: Environment, values: "dict[str, str] | None" = None) -> None:
        _refuse_in_production(environment, "InMemorySecretResolver")
        self._values = dict(values or {})

    def store(self, reference: SecretReference, value: Secret) -> None:
        self._values[self._key(reference)] = value.reveal()

    def resolve(self, reference: SecretReference) -> Secret:
        # The same sentinel lookup as the test vault's, for the same two reasons. The key
        # here is a reference and every part of it has been validated to be an identifier,
        # so this one is defence against the shape of the mistake rather than against a
        # known leak -- which is the point of auditing every lookup rather than the one
        # that was reported.
        found = self._values.get(self._key(reference), _MISSING)
        if found is _MISSING:
            raise SecretBackendUnavailable(
                f"no test value is registered for {reference.backend.value}:{reference.name}"
            )
        return Secret(found)

    @staticmethod
    def _key(reference: SecretReference) -> str:
        return f"{reference.backend.value}:{reference.name}:{reference.version or ''}"

    def __repr__(self) -> str:
        # The count, not the keys and certainly not the values.
        return f"InMemorySecretResolver(<{len(self._values)} test values>)"


# --------------------------------------------------------------------- encryption

class KeyBackend(str, Enum):
    AWS_KMS = "aws-kms"
    IN_MEMORY = "in-memory"


@dataclass(frozen=True, repr=False)
class KeyReference:
    """An opaque reference to the key an envelope was sealed with.

    A key alias or ARN, never key material. Stored beside the ciphertext so that a value
    encrypted before a rotation can still be identified -- and refused, if its key is
    gone -- rather than failing as an unexplained decryption error.

    Validated the same way as :class:`SecretReference`, and for the same reason: this
    identifier is rendered by :class:`EncryptedValue`'s ``repr``, so a secret-shaped one
    would be revealed transitively by every envelope that carried it.
    """

    backend: KeyBackend
    identifier: str

    def __post_init__(self) -> None:
        if not isinstance(self.backend, KeyBackend):
            _require_non_secret(self.backend, field="key backend")
            raise SecretError("the key backend is not a KeyBackend")
        _require_reference_field(self.identifier, _REFERENCE_NAME, field="key identifier")

    def __repr__(self) -> str:
        return f"KeyReference(backend={self.backend.value!r}, identifier={self.identifier!r})"

    __str__ = __repr__


#: The envelope format this milestone defines. It is inside every value rather than in a
#: deployment note, so that a change of scheme is legible per row and a value written
#: under an older one can be recognised instead of guessed at.
CURRENT_ENVELOPE_VERSION = 1


@dataclass(frozen=True, repr=False)
class EncryptedValue:
    """Versioned ciphertext plus the reference to the key that sealed it.

    There is no ``plaintext`` field, and there is no method that returns one: decryption
    belongs to an :class:`Encryptor`, which is the boundary where the key lives. The
    ``repr`` renders the version and the key reference -- both non-secret and both useful
    in a traceback -- and never the ciphertext, because a short ciphertext is a short
    secret.
    """

    version: int
    key: KeyReference
    ciphertext: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 1:
            raise SecretError("the envelope version is not a positive integer")
        if not isinstance(self.key, KeyReference):
            raise SecretError("an encrypted value carries a KeyReference")
        if not isinstance(self.ciphertext, (bytes, bytearray)) or not self.ciphertext:
            raise SecretError("an encrypted value carries non-empty ciphertext")

    def __repr__(self) -> str:
        return (
            f"EncryptedValue(version={self.version}, key={self.key.backend.value}:"
            f"{self.key.identifier}, ciphertext=<redacted>)"
        )

    __str__ = __repr__

    def __format__(self, _spec: str) -> str:
        return repr(self)


class Encryptor(Protocol):
    """Seals and opens envelopes. The only place a key is used."""

    def encrypt(self, plaintext: Secret) -> EncryptedValue:  # pragma: no cover - protocol
        ...

    def decrypt(self, value: EncryptedValue) -> Secret:  # pragma: no cover - protocol
        ...


@dataclass(frozen=True)
class UnimplementedEncryptor:
    """The production encryptor, and it encrypts nothing yet.

    Milestone 8 replaces it with AWS KMS. Firmbatch does not implement a cipher: the one
    thing worse than not having encryption here would be having one somebody in this
    repository invented.
    """

    key: KeyReference = KeyReference(KeyBackend.AWS_KMS, "firmbatch-unconfigured")

    def encrypt(self, plaintext: Secret) -> EncryptedValue:
        raise SecretBackendUnavailable(
            "encryption is not implemented in this milestone. The AWS KMS adapter is Milestone 8 "
            "work. There is no fallback and there must not be one: storing a plaintext value "
            "under a name that says 'encrypted' is worse than storing it under its own name."
        )

    def decrypt(self, value: EncryptedValue) -> Secret:
        raise SecretBackendUnavailable(
            f"decrypting a version-{value.version} envelope sealed with "
            f"{value.key.backend.value}:{value.key.identifier} is not implemented in this "
            "milestone (Milestone 8)."
        )


class InMemoryEncryptor:
    """A test double that stores plaintext in a dictionary and calls it nothing else.

    Deliberately **not** an encoding, an obfuscation, or a cipher of any kind: the
    "ciphertext" is a random opaque token, and the value it stands for lives in this
    object. That keeps the shape of the interface honest for tests without anybody being
    able to mistake it for cryptography or being tempted to reuse it. Refused in
    production.
    """

    def __init__(self, environment: Environment) -> None:
        _refuse_in_production(environment, "InMemoryEncryptor")
        self._vault: dict[bytes, str] = {}
        self.key = KeyReference(KeyBackend.IN_MEMORY, "test-vault")

    def encrypt(self, plaintext: Secret) -> EncryptedValue:
        token = _stdlib_secrets.token_bytes(16)
        self._vault[token] = plaintext.reveal()
        return EncryptedValue(version=CURRENT_ENVELOPE_VERSION, key=self.key, ciphertext=token)

    def decrypt(self, value: EncryptedValue) -> Secret:
        if value.key != self.key:
            raise SecretBackendUnavailable(
                f"this test vault cannot open an envelope sealed with {value.key.backend.value}"
            )
        # ``.get`` with a sentinel rather than ``self._vault[...]``, and the refusal raised
        # **after** the lookup rather than from inside an ``except KeyError``. Both halves
        # matter, and neither is stylistic:
        #
        # * a failing subscript builds ``KeyError(<the ciphertext bytes>)``. The exception
        #   carries the key in ``args``, so the ciphertext is rendered by its ``repr`` --
        #   and a short ciphertext is a short secret;
        # * raising inside the handler attaches that KeyError as ``__context__``. ``from
        #   None`` sets ``__suppress_context__``, which stops a *printed* traceback showing
        #   it; it does not detach it, so anything walking the chain still finds it. Out
        #   here there is no exception being handled and nothing is attached at all.
        found = self._vault.get(bytes(value.ciphertext), _MISSING)
        if found is _MISSING:
            raise SecretBackendUnavailable("no test value stands behind this envelope")
        return Secret(found)

    def __repr__(self) -> str:
        return f"InMemoryEncryptor(<{len(self._vault)} test values>)"


def _refuse_in_production(environment: Environment, what: str) -> None:
    if environment is not Environment.TEST:
        raise SecretError(
            f"{what} is a test double and refuses to run in {environment.value!r}. Production "
            "resolves secrets and encrypts values through the adapters that own the key; there is "
            "no configuration that substitutes a fake for one, because a silent substitution is "
            "how plaintext ends up somewhere nobody was told about."
        )


def resolver_for(environment: Environment) -> SecretResolver:
    """The resolver a process gets. In production it is the one that raises.

    There is no parameter that selects a fake and no environment variable that changes the
    answer. A test that wants a double constructs :class:`InMemorySecretResolver` itself,
    which refuses outside ``test`` -- so the fallback path does not exist rather than
    being merely discouraged.
    """
    _require_environment(environment)
    return UnimplementedSecretResolver()


def encryptor_for(environment: Environment) -> Encryptor:
    """The encryptor a process gets. In production it is the one that raises."""
    _require_environment(environment)
    return UnimplementedEncryptor()


def _require_environment(environment: Environment) -> Environment:
    """Both factories take the environment and both check it.

    Not because the answer differs -- it does not, and that is the property -- but
    because a factory that ignored its argument would be one edit away from being the
    place somebody added ``if environment is test: return the fake``.
    """
    if not isinstance(environment, Environment):
        raise SecretError(
            f"{environment!r} is not an Environment. The environment is stated explicitly "
            "everywhere in this package; there is no default."
        )
    return environment


# ------------------------------------------------------------------- the model

class SecretClass(str, Enum):
    BEARER_CREDENTIAL = "bearer_credential"
    OPERATIONAL_SECRET = "operational_secret"
    ENCRYPTED_VALUE = "encrypted_value"
    MIGRATION_CREDENTIAL = "migration_credential"


@dataclass(frozen=True)
class SecretClassRule:
    """One class of secret, and the boundary it may not cross."""

    secret_class: SecretClass
    #: What a Firmbatch table may contain for a value of this class.
    stored_as: str
    #: Which process may hold the usable value.
    held_by: str
    #: How it is replaced.
    rotation: str
    #: The type in this module that represents it, or ``None`` where the representation
    #: deliberately lives outside this module.
    representation: str | None


#: The model, as data. ``tests/test_secrets_model.py`` walks it, so a class that gains a
#: representation without a boundary -- or a boundary without a representation -- fails
#: the suite instead of being a paragraph that stopped being true.
SECRET_CLASSES: tuple[SecretClassRule, ...] = (
    SecretClassRule(
        secret_class=SecretClass.BEARER_CREDENTIAL,
        stored_as="a one-way sha256 fingerprint, computed in PostgreSQL, in firmbatch.auth_bindings",
        held_by="the customer; shown once at creation and never retrievable afterwards",
        rotation="register a new binding, then revoke the old one",
        representation="Secret",
    ),
    SecretClassRule(
        secret_class=SecretClass.OPERATIONAL_SECRET,
        stored_as="an opaque SecretReference; the value is never in a Firmbatch table",
        held_by="the one service role that owns it (provider credentials: controller/reconciler)",
        rotation="rotate in the secret backend; the reference is unchanged or gains a version",
        representation="SecretReference",
    ),
    SecretClassRule(
        secret_class=SecretClass.ENCRYPTED_VALUE,
        stored_as="a versioned ciphertext envelope plus an opaque KeyReference",
        held_by="whichever role holds the key; plaintext exists only between encrypt and use",
        rotation="re-encrypt under a new key reference; the envelope version records the scheme",
        representation="EncryptedValue",
    ),
    SecretClassRule(
        secret_class=SecretClass.MIGRATION_CREDENTIAL,
        stored_as="nothing; it is configuration, never a row",
        held_by="the migration entry point alone, through its own settings type and variable",
        rotation="rotate the database role's password out of band",
        # Deliberately outside this module: giving the owner credential a type here would
        # put it in the import graph of every process that handles the other three.
        representation=None,
    ),
)
