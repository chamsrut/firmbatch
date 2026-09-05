"""The secrets and encryption model: four classes, four boundaries, no silent fallback.

Milestone 2.3 implements the model and not the infrastructure. There is no AWS call here
to test, and that absence is the thing most worth asserting: a production path that
*quietly* did something cheaper than the real adapter -- read a plaintext environment
variable, fall back to a test double, store an unencrypted value under a field named
``ciphertext`` -- would be invisible until it leaked. So the production resolver and the
production encryptor **raise**, the test doubles refuse to exist outside ``test``, and both
of those are tested rather than described.

The rest of this module is about rendering. A secret reaches a log line, a traceback, an
f-string, a pytest fixture repr or a JSON body without anybody deciding that it should, so
:class:`Secret` and :class:`EncryptedValue` close every one of those routes and each is
checked here -- including for a *short* value, because the length of a short secret is
most of a short secret.

The fourth class, the migration-owner credential, has no type in this module on purpose.
Its boundary is a configuration one -- one settings type, one environment variable, one
loader, and a static check that no runtime module can reach any of them -- so it is tested
where that boundary lives: ``test_settings_separation.py`` and
``scripts/check-runtime-imports.py --static``. What is asserted here is that the model
*says* so, and that the model and the code agree about the other three.
"""

from __future__ import annotations

import ast
import copy
import json
import pathlib
import pickle
import re

import pytest

from firmbatch.control_plane.config import Environment
from firmbatch.control_plane.security import secrets as secrets_module
from firmbatch.control_plane.security.secrets import (
    BEARER_CREDENTIAL_REGEX,
    CREDENTIAL_ENTROPY_BYTES,
    CREDENTIAL_PREFIX,
    DATABASE_CREDENTIAL_ENTROPY_BITS,
    UUID4_ENTROPY_BITS,
    CURRENT_ENVELOPE_VERSION,
    FINGERPRINT_ALGORITHM,
    SECRET_CLASSES,
    EncryptedValue,
    InMemoryEncryptor,
    InMemorySecretResolver,
    KeyBackend,
    KeyReference,
    Secret,
    SecretBackend,
    SecretBackendUnavailable,
    SecretClass,
    SecretError,
    SecretHandlingError,
    SecretReference,
    UnimplementedEncryptor,
    UnimplementedSecretResolver,
    encryptor_for,
    generate_bearer_credential,
    is_well_formed_credential,
    looks_like_secret,
    resolver_for,
)
from firmbatch.control_plane.tests.conftest import exception_chain

SHORT = Secret("s")


# ------------------------------------------------------------------- bearer credentials


def test_a_generated_credential_has_the_declared_shape_and_entropy():
    credential = generate_bearer_credential()
    raw = credential.reveal()
    assert BEARER_CREDENTIAL_REGEX.fullmatch(raw)
    assert is_well_formed_credential(credential) and is_well_formed_credential(raw)
    # 32 random bytes rendered URL-safe. The length is a consequence of the entropy, and
    # asserting it is how a quieter generator would be noticed.
    assert CREDENTIAL_ENTROPY_BYTES == 32
    assert len(raw) == len("fbk_") + 43


def test_two_credentials_are_never_the_same():
    assert len({generate_bearer_credential().reveal() for _ in range(200)}) == 200


def test_the_stored_form_is_named_and_is_one_way():
    """The digest is computed in PostgreSQL; this pins the algorithm the model claims."""
    assert FINGERPRINT_ALGORITHM == "sha256"


@pytest.mark.parametrize(
    "bad", ["", "fbk_", "fbk_short", "nope", "fbk_" + "x" * 42, "fbk_" + "x" * 44, "fbk_" + "!" * 43]
)
def test_a_malformed_credential_is_recognised_as_such(bad):
    assert is_well_formed_credential(bad) is False


def test_a_secret_refuses_to_wrap_nothing():
    for value in ("", None, 123, b"bytes"):
        with pytest.raises(SecretHandlingError):
            Secret(value)


# ------------------------------------------------------------------------- rendering


@pytest.mark.parametrize("secret", [SHORT, Secret("fbk_" + "A" * 43)])
def test_a_secret_renders_nothing_of_itself_by_any_route(secret):
    """Every route a value takes into text, closed and checked -- short values included."""
    raw = secret.reveal()
    renderings = [
        repr(secret),
        str(secret),
        f"{secret}",
        "{}".format(secret),  # noqa: UP032 - the .format path is a separate dunder
        f"{secret!s}",
        f"{secret!r}",
        format(secret, ">30"),
        repr([secret]),
        repr({"credential": secret}),
        str(RuntimeError(secret)),
    ]
    for rendering in renderings:
        assert raw not in rendering, rendering
        assert "redacted" in rendering


def test_a_secret_does_not_leak_its_length():
    """A four-character secret and a hundred-character one must render identically.

    Length is most of what an attacker needs to know about a short secret, and a ``repr``
    that helpfully said ``Secret(1 char)`` would give it away every time.
    """
    assert repr(Secret("s")) == repr(Secret("x" * 400))


def test_a_secret_cannot_be_serialized_or_copied():
    """Serializing is how a secret reaches a cache, a queue, or a crash dump."""
    secret = generate_bearer_credential()
    with pytest.raises(SecretHandlingError):
        pickle.dumps(secret)
    with pytest.raises(SecretHandlingError):
        copy.copy(secret)
    with pytest.raises(SecretHandlingError):
        copy.deepcopy(secret)
    with pytest.raises(TypeError):
        json.dumps({"credential": secret})


def test_a_secret_is_not_hashable():
    """A hashable secret becomes a dict key, and dict keys appear in the dict's repr."""
    with pytest.raises(TypeError):
        {generate_bearer_credential(): 1}


def test_secret_equality_is_by_value_and_constant_time():
    raw = generate_bearer_credential().reveal()
    assert Secret(raw) == Secret(raw)
    assert Secret(raw) != generate_bearer_credential()
    assert (Secret(raw) == raw) is False, "a Secret does not compare equal to a bare string"


# ------------------------------------------------------------------------ references


def test_a_reference_is_not_a_secret_and_says_what_it_points_at():
    reference = SecretReference(SecretBackend.AWS_SECRETS_MANAGER, "firmbatch/prod/verda-api-key", "v3")
    rendered = repr(reference)
    assert "firmbatch/prod/verda-api-key" in rendered
    assert "aws-secrets-manager" in rendered


@pytest.mark.parametrize("name", ["", " ", "has space", "x" * 300, "/leading", None, 5])
def test_a_malformed_reference_is_refused(name):
    with pytest.raises(SecretError):
        SecretReference(SecretBackend.AWS_SECRETS_MANAGER, name)


def test_a_reference_needs_a_known_backend():
    with pytest.raises(SecretError):
        SecretReference("wherever", "firmbatch/prod/key")


# ------------------------------------------------------- production fails, loudly


def test_the_production_resolver_raises_rather_than_falling_back():
    reference = SecretReference(SecretBackend.AWS_SECRETS_MANAGER, "firmbatch/prod/verda-api-key")
    resolver = resolver_for(Environment.PRODUCTION)
    assert isinstance(resolver, UnimplementedSecretResolver)
    with pytest.raises(SecretBackendUnavailable) as exc:
        resolver.resolve(reference)
    assert "Milestone 8" in str(exc.value)
    assert "fallback" in str(exc.value)


def test_the_production_encryptor_raises_rather_than_storing_plaintext():
    encryptor = encryptor_for(Environment.PRODUCTION)
    assert isinstance(encryptor, UnimplementedEncryptor)
    with pytest.raises(SecretBackendUnavailable):
        encryptor.encrypt(generate_bearer_credential())
    with pytest.raises(SecretBackendUnavailable):
        encryptor.decrypt(
            EncryptedValue(CURRENT_ENVELOPE_VERSION, KeyReference(KeyBackend.AWS_KMS, "alias/x"), b"\x00")
        )


def test_the_test_environment_gets_the_same_unimplemented_adapters():
    """There is no configuration that substitutes a fake, which is the property.

    A factory that returned a double in ``test`` would be one edit away from returning one
    in production, and the edit would look like a convenience.
    """
    assert isinstance(resolver_for(Environment.TEST), UnimplementedSecretResolver)
    assert isinstance(encryptor_for(Environment.TEST), UnimplementedEncryptor)


def test_the_factories_refuse_an_unstated_environment():
    for value in (None, "production", "test", 1):
        with pytest.raises(SecretError):
            resolver_for(value)
        with pytest.raises(SecretError):
            encryptor_for(value)


@pytest.mark.parametrize("double", [InMemorySecretResolver, InMemoryEncryptor])
def test_a_test_double_refuses_to_exist_in_production(double):
    with pytest.raises(SecretError) as exc:
        double(Environment.PRODUCTION)
    assert "test double" in str(exc.value)


def test_the_test_doubles_work_where_they_are_allowed():
    """They exist so that code which *uses* a resolver can be tested without inventing one."""
    reference = SecretReference(SecretBackend.IN_MEMORY, "provider/key")
    resolver = InMemorySecretResolver(Environment.TEST)
    with pytest.raises(SecretBackendUnavailable):
        resolver.resolve(reference)
    resolver.store(reference, Secret("provider-value"))
    assert resolver.resolve(reference).reveal() == "provider-value"
    assert "provider-value" not in repr(resolver)


# ------------------------------------------------------------------------ envelopes


def test_an_envelope_carries_a_version_and_a_key_reference_and_no_plaintext():
    encryptor = InMemoryEncryptor(Environment.TEST)
    plaintext = Secret("the-provider-api-key")
    envelope = encryptor.encrypt(plaintext)

    assert envelope.version == CURRENT_ENVELOPE_VERSION
    assert envelope.key.backend is KeyBackend.IN_MEMORY
    assert not hasattr(envelope, "plaintext")
    assert encryptor.decrypt(envelope).reveal() == "the-provider-api-key"


def test_an_envelope_renders_its_version_and_key_and_never_its_ciphertext():
    encryptor = InMemoryEncryptor(Environment.TEST)
    envelope = encryptor.encrypt(Secret("x"))
    for rendering in (repr(envelope), str(envelope), f"{envelope}", str(RuntimeError(envelope))):
        assert "ciphertext=<redacted>" in rendering
        assert str(envelope.ciphertext) not in rendering
        assert "version=1" in rendering
        assert "in-memory" in rendering


def test_an_envelope_refuses_to_be_malformed():
    key = KeyReference(KeyBackend.AWS_KMS, "alias/firmbatch")
    for args in ((0, key, b"x"), (1, "not-a-key", b"x"), (1, key, b""), (1, key, "not-bytes")):
        with pytest.raises(SecretError):
            EncryptedValue(*args)


def test_a_key_reference_is_a_reference_and_not_key_material():
    reference = KeyReference(KeyBackend.AWS_KMS, "alias/firmbatch-payload")
    assert "alias/firmbatch-payload" in repr(reference)
    with pytest.raises(SecretError):
        KeyReference(KeyBackend.AWS_KMS, "not a key id")
    with pytest.raises(SecretError):
        KeyReference("kms", "alias/x")


def test_one_vault_cannot_open_another_vaults_envelope():
    first = InMemoryEncryptor(Environment.TEST)
    envelope = first.encrypt(Secret("value"))
    forged = EncryptedValue(
        envelope.version, KeyReference(KeyBackend.AWS_KMS, "alias/other"), envelope.ciphertext
    )
    with pytest.raises(SecretBackendUnavailable):
        first.decrypt(forged)


# --------------------------------------------------------------- shape recognition


@pytest.mark.parametrize(
    "value, expected",
    [
        ("fbk_" + "A" * 43, "a Firmbatch bearer credential"),
        ("-----BEGIN EC PRIVATE KEY-----\nabc", "a PEM-encoded key block"),
        ("Bearer abc.def.ghi", "an HTTP authorization header value"),
        ("postgresql://u:p@host:5432/db", "a database URL carrying a password"),
        ("AKIAIOSFODNN7EXAMPLE", "an AWS access key id"),
        ("password: hunter2", "a private key or token assignment"),
    ],
)
def test_a_recognisable_secret_shape_is_named_and_not_echoed(value, expected):
    assert looks_like_secret(value) == expected
    # The *name* of the shape, never the value: a refusal that quoted what it refused
    # would be the leak it exists to prevent.
    assert value not in expected


@pytest.mark.parametrize(
    "value",
    [
        "input_manifest_id",
        "sha256:" + "0" * 64,
        "tenant/abc/attempt/1/output.jsonl",
        "production",
        4000,
        None,
        True,
    ],
)
def test_an_ordinary_reference_is_not_mistaken_for_a_secret(value):
    """The rule has to leave the vocabulary these columns exist to hold usable."""
    assert looks_like_secret(value) is None


def test_a_secret_object_is_recognised_without_being_revealed():
    assert looks_like_secret(generate_bearer_credential()) == "a secret value object"
    encryptor = InMemoryEncryptor(Environment.TEST)
    assert looks_like_secret(encryptor.encrypt(Secret("x"))) == "a secret value object"


# ----------------------------------------------------------------------- the model


def test_the_model_names_four_classes_and_a_boundary_for_each():
    assert {rule.secret_class for rule in SECRET_CLASSES} == set(SecretClass)
    assert len(SECRET_CLASSES) == len(SecretClass)
    for rule in SECRET_CLASSES:
        assert rule.stored_as.strip()
        assert rule.held_by.strip()
        assert rule.rotation.strip()


def test_every_represented_class_names_a_type_this_module_exports():
    import firmbatch.control_plane.security.secrets as module

    for rule in SECRET_CLASSES:
        if rule.representation is None:
            # The migration-owner credential, deliberately. Giving it a type here would
            # put the owner credential in the import graph of every process that handles
            # the other three.
            assert rule.secret_class is SecretClass.MIGRATION_CREDENTIAL
            continue
        assert hasattr(module, rule.representation), rule.representation


def test_the_migration_credential_has_no_representation_here_and_says_why():
    rule = next(r for r in SECRET_CLASSES if r.secret_class is SecretClass.MIGRATION_CREDENTIAL)
    assert rule.representation is None
    assert "migration entry point" in rule.held_by
    assert "never a row" in rule.stored_as


def test_a_bearer_credential_is_stored_only_as_a_fingerprint_in_the_model():
    rule = next(r for r in SECRET_CLASSES if r.secret_class is SecretClass.BEARER_CREDENTIAL)
    assert "fingerprint" in rule.stored_as and "sha256" in rule.stored_as
    assert "once" in rule.held_by
    assert "revoke" in rule.rotation


def test_an_operational_secret_is_never_in_a_firmbatch_table_in_the_model():
    rule = next(r for r in SECRET_CLASSES if r.secret_class is SecretClass.OPERATIONAL_SECRET)
    assert "SecretReference" in rule.stored_as
    assert "never in a Firmbatch table" in rule.stored_as
    # And the role that holds it is the one the target architecture puts it with.
    assert "controller" in rule.held_by


def test_this_module_reaches_no_aws_sdk_and_no_cryptography():
    """The model, and nothing that would make it look implemented.

    An import here would be the first step towards a half-built adapter, and a half-built
    adapter is worse than a declared absence because it stops people asking.
    """
    import ast
    import pathlib

    import firmbatch.control_plane.security.secrets as module

    tree = ast.parse(pathlib.Path(module.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    for forbidden in ("boto3", "botocore", "cryptography", "nacl", "Crypto"):
        assert forbidden not in imported, forbidden


# ------------------------------------------------ references never echo (finding 5)

#: Values a reference field must refuse **because of their shape**, and never repeat. Each
#: is something somebody really does paste into the wrong field.
SECRET_SHAPED_INPUTS = (
    "fbk_" + "A" * 43,
    "postgresql://firmbatch:hunter2@db.internal:5432/prod",
    "AKIAIOSFODNN7EXAMPLE",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "Bearer eyJhbGciOiJIUzI1NiJ9.e30.abc",
    "password: hunter2",
)

#: Values a reference field refuses because they are **malformed**, including short ones.
#: The non-echo rule applies to these identically, and that is the half that matters for a
#: short secret: the shape rules cannot recognise ``hunter2!`` as a password, but the
#: refusal it does produce must still not quote it.
SHORT_AND_MALFORMED_INPUTS = (
    "hunter2!",
    "s3cr3t!",
    "pw pw",
    "x" * 300,
    "/leading",
    "semi;colon",
)


def rendered_chain(error: BaseException) -> str:
    """Everything an exception can put in front of a human, including what it chains to.

    ``str(exc)`` is not enough. ``raise X from Y`` and an implicit re-raise both leave the
    original reachable through ``__cause__``/``__context__``, and a traceback printer -- or
    a structured logger -- renders it. A refusal that quoted its input into an exception
    that then became somebody's ``__context__`` would leak just as surely as one that
    printed it.
    """
    seen = []
    current: BaseException | None = error
    while current is not None and len(seen) < 20:
        seen.append(f"{current!r} {current!s}")
        current = current.__cause__ or current.__context__
    return " || ".join(seen)


@pytest.mark.parametrize("value", SECRET_SHAPED_INPUTS)
def test_a_secret_shaped_reference_name_is_refused_without_being_repeated(value):
    """Rejected for its shape, and the rejection does not carry it.

    The shape test runs before the format test on purpose: the format test is the one that
    used to interpolate its input, so a credential pasted into a reference field was echoed
    by the very check that existed to notice it.
    """
    with pytest.raises(SecretError) as exc:
        SecretReference(SecretBackend.AWS_SECRETS_MANAGER, value)
    chain = rendered_chain(exc.value)
    assert value not in chain
    # Not even a fragment of it: a prefix is enough to confirm a guess.
    assert value[:8] not in chain


@pytest.mark.parametrize("value", SECRET_SHAPED_INPUTS)
def test_a_secret_shaped_key_identifier_is_refused_without_being_repeated(value):
    with pytest.raises(SecretError) as exc:
        KeyReference(KeyBackend.AWS_KMS, value)
    chain = rendered_chain(exc.value)
    assert value not in chain
    assert value[:8] not in chain


@pytest.mark.parametrize("value", SECRET_SHAPED_INPUTS)
def test_a_secret_shaped_version_is_refused_without_being_repeated(value):
    with pytest.raises(SecretError) as exc:
        SecretReference(SecretBackend.AWS_SECRETS_MANAGER, "firmbatch/prod/key", value)
    chain = rendered_chain(exc.value)
    assert value not in chain
    assert value[:8] not in chain


@pytest.mark.parametrize("value", SHORT_AND_MALFORMED_INPUTS)
def test_a_merely_malformed_identifier_is_not_echoed_either(value):
    """Not secret-shaped, and still not repeated -- short values included.

    The rule is not "hide the ones we recognise": no pattern recognises everything, and a
    short password looks exactly like a short name. It is that a *rejected* value is
    unvetted input by definition, so none of it comes back regardless of what it turned out
    to be.
    """
    with pytest.raises(SecretError) as exc:
        SecretReference(SecretBackend.AWS_SECRETS_MANAGER, value)
    chain = rendered_chain(exc.value)
    assert value not in chain
    # A distinctive prefix too, because a partial quote confirms a guess. Five characters:
    # shorter than that and the fragment starts matching ordinary English in the message,
    # which would make this assert something about prose rather than about the value.
    assert value[:5] not in chain


def test_what_the_shape_rules_cannot_do_is_stated_rather_than_implied():
    """``hunter2`` is a valid reference name, and no rule here can say otherwise.

    Worth a passing test rather than a paragraph, because the failure mode is somebody
    reading the list of patterns and concluding that a name which got through must be safe.
    It got through because it is a well-formed identifier; that is all that was checked.
    The defence against a password *being* a reference name is the type -- a
    :class:`SecretReference` names where a secret lives, and the value lives in the backend.
    """
    assert looks_like_secret("hunter2") is None
    reference = SecretReference(SecretBackend.AWS_SECRETS_MANAGER, "hunter2")
    assert reference.name == "hunter2"


def test_a_secret_shaped_backend_is_refused_without_being_repeated():
    """The type check is a refusal path too, and takes arbitrary objects."""
    value = "fbk_" + "C" * 43
    for constructor in (
        lambda: SecretReference(value, "firmbatch/prod/key"),
        lambda: KeyReference(value, "alias/firmbatch"),
    ):
        with pytest.raises(SecretError) as exc:
            constructor()
        assert value not in rendered_chain(exc.value)


def test_an_envelope_cannot_transitively_reveal_a_key_reference_input():
    """``EncryptedValue`` renders its key identifier, so the identifier has to be safe.

    It is, because ``KeyReference`` refuses a secret-shaped one at construction -- there is
    no envelope that could carry one to render. Both halves are checked: the refusal, and
    the rendering of a legitimate reference.
    """
    for value in SECRET_SHAPED_INPUTS:
        with pytest.raises(SecretError):
            EncryptedValue(1, KeyReference(KeyBackend.AWS_KMS, value), b"x")

    envelope = EncryptedValue(1, KeyReference(KeyBackend.AWS_KMS, "alias/firmbatch"), b"\x01\x02")
    for rendering in (repr(envelope), str(envelope), f"{envelope}"):
        assert "alias/firmbatch" in rendering
        assert "ciphertext=<redacted>" in rendering
        assert "\\x01" not in rendering


def test_the_reference_types_render_themselves_explicitly():
    """Written out rather than generated, so adding a field is a decision about ``repr``."""
    reference = SecretReference(SecretBackend.AWS_SECRETS_MANAGER, "firmbatch/prod/key", "v3")
    assert repr(reference) == (
        "SecretReference(backend='aws-secrets-manager', name='firmbatch/prod/key', version='v3')"
    )
    assert str(reference) == repr(reference)
    assert repr(SecretReference(SecretBackend.IN_MEMORY, "a/b")) == (
        "SecretReference(backend='in-memory', name='a/b')"
    )
    assert repr(KeyReference(KeyBackend.AWS_KMS, "alias/x")) == (
        "KeyReference(backend='aws-kms', identifier='alias/x')"
    )
    # And neither is the dataclass default, which would have rendered the enum members.
    assert "SecretBackend." not in repr(reference)
    assert "KeyBackend." not in repr(KeyReference(KeyBackend.AWS_KMS, "alias/x"))


# ------------------------------------------- lookups that must not build a KeyError
#
# ``self._vault[bytes(value.ciphertext)]`` looks harmless and is not. When the key is
# missing PostgreSQL is not involved at all -- Python builds ``KeyError(<the ciphertext
# bytes>)``, whose ``args`` hold the key and whose ``repr`` therefore renders it. Raising
# the sanitized error from inside the ``except KeyError`` then attaches that object as
# ``__context__``: ``from None`` sets ``__suppress_context__``, which stops a *printed*
# traceback showing it, and does not detach it.
#
# So a short ciphertext -- and every ciphertext this test double produces is 16 bytes --
# was reachable from the exception that existed to avoid mentioning it. Both halves are
# fixed: a sentinel ``.get`` instead of a subscript, and the raise moved out of the handler.


def _reachable(error: BaseException) -> str:
    """Everything the exception graph renders, not just what a traceback prints."""
    return exception_chain(error)


def test_a_missing_ciphertext_leaves_no_trace_of_itself():
    encryptor = InMemoryEncryptor(Environment.TEST)
    plaintext = "swordfish"
    envelope = encryptor.encrypt(Secret(plaintext))

    stranger = EncryptedValue(
        version=envelope.version, key=encryptor.key, ciphertext=b"\x00" * 16
    )
    with pytest.raises(SecretBackendUnavailable) as exc:
        encryptor.decrypt(stranger)

    chain = _reachable(exc.value)
    for forbidden in (
        repr(stranger.ciphertext),
        stranger.ciphertext.hex(),
        str(stranger.ciphertext),
        plaintext,
        encryptor.key.identifier,
    ):
        assert forbidden not in chain, (forbidden, chain)
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None


def test_a_real_ciphertext_is_not_echoed_by_a_key_mismatch():
    """The other refusal in the same method, on an envelope this vault really could open."""
    encryptor = InMemoryEncryptor(Environment.TEST)
    envelope = encryptor.encrypt(Secret("swordfish"))
    foreign = EncryptedValue(
        version=envelope.version,
        key=KeyReference(KeyBackend.AWS_KMS, "alias/somebody-elses"),
        ciphertext=envelope.ciphertext,
    )
    with pytest.raises(SecretBackendUnavailable) as exc:
        encryptor.decrypt(foreign)
    chain = _reachable(exc.value)
    assert repr(envelope.ciphertext) not in chain
    assert envelope.ciphertext.hex() not in chain
    assert "swordfish" not in chain


def test_an_unregistered_reference_leaves_no_trace_of_the_value():
    """The same audit, applied to the resolver rather than to the vault.

    The key here is a reference, and every part of a reference has been validated to be an
    identifier -- so this one is defence against the shape of the mistake rather than
    against a known leak. Auditing every lookup rather than only the reported one is the
    point.
    """
    resolver = InMemorySecretResolver(Environment.TEST)
    reference = SecretReference(SecretBackend.IN_MEMORY, "firmbatch/test/absent")
    stored = SecretReference(SecretBackend.IN_MEMORY, "firmbatch/test/present")
    resolver.store(stored, Secret("swordfish"))

    with pytest.raises(SecretBackendUnavailable) as exc:
        resolver.resolve(reference)
    chain = _reachable(exc.value)
    assert "swordfish" not in chain
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None
    # The reference itself may be named: that is what a reference is for.
    assert "firmbatch/test/absent" in str(exc.value)


def test_no_read_in_this_module_subscripts_a_dict_it_would_not_print():
    """The rule behind the three tests above, checked against the parse tree.

    A rule stated in a docstring is a rule that comes back, and this is the only thing that
    notices the next ``self._vault[...]``. Parsed rather than grepped, because the
    distinction is real: ``self._vault[token] = ...`` is a **store** and cannot raise
    ``KeyError``, while ``... = self._vault[token]`` is a **load** and builds one carrying
    the key. Only the second is the mistake.

    ``except KeyError`` is refused outright as well. Catching it is not enough on its own:
    the object exists by then, and raising the replacement from inside the handler attaches
    it as ``__context__``.
    """
    tree = ast.parse(pathlib.Path(secrets_module.__file__).read_text())
    loads = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Subscript)
        and isinstance(node.ctx, ast.Load)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr in ("_vault", "_values")
    ]
    assert loads == [], [ast.dump(node) for node in loads]
    handlers = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ExceptHandler)
        and isinstance(node.type, ast.Name)
        and node.type.id == "KeyError"
    ]
    assert handlers == []


# --------------------------------------------------------------- entropy, exactly
#
# Two generators, two numbers, and the numbers are different. Writing the larger one twice
# would be a sentence that reads better and is false.


def test_the_python_generator_is_exactly_thirty_two_random_bytes():
    """256 bits because 32 bytes are 256 bits. The rendering is not the entropy."""
    assert CREDENTIAL_ENTROPY_BYTES == 32
    assert CREDENTIAL_ENTROPY_BYTES * 8 == 256
    credential = generate_bearer_credential().reveal()
    assert BEARER_CREDENTIAL_REGEX.fullmatch(credential)
    # 43 characters is what base64url of 32 bytes renders as, with the padding stripped.
    # It is a consequence of the entropy and is never quoted as though it were the entropy.
    assert len(credential) == len(CREDENTIAL_PREFIX) + 43


def test_the_database_generator_is_exactly_two_uuid4_values():
    """244 bits: 122 each, which is what a version-4 UUID carries.

    A UUIDv4 is 128 bits with 4 version bits and 2 variant bits fixed, so 122 are random.
    The database concatenates two of them and renders the 32 bytes the same way the Python
    generator renders its own, which is why both produce the same 43 characters and why the
    43 says nothing about either.
    """
    assert UUID4_ENTROPY_BITS == 122
    assert DATABASE_CREDENTIAL_ENTROPY_BITS == 2 * UUID4_ENTROPY_BITS == 244
    assert DATABASE_CREDENTIAL_ENTROPY_BITS < CREDENTIAL_ENTROPY_BYTES * 8


def test_the_database_generator_really_is_the_source_and_the_shape_matches(
    application_engine, principal_a, issue_credential
):
    """Source and format, from a real credential. Randomness is not asserted.

    What can be checked is that the value came from the database rather than from Python,
    that it has the one format this system has, and that two of them differ. What cannot be
    checked in a unit test is that the generator is a good one; ``gen_random_uuid()`` is
    PostgreSQL's strong RNG and this test does not pretend to have verified that.
    """
    first = issue_credential(principal_a, []).credential.reveal()
    second = issue_credential(principal_a, []).credential.reveal()
    assert BEARER_CREDENTIAL_REGEX.fullmatch(first)
    assert BEARER_CREDENTIAL_REGEX.fullmatch(second)
    assert first != second
    assert first.startswith(CREDENTIAL_PREFIX)
    # base64url alphabet only: the migration translates ``+/=`` and any newline away.
    body = first[len(CREDENTIAL_PREFIX):]
    assert set(body) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )


def test_no_source_file_calls_the_credential_length_its_entropy():
    """The specific error this correction removed, kept out by a check rather than by care.

    "43 characters of entropy" and "a 256-bit credential" said of the database's value were
    both wrong in the same way: a rendering is not a measurement, and the two generators do
    not carry the same number of bits.
    """
    root = pathlib.Path(secrets_module.__file__).resolve().parents[2]
    for relative in (
        "control_plane/security/secrets.py",
        "control_plane/db/auth.py",
        "control_plane/db/migrations/versions/0003_auth_context_and_audit.py",
    ):
        text_of = (root / relative).read_text()
        assert "43 bits" not in text_of, relative
        assert "43-bit" not in text_of, relative


# ------------------------------------------------------------- whitespace, enumerated
#
# The shape recogniser runs twice -- here, and as ``firmbatch.secret_shape`` inside
# PostgreSQL -- and "whitespace" used to be spelled ``\s`` in one and ``[[:space:]]`` in
# the other. Those are different sets, and the second is decided by the server's
# ``lc_ctype``, so the two implementations disagreed on real values: a U+00A0 followed
# by ``Bearer example`` was refused here and stored there.
#
# The set is therefore enumerated as data and folded to ASCII before any pattern runs.
# ``tests/test_audit_events.py`` is where the two implementations are compared against
# each other across the whole set; what is asserted here is the enumeration itself and
# the Python half's behaviour on it.


def test_the_whitespace_enumeration_is_exactly_pythons_own():
    """``WHITESPACE_CODE_POINTS`` is the contract, so it is checked against ``\\s``.

    Not a subset and not a superset. A missing code point is a value Python treats as a
    separator and the fold leaves alone, which is the gap this exists to close; an extra
    one would be a character folded to a space in Python and not in PostgreSQL, which is
    the same gap pointing the other way.
    """
    matched = {code for code in range(0x110000) if re.match(r"\s", chr(code))}
    assert set(secrets_module.WHITESPACE_CODE_POINTS) == matched
    assert len(secrets_module.WHITESPACE_CODE_POINTS) == len(
        set(secrets_module.WHITESPACE_CODE_POINTS)
    )
    assert list(secrets_module.WHITESPACE_CODE_POINTS) == sorted(
        secrets_module.WHITESPACE_CODE_POINTS
    )


def test_the_enumeration_contains_every_code_point_the_review_named():
    """The specific ones, so the list cannot be trimmed back to "the ASCII ones"."""
    named = {
        0x0085, 0x00A0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
        *range(0x2000, 0x200B),
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20,
    }
    assert named <= set(secrets_module.WHITESPACE_CODE_POINTS)


@pytest.mark.parametrize(
    "code", secrets_module.WHITESPACE_CODE_POINTS, ids=lambda c: f"U+{c:04X}"
)
def test_every_declared_whitespace_folds_to_an_ascii_space(code):
    assert secrets_module.normalize_whitespace(chr(code)) == " "


@pytest.mark.parametrize(
    "code", secrets_module.WHITESPACE_CODE_POINTS, ids=lambda c: f"U+{c:04X}"
)
def test_a_secret_shape_separated_by_any_declared_whitespace_is_recognised(code):
    """The reported bypasses, walked across the whole set rather than the two examples."""
    character = chr(code)
    assert (
        looks_like_secret(f"{character}Bearer example")
        == "an HTTP authorization header value"
    )
    assert (
        looks_like_secret(f"token{character}={character}example")
        == "a private key or token assignment"
    )


@pytest.mark.parametrize(
    "value",
    [
        "Grüße, naïve café",
        "日本語のノート",
        "русский текст",
        "αβγδε",
        "emoji 🙂 in a note",
    ],
)
def test_ordinary_unicode_is_left_alone_by_the_fold(value):
    """The fold rewrites separators and nothing else.

    "Refuse anything non-ASCII" would have closed the same gap and made a note in most of
    the world's scripts unstorable, which is why the correction is a fold over an
    enumerated set rather than a character-set restriction.
    """
    assert secrets_module.normalize_whitespace(value) == value
    assert looks_like_secret(value) is None


@pytest.mark.parametrize(
    "value",
    [
        "token\u00a0=\u00a0example",
        "TOKEN\u202f=\u202fexample",
        "Api_Key=example",
        "SECRET:example",
        "password\u2007:\u2007example",
    ],
)
def test_the_assignment_shape_is_case_insensitive_over_ascii(value):
    """Lowercase and uppercase markers alike.

    Case insensitivity used to come from ``re.IGNORECASE`` here and the ``~*`` operator
    there, which are Unicode and locale case folding respectively and did not agree. It
    now comes from the explicit ASCII fold in
    :func:`~firmbatch.control_plane.security.secrets.normalize_for_shape_scan`, applied
    before a case-*sensitive* pattern -- see the ASCII case-folding section below.

    Asserted here as well as in the cross-language corpus so that a change to either
    pattern fails on the Python side first, where the message is clearer."""
    assert looks_like_secret(value) == "a private key or token assignment"


def test_a_shape_refusal_still_names_only_the_shape():
    """The fold changes what is matched, never what is reported.

    The recogniser returns a description; it must not start returning the folded text,
    which would be the value it was asked about with its separators rewritten -- still the
    value.
    """
    probe = "\u00a0Bearer swordfish-swordfish"
    shape = looks_like_secret(probe)
    assert shape == "an HTTP authorization header value"
    assert "swordfish" not in shape
    assert "\u00a0" not in shape


# ------------------------------------------------- ASCII case folding, also enumerated
#
# The second half of the same defect. ``\s`` versus ``[[:space:]]`` was one
# locale-dependent construct; ``re.IGNORECASE`` versus ``~*`` was another, and it was still
# open after the whitespace fix. Measured on a real PostgreSQL 16 server, on the pre-fix
# patterns:
#
#     U+017F + "ecret=x"    (LATIN SMALL LETTER LONG S)  Python: refused  PostgreSQL: STORED
#     "api" + U+212A + "ey=x" (KELVIN SIGN)              Python: refused  PostgreSQL: STORED
#
# Python's ``re.IGNORECASE`` is Unicode case folding, which maps both of those onto ASCII
# letters. PostgreSQL's ``~*`` is locale case folding, which does not. The database is the
# half that holds when a runtime role calls ``append_audit_event`` itself, so the two
# disagreed exactly across the boundary a caller can walk around.
#
# The correction is the same shape as the whitespace one: fold explicitly, then match
# case-sensitively. Twenty-six pairs, A-Z to a-z, and nothing else in any script.
#
# The honest consequence is asserted here rather than hidden: a homoglyph is now detected
# by *neither* implementation. That is the right trade -- the alternative is a Unicode fold
# PostgreSQL cannot reproduce, which keeps a detection in the layer a caller can bypass and
# loses it in the layer that actually holds -- and ``looks_like_secret`` has never claimed
# to be anything but defense in depth against the obvious mistake.
#
# Every confusable or invisible character below is written as an escape. A U+017F is not
# distinguishable from an "s" in a diff, and this file is where that distinction is the
# entire subject.

SECRET_MARKERS = ("secret", "password", "token", "api_key", "apikey", "api-key")


def ascii_case_variants(word: str) -> tuple[str, ...]:
    """Lower, UPPER, Capitalised and aLtErNaTiNg -- ASCII case variation only."""
    return (
        word,
        word.upper(),
        word[:1].upper() + word[1:],
        "".join(c.upper() if i % 2 else c for i, c in enumerate(word)),
    )


def test_the_case_fold_is_exactly_the_twenty_six_ascii_pairs():
    """The mapping is the contract, so it is checked rather than described."""
    assert secrets_module.ASCII_UPPERCASE == "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    assert secrets_module.ASCII_LOWERCASE == "abcdefghijklmnopqrstuvwxyz"
    assert len(secrets_module.ASCII_UPPERCASE) == len(secrets_module.ASCII_LOWERCASE) == 26

    folded = secrets_module.fold_ascii_case
    for upper, lower in zip(secrets_module.ASCII_UPPERCASE, secrets_module.ASCII_LOWERCASE):
        assert folded(upper) == lower
    # And every other code point below U+0080 is carried through untouched, so the fold
    # cannot have picked up a digit, a separator or a punctuation mark by accident.
    for code in range(0x80):
        if chr(code) in secrets_module.ASCII_UPPERCASE:
            continue
        assert folded(chr(code)) == chr(code), hex(code)


@pytest.mark.parametrize(
    "value, why",
    [
        ("\u017F", "U+017F LATIN SMALL LETTER LONG S casefolds to 's' under Unicode"),
        ("\u212A", "U+212A KELVIN SIGN lowercases to 'k' under Unicode"),
        ("\u0130", "U+0130 LATIN CAPITAL I WITH DOT ABOVE lowercases under Unicode"),
        ("\u0131", "U+0131 LATIN SMALL DOTLESS I uppercases to 'I' under Unicode"),
        ("\u00C0", "U+00C0 LATIN CAPITAL A WITH GRAVE lowercases to U+00E0"),
        ("\u0391", "U+0391 GREEK CAPITAL ALPHA lowercases to U+03B1"),
        ("\u0410", "U+0410 CYRILLIC CAPITAL A lowercases to U+0430"),
    ],
)
def test_the_fold_is_ascii_and_not_unicode_case_conversion(value, why):
    """Each of these is changed by ``str.lower``/``str.casefold`` and must not be by us.

    This is the test that fails if somebody replaces the explicit table with
    ``value.lower()`` because it reads more naturally -- which is how the defect arrived in
    the first place, as ``re.IGNORECASE``.
    """
    # Some Unicode case operation changes it -- which one differs by character: the
    # long s and the Kelvin sign move under casefold/lower, the dotless i only under
    # upper. What matters is that Unicode has an opinion about all of them.
    assert {value.lower(), value.upper(), value.casefold()} != {value}, why
    # And ours has none.
    assert secrets_module.fold_ascii_case(value) == value, why
    assert secrets_module.normalize_for_shape_scan(value) == value, why


def test_the_module_uses_no_unicode_case_operation_anywhere():
    """Checked against the parse tree, because the rule is easy to state and easy to undo.

    ``str.lower()``, ``str.casefold()``, ``str.upper()``, ``re.IGNORECASE`` and an inline
    ``(?i)`` are all Unicode or locale operations that PostgreSQL's ``translate()`` cannot
    reproduce. None of them may appear in this module.
    """
    source = pathlib.Path(secrets_module.__file__).read_text()
    tree = ast.parse(source)

    calls = [
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("lower", "upper", "casefold", "swapcase", "title")
    ]
    assert calls == [], calls

    flags = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and node.attr in ("IGNORECASE", "I", "LOCALE", "L")
        and isinstance(node.value, ast.Name)
        and node.value.id == "re"
    ]
    assert flags == [], [ast.dump(node) for node in flags]


@pytest.mark.parametrize("name, pattern", secrets_module.SECRET_SHAPE_PATTERNS)
def test_no_pattern_contains_a_construct_either_engine_has_to_look_up(name, pattern):
    """The structural guarantee behind "the two agree by construction".

    Every one of these means something a locale or a Unicode table decides, and each is a
    way for the two implementations to disagree again:

    * ``\\s``/``\\S`` -- Unicode in Python, ``lc_ctype`` in PostgreSQL (the first defect);
    * ``(?i)`` -- Unicode case folding (the second);
    * ``\\b``/``\\y`` -- Unicode ``\\w`` versus locale ``[[:alnum:]]``;
    * ``\\w``/``\\d`` and ``[[:...:]]`` -- the same question in other clothes.

    What is left is literals, explicit ASCII classes, and lookaround.
    """
    for forbidden in (
        r"\s", r"\S", r"\b", r"\B", r"\w", r"\W", r"\d", r"\D",
        r"\y", r"\Y", r"\m", r"\M", "(?i)", "[[:",
    ):
        assert forbidden not in pattern, (name, forbidden)
    # Lowercase only: an uppercase ASCII letter could never match folded text, so one here
    # would be a pattern that had silently stopped firing.
    assert not any(c in secrets_module.ASCII_UPPERCASE for c in pattern), name


def test_the_compiled_patterns_are_ascii_and_case_sensitive():
    """No ``IGNORECASE`` survives to the compiled form, and ``re.ASCII`` is set."""
    for _, compiled in secrets_module.SECRET_VALUE_PATTERNS:
        assert not compiled.flags & re.IGNORECASE
        assert compiled.flags & re.ASCII
    assert [name for name, _ in secrets_module.SECRET_VALUE_PATTERNS] == [
        name for name, _ in secrets_module.SECRET_SHAPE_PATTERNS
    ]


def test_the_pipeline_is_whitespace_then_ascii_case():
    """Both steps, in the stated order, on one value that needs both."""
    probe = "\u00A0ToKeN = x"
    assert secrets_module.normalize_whitespace(probe) == " ToKeN = x"
    assert secrets_module.fold_ascii_case(" ToKeN = x") == " token = x"
    assert secrets_module.normalize_for_shape_scan(probe) == " token = x"


@pytest.mark.parametrize("marker", SECRET_MARKERS)
@pytest.mark.parametrize("separator", ["=", ":"])
def test_every_ascii_case_variant_of_every_marker_is_recognised(marker, separator):
    """SECRET, Secret, sEcReT, APIKEY -- one rule, not four spellings."""
    for variant in ascii_case_variants(marker):
        value = f"{variant}{separator}swordfish"
        assert looks_like_secret(value) == "a private key or token assignment", value


@pytest.mark.parametrize("word", ["bearer", "basic"])
def test_every_ascii_case_variant_of_an_authorization_scheme_is_recognised(word):
    for variant in ascii_case_variants(word):
        value = f"{variant} abcdefghijklmnop"
        assert looks_like_secret(value) == "an HTTP authorization header value", value


def test_the_other_shapes_are_case_folded_too():
    """The credential prefix, the PEM header, the URL scheme and the access-key prefix.

    All four used to be case-*sensitive* or case-insensitive by accident of which pattern
    happened to carry a flag. They are uniformly ASCII-case-insensitive now, which is a
    wider net and -- the point -- the same net in both implementations.
    """
    assert looks_like_secret("FBK_" + "a" * 43) == "a Firmbatch bearer credential"
    assert looks_like_secret("fbk_" + "A" * 43) == "a Firmbatch bearer credential"
    assert looks_like_secret("-----BEGIN RSA PRIVATE KEY-----") == "a PEM-encoded key block"
    assert looks_like_secret("-----begin rsa private key-----") == "a PEM-encoded key block"
    assert looks_like_secret("POSTGRESQL://u:p@h/db") == "a database URL carrying a password"
    assert looks_like_secret("AKIAIOSFODNN7EXAMPLE") == "an AWS access key id"
    assert looks_like_secret("akiaiosfodnn7example") == "an AWS access key id"


@pytest.mark.parametrize(
    "value",
    [
        "\u017Fecret=x",
        "\u017FECRET=x",
        "api\u212Aey=x",
        "API\u212AEY=x",
    ],
)
def test_a_homoglyph_marker_is_not_detected_and_that_is_a_stated_limitation(value):
    """The honest consequence of an explicit ASCII fold, asserted rather than left implicit.

    Before this correction Python refused these and PostgreSQL stored them. Now neither
    refuses them, and that is the deliberate choice: a Unicode fold cannot be reproduced by
    ``translate()``, so keeping it would mean the boundary a caller can bypass is stricter
    than the boundary that actually holds -- the worse of the two failures, because it reads
    as protection.

    ``looks_like_secret`` is defense in depth against a credential pasted where a reference
    belongs. It does not claim to recognise a semantic secret and it does not claim to
    survive a Unicode homoglyph. The data-flow proof is Milestone 5's; ADR 0005 decision 9
    and ADR 0006 decision 8c both say so.
    """
    assert looks_like_secret(value) is None
    # The homoglyph survives the pipeline untouched -- which is precisely why no pattern
    # matches it, and precisely why PostgreSQL gives the same answer.
    homoglyph = next(c for c in value if ord(c) > 0x7F)
    assert homoglyph in secrets_module.normalize_for_shape_scan(value)


@pytest.mark.parametrize(
    "value, expected",
    [
        # Turkish dotless and dotted i. Neither is ASCII, so neither folds -- and because
        # the word boundary is ASCII-explicit, a non-ASCII letter *is* a boundary, so the
        # marker after it is recognised. Both implementations say so together.
        ("\u0131token=x", "a private key or token assignment"),
        ("\u0130token=x", "a private key or token assignment"),
        # Not a match: the ASCII underscore between them is a word character, so there is
        # no boundary immediately before the marker.
        ("\u0130d_token=x", None),
        # Ordinary words in other scripts are ordinary metadata and stay storable.
        ("\u0130stanbul", None),
        ("\u0131smail", None),
        ("Grüße, naïve café", None),
        ("日本語", None),
        ("русский", None),
    ],
)
def test_non_ascii_text_is_carried_through_and_answered_consistently(value, expected):
    assert looks_like_secret(value) == expected
    # Every non-ASCII character survives the fold untouched. ASCII letters in the same
    # string do fold -- "Gr..e" becomes "gr..e" -- which is the whole design: ASCII
    # case is normalised, and nothing else in any script is.
    folded = secrets_module.fold_ascii_case(value)
    assert len(folded) == len(value)
    for original, result in zip(value, folded):
        if ord(original) > 0x7F:
            assert result == original, (hex(ord(original)), hex(ord(result)))
