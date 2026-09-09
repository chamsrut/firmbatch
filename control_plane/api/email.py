"""The email-delivery boundary: where a verification, recovery or invitation secret leaves the process.

Milestone 3.1 implements the *interface* and a test-only capture adapter, and no provider.
The production adapter is :class:`UnavailableEmailDelivery`, which **raises**: there is no
provider configured at this milestone, no environment variable that substitutes one, and
no fallback that writes the message somewhere else. The same fail-closed shape as the
secret resolver in ``security/secrets.py``, and for the same reason -- a delivery path
that quietly logged the message would put every verification link in a log file.

What a message carries
----------------------

A :class:`OutboundEmail` names the kind of message, the recipient, and -- for the three
kinds that carry one -- the secret as a
:class:`~firmbatch.control_plane.security.secrets.Secret`. The secret is the only copy
outside the database's result row; it is never rendered by the message, never logged, and
reaches text only inside an adapter's ``deliver``. The HTTP boundary never returns it in a
response.

The capture adapter exists so tests can complete a flow: it keeps every message in memory
and hands the secret back to a test that asks. It refuses to be constructed outside the
``test`` environment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ..config import Environment
from ..security.secrets import Secret, SecretError

#: The kinds of message this boundary sends. Closed.
EMAIL_KINDS: tuple[str, ...] = (
    "account_exists",
    "email_verification",
    "account_recovery",
    "workspace_invitation",
)


class EmailDeliveryError(RuntimeError):
    """Delivery failed. Never carries the recipient's secret."""


class EmailDeliveryUnavailable(EmailDeliveryError):
    """No delivery adapter is configured in this environment."""


@dataclass(frozen=True, repr=False)
class OutboundEmail:
    """One message to one recipient, carrying at most one secret."""

    kind: str
    recipient: str
    secret: Secret | None = None
    #: Non-secret context for the template: a workspace name, a role. Bounded, plain.
    context: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in EMAIL_KINDS:
            raise SecretError("that is not a kind of message this boundary sends")
        if self.secret is not None and not isinstance(self.secret, Secret):
            raise SecretError("an outbound secret is handled as a Secret, never as a plain string")
        for value in self.context.values():
            if not isinstance(value, str) or len(value) > 256:
                raise SecretError("email context values are short plain strings")

    def __repr__(self) -> str:
        # The recipient is not secret; the secret is, and is not rendered.
        return f"OutboundEmail(kind={self.kind!r}, recipient={self.recipient!r}, secret=<redacted>)"

    __str__ = __repr__


class EmailDelivery(Protocol):
    def deliver(self, message: OutboundEmail) -> None:  # pragma: no cover - protocol
        ...


@dataclass(frozen=True)
class UnavailableEmailDelivery:
    """The production adapter, and it delivers nothing yet.

    A later milestone replaces the body with a provider call from the service role that
    owns the provider credential. Until then it raises, so that a signup in an environment
    with no provider is visibly undeliverable rather than silently lost.
    """

    def deliver(self, message: OutboundEmail) -> None:
        raise EmailDeliveryUnavailable(
            f"no email delivery adapter is configured in this environment, so the {message.kind} "
            "message could not be sent. Milestone 3.1 implements the interface and a test capture "
            "adapter only; a real provider is configured and contacted by a later milestone, and "
            "there is deliberately no fallback."
        )


class CapturingEmailDelivery:
    """The test double: keeps every message in memory. Refuses to exist outside ``test``."""

    def __init__(self, environment: Environment) -> None:
        if environment is not Environment.TEST:
            raise SecretError(
                "CapturingEmailDelivery is a test double and refuses to run outside the test "
                "environment: it holds verification, recovery and invitation secrets in memory."
            )
        self.messages: list[OutboundEmail] = []

    def deliver(self, message: OutboundEmail) -> None:
        self.messages.append(message)

    def last(self, kind: str, recipient: str | None = None) -> OutboundEmail | None:
        for message in reversed(self.messages):
            if message.kind == kind and (recipient is None or message.recipient == recipient):
                return message
        return None

    def __repr__(self) -> str:
        return f"CapturingEmailDelivery(<{len(self.messages)} messages>)"
