"""The consent and subprocessor statement, and the one place its text lives.

Milestone 3.2 deliverable. The rev D review register closes item D8 with: "The
customer-facing consent text is an M3.2/M5 deliverable and **must match the rule**", and the
rule is target §5.4 with §17 invariant 13. So the text is held here, versioned, served by
``GET /v1/consent``, and rendered by the portal from that response rather than from a copy
of its own -- a second copy in the frontend is a second copy that can drift, and this one is
the one the database validates an acknowledgement against
(``models.CONSENT_VERSIONS``).

**What the text must say, exactly, and why each clause is load-bearing:**

* ``provider_policy`` is a customer-stated exclusion of a provider **class or named
  subprocessor**, and it constrains **execution placement only** -- first placement, every
  retry, every move to shared capacity and every hedge. It names *whose*, never *where*, and
  it never selects a placement (§5.4).
* It **does not govern the payload plane**. The payload plane is S3 for every tenant until a
  bucket per supplier cloud region exists (§3.3).
* Therefore **a customer who excludes Amazon altogether cannot be served in v1**. D.1's
  instruction is that the consent text says exactly that "rather than promising an exclusion
  the design cannot honour". It is stated here as a plain refusal, not a footnote.
* An exclusion grants the customer **no view of or control over** supplier capacity, pool
  identities, bridge budgets or operator settlement (§17 invariants 11 and 13).

**What the text must not say.** It is not a privacy policy, not a DPA, not a contract, and
not a price. It carries no figure, no region list beyond what the target names, and no
promise about a capability a later milestone owns. The marketing site (`firmbatch.com`, a
separate repository) is not the authority for it and does not carry a copy.

Adding a version means appending to :data:`CONSENT_DOCUMENTS` **and** to
``models.CONSENT_VERSIONS``, which migration ``0006`` renders as a check constraint. A row
cannot acknowledge text that does not exist, and ``tests/test_portal_migration.py`` holds the
two inventories equal (``test_the_consent_versions_the_schema_knows_are_the_ones_the_api_serves``).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ConsentSection:
    """One headed block of the statement. Plain text; the portal supplies the markup."""

    heading: str
    body: tuple[str, ...]


@dataclass(frozen=True)
class ConsentDocument:
    """One version of the consent and subprocessor statement."""

    version: str
    title: str
    #: The authorities this text states, so a reader can check it against them.
    authority: str
    sections: tuple[ConsentSection, ...]

    def payload(self) -> dict:
        return {
            "version": self.version,
            "title": self.title,
            "authority": self.authority,
            "sections": [
                {"heading": section.heading, "body": list(section.body)} for section in self.sections
            ],
        }


_PROVIDER_POLICY_V1 = ConsentDocument(
    version="provider-policy-v1-d.1",
    title="Execution placement, subprocessors and what Firmbatch can and cannot honour",
    authority=(
        "Firmbatch v1 target architecture revision D.1, sections 3.3 and 5.4, and invariant 13. "
        "This statement describes v1 scope. It is not a contract, a privacy policy or a price."
    ),
    sections=(
        ConsentSection(
            heading="What a provider policy is",
            body=(
                "A provider policy is a constraint you state: a class of provider, or a named "
                "subprocessor, that Firmbatch must not run your work on.",
                "It names whose hardware, never where the work runs. You do not choose a "
                "placement, a region, a machine or a supplier; Firmbatch chooses those, and your "
                "exclusions bound the choice.",
            ),
        ),
        ConsentSection(
            heading="What it governs, and what it does not",
            body=(
                "In v1 a provider policy governs execution placement only. It applies to the "
                "first placement, to every retry, to every move to shared capacity, and to every "
                "hedge.",
                "It does not govern the payload plane. Your inputs and outputs are stored in "
                "Amazon S3 for every customer, and will be until Firmbatch operates a storage "
                "bucket in each supplier's cloud region.",
            ),
        ),
        ConsentSection(
            heading="The exclusion v1 cannot honour",
            body=(
                "Because the payload plane is Amazon S3, a customer who excludes Amazon "
                "altogether cannot be served by Firmbatch v1.",
                "You may still record that requirement here, and it will be kept. Firmbatch will "
                "not accept work under an exclusion it cannot honour, and will refuse the "
                "submission with that reason rather than run the work anyway.",
            ),
        ),
        ConsentSection(
            heading="Subprocessors in v1",
            body=(
                "Execution runs on purchased capacity from Google Cloud, Microsoft Azure, Amazon "
                "Web Services and Verda. Every one of them may process the requests you submit.",
                "Amazon Web Services additionally stores your inputs and outputs as the payload "
                "plane, whether or not you exclude it from execution.",
            ),
        ),
        ConsentSection(
            heading="What a provider policy does not give you",
            body=(
                "Stating an exclusion gives you no view of and no control over supplier capacity, "
                "pool identities, Firmbatch's own spend, or how Firmbatch settles with suppliers. "
                "Those are internal and supplier surfaces with separate identities and interfaces, "
                "and no customer account reaches them.",
            ),
        ),
        ConsentSection(
            heading="What acknowledging this records",
            body=(
                "Acknowledging records that this version of this statement was shown to you, when, "
                "and by which account. It does not create a job, a quote, an invoice or any "
                "commitment to run work.",
            ),
        ),
    ),
)

#: Every version this API knows, newest last. Keyed by version so a lookup cannot pick the
#: wrong one by position.
CONSENT_DOCUMENTS: dict[str, ConsentDocument] = {_PROVIDER_POLICY_V1.version: _PROVIDER_POLICY_V1}

#: The version a portal is offered when it asks for the statement to acknowledge.
CURRENT_CONSENT_VERSION: str = _PROVIDER_POLICY_V1.version


def current_consent() -> ConsentDocument:
    return CONSENT_DOCUMENTS[CURRENT_CONSENT_VERSION]
