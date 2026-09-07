# ADR 0008: Phase 0 runs on purchased capacity; Milestone 2 stands; delivery is staged; supplier, endpoint and frontier work waits for its trigger

- **Status:** Accepted
- **Date:** 2026-09-06
- **Decision owners:** Firmbatch product owner and maintainers
- **Milestone:** 3.0, architecture revision D.1 documentation adoption, on `main` `4511f7d` (PR #7)
- **Related:** ADR 0002 (authority order and language boundaries — this ADR updates the
  source revision it names and moves the operator agent's trigger); ADR 0003 (build beside
  v0; customer and operator products stay separate); ADR 0004–0007 (the Milestone 2
  foundation this ADR preserves); `docs/architecture/v1-target-architecture.md` rev D.1;
  `docs/architecture/rev-d-decision-register.md`; `docs/architecture/sources/README.md`

## Context

Revision D of the target architecture (6 September 2026, supplied as a PDF and a Markdown
file) follows business plan v3.4's **Phase 0**: the first paying jobs run on hyperscaler spot
capacity that Firmbatch **buys** — Google Cloud first, then Azure and AWS, with Verda asked
to match — and the operator capacity agent is built only when a supplier signs. Rev C had
grouped the operator agent, the Verda and Lyceum adapters, window offers and settlement into
one Milestone 6 and put a signed residual supplier on the launch path.

Rev D changes what v1 is made of, not what it is. It adds a purchased supply class with
frozen purchase fields, a platform-level bridge envelope, a cost term in routing while
capacity is bought, three spot drivers, Gate 1 measurements as first-class records, a usage
basis per supply class, node-level windows and multi-GPU executions, measured throughput in
the certification registry, the evaluation tier, `auto_accept_below` decided in favour, an
optional provider policy, cross-cloud egress in the cost table, and the firm tier's
definition aligned with the plan. The ledgers and the settlement formulas do not change.

The rev D adoption review found ten items — four differences between the rev D PDF and
Markdown, and six rules both deferred to companions that had not been supplied — and
carried them open. **Revision D.1**, issued the same day and before this branch was
committed, resolves all ten by taking the settlement canon (`settlement-model-r1_3.md`,
Amendment 4), plan v3.4 or roadmap r2_4 as the authority, and adds an internal
**qualification** service tier. The companions — the settlement canon, plan v3.4, roadmap
r2_4, the GPU price register, the customer brief, the definitions register, the
demand-alternatives map, the operator's equation paper and both RFQs — were supplied with
D.1 and read in full for this adoption.

Meanwhile Milestone 2 closed under its agreed scope: M2.1 PostgreSQL and tenant isolation,
M2.2 idempotency and the transactional outbox, M2.3 authenticated context, authorization,
audit and secrets, M2.4 persisted lifecycle state machines — merged through PR #7 at
`4511f7d` (implementation `d91e4f2`), with the post-merge verification transcript reporting
14 gates passed and 97 required files, and the last detailed local foundation-suite count at
1,746 collected, 1,745 passed, 1 skipped. Nothing in M2 is deployed or VERIFIED LIVE.

Two facts made a recorded decision necessary rather than an edit:

1. The supplied D and D.1 Markdown files open with "Nothing here is implemented". Read as a
   statement about the repository it would erase a merged foundation. Read correctly it is
   a target document's disclaimer about itself.
2. The companions inform the architecture and carry planning figures — a bridge budget
   range, list prices, throughput assumptions — that are decisions and assumptions in their
   own registers, not verified market data. An adoption that copied them into the repository
   as configured caps or prices would be presenting a plan's range as a production number.

## Decision

### 1. Rev D.1 is the target; the canonical rendering keeps its numbering and §17

`docs/architecture/v1-target-architecture.md` now renders **rev D.1**, sourced from
`firmbatch_v1_target_architecture_5.pdf` and `architecture-v1_4.md`. ADR 0002 decision 1,
which named the rev C PDF, is updated by this decision without being rewritten; ADR 0002's
authority order is unchanged.

The rendering keeps sections 1–17 and their numbers. §17 invariants 1–11 are preserved
byte for byte, because `AGENTS.md`, the `milestone` skill and ADRs 0004–0007 cite them by
number; the purchased-capacity rule is appended as invariant 12 and the provider-policy
scope as invariant 13, both stated as D.1 states them. D.1 content is integrated into the
existing sections as subsections, and §18 records the rev C → D → D.1 change list. Both
supplied Markdown revisions are preserved verbatim under `docs/architecture/sources/` with
their hashes; D.1 is the current source and D is the historical reviewed input; the PDFs and
the companions are hash-referenced in the manifest.

### 2. Business phases are not engineering milestones

**Phase 0** is the purchased-capacity launch track; **Phase P** is the signed-supplier
extension (operator agent, nominated classes in production, two-sided settlement statements,
router across operators); **Phase B** is the frontier and multi-GPU lane and firm-tier
activation. Engineering milestones remain M0–M8. "Milestone 0" and "Phase 0" are different
things and the documents say which they mean.

### 3. Milestone 2 stands, and later domain work extends it through new migrations

The merged foundation — PostgreSQL as metadata authority, forced row-level security,
authenticated context with a separate issuing authority, atomic idempotency, audit and
outbox, generic lifecycle machines with protected provenance, the dedicated lifecycle
writer role, explicit configuration and secrets boundaries, disposable-cluster
verification — is retained unchanged. D.1 requires no M2 rewrite and no "M2.5". New
application features (accounts, jobs, purchases, measurements, windows) arrive as new
domain migrations; merged migrations `0001`–`0004` are history and are not edited.

M2's completion is **not** proof of S3 access isolation, billable job contracts, cloud launch
caps, supplier settlement, production secret integration or customer launch readiness.
Each has its own later gate.

### 4. Milestone 3 is next, and it starts with identity bound to membership

M3.0 is this documentation adoption. M3.1 builds real customer identities, workspace
membership and the trusted issuance path from verified identity and active membership to
the M2.3 database context, keeping browser sessions distinct from scoped API credentials.
M3.2 builds the customer application. `AUTH-MEMBERSHIP-BOUND-IDENTITY` remains the
launch-blocking requirement; the raw-GUC weakness the old roadmap described as open was
closed in M2.3 and its adversarial tests are retained, not rebuilt.

### 5. A protected AWS staging preview is pulled forward to M3.3

A minimal customer frontend, API and RDS PostgreSQL staging environment is scheduled at the
end of M3, before M4, so the product can be seen and reviewed on real infrastructure with
synthetic accounts. This pulls a **necessary subset** of M8's controls forward — TLS, network
isolation, real secrets delivery, separated runtime, migration and issuer credentials, safe
metadata-only logging, migrations as an explicit step, backups and restore, session, cookie,
CSRF and origin protections, access restriction — and qualifies M2.4's `NOLOGIN` lifecycle
writer and the role and migration installation on managed RDS permissions.

It is a recommendation responding to the wish to see the product, not a D.1 requirement.
**Deploying it is planned, not authorized:** a reviewed infrastructure plan, a current cost
estimate and explicit deployment authorization precede creating any resource. No cloud
resource was created by this decision.

### 6. Phase 0 purchases are admitted, capped, accounted gross, and human-authorized

No purchase is launched without an admitted job, and none outside the platform bridge
envelope; `purchase_rate` and `supplier_account` are frozen on every purchased execution;
evaluation and qualification jobs spend the bridge under their own caps and count against it
(target §17 invariant 12). The envelope's accounting is D.1's, from plan v3.4: **enforcement
is gross accrued spend** — every launch reserves its envelope's maximum hours at the frozen
rate, usage records replace the reservation, provider invoices reconcile monthly — while
**reporting** is net of customer billings invoiced in the same calendar month, in USD at the
ECB reference rate of the day; a launch that would breach the monthly cap, the total cap or
a supplier sub-cap is refused at admission; retirement is numeric (no new purchase for a job
once a shared placement is eligible; none after twelve months from the first purchase
without a recorded re-authorisation); reporting is weekly against the caps.

**The plan's $3–5k a month and $10k total are a planning range and an exposure line, not a
configured cap.** The exact monthly cap, total cap and per-supplier sub-caps are spend and
deployment decisions a human records on the envelope before the first purchase. This ADR
fixes none of them.

To break the cycle in which paid admission needs measured certification and measurement
needs executions, D.1's **qualification service tier** is adopted: internal jobs on an
internal tenant, on allow-listed profiles, capped like any purchase, invisible to customers,
each specifically authorised by a human with its account, region, SKU, duration, maximum
spend and cleanup stated, and whose only output is the registry's measurements and the pool's
measurement records. Gate 1 runs its stated protocol — one instance per pool per zone for
seven days on the smallest single-GPU SKU, with the pass and fail thresholds D.1 states and
the plan owns. A qualification run does not certify a profile for customers by fiat, and a
single successful run is not "Gate 1 passed" without the plan's evidence requirements.

Any "capacity probe" that allocates a real VM is a purchase. `fb run --provider verda` and
its successors remain human-run actions under `AGENTS.md`.

### 7. One driver first; all four Phase 0 VM drivers remain scope

The first purchased driver is Google Cloud spot, per the stated preference and subject to
current price, SKU, region and quota eligibility. Azure, AWS and Verda follow as separate
reviewed slices behind the same execution contract. Completing one driver before multiplying
it is a sequencing choice, not a reduction of the four-driver target. An unqualified pool is
recorded as unavailable and gated off, never claimed launch-ready.

### 8. Windows, nominations and operator statements are built and tested dark, to the canon

The window state machine, nominated supply classes, frozen terms and operator statement
calculations are Phase 0 target scope: built in M6.5 against the settlement canon's rules —
the twelve-cause enum with `operator_platform_failure`, revocation by `operator_reclaim`,
`operator_blackout` and an operator-asserted `security_stop`, the once-per-operator-month
`max` with per-class grouping as a contract parameter, the 90-day true-up and the two-clock
settlement timing — exercised end to end in tests, and dark until a supplier signs or exposes
a capacity endpoint. The operator capacity agent and production two-sided statements move to
Phase P. Deferring the agent does not delete the test scope, and the dormant paths must be
unable to create a production obligation.

### 9. The endpoint adapter waits for a signed endpoint supplier

Lyceum or an equivalent endpoint is implemented only after terms, drop signals and usage
evidence exist. Accounting is per request from the supplier's usage records, with raw token
meters retained as evidence and the contract's pricing unit frozen on the attempt, and it
preserves the three ledgers with one execution per attempt. Endpoint participation never
passes Business Gate 2 and never earns a nomination premium.

### 10. Multi-GPU, the frontier lane and firm activation are Phase B

`execution_spec` carries `gpu_count`, parallelism and node class from the start so the
certification registry can be keyed on them; Phase 0 execution is `gpu_count = 1`. Node
windows and multi-GPU executions are certified and enabled in Phase B. The firm tier — a
customer-named deadline of at least 24 hours and under 72 — is defined and built dark in
M4–M6 and activated in Phase B after the same workload survives measured provider loss and
cross-provider recovery with eligible hedge capacity, admission coverage and the agreed
credit policy. The previous "24-hour firm tier" wording is superseded.

### 11. The D review items are resolved by D.1 and recorded; the remaining choices are named

`docs/architecture/rev-d-decision-register.md` records, for each of the ten rev D review
items, what the review found, what D.1 decides and the source authority by section. The
canonical target carries every resolution unmarked. What remains are **implementation
choices the authorities leave open on purpose** — the configured bridge caps, the numeric
per-evaluation token and spend caps, the quote validity duration, the corpus identity rule,
the qualification tenant and allow-list, per-contract settlement parameters, operator- and
supplier-quoted rates, the model band as a measurement outcome, the AWS staging
authorisation and the agent language — each with its owner and slice. No value for any of
them is invented by this adoption, and none blocks Milestone 3.

### 12. The customer application and operator-side software remain separate

Unchanged from ADR 0003 and §17 invariant 11. Supplier capacity, pool identities, bridge
budgets and operator settlement have no customer administrative route. A customer's
`provider_policy` is a constraint the customer states, not an internal capacity console; in
v1 it governs execution placement only and not the payload plane, and the consent text says
so.

## Consequences

- One active implementation sequence: `docs/firmbatch-v1-roadmap.md` at rev D.1. The rev C
  roadmap is recoverable from git history and is not a competing plan.
- The M2 foundation is cited as the base for M3 rather than reopened; every later slice
  inspects the code it extends and adds migrations and regressions where needed.
- The first hosted, protected view of the product arrives at M3.3, before any commercial or
  execution milestone, and before any GPU driver is enabled.
- Spend enters the system in M6.2 and nowhere earlier, behind admission, gross-accrual caps a
  human has configured, credentials and per-run human authorization.
- Contract enums and settlement schemas can be frozen to the canon in M6.5 without waiting
  on a further architecture revision, because D.1 resolved the source differences.
- Documents now distinguish Phase 0 / P / B from M0–M8 explicitly, at the cost of one more
  vocabulary a reader has to hold.

## What this decision does not claim

- It does not authorize any cloud purchase, deployment, customer invitation, supplier
  contact or settlement payment. Selecting a sequence and accepting a document authorizes
  none of those, and neither does reading the companions.
- It does not claim that any D.1 capability is implemented. `docs/STATE.md` is the record of
  what the code does, and every D.1 addition is PLANNED there.
- It does not verify a price, SKU, region, quota, notice period, throughput figure or cost
  example in the sources or the companions. Those are the documents' figures at their capture
  dates, require fresh verification before use, and are never spending authority.
- It does not fix the bridge caps, the evaluation caps, the quote expiry or any other value
  the authorities leave to configuration, contract or measurement.
- It does not reclassify any M2 evidence. Milestone 2 remains implemented and tested, not
  deployed and not VERIFIED LIVE; no evidence artifact exists for it.

## Rejected alternatives

### Replace the canonical target with the supplied Markdown wholesale

Rejected. The supplied file is unnumbered, `AGENTS.md`, the `milestone` skill and four ADRs
cite §17 by number, and a wholesale replacement would have forced a protected-file rewrite
to fix anchors. The snapshots are preserved verbatim instead, and the canonical rendering
integrates D.1 under the existing numbering.

### Reopen Milestone 2 as "M2.5" to pre-build purchase, measurement and evaluation tables

Rejected. Nothing in D.1 requires a foundation change; the new domain tables belong with the
milestones that give them meaning (M4–M6), where their contracts can be tested against real
fixtures. Pre-building them now would be the opportunistic later-milestone work the working
contract forbids.

### Keep the rev C sequence and treat D.1 as a later supply detail

Rejected. D.1 moves the launch dependency from a signed residual supplier to purchased
capacity with spend controls, which changes M4's budget model, M5's contract fields, M6's
entire shape and M8's release matrix. A roadmap that still put the operator agent and a
Lyceum adapter on the launch path would be sequencing work the product no longer needs
first.

### Copy the plan's bridge range into the repository as the production cap

Rejected. Plan v3.4 carries $3–5k a month and $10k total as a planning range and an exposure
line, and the definitions register grades the cap a *decision*. Writing a point value into
the architecture would present a planning range as a configured production number and would
make a spend decision that belongs to a human at deployment time.

### Keep D1–D10 open until a further revision

Rejected. D.1 resolves each against a named authority that is now supplied; keeping them
open would leave M6.5 unable to freeze contracts the canon already settles. The register
keeps the review findings visible beside the resolutions, which is the auditability that
mattered.

### Deploy staging as part of this adoption, since the controls are known

Rejected. This is a documentation change. Creating cloud resources needs a reviewed
infrastructure plan, a cost estimate and explicit authorization, none of which a document
adoption supplies.
