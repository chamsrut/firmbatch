# Architecture rev D review and rev D.1 resolution register

**Status:** Auditable record of the ten rev D review items, each with its rev D.1 resolution and source authority, plus the implementation choices that genuinely remain
**Adopted:** 2026-09-06, Milestone 3.0 documentation adoption, on `main` `4511f7d` (PR #7)
**Sources:** the rev D.1 Markdown and PDF, the rev D Markdown and PDF (historical reviewed input), and the companions listed with hashes in `docs/architecture/sources/README.md`
**Canonical rendering:** `docs/architecture/v1-target-architecture.md` (revision D.1)
**Related:** ADR 0008; `docs/firmbatch-v1-roadmap.md` §"Remaining decisions"

## How to read this register

The rev D adoption reviewed two supplied rev D documents (a PDF and a Markdown file) against
each other and against the repository, and found ten items: four places where the two sources
differed (D1–D4) and six rules both sources deferred to companion documents that had not been
supplied (D5–D10). It carried all ten as open rather than choosing a reading.

**Revision D.1 (6 September 2026, same day) resolves all ten**, in every case by taking the
settlement canon (`settlement-model-r1_3.md`, Amendment 4), plan v3.4 or roadmap r2_4 as the
authority, and the companions are now supplied and were read in full for this adoption. Each
entry below records: what the D review found; what D.1 decides; the source authority, by
section; where the canonical target now states it; and whether any **genuine implementation
choice** remains. A remaining choice is one the authorities deliberately leave to a
configuration, a contract or a measurement. **No value is invented here.** Where an authority
gives a planning range, the register says so and does not turn it into a fixed number.

Nothing in this register authorizes a purchase, a deployment, a supplier contact or a customer
launch. The companions inform the documentation; the human owns those actions.

## 1. Items D1–D10: review finding and D.1 resolution

### D1 — cancellation cause identifier

- **D review finding.** The rev D PDF (p. 7) and the rev C rendering named
  `operator_platform_failure`; the rev D Markdown's enum named `platform_failure`. Not
  interchangeable in a closed contract enum.
- **D.1 resolution.** The cause is **`operator_platform_failure`**. The D.1 Markdown's enum
  block and the D.1 PDF (p. 8) both carry it, and say the names are the settlement canon's.
- **Authority.** `settlement-model-r1_3.md` §4 "Cancellation causes — a fixed enum"; roadmap
  r2_4 §5 invariant 21 and §6.3 (the same twelve causes, "no second list anywhere").
- **Canonical target.** §11 table, unmarked.
- **Remaining choice.** None. Adding or renaming a cause is a contract amendment.

### D2 — `security_stop` and window revocation

- **D review finding.** The rev D PDF said an operator-asserted `security_stop` revokes an
  accepted window; the rev D Markdown said only `operator_reclaim` and `operator_blackout` do.
- **D.1 resolution.** Revocation follows the canon's table: **`operator_reclaim`,
  `operator_blackout`, and a `security_stop` the operator asserts** revoke an accepted window;
  `operator_platform_failure` does not, because nobody chose it; no Firmbatch-side cause does.
- **Authority.** `settlement-model-r1_3.md` §4 cause table, "Revokes an accepted window"
  column (`security_stop`: "operator-asserted: yes"); D.1 Markdown "Settlement" bullets; D.1
  PDF p. 8.
- **Canonical target.** §11 table and the paragraph after it.
- **Remaining choice.** None. **Companion note:** roadmap r2_4 §5 invariant 21 still says
  "only the two operator-side causes do". The canon's own status line makes the canon right
  and that sentence stale; D.1 follows the canon. Recorded so a reader of r2_4 is not misled;
  it is not an open rule.

### D3 — settlement grouping and the late-collection true-up

- **D review finding.** The rev D PDF stated operator-month aggregation across supply classes
  with per-class grouping as a contractual fallback, and the 90-day true-up; the rev D
  Markdown stated the monthly formula and omitted both.
- **D.1 resolution.** The `max` is taken **once per operator per settlement month across all
  supply classes together**; per-class grouping is the contractual fallback if an operator
  refuses, and the reconciler takes the grouping as a **contract parameter** so one
  implementation serves either; never pooled across operators. **Each period stays open for
  true-up for 90 days**: the floor leg and cancellation credits are paid on the statement
  whatever has been collected; the share leg, and under Structure B any amount by which it
  exceeds the floor already paid, is paid on collection at the `s_u` frozen on the unit;
  collections inside the window settle on the next statement; nothing is clawed back; a paid
  floor is final; the true-up moves only in the supplier's favour.
- **Authority.** `settlement-model-r1_3.md` §3 (grouping), §4 "Late collection — the
  true-up" and "Settlement timing"; plan v3.4 §6.5; roadmap r2_4 P4 cash rules; RFQ r2 §2.2–2.3.
- **Canonical target.** §9.3 and §9.4.
- **Remaining choice.** Which grouping a given contract carries (operator-month by default;
  per-class only if that operator refuses) is a **per-contract parameter**, set when a
  supplier signs (Phase P). Not an architecture decision and not open for Phase 0, which has
  no supplier settlement.

### D4 — endpoint metering unit

- **D review finding.** The rev D supply table said accepted requests or tokens, or a
  per-token price; the enum prose said `usage_basis = requests`; delivery-valid work and
  customer acceptance were at risk of being collapsed.
- **D.1 resolution.** Execution accounting on endpoint supply is **per request**, from the
  supplier's own usage records; **raw input and output token meters are stored beside it**
  whenever the supplier reports them, as evidence; the **pricing unit** — a share of NCR or a
  per-token price — is a **frozen term on the attempt**, like `share_bps`; a delivery-valid
  request is one whose response passed structural validation; an accepted unit is one the
  customer's policy accepted, attributed per request exactly as on GPU supply; no GPU-hours
  are ever fabricated for an endpoint supplier, and delivery-valid work and customer
  acceptance are not collapsed.
- **Authority.** D.1 Markdown "Supply classes" (endpoint metering paragraph); D.1 PDF p. 9;
  endpoint RFQ r1 §2 (share of NCR or per-million-token price; drop signal; per-request usage
  records); `settlement-model-r1_3.md` §2 (attribution per request).
- **Canonical target.** §12.2.
- **Remaining choice.** Which pricing unit a particular endpoint supplier quotes (share or
  per-token) is the supplier's answer to endpoint RFQ Q3 and is frozen per contract. Belongs
  to the endpoint extension; blocks nothing before it.

### D5 — bridge cap amounts and the spend-accounting definition

- **D review finding.** Both rev D sources specified a monthly cap "net of billings", a total
  cap and per-supplier-account sub-caps, with no amounts and no accounting definition.
- **D.1 resolution.** The amounts come from **plan v3.4: $3–5k a month net of billings and
  $10k in total** — a planning range and exposure line. The envelope **enforces gross accrued
  spend**: every launch reserves its envelope's maximum hours at the frozen rate; usage records
  replace the reservation as they arrive; provider invoices reconcile the total monthly. It
  **reports** net of the customer billings **invoiced** (not collected) for jobs run on
  purchased capacity in the same calendar month, before credits, refunds and taxes, in USD at
  the ECB reference rate of the day. Evaluation and qualification spend count gross like any
  other. A launch that would breach the monthly or total cap or its supplier sub-cap is
  **refused at admission**, not flagged. Retirement is numeric: no new purchase for a job once a
  shared placement is eligible for it, and none at all after twelve months from the first
  purchase without a re-authorisation recorded on the envelope. Reporting is weekly against
  the caps and monthly at reconciliation.
- **Authority.** Plan v3.4 §3.2 ("Three caps, written down before the first purchase") and §5
  (exposure "capped at ~$10k"); definitions r4 §8 register row "bridge budget cap — decision";
  roadmap r2_4 decision rule 15 and D5; D.1 Markdown "The bridge envelope"; D.1 PDF p. 4.
- **Canonical target.** §8.1; §17 invariant 12.
- **Remaining choice — genuine, and deliberately not fixed here.** The **exact configured
  monthly cap, total cap and per-supplier sub-caps** are deployment and spend decisions a
  human records on the envelope before the first purchase (M4.3 model, enforced before M6.2).
  The plan's $3–5k is a planning range, not a production number, and this register does not
  pick a point in it. The ECB reference-rate convention (rate of the launch day) is stated;
  whether a cap is re-authorised at month twelve is a later human decision by construction.

### D6 — measured qualification protocol and thresholds

- **D review finding.** Gate 1's observations were explicit; the sample, protocol and pass
  thresholds were said to live in the business plan, which had not then been supplied; the
  narrative example was at risk of being operationalised as the whole gate.
- **D.1 resolution.** Gate 1 has a **protocol**: one instance per pool per zone for **seven
  days**, on the smallest single-GPU SKU, running a **qualification** job. The pool **passes**
  when the median lifetime exceeds sixty minutes, preemptions run at three a day or fewer per
  instance, and grants succeed on at least four attempts in five; it **fails** when the median
  sits within a factor of two of `W_min` or grants fail more often than one in five, and the
  bridge moves to the next supplier. Samples and their provenance are stored, not only the
  summary. The plan owns the thresholds and may change them; the architecture insists only
  that they are numbers and that only measured profiles are certified. Listed prices and the
  `W_min` table's examples are not measurements.
- **Authority.** D.1 Markdown "Measurement records" and D.1 PDF p. 4, which state the protocol
  and attribute the decision rule to plan v3.4 §3.1. **Attribution note:** the supplied plan
  v3.4 (§3.1, §5 Gate 1 row) states Gate 1's deliverable — run, kill, recover, reconcile,
  measure load times, commit interval, recovery cost, `η_delivery`, throughput and `W_min` —
  and its kill condition, but the seven-day protocol and the numeric thresholds are printed
  in rev D.1, not in the plan copy supplied. They are adopted from D.1 as the plan-owned rule
  D.1 says they are.
- **Canonical target.** §8.3; roadmap M6.2.
- **Remaining choice.** None in the rule. The thresholds are the plan's to revise, and a
  revision is recorded as a plan change, not silently in code. Business Gate 1 "passed" still
  needs the plan's evidence, not a single run.

### D7 — evaluation and `auto_accept_below` contract details

- **D review finding.** Evaluation scope and reset, anti-abuse rules, token and spend caps,
  report behaviour on zero accepted units and on failed, partial or cancelled jobs, and the
  definition of the escalation rate `x` were unstated; `auto_accept_below` lacked an equality
  rule, tax, fee and currency treatment, expiry and consent binding.
- **D.1 resolution — evaluation.** **One free evaluation per tenant per corpus**; a second on
  the same corpus needs a Firmbatch approval recorded on the job. **At most 1,000 requests**,
  with per-evaluation caps on input and output tokens and on purchased spend written into its
  envelope like any other job's. **The report is always produced** — for zero accepted units,
  and for failed, partial and cancelled jobs, in which case it says so — and carries the pass
  rate against the customer's own rules, every failure with the rule that rejected it, cost
  per thousand accepted units at list, and the **escalation rate `x`**, defined as roadmap
  r2_4 D4 defines it: the share of requests that pass only on a larger model, measured per
  corpus. An evaluation **never converts itself into a paid job**; the paid job is a new job
  with a quote.
- **D.1 resolution — `auto_accept_below`.** The quote is **always issued and stored**,
  auto-accepted or not. It is auto-accepted when its **total excluding VAT and payment fees,
  in the tenant's billing currency (USD unless the contract says otherwise), is less than or
  equal to the amount**. The consent is the JobSpec field itself, **bound to the credential
  that submitted the job and recorded on the quote**; it **lapses when the quote expires** and
  is never carried to another job. Evaluation jobs have no quote and are never auto-accepted
  into anything.
- **Authority.** D.1 Markdown "Customer API" (evaluation and `auto_accept_below` paragraphs);
  D.1 PDF p. 2; customer brief r2 §2, §8 (the evaluation offer and what a pilot needs);
  roadmap r2_4 D4 (the report's contents and the definition of `x`); plan v3.4 §2.2;
  demand-alternatives r3 §3.2 (why `x` is measured per corpus).
- **Canonical target.** §5.3 and §5.4.
- **Remaining choices — genuine.** (a) The **numeric per-evaluation caps** on input tokens,
  output tokens and purchased spend: D.1 requires them in the envelope and gives no number;
  no companion does either. A configuration decision for M4.1, recorded on the evaluation
  policy, not invented here. (b) **Quote validity duration**: every authority requires a quote
  expiry (roadmap r2_4 P6, D.1) and none states one. M4.1. (c) **How a corpus is identified**
  for "one per tenant per corpus" (an input-manifest digest is the obvious candidate, but it
  is an implementation choice for M5 and the approval path must not become an oracle).

### D8 — `provider_policy` coverage and the payload plane

- **D review finding.** Unclear whether an exclusion covered execution providers only or all
  subprocessors including storage; a customer excluding AWS could not be promised compliance
  while payloads reside in S3; enforcement on retries, moves and hedges unstated.
- **D.1 resolution.** In v1 `provider_policy` governs **execution placement only** — first
  placement, every retry, every move to shared capacity and every hedge. It **does not govern
  the payload plane**, which is S3 for every tenant until a bucket per supplier cloud exists;
  so **a customer who excludes Amazon altogether cannot be served in v1**, and the consent text
  and the subprocessor list say exactly that rather than promising an exclusion the design
  cannot honour.
- **Authority.** D.1 Markdown "Customer API" (`provider_policy` paragraph); D.1 PDF p. 2;
  plan v3.4 §2.2 and §7 (every operator whose hardware can touch data, plus AWS, on the
  subprocessor list); customer brief r2 §3 (EU processing "on paper").
- **Canonical target.** §5.4; §17 invariant 13.
- **Remaining choice.** None in the rule. The customer-facing consent text is an M3.2/M5
  deliverable and must match the rule.

### D9 — purchase launch snapshot vs actual cost

- **D review finding.** A price can move during an execution; the risk was recomputing past
  cost from today's register or a single final price, and confusing "no counterparty payable"
  with "no cost".
- **D.1 resolution.** Every purchased execution writes, at launch and immutably, a snapshot:
  `supplier_account`, region and zone, SKU, and the `purchase_rate` in force when it started.
  The record then grows **only by appending**: usage and rate intervals taken from the
  provider's own records as they arrive, and invoice adjustments at reconciliation. **Past
  cost is never recomputed** from today's register or from a single final price. "No
  counterparty payable" means no operator settlement under A or B; the cloud's invoice exists
  and is the purchased cost of goods.
- **Authority.** D.1 Markdown "Purchase records"; D.1 PDF p. 4; `settlement-model-r1_3.md`
  §7 (Phase 0 bought capacity is a purchased cost of goods outside the supplier contract);
  roadmap r2_4 §6.3 "Bridge purchase record".
- **Canonical target.** §8.2; §17 invariant 12.
- **Remaining choice.** None.

### D10 — frozen commercial terms vs measured outcomes

- **D review finding.** Rev D listed usage and cancellation facts beside terms "frozen at
  execution time", though some facts are only known later; an honoured or revoked window
  could be read as rewriting a frozen share.
- **D.1 resolution.** Every attempt carries **two kinds of field, kept apart**. *Frozen when
  the work starts, immutable afterwards — the terms:* `operator_id`, `contract_version`,
  `supply_class`, `usage_basis`, `window_offer_id`, `share_bps`, `floor_rate`, the
  acceptance-policy version, and on purchased executions `supplier_account` and
  `purchase_rate`. *Measured, append-only, known only as the work runs or ends — the
  outcomes:* `delivery_valid_gpu_seconds` (or `delivery_valid_requests`, per the usage basis),
  `cancellation_cause`, `cancellation_actor`, and the window's `honoured` or `revoked`
  outcome. A measured outcome decides eligibility — whether the step-up vests, whether an
  execution is payable — and **never rewrites a frozen term or an accepted customer quote**.
- **Authority.** D.1 Markdown "Settlement" (the two-kinds-of-field paragraph); D.1 PDF p. 7;
  `settlement-model-r1_3.md` §2 "What every attempt carries" and §5 vesting rule; roadmap
  r2_4 invariant 29.
- **Canonical target.** §10.1; §12.2.
- **Remaining choice.** None in the rule. The M6 domain ADR records the schema that
  implements the split.

### Added by D.1 — the qualification service tier

- **What D.1 adds.** `service_tier` gains **`qualification`**: internal jobs on an internal
  tenant, on allow-listed profiles, capped like any purchase, human-authorised, whose only
  output is the registry's measured throughput, load times and the pool's measurement
  records. It exists because a paid quote needs measured performance and the measurement
  needs an admitted job, so the first admitted jobs on any new profile or pool are
  qualification jobs, and no profile is certified by fiat. **Customers never see the tier;
  the registry does.**
- **Authority.** D.1 Markdown "Customer API" (qualification paragraph); D.1 PDF p. 2.
- **Canonical target.** §5.5; roadmap M6.1 and M6.2.
- **Remaining choice.** The identity of the internal tenant and the allow-list are
  operational configuration (M6.1); each qualification run's account, region, SKU, duration,
  maximum spend and cleanup are stated and authorised by a human per run (ADR 0008 decision
  6). Neither is invented here.

## 2. Companion authorities

All named companions were supplied for this adoption and read in full. Hashes, roles and the
stored-versus-referenced status of each are in `docs/architecture/sources/README.md`. The
rev D register's "missing companions" section is superseded by that manifest.

## 3. Genuinely remaining decisions, and who owns them

These are the items the authorities leave open **on purpose**. None is a discrepancy between
sources, and none blocks Milestone 3.

| Decision | Nature | Owner and slice |
| --- | --- | --- |
| Exact configured bridge monthly cap, total cap and per-supplier sub-caps (plan range $3–5k a month net of invoiced billings, $10k total) | Spend and deployment decision, recorded on the envelope | Human, before any M6.2 purchase; modelled in M4.3 |
| Numeric per-evaluation caps on input tokens, output tokens and purchased spend | Configuration of the evaluation policy | M4.1 |
| Quote validity duration | Commercial configuration | M4.1 |
| Corpus identity rule for "one free evaluation per tenant per corpus", and the recorded-approval path | Implementation choice | M5 |
| Internal tenant and profile allow-list for qualification jobs; per-run authorisation | Operational configuration; human per run | M6.1, M6.2 |
| Settlement grouping parameter (operator-month default; per-class if an operator refuses) | Per-contract parameter | Phase P, per signed supplier |
| `f_c` cancellation-credit rate | Quoted by the operator (RFQ Q5); "to measure" in the definitions register | Phase P, per signed supplier |
| Endpoint pricing unit (share of NCR or per-token) | Quoted by the endpoint supplier (endpoint RFQ Q3) | Endpoint extension, per signed supplier |
| Model band default (8B vs 27–35B) | Measurement outcome of the evaluation harness and Gate 1, not a document decision | M6.2 measurements |
| Gate 1 threshold revisions | Owned by the plan; a revision is a plan change | Business plan |
| AWS staging **deployment parameters** — the account ID; the region (recommended `eu-central-1`, unconfirmed); the domains; the CIDRs, including the reviewer allow-list and its maximum address-space allowance; the SES identity; the alert recipient; the budget threshold; RDS sizing and the PostgreSQL 16 minor; the saved-plan lifetime (24 hours recommended) and the reviewers of the two GitHub environments; the staging identities to bind; the retention of AWS-managed logs that can hold identity data — plus the current cost estimate and explicit deployment authorization. The staging architecture itself (one origin, Cognito behind an identity broker, Terraform, four slices) is decided by ADR 0011 (2026-09-13, M3.3a) and is no longer open | Human deployment decision | M3.3d, confirmed immediately before plan and apply |
| Rust vs Go for the operator agent | Focused ADR when Phase P is commissioned | Phase P |

## 4. Sequencing decisions taken by this adoption

Recorded here and in ADR 0008; unchanged by the move from D to D.1:

1. Milestone numbering M0–M8 is preserved; M2 is closed under its agreed scope at `4511f7d`.
   M3.0 is the documentation adoption.
2. A protected AWS staging preview is placed at M3.3, pulling a limited subset of M8 controls
   forward. It is a recommendation, not a D.1 requirement, and it created no cloud resource.
   *Amended 2026-09-13 (ADR 0011, M3.3a, corrected the same day after review):* M3.3 is
   four slices — architecture adoption; Terraform and task scaffolding; the broker,
   bootstrap and identity-binding programs with the identity mapping and dependencies;
   authorized deployment with evidence — on one customer origin, with Cognito authenticating behind a
   Firmbatch identity broker and Terraform delivering it; only the fourth slice may create a
   resource, after a reviewed plan, a current cost estimate and explicit authorization.
   Still no cloud resource.
3. The quote-versus-measurement cycle is broken by D.1's **qualification tier**: admitted,
   explicitly capped, human-authorised internal jobs after the M4 and M5 contracts and the
   M6.1 controls exist. No idle speculative fleet; qualification profiles are test-allowlisted
   and are not customer-certified by fiat.
4. One VM driver is completed before the others are multiplied; all four Phase 0 VM drivers
   remain target scope.
5. Nomination, window and operator-statement paths are built and tested dark in M6 against the
   canon's rules; the agent and real operator payments move to Phase P.
6. AWS control-plane hosting is kept separate from the GCP, Azure, AWS and Verda GPU-supply
   decisions. A customer can see the portal long before GPU provider qualification.

## 5. How an entry changes

A resolved entry is changed only by a later architecture revision or a canon amendment, and
the change is recorded here with its source and date, leaving the earlier resolution visible.
A remaining decision is closed by recording the human's decision or the measurement, with its
source, in this table and in the slice that consumes it — and only then is the affected
schema, enum or contract test frozen.
